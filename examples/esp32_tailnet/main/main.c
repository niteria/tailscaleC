/* Actual Xtensa/lwIP/mbedTLS client interop, using QEMU virtual Ethernet.
 * The runner generates private/lab_config.h inside the ignored build tree.
 * This fixture is for QEMU, where radio and physical entropy are simulated. */
#include "tailscalec/client.h"
#include "tailscalec/socket.h"
#include "tailscalec/crypto.h"
#include "lab_config.h"
#include "bootloader_random.h"
#include "esp_err.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#if !CONFIG_ETH_USE_OPENETH
#error "This test firmware requires QEMU virtual Ethernet"
#endif

static tsc_client client;
static tsc_socket outer = TSC_SOCKET_INITIALIZER;
static tsc_udp app_udp;
static tsc_identity identity;
static EventGroupHandle_t ethernet_events;
static nvs_handle_t private_store;
static tsc_endpoint reference;
static const size_t lengths[] = {1, 32, 512, 1200};
static uint8_t payload[1200];
static size_t payload_length;
static int received, unexpected;
static int identity_restored;
static int upstream_mode, upstream_received;

static void fail(const char *step, int result)
{
    printf("TSC_QEMU_TAILNET_FAILED %s: %s (%d): %s\n", step,
           tsc_status_string(result), result, tsc_client_last_error(&client));
    fflush(stdout);
    abort();
}

static void got_ip(void *argument, esp_event_base_t base, int32_t event, void *data)
{
    (void)argument; (void)base; (void)event;
    ip_event_got_ip_t *ip = data;
    printf("ETHERNET " IPSTR "\n", IP2STR(&ip->ip_info.ip));
    xEventGroupSetBits(ethernet_events, 1);
}

static void network_start(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ethernet_events = xEventGroupCreate();
    if (!ethernet_events) abort();
    esp_netif_config_t interface_config = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *interface = esp_netif_new(&interface_config);
    if (!interface) abort();
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = 1;
    phy_config.reset_gpio_num = -1;
    phy_config.autonego_timeout_ms = 100;
    esp_eth_mac_t *mac = esp_eth_mac_new_openeth(&mac_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_dp83848(&phy_config);
    if (!mac || !phy) abort();
    esp_eth_handle_t ethernet;
    esp_eth_config_t driver_config = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_ERROR_CHECK(esp_eth_driver_install(&driver_config, &ethernet));
    ESP_ERROR_CHECK(esp_netif_attach(interface, esp_eth_new_netif_glue(ethernet)));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP,
                                                got_ip, NULL));
    ESP_ERROR_CHECK(esp_eth_start(ethernet));
    if (!(xEventGroupWaitBits(ethernet_events, 1, pdFALSE, pdFALSE,
                             pdMS_TO_TICKS(20000)) & 1))
        fail("Ethernet DHCP", TSC_ERR_TIMEOUT);
}

/* Persist before using a handshake timestamp, including when wall time steps
 * backwards. This test uses an NVS commit per handshake for simple durability;
 * production firmware should budget flash endurance and encrypt its NVS. */
static int durable_timestamp(void *user, uint8_t timestamp[12])
{
    uint8_t previous[12];
    size_t length = sizeof(previous);
    int result = tsc_socket_tai64n_now(user, timestamp);
    if (result != TSC_OK) return result;
    esp_err_t error = nvs_get_blob(private_store, "timestamp", previous, &length);
    if (error != ESP_OK && error != ESP_ERR_NVS_NOT_FOUND) return TSC_ERR_IO;
    if (error == ESP_OK) {
        if (length != sizeof(previous)) return TSC_ERR_PROTOCOL;
        if (memcmp(timestamp, previous, sizeof(previous)) <= 0) {
            memcpy(timestamp, previous, sizeof(previous));
            /* Increment the seconds field and reset nanoseconds, retaining a
             * valid TAI64N value even if the previous nanoseconds were maximal. */
            memset(timestamp + 8, 0, 4);
            int index = 7;
            while (index >= 0 && ++timestamp[index] == 0) --index;
            if (index < 0) return TSC_ERR_IO;
        }
    }
    if (nvs_set_blob(private_store, "timestamp", timestamp, 12) != ESP_OK ||
        nvs_commit(private_store) != ESP_OK) return TSC_ERR_IO;
    return TSC_OK;
}

static void load_identity(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(nvs_open("tailscalec", NVS_READWRITE, &private_store));
    size_t length = sizeof(identity);
    esp_err_t error = nvs_get_blob(private_store, "identity", &identity, &length);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        int result = tsc_identity_generate(&identity);
        if (result != TSC_OK) fail("identity", result);
        ESP_ERROR_CHECK(nvs_set_blob(private_store, "identity", &identity,
                                       sizeof(identity)));
        ESP_ERROR_CHECK(nvs_commit(private_store));
        puts("IDENTITY generated");
    } else {
        ESP_ERROR_CHECK(error);
        if (length != sizeof(identity)) fail("persisted identity", TSC_ERR_PROTOCOL);
        identity_restored = 1;
        puts("IDENTITY restored");
    }
}

static void on_udp(void *user, tsc_udp *socket, const tsc_endpoint *source,
                     const void *bytes, size_t length)
{
    (void)user; (void)socket;
    if (source->family != reference.family ||
        memcmp(source->address, reference.address, 4) != 0) {
        unexpected = 1;
        return;
    }
    if (upstream_mode) {
        static const char challenge[] = "upstream-to-esp32-binary";
        if (length < sizeof(challenge) - 1 ||
            memcmp(bytes, challenge, sizeof(challenge) - 1) != 0) return;
        int result = tsc_udp_send(socket, source, bytes, length);
        if (result != TSC_OK) fail("upstream UDP response", result);
        upstream_received = 1;
        return;
    }
    if (source->port == 32124) {
        unexpected = 1;
        return;
    }
    if (source->port != reference.port) return;
    if (length == payload_length && memcmp(bytes, payload, length) == 0)
        received = 1;
}

static void exercise(uint64_t duration_ms, int expect_reply)
{
    uint64_t deadline = client.platform.monotonic_ms(client.platform.user) + duration_ms;
    uint64_t next_send = 0;
    received = unexpected = 0;
    while (client.platform.monotonic_ms(client.platform.user) < deadline) {
        uint64_t now = client.platform.monotonic_ms(client.platform.user);
        int result = tsc_client_poll(&client);
        if (result < 0) fail("poll", result);
        if (now >= next_send) {
            result = tsc_udp_send(&app_udp, &reference, payload, payload_length);
            if (result < 0) fail("UDP send", result);
            next_send = now + (result == TSC_OK ? 500 : 50);
        }
        if (unexpected || (!expect_reply && received)) fail("unexpected reply", TSC_ERR_PROTOCOL);
        if (expect_reply && received) return;
        vTaskDelay(1);
    }
    if (expect_reply) fail("encrypted UDP echo", TSC_ERR_TIMEOUT);
}

void app_main(void)
{
    struct timeval clock = { .tv_sec = TSC_LAB_EPOCH };
    if (settimeofday(&clock, NULL) != 0) abort();
    /* QEMU emulates this source. No claim of hardware entropy is made here. */
    bootloader_random_enable();
    network_start();
    load_identity();
    tsc_endpoint bind = { .family = TSC_AF_IPV4, .port = 41641 };
    tsc_endpoint advertised = { .family = TSC_AF_IPV4, .port = TSC_LAB_FORWARD_PORT };
    if (tsc_socket_resolve(TSC_LAB_ADVERTISE_IP, advertised.port, TSC_AF_IPV4,
                            &advertised) != TSC_OK) abort();
    reference.family = TSC_AF_IPV4;
    reference.port = 32123;
    if (tsc_socket_resolve(TSC_LAB_REFERENCE_IP, reference.port, TSC_AF_IPV4,
                            &reference) != TSC_OK) abort();
    int result = tsc_socket_open(&outer, &bind);
    if (result != TSC_OK) fail("outer socket", result);
    tsc_client_config config = {
        .control_url = TSC_LAB_CONTROL_URL,
        .auth_key = identity_restored ? NULL : TSC_LAB_AUTH_KEY,
        .hostname = "esp32-s3-qemu", .identity = &identity,
        .platform = tsc_socket_platform(&outer), .tai64n_now = durable_timestamp,
        .endpoints = &advertised, .endpoint_count = 1, .control_timeout_ms = 20000
    };
    printf("MEMORY client=%zu control=%zu heap_before_join=%u\n", sizeof(client),
           tsc_control_memory_size(), (unsigned)esp_get_free_heap_size());
    result = tsc_client_init(&client, &config);
    if (result != TSC_OK) fail("init", result);
    result = tsc_client_join(&client);
    if (result != TSC_OK) fail("authenticated join", result);
    tsc_endpoint own;
    result = tsc_client_address(&client, &own);
    if (result != TSC_OK) fail("address", result);
    printf("JOINED %u.%u.%u.%u\n", own.address[0], own.address[1], own.address[2], own.address[3]);
    result = tsc_udp_open(&client, &app_udp, 32123, on_udp, NULL);
    if (result != TSC_OK) fail("application UDP", result);
    for (size_t test = 0; test < sizeof(lengths) / sizeof(lengths[0]); ++test) {
        payload_length = lengths[test];
        for (size_t index = 0; index < payload_length; ++index)
            payload[index] = (uint8_t)(index * 73u + payload_length);
        exercise(15000, 1);
        printf("UDP_BINARY_ECHO %zu\n", payload_length);
    }
    /* The real upstream receiver enforces its map's inbound policy. */
    reference.port = 32124;
    payload_length = 32;
    memset(payload, 0xd7, payload_length);
    exercise(3000, 0);
    puts("UDP_DENIED_PORT 32124");
    result = tsc_client_refresh_map(&client);
    if (result != TSC_OK) fail("map refresh", result);
    puts("MAP_REFRESH_OK");
    upstream_mode = 1;
    puts("UPSTREAM_UDP_READY");
    fflush(stdout);
    uint64_t deadline = client.platform.monotonic_ms(client.platform.user) + 15000;
    while (!upstream_received &&
           client.platform.monotonic_ms(client.platform.user) < deadline) {
        result = tsc_client_poll(&client);
        if (result < 0) fail("upstream UDP poll", result);
        vTaskDelay(1);
    }
    if (!upstream_received) fail("upstream UDP request", TSC_ERR_TIMEOUT);
    puts("UPSTREAM_UDP_ECHO_OK");
    printf("MEMORY heap_after_join=%u heap_minimum=%u stack_unused=%u\n",
           (unsigned)esp_get_free_heap_size(), (unsigned)esp_get_minimum_free_heap_size(),
           (unsigned)uxTaskGetStackHighWaterMark(NULL));
    tsc_client_close(&client);
    tsc_socket_close(&outer);
    tsc_crypto_zero(&identity, sizeof(identity));
    nvs_close(private_store);
    puts("TSC_QEMU_TAILNET_OK");
    fflush(stdout);
}
