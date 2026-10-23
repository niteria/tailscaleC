#include "tailscalec/socket.h"
#include "tailscalec/stun.h"
#include "esp_err.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exercise real UDP through the ESP-IDF/lwIP loopback interface. This needs
 * neither a radio nor a virtual Ethernet device in QEMU. */
static int loopback(tsc_socket *socket)
{
    const char payload[] = "tailscaleC transport test";
    char received[sizeof(payload)];
    tsc_endpoint address, from;
    size_t length;
    int rc = tsc_socket_local(socket, &address);
    if (rc != TSC_OK)
        return rc;
    rc = tsc_socket_send(socket, &address, payload, sizeof(payload));
    if (rc != TSC_OK)
        return rc;
    for (unsigned i = 0; i < 100; ++i) {
        rc = tsc_socket_receive(socket, &from, received, sizeof(received), &length);
        if (rc == TSC_OK)
            return length == sizeof(payload) &&
                   memcmp(received, payload, length) == 0 &&
                   tsc_endpoint_equal(&from, &address) ? TSC_OK : TSC_ERR_PROTOCOL;
        if (rc != TSC_AGAIN)
            return rc;
        vTaskDelay(1);
    }
    return TSC_ERR_TIMEOUT;
}

/* No Wi-Fi setup, external server or Tailscale registration is involved. */
void app_main(void)
{
    static tsc_socket socket = TSC_SOCKET_INITIALIZER;
    tsc_endpoint local = { .family = TSC_AF_IPV4, .address = {127,0,0,1} };
    int rc;
    ESP_ERROR_CHECK(esp_netif_init());
    printf("tailscaleC transport foundation\n");
    printf("Socket storage: %zu bytes; configured datagram limit: %u\n",
           sizeof(socket), (unsigned)TSC_MAX_DATAGRAM_SIZE);
#if TSC_ENABLE_STUN
    printf("STUN client storage: %zu bytes, plus caller packet scratch\n",
           sizeof(tsc_stun_client));
#endif
    rc = tsc_socket_open(&socket, &local);
    if (rc == TSC_OK)
        rc = loopback(&socket);
    tsc_socket_close(&socket);
    printf("UDP loopback: %s\n", tsc_status_string(rc));
    if (rc != TSC_OK)
        abort();
    puts("TSC_QEMU_TRANSPORT_OK");
}
