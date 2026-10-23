#include "esp_netif.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int tsc_tcp_vectors_main(void);

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        printf("ESP TCP fixture failed: %s at %s:%d\n", #condition, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)

static void native_udp_loopback(void)
{
    static const unsigned char payload[] = {0, 255, 0x13, 0x42, 0, 0x80};
    unsigned char received[sizeof(payload)];
    struct sockaddr_in local = {
        .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = 0
    };
    struct sockaddr_in sender;
    socklen_t local_size = sizeof(local), sender_size = sizeof(sender);
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    int server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(server >= 0 && client >= 0);
    REQUIRE(setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    REQUIRE(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    REQUIRE(bind(server, (struct sockaddr *)&local, sizeof(local)) == 0);
    REQUIRE(getsockname(server, (struct sockaddr *)&local, &local_size) == 0);
    REQUIRE(sendto(client, payload, sizeof(payload), 0,
                    (struct sockaddr *)&local, sizeof(local)) == sizeof(payload));
    REQUIRE(recvfrom(server, received, sizeof(received), 0,
                      (struct sockaddr *)&sender, &sender_size) == sizeof(payload));
    REQUIRE(memcmp(received, payload, sizeof(payload)) == 0);
    REQUIRE(sendto(server, received, sizeof(received), 0,
                    (struct sockaddr *)&sender, sender_size) == sizeof(received));
    REQUIRE(recv(client, received, sizeof(received), 0) == sizeof(received));
    REQUIRE(memcmp(received, payload, sizeof(payload)) == 0);
    REQUIRE(close(client) == 0);
    REQUIRE(close(server) == 0);
    puts("Native ESP-IDF lwIP UDP loopback passed");
}

void app_main(void)
{
    int64_t start = esp_timer_get_time();
    REQUIRE(esp_netif_init() == ESP_OK);
    native_udp_loopback();
    puts("Running shared portable TCP cases on ESP32-S3");
    REQUIRE(tsc_tcp_vectors_main() == 0);
    native_udp_loopback();
    printf("TCP target tests elapsed: %" PRId64 " ms\n",
           (esp_timer_get_time() - start) / 1000);
    puts("TSC_QEMU_TCP_OK");
}
