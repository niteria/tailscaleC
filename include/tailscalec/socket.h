#ifndef TAILSCALEC_SOCKET_H
#define TAILSCALEC_SOCKET_H

#include "tailscalec/tsc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* BSD-socket adapter shared by POSIX and ESP-IDF. No dynamic allocation in
 * our adapter. The OS/lwIP socket implementation has its own memory costs.
 * Use TSC_SOCKET_INITIALIZER and close before reopening. Single-owner API. */
typedef struct {
    int fd;
    uint8_t receive_buffer[TSC_MAX_DATAGRAM_SIZE + 1];
} tsc_socket;

#define TSC_SOCKET_INITIALIZER { -1, { 0 } }

int tsc_socket_open(tsc_socket *socket, const tsc_endpoint *bind_address);
void tsc_socket_close(tsc_socket *socket);
int tsc_socket_local(const tsc_socket *socket, tsc_endpoint *address);
int tsc_socket_send(tsc_socket *socket, const tsc_endpoint *to,
                    const void *packet, size_t length);
int tsc_socket_receive(tsc_socket *socket, tsc_endpoint *from,
                       void *packet, size_t capacity, size_t *length);

/* Resolution may block. Call before entering the protocol event loop.
 * family is TSC_AF_IPV4 or TSC_AF_IPV6, never a platform AF_* value. */
int tsc_socket_resolve(const char *host, uint16_t port,
                       tsc_address_family family, tsc_endpoint *address);
tsc_platform tsc_socket_platform(tsc_socket *socket);
/* WireGuard handshake timestamp callback. Uses synchronized wall clock and
 * returns TSC_ERR_IO before year 2020 to catch an unsynchronized MCU clock.
 * The caller must ensure timestamps do not go backwards across reboots. */
int tsc_socket_tai64n_now(void *user, uint8_t output[12]);

#ifdef __cplusplus
}
#endif
#endif
