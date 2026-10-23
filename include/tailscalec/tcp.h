#ifndef TAILSCALEC_TCP_H
#define TAILSCALEC_TCP_H

#include "tailscalec/tsc.h"

#ifdef __cplusplus
extern "C" {
#endif

#if TSC_APP_TCP

#ifndef TSC_MAX_TCP_LISTENERS
#define TSC_MAX_TCP_LISTENERS 2
#endif

typedef struct tsc_tcp tsc_tcp;
typedef unsigned tsc_tcp_handle;

typedef struct {
    uint8_t local_ipv4[4];
    uint16_t mtu; /* 0 selects 1280; valid range 576..TSC_MAX_DATAGRAM_SIZE. */
    void *user;
    /* Output is a complete IPv4 packet, copied/consumed before returning.
     * Do not call back into this TCP stack from send_ip. Queue packets instead.
     * send_ip returns TSC_OK, TSC_AGAIN, or a negative TSC_ERR_* value. A
     * transient send failure retains TCP bytes for a later retransmission. */
    int (*send_ip)(void *user, const void *packet, size_t length);
    int (*random_bytes)(void *user, void *output, size_t length);
} tsc_tcp_config;

typedef enum {
    TSC_TCP_UNUSED = 0,
    TSC_TCP_CONNECTING,
    TSC_TCP_ESTABLISHED,
    TSC_TCP_EOF,
    TSC_TCP_FAILED
} tsc_tcp_state;

/* Private storage is public solely to allow static allocation without malloc.
 * Do not modify any field. Handles remain valid until tsc_tcp_close(). */
typedef struct {
    void *pcb;
    tsc_tcp *owner;
    tsc_endpoint remote;
    size_t head, length;
    int error;
    tsc_tcp_handle listener;
    uint8_t state, pending, write_closed;
    uint8_t receive[TSC_TCP_RECEIVE_BUFFER];
} tsc_tcp_connection_storage;

struct tsc_tcp {
    tsc_tcp_config config;
    uint64_t timer_ms;
    int initialized, rng_failed, in_call;
    uint8_t output[TSC_MAX_DATAGRAM_SIZE];
    void *listeners[TSC_MAX_TCP_LISTENERS];
    tsc_tcp_connection_storage connections[TSC_MAX_TCP_CONNECTIONS];
};

/* One stack may be initialized at a time, independent of native/ESP-IDF lwIP.
 * Every API call must come from the same task/thread. All calls are nonblocking.
 * init rejects an existing live stack with TSC_ERR_SPACE. This component handles
 * IPv4 TCP only; use the client UDP API for application UDP. */
int tsc_tcp_init(tsc_tcp *stack, const tsc_tcp_config *config, uint64_t now_ms);
void tsc_tcp_destroy(tsc_tcp *stack);
int tsc_tcp_input(tsc_tcp *stack, const void *ipv4, size_t length);
int tsc_tcp_poll(tsc_tcp *stack, uint64_t now_ms);

int tsc_tcp_listen(tsc_tcp *stack, uint16_t port, tsc_tcp_handle *listener);
int tsc_tcp_unlisten(tsc_tcp *stack, tsc_tcp_handle listener);
int tsc_tcp_accept(tsc_tcp *stack, tsc_tcp_handle listener,
                   tsc_tcp_handle *connection, tsc_endpoint *remote);
/* TSC_OK means the asynchronous connect started. Inspect state before send. */
int tsc_tcp_connect(tsc_tcp *stack, const tsc_endpoint *remote,
                    uint16_t local_port, tsc_tcp_handle *connection);
int tsc_tcp_get_state(tsc_tcp *stack, tsc_tcp_handle connection,
                      tsc_tcp_state *state);
/* Partial writes/reads are possible. AGAIN means no progress; received==0 with
 * TSC_OK means orderly EOF. TCP send storage stays bounded by SEND_BUFFER. */
int tsc_tcp_send(tsc_tcp *stack, tsc_tcp_handle connection,
                 const void *data, size_t length, size_t *sent);
int tsc_tcp_receive(tsc_tcp *stack, tsc_tcp_handle connection,
                    void *data, size_t capacity, size_t *received);
/* shutdown sends FIN after queued bytes; receive remains available. close
 * releases the handle and aborts any connection not already gracefully closed.
 * Call shutdown, read EOF, then close for a graceful full-duplex exchange. */
int tsc_tcp_shutdown(tsc_tcp *stack, tsc_tcp_handle connection);
int tsc_tcp_close(tsc_tcp *stack, tsc_tcp_handle connection);

#endif /* TSC_APP_TCP */

#ifdef __cplusplus
}
#endif
#endif
