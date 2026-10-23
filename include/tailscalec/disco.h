#ifndef TAILSCALEC_DISCO_H
#define TAILSCALEC_DISCO_H

#include "tailscalec/tsc.h"

#ifdef __cplusplus
extern "C" {
#endif

#if TSC_ENABLE_DISCO
#if TSC_DISCO_MAX_PROBES < 1 || TSC_DISCO_MAX_PROBES > 65536
#error "TSC_DISCO_MAX_PROBES must be between 1 and 65536"
#endif
#if TSC_MAX_DATAGRAM_SIZE < 124
#error "DISCO needs datagram storage of at least 124 bytes"
#endif

/* No allocations. One owner/event loop; callbacks must not reenter this object.
 * The application demultiplexes DISCO and WireGuard on the same UDP socket.
 * Configure peer/endpoint/probe bounds in the shared configuration header. */
typedef struct {
    void *user;
    int (*relay_send)(void *user, const uint8_t node_key[32],
                      const void *packet, size_t length);
    void (*path_changed)(void *user, const uint8_t node_key[32],
                         const tsc_endpoint *endpoint, uint32_t rtt_ms);
    void (*observed_endpoint)(void *user, const tsc_endpoint *endpoint);
} tsc_disco_callbacks;

typedef struct {
    uint8_t active;
    uint8_t node_key[32];
    uint8_t disco_key[32];
    uint8_t shared_key[32];
    tsc_endpoint endpoints[TSC_MAX_PEER_ENDPOINTS];
    size_t endpoint_count;
    size_t probe_cursor;
    tsc_endpoint best_endpoint;
    uint64_t trusted_until_ms;
    uint64_t next_probe_ms;
    uint32_t best_rtt_ms;
    uint8_t has_best;
    uint8_t relay_next;
} tsc_disco_peer;

typedef struct {
    uint8_t active;
    uint8_t via_relay;
    tsc_endpoint destination;
    uint8_t txid[12];
    size_t peer_index;
    uint64_t sent_ms;
} tsc_disco_probe_state;

typedef struct {
    tsc_platform platform;
    tsc_disco_callbacks callbacks;
    uint8_t private_key[32];
    uint8_t public_key[32];
    uint8_t node_key[32];
    tsc_disco_peer peers[TSC_MAX_PEERS];
    tsc_disco_probe_state probes[TSC_DISCO_MAX_PROBES];
    size_t tick_cursor;
} tsc_disco;

int tsc_disco_init(tsc_disco *disco, const tsc_platform *platform,
                   const tsc_disco_callbacks *callbacks,
                   const uint8_t private_key[32], const uint8_t node_key[32]);
void tsc_disco_clear(tsc_disco *disco);
int tsc_disco_is_packet(const void *packet, size_t length);
int tsc_disco_set_peer(tsc_disco *disco, const uint8_t node_key[32],
                       const uint8_t disco_key[32],
                       const tsc_endpoint *endpoints, size_t endpoint_count);
int tsc_disco_remove_peer(tsc_disco *disco, const uint8_t node_key[32]);
/* Returns TSC_AGAIN when no currently validated direct endpoint is available. */
int tsc_disco_endpoint(tsc_disco *disco, const uint8_t node_key[32],
                       tsc_endpoint *endpoint);
/* Probe candidates and the current direct path, optionally through DERP.
 * Candidates rotate when the transaction budget cannot cover every endpoint.
 * A relayed pong cannot select or refresh a direct endpoint. */
int tsc_disco_probe(tsc_disco *disco, const uint8_t node_key[32], int relay);
/* Call periodically. Expire transactions and probe at most one peer per call. */
int tsc_disco_tick(tsc_disco *disco);
/* direct source must be non-NULL; relay source must be NULL. Relayed packets
 * must additionally be bound to their DERP node key with the relay API below. */
int tsc_disco_receive(tsc_disco *disco, const tsc_endpoint *source,
                      const void *packet, size_t length);
int tsc_disco_receive_relay(tsc_disco *disco, const uint8_t relay_node_key[32],
                            const void *packet, size_t length);
/* CallMeMaybe is sent only through DERP. Advertised endpoints are bounded. */
int tsc_disco_call_me_maybe(tsc_disco *disco, const uint8_t node_key[32],
                            const tsc_endpoint *endpoints, size_t count);

#endif /* TSC_ENABLE_DISCO */
#ifdef __cplusplus
}
#endif
#endif
