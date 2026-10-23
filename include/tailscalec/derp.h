#ifndef TAILSCALEC_DERP_H
#define TAILSCALEC_DERP_H

#include "tailscalec/tsc.h"

#ifdef __cplusplus
extern "C" {
#endif

#if TSC_ENABLE_DERP

#ifndef TSC_DERP_MAX_HTTP_HEADER
#define TSC_DERP_MAX_HTTP_HEADER 1024
#endif
#ifndef TSC_DERP_MAX_FRAME_SIZE
#define TSC_DERP_MAX_FRAME_SIZE (TSC_MAX_DATAGRAM_SIZE + 256)
#endif
#if TSC_DERP_MAX_HTTP_HEADER < 128 || TSC_DERP_MAX_HTTP_HEADER > 65536
#error "TSC_DERP_MAX_HTTP_HEADER must be between 128 and 65536"
#endif
#if TSC_DERP_MAX_FRAME_SIZE < 128 || TSC_DERP_MAX_FRAME_SIZE > 1048576
#error "TSC_DERP_MAX_FRAME_SIZE must be between 128 and 1048576"
#endif

#define TSC_DERP_BUFFER_SIZE \
    ((TSC_DERP_MAX_FRAME_SIZE > TSC_DERP_MAX_HTTP_HEADER) ? \
     TSC_DERP_MAX_FRAME_SIZE : TSC_DERP_MAX_HTTP_HEADER)

typedef enum {
    TSC_DERP_EVENT_NONE = 0,
    TSC_DERP_EVENT_READY,
    TSC_DERP_EVENT_PACKET,
    TSC_DERP_EVENT_PEER_GONE,
    TSC_DERP_EVENT_PONG,
    TSC_DERP_EVENT_HEALTH,
    TSC_DERP_EVENT_RESTARTING
} tsc_derp_event_type;

typedef struct {
    tsc_derp_event_type type;
    uint8_t peer_key[32];
    const uint8_t *data;
    size_t length;
    uint8_t reason;
    uint32_t reconnect_in_ms;
    uint32_t retry_for_ms;
} tsc_derp_event;

/* Allocation-free DERP v2 protocol engine, owned by one event loop. The caller
 * supplies an authenticated TLS stream in production; plaintext is suitable
 * only for trusted local test servers. Keep a handshake/idle deadline in the
 * caller. No network, TLS, clock, or platform headers enter this module.
 *
 * Public fields permit static allocation; applications must not modify them.
 * Maximum inbound frame size is an explicit resource limit, including the
 * 32-byte source key. Larger frames fail closed, requiring a new connection. */
typedef struct {
    uint8_t private_key[32];
    uint8_t public_key[32];
    uint8_t server_key[32];
    uint8_t shared_key[32];
    uint8_t receive_buffer[TSC_DERP_BUFFER_SIZE];
    uint8_t transmit_buffer[TSC_DERP_BUFFER_SIZE + 5];
    uint8_t frame_header[5];
    uint8_t pending_pong[8];
    size_t header_used;
    size_t frame_used;
    size_t transmit_length;
    size_t transmit_offset;
    uint32_t frame_length;
    uint8_t frame_type;
    uint8_t stage;
    uint8_t has_pending_pong;
    int error;
} tsc_derp;

int tsc_derp_init(tsc_derp *derp, const uint8_t node_private_key[32]);
void tsc_derp_clear(tsc_derp *derp);

/* host is the HTTP Host value (optionally including a port). NULL skips HTTP
 * Upgrade for an already-upgraded/raw DERP connection. Call once after init.
 * No "fast start": the HTTP response and DERP server greeting are validated. */
int tsc_derp_start(tsc_derp *derp, const char *host);
int tsc_derp_is_ready(const tsc_derp *derp);

/* Feed arbitrary stream fragments. At most one complete frame is processed.
 * Always advance by *consumed, even on TSC_AGAIN. Events borrow receive_buffer
 * until the next feed. READY carries authenticated server-info JSON. Automatic
 * pong replies use the bounded output slot. If output backpressure blocks
 * processing, drain output then call feed again (a zero-length feed is valid).
 * All negative protocol errors are sticky until clear/init. */
int tsc_derp_feed(tsc_derp *derp, const void *data, size_t length,
                   size_t *consumed, tsc_derp_event *event);

/* Output remains stable until consumed, suitable for partial/TLS retry writes.
 * TSC_AGAIN means no pending output. Consuming a prefix is permitted. */
int tsc_derp_output(const tsc_derp *derp, const uint8_t **data, size_t *length);
int tsc_derp_output_consumed(tsc_derp *derp, size_t length);

/* Queue one frame; TSC_AGAIN means the output slot is occupied. Packet payload
 * is copied and may be released after TSC_OK. No heap or unbounded queue. */
int tsc_derp_send(tsc_derp *derp, const uint8_t destination_key[32],
                  const void *packet, size_t length);
int tsc_derp_note_preferred(tsc_derp *derp, int preferred);
int tsc_derp_ping(tsc_derp *derp, const uint8_t payload[8]);

#endif

#ifdef __cplusplus
}
#endif
#endif
