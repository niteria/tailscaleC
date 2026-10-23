#ifndef TAILSCALEC_CONTROL_PROTOCOL_H
#define TAILSCALEC_CONTROL_PROTOCOL_H

#include "tailscalec/stream.h"
#include <stddef.h>
#include <stdint.h>

/* TS2021 fixes the receive record limit at 4096 bytes on the wire. A smaller
 * receive buffer cannot accept all conforming server records. */
#define TSC_NOISE_RECORD_SIZE 4096
#define TSC_NOISE_PLAINTEXT_SIZE (TSC_NOISE_RECORD_SIZE - 19)
/* The sender may split its byte stream into smaller authenticated records.
 * Keep the full receive capacity: the coordinator chooses its record sizes. */
#ifndef TSC_NOISE_TX_RECORD_SIZE
#define TSC_NOISE_TX_RECORD_SIZE TSC_NOISE_RECORD_SIZE
#endif
#if TSC_NOISE_TX_RECORD_SIZE < 64 || TSC_NOISE_TX_RECORD_SIZE > TSC_NOISE_RECORD_SIZE
#error "Noise transmit record size must be 64..4096"
#endif
#ifndef TSC_CONTROL_HEADER_SIZE
#define TSC_CONTROL_HEADER_SIZE 2048
#endif

typedef struct {
    tsc_stream *stream;
    uint32_t timeout_ms;
    uint8_t hash[32], chaining_key[32];
    uint8_t machine_private[32], ephemeral_private[32];
    uint8_t tx_key[32], rx_key[32];
    uint64_t tx_nonce, rx_nonce;
    size_t rx_offset, rx_length;
    int ready, failed;
    uint8_t tx_buffer[TSC_NOISE_TX_RECORD_SIZE];
    uint8_t rx_buffer[TSC_NOISE_RECORD_SIZE];
} tsc_noise;

/* The 101 byte initiation is put in the HTTP upgrade's
 * X-Tailscale-Handshake header using standard padded base64. The caller reads
 * the HTTP 101 headers without consuming any subsequent binary bytes. */
int tsc_noise_handshake_start(tsc_noise *noise, tsc_stream *stream,
    uint16_t version, const uint8_t machine_private[32],
    const uint8_t server_public[32], uint8_t initiation[101]);
int tsc_noise_handshake_finish(tsc_noise *noise);
int tsc_noise_send(tsc_noise *noise, const void *data, size_t length);
int tsc_noise_read(tsc_noise *noise, void *data, size_t capacity,
                    size_t *length);
int tsc_noise_read_exact(tsc_noise *noise, void *data, size_t length);
void tsc_noise_clear(tsc_noise *noise);

/* A deliberately sequential HTTP/2 client. Responses are bounded by the
 * caller's buffer; frames and Noise records are consumed incrementally. */
typedef struct {
    tsc_noise *noise;
    uint32_t next_stream;
    uint32_t active_stream;
    uint32_t server_initial_window;
    int64_t tx_connection_window;
    int64_t tx_stream_window;
    uint32_t server_max_frame;
    unsigned status;
    int ready, failed, stream_open;
    unsigned has_challenge;
    uint8_t challenge[32];
    uint8_t header_buffer[TSC_CONTROL_HEADER_SIZE];
} tsc_h2;

/* Also reads optional EarlyNoise and the server's initial SETTINGS, exposing
 * the node key challenge before registration is constructed. */
int tsc_h2_start(tsc_h2 *h2, tsc_noise *noise);
int tsc_h2_post(tsc_h2 *h2, const char *authority, const char *path,
    const void *request, size_t request_length, void *response,
    size_t response_capacity, size_t *response_length, unsigned *http_status);
/* Headscale requires Stream:true for an initial map. Return after one complete
 * little-endian length-prefixed map, keeping the stream open until the next
 * request cancels it. Any extra maps in the same DATA frame are discarded. */
int tsc_h2_post_map(tsc_h2 *h2, const char *authority, const char *path,
    const void *request, size_t request_length, void *response,
    size_t response_capacity, size_t *response_length, unsigned *http_status);
/* Deliver the first map's JSON incrementally, without its length prefix. */
int tsc_h2_post_map_stream(tsc_h2 *h2, const char *authority, const char *path,
    const void *request, size_t request_length, size_t maximum_json,
    int (*sink)(void *, const void *, size_t), void *user, unsigned *http_status);

#endif
