#ifndef TAILSCALEC_STUN_H
#define TAILSCALEC_STUN_H

#include "tailscalec/tsc.h"

#if TSC_ENABLE_STUN
#ifdef __cplusplus
extern "C" {
#endif

#define TSC_STUN_TRANSACTION_SIZE 12
#define TSC_STUN_REQUEST_SIZE 40

/* RFC 8489 Binding request with the SOFTWARE marker and FINGERPRINT required
 * by Tailscale/Headscale STUN servers. No authentication attributes. */
int tsc_stun_request(const uint8_t transaction[TSC_STUN_TRANSACTION_SIZE],
                     void *packet, size_t capacity, size_t *length);
/* On failure, mapped is unchanged. Checks framing and transaction identity.
 * This is endpoint discovery, not authenticated peer discovery. */
int tsc_stun_response(const void *packet, size_t length,
                      const uint8_t transaction[TSC_STUN_TRANSACTION_SIZE],
                      tsc_endpoint *mapped);

typedef struct {
    tsc_platform platform;
    tsc_endpoint server;
    tsc_endpoint mapped;
    uint8_t transaction[TSC_STUN_TRANSACTION_SIZE];
    uint64_t next_attempt_ms;
    uint64_t deadline_ms;
    uint32_t retry_ms;
    unsigned attempts;
    int status;
} tsc_stun_client;

/* Use a dedicated UDP socket. poll consumes at most one datagram per call.
 * scratch is caller-owned and must be >= TSC_MAX_DATAGRAM_SIZE bytes.
 * No threads, sleeps or allocations are created by the client.
 * start initializes an uninitialized client; start again to restart it. */
int tsc_stun_start(tsc_stun_client *client, const tsc_platform *platform,
                   const tsc_endpoint *server);
int tsc_stun_poll(tsc_stun_client *client, void *scratch, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
#endif
