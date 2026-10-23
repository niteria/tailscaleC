#ifndef TAILSCALEC_TSC_H
#define TAILSCALEC_TSC_H

#include "tailscalec/config.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    TSC_OK = 0,
    TSC_AGAIN = 1,
    TSC_ERR_ARGUMENT = -1,
    TSC_ERR_IO = -2,
    TSC_ERR_SPACE = -3,
    TSC_ERR_PROTOCOL = -4,
    TSC_ERR_TIMEOUT = -5,
    TSC_ERR_UNSUPPORTED = -6,
    TSC_ERR_TRUNCATED = -7
};

typedef enum {
    TSC_AF_IPV4 = 4,
    TSC_AF_IPV6 = 6
} tsc_address_family;

typedef struct {
    tsc_address_family family;
    uint8_t address[16]; /* Network byte order; IPv4 uses the first 4 bytes. */
    uint16_t port;       /* Host byte order. */
    uint32_t scope_id;   /* IPv6 interface scope; zero for IPv4. */
} tsc_endpoint;

int tsc_endpoint_equal(const tsc_endpoint *a, const tsc_endpoint *b);
const char *tsc_status_string(int status);

/* Transport callbacks operate on UNDERLYING UDP, not tailnet application data.
 * Callbacks must be nonblocking, except random_bytes during initialization.
 * The caller owns the adapter, socket and all packet buffers. */
typedef struct {
    void *user;
    int (*udp_send)(void *user, const tsc_endpoint *to,
                    const void *packet, size_t length);
    int (*udp_receive)(void *user, tsc_endpoint *from,
                       void *packet, size_t capacity, size_t *length);
    /* Nondecreasing milliseconds, including time spent suspended: coordinator
     * key-expiry deadlines depend on this clock. If the platform clock pauses
     * during suspend, refresh the authenticated control map before allowing
     * tailnet traffic after resume. Linux prefers CLOCK_BOOTTIME; the POSIX
     * CLOCK_MONOTONIC fallback may pause during suspend. */
    uint64_t (*monotonic_ms)(void *user);
    int (*random_bytes)(void *user, void *buffer, size_t length);
} tsc_platform;

#ifdef __cplusplus
}
#endif
#endif
