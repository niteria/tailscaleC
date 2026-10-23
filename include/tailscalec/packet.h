#ifndef TAILSCALEC_PACKET_H
#define TAILSCALEC_PACKET_H

#include "tailscalec/tsc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TSC_IPV4_HEADER_SIZE 20u
#define TSC_UDP_HEADER_SIZE 8u
#define TSC_UDP_MAX_PAYLOAD 65507u

typedef struct {
    uint8_t src[4];
    uint8_t dst[4];
    uint16_t src_port; /* Host byte order. */
    uint16_t dst_port; /* Host byte order. */
    const uint8_t *payload; /* Borrows the input packet's storage. */
    size_t length;
} tsc_udp_packet_view;

/* Encode one IPv4 UDP packet, with TTL 64 and Don't Fragment set. Addresses
 * are network-order bytes; ports and identification are host byte order.
 * The payload may overlap out. NULL payload is allowed only for length zero.
 * No allocation is performed. On failure, *out_length is zero and out is
 * unchanged. A payload larger than TSC_UDP_MAX_PAYLOAD is an argument error. */
int tsc_packet_udp_encode(const uint8_t src[4], const uint8_t dst[4],
                          uint16_t src_port, uint16_t dst_port,
                          const void *payload, size_t length,
                          uint16_t identification, void *out, size_t capacity,
                          size_t *out_length);

/* Decode a complete, unfragmented IPv4 UDP packet. IPv4 options are accepted
 * and covered by the header checksum. The IPv4 total length and UDP length
 * must match the supplied framing exactly; trim WireGuard padding first.
 * Both checksums are checked, except that UDP checksum zero means omitted
 * as permitted by IPv4. Malformed packets return TSC_ERR_PROTOCOL. On any
 * failure, view is unchanged. The returned payload lives as long as packet. */
int tsc_packet_udp_decode(const void *packet, size_t length,
                          tsc_udp_packet_view *view);

#ifdef __cplusplus
}
#endif
#endif
