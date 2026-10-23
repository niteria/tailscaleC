#ifndef TAILSCALEC_POLICY_H
#define TAILSCALEC_POLICY_H

#include "tailscalec/tsc.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TSC_MAX_FILTER_RULES
#define TSC_MAX_FILTER_RULES 32
#endif
#ifndef TSC_MAX_FILTER_SOURCES
#define TSC_MAX_FILTER_SOURCES 8
#endif
#ifndef TSC_MAX_FILTER_DESTINATIONS
#define TSC_MAX_FILTER_DESTINATIONS 8
#endif

#if TSC_MAX_FILTER_RULES < 1 || TSC_MAX_FILTER_RULES > 65535
#error "TSC_MAX_FILTER_RULES must be between 1 and 65535"
#endif
#if TSC_MAX_FILTER_SOURCES < 1 || TSC_MAX_FILTER_SOURCES > 255
#error "TSC_MAX_FILTER_SOURCES must be between 1 and 255"
#endif
#if TSC_MAX_FILTER_DESTINATIONS < 1 || TSC_MAX_FILTER_DESTINATIONS > 255
#error "TSC_MAX_FILTER_DESTINATIONS must be between 1 and 255"
#endif

typedef struct {
    uint8_t address[TSC_ENABLE_IPV6 ? 16 : 4];
    uint8_t end_address[TSC_ENABLE_IPV6 ? 16 : 4];
    uint8_t family; /* 0 means wildcard, otherwise TSC_AF_IPV4 or TSC_AF_IPV6. */
    uint8_t bits;
    uint8_t is_range; /* Inclusive address..end_address instead of a CIDR. */
} tsc_policy_prefix;

typedef struct {
    tsc_policy_prefix prefix;
    uint16_t first_port;
    uint16_t last_port;
} tsc_policy_destination;

typedef struct {
    tsc_policy_prefix sources[TSC_MAX_FILTER_SOURCES];
    tsc_policy_destination destinations[TSC_MAX_FILTER_DESTINATIONS];
    uint8_t protocols[32]; /* 256-bit IP protocol set. */
    uint8_t source_count;
    uint8_t destination_count;
} tsc_policy_rule;

/* Fixed capacity, no heap allocation. Initialize to {0} for deny-all. */
typedef struct {
    tsc_policy_rule rules[TSC_MAX_FILTER_RULES];
    uint16_t rule_count;
} tsc_policy;

/* Read the PacketFilter ARRAY itself, not the enclosing MapResponse.
 * Supports SrcIPs (addresses, CIDR prefixes, inclusive IP ranges or "*"),
 * DstPorts with inclusive
 * Ports.First/Last, and IPProto. An absent/empty IPProto selects TCP, UDP and
 * ICMP. An empty or null array denies everything. All failures clear policy,
 * including syntax, unsupported constructs, or configured capacity limits.
 * JSON escapes in ASCII strings are supported. Legacy nonempty SrcBits/Bits,
 * capability rules and unknown fields fail closed. IPv6 syntax is validated
 * in every build; IPv6 entries never match when TSC_ENABLE_IPV6 is disabled.
 * json must not overlap policy. */
int tsc_policy_parse_json(tsc_policy *policy, const uint8_t *json, size_t length);
/* Append a complete rule array (or null) to a validated policy without a second
 * policy-sized scratch buffer. Any error clears the ENTIRE policy. */
int tsc_policy_append_json(tsc_policy *policy, const uint8_t *json, size_t length);

/* Stateless inbound allow-rule check. src/dst are network-order bytes (4 or
 * 16). Pass host-order destination port for TCP/UDP/SCTP. ICMP has no port;
 * its port argument is ignored. Other protocols require a full 0..65535
 * destination range. Source ownership, local destination, framing, checksums
 * and fragmentation MUST be validated by the authenticated packet path first.
 * This function does not grant exceptions for TCP continuation or replies to
 * outbound traffic; connection tracking belongs to the client.
 * Returns 1 for allowed and 0 for denied, including invalid arguments. */
int tsc_policy_allows(const tsc_policy *policy, unsigned ip_version,
                      const uint8_t *src, const uint8_t *dst,
                      uint8_t ip_protocol, uint16_t destination_port);

#ifdef __cplusplus
}
#endif
#endif
