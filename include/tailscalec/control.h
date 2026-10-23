#ifndef TAILSCALEC_CONTROL_H
#define TAILSCALEC_CONTROL_H

#include "tailscalec/policy.h"
#include "tailscalec/tsc.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TSC_MAX_PEERS
#define TSC_MAX_PEERS 8
#endif
#ifndef TSC_CONTROL_MAX_ENDPOINTS
#define TSC_CONTROL_MAX_ENDPOINTS 8
#endif
#ifndef TSC_CONTROL_RESPONSE_SIZE
#define TSC_CONTROL_RESPONSE_SIZE 32768
#endif
#ifndef TSC_CONTROL_JSON_TOKENS
#define TSC_CONTROL_JSON_TOKENS 1024
#endif

/* A bounded implementation of TS2021 control, not a local tailscaled wrapper.
 * Identity private keys must be securely generated and persisted by the caller.
 * Endpoints are UNDERLYING UDP addresses at which peers can reach this node.
 * Strings and platform callbacks must remain valid until close(). */
typedef struct {
  const char *url; /* http:// or https:// Headscale/Tailscale */
  const char *auth_key;
  /* Optional trusted 32-byte Noise key. Otherwise discovered at /key; HTTPS
   * authenticates discovery. Plain HTTP discovery is for trusted networks. */
  const uint8_t *server_public_key;
  const char *hostname;
  const char *ca_pem;
  size_t ca_pem_length;
  uint32_t timeout_ms; /* zero selects 10000 ms */
  uint8_t machine_private_key[32];
  uint8_t node_private_key[32];
  uint8_t disco_public_key[32];
  const tsc_platform *platform;
  const tsc_endpoint *endpoints;
  size_t endpoint_count;
  uint16_t preferred_derp; /* Home relay region, 0 when no relay is connected. */
  const uint8_t *endpoint_types; /* Optional tailcfg types, default Local (1). */
} tsc_control_config;

#if TSC_ENABLE_DERP
#ifndef TSC_MAX_DERP_REGIONS
#define TSC_MAX_DERP_REGIONS 64
#endif
#ifndef TSC_MAX_DERP_NODES
#define TSC_MAX_DERP_NODES 8
#endif
typedef struct {
  char hostname[128];
  uint8_t ipv4[4];
  uint16_t derp_port, stun_port;
  unsigned has_ipv4, stun_only;
} tsc_control_derp_node;
typedef struct {
  uint16_t id;
  size_t node_count;
  tsc_control_derp_node nodes[TSC_MAX_DERP_NODES];
} tsc_control_derp_region;
#if TSC_MAX_DERP_REGIONS < 1 || TSC_MAX_DERP_REGIONS > 256 || \
    TSC_MAX_DERP_NODES < 1 || TSC_MAX_DERP_NODES > 16
#error "DERP map capacities are out of range"
#endif
#endif

#if TSC_CONTROL_COMPACT_PEERS
typedef struct { uint8_t address[4]; uint16_t port; } tsc_control_endpoint;
static inline tsc_endpoint tsc_control_endpoint_load(const tsc_control_endpoint *p) {
  tsc_endpoint out = {0};
  out.family = TSC_AF_IPV4; out.port = p->port;
  for (unsigned i = 0; i < 4; ++i) out.address[i] = p->address[i];
  return out;
}
static inline void tsc_control_endpoint_store(tsc_control_endpoint *p, const tsc_endpoint *in) {
  p->port = in->port;
  for (unsigned i = 0; i < 4; ++i) p->address[i] = in->address[i];
}
#else
typedef tsc_endpoint tsc_control_endpoint;
static inline tsc_endpoint tsc_control_endpoint_load(const tsc_control_endpoint *p) { return *p; }
static inline void tsc_control_endpoint_store(tsc_control_endpoint *p, const tsc_endpoint *in) { *p = *in; }
#endif

typedef struct {
  uint64_t id;
  /* Monotonic deadline anchored to authenticated coordinator time. */
  union { uint64_t expires_at_ms; int64_t staging_expiry_unix_ms; };
  unsigned has_expiry;
  uint8_t public_key[32];
  uint8_t disco_key[32];
  uint8_t ipv4[4];
  uint8_t ipv6[16];
  unsigned has_ipv4;
  unsigned has_ipv6;
  unsigned online;
  tsc_control_endpoint endpoints[TSC_CONTROL_MAX_ENDPOINTS];
  size_t endpoint_count;
  uint16_t home_derp;
  char name[TSC_CONTROL_PEER_NAME_SIZE];
} tsc_control_peer;

typedef struct {
  uint8_t ipv4[4];
  uint8_t ipv6[16];
  unsigned has_ipv4;
  unsigned has_ipv6;
  uint64_t node_id;
  uint64_t expires_at_ms;
  unsigned has_expiry;
  tsc_policy policy;
#if TSC_CONTROL_DYNAMIC_PEERS
  tsc_control_peer *peers;
  size_t peer_capacity;
#else
  tsc_control_peer peers[TSC_MAX_PEERS];
#endif
  size_t peer_count;
  uint64_t generation;
  uint16_t home_derp;
  char name[128];
#if TSC_ENABLE_DERP
  tsc_control_derp_region derp_regions[TSC_MAX_DERP_REGIONS];
  size_t derp_region_count;
#endif
} tsc_control_map;

typedef struct {
  void *implementation;
} tsc_control;

/* Initialize control to {0}. Join is synchronous and uses bounded I/O. Poll
 * refreshes endpoints and opens a fresh full-map stream on the same encrypted
 * connection. The stream remains open between polls, keeping the node online.
 * Unsupported packet filters fail closed with TSC_ERR_UNSUPPORTED; no traffic
 * should be accepted after a failed update. */
int tsc_control_join(tsc_control *control, const tsc_control_config *config);
int tsc_control_poll(tsc_control *control);
/* No network I/O. Remove expired peers and increment map generation; an
 * expired local key clears traffic policy and returns TSC_ERR_PROTOCOL.
 * Expiring maps require authenticated ControlTime plus a monotonic callback. */
int tsc_control_expire(tsc_control *control);
/* Separate control maintenance, possibly blocking only when a refresh is due.
 * Call regularly outside a nonblocking packet loop. Maps older than max_age_ms
 * are replaced; queued streaming deltas are discarded during that refresh.
 * max_age_ms must be nonzero and platform.monotonic_ms must be available. */
int tsc_control_maintain(tsc_control *control, uint32_t max_age_ms);
int tsc_control_set_endpoints(tsc_control *control,
                               const tsc_endpoint *endpoints, size_t count);
int tsc_control_set_endpoints_typed(tsc_control *control,
    const tsc_endpoint *endpoints, const uint8_t *types, size_t count);
const tsc_control_map *tsc_control_get_map(const tsc_control *control);
const char *tsc_control_last_error(const tsc_control *control);
void tsc_control_close(tsc_control *control);
/* Fixed context allocation, excluding platform TCP/TLS/crypto provider heap. */
size_t tsc_control_memory_size(void);
/* Additional temporary allocation during join/map refresh, zero when the
 * configured fixed context already contains this storage. */
size_t tsc_control_scratch_size(void);

#ifdef __cplusplus
}
#endif
#endif
