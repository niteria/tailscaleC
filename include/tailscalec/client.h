#ifndef TAILSCALEC_CLIENT_H
#define TAILSCALEC_CLIENT_H

#include "tailscalec/control.h"
#include "tailscalec/wireguard.h"
#if TSC_ENABLE_DISCO
#include "tailscalec/disco.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if TSC_ENABLE_CLIENT

/* Persist these keys securely to retain the node's identity across restarts.
 * The portable core never reads files or takes ownership of network setup. */
typedef struct {
    uint8_t machine_private[32];
    uint8_t node_private[32];
    uint8_t disco_private[32];
} tsc_identity;
int tsc_identity_generate(tsc_identity *identity);

struct tsc_client;
struct tsc_udp;
typedef struct tsc_client tsc_client;
typedef struct tsc_udp tsc_udp;

typedef void (*tsc_ip_receive_fn)(void *user, const void *packet, size_t length);
typedef void (*tsc_udp_receive_fn)(void *user, tsc_udp *socket,
                                  const tsc_endpoint *source,
                                  const void *payload, size_t length);
typedef int (*tsc_client_relay_send_fn)(void *user, const uint8_t node_key[32],
                                       const void *packet, size_t length);

/* Strings and CA bytes are borrowed until close. Identity keys, a pinned
 * server key and endpoint arrays are copied by init. Callback users and the
 * underlying UDP adapter must remain alive until close. */
typedef struct {
    const char *control_url;
    const char *auth_key;
    const uint8_t *server_public_key; /* Optional trusted 32-byte Noise key. */
    const char *hostname;
    const char *ca_pem;
    size_t ca_pem_length;
    uint32_t control_timeout_ms;
    const tsc_identity *identity;
    tsc_platform platform;
    /* Required: secure clock or persisted counter, strictly increasing across
     * reboots. See wireguard.h. Callback clock_user is independent of platform. */
    int (*tai64n_now)(void *clock_user, uint8_t timestamp[12]);
    void *clock_user;
    const tsc_endpoint *endpoints;
    size_t endpoint_count;
    /* Optional caller-owned DERP transport. Packets are always encrypted here.
     * Feed relayed incoming packets through tsc_client_receive_relay(). */
    tsc_client_relay_send_fn relay_send;
    void *relay_user;
    uint16_t preferred_derp;
    const uint8_t *endpoint_types; /* Copied at init; Local=1, STUN=2. */
} tsc_client_config;

#ifndef TSC_MAX_FLOWS
#define TSC_MAX_FLOWS 16
#endif
#if TSC_MAX_FLOWS < 1 || TSC_MAX_FLOWS > 1024
#error "TSC_MAX_FLOWS must be between 1 and 1024"
#endif

typedef struct {
    uint64_t expires_ms;
    uint8_t remote[4], protocol, active;
    uint16_t local_port, remote_port;
} tsc_client_flow;

typedef struct {
    unsigned active, has_ipv4, has_endpoint, initiate_pending;
    uint8_t public_key[32], ipv4[4];
    tsc_endpoint endpoint;
    uint64_t endpoint_millis;
    uint64_t last_used_ms;
    tsc_endpoint candidates[TSC_CONTROL_MAX_ENDPOINTS];
    size_t candidate_count;
} tsc_client_peer;

/* Caller-owned, bounded storage. Initialize to {0}; serialize every call on
 * one event loop. Do not copy a live client. Callback payloads are borrowed
 * until callback return. UDP callbacks may send or close their own socket.
 * The selected configuration header must be identical for every consumer. */
struct tsc_client {
    tsc_platform platform;
    tsc_control control;
    tsc_control_config control_config;
    tsc_identity identity;
    uint8_t server_public_key[32];
    int (*tai64n_now)(void *, uint8_t[12]);
    void *clock_user;
    tsc_wg wireguard;
    tsc_wg_peer wg_peers[TSC_CLIENT_PEER_SLOTS];
    tsc_client_peer peers[TSC_CLIENT_PEER_SLOTS];
#if TSC_SESSION_CACHE
    struct tsc_peer_history *history;
    size_t history_count;
    size_t sweep_cursor;
    uint64_t next_sweep_ms;
    uint8_t sweep_key[32];
    unsigned probe_generation;
#endif
    tsc_endpoint endpoints[TSC_CONTROL_MAX_ENDPOINTS];
    uint8_t endpoint_types[TSC_CONTROL_MAX_ENDPOINTS];
    size_t endpoint_count;
#if TSC_ENABLE_DISCO
    tsc_disco disco;
#endif
#if TSC_APP_UDP
    tsc_udp *udp_ports[TSC_MAX_UDP_PORTS];
#endif
    tsc_ip_receive_fn ip_receive;
    void *ip_user;
    tsc_client_relay_send_fn relay_send;
    void *relay_user;
    uint8_t ipv4[4];
    unsigned initialized, joined, allow_traffic;
    uint16_t next_port, next_identification;
    uint64_t map_generation;
    uint8_t policy_digest[32];
    tsc_client_flow flows[TSC_MAX_FLOWS];
    uint8_t receive_buffer[TSC_MAX_DATAGRAM_SIZE];
    uint8_t inner_buffer[TSC_MAX_DATAGRAM_SIZE];
    uint8_t send_buffer[TSC_MAX_DATAGRAM_SIZE];
#if TSC_APP_UDP
    uint8_t packet_buffer[TSC_MTU];
#endif
};

/* init is local only. join performs authenticated registration and installs
 * the coordinator's map; a successful init never implies tailnet membership.
 * join and refresh_map can block, bounded by control_timeout_ms. A failed map
 * update disables all application traffic until a successful update/join. */
int tsc_client_init(tsc_client *client, const tsc_client_config *config);
int tsc_client_join(tsc_client *client);
int tsc_client_refresh_map(tsc_client *client);
/* Call regularly to bound control-map age. This performs network I/O only
 * when max_age_ms elapses, bounded by control_timeout_ms. Nonblocking poll,
 * sends and receives always enforce known local/peer expiry independently. */
int tsc_client_maintain(tsc_client *client, uint32_t max_age_ms);
/* Replace advertised UNDERLYING addresses after DHCP/STUN changes. No network
 * I/O occurs here; the next refresh_map publishes them to the coordinator. */
int tsc_client_set_endpoints(tsc_client *client, const tsc_endpoint *endpoints,
                               size_t count);
int tsc_client_set_endpoints_typed(tsc_client *client, const tsc_endpoint *endpoints,
                                  const uint8_t *types, size_t count);
void tsc_client_close(tsc_client *client);
int tsc_client_address(const tsc_client *client, tsc_endpoint *address);
const char *tsc_client_last_error(const tsc_client *client);
/* Nonblocking packet and timer processing, with a bounded receive budget.
 * It enforces key expiry but does not refresh the control map; schedule
 * maintain or refresh_map separately. New mapped peers receive an initial
 * handshake, allowing listening-only nodes to recover after a restart. */
int tsc_client_poll(tsc_client *client);
/* Optional stack hook (e.g. TCP). Only authenticated, source-authorized IPv4
 * packets addressed to this node reach the handler. UDP bound ports take
 * precedence. send_ip encrypts a complete IPv4 packet synchronously; AGAIN
 * means handshake/route is pending and the caller must retain/retry data. */
void tsc_client_set_ip_handler(tsc_client *client, tsc_ip_receive_fn receive,
                                void *user);
int tsc_client_send_ip(tsc_client *client, const void *packet, size_t length);
int tsc_client_receive_relay(tsc_client *client, const uint8_t node_key[32],
                              const void *packet, size_t length);
int tsc_client_set_peer_endpoint(tsc_client *client, const uint8_t node_key[32],
                                  const tsc_endpoint *endpoint);

#if TSC_APP_UDP
/* Initialize sockets to {0}; port zero selects a bounded ephemeral port.
 * No OS socket is opened: these ports exist inside the encrypted tailnet. */
struct tsc_udp {
    tsc_client *client;
    uint16_t port;
    tsc_udp_receive_fn receive;
    void *user;
};
int tsc_udp_open(tsc_client *client, tsc_udp *socket, uint16_t port,
                  tsc_udp_receive_fn receive, void *user);
void tsc_udp_close(tsc_udp *socket);
int tsc_udp_send(tsc_udp *socket, const tsc_endpoint *destination,
                  const void *payload, size_t length);
#endif

#endif /* TSC_ENABLE_CLIENT */
#ifdef __cplusplus
}
#endif
#endif
