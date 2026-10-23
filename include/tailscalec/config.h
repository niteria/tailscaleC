#ifndef TAILSCALEC_CONFIG_H
#define TAILSCALEC_CONFIG_H

/* Set this for the library AND its consumers; the CMake targets do so. */
#ifdef TSC_CONFIG_HEADER
#include TSC_CONFIG_HEADER
#endif

#ifndef TSC_ENABLE_STUN
#define TSC_ENABLE_STUN 1
#endif
#ifndef TSC_ENABLE_CLIENT
#define TSC_ENABLE_CLIENT 0
#endif
#ifndef TSC_APP_UDP
#define TSC_APP_UDP 1
#endif
#ifndef TSC_APP_TCP
#define TSC_APP_TCP 0
#endif
#ifndef TSC_ENABLE_TLS
#define TSC_ENABLE_TLS 1
#endif
#ifndef TSC_ENABLE_DISCO
#define TSC_ENABLE_DISCO 0
#endif
#ifndef TSC_ENABLE_DERP
#define TSC_ENABLE_DERP 0
#endif
#ifndef TSC_ENABLE_IPV6
#define TSC_ENABLE_IPV6 1
#endif
#ifndef TSC_MAX_DATAGRAM_SIZE
#define TSC_MAX_DATAGRAM_SIZE 1536
#endif
#ifndef TSC_MTU
#define TSC_MTU 1280
#endif
#ifndef TSC_MAX_PEERS
#define TSC_MAX_PEERS 8
#endif
#ifndef TSC_MAX_PEER_ENDPOINTS
#define TSC_MAX_PEER_ENDPOINTS 8
#endif
#ifndef TSC_CONTROL_MAX_ENDPOINTS
#define TSC_CONTROL_MAX_ENDPOINTS TSC_MAX_PEER_ENDPOINTS
#endif
#ifndef TSC_CONTROL_RESPONSE_SIZE
#define TSC_CONTROL_RESPONSE_SIZE 32768
#endif
#ifndef TSC_CONTROL_JSON_TOKENS
#define TSC_CONTROL_JSON_TOKENS 1024
#endif
#ifndef TSC_MAX_UDP_PORTS
#define TSC_MAX_UDP_PORTS 4
#endif
#ifndef TSC_MAX_FLOWS
#define TSC_MAX_FLOWS 16
#endif
#ifndef TSC_MAX_TCP_CONNECTIONS
#define TSC_MAX_TCP_CONNECTIONS 4
#endif
#ifndef TSC_MAX_TCP_LISTENERS
#define TSC_MAX_TCP_LISTENERS 2
#endif
#ifndef TSC_TCP_SEND_BUFFER
#define TSC_TCP_SEND_BUFFER 2048
#endif
#ifndef TSC_TCP_RECEIVE_BUFFER
#define TSC_TCP_RECEIVE_BUFFER 2048
#endif
/* Conservative default for small profiles; larger tunnels may opt in to
 * MTU-sized segments to reduce packet encryption and acknowledgement work. */
#ifndef TSC_TCP_MSS
#define TSC_TCP_MSS 536
#endif
#ifndef TSC_MAX_FILTER_RULES
#define TSC_MAX_FILTER_RULES 32
#endif
#ifndef TSC_DISCO_MAX_PROBES
#define TSC_DISCO_MAX_PROBES (2 * TSC_MAX_PEERS)
#endif
#ifndef TSC_DERP_MAX_HTTP_HEADER
#define TSC_DERP_MAX_HTTP_HEADER 1024
#endif
#ifndef TSC_DERP_MAX_FRAME_SIZE
#define TSC_DERP_MAX_FRAME_SIZE (TSC_MAX_DATAGRAM_SIZE + 256)
#endif
#ifndef TSC_DERP_HANDSHAKE_TIMEOUT_MS
#define TSC_DERP_HANDSHAKE_TIMEOUT_MS 10000
#endif
#ifndef TSC_DERP_IDLE_TIMEOUT_MS
#define TSC_DERP_IDLE_TIMEOUT_MS 120000
#endif
#ifndef TSC_STUN_MAX_ATTEMPTS
#define TSC_STUN_MAX_ATTEMPTS 4
#endif
#ifndef TSC_STUN_INITIAL_RTO_MS
#define TSC_STUN_INITIAL_RTO_MS 500
#endif

#if (TSC_ENABLE_STUN != 0 && TSC_ENABLE_STUN != 1) || \
    (TSC_ENABLE_IPV6 != 0 && TSC_ENABLE_IPV6 != 1)
#error "Feature switches must be 0 or 1"
#endif
#if (TSC_ENABLE_CLIENT != 0 && TSC_ENABLE_CLIENT != 1) || \
    (TSC_APP_UDP != 0 && TSC_APP_UDP != 1) || \
    (TSC_APP_TCP != 0 && TSC_APP_TCP != 1) || \
    (TSC_ENABLE_TLS != 0 && TSC_ENABLE_TLS != 1) || \
    (TSC_ENABLE_DISCO != 0 && TSC_ENABLE_DISCO != 1) || \
    (TSC_ENABLE_DERP != 0 && TSC_ENABLE_DERP != 1)
#error "Feature switches must be 0 or 1"
#endif
#if TSC_MAX_PEERS < 1 || TSC_MAX_PEERS > 256 || \
    TSC_MAX_PEER_ENDPOINTS < 1 || TSC_MAX_PEER_ENDPOINTS > 32
#error "Peer capacities are out of range"
#endif
#if TSC_MAX_UDP_PORTS < 1 || TSC_MAX_UDP_PORTS > 256 || \
    TSC_MAX_TCP_CONNECTIONS < 1 || TSC_MAX_TCP_CONNECTIONS > 256
#error "Application connection capacities are out of range"
#endif
#if TSC_ENABLE_CLIENT && (TSC_MTU < 256 || TSC_MTU > 1280 || \
    TSC_MAX_DATAGRAM_SIZE < ((TSC_MTU + 15) / 16) * 16 + 32)
#error "Client needs MTU 256..1280 and datagram storage >= padded MTU + 32"
#endif
#if TSC_APP_TCP && (TSC_MAX_TCP_CONNECTIONS > 255 || \
    TSC_MAX_TCP_LISTENERS < 1 || TSC_MAX_TCP_LISTENERS > 255 || \
    TSC_TCP_SEND_BUFFER < 1072 || TSC_TCP_SEND_BUFFER > 65535 || \
    TSC_TCP_RECEIVE_BUFFER < 536 || TSC_TCP_RECEIVE_BUFFER > 65535 || \
    TSC_TCP_MSS < 536 || TSC_TCP_MSS > TSC_MAX_DATAGRAM_SIZE - 40 || \
    TSC_TCP_SEND_BUFFER < 2 * TSC_TCP_MSS || \
    TSC_TCP_RECEIVE_BUFFER < TSC_TCP_MSS || \
    (TSC_ENABLE_CLIENT && TSC_TCP_MSS > TSC_MTU - 40) || \
    TSC_MAX_DATAGRAM_SIZE < 576 || (TSC_ENABLE_CLIENT && TSC_MTU < 576))
#error "TCP capacity/buffer/MTU settings are out of range"
#endif
#if TSC_MAX_FLOWS < 1 || TSC_MAX_FLOWS > 4096
#error "TSC_MAX_FLOWS must be between 1 and 4096"
#endif
#if TSC_MAX_DATAGRAM_SIZE < 64 || TSC_MAX_DATAGRAM_SIZE > 65507
#error "TSC_MAX_DATAGRAM_SIZE must be between 64 and 65507"
#endif
#if TSC_ENABLE_STUN
#if TSC_STUN_MAX_ATTEMPTS < 1 || TSC_STUN_MAX_ATTEMPTS > 10
#error "TSC_STUN_MAX_ATTEMPTS must be between 1 and 10"
#endif
#if TSC_STUN_INITIAL_RTO_MS < 1 || TSC_STUN_INITIAL_RTO_MS > 60000
#error "TSC_STUN_INITIAL_RTO_MS must be between 1 and 60000"
#endif
#endif

#endif
