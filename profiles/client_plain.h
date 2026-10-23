#ifndef TAILSCALEC_CLIENT_PLAIN_CONFIG_H
#define TAILSCALEC_CLIENT_PLAIN_CONFIG_H
/* Authenticated Noise with a pinned coordinator key or trusted test LAN.
 * HTTPS and relay transport are deliberately excluded in this profile. */
#define TSC_ENABLE_CLIENT 1
#define TSC_APP_UDP 1
#define TSC_APP_TCP 0
#define TSC_ENABLE_TLS 0
#define TSC_ENABLE_DISCO 0
#define TSC_ENABLE_DERP 0
#define TSC_ENABLE_STUN 0
#define TSC_ENABLE_IPV6 0
#define TSC_MTU 1280
#define TSC_MAX_DATAGRAM_SIZE 1536
#define TSC_MAX_PEERS 2
#define TSC_MAX_PEER_ENDPOINTS 4
#define TSC_MAX_UDP_PORTS 2
#define TSC_MAX_FLOWS 4
#define TSC_MAX_FILTER_RULES 8
#define TSC_MAX_FILTER_SOURCES 4
#define TSC_MAX_FILTER_DESTINATIONS 4
#define TSC_CONTROL_RESPONSE_SIZE 16384
#define TSC_CONTROL_JSON_TOKENS 768
#endif
