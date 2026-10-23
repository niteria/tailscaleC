#ifndef TAILSCALEC_CRYPTO_TEST_CONFIG_H
#define TAILSCALEC_CRYPTO_TEST_CONFIG_H
/* Exercise only the platform cryptographic provider, without a live tailnet. */
#define TSC_ENABLE_CLIENT 0
#define TSC_ENABLE_TLS 1
#define TSC_ENABLE_DISCO 0
#define TSC_ENABLE_DERP 0
#define TSC_ENABLE_STUN 0
#define TSC_APP_UDP 0
#define TSC_APP_TCP 0
#define TSC_ENABLE_IPV6 0
#endif
