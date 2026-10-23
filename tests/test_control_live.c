/* Opt-in real Headscale registration/map integration test. Never logs auth keys.
 * TSC_TEST_CONTROL_URL and TSC_TEST_AUTH_KEY must name a disposable test tailnet.
 * A test CA can be supplied as TSC_TEST_CA_PEM (PEM contents). */
#include "tailscalec/control.h"
#include "tailscalec/crypto.h"
#include "../platform/system.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *url = getenv("TSC_TEST_CONTROL_URL");
    const char *auth = getenv("TSC_TEST_AUTH_KEY");
    if (!url || !auth) return 77;
    tsc_control control = {0};
    tsc_control_config config = {0};
    tsc_platform platform = {.monotonic_ms = tsc_system_monotonic_ms};
    config.platform = &platform;
    config.url = url; config.auth_key = auth;
    config.hostname = "tailscalec-control-test";
    config.ca_pem = getenv("TSC_TEST_CA_PEM");
    if (config.ca_pem) config.ca_pem_length = strlen(config.ca_pem);
    uint8_t disco_private[32];
    if (tsc_crypto_random(config.machine_private_key,32) ||
        tsc_crypto_random(config.node_private_key,32) ||
        tsc_crypto_random(disco_private,32) ||
        tsc_crypto_x25519_public(config.disco_public_key,disco_private)) return 1;
    tsc_crypto_zero(disco_private,sizeof(disco_private));
    int r = tsc_control_join(&control,&config);
    if (r) {fprintf(stderr,"join: %d %s\n",r,tsc_control_last_error(&control));tsc_control_close(&control);return 1;}
    const tsc_control_map *map = tsc_control_get_map(&control);
    if (!map || !map->has_ipv4) {tsc_control_close(&control);return 1;}
    printf("joined %u.%u.%u.%u peers=%zu rules=%u\n",map->ipv4[0],map->ipv4[1],map->ipv4[2],map->ipv4[3],map->peer_count,map->policy.rule_count);
    uint64_t generation=map->generation;
    r=tsc_control_poll(&control);
    if(r)fprintf(stderr,"poll: %d %s\n",r,tsc_control_last_error(&control));
    if(!r&&tsc_control_get_map(&control)->generation<=generation)r=1;
    tsc_control_close(&control);
    return r?1:0;
}
