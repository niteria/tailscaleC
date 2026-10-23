#include "tailscalec/socket.h"
#include "tailscalec/stun.h"
#if TSC_ENABLE_CLIENT
#include "tailscalec/client.h"
#endif
#if TSC_APP_TCP
#include "tailscalec/tcp.h"
#endif
#if TSC_ENABLE_DISCO
#include "tailscalec/disco.h"
#endif
#if TSC_ENABLE_DERP
#include "tailscalec/derp.h"
#endif
#include <stdio.h>

int main(void)
{
    puts("Per-object storage for this build; sum only the objects your app uses.");
    printf("underlying UDP socket: %zu\n", sizeof(tsc_socket));
#if TSC_ENABLE_STUN
    printf("STUN client: %zu, plus %u scratch\n", sizeof(tsc_stun_client),
           (unsigned)TSC_MAX_DATAGRAM_SIZE);
#endif
#if TSC_ENABLE_CLIENT
    printf("client (includes WireGuard peers and packet buffers): %zu\n", sizeof(tsc_client));
    printf("control context (one separate allocation): %zu\n", tsc_control_memory_size());
    printf("temporary control scratch during join/refresh: %zu\n", tsc_control_scratch_size());
#if TSC_CONTROL_DYNAMIC_PEERS
    printf("dynamic directory: %zu bytes per peer, capacity limit %u (allocated as needed)\n",
           sizeof(tsc_control_peer), (unsigned)TSC_MAX_PEERS);
#endif
#if TSC_SESSION_CACHE
    printf("authenticated session cache: %u slots, plus one probationary slot; replay/discovery history allocated per known peer\n",
           (unsigned)TSC_MAX_SESSIONS);
#endif
    printf("WireGuard device: %zu; each peer: %zu (already in client)\n",
           sizeof(tsc_wg), sizeof(tsc_wg_peer));
    printf("policy: %zu (already in each control map)\n", sizeof(tsc_policy));
#if TSC_APP_UDP
    printf("each application UDP port: %zu\n", sizeof(tsc_udp));
#endif
#endif
#if TSC_APP_TCP
    printf("TCP caller context: %zu, plus private lwIP static pools\n", sizeof(tsc_tcp));
#endif
#if TSC_ENABLE_DISCO
    printf("DISCO context: %zu (already in client when enabled)\n", sizeof(tsc_disco));
#endif
    puts("Excluded: OS/lwIP socket state, TLS/crypto provider heap, task stacks and allocator metadata.");
    return 0;
}
