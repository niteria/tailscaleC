#define _POSIX_C_SOURCE 200809L
#include "tailscalec/socket.h"
#include "tailscalec/stun.h"
#include <stdio.h>

#if TSC_ENABLE_STUN
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv)
{
    tsc_socket socket = TSC_SOCKET_INITIALIZER;
    tsc_endpoint server, local = { .family = TSC_AF_IPV4 };
    tsc_stun_client client;
    uint8_t scratch[TSC_MAX_DATAGRAM_SIZE];
    tsc_platform platform;
    char *end;
    unsigned long port;
    int rc;
    if (argc != 3) {
        fprintf(stderr, "Usage: %s STUN_HOST PORT\n"
                        "Underlying network diagnostic; does not join a tailnet.\n",
                argv[0]);
        return 2;
    }
    errno = 0;
    port = strtoul(argv[2], &end, 10);
    if (errno || end == argv[2] || *end || port == 0 || port > 65535) {
        fprintf(stderr, "Invalid UDP port\n");
        return 2;
    }
    rc = tsc_socket_resolve(argv[1], (uint16_t)port, TSC_AF_IPV4, &server);
    if (rc != TSC_OK)
        goto done;
    rc = tsc_socket_open(&socket, &local);
    if (rc != TSC_OK)
        goto done;
    platform = tsc_socket_platform(&socket);
    rc = tsc_stun_start(&client, &platform, &server);
    if (rc != TSC_OK)
        goto done;
    printf("Caller storage: socket=%zu, STUN client=%zu, scratch=%zu bytes\n",
           sizeof(socket), sizeof(client), sizeof(scratch));
    do {
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000 };
        rc = tsc_stun_poll(&client, scratch, sizeof(scratch));
        if (rc == TSC_AGAIN)
            nanosleep(&delay, NULL);
    } while (rc == TSC_AGAIN);
    if (rc == TSC_OK) {
        char address[INET6_ADDRSTRLEN];
        int family = client.mapped.family == TSC_AF_IPV4 ? AF_INET : AF_INET6;
        if (!inet_ntop(family, client.mapped.address, address, sizeof(address))) {
            rc = TSC_ERR_IO;
            goto done;
        }
        printf("Server-observed UDP endpoint: %s:%u\n", address,
               (unsigned)client.mapped.port);
    }
done:
    tsc_socket_close(&socket);
    if (rc != TSC_OK)
        fprintf(stderr, "STUN probe: %s\n", tsc_status_string(rc));
    return rc == TSC_OK ? 0 : 1;
}
#else
int main(void)
{
    fprintf(stderr, "STUN is excluded by the selected configuration.\n");
    return 2;
}
#endif
