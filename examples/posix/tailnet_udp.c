#define _POSIX_C_SOURCE 200809L
#include "tailscalec/client.h"
#include "tailscalec/socket.h"
#include "tailscalec/crypto.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if !TSC_ENABLE_CLIENT || !TSC_APP_UDP
#error "Build this example with TSC_ENABLE_CLIENT=1 and TSC_APP_UDP=1"
#endif

static volatile sig_atomic_t stopped;
static int echo_mode, received;
static const char *expected;
static size_t expected_length;

static void stop_handler(int signal_number)
{
    (void)signal_number;
    stopped = 1;
}

static void address_text(const tsc_endpoint *endpoint, char text[INET6_ADDRSTRLEN])
{
    if (!inet_ntop(AF_INET, endpoint->address, text, INET6_ADDRSTRLEN))
        strcpy(text, "invalid");
}

static void on_udp(void *user, tsc_udp *socket, const tsc_endpoint *source,
                     const void *payload, size_t length)
{
    char text[INET6_ADDRSTRLEN];
    (void)user;
    address_text(source, text);
    printf("RECEIVED %s:%u ", text, source->port);
    if (length) (void)fwrite(payload, 1, length, stdout);
    putchar('\n');
    fflush(stdout);
    if (!expected || (length == expected_length &&
                      memcmp(expected, payload, length) == 0)) received = 1;
    if (echo_mode) {
        int rc = tsc_udp_send(socket, source, payload, length);
        if (rc != TSC_OK) fprintf(stderr, "echo: %s\n", tsc_status_string(rc));
    }
}

static int parse_endpoint(const char *text, tsc_endpoint *endpoint, int allow_zero)
{
    char address[INET_ADDRSTRLEN];
    const char *colon = strrchr(text, ':');
    char *end;
    unsigned long port;
    size_t length;
    if (!colon || colon == text) return 0;
    length = (size_t)(colon - text);
    if (length >= sizeof(address)) return 0;
    memcpy(address, text, length);
    address[length] = 0;
    errno = 0;
    port = strtoul(colon + 1, &end, 10);
    if (errno || !colon[1] || *end || port > 65535 || (!allow_zero && !port))
        return 0;
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->family = TSC_AF_IPV4;
    endpoint->port = (uint16_t)port;
    return inet_pton(AF_INET, address, endpoint->address) == 1;
}

static int read_all(int fd, void *buffer, size_t length)
{
    uint8_t *bytes = buffer;
    while (length) {
        ssize_t count = read(fd, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        bytes += (size_t)count;
        length -= (size_t)count;
    }
    return 1;
}

static int write_all(int fd, const void *buffer, size_t length)
{
    const uint8_t *bytes = buffer;
    while (length) {
        ssize_t count = write(fd, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        bytes += (size_t)count;
        length -= (size_t)count;
    }
    return 1;
}

static int load_identity(const char *path, tsc_identity *identity)
{
    static const char magic[8] = {'T','S','C','K','E','Y','1',0};
    struct stat status;
    char header[8];
    int fd, ok;
    if (!path) return tsc_identity_generate(identity) == TSC_OK;
    fd = open(path, O_RDONLY | O_CLOEXEC
#ifdef O_NOFOLLOW
              | O_NOFOLLOW
#endif
              );
    if (fd >= 0) {
        ok = fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
             status.st_uid == getuid() && !(status.st_mode & 077) &&
             status.st_size == (off_t)(sizeof(header) + sizeof(*identity)) &&
             read_all(fd, header, sizeof(header)) &&
             memcmp(header, magic, sizeof(header)) == 0 &&
             read_all(fd, identity, sizeof(*identity));
        close(fd);
        return ok;
    }
    if (errno != ENOENT || tsc_identity_generate(identity) != TSC_OK) return 0;
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    ok = write_all(fd, magic, sizeof(magic)) &&
         write_all(fd, identity, sizeof(*identity)) && fsync(fd) == 0;
    if (close(fd) < 0) ok = 0;
    if (!ok) (void)unlink(path);
    return ok;
}

static char *read_ca(const char *path, size_t *length)
{
    struct stat status;
    char *bytes;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    if (fstat(fd, &status) < 0 || status.st_size < 1 || status.st_size > 1048576) {
        close(fd);
        return NULL;
    }
    *length = (size_t)status.st_size;
    bytes = malloc(*length + 1);
    if (!bytes || !read_all(fd, bytes, *length)) {
        free(bytes);
        close(fd);
        return NULL;
    }
    close(fd);
    bytes[*length] = 0;
    return bytes;
}

static int parse_key(const char *text, uint8_t key[32])
{
    size_t i;
    if (strlen(text) != 64) return 0;
    for (i = 0; i < 32; ++i) {
        unsigned j, value = 0;
        for (j = 0; j < 2; ++j) {
            unsigned char c = (unsigned char)text[i * 2 + j];
            unsigned digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else return 0;
            value = value * 16 + digit;
        }
        key[i] = (uint8_t)value;
    }
    return 1;
}

static unsigned number(const char *text, unsigned maximum)
{
    char *end;
    unsigned long value;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !*text || *end || !value || value > maximum) return 0;
    return (unsigned)value;
}

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s --control-url URL [--auth-key KEY] "
        "[--state-file FILE] [--name NAME] [--ca-file PEM] [--server-key HEX] "
        "[--bind IPV4:PORT] [--endpoint IPV4:PORT] "
        "[--listen-port PORT] [--echo | --send IPV4:PORT --message TEXT] "
        "[--timeout SECONDS] [--map-refresh SECONDS]\n", program);
}

int main(int argc, char **argv)
{
    static tsc_client client;
    tsc_socket outer = TSC_SOCKET_INITIALIZER;
    tsc_udp socket = {0};
    tsc_identity identity;
    uint8_t server_key[32];
    tsc_client_config config = {0};
    tsc_endpoint bind_address = { .family = TSC_AF_IPV4, .port = 41641 };
    tsc_endpoint endpoint = {0}, destination = {0}, own;
    const char *state_file = NULL, *ca_file = NULL, *message = "tailscaleC";
    unsigned listen_port = 12345, timeout = 30, map_refresh = 5;
    uint64_t deadline, next_send = 0, next_map;
    int i, rc = TSC_ERR_ARGUMENT, sending = 0, sent = 0, exit_status = 1;
    char *ca = NULL, text[INET6_ADDRSTRLEN];
    config.hostname = "tailscalec";
    config.auth_key = getenv("TSC_AUTH_KEY");
    config.control_url = getenv("TSC_CONTROL_URL");
    for (i = 1; i < argc; ++i) {
        const char *option = argv[i];
        if (strcmp(option, "--echo") == 0) { echo_mode = 1; continue; }
        if (strcmp(option, "--help") == 0) { usage(argv[0]); return 0; }
        if (++i >= argc) { usage(argv[0]); return 2; }
        if (strcmp(option, "--control-url") == 0) config.control_url = argv[i];
        else if (strcmp(option, "--auth-key") == 0) config.auth_key = argv[i];
        else if (strcmp(option, "--server-key") == 0) {
            if (!parse_key(argv[i], server_key)) goto arguments;
            config.server_public_key = server_key;
        }
        else if (strcmp(option, "--name") == 0) config.hostname = argv[i];
        else if (strcmp(option, "--state-file") == 0) state_file = argv[i];
        else if (strcmp(option, "--ca-file") == 0) ca_file = argv[i];
        else if (strcmp(option, "--message") == 0) message = argv[i];
        else if (strcmp(option, "--bind") == 0) {
            if (!parse_endpoint(argv[i], &bind_address, 1)) goto arguments;
        } else if (strcmp(option, "--endpoint") == 0) {
            if (!parse_endpoint(argv[i], &endpoint, 0)) goto arguments;
        } else if (strcmp(option, "--send") == 0) {
            if (!parse_endpoint(argv[i], &destination, 0)) goto arguments;
            sending = 1;
        } else if (strcmp(option, "--listen-port") == 0) {
            listen_port = number(argv[i], 65535);
            if (!listen_port && strcmp(argv[i], "0") != 0) goto arguments;
        } else if (strcmp(option, "--map-refresh") == 0) {
            map_refresh = number(argv[i], 86400);
            if (!map_refresh && strcmp(argv[i], "0") != 0) goto arguments;
        } else if (strcmp(option, "--timeout") == 0) {
            timeout = number(argv[i], 86400);
            if (!timeout) goto arguments;
        } else goto arguments;
    }
    if (!config.control_url || (sending && echo_mode) || strlen(message) > TSC_MTU - 28u)
        goto arguments;
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
    if (!load_identity(state_file, &identity)) {
        fprintf(stderr, "Cannot load/create private identity file (requires owner-only mode).\n");
        goto cleanup;
    }
    if (ca_file) {
        ca = read_ca(ca_file, &config.ca_pem_length);
        if (!ca) { fprintf(stderr, "Cannot read CA file.\n"); goto cleanup; }
        config.ca_pem = ca;
    }
    rc = tsc_socket_open(&outer, &bind_address);
    if (rc != TSC_OK) goto failed;
    rc = tsc_socket_local(&outer, &own);
    if (rc != TSC_OK) goto failed;
    printf("OUTER_PORT %u\n", own.port);
    if (!endpoint.port && bind_address.address[0]) endpoint = own;
    if (endpoint.port) {
        config.endpoints = &endpoint;
        config.endpoint_count = 1;
    }
    config.platform = tsc_socket_platform(&outer);
    config.tai64n_now = tsc_socket_tai64n_now;
    config.identity = &identity;
    config.control_timeout_ms = 10000;
    rc = tsc_client_init(&client, &config);
    if (rc != TSC_OK) goto failed;
    rc = tsc_client_join(&client);
    if (rc != TSC_OK) goto failed;
    rc = tsc_client_address(&client, &own);
    if (rc != TSC_OK) goto failed;
    address_text(&own, text);
    printf("JOINED %s\n", text);
    rc = tsc_udp_open(&client, &socket, (uint16_t)listen_port, on_udp, NULL);
    if (rc != TSC_OK) goto failed;
    printf("LISTENING %u\n", socket.port);
    if (sending) { expected = message; expected_length = strlen(message); }
    deadline = config.platform.monotonic_ms(config.platform.user) + timeout * 1000u;
    next_map = config.platform.monotonic_ms(config.platform.user) + map_refresh * 1000u;
    while (!stopped && config.platform.monotonic_ms(config.platform.user) < deadline) {
        uint64_t now = config.platform.monotonic_ms(config.platform.user);
        struct timespec pause = {0, 5000000};
        rc = tsc_client_poll(&client);
        if (rc < 0) goto failed;
        if (sending && now >= next_send) {
            rc = tsc_udp_send(&socket, &destination, message, strlen(message));
            if (rc < 0) goto failed;
            if (rc == TSC_OK && !sent) {
                printf("SENT %zu\n", strlen(message));
                sent = 1;
            }
            /* Repeat application datagrams to tolerate UDP loss, preserving
             * the example's request/reply contract. */
            next_send = now + (rc == TSC_OK ? 500u : 50u);
        }
        if (sending && received) { exit_status = 0; goto cleanup; }
        if (map_refresh && now >= next_map) {
            rc = tsc_client_maintain(&client, map_refresh * 1000u);
            if (rc != TSC_OK) goto failed;
            next_map = config.platform.monotonic_ms(config.platform.user) + map_refresh * 1000u;
        }
        (void)nanosleep(&pause, NULL);
    }
    if (!sending || stopped) exit_status = 0;
    else fprintf(stderr, "Timed out waiting for UDP reply.\n");
    goto cleanup;
arguments:
    usage(argv[0]);
    return 2;
failed:
    fprintf(stderr, "tailscaleC: %s (%d): %s\n", tsc_status_string(rc), rc,
              tsc_client_last_error(&client));
cleanup:
    tsc_client_close(&client);
    tsc_socket_close(&outer);
    tsc_crypto_zero(&identity, sizeof(identity));
    free(ca);
    return exit_status;
}
