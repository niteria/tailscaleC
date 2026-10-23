#define _POSIX_C_SOURCE 200809L
#include "tailscalec/client.h"
#include "tailscalec/socket.h"
#include "tailscalec/tcp.h"
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

#if !TSC_ENABLE_CLIENT || !TSC_APP_TCP
#error "Build this example with TSC_ENABLE_CLIENT=1 and TSC_APP_TCP=1"
#endif

static volatile sig_atomic_t stopped;
static int syn_sent;

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

static int send_ip(void *user, const void *packet, size_t length)
{
    int rc = tsc_client_send_ip(user, packet, length);
    const uint8_t *bytes = packet;
    size_t header = length ? (size_t)(bytes[0] & 15u) * 4u : 0;
    if (rc == TSC_OK && !syn_sent && length >= 40 && header + 14 <= length &&
        bytes[9] == 6 && (bytes[header + 13] & 2u)) {
        puts("SYN_SENT");
        syn_sent = 1;
    }
    /* A pending WireGuard handshake looks like packet loss to TCP. lwIP keeps
     * the unacknowledged segment and retransmits after its normal timer. */
    return rc == TSC_AGAIN ? TSC_OK : rc;
}

static int random_bytes(void *user, void *output, size_t length)
{
    tsc_client *client = user;
    return client->platform.random_bytes(client->platform.user, output, length);
}

static void receive_ip(void *user, const void *packet, size_t length)
{
    int rc = tsc_tcp_input(user, packet, length);
    if (rc < 0) fprintf(stderr, "TCP input: %s\n", tsc_status_string(rc));
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
        "[--state-file FILE] [--name NAME] [--ca-file PEM] "
        "[--bind IPV4:PORT] [--endpoint IPV4:PORT] "
        "[--listen-port PORT] [--echo | --send IPV4:PORT --message TEXT] "
        "[--timeout SECONDS]\n", program);
}

int main(int argc, char **argv)
{
    static tsc_client client;
    static tsc_tcp tcp;
    tsc_socket outer = TSC_SOCKET_INITIALIZER;
    tsc_identity identity;
    tsc_client_config config = {0};
    tsc_tcp_config tcp_config = {0};
    tsc_endpoint bind_address = { .family = TSC_AF_IPV4, .port = 41641 };
    tsc_endpoint endpoint = {0}, destination = {0}, own;
    tsc_tcp_handle connection = 0, listener = 0;
    const char *state_file = NULL, *ca_file = NULL, *message = "tailscaleC TCP";
    unsigned listen_port = 32123, timeout = 30;
    uint64_t deadline, next_map;
    size_t sent_total = 0, received_total = 0, pending_length = 0, pending_offset = 0;
    uint8_t buffer[1024];
    int i, rc = TSC_ERR_ARGUMENT, sending = 0, echo_mode = 0, exit_status = 1;
    int write_closed = 0, eof = 0;
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
            if (!listen_port) goto arguments;
        } else if (strcmp(option, "--timeout") == 0) {
            timeout = number(argv[i], 86400);
            if (!timeout) goto arguments;
        } else goto arguments;
    }
    if (!config.control_url || sending == echo_mode || !*message) goto arguments;
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
    memcpy(tcp_config.local_ipv4, own.address, 4);
    tcp_config.mtu = TSC_MTU;
    tcp_config.user = &client;
    tcp_config.send_ip = send_ip;
    tcp_config.random_bytes = random_bytes;
    rc = tsc_tcp_init(&tcp, &tcp_config,
                      config.platform.monotonic_ms(config.platform.user));
    if (rc != TSC_OK) goto failed;
    tsc_client_set_ip_handler(&client, receive_ip, &tcp);
    if (sending)
        rc = tsc_tcp_connect(&tcp, &destination, 0, &connection);
    else
        rc = tsc_tcp_listen(&tcp, (uint16_t)listen_port, &listener);
    if (rc != TSC_OK) goto failed;
    if (listener) printf("LISTENING %u\n", listen_port);
    deadline = config.platform.monotonic_ms(config.platform.user) + timeout * 1000u;
    next_map = config.platform.monotonic_ms(config.platform.user) + 5000;
    while (!stopped && config.platform.monotonic_ms(config.platform.user) < deadline) {
        uint64_t now = config.platform.monotonic_ms(config.platform.user);
        struct timespec pause = {0, 5000000};
        tsc_tcp_state state;
        rc = tsc_client_poll(&client);
        if (rc < 0) goto failed;
        rc = tsc_tcp_poll(&tcp, now);
        if (rc < 0) goto failed;
        if (listener && !connection) {
            rc = tsc_tcp_accept(&tcp, listener, &connection, NULL);
            if (rc < 0) goto failed;
            if (rc == TSC_OK) puts("CONNECTED");
        }
        if (connection) {
            rc = tsc_tcp_get_state(&tcp, connection, &state);
            if (rc < 0) goto failed;
            if (state == TSC_TCP_FAILED) { rc = TSC_ERR_IO; goto failed; }
            if (state == TSC_TCP_ESTABLISHED || state == TSC_TCP_EOF) {
                size_t count = 0;
                if (sending && sent_total < strlen(message)) {
                    rc = tsc_tcp_send(&tcp, connection, message + sent_total,
                                      strlen(message) - sent_total, &count);
                    if (rc < 0) goto failed;
                    sent_total += count;
                }
                if (!sending && pending_offset < pending_length) {
                    rc = tsc_tcp_send(&tcp, connection, buffer + pending_offset,
                                      pending_length - pending_offset, &count);
                    if (rc < 0) goto failed;
                    pending_offset += count;
                }
                if (!eof && (sending || pending_offset == pending_length)) {
                    rc = tsc_tcp_receive(&tcp, connection, buffer, sizeof(buffer), &count);
                    if (rc < 0) goto failed;
                    if (rc == TSC_OK) {
                        if (!count) eof = 1;
                        else if (sending) {
                            if (count > strlen(message) - received_total ||
                                memcmp(buffer, message + received_total, count) != 0) {
                                fprintf(stderr, "TCP echo payload mismatch.\n");
                                goto cleanup;
                            }
                            received_total += count;
                        } else {
                            received_total += count;
                            pending_length = count;
                            pending_offset = 0;
                        }
                    }
                }
                if (!write_closed && ((sending && sent_total == strlen(message) &&
                      received_total == strlen(message)) || (!sending && eof &&
                      pending_offset == pending_length))) {
                    rc = tsc_tcp_shutdown(&tcp, connection);
                    if (rc < 0) goto failed;
                    if (rc == TSC_OK) write_closed = 1;
                }
                if (sending && eof && write_closed) {
                    printf("SENT %zu\nRECEIVED %zu\n", sent_total, received_total);
                    exit_status = 0;
                    goto cleanup;
                }
                if (!sending && eof == 1 && write_closed) {
                    printf("RECEIVED %zu\n", received_total);
                    /* Keep polling to ACK the peer's orderly shutdown. */
                    eof = 2;
                }
            }
        }
        if (now >= next_map) {
            rc = tsc_client_maintain(&client, 5000);
            if (rc != TSC_OK) goto failed;
            next_map = config.platform.monotonic_ms(config.platform.user) + 5000;
        }
        (void)nanosleep(&pause, NULL);
    }
    if (!sending || stopped) exit_status = 0;
    else fprintf(stderr, "Timed out waiting for TCP reply.\n");
    goto cleanup;
arguments:
    usage(argv[0]);
    return 2;
failed:
    fprintf(stderr, "tailscaleC: %s (%d): %s\n", tsc_status_string(rc), rc,
              tsc_client_last_error(&client));
cleanup:
    tsc_client_set_ip_handler(&client, NULL, NULL);
    tsc_tcp_destroy(&tcp);
    tsc_client_close(&client);
    tsc_socket_close(&outer);
    memset(&identity, 0, sizeof(identity));
    free(ca);
    return exit_status;
}
