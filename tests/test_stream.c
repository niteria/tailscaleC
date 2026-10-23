#define _POSIX_C_SOURCE 200809L
#include "tailscalec/stream.h"
#include "check.h"
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef TSC_ENABLE_TLS
#define TSC_ENABLE_TLS 1
#endif
#if TSC_ENABLE_TLS
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

typedef struct {
    int fd;
    uint16_t port;
} listener;

static uint64_t milliseconds(void)
{
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static listener listen_local(void)
{
    listener result;
    struct sockaddr_in address = { 0 };
    socklen_t length = sizeof(address);
    result.fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(result.fd >= 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(result.fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(listen(result.fd, 1) == 0);
    CHECK(getsockname(result.fd, (struct sockaddr *)&address, &length) == 0);
    result.port = ntohs(address.sin_port);
    return result;
}

static int accept_client(listener server)
{
    struct pollfd pfd = { .fd = server.fd, .events = POLLIN };
    struct timeval timeout = { .tv_sec = 3 };
    int fd;
    CHECK(poll(&pfd, 1, 3000) == 1);
    fd = accept(server.fd, NULL, NULL);
    CHECK(fd >= 0);
    close(server.fd);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    signal(SIGPIPE, SIG_IGN); /* Child server must survive rejected handshakes. */
    return fd;
}

static void finish_child(pid_t pid)
{
    int status;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void write_all(tsc_stream *stream, const void *data, size_t length)
{
    const uint8_t *bytes = data;
    size_t at = 0;
    while (at < length) {
        size_t count;
        CHECK(tsc_stream_write(stream, bytes + at, length - at, &count, 1000) ==
              TSC_OK);
        CHECK(count > 0 && count <= length - at);
        at += count;
    }
}

static void read_all(tsc_stream *stream, void *data, size_t length)
{
    uint8_t *bytes = data;
    size_t at = 0;
    while (at < length) {
        size_t count;
        CHECK(tsc_stream_read(stream, bytes + at, length - at, &count, 1000) ==
              TSC_OK);
        CHECK(count > 0 && count <= length - at);
        at += count;
    }
}

static void plain_stream(void)
{
    listener server = listen_local();
    tsc_stream stream = TSC_STREAM_INITIALIZER;
    tsc_stream_options options = { .timeout_ms = 1000 };
    tsc_endpoint endpoint = { .family = TSC_AF_IPV4,
                              .address = { 127, 0, 0, 1 },
                              .port = server.port };
    static const char payload[] = "hello\0world";
    char reply[sizeof(payload)];
    size_t count;
    uint64_t started;
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (!pid) {
        size_t at = 0;
        int fd = accept_client(server);
        while (at < sizeof(reply)) {
            ssize_t n = recv(fd, reply + at, sizeof(reply) - at, 0);
            CHECK(n > 0);
            at += (size_t)n;
        }
        CHECK(memcmp(reply, payload, sizeof(payload)) == 0);
        CHECK(send(fd, reply, sizeof(reply), 0) == (ssize_t)sizeof(reply));
        close(fd);
        _exit(0);
    }
    close(server.fd);
    CHECK(tsc_stream_connect_address(&stream, &endpoint, NULL, &options) == TSC_OK);
    CHECK(tsc_stream_connect(&stream, "127.0.0.1", server.port, &options) ==
          TSC_ERR_ARGUMENT);
    started = milliseconds();
    CHECK(tsc_stream_read(&stream, reply, sizeof(reply), &count, 40) ==
          TSC_ERR_TIMEOUT);
    CHECK(count == 0);
    CHECK(milliseconds() - started >= 20 && milliseconds() - started < 1000);
    CHECK(tsc_stream_read(&stream, reply, sizeof(reply), &count, 0) ==
          TSC_ERR_TIMEOUT);
    CHECK(tsc_stream_read(&stream, NULL, 0, &count, 0) == TSC_OK && count == 0);
    CHECK(tsc_stream_write(&stream, NULL, 0, &count, 0) == TSC_OK && count == 0);
    CHECK(tsc_stream_read(&stream, NULL, 1, &count, 0) == TSC_ERR_ARGUMENT);
    CHECK(tsc_stream_write(&stream, NULL, 1, &count, 0) == TSC_ERR_ARGUMENT);
    CHECK(tsc_stream_read(&stream, reply, sizeof(reply), &count, UINT32_MAX) ==
          TSC_ERR_ARGUMENT);
    write_all(&stream, payload, sizeof(payload));
    read_all(&stream, reply, sizeof(reply));
    CHECK(memcmp(reply, payload, sizeof(payload)) == 0);
    CHECK(tsc_stream_read(&stream, reply, sizeof(reply), &count, 1000) == TSC_OK);
    CHECK(count == 0);
    tsc_stream_close(&stream);
    tsc_stream_close(&stream);
    CHECK(stream.implementation == NULL);
    finish_child(pid);
}

static void write_backpressure(void)
{
    listener server = listen_local();
    tsc_stream stream = TSC_STREAM_INITIALIZER;
    tsc_stream_options options = { .timeout_ms = 1000 };
    char *payload = malloc(1024 * 1024);
    pid_t pid = fork();
    int rc = TSC_OK;
    size_t attempts;
    CHECK(payload != NULL && pid >= 0);
    memset(payload, 0x5a, 1024 * 1024);
    if (!pid) {
        struct timespec pause = { .tv_nsec = 300000000 };
        int fd = accept_client(server);
        /* The client must stop at its deadline when the peer stops consuming. */
        nanosleep(&pause, NULL);
        close(fd);
        free(payload);
        _exit(0);
    }
    close(server.fd);
    CHECK(tsc_stream_connect(&stream, "127.0.0.1", server.port, &options) == TSC_OK);
    for (attempts = 0; attempts < 64 && rc == TSC_OK; ++attempts) {
        size_t count;
        rc = tsc_stream_write(&stream, payload, 1024 * 1024, &count, 30);
        if (rc == TSC_OK)
            CHECK(count > 0);
        else
            CHECK(count == 0);
    }
    CHECK(rc == TSC_ERR_TIMEOUT);
    tsc_stream_close(&stream);
    free(payload);
    finish_child(pid);
}

static void invalid_arguments(void)
{
    tsc_stream stream = TSC_STREAM_INITIALIZER;
    tsc_stream_options options = { .timeout_ms = 100 };
    size_t count = 99;
    CHECK(tsc_stream_read(NULL, NULL, 0, &count, 1) == TSC_ERR_ARGUMENT);
    CHECK(count == 0);
    CHECK(tsc_stream_write(&stream, NULL, 0, &count, 1) == TSC_ERR_ARGUMENT);
    CHECK(tsc_stream_connect(&stream, NULL, 1, &options) == TSC_ERR_ARGUMENT);
    CHECK(tsc_stream_connect(&stream, "", 1, &options) == TSC_ERR_ARGUMENT);
    CHECK(tsc_stream_connect(&stream, "localhost", 0, &options) == TSC_ERR_ARGUMENT);
    CHECK(tsc_stream_connect(&stream, "localhost", 1, NULL) == TSC_ERR_ARGUMENT);
    options.timeout_ms = 0;
    CHECK(tsc_stream_connect(&stream, "localhost", 1, &options) == TSC_ERR_ARGUMENT);
    options.timeout_ms = UINT32_MAX;
    CHECK(tsc_stream_connect(&stream, "localhost", 1, &options) == TSC_ERR_ARGUMENT);
    options.timeout_ms = 100;
    options.use_tls = 2;
    CHECK(tsc_stream_connect(&stream, "localhost", 1, &options) == TSC_ERR_ARGUMENT);
    options.use_tls = 0;
    options.ca_pem_length = 1;
    CHECK(tsc_stream_connect(&stream, "localhost", 1, &options) == TSC_ERR_ARGUMENT);
#if !TSC_ENABLE_TLS
    options.ca_pem_length = 0;
    options.use_tls = 1;
    CHECK(tsc_stream_connect(&stream, "localhost", 1, &options) ==
          TSC_ERR_UNSUPPORTED);
#endif
    tsc_stream_close(NULL);
}

#if TSC_ENABLE_TLS
typedef struct {
    EVP_PKEY *key;
    X509 *certificate;
    char *pem;
    size_t pem_length;
} identity;

static void add_extension(X509 *certificate, int type, const char *value)
{
    X509V3_CTX context;
    X509_EXTENSION *extension;
    X509V3_set_ctx(&context, certificate, certificate, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid(NULL, &context, type, value);
    CHECK(extension != NULL);
    CHECK(X509_add_ext(certificate, extension, -1) == 1);
    X509_EXTENSION_free(extension);
}

static identity make_identity(int expired)
{
    identity result = { 0 };
    EVP_PKEY_CTX *keygen = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    X509_NAME *name;
    BIO *output;
    char *pem;
    long length;
    CHECK(keygen != NULL);
    CHECK(EVP_PKEY_keygen_init(keygen) == 1);
    CHECK(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keygen, NID_X9_62_prime256v1) == 1);
    CHECK(EVP_PKEY_keygen(keygen, &result.key) == 1);
    EVP_PKEY_CTX_free(keygen);
    result.certificate = X509_new();
    CHECK(result.certificate != NULL);
    CHECK(X509_set_version(result.certificate, 2) == 1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(result.certificate), 1) == 1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(result.certificate), -3600) != NULL);
    CHECK(X509_gmtime_adj(X509_getm_notAfter(result.certificate),
                           expired ? -60 : 86400) != NULL);
    CHECK(X509_set_pubkey(result.certificate, result.key) == 1);
    name = X509_get_subject_name(result.certificate);
    CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                     (const unsigned char *)"localhost",
                                     -1, -1, 0) == 1);
    CHECK(X509_set_issuer_name(result.certificate, name) == 1);
    add_extension(result.certificate, NID_basic_constraints, "critical,CA:TRUE");
    add_extension(result.certificate, NID_key_usage,
                    "critical,digitalSignature,keyCertSign");
    add_extension(result.certificate, NID_ext_key_usage, "serverAuth");
    add_extension(result.certificate, NID_subject_alt_name,
                    "DNS:localhost,IP:127.0.0.1");
    CHECK(X509_sign(result.certificate, result.key, EVP_sha256()) > 0);
    output = BIO_new(BIO_s_mem());
    CHECK(output != NULL);
    CHECK(PEM_write_bio_X509(output, result.certificate) == 1);
    length = BIO_get_mem_data(output, &pem);
    CHECK(length > 0);
    result.pem = malloc((size_t)length + 1);
    CHECK(result.pem != NULL);
    memcpy(result.pem, pem, (size_t)length);
    result.pem[length] = '\0';
    result.pem_length = (size_t)length;
    BIO_free(output);
    return result;
}

static void destroy_identity(identity *id)
{
    EVP_PKEY_free(id->key);
    X509_free(id->certificate);
    free(id->pem);
}

enum { TLS_ECHO, TLS_REJECT, TLS_TRUNCATE, TLS_STALL, TLS_OBSOLETE, TLS_BULK };

static pid_t start_tls_server(listener server, const identity *id, int mode)
{
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (!pid) {
        int fd = accept_client(server);
        SSL_CTX *context;
        SSL *tls;
        char request[4];
        if (mode == TLS_STALL) {
            struct timespec pause = { .tv_nsec = 300000000 };
            nanosleep(&pause, NULL);
            close(fd);
            _exit(0);
        }
        context = SSL_CTX_new(TLS_server_method());
        CHECK(context != NULL);
        CHECK(SSL_CTX_use_certificate(context, id->certificate) == 1);
        CHECK(SSL_CTX_use_PrivateKey(context, id->key) == 1);
        if (mode == TLS_OBSOLETE) {
            CHECK(SSL_CTX_set_min_proto_version(context, TLS1_VERSION) == 1);
            CHECK(SSL_CTX_set_max_proto_version(context, TLS1_1_VERSION) == 1);
        }
        tls = SSL_new(context);
        CHECK(tls != NULL && SSL_set_fd(tls, fd) == 1);
        if (mode == TLS_REJECT || mode == TLS_OBSOLETE) {
            CHECK(SSL_accept(tls) <= 0);
        } else {
            CHECK(SSL_accept(tls) == 1);
            if (mode == TLS_ECHO) {
                CHECK(SSL_read(tls, request, sizeof(request)) == sizeof(request));
                CHECK(memcmp(request, "ping", sizeof(request)) == 0);
                CHECK(SSL_write(tls, "pong", 4) == 4);
                (void)SSL_shutdown(tls);
            } else if (mode == TLS_BULK) {
                size_t at = 0;
                char buffer[4096];
                while (at < 65537) {
                    int n = SSL_read(tls, buffer, sizeof(buffer));
                    int sent = 0;
                    CHECK(n > 0);
                    while (sent < n) {
                        int count = SSL_write(tls, buffer + sent, n - sent);
                        CHECK(count > 0);
                        sent += count;
                    }
                    at += (size_t)n;
                }
                CHECK(at == 65537);
                (void)SSL_shutdown(tls);
            }
        }
        SSL_free(tls);
        SSL_CTX_free(context);
        close(fd);
        _exit(0);
    }
    close(server.fd);
    return pid;
}

static void tls_roundtrip(const identity *id, int use_address)
{
    listener server = listen_local();
    pid_t pid = start_tls_server(server, id, TLS_ECHO);
    tsc_stream stream = TSC_STREAM_INITIALIZER;
    tsc_stream_options options = { .timeout_ms = 1000, .use_tls = 1,
                                   .ca_pem = id->pem,
                                   .ca_pem_length = id->pem_length };
    tsc_endpoint endpoint = { .family = TSC_AF_IPV4,
                              .address = { 127, 0, 0, 1 },
                              .port = server.port };
    char reply[4];
    size_t count;
    if (use_address)
        CHECK(tsc_stream_connect_address(&stream, &endpoint, "localhost",
                                          &options) == TSC_OK);
    else
        CHECK(tsc_stream_connect(&stream, "127.0.0.1", server.port, &options) ==
              TSC_OK);
    CHECK(tsc_stream_read(&stream, reply, sizeof(reply), &count, 25) ==
          TSC_ERR_TIMEOUT);
    CHECK(count == 0);
    write_all(&stream, "ping", 4);
    read_all(&stream, reply, sizeof(reply));
    CHECK(memcmp(reply, "pong", 4) == 0);
    CHECK(tsc_stream_read(&stream, reply, sizeof(reply), &count, 1000) == TSC_OK);
    CHECK(count == 0);
    tsc_stream_close(&stream);
    finish_child(pid);
}

static void tls_rejected(const identity *id, int wrong_host, int trust)
{
    listener server = listen_local();
    pid_t pid = start_tls_server(server, id, TLS_REJECT);
    tsc_stream stream = TSC_STREAM_INITIALIZER;
    tsc_stream_options options = { .timeout_ms = 1000, .use_tls = 1 };
    tsc_endpoint endpoint = { .family = TSC_AF_IPV4,
                              .address = { 127, 0, 0, 1 },
                              .port = server.port };
    if (trust) {
        options.ca_pem = id->pem;
        options.ca_pem_length = id->pem_length + 1; /* Accept NUL in length. */
    }
    {
        int rc = tsc_stream_connect_address(
            &stream, &endpoint, wrong_host ? "wrong.invalid" : "localhost",
            &options);
        /* ESP-IDF without a compiled CA bundle explicitly requires a CA. */
        CHECK(rc == TSC_ERR_PROTOCOL || (!trust && rc == TSC_ERR_UNSUPPORTED));
    }
    CHECK(stream.implementation == NULL);
    finish_child(pid);
}

static void tls_malformed_ca(const identity *id)
{
    listener server = listen_local();
    pid_t pid = start_tls_server(server, id, TLS_REJECT);
    tsc_stream stream = TSC_STREAM_INITIALIZER;
    tsc_stream_options options = { .timeout_ms = 1000, .use_tls = 1,
                                   .ca_pem = "not a certificate",
                                   .ca_pem_length = 17 };
    CHECK(tsc_stream_connect(&stream, "127.0.0.1", server.port, &options) ==
          TSC_ERR_PROTOCOL);
    CHECK(stream.implementation == NULL);
    finish_child(pid);
}

static void tls_bulk(const identity *id)
{
    listener server = listen_local();
    pid_t pid = start_tls_server(server, id, TLS_BULK);
    tsc_stream stream = TSC_STREAM_INITIALIZER;
    tsc_stream_options options = { .timeout_ms = 1000, .use_tls = 1,
                                   .ca_pem = id->pem,
                                   .ca_pem_length = id->pem_length };
    unsigned char *payload = malloc(65537), *reply = malloc(65537);
    size_t i;
    CHECK(payload != NULL && reply != NULL);
    for (i = 0; i < 65537; ++i)
        payload[i] = (unsigned char)(i % 251);
    CHECK(tsc_stream_connect(&stream, "127.0.0.1", server.port, &options) == TSC_OK);
    write_all(&stream, payload, 65537);
    read_all(&stream, reply, 65537);
    CHECK(memcmp(payload, reply, 65537) == 0);
    tsc_stream_close(&stream);
    free(reply);
    free(payload);
    finish_child(pid);
}

static void tls_special(const identity *id, int mode)
{
    listener server = listen_local();
    pid_t pid = start_tls_server(server, id, mode);
    tsc_stream stream = TSC_STREAM_INITIALIZER;
    tsc_stream_options options = { .timeout_ms = mode == TLS_STALL ? 40 : 1000,
                                   .use_tls = 1, .ca_pem = id->pem,
                                   .ca_pem_length = id->pem_length };
    int rc = tsc_stream_connect(&stream, "127.0.0.1", server.port, &options);
    if (mode == TLS_STALL || mode == TLS_OBSOLETE) {
        CHECK(rc == (mode == TLS_STALL ? TSC_ERR_TIMEOUT : TSC_ERR_PROTOCOL));
        CHECK(stream.implementation == NULL);
    } else {
        char byte;
        size_t count;
        CHECK(rc == TSC_OK);
        CHECK(tsc_stream_read(&stream, &byte, 1, &count, 1000) == TSC_ERR_PROTOCOL);
        CHECK(count == 0);
        /* Also exercises OpenSSL's BIO write path after the peer has closed.
         * The process has default SIGPIPE disposition and must stay alive. */
        (void)tsc_stream_write(&stream, "x", 1, &count, 100);
        tsc_stream_close(&stream);
    }
    finish_child(pid);
}
#endif

int main(void)
{
    invalid_arguments();
    plain_stream();
    write_backpressure();
#if TSC_ENABLE_TLS
    {
        identity valid = make_identity(0);
        identity expired = make_identity(1);
        tls_roundtrip(&valid, 0);
        tls_roundtrip(&valid, 1);
        tls_rejected(&valid, 0, 0); /* An untrusted self-signed certificate. */
        tls_rejected(&valid, 1, 1); /* Trusted root, wrong server identity. */
        tls_rejected(&expired, 0, 1); /* Trusted certificate outside validity. */
        tls_special(&valid, TLS_STALL);
        tls_special(&valid, TLS_TRUNCATE);
        tls_special(&valid, TLS_OBSOLETE);
        tls_malformed_ca(&valid);
        tls_bulk(&valid);
        destroy_identity(&valid);
        destroy_identity(&expired);
    }
#endif
    puts("TCP/TLS stream tests passed");
    return 0;
}
