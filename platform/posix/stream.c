#define _POSIX_C_SOURCE 200809L
#include "tailscalec/stream.h"
#include "../system.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__) || defined(__DragonFly__)
#define TSC_SOCKADDR_HAS_LENGTH 1
#endif

#ifndef TSC_ENABLE_TLS
#define TSC_ENABLE_TLS 1
#endif
#if TSC_ENABLE_TLS
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

typedef struct {
    int fd;
#if TSC_ENABLE_TLS
    SSL_CTX *context;
    SSL *tls;
    BIO_METHOD *bio_method;
#endif
} stream_impl;

static uint64_t now_ms(void)
{
    return tsc_system_monotonic_ms(NULL);
}

static int wait_ready(int fd, short events, uint64_t deadline)
{
    struct pollfd descriptor = { .fd = fd, .events = events };
    for (;;) {
        uint64_t now = now_ms();
        uint64_t left = now < deadline ? deadline - now : 0;
        int timeout = left > INT_MAX ? INT_MAX : (int)left;
        int rc = poll(&descriptor, 1, timeout);
        if (rc > 0) {
            if (descriptor.revents & POLLNVAL)
                return TSC_ERR_IO;
            /* HUP/ERR must reach recv/SSL so orderly EOF and real failures
             * are distinguished by the operation that owns the socket. */
            return TSC_OK;
        }
        if (rc == 0)
            return TSC_ERR_TIMEOUT;
        if (errno != EINTR)
            return TSC_ERR_IO;
    }
}

static ssize_t send_without_signal(int fd, const void *buffer, size_t length)
{
#ifdef MSG_NOSIGNAL
    return send(fd, buffer, length, MSG_NOSIGNAL);
#else
    /* BSD/macOS sockets have SO_NOSIGPIPE set during creation. */
    return send(fd, buffer, length, 0);
#endif
}

#if TSC_ENABLE_TLS
/* A private socket BIO lets TLS writes use MSG_NOSIGNAL without changing the
 * application's process-wide SIGPIPE disposition. The stream owns its fd. */
static int bio_create(BIO *bio)
{
    BIO_set_init(bio, 1);
    BIO_set_data(bio, NULL);
    return 1;
}

static int bio_destroy(BIO *bio)
{
    if (bio)
        BIO_set_data(bio, NULL);
    return 1;
}

static int bio_read(BIO *bio, char *out, int length)
{
    stream_impl *impl = BIO_get_data(bio);
    ssize_t count;
    if (!impl || !out || length <= 0)
        return 0;
    BIO_clear_retry_flags(bio);
    do {
        count = recv(impl->fd, out, (size_t)length, 0);
    } while (count < 0 && errno == EINTR);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        BIO_set_retry_read(bio);
    return (int)count;
}

static int bio_write(BIO *bio, const char *in, int length)
{
    stream_impl *impl = BIO_get_data(bio);
    ssize_t count;
    if (!impl || !in || length <= 0)
        return 0;
    BIO_clear_retry_flags(bio);
    do {
        count = send_without_signal(impl->fd, in, (size_t)length);
    } while (count < 0 && errno == EINTR);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        BIO_set_retry_write(bio);
    return (int)count;
}

static long bio_control(BIO *bio, int command, long number, void *pointer)
{
    (void)bio;
    (void)number;
    (void)pointer;
    return command == BIO_CTRL_FLUSH || command == BIO_CTRL_DUP ? 1 : 0;
}

static int add_trust(SSL_CTX *context, const char *pem, size_t length)
{
    BIO *input;
    int added = 0;
    if (!pem)
        return SSL_CTX_set_default_verify_paths(context) == 1 ?
                   TSC_OK : TSC_ERR_IO;
    while (length && pem[length - 1] == '\0')
        --length;
    input = BIO_new_mem_buf(pem, (int)length);
    if (!input)
        return TSC_ERR_SPACE;
    while (BIO_ctrl_pending(input)) {
        X509 *certificate;
        char *pending;
        long remaining = BIO_get_mem_data(input, &pending);
        if (remaining <= 0)
            break;
        if (*pending == ' ' || *pending == '\t' || *pending == '\r' ||
            *pending == '\n') {
            char ignored;
            if (BIO_read(input, &ignored, 1) != 1)
                goto invalid;
            continue;
        }
        ERR_clear_error();
        certificate = PEM_read_bio_X509(input, NULL, NULL, NULL);
        if (!certificate)
            goto invalid;
        if (X509_STORE_add_cert(SSL_CTX_get_cert_store(context), certificate) != 1) {
            unsigned long error = ERR_peek_last_error();
            if (ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                X509_free(certificate);
                goto invalid;
            }
            ERR_clear_error();
        }
        X509_free(certificate);
        ++added;
    }
    BIO_free(input);
    return added ? TSC_OK : TSC_ERR_PROTOCOL;
invalid:
    BIO_free(input);
    ERR_clear_error();
    return TSC_ERR_PROTOCOL;
}

static int start_tls(stream_impl *impl, const char *host,
                      const tsc_stream_options *options, uint64_t deadline)
{
    uint8_t numeric[16];
    BIO *bio;
    int rc;
    impl->context = SSL_CTX_new(TLS_client_method());
    if (!impl->context)
        return TSC_ERR_SPACE;
    if (!SSL_CTX_set_min_proto_version(impl->context, TLS1_2_VERSION))
        return TSC_ERR_IO;
    SSL_CTX_set_verify(impl->context, SSL_VERIFY_PEER, NULL);
    rc = add_trust(impl->context, options->ca_pem, options->ca_pem_length);
    if (rc != TSC_OK)
        return rc;
    impl->tls = SSL_new(impl->context);
    impl->bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "tailscalec socket");
    if (!impl->tls || !impl->bio_method)
        return TSC_ERR_SPACE;
    if (!BIO_meth_set_create(impl->bio_method, bio_create) ||
        !BIO_meth_set_destroy(impl->bio_method, bio_destroy) ||
        !BIO_meth_set_read(impl->bio_method, bio_read) ||
        !BIO_meth_set_write(impl->bio_method, bio_write) ||
        !BIO_meth_set_ctrl(impl->bio_method, bio_control))
        return TSC_ERR_IO;
    bio = BIO_new(impl->bio_method);
    if (!bio)
        return TSC_ERR_SPACE;
    BIO_set_data(bio, impl);
    SSL_set_bio(impl->tls, bio, bio);
    SSL_set_mode(impl->tls, SSL_MODE_ENABLE_PARTIAL_WRITE |
                             SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    X509_VERIFY_PARAM_set_hostflags(SSL_get0_param(impl->tls),
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (inet_pton(AF_INET, host, numeric) == 1 ||
        inet_pton(AF_INET6, host, numeric) == 1) {
        if (!X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(impl->tls), host))
            return TSC_ERR_ARGUMENT;
    } else if (!SSL_set1_host(impl->tls, host) ||
               !SSL_set_tlsext_host_name(impl->tls, host)) {
        return TSC_ERR_ARGUMENT;
    }
    for (;;) {
        int error;
        ERR_clear_error();
        rc = SSL_connect(impl->tls);
        if (rc == 1)
            return SSL_get_verify_result(impl->tls) == X509_V_OK ?
                       TSC_OK : TSC_ERR_PROTOCOL;
        error = SSL_get_error(impl->tls, rc);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
            return TSC_ERR_PROTOCOL;
        rc = wait_ready(impl->fd,
                         error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT,
                         deadline);
        if (rc != TSC_OK)
            return rc;
    }
}
#endif

static int valid_options(const tsc_stream_options *options)
{
    return options && options->timeout_ms && options->timeout_ms <= INT_MAX &&
           (options->use_tls == 0 || options->use_tls == 1) &&
           options->ca_pem_length <= INT_MAX &&
           ((!options->ca_pem && !options->ca_pem_length) ||
            (options->ca_pem && options->ca_pem_length));
}

void tsc_stream_close(tsc_stream *stream)
{
    stream_impl *impl;
    if (!stream || !stream->implementation)
        return;
    impl = stream->implementation;
    stream->implementation = NULL;
#if TSC_ENABLE_TLS
    /* Best-effort close_notify on the nonblocking socket; never wait for the
     * peer or retry if backpressure prevents sending the alert. */
    if (impl->tls && SSL_is_init_finished(impl->tls)) {
        ERR_clear_error();
        (void)SSL_shutdown(impl->tls);
    }
    SSL_free(impl->tls);
    BIO_meth_free(impl->bio_method);
    SSL_CTX_free(impl->context);
#endif
    if (impl->fd >= 0)
        close(impl->fd);
    free(impl);
}

static int connect_native(tsc_stream *stream, const struct sockaddr *address,
                           socklen_t length, const char *host,
                           const tsc_stream_options *options, uint64_t deadline)
{
    stream_impl *impl = calloc(1, sizeof(*impl));
    int flags, error, rc = TSC_ERR_IO;
    socklen_t error_length = sizeof(error);
    if (!impl)
        return TSC_ERR_SPACE;
    impl->fd = -1;
    stream->implementation = impl;
    impl->fd = socket(address->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (impl->fd < 0)
        goto fail;
    flags = fcntl(impl->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(impl->fd, F_SETFL, flags | O_NONBLOCK) < 0)
        goto fail;
    flags = fcntl(impl->fd, F_GETFD, 0);
    if (flags < 0 || fcntl(impl->fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        goto fail;
#ifdef SO_NOSIGPIPE
    error = 1;
    if (setsockopt(impl->fd, SOL_SOCKET, SO_NOSIGPIPE, &error, sizeof(error)) < 0)
        goto fail;
#endif
    if (connect(impl->fd, address, length) < 0) {
        if (errno != EINPROGRESS && errno != EINTR)
            goto fail;
        rc = wait_ready(impl->fd, POLLOUT, deadline);
        if (rc != TSC_OK)
            goto fail;
        rc = TSC_ERR_IO;
        if (getsockopt(impl->fd, SOL_SOCKET, SO_ERROR, &error, &error_length) < 0 ||
            error)
            goto fail;
    }
    if (options->use_tls) {
#if TSC_ENABLE_TLS
        rc = start_tls(impl, host, options, deadline);
        if (rc != TSC_OK)
            goto fail;
#else
        (void)host;
        rc = TSC_ERR_UNSUPPORTED;
        goto fail;
#endif
    }
    return TSC_OK;
fail:
    tsc_stream_close(stream);
    return rc;
}

int tsc_stream_connect(tsc_stream *stream, const char *host, uint16_t port,
                       const tsc_stream_options *options)
{
    struct addrinfo hints = { 0 }, *addresses = NULL, *address;
    char service[6];
    uint64_t deadline;
    int rc = TSC_ERR_IO;
    if (!stream || stream->implementation || !host || !host[0] || !port ||
        !valid_options(options))
        return TSC_ERR_ARGUMENT;
#if !TSC_ENABLE_TLS
    if (options->use_tls)
        return TSC_ERR_UNSUPPORTED;
#endif
    hints.ai_family = TSC_ENABLE_IPV6 ? AF_UNSPEC : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    (void)snprintf(service, sizeof(service), "%u", (unsigned)port);
    if (getaddrinfo(host, service, &hints, &addresses) != 0)
        return TSC_ERR_IO;
    deadline = now_ms() + options->timeout_ms;
    for (address = addresses; address; address = address->ai_next) {
        if (now_ms() >= deadline) {
            rc = TSC_ERR_TIMEOUT;
            break;
        }
        rc = connect_native(stream, address->ai_addr,
                             (socklen_t)address->ai_addrlen, host, options,
                             deadline);
        if (rc == TSC_OK || rc == TSC_ERR_PROTOCOL || rc == TSC_ERR_SPACE)
            break;
    }
    freeaddrinfo(addresses);
    return rc;
}

int tsc_stream_connect_address(tsc_stream *stream, const tsc_endpoint *address,
                               const char *host,
                               const tsc_stream_options *options)
{
    struct sockaddr_storage storage = { 0 };
    socklen_t length;
    if (!stream || stream->implementation || !address || !address->port ||
        !valid_options(options) || (options->use_tls && (!host || !host[0])))
        return TSC_ERR_ARGUMENT;
#if !TSC_ENABLE_TLS
    if (options->use_tls)
        return TSC_ERR_UNSUPPORTED;
#endif
    if (address->family == TSC_AF_IPV4) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&storage;
#ifdef TSC_SOCKADDR_HAS_LENGTH
        v4->sin_len = sizeof(*v4);
#endif
        v4->sin_family = AF_INET;
        v4->sin_port = htons(address->port);
        memcpy(&v4->sin_addr, address->address, 4);
        length = sizeof(*v4);
#if TSC_ENABLE_IPV6
    } else if (address->family == TSC_AF_IPV6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&storage;
#ifdef TSC_SOCKADDR_HAS_LENGTH
        v6->sin6_len = sizeof(*v6);
#endif
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(address->port);
        v6->sin6_scope_id = address->scope_id;
        memcpy(&v6->sin6_addr, address->address, 16);
        length = sizeof(*v6);
#endif
    } else {
        return TSC_ERR_UNSUPPORTED;
    }
    return connect_native(stream, (const struct sockaddr *)&storage, length,
                            host, options, now_ms() + options->timeout_ms);
}

static int transfer(tsc_stream *stream, void *buffer, size_t length,
                     size_t *transferred, uint32_t timeout_ms, int writing)
{
    stream_impl *impl;
    uint64_t deadline;
    if (transferred)
        *transferred = 0;
    if (!stream || !stream->implementation || !transferred ||
        (!buffer && length) || timeout_ms > INT_MAX)
        return TSC_ERR_ARGUMENT;
    if (!length)
        return TSC_OK;
    impl = stream->implementation;
    deadline = now_ms() + timeout_ms;
    if (length > INT_MAX)
        length = INT_MAX;
    for (;;) {
        ssize_t count;
        short events = writing ? POLLOUT : POLLIN;
#if TSC_ENABLE_TLS
        if (impl->tls) {
            int error;
            ERR_clear_error();
            count = writing ? SSL_write(impl->tls, buffer, (int)length) :
                              SSL_read(impl->tls, buffer, (int)length);
            if (count > 0) {
                *transferred = (size_t)count;
                return TSC_OK;
            }
            error = SSL_get_error(impl->tls, (int)count);
            if (error == SSL_ERROR_ZERO_RETURN)
                return writing ? TSC_ERR_IO : TSC_OK;
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                return TSC_ERR_PROTOCOL;
            events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        } else
#endif
        {
            do {
                count = writing ? send_without_signal(impl->fd, buffer, length) :
                                  recv(impl->fd, buffer, length, 0);
            } while (count < 0 && errno == EINTR);
            if (count >= 0) {
                *transferred = (size_t)count;
                return TSC_OK;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                return TSC_ERR_IO;
        }
        {
            int rc = wait_ready(impl->fd, events, deadline);
            if (rc != TSC_OK)
                return rc;
        }
    }
}

int tsc_stream_read(tsc_stream *stream, void *buffer, size_t capacity,
                    size_t *received, uint32_t timeout_ms)
{
    return transfer(stream, buffer, capacity, received, timeout_ms, 0);
}

int tsc_stream_write(tsc_stream *stream, const void *buffer, size_t length,
                     size_t *written, uint32_t timeout_ms)
{
    return transfer(stream, (void *)buffer, length, written, timeout_ms, 1);
}
