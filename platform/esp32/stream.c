#include "tailscalec/stream.h"
#include "../system.h"
#include "sdkconfig.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lwip/netdb.h"
#include "lwip/sockets.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef TSC_ENABLE_TLS
#define TSC_ENABLE_TLS 1
#endif
#if TSC_ENABLE_TLS
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) || defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE) && CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#endif
#endif

typedef struct {
    int fd;
    int tls_active;
#if TSC_ENABLE_TLS
    mbedtls_ssl_context tls;
    mbedtls_ssl_config config;
    mbedtls_x509_crt ca;
#endif
} stream_impl;

static uint64_t now_ms(void)
{
    return tsc_system_monotonic_ms(NULL);
}

static int wait_ready(int fd, int writing, uint64_t deadline)
{
    for (;;) {
        fd_set descriptors;
        struct timeval timeout;
        uint64_t now = now_ms();
        uint64_t left = now < deadline ? deadline - now : 0;
        int rc;
        FD_ZERO(&descriptors);
        FD_SET(fd, &descriptors);
        timeout.tv_sec = (long)(left / 1000);
        timeout.tv_usec = (long)(left % 1000) * 1000;
        rc = select(fd + 1, writing ? NULL : &descriptors,
                     writing ? &descriptors : NULL, NULL, &timeout);
        if (rc > 0)
            return TSC_OK;
        if (!rc)
            return TSC_ERR_TIMEOUT;
        if (errno != EINTR)
            return TSC_ERR_IO;
    }
}

#if TSC_ENABLE_TLS
static int tls_random(void *user, unsigned char *buffer, size_t length)
{
    return tsc_system_random_bytes(user, buffer, length) == TSC_OK ?
               0 : MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
}

static int tls_send(void *user, const unsigned char *buffer, size_t length)
{
    stream_impl *impl = user;
    ssize_t count;
    do {
        count = send(impl->fd, buffer, length, MSG_NOSIGNAL);
    } while (count < 0 && errno == EINTR);
    if (count >= 0)
        return (int)count;
    return errno == EAGAIN || errno == EWOULDBLOCK ?
               MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_SEND_FAILED;
}

static int tls_receive(void *user, unsigned char *buffer, size_t length)
{
    stream_impl *impl = user;
    ssize_t count;
    do {
        count = recv(impl->fd, buffer, length, 0);
    } while (count < 0 && errno == EINTR);
    if (count >= 0)
        return (int)count;
    return errno == EAGAIN || errno == EWOULDBLOCK ?
               MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_RECV_FAILED;
}

static int start_tls(stream_impl *impl, const char *host,
                      const tsc_stream_options *options, uint64_t deadline)
{
    int rc;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) || defined(MBEDTLS_USE_PSA_CRYPTO)
    if (psa_crypto_init() != PSA_SUCCESS)
        return TSC_ERR_IO;
#endif
    if (mbedtls_ssl_config_defaults(&impl->config, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT))
        return TSC_ERR_IO;
    mbedtls_ssl_conf_min_tls_version(&impl->config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_authmode(&impl->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&impl->config, tls_random, NULL);
    if (options->ca_pem) {
        char *terminated;
        size_t length = options->ca_pem_length;
        while (length && options->ca_pem[length - 1] == '\0')
            --length;
        terminated = malloc(length + 1);
        if (!terminated)
            return TSC_ERR_SPACE;
        memcpy(terminated, options->ca_pem, length);
        terminated[length] = '\0';
        rc = mbedtls_x509_crt_parse(&impl->ca,
                                     (const unsigned char *)terminated,
                                     length + 1);
        free(terminated);
        /* Positive return values mean some certificates failed to parse. */
        if (rc != 0)
            return TSC_ERR_PROTOCOL;
        mbedtls_ssl_conf_ca_chain(&impl->config, &impl->ca, NULL);
    } else {
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE) && CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
        if (esp_crt_bundle_attach(&impl->config) != ESP_OK)
            return TSC_ERR_IO;
#else
        return TSC_ERR_UNSUPPORTED;
#endif
    }
    if (mbedtls_ssl_setup(&impl->tls, &impl->config) ||
        mbedtls_ssl_set_hostname(&impl->tls, host))
        return TSC_ERR_IO;
    mbedtls_ssl_set_bio(&impl->tls, impl, tls_send, tls_receive, NULL);
    for (;;) {
        rc = mbedtls_ssl_handshake(&impl->tls);
        if (!rc) {
            if (mbedtls_ssl_get_verify_result(&impl->tls))
                return TSC_ERR_PROTOCOL;
            impl->tls_active = 1;
            return TSC_OK;
        }
        if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE)
            return TSC_ERR_PROTOCOL;
        rc = wait_ready(impl->fd, rc == MBEDTLS_ERR_SSL_WANT_WRITE, deadline);
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
    if (impl->tls_active)
        (void)mbedtls_ssl_close_notify(&impl->tls); /* Nonblocking, best effort. */
    mbedtls_ssl_free(&impl->tls);
    mbedtls_ssl_config_free(&impl->config);
    mbedtls_x509_crt_free(&impl->ca);
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
#if TSC_ENABLE_TLS
    mbedtls_ssl_init(&impl->tls);
    mbedtls_ssl_config_init(&impl->config);
    mbedtls_x509_crt_init(&impl->ca);
#endif
    stream->implementation = impl;
    impl->fd = socket(address->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (impl->fd < 0 || impl->fd >= FD_SETSIZE)
        goto fail;
    flags = fcntl(impl->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(impl->fd, F_SETFL, flags | O_NONBLOCK) < 0)
        goto fail;
    if (connect(impl->fd, address, length) < 0) {
        if (errno != EINPROGRESS && errno != EINTR)
            goto fail;
        rc = wait_ready(impl->fd, 1, deadline);
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
        v4->sin_len = sizeof(*v4);
        v4->sin_family = AF_INET;
        v4->sin_port = htons(address->port);
        memcpy(&v4->sin_addr, address->address, 4);
        length = sizeof(*v4);
#if TSC_ENABLE_IPV6
    } else if (address->family == TSC_AF_IPV6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&storage;
        v6->sin6_len = sizeof(*v6);
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
        int want_write = writing;
#if TSC_ENABLE_TLS
        if (impl->tls_active) {
            count = writing ? mbedtls_ssl_write(&impl->tls, buffer, length) :
                              mbedtls_ssl_read(&impl->tls, buffer, length);
            if (count > 0) {
                *transferred = (size_t)count;
                return TSC_OK;
            }
            if (count == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                return writing ? TSC_ERR_IO : TSC_OK;
            /* An underlying EOF without authenticated close_notify is a
             * truncated TLS stream, not an orderly application EOF. */
            if (count != MBEDTLS_ERR_SSL_WANT_READ &&
                count != MBEDTLS_ERR_SSL_WANT_WRITE)
                return TSC_ERR_PROTOCOL;
            want_write = count == MBEDTLS_ERR_SSL_WANT_WRITE;
        } else
#endif
        {
            do {
                count = writing ? send(impl->fd, buffer, length, MSG_NOSIGNAL) :
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
            int rc = wait_ready(impl->fd, want_write, deadline);
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
