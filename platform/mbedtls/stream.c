#include "tailscalec/stream.h"
#include "../system.h"
#ifdef TSC_PLATFORM_LWIP
#include "lwip/errno.h"
#else
#include <errno.h>
#include <fcntl.h>
#endif
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef TSC_PLATFORM_LWIP
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#if TSC_ENABLE_TLS
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#endif

typedef struct {
    int fd, secured;
#if TSC_ENABLE_TLS
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt ca;
    uint8_t ip_identity[4];
    int verify_ip;
#endif
} implementation;

static uint64_t now_ms(void) { return tsc_system_monotonic_ms(NULL); }

static int wait_fd(int fd, int writing, uint64_t deadline)
{
    for (;;) {
        fd_set fds;
        uint64_t now = now_ms(), remaining = now < deadline ? deadline - now : 0;
        struct timeval timeout = {(long)(remaining / 1000), (long)(remaining % 1000) * 1000};
        FD_ZERO(&fds); FD_SET(fd, &fds);
        int r = select(fd + 1, writing ? NULL : &fds, writing ? &fds : NULL, NULL, &timeout);
        if (r > 0) return TSC_OK;
        if (!r) return TSC_ERR_TIMEOUT;
        if (errno != EINTR) return TSC_ERR_IO;
    }
}

#if TSC_ENABLE_TLS
/* mbedTLS 2.x checks DNS identities but does not match IP-address SANs. For a
 * literal IPv4 host, require an exact iPAddress SAN and preserve every other
 * chain/expiry/usage error. Numeric dNSName/CN entries cannot substitute for it. */
static int verify_identity(void *user, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    implementation *s = user;
    if (!depth && s->verify_ip) {
        int matched = 0;
        for (const mbedtls_x509_sequence *san = &crt->subject_alt_names; san; san = san->next)
            if (san->buf.tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7) && san->buf.len == 4 &&
                !memcmp(san->buf.p, s->ip_identity, 4)) matched = 1;
        if (matched) *flags &= ~MBEDTLS_X509_BADCERT_CN_MISMATCH;
        else *flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
    }
    return 0;
}

static int random_bytes(void *u, unsigned char *p, size_t n)
{
    return tsc_system_random_bytes(u, p, n) == TSC_OK ? 0 : MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
}
static int tls_send(void *u, const unsigned char *p, size_t n)
{
    implementation *s = u;
    int r;
    do { r = send(s->fd, p, n, MSG_NOSIGNAL); } while (r < 0 && errno == EINTR);
    if (r >= 0) return r;
    return errno == EAGAIN || errno == EWOULDBLOCK ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_SEND_FAILED;
}
static int tls_recv(void *u, unsigned char *p, size_t n)
{
    implementation *s = u;
    int r;
    do { r = recv(s->fd, p, n, 0); } while (r < 0 && errno == EINTR);
    if (r >= 0) return r;
    return errno == EAGAIN || errno == EWOULDBLOCK ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_RECV_FAILED;
}
static int tls_start(implementation *s, const char *host,
                     const tsc_stream_options *o, uint64_t deadline)
{
    if (!o->ca_pem || !o->ca_pem_length) return TSC_ERR_UNSUPPORTED;
    size_t n = o->ca_pem_length;
    while (n && !o->ca_pem[n - 1]) --n;
    char *pem = malloc(n + 1);
    if (!pem) return TSC_ERR_SPACE;
    memcpy(pem, o->ca_pem, n); pem[n] = 0;
    int r = mbedtls_x509_crt_parse(&s->ca, (const unsigned char *)pem, n + 1);
    free(pem);
    if (r) return TSC_ERR_PROTOCOL;
    if (mbedtls_ssl_config_defaults(&s->config, MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) return TSC_ERR_IO;
    mbedtls_ssl_conf_min_version(&s->config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_authmode(&s->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&s->config, random_bytes, NULL);
    s->verify_ip = inet_pton(AF_INET, host, s->ip_identity) == 1;
    mbedtls_ssl_conf_verify(&s->config, verify_identity, s);
    mbedtls_ssl_conf_ca_chain(&s->config, &s->ca, NULL);
    if (mbedtls_ssl_setup(&s->ssl, &s->config) || mbedtls_ssl_set_hostname(&s->ssl, host))
        return TSC_ERR_IO;
    mbedtls_ssl_set_bio(&s->ssl, s, tls_send, tls_recv, NULL);
    for (;;) {
        r = mbedtls_ssl_handshake(&s->ssl);
        if (!r) {
            if (mbedtls_ssl_get_verify_result(&s->ssl)) return TSC_ERR_PROTOCOL;
            s->secured = 1;
            return TSC_OK;
        }
        if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
            return TSC_ERR_PROTOCOL;
        r = wait_fd(s->fd, r == MBEDTLS_ERR_SSL_WANT_WRITE, deadline);
        if (r) return r;
    }
}
#endif

void tsc_stream_close(tsc_stream *stream)
{
    if (!stream || !stream->implementation) return;
    implementation *s = stream->implementation;
    stream->implementation = NULL;
#if TSC_ENABLE_TLS
    if (s->secured) (void)mbedtls_ssl_close_notify(&s->ssl);
    mbedtls_ssl_free(&s->ssl);
    mbedtls_ssl_config_free(&s->config);
    mbedtls_x509_crt_free(&s->ca);
#endif
    if (s->fd >= 0) close(s->fd);
    free(s);
}

static int valid(const tsc_stream_options *o)
{
    return o && o->timeout_ms && o->timeout_ms <= INT_MAX &&
        (o->use_tls == 0 || o->use_tls == 1) && o->ca_pem_length <= INT_MAX &&
        ((!o->ca_pem && !o->ca_pem_length) || (o->ca_pem && o->ca_pem_length));
}

static int connect_address(tsc_stream *stream, const struct sockaddr *addr,
    socklen_t len, const char *host, const tsc_stream_options *o, uint64_t deadline)
{
    implementation *s = calloc(1, sizeof(*s));
    int r = TSC_ERR_IO, error;
    socklen_t error_size = sizeof(error);
    if (!s) return TSC_ERR_SPACE;
    s->fd = -1;
    stream->implementation = s;
#if TSC_ENABLE_TLS
    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->config);
    mbedtls_x509_crt_init(&s->ca);
#else
    (void)host;
#endif
    s->fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (s->fd < 0 || s->fd >= FD_SETSIZE) goto failed;
    int flags = fcntl(s->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(s->fd, F_SETFL, flags | O_NONBLOCK) < 0) goto failed;
    if (connect(s->fd, addr, len) < 0) {
        if (errno != EINPROGRESS && errno != EINTR) goto failed;
        r = wait_fd(s->fd, 1, deadline);
        if (r) goto failed;
        r = TSC_ERR_IO;
        if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &error, &error_size) < 0 || error) goto failed;
    }
    if (o->use_tls) {
#if TSC_ENABLE_TLS
        r = tls_start(s, host, o, deadline);
#else
        r = TSC_ERR_UNSUPPORTED;
#endif
        if (r) goto failed;
    }
    return TSC_OK;
failed:
    tsc_stream_close(stream);
    return r;
}

int tsc_stream_connect(tsc_stream *stream, const char *host, uint16_t port,
                       const tsc_stream_options *o)
{
    struct addrinfo hints = {0}, *list = NULL;
    char service[6];
    int r = TSC_ERR_IO;
    if (!stream || stream->implementation || !host || !*host || !port || !valid(o))
        return TSC_ERR_ARGUMENT;
#if !TSC_ENABLE_TLS
    if (o->use_tls) return TSC_ERR_UNSUPPORTED;
#endif
    hints.ai_family = TSC_ENABLE_IPV6 ? AF_UNSPEC : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(service, sizeof(service), "%u", (unsigned)port);
    if (getaddrinfo(host, service, &hints, &list)) return TSC_ERR_IO;
    uint64_t deadline = now_ms() + o->timeout_ms;
    for (struct addrinfo *a = list; a; a = a->ai_next) {
        if (now_ms() >= deadline) { r = TSC_ERR_TIMEOUT; break; }
        r = connect_address(stream, a->ai_addr, a->ai_addrlen, host, o, deadline);
        if (r == TSC_OK || r == TSC_ERR_PROTOCOL || r == TSC_ERR_SPACE) break;
    }
    freeaddrinfo(list);
    return r;
}

int tsc_stream_connect_address(tsc_stream *stream, const tsc_endpoint *addr,
    const char *host, const tsc_stream_options *o)
{
    struct sockaddr_in native = {0};
    if (!stream || stream->implementation || !addr || !addr->port || !valid(o) ||
        (o->use_tls && (!host || !*host))) return TSC_ERR_ARGUMENT;
    if (addr->family != TSC_AF_IPV4) return TSC_ERR_UNSUPPORTED;
#if !TSC_ENABLE_TLS
    if (o->use_tls) return TSC_ERR_UNSUPPORTED;
#endif
#ifdef TSC_PLATFORM_LWIP
    native.sin_len = sizeof(native);
#endif
    native.sin_family = AF_INET;
    native.sin_port = htons(addr->port);
    memcpy(&native.sin_addr, addr->address, 4);
    return connect_address(stream, (const struct sockaddr *)&native, sizeof(native),
                           host, o, now_ms() + o->timeout_ms);
}

static int transfer(tsc_stream *stream, void *p, size_t n, size_t *done,
                     uint32_t timeout, int writing)
{
    if (done) *done = 0;
    if (!stream || !stream->implementation || !done || (!p && n) || timeout > INT_MAX)
        return TSC_ERR_ARGUMENT;
    if (!n) return TSC_OK;
    if (n > INT_MAX) n = INT_MAX;
    implementation *s = stream->implementation;
    uint64_t deadline = now_ms() + timeout;
    for (;;) {
        int r, want_write = writing;
#if TSC_ENABLE_TLS
        if (s->secured) {
            r = writing ? mbedtls_ssl_write(&s->ssl, p, n) : mbedtls_ssl_read(&s->ssl, p, n);
            if (r > 0) { *done = (size_t)r; return TSC_OK; }
            if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return writing ? TSC_ERR_IO : TSC_OK;
            if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
                return TSC_ERR_PROTOCOL;
            want_write = r == MBEDTLS_ERR_SSL_WANT_WRITE;
        } else
#endif
        {
            do { r = writing ? send(s->fd, p, n, MSG_NOSIGNAL) : recv(s->fd, p, n, 0); }
            while (r < 0 && errno == EINTR);
            if (r >= 0) { *done = (size_t)r; return TSC_OK; }
            if (errno != EAGAIN && errno != EWOULDBLOCK) return TSC_ERR_IO;
        }
        r = wait_fd(s->fd, want_write, deadline);
        if (r) return r;
    }
}
int tsc_stream_read(tsc_stream *s, void *p, size_t n, size_t *done, uint32_t timeout)
{ return transfer(s, p, n, done, timeout, 0); }
int tsc_stream_write(tsc_stream *s, const void *p, size_t n, size_t *done, uint32_t timeout)
{ return transfer(s, (void *)p, n, done, timeout, 1); }
