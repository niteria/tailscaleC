#ifndef ESP_PLATFORM
#define _POSIX_C_SOURCE 200809L
#endif
#include "tailscalec/socket.h"
#include "system.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#if defined(ESP_PLATFORM) && TSC_ENABLE_IPV6 && !LWIP_IPV6
#error "Enable CONFIG_LWIP_IPV6 in ESP-IDF, or set TSC_ENABLE_IPV6 to 0"
#endif

#if defined(ESP_PLATFORM) || defined(__APPLE__) || defined(__FreeBSD__) || \
    defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#define TSC_SOCKADDR_HAS_LENGTH 1
#endif

static int native_address(const tsc_endpoint *in, struct sockaddr_storage *out,
                           socklen_t *length)
{
    memset(out, 0, sizeof(*out));
    if (in->family == TSC_AF_IPV4) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)out;
#ifdef TSC_SOCKADDR_HAS_LENGTH
        v4->sin_len = sizeof(*v4);
#endif
        v4->sin_family = AF_INET;
        v4->sin_port = htons(in->port);
        memcpy(&v4->sin_addr, in->address, 4);
        *length = sizeof(*v4);
        return TSC_OK;
    }
#if TSC_ENABLE_IPV6
    if (in->family == TSC_AF_IPV6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)out;
#ifdef TSC_SOCKADDR_HAS_LENGTH
        v6->sin6_len = sizeof(*v6);
#endif
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(in->port);
        v6->sin6_scope_id = in->scope_id;
        memcpy(&v6->sin6_addr, in->address, 16);
        *length = sizeof(*v6);
        return TSC_OK;
    }
#endif
    return TSC_ERR_UNSUPPORTED;
}

static int portable_address(const struct sockaddr *in, socklen_t length,
                             tsc_endpoint *out)
{
    memset(out, 0, sizeof(*out));
    if (in->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)in;
        out->family = TSC_AF_IPV4;
        out->port = ntohs(v4->sin_port);
        memcpy(out->address, &v4->sin_addr, 4);
        return TSC_OK;
    }
#if TSC_ENABLE_IPV6
    if (in->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)in;
        out->family = TSC_AF_IPV6;
        out->port = ntohs(v6->sin6_port);
        out->scope_id = v6->sin6_scope_id;
        memcpy(out->address, &v6->sin6_addr, 16);
        return TSC_OK;
    }
#endif
    return TSC_ERR_UNSUPPORTED;
}

static int socket_error(void)
{
    return errno == EAGAIN || errno == EWOULDBLOCK ? TSC_AGAIN : TSC_ERR_IO;
}

int tsc_socket_open(tsc_socket *handle, const tsc_endpoint *address)
{
    struct sockaddr_storage native;
    socklen_t length;
    int fd, flags, rc;
    if (!handle || !address || handle->fd != -1)
        return TSC_ERR_ARGUMENT;
    rc = native_address(address, &native, &length);
    if (rc != TSC_OK)
        return rc;
    fd = socket(native.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return TSC_ERR_IO;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        goto fail;
#ifndef ESP_PLATFORM
    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        goto fail;
#endif
#if TSC_ENABLE_IPV6 && defined(IPV6_V6ONLY)
    if (address->family == TSC_AF_IPV6) {
        int enabled = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                       &enabled, sizeof(enabled)) < 0)
            goto fail;
    }
#endif
    if (bind(fd, (const struct sockaddr *)&native, length) < 0)
        goto fail;
    handle->fd = fd;
    return TSC_OK;
fail:
    close(fd);
    return TSC_ERR_IO;
}

void tsc_socket_close(tsc_socket *handle)
{
    if (handle && handle->fd >= 0) {
        int fd = handle->fd;
        handle->fd = -1;
        close(fd);
    }
}

int tsc_socket_local(const tsc_socket *handle, tsc_endpoint *address)
{
    struct sockaddr_storage native;
    socklen_t length = sizeof(native);
    if (!handle || handle->fd < 0 || !address)
        return TSC_ERR_ARGUMENT;
    if (getsockname(handle->fd, (struct sockaddr *)&native, &length) < 0)
        return TSC_ERR_IO;
    return portable_address((const struct sockaddr *)&native, length, address);
}

int tsc_socket_send(tsc_socket *handle, const tsc_endpoint *to,
                    const void *packet, size_t length)
{
    struct sockaddr_storage native;
    socklen_t address_length;
    ssize_t sent;
    int rc;
    if (!handle || handle->fd < 0 || !to || (!packet && length != 0))
        return TSC_ERR_ARGUMENT;
    if (length > TSC_MAX_DATAGRAM_SIZE)
        return TSC_ERR_SPACE;
    rc = native_address(to, &native, &address_length);
    if (rc != TSC_OK)
        return rc;
    do {
        sent = sendto(handle->fd, packet, length, 0,
                       (const struct sockaddr *)&native, address_length);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0)
        return socket_error();
    return (size_t)sent == length ? TSC_OK : TSC_ERR_IO;
}

int tsc_socket_receive(tsc_socket *handle, tsc_endpoint *from,
                       void *packet, size_t capacity, size_t *length)
{
    struct sockaddr_storage native;
    socklen_t address_length;
    ssize_t received;
    int rc;
    if (!handle || handle->fd < 0 || !from || !length || (!packet && capacity))
        return TSC_ERR_ARGUMENT;
    *length = 0;
    /* One extra byte detects oversized datagrams on POSIX AND lwIP, without
     * relying on recvmsg/MSG_TRUNC extensions. Never deliver a partial packet. */
    do {
        address_length = sizeof(native);
        received = recvfrom(handle->fd, handle->receive_buffer,
                             sizeof(handle->receive_buffer), 0,
                             (struct sockaddr *)&native, &address_length);
    } while (received < 0 && errno == EINTR);
    if (received < 0)
        return socket_error();
    if ((size_t)received > TSC_MAX_DATAGRAM_SIZE || (size_t)received > capacity)
        return TSC_ERR_TRUNCATED;
    rc = portable_address((const struct sockaddr *)&native, address_length, from);
    if (rc != TSC_OK)
        return rc;
    if (received != 0)
        memcpy(packet, handle->receive_buffer, (size_t)received);
    *length = (size_t)received;
    return TSC_OK;
}

int tsc_socket_resolve(const char *host, uint16_t port,
                       tsc_address_family family, tsc_endpoint *address)
{
    struct addrinfo hints = { 0 }, *result = NULL;
    int rc;
    if (!host || !address)
        return TSC_ERR_ARGUMENT;
    if (family == TSC_AF_IPV4) {
        hints.ai_family = AF_INET;
#if TSC_ENABLE_IPV6
    } else if (family == TSC_AF_IPV6) {
        hints.ai_family = AF_INET6;
#endif
    } else {
        return TSC_ERR_UNSUPPORTED;
    }
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    if (getaddrinfo(host, NULL, &hints, &result) != 0)
        return TSC_ERR_IO;
    rc = result ? portable_address(result->ai_addr, (socklen_t)result->ai_addrlen,
                                    address) : TSC_ERR_IO;
    if (rc == TSC_OK)
        address->port = port;
    if (result)
        freeaddrinfo(result);
    return rc;
}

static int adapter_send(void *user, const tsc_endpoint *to,
                         const void *packet, size_t length)
{
    return tsc_socket_send(user, to, packet, length);
}

static int adapter_receive(void *user, tsc_endpoint *from,
                            void *packet, size_t capacity, size_t *length)
{
    return tsc_socket_receive(user, from, packet, capacity, length);
}

tsc_platform tsc_socket_platform(tsc_socket *handle)
{
    tsc_platform platform = {
        .user = handle,
        .udp_send = adapter_send,
        .udp_receive = adapter_receive,
        .monotonic_ms = tsc_system_monotonic_ms,
        .random_bytes = tsc_system_random_bytes
    };
    return platform;
}
