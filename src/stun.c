#include "tailscalec/stun.h"

#if TSC_ENABLE_STUN
#include <string.h>

static const uint8_t cookie[4] = { 0x21, 0x12, 0xa4, 0x42 };

static uint16_t read16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t fingerprint(const uint8_t *p, size_t length)
{
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < length; ++i) {
        crc ^= p[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
    }
    return (~crc) ^ UINT32_C(0x5354554e);
}

int tsc_stun_request(const uint8_t transaction[12], void *packet,
                     size_t capacity, size_t *length)
{
    uint8_t *out = packet;
    if (!transaction || !packet || !length)
        return TSC_ERR_ARGUMENT;
    *length = 0;
    if (capacity < TSC_STUN_REQUEST_SIZE)
        return TSC_ERR_SPACE;
    memset(out, 0, TSC_STUN_REQUEST_SIZE);
    out[1] = 1; /* Binding request */
    memcpy(out + 4, cookie, 4);
    memcpy(out + 8, transaction, 12);
    out[3] = 20; /* SOFTWARE (12 bytes) + FINGERPRINT (8 bytes). */
    out[20] = 0x80;
    out[21] = 0x22;
    out[23] = 8;
    memcpy(out + 24, "tailnode", 8);
    uint32_t crc = fingerprint(out, 32);
    out[32] = 0x80;
    out[33] = 0x28;
    out[35] = 4;
    out[36] = (uint8_t)(crc >> 24);
    out[37] = (uint8_t)(crc >> 16);
    out[38] = (uint8_t)(crc >> 8);
    out[39] = (uint8_t)crc;
    *length = TSC_STUN_REQUEST_SIZE;
    return TSC_OK;
}

static int decode_address(const uint8_t *p, size_t length, int xor_mapped,
                          const uint8_t transaction[12], tsc_endpoint *out)
{
    size_t count;
    if (length < 4 || p[0] != 0)
        return TSC_ERR_PROTOCOL;
    memset(out, 0, sizeof(*out));
    if (p[1] == 1) {
        count = 4;
        out->family = TSC_AF_IPV4;
    } else if (p[1] == 2) {
        count = 16;
        out->family = TSC_AF_IPV6;
    } else {
        return TSC_ERR_PROTOCOL;
    }
    if (length != 4 + count)
        return TSC_ERR_PROTOCOL;
    out->port = read16(p + 2);
    if (xor_mapped)
        out->port ^= 0x2112;
    for (size_t i = 0; i < count; ++i) {
        uint8_t mask = 0;
        if (xor_mapped)
            mask = i < 4 ? cookie[i] : transaction[i - 4];
        out->address[i] = p[4 + i] ^ mask;
    }
    /* Some STUN servers report IPv4 sources as ::ffff:a.b.c.d. Preserve IPv4
     * interoperability even when native IPv6 support is compiled out. */
    if (out->family == TSC_AF_IPV6) {
        static const uint8_t mapped_prefix[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
        if (memcmp(out->address, mapped_prefix, sizeof(mapped_prefix)) == 0) {
            memmove(out->address, out->address + 12, 4);
            memset(out->address + 4, 0, 12);
            out->family = TSC_AF_IPV4;
        }
    }
#if !TSC_ENABLE_IPV6
    if (out->family == TSC_AF_IPV6)
        return TSC_ERR_UNSUPPORTED;
#endif
    return TSC_OK;
}

int tsc_stun_response(const void *packet, size_t length,
                      const uint8_t transaction[12], tsc_endpoint *mapped)
{
    const uint8_t *p = packet;
    tsc_endpoint result = { 0 };
    int found = 0;
    int found_xor = 0;
    if (!packet || !transaction || !mapped)
        return TSC_ERR_ARGUMENT;
    if (length < 20 || read16(p) != 0x0101 ||
        memcmp(p + 4, cookie, 4) != 0 ||
        memcmp(p + 8, transaction, 12) != 0 ||
        (read16(p + 2) & 3) != 0 || (size_t)read16(p + 2) != length - 20)
        return TSC_ERR_PROTOCOL;

    for (size_t at = 20; at < length;) {
        uint16_t type;
        size_t size, padded;
        if (length - at < 4)
            return TSC_ERR_PROTOCOL;
        type = read16(p + at);
        size = read16(p + at + 2);
        at += 4;
        padded = (size + 3) & ~(size_t)3;
        if (padded > length - at)
            return TSC_ERR_PROTOCOL;
        /* Prefer XOR-MAPPED-ADDRESS; RFC 8489 uses the first duplicate. */
        if ((type == 0x0020 && !found_xor) || (type == 0x0001 && !found)) {
            int rc = decode_address(p + at, size, type == 0x0020,
                                    transaction, &result);
            if (rc != TSC_OK)
                return rc;
            found = 1;
            found_xor = type == 0x0020;
        }
        at += padded;
    }
    if (!found)
        return TSC_ERR_PROTOCOL;
    *mapped = result;
    return TSC_OK;
}

int tsc_stun_start(tsc_stun_client *client, const tsc_platform *platform,
                   const tsc_endpoint *server)
{
    tsc_platform selected_platform;
    tsc_endpoint selected_server;
    uint64_t now;
    int rc;
    if (!client || !platform || !server || !platform->udp_send ||
        !platform->udp_receive || !platform->monotonic_ms ||
        !platform->random_bytes || server->port == 0)
        return TSC_ERR_ARGUMENT;
    if (server->family != TSC_AF_IPV4 && server->family != TSC_AF_IPV6)
        return TSC_ERR_ARGUMENT;
#if !TSC_ENABLE_IPV6
    if (server->family == TSC_AF_IPV6)
        return TSC_ERR_UNSUPPORTED;
#endif
    /* Restarting with &client->platform / &client->server is valid. */
    selected_platform = *platform;
    selected_server = *server;
    memset(client, 0, sizeof(*client));
    client->platform = selected_platform;
    client->server = selected_server;
    client->retry_ms = TSC_STUN_INITIAL_RTO_MS;
    client->status = TSC_AGAIN;
    rc = selected_platform.random_bytes(selected_platform.user, client->transaction, 12);
    if (rc != TSC_OK) {
        client->status = rc < 0 ? rc : TSC_ERR_IO;
        return client->status;
    }
    now = selected_platform.monotonic_ms(selected_platform.user);
    client->next_attempt_ms = now;
    client->deadline_ms = now + (uint64_t)TSC_STUN_INITIAL_RTO_MS *
        (((uint64_t)1 << TSC_STUN_MAX_ATTEMPTS) - 1);
    return TSC_OK;
}

int tsc_stun_poll(tsc_stun_client *client, void *scratch, size_t capacity)
{
    tsc_endpoint from;
    size_t length = 0;
    uint64_t now;
    int rc;
    if (!client || !scratch || capacity < TSC_MAX_DATAGRAM_SIZE)
        return TSC_ERR_ARGUMENT;
    if (client->status != TSC_AGAIN)
        return client->status;
    rc = client->platform.udp_receive(client->platform.user, &from,
                                      scratch, capacity, &length);
    if (rc == TSC_OK && length <= capacity && client->attempts != 0 &&
        tsc_endpoint_equal(&from, &client->server) &&
        tsc_stun_response(scratch, length, client->transaction,
                          &client->mapped) == TSC_OK) {
        client->status = TSC_OK;
        return TSC_OK;
    }
    if (rc != TSC_OK && rc != TSC_AGAIN && rc != TSC_ERR_TRUNCATED) {
        client->status = rc < 0 ? rc : TSC_ERR_IO;
        return client->status;
    }
    now = client->platform.monotonic_ms(client->platform.user);
    if (now >= client->deadline_ms) {
        client->status = TSC_ERR_TIMEOUT;
        return client->status;
    }
    if (now < client->next_attempt_ms)
        return TSC_AGAIN;
    if (client->attempts >= TSC_STUN_MAX_ATTEMPTS) {
        client->status = TSC_ERR_TIMEOUT;
        return client->status;
    }
    rc = tsc_stun_request(client->transaction, scratch, capacity, &length);
    if (rc == TSC_OK)
        rc = client->platform.udp_send(client->platform.user, &client->server,
                                       scratch, length);
    if (rc == TSC_AGAIN)
        return TSC_AGAIN;
    if (rc != TSC_OK) {
        client->status = rc < 0 ? rc : TSC_ERR_IO;
        return client->status;
    }
    ++client->attempts;
    client->next_attempt_ms = now + client->retry_ms;
    client->retry_ms *= 2;
    return TSC_AGAIN;
}
#endif
