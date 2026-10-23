#include "tailscalec/packet.h"

#include <string.h>

static uint16_t read16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static void write16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

/* Each call starts on a 16-bit boundary. Fold every word so even arbitrary
 * lengths cannot overflow the accumulator, without unaligned host reads. */
static uint32_t checksum_add(uint32_t sum, const uint8_t *p, size_t length)
{
    while (length >= 2) {
        sum += read16(p);
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
        p += 2;
        length -= 2;
    }
    if (length != 0)
        sum += (uint32_t)p[0] << 8;
    return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t udp_checksum(const uint8_t src[4], const uint8_t dst[4],
                              const uint8_t *udp, size_t length)
{
    uint32_t sum = checksum_add(0, src, 4);
    sum = checksum_add(sum, dst, 4);
    sum += UINT32_C(17) + (uint32_t)length;
    return checksum_finish(checksum_add(sum, udp, length));
}

int tsc_packet_udp_encode(const uint8_t src[4], const uint8_t dst[4],
                          uint16_t src_port, uint16_t dst_port,
                          const void *payload, size_t length,
                          uint16_t identification, void *out, size_t capacity,
                          size_t *out_length)
{
    uint8_t addresses[8];
    uint8_t *ip = out;
    const size_t overhead = TSC_IPV4_HEADER_SIZE + TSC_UDP_HEADER_SIZE;
    size_t total;
    uint16_t checksum;
    if (out_length == NULL)
        return TSC_ERR_ARGUMENT;
    *out_length = 0;
    if (src == NULL || dst == NULL || out == NULL ||
        (payload == NULL && length != 0) || length > TSC_UDP_MAX_PAYLOAD)
        return TSC_ERR_ARGUMENT;
    total = overhead + length;
    if (capacity < total)
        return TSC_ERR_SPACE;

    /* Copy addresses and move payload before writing the header. This also
     * supports constructing a packet in a caller's existing payload buffer. */
    memcpy(addresses, src, 4);
    memcpy(addresses + 4, dst, 4);
    if (length != 0)
        memmove(ip + overhead, payload, length);
    memset(ip, 0, overhead);
    ip[0] = 0x45;
    write16(ip + 2, (uint16_t)total);
    write16(ip + 4, identification);
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 17;
    memcpy(ip + 12, addresses, sizeof(addresses));
    write16(ip + 10, checksum_finish(checksum_add(0, ip, TSC_IPV4_HEADER_SIZE)));
    write16(ip + 20, src_port);
    write16(ip + 22, dst_port);
    write16(ip + 24, (uint16_t)(TSC_UDP_HEADER_SIZE + length));
    checksum = udp_checksum(ip + 12, ip + 16, ip + 20,
                             TSC_UDP_HEADER_SIZE + length);
    write16(ip + 26, checksum != 0 ? checksum : UINT16_C(0xffff));
    *out_length = total;
    return TSC_OK;
}

int tsc_packet_udp_decode(const void *packet, size_t length,
                          tsc_udp_packet_view *view)
{
    const uint8_t *ip = packet;
    const uint8_t *udp;
    size_t header_length, udp_length;
    tsc_udp_packet_view result;
    if (packet == NULL || view == NULL)
        return TSC_ERR_ARGUMENT;
    if (length < TSC_IPV4_HEADER_SIZE || (ip[0] >> 4) != 4)
        return TSC_ERR_PROTOCOL;
    header_length = (size_t)(ip[0] & 0x0f) * 4;
    if (header_length < TSC_IPV4_HEADER_SIZE ||
        header_length > length || length - header_length < TSC_UDP_HEADER_SIZE ||
        read16(ip + 2) != length || ip[9] != 17 ||
        (ip[6] & 0xbf) != 0 || ip[7] != 0 ||
        checksum_finish(checksum_add(0, ip, header_length)) != 0)
        return TSC_ERR_PROTOCOL;
    udp = ip + header_length;
    udp_length = read16(udp + 4);
    if (udp_length < TSC_UDP_HEADER_SIZE || udp_length != length - header_length ||
        (read16(udp + 6) != 0 &&
         udp_checksum(ip + 12, ip + 16, udp, udp_length) != 0))
        return TSC_ERR_PROTOCOL;
    memcpy(result.src, ip + 12, sizeof(result.src));
    memcpy(result.dst, ip + 16, sizeof(result.dst));
    result.src_port = read16(udp);
    result.dst_port = read16(udp + 2);
    result.payload = udp + TSC_UDP_HEADER_SIZE;
    result.length = udp_length - TSC_UDP_HEADER_SIZE;
    *view = result;
    return TSC_OK;
}
