#include "tailscalec/packet.h"
#include "check.h"

#include <string.h>

static const uint8_t src[] = { 100, 64, 0, 1 };
static const uint8_t dst[] = { 100, 64, 0, 2 };
/* Independently generated with Python struct.pack and a one's-complement
 * checksum. Includes odd payload length to exercise the final high byte. */
static const uint8_t golden[] = {
    0x45,0x00,0x00,0x21,0x12,0x34,0x40,0x00,0x40,0x11,0x60,0x15,
    0x64,0x40,0x00,0x01,0x64,0x40,0x00,0x02,0x30,0x39,0xd4,0x31,
    0x00,0x0d,0x09,0x1f,0x61,0x62,0x63,0x64,0x65
};

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

/* Independent bounded test oracle: defer folding until all words are added,
 * unlike the codec, and explicitly supply an odd byte's zero padding. */
static uint16_t checksum(const uint8_t *p, size_t length)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < length; i += 2)
        sum += (uint32_t)p[i] * 256 + (i + 1 < length ? p[i + 1] : 0);
    sum = (sum & 65535) + sum / 65536;
    sum = (sum & 65535) + sum / 65536;
    return (uint16_t)(65535 - sum);
}

static void repair_ip(uint8_t *packet)
{
    packet[10] = packet[11] = 0;
    put16(packet + 10, checksum(packet, (size_t)(packet[0] & 15) * 4));
}

static void reject(const void *packet, size_t length)
{
    tsc_udp_packet_view view, before;
    memset(&view, 0xa5, sizeof(view));
    memcpy(&before, &view, sizeof(view));
    CHECK(tsc_packet_udp_decode(packet, length, &view) == TSC_ERR_PROTOCOL);
    CHECK(memcmp(&view, &before, sizeof(view)) == 0);
}

static void golden_and_arguments(void)
{
    uint8_t packet[sizeof(golden)], before[sizeof(golden)];
    tsc_udp_packet_view view;
    size_t size = 123;
    CHECK(tsc_packet_udp_encode(src, dst, 12345, 54321, "abcde", 5,
                               0x1234, packet, sizeof(packet), &size) == TSC_OK);
    CHECK(size == sizeof(golden));
    CHECK(memcmp(packet, golden, sizeof(golden)) == 0);
    CHECK(tsc_packet_udp_decode(packet, size, &view) == TSC_OK);
    CHECK(memcmp(view.src, src, 4) == 0 && memcmp(view.dst, dst, 4) == 0);
    CHECK(view.src_port == 12345 && view.dst_port == 54321);
    CHECK(view.length == 5 && view.payload == packet + 28);
    CHECK(memcmp(view.payload, "abcde", 5) == 0);

    memset(packet, 0x5a, sizeof(packet));
    memcpy(before, packet, sizeof(packet));
    for (size_t capacity = 0; capacity < sizeof(packet); ++capacity) {
        size = 123;
        CHECK(tsc_packet_udp_encode(src, dst, 12345, 54321, "abcde", 5,
                                   0x1234, packet, capacity, &size) == TSC_ERR_SPACE);
        CHECK(size == 0 && memcmp(packet, before, sizeof(packet)) == 0);
    }
    CHECK(tsc_packet_udp_encode(NULL, dst, 1, 2, "a", 1, 0,
                               packet, sizeof(packet), &size) == TSC_ERR_ARGUMENT);
    CHECK(size == 0);
    CHECK(tsc_packet_udp_encode(src, NULL, 1, 2, "a", 1, 0,
                               packet, sizeof(packet), &size) == TSC_ERR_ARGUMENT);
    CHECK(tsc_packet_udp_encode(src, dst, 1, 2, NULL, 1, 0,
                               packet, sizeof(packet), &size) == TSC_ERR_ARGUMENT);
    CHECK(tsc_packet_udp_encode(src, dst, 1, 2, "a", 1, 0,
                               NULL, sizeof(packet), &size) == TSC_ERR_ARGUMENT);
    CHECK(tsc_packet_udp_encode(src, dst, 1, 2, "a", 1, 0,
                               packet, sizeof(packet), NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_packet_udp_encode(src, dst, 1, 2, "a", TSC_UDP_MAX_PAYLOAD + 1u, 0,
                               packet, SIZE_MAX, &size) == TSC_ERR_ARGUMENT);
    CHECK(tsc_packet_udp_encode(src, dst, 1, 2, "a", SIZE_MAX, 0,
                               packet, SIZE_MAX, &size) == TSC_ERR_ARGUMENT);
    CHECK(memcmp(packet, before, sizeof(packet)) == 0);
    CHECK(tsc_packet_udp_decode(NULL, 0, &view) == TSC_ERR_ARGUMENT);
    CHECK(tsc_packet_udp_decode(golden, sizeof(golden), NULL) == TSC_ERR_ARGUMENT);
}

static void bounded_payloads(void)
{
    static uint8_t payload[TSC_UDP_MAX_PAYLOAD];
    static uint8_t packet[65535];
    static uint8_t pseudo[65527]; /* IPv4 pseudoheader plus largest UDP. */
    static const size_t lengths[] = { 0, 1, 2, 3, 255, 256, 511, 512, 1500,
                                      TSC_UDP_MAX_PAYLOAD - 1, TSC_UDP_MAX_PAYLOAD };
    tsc_udp_packet_view view;
    size_t size;
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i * 37 + i / 251);
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        const size_t length = lengths[i];
        CHECK(tsc_packet_udp_encode(src, dst, 0, 65535, length ? payload : NULL,
                                   length, 65535, packet, sizeof(packet), &size) == TSC_OK);
        CHECK(size == length + 28);
        CHECK(tsc_packet_udp_decode(packet, size, &view) == TSC_OK);
        CHECK(view.length == length && view.src_port == 0 && view.dst_port == 65535);
        CHECK(memcmp(view.payload, payload, length) == 0);
        CHECK(checksum(packet, 20) == 0);
        memcpy(pseudo, src, 4);
        memcpy(pseudo + 4, dst, 4);
        pseudo[8] = 0;
        pseudo[9] = 17;
        put16(pseudo + 10, (uint16_t)(length + 8));
        memcpy(pseudo + 12, packet + 20, length + 8);
        CHECK(checksum(pseudo, length + 20) == 0);
        CHECK(packet[26] != 0 || packet[27] != 0);
    }
    /* Every truncation of the largest legal IPv4 packet is rejected. */
    for (size_t length = 0; length < sizeof(packet); ++length)
        reject(packet, length);
    reject(packet, SIZE_MAX);
}

static void malformed(void)
{
    uint8_t packet[sizeof(golden) + 1];
    for (size_t i = 0; i < sizeof(golden); ++i) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            memcpy(packet, golden, sizeof(golden));
            packet[i] ^= (uint8_t)(1u << bit);
            reject(packet, sizeof(golden));
        }
    }
    for (size_t length = 0; length < sizeof(golden); ++length)
        reject(golden, length);
    memcpy(packet, golden, sizeof(golden));
    packet[sizeof(golden)] = 0;
    reject(packet, sizeof(packet)); /* Even zero trailing padding is framing. */

    /* Repair IPv4 checksum so protocol and fragmentation checks stand alone. */
    static const uint8_t flags[] = { 0x80, 0x20, 0x01, 0x60, 0xff };
    for (size_t i = 0; i < sizeof(flags); ++i) {
        memcpy(packet, golden, sizeof(golden));
        packet[6] = flags[i];
        repair_ip(packet);
        reject(packet, sizeof(golden));
    }
    memcpy(packet, golden, sizeof(golden));
    packet[7] = 1;
    repair_ip(packet);
    reject(packet, sizeof(golden));
    memcpy(packet, golden, sizeof(golden));
    packet[9] = 6;
    repair_ip(packet);
    reject(packet, sizeof(golden));
    memcpy(packet, golden, sizeof(golden));
    packet[0] = 0x44;
    reject(packet, sizeof(golden));
    packet[0] = 0x4f;
    reject(packet, sizeof(golden));
    packet[0] = 0x65;
    reject(packet, sizeof(golden));
    /* The transport checksum covers the pseudoheader, even if the IPv4
     * checksum was recomputed after an address changed in transit. */
    for (size_t address_byte = 12; address_byte < 20; ++address_byte) {
        memcpy(packet, golden, sizeof(golden));
        packet[address_byte] ^= 0x80;
        repair_ip(packet);
        reject(packet, sizeof(golden));
    }

    static const uint16_t invalid_lengths[] = { 0, 1, 7, 8, 12, 14, 65535 };
    for (size_t i = 0; i < sizeof(invalid_lengths) / sizeof(invalid_lengths[0]); ++i) {
        memcpy(packet, golden, sizeof(golden));
        put16(packet + 24, invalid_lengths[i]);
        packet[26] = packet[27] = 0; /* Length check must survive omitted checksum. */
        reject(packet, sizeof(golden));
    }
    for (uint16_t length = 0; length < 28; ++length) {
        memcpy(packet, golden, sizeof(golden));
        put16(packet + 2, length);
        repair_ip(packet);
        reject(packet, sizeof(golden));
    }
}

static void options_and_checksums(void)
{
    uint8_t packet[sizeof(golden) + 40];
    tsc_udp_packet_view view;
    size_t size;
    for (size_t options = 4; options <= 40; options += 4) {
        memcpy(packet, golden, 20);
        memset(packet + 20, 1, options); /* IPv4 NOP options. */
        memcpy(packet + 20 + options, golden + 20, sizeof(golden) - 20);
        packet[0] = (uint8_t)(0x45 + options / 4);
        put16(packet + 2, (uint16_t)(sizeof(golden) + options));
        repair_ip(packet);
        CHECK(tsc_packet_udp_decode(packet, sizeof(golden) + options, &view) == TSC_OK);
        CHECK(view.payload == packet + 28 + options && view.length == 5);
        CHECK(memcmp(view.payload, "abcde", 5) == 0);
        packet[20] ^= 1;
        reject(packet, sizeof(golden) + options);
    }
    memcpy(packet, golden, sizeof(golden));
    packet[26] = packet[27] = 0;
    CHECK(tsc_packet_udp_decode(packet, sizeof(golden), &view) == TSC_OK);
    packet[32] ^= 0x55; /* IPv4 explicitly permits unchecked UDP datagrams. */
    CHECK(tsc_packet_udp_decode(packet, sizeof(golden), &view) == TSC_OK);
    /* No-fragment flags may also be zero. */
    packet[6] = 0;
    repair_ip(packet);
    CHECK(tsc_packet_udp_decode(packet, sizeof(golden), &view) == TSC_OK);

    /* Pseudoheader sum 17+10, UDP length 10, payload 0xffda: final checksum
     * computes to zero and must be encoded as 0xffff, not omitted. */
    const uint8_t zero[4] = { 0,0,0,0 };
    const uint8_t balancing[] = { 0xff,0xda };
    CHECK(tsc_packet_udp_encode(zero, zero, 0, 0, balancing, 2, 0,
                               packet, sizeof(packet), &size) == TSC_OK);
    CHECK(packet[26] == 0xff && packet[27] == 0xff);
    CHECK(tsc_packet_udp_decode(packet, size, &view) == TSC_OK);
    packet[29] ^= 1;
    reject(packet, size);
}

static void overlap_and_unaligned(void)
{
    uint8_t storage[128];
    size_t size;
    tsc_udp_packet_view view;
    for (size_t offset = 0; offset < 64; ++offset) {
        memset(storage, 0x5a, sizeof(storage));
        memcpy(storage + offset, "abcde", 5);
        CHECK(tsc_packet_udp_encode(src, dst, 12345, 54321, storage + offset, 5,
                                   0x1234, storage + 1, sizeof(storage) - 1, &size) == TSC_OK);
        CHECK(size == sizeof(golden) && memcmp(storage + 1, golden, size) == 0);
        CHECK(tsc_packet_udp_decode(storage + 1, size, &view) == TSC_OK);
        CHECK(memcmp(view.payload, "abcde", 5) == 0);
    }
    /* Both addresses can be borrowed from the output header before encode. */
    memcpy(storage, src, 4);
    memcpy(storage + 4, dst, 4);
    CHECK(tsc_packet_udp_encode(storage, storage + 4, 12345, 54321, "abcde", 5,
                               0x1234, storage, sizeof(storage), &size) == TSC_OK);
    CHECK(memcmp(storage, golden, size) == 0);
}

int main(void)
{
    golden_and_arguments();
    bounded_payloads();
    malformed();
    options_and_checksums();
    overlap_and_unaligned();
    puts("IPv4/UDP packet tests passed");
    return 0;
}
