#include "tailscalec/packet.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    tsc_udp_packet_view before, view;
    memset(&before, 0xa5, sizeof(before));
    view = before;
    int rc = tsc_packet_udp_decode(data, size, &view);
    if (rc != TSC_OK) assert(memcmp(&before, &view, sizeof(view)) == 0);
    else {
        assert(view.payload >= data && view.payload <= data + size);
        assert(view.length == (size_t)(data + size - view.payload));
    }
    if (size > 4096) return 0;
    uint8_t out[4096 + 64], overlap[4096 + 64], addresses[8] = {100,64,0,1,100,64,0,2};
    if (size >= sizeof(addresses)) memcpy(addresses, data, sizeof(addresses));
    uint16_t sport = size > 1 ? (uint16_t)((uint16_t)data[0] << 8 | data[1]) : 0;
    uint16_t dport = (uint16_t)~sport;
    size_t length = 99;
    rc = tsc_packet_udp_encode(addresses, addresses + 4, sport, dport,
        data, size, sport, out, sizeof(out), &length);
    assert(rc == TSC_OK && length == size + 28);
    assert(tsc_packet_udp_decode(out, length, &view) == TSC_OK);
    assert(view.length == size && view.src_port == sport && view.dst_port == dport);
    assert(memcmp(view.src, addresses, 4) == 0 && memcmp(view.dst, addresses + 4, 4) == 0);
    assert(memcmp(view.payload, data, size) == 0);
    /* Exercise both directions of overlap, with address aliases too. */
    size_t source_offset = size ? data[0] % 33 : 0;
    memcpy(overlap + source_offset, data, size);
    size_t overlap_length = 99;
    assert(tsc_packet_udp_encode(addresses, addresses + 4, sport, dport,
        overlap + source_offset, size, sport, overlap, sizeof(overlap),
        &overlap_length) == TSC_OK);
    assert(length == overlap_length && memcmp(overlap, out, length) == 0);
    uint8_t saved[sizeof(overlap)];
    memset(overlap, 0xa5, sizeof(overlap));
    memcpy(saved, overlap, sizeof(saved));
    assert(tsc_packet_udp_encode(addresses, addresses + 4, sport, dport,
        data, size, sport, overlap, length - 1, &overlap_length) == TSC_ERR_SPACE);
    assert(overlap_length == 0 && memcmp(saved, overlap, sizeof(saved)) == 0);
    return 0;
}
