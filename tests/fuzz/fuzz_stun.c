#include "tailscalec/stun.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

static void inspect(const uint8_t *data, size_t size, const uint8_t txid[12])
{
    tsc_endpoint before, after;
    memset(&before, 0xa5, sizeof(before));
    after = before;
    int rc = tsc_stun_response(data, size, txid, &after);
    if (rc != TSC_OK)
        assert(memcmp(&before, &after, sizeof(before)) == 0);
    else
        assert(after.family == TSC_AF_IPV4 || after.family == TSC_AF_IPV6);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t txid[12] = {0};
    uint8_t framed[65556];
    if (size > 65536) return 0;
    if (size >= sizeof(txid)) memcpy(txid, data, sizeof(txid));
    inspect(data, size, txid);
    /* Keep framing valid so mutations also explore the attribute decoder. */
    size_t body = size & ~(size_t)3;
    if (body > 65532) body = 65532;
    memset(framed, 0, 20);
    framed[0] = 1; framed[1] = 1;
    framed[2] = (uint8_t)(body >> 8); framed[3] = (uint8_t)body;
    memcpy(framed + 4, "\x21\x12\xa4\x42", 4);
    memcpy(framed + 8, txid, sizeof(txid));
    if (body) memcpy(framed + 20, data, body);
    inspect(framed, body + 20, txid);
    uint8_t request[40];
    for (size_t cap = 0; cap <= sizeof(request); cap += 8) {
        size_t length = 99;
        memset(request, 0xa5, sizeof(request));
        int rc = tsc_stun_request(txid, request, cap, &length);
        assert(rc == (cap < sizeof(request) ? TSC_ERR_SPACE : TSC_OK));
        assert(length == (cap < sizeof(request) ? 0 : sizeof(request)));
        if (rc != TSC_OK)
            for (size_t i = 0; i < sizeof(request); i++) assert(request[i] == 0xa5);
    }
    return 0;
}
