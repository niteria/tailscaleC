#include "tailscalec/policy.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    tsc_policy policy;
    memset(&policy, 0xa5, sizeof(policy));
    int rc = tsc_policy_parse_json(&policy, data, size);
    if (rc != TSC_OK) {
        const uint8_t *bytes = (const uint8_t *)&policy;
        for (size_t i = 0; i < sizeof(policy); i++) assert(bytes[i] == 0);
    } else {
        assert(policy.rule_count <= TSC_MAX_FILTER_RULES);
        for (size_t i = 0; i < policy.rule_count; i++) {
            assert(policy.rules[i].source_count <= TSC_MAX_FILTER_SOURCES);
            assert(policy.rules[i].destination_count <= TSC_MAX_FILTER_DESTINATIONS);
        }
    }
    uint8_t src[16] = {100,64,0,1}, dst[16] = {100,64,0,2};
    if (size >= 32) { memcpy(src, data, 16); memcpy(dst, data + 16, 16); }
    for (unsigned protocol = 0; protocol < 256; protocol++) {
        int allowed = tsc_policy_allows(&policy, 4, src, dst, (uint8_t)protocol, (uint16_t)size);
        assert(allowed == 0 || allowed == 1);
        if (rc != TSC_OK) assert(allowed == 0);
        allowed = tsc_policy_allows(&policy, 6, src, dst, (uint8_t)protocol, (uint16_t)size);
        assert(allowed == 0 || allowed == 1);
        if (rc != TSC_OK) assert(allowed == 0);
    }
    assert(tsc_policy_allows(&policy, 0, src, dst, 17, 80) == 0);
    return 0;
}
