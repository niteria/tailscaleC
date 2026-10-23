#include "tailscalec/policy.h"
#include "check.h"

#include <stdio.h>
#include <string.h>

static tsc_policy policy;
static const uint8_t source[4] = {100, 64, 0, 2};
static const uint8_t destination[4] = {100, 64, 0, 1};
static const char allow_all[] =
    "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\","
    "\"Ports\":{\"First\":0,\"Last\":65535}}]}]";
static const char udp_rule[] =
    "[{\"SrcIPs\":[\"100.64.0.2/32\"],\"DstPorts\":[{\"IP\":\"100.64.0.1/32\","
    "\"Ports\":{\"First\":32123,\"Last\":32123}}],\"IPProto\":[17]}]";

static int parse(const char *json)
{
    return tsc_policy_parse_json(&policy, (const uint8_t *)json, strlen(json));
}

static int allowed(unsigned proto, unsigned port)
{
    return tsc_policy_allows(&policy, 4, source, destination,
                              (uint8_t)proto, (uint16_t)port);
}

static void check_cleared(void)
{
    const uint8_t *bytes = (const uint8_t *)&policy;
    size_t i;
    for (i = 0; i < sizeof(policy); i++) CHECK(bytes[i] == 0);
    CHECK(!allowed(17, 32123));
}

static void check_rejected(const char *json, int expected)
{
    int actual;
    CHECK(parse(allow_all) == TSC_OK);
    actual = parse(json);
    if (actual != expected)
        fprintf(stderr, "expected %d, received %d for %s\n", expected, actual, json);
    CHECK(actual == expected);
    check_cleared();
}

static void defaults_and_validation(void)
{
    CHECK(!allowed(17, 32123));
    CHECK(tsc_policy_parse_json(NULL, NULL, 0) == TSC_ERR_ARGUMENT);
    CHECK(parse(allow_all) == TSC_OK);
    CHECK(tsc_policy_parse_json(&policy, NULL, 0) == TSC_ERR_ARGUMENT);
    check_cleared();
    CHECK(parse("[]") == TSC_OK);
    CHECK(parse("  null\t\r\n") == TSC_OK);
    CHECK(parse("[{}]") == TSC_OK);
    CHECK(!allowed(6, 80));
    CHECK(parse(allow_all) == TSC_OK);
    CHECK(allowed(6, 0));
    CHECK(allowed(6, 65535));
    CHECK(allowed(17, 32123));
    CHECK(allowed(1, 0));
    CHECK(allowed(58, 0));
    CHECK(!allowed(47, 0));
    CHECK(!allowed(132, 32123));
    CHECK(!tsc_policy_allows(NULL, 4, source, destination, 17, 32123));
    CHECK(!tsc_policy_allows(&policy, 4, NULL, destination, 17, 32123));
    CHECK(!tsc_policy_allows(&policy, 4, source, NULL, 17, 32123));
    CHECK(!tsc_policy_allows(&policy, 5, source, destination, 17, 32123));
    policy.rule_count = 0;
    CHECK(!allowed(17, 32123));
}

static void restrictive_rules(void)
{
    uint8_t other[4] = {100, 64, 0, 3};
    CHECK(parse(udp_rule) == TSC_OK);
    CHECK(policy.rule_count == 1);
    CHECK(allowed(17, 32123));
    CHECK(!allowed(17, 32122));
    CHECK(!allowed(17, 32124));
    CHECK(!allowed(6, 32123));
    CHECK(!allowed(1, 0));
    CHECK(!tsc_policy_allows(&policy, 4, other, destination, 17, 32123));
    CHECK(!tsc_policy_allows(&policy, 4, source, other, 17, 32123));
    CHECK(parse("[{\"SrcIPs\":[\"100.64.0.255/25\",\"192.168.1.2\"],"
                "\"DstPorts\":[{\"IP\":\"10.0.0.0/9\",\"Ports\":{\"First\":100,"
                "\"Last\":200}}],\"IPProto\":[6,17]}]") == TSC_OK);
    {
        const uint8_t first[4] = {100, 64, 0, 128};
        const uint8_t last[4] = {100, 64, 0, 255};
        const uint8_t before[4] = {100, 64, 0, 127};
        const uint8_t dst[4] = {10, 127, 255, 255};
        const uint8_t beyond[4] = {10, 128, 0, 0};
        const uint8_t exact[4] = {192, 168, 1, 2};
        CHECK(tsc_policy_allows(&policy, 4, first, dst, 6, 100));
        CHECK(tsc_policy_allows(&policy, 4, last, dst, 17, 200));
        CHECK(tsc_policy_allows(&policy, 4, exact, dst, 17, 150));
        CHECK(!tsc_policy_allows(&policy, 4, before, dst, 17, 150));
        CHECK(!tsc_policy_allows(&policy, 4, first, beyond, 17, 150));
        CHECK(!tsc_policy_allows(&policy, 4, first, dst, 17, 99));
        CHECK(!tsc_policy_allows(&policy, 4, first, dst, 17, 201));
    }
    CHECK(parse("[{\"SrcIPs\":[\"0.0.0.0/0\"],\"DstPorts\":[{\"IP\":\"0.0.0.0/0\","
                "\"Ports\":{\"First\":53,\"Last\":53}}],\"IPProto\":[]}]") == TSC_OK);
    CHECK(allowed(17, 53));
    CHECK(allowed(6, 53));
    CHECK(allowed(1, 0));
    CHECK(!allowed(17, 54));
    CHECK(parse("[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\","
                "\"Ports\":{\"First\":0,\"Last\":65535}}],"
                "\"IPProto\":[47,132,255]}]") == TSC_OK);
    CHECK(allowed(47, 0));
    CHECK(allowed(255, 65535));
    CHECK(allowed(132, 123));
    CHECK(!allowed(6, 123));
    CHECK(parse("[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\","
                "\"Ports\":{\"First\":1,\"Last\":65535}}],"
                "\"IPProto\":[47,132]}]") == TSC_OK);
    CHECK(!allowed(47, 10));
    CHECK(allowed(132, 10));
    CHECK(!allowed(132, 0));
}

static void reordered_escaped_and_empty_fields(void)
{
    CHECK(parse(" [ { \"IPProto\" : [17,17], \"DstPorts\" : [ {"
                "\"Ports\" : {\"Last\":32123,\"First\":32123},"
                "\"Bits\":null,\"IP\":\"100.64.0.1\\/32\"} ],"
                "\"Src\\u0049Ps\":[\"100.64.0.2\"],\"SrcBits\":[],"
                "\"CapGrant\":null } ] ") == TSC_OK);
    CHECK(allowed(17, 32123));
    CHECK(!allowed(6, 32123));
    CHECK(parse("[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\","
                "\"Ports\":{\"First\":0,\"Last\":65535}}],\"IPProto\":null}]") == TSC_OK);
    CHECK(allowed(17, 123));
    CHECK(parse("[{\"SrcIPs\":null,\"DstPorts\":null}]") == TSC_OK);
    CHECK(!allowed(17, 123));
    CHECK(parse("[{\"SrcIPs\":[],\"DstPorts\":[],\"SrcBits\":null,\"CapGrant\":[]}]") == TSC_OK);
    CHECK(!allowed(6, 123));
    CHECK(parse("[{\"SrcIPs\":[\"*\"]}]") == TSC_OK);
    CHECK(!allowed(6, 123));
    CHECK(parse("[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]") == TSC_OK);
    CHECK(!allowed(6, 123));
}

static void malformed(void)
{
    static const char *const cases[] = {
        "", " ", "nul", "nullx", "[", "[{}", "[{},]", "[{},", "[{}]x", "{}", "[null]",
        "[{\"SrcIPs\":[\"*\",]}]", "[{\"SrcIPs\":[\"*\"] \"DstPorts\":[]}]",
        "[{\"SrcIPs\":[\"*\"],\"SrcIPs\":[\"100.64.0.2\"]}]",
        "[{\"IPProto\":[17],\"IPProto\":[6]}]", "[{\"IPProto\":[-1]}]",
        "[{\"IPProto\":[256]}]", "[{\"IPProto\":[017]}]", "[{\"IPProto\":[17.0]}]",
        "[{\"IPProto\":[1e1]}]", "[{\"IPProto\":[true]}]", "[{\"IPProto\":[17,]}]",
        "[{\"SrcIPs\":[\"256.1.1.1\"]}]", "[{\"SrcIPs\":[\"1.2.3\"]}]",
        "[{\"SrcIPs\":[\"01.2.3.4\"]}]", "[{\"SrcIPs\":[\"1.2.3.4/33\"]}]",
        "[{\"SrcIPs\":[\"1.2.3.4/\"]}]", "[{\"SrcIPs\":[\"1.2.3.4/-1\"]}]",
        "[{\"SrcIPs\":[\"1.2.3.4/01\"]}]", "[{\"SrcIPs\":[\"1.2.3.4/1/2\"]}]",
        "[{\"SrcIPs\":[\"1.2.3.4 \" ]}]", "[{\"SrcIPs\":[\"\"]}]",
        "[{\"SrcIPs\":[\"\\x\"]}]", "[{\"SrcIPs\":[\"\\u00gg\"]}]",
        "[{\"SrcIPs\":[\"*\n\"]}]", "[{\"SrcIPs\":[\"*\\t\"]}]",
        "[{\"DstPorts\":[{}]}]", "[{\"DstPorts\":[{\"IP\":\"*\"}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"IP\":\"100.64.0.1\",\"Ports\":{\"First\":0,\"Last\":1}}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":5,\"Last\":4}}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65536}}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":00}}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0}}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":1,\"Last\":2}}]}]"
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        check_rejected(cases[i], TSC_ERR_PROTOCOL);
    {
        static const char embedded_nul[] = {'[', ']', '\0', ' '};
        CHECK(parse(allow_all) == TSC_OK);
        CHECK(tsc_policy_parse_json(&policy, (const uint8_t *)embedded_nul,
                                     sizeof(embedded_nul)) == TSC_ERR_PROTOCOL);
        check_cleared();
    }
    for (i = 0; i < strlen(udp_rule); i++) {
        CHECK(parse(allow_all) == TSC_OK);
        CHECK(tsc_policy_parse_json(&policy, (const uint8_t *)udp_rule, i) != TSC_OK);
        check_cleared();
    }
}

static void unsupported(void)
{
    static const char *const cases[] = {
        "[{\"SrcIPs\":[\"cap:test\"]}]",
        "[{\"SrcBits\":[32]}]", "[{\"SrcBits\":0}]",
        "[{\"CapGrant\":[{}]}]", "[{\"FutureRestrictiveField\":false}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Bits\":0,\"Ports\":{\"First\":0,\"Last\":65535}}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Restrict\":true,\"Ports\":{\"First\":0,\"Last\":65535}}]}]",
        "[{\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535,\"Exclude\":80}}]}]",
        "[{\"SrcIPs\":[\"\\u0000*\"]}]", "[{\"SrcIPs\":[\"\\u2603\"]}]"
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        check_rejected(cases[i], TSC_ERR_UNSUPPORTED);
    {
        char extended[1024];
        int used = snprintf(extended, sizeof(extended), "%.*s,{\"Nope\":true}]",
                            (int)strlen(allow_all) - 1, allow_all);
        CHECK(used > 0 && (size_t)used < sizeof(extended));
        check_rejected(extended, TSC_ERR_UNSUPPORTED);
    }
}

static void append(char *out, size_t capacity, size_t *used, const char *text)
{
    size_t length = strlen(text);
    CHECK(length < capacity - *used);
    memcpy(out + *used, text, length + 1);
    *used += length;
}

static void capacities(void)
{
    char json[32768];
    size_t used = 0;
    size_t i;
    append(json, sizeof(json), &used, "[");
    for (i = 0; i < TSC_MAX_FILTER_RULES; i++) {
        if (i) append(json, sizeof(json), &used, ",");
        append(json, sizeof(json), &used, "{}");
    }
    append(json, sizeof(json), &used, "]");
    CHECK(parse(json) == TSC_OK);
    CHECK(policy.rule_count == TSC_MAX_FILTER_RULES);
    used--;
    append(json, sizeof(json), &used, ",{}]");
    check_rejected(json, TSC_ERR_SPACE);
    used = 0;
    append(json, sizeof(json), &used, "[{\"SrcIPs\":[");
    for (i = 0; i <= TSC_MAX_FILTER_SOURCES; i++) {
        if (i) append(json, sizeof(json), &used, ",");
        append(json, sizeof(json), &used, "\"*\"");
    }
    append(json, sizeof(json), &used, "]}]");
    check_rejected(json, TSC_ERR_SPACE);
    used = 0;
    append(json, sizeof(json), &used, "[{\"DstPorts\":[");
    for (i = 0; i <= TSC_MAX_FILTER_DESTINATIONS; i++) {
        if (i) append(json, sizeof(json), &used, ",");
        append(json, sizeof(json), &used,
               "{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}");
    }
    append(json, sizeof(json), &used, "]}]");
    check_rejected(json, TSC_ERR_SPACE);
}

static void ipv6_rules(void)
{
#if TSC_ENABLE_IPV6
    static const uint8_t src[16] = {0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 2};
    static const uint8_t dst[16] = {0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 1};
    static const char *const malformed_v6[] = {
        "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::",
        ":1", "1:", ":::1", "1:::2", "1::2::3", "1::2:",
        "12345::", "g::", "::ffff:192.0.2.256", "::ffff:192.0.2.1:2",
        "::/129", "fe80::1%eth0", "::ffff:192.0.2.01"
    };
    size_t i;
    CHECK(parse("[{\"SrcIPs\":[\"fd7a:115c:a1e0::2/128\"],\"DstPorts\":[{"
                "\"IP\":\"fd7a:115c:a1e0::/48\",\"Ports\":{\"First\":53,\"Last\":53}}]}]") == TSC_OK);
    CHECK(tsc_policy_allows(&policy, 6, src, dst, 17, 53));
    CHECK(!tsc_policy_allows(&policy, 6, src, dst, 17, 54));
    CHECK(!tsc_policy_allows(&policy, 6, dst, src, 17, 53));
    CHECK(!allowed(17, 53));
    CHECK(parse("[{\"SrcIPs\":[\"::/0\",\"::ffff:192.0.2.1\"],\"DstPorts\":[{"
                "\"IP\":\"::/0\",\"Ports\":{\"First\":0,\"Last\":65535}}]}]") == TSC_OK);
    CHECK(tsc_policy_allows(&policy, 6, src, dst, 17, 53));
    CHECK(!allowed(17, 53));
    CHECK(parse("[{\"SrcIPs\":[\"1:2:3:4:5:6:192.0.2.1\",\"::\"],"
                "\"DstPorts\":[]}]" ) == TSC_OK);
    for (i = 0; i < sizeof(malformed_v6) / sizeof(malformed_v6[0]); i++) {
        char json[256];
        int length = snprintf(json, sizeof(json), "[{\"SrcIPs\":[\"%s\"]}]", malformed_v6[i]);
        CHECK(length > 0 && (size_t)length < sizeof(json));
        check_rejected(json, TSC_ERR_PROTOCOL);
    }
#else
    uint8_t addr[16] = {0};
    CHECK(parse("[{\"SrcIPs\":[\"::/0\"]}]") == TSC_OK);
    CHECK(!allowed(17, 53));
    check_rejected("[{\"SrcIPs\":[\"1::2::3\"]}]", TSC_ERR_PROTOCOL);
    check_rejected("[{\"SrcIPs\":[\"::/129\"]}]", TSC_ERR_PROTOCOL);
    CHECK(parse(allow_all) == TSC_OK);
    CHECK(!tsc_policy_allows(&policy, 6, addr, addr, 17, 53));
#endif
}

static void inclusive_ranges(void)
{
    static const char headscale_filter[] =
        "[{\"SrcIPs\":[\"100.64.0.0-100.115.91.255\","
        "\"100.115.94.0-100.127.255.255\",\"fd7a:115c:a1e0::/48\"],"
        "\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":32123,\"Last\":32123}}],"
        "\"IPProto\":[17]}]";
    static const uint8_t accepted[][4] = {
        {100, 64, 0, 0}, {100, 64, 0, 1}, {100, 115, 91, 255},
        {100, 115, 94, 0}, {100, 127, 255, 255}
    };
    static const uint8_t rejected[][4] = {
        {100, 63, 255, 255}, {100, 115, 92, 0}, {100, 115, 93, 255},
        {100, 128, 0, 0}, {192, 168, 1, 1}
    };
    static const char *const malformed_ranges[] = {
        "100.64.0.2-100.64.0.1", "100.64.0.1-", "-100.64.0.1",
        "100.64.0.1-100.64.0.2/32", "100.64.0.1-100.64.0.2-100.64.0.3",
        "100.64.0.1-::1", "::1-100.64.0.1", "::2-::1", "::1-", "::1-::x",
        "::1-::2/128", "*-*"
    };
    size_t i;
    CHECK(parse(headscale_filter) == TSC_OK);
    for (i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        CHECK(tsc_policy_allows(&policy, 4, accepted[i], destination, 17, 32123));
        CHECK(!tsc_policy_allows(&policy, 4, accepted[i], destination, 17, 32124));
        CHECK(!tsc_policy_allows(&policy, 4, accepted[i], destination, 6, 32123));
    }
    for (i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++)
        CHECK(!tsc_policy_allows(&policy, 4, rejected[i], destination, 17, 32123));
    CHECK(parse("[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{"
                "\"IP\":\"100.64.0.1-100.64.0.2\","
                "\"Ports\":{\"First\":32123,\"Last\":32123}}]}]") == TSC_OK);
    CHECK(allowed(17, 32123));
    CHECK(tsc_policy_allows(&policy, 4, source, source, 17, 32123));
    CHECK(!tsc_policy_allows(&policy, 4, destination, rejected[0], 17, 32123));
    CHECK(parse("[{\"SrcIPs\":[\"100.64.0.2-100.64.0.2\"],\"DstPorts\":[{"
                "\"IP\":\"*\",\"Ports\":{\"First\":32123,\"Last\":32123}}]}]") == TSC_OK);
    CHECK(allowed(17, 32123));
    CHECK(!tsc_policy_allows(&policy, 4, destination, source, 17, 32123));
    CHECK(parse("[{\"SrcIPs\":[\"::1-::ffff:255.255.255.255\",\"100.64.0.2\"],"
                "\"DstPorts\":[{\"IP\":\"fd7a:115c:a1e0::-fd7a:115c:a1e0::ffff\","
                "\"Ports\":{\"First\":7,\"Last\":7}}]}]") == TSC_OK);
    CHECK(!allowed(17, 7));
#if TSC_ENABLE_IPV6
    {
        uint8_t src[16] = {0};
        uint8_t dst[16] = {0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0};
        src[15] = 1;
        CHECK(tsc_policy_allows(&policy, 6, src, dst, 17, 7));
        dst[14] = dst[15] = 255;
        CHECK(tsc_policy_allows(&policy, 6, src, dst, 17, 7));
        dst[13] = 1;
        CHECK(!tsc_policy_allows(&policy, 6, src, dst, 17, 7));
        dst[13] = 0;
        src[15] = 0;
        CHECK(!tsc_policy_allows(&policy, 6, src, dst, 17, 7));
    }
#endif
    for (i = 0; i < sizeof(malformed_ranges) / sizeof(malformed_ranges[0]); i++) {
        char json[256];
        int length = snprintf(json, sizeof(json), "[{\"SrcIPs\":[\"%s\"]}]", malformed_ranges[i]);
        CHECK(length > 0 && (size_t)length < sizeof(json));
        check_rejected(json, TSC_ERR_PROTOCOL);
    }
}

static void prefix_boundaries(void)
{
    unsigned bits;
    unsigned flipped;
    char json[512];
    const uint8_t exact[4] = {203, 177, 123, 15};
    for (bits = 0; bits <= 32; bits++) {
        int length = snprintf(json, sizeof(json),
                              "[{\"SrcIPs\":[\"203.177.123.15/%u\"],"
                              "\"DstPorts\":[{\"IP\":\"*\","
                              "\"Ports\":{\"First\":7,\"Last\":7}}]}]", bits);
        CHECK(length > 0 && (size_t)length < sizeof(json));
        CHECK(parse(json) == TSC_OK);
        CHECK(tsc_policy_allows(&policy, 4, exact, destination, 17, 7));
        for (flipped = 0; flipped < 32; flipped++) {
            uint8_t changed[4];
            memcpy(changed, exact, sizeof(changed));
            changed[flipped / 8] ^= (uint8_t)(0x80u >> (flipped % 8));
            CHECK(tsc_policy_allows(&policy, 4, changed, destination, 17, 7) ==
                  (flipped >= bits));
        }
    }
#if TSC_ENABLE_IPV6
    {
        const uint8_t exact6[16] = {0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0x12, 0x34,
                                  0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34};
        for (bits = 0; bits <= 128; bits++) {
            int length = snprintf(json, sizeof(json),
                                  "[{\"SrcIPs\":[\"*\"],\"DstPorts\":[{"
                                  "\"IP\":\"fd7a:115c:a1e0:1234:5678:9abc:def0:1234/%u\","
                                  "\"Ports\":{\"First\":7,\"Last\":7}}]}]", bits);
            CHECK(length > 0 && (size_t)length < sizeof(json));
            CHECK(parse(json) == TSC_OK);
            CHECK(tsc_policy_allows(&policy, 6, exact6, exact6, 17, 7));
            for (flipped = 0; flipped < 128; flipped++) {
                uint8_t changed[16];
                memcpy(changed, exact6, sizeof(changed));
                changed[flipped / 8] ^= (uint8_t)(0x80u >> (flipped % 8));
                CHECK(tsc_policy_allows(&policy, 6, exact6, changed, 17, 7) ==
                      (flipped >= bits));
            }
        }
    }
#endif
}

static void mutations(void)
{
    char mutated[sizeof(udp_rule)];
    size_t i;
    unsigned byte;
    for (i = 0; i < strlen(udp_rule); i++) {
        for (byte = 0; byte < 256; byte++) {
            int result;
            memcpy(mutated, udp_rule, sizeof(udp_rule));
            mutated[i] = (char)byte;
            result = tsc_policy_parse_json(&policy, (const uint8_t *)mutated,
                                           sizeof(udp_rule) - 1);
            if (result != TSC_OK) check_cleared();
            else {
                CHECK(policy.rule_count <= TSC_MAX_FILTER_RULES);
                (void)allowed(17, 32123);
            }
        }
    }
}

int main(void)
{
    defaults_and_validation();
    restrictive_rules();
    reordered_escaped_and_empty_fields();
    malformed();
    unsupported();
    capacities();
    ipv6_rules();
    inclusive_ranges();
    prefix_boundaries();
    mutations();
    printf("policy tests passed (%zu-byte bounded policy)\n", sizeof(policy));
    return 0;
}
