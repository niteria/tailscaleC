#include "../src/control/project.h"
#include "check.h"
#include <string.h>

static int project(const char *s, size_t n, char *out, size_t capacity, size_t chunk)
{
    tsc_json_project p;
    tsc_json_project_init(&p, out, capacity);
    for (size_t at = 0; at < n;) {
        size_t take = n - at < chunk ? n - at : chunk;
        int r = tsc_json_project_feed(&p, s + at, take);
        if (r) return r;
        at += take;
    }
    return tsc_json_project_finish(&p);
}
int main(void)
{
    static const char input[] =
        " {\"UserProfiles\":[{\"x\":[true,false,null,-1.25e3,\"\\ud83d\\ude03\"]}],"
        "\"No\\u0064e\":{\"ID\":1,\"Hostinfo\":{\"anything\":2},\"MachineAuthorized\":false},"
        "\"PeersChanged\":[{\"ID\":2,\"Name\":\"a\\\"b\",\"Online\":true}],"
        "\"PacketFilters\":{\"base\":[{\"UnknownAllow\":true}]},\"ControlTime\":null} ";
    static const char expected[] =
        "{\"No\\u0064e\":{\"ID\":1,\"MachineAuthorized\":false},"
        "\"PeersChanged\":[{\"ID\":2,\"Name\":\"a\\\"b\",\"Online\":true}],"
        "\"PacketFilters\":{\"base\":[{\"UnknownAllow\":true}]},\"ControlTime\":null}";
    char out[2048];
    for (size_t chunk = 1; chunk <= sizeof(input); ++chunk) {
        CHECK(project(input, strlen(input), out, sizeof(out), chunk) == TSC_OK);
        CHECK(!strcmp(out, expected));
    }
    for (size_t capacity = 1; capacity < sizeof(expected); ++capacity)
        CHECK(project(input, strlen(input), out, capacity, 7) == TSC_ERR_SPACE);
    CHECK(project(input, strlen(input), out, sizeof(expected), 7) == TSC_OK);

    /* Metadata exceeds the retained buffer and token table, but each ignored
     * scalar/container is still checked. */
    tsc_json_project p;
    tsc_json_project_init(&p, out, sizeof(out));
    const char start[] = "{\"Unused\":[";
    CHECK(tsc_json_project_feed(&p, start, strlen(start)) == TSC_OK);
    for (unsigned i = 0; i < 10000; ++i)
        CHECK(tsc_json_project_feed(&p, i ? ",0" : "0", i ? 2 : 1) == TSC_OK);
    const char end[] = "],\"Node\":{\"ID\":7}}";
    CHECK(tsc_json_project_feed(&p, end, strlen(end)) == TSC_OK);
    CHECK(tsc_json_project_finish(&p) == TSC_OK);
    CHECK(!strcmp(out, "{\"Node\":{\"ID\":7}}"));

    const char *bad[] = {"{\"unused\":[1,]}", "{\"unused\":{\"x\":1,}}",
        "{\"unused\":01}", "{\"unused\":true false}", "{\"unused\":\"\\ud800\"}",
        "{\"unused\":\"\xc0\x80\"}", "{\"unused\":[1}", "{}{}", "{\"x\" 1}",
        "{\"unused\":[", "{\"Node\":{\"ID\":1}", "{\"unused\":\"unfinished"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        for (size_t chunk = 1; chunk <= strlen(bad[i]); ++chunk)
            CHECK(project(bad[i], strlen(bad[i]), out, sizeof(out), chunk) < 0);

    char deep[80];
    memset(deep, '[', 33); memset(deep + 33, ']', 33);
    CHECK(project(deep, 66, out, sizeof(out), 1) == TSC_ERR_SPACE);
    char huge[600]; memset(huge, 'a', sizeof(huge)); huge[0] = '"'; huge[599] = '"';
    CHECK(project(huge, sizeof(huge), out, sizeof(out), 1) == TSC_ERR_SPACE);

    /* Differential grammar check: projection must never turn malformed
     * authenticated JSON (including skipped metadata) into an accepted map. */
    char mutation[sizeof(input)];
    for (size_t i = 0; i < strlen(input); ++i) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            memcpy(mutation, input, sizeof(input));
            mutation[i] ^= (char)(1u << bit);
            int r = project(mutation, strlen(input), out, sizeof(out), 13);
            if (r == TSC_OK) {
                tsc_json_token tokens[256]; size_t count;
                CHECK(tsc_json_parse(mutation, strlen(input), tokens, 256, &count) == TSC_OK);
                CHECK(tsc_json_parse(out, strlen(out), tokens, 256, &count) == TSC_OK);
            }
        }
    }
    puts("streaming map projection tests passed");
    return 0;
}
