#include "json.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    tsc_json_token tokens[512];
    size_t count = 99;
    if (size > 16384) return 0;
    int rc = tsc_json_parse((const char *)data, size, tokens, 512, &count);
    if (rc != TSC_OK) { assert(count == 0); return 0; }
    assert(count > 0 && count <= 512 && tokens[0].next == count);
    for (size_t i = 0; i < count; i++) {
        tsc_json_token *t = &tokens[i];
        assert(t->start <= t->end && t->end <= size);
        assert(t->next > i && t->next <= count);
        assert(t->parent == TSC_JSON_NONE || t->parent < i);
        size_t index = SIZE_MAX;
        if (t->type == TSC_JSON_STRING) {
            size_t needed, copied;
            assert(tsc_json_string_copy((const char *)data, t, NULL, 0, &needed) == TSC_ERR_SPACE);
            assert(needed <= size);
            char *output = malloc(needed + 1);
            assert(output);
            assert(tsc_json_string_copy((const char *)data, t, output, needed + 1, &copied) == TSC_OK);
            assert(copied == needed && output[needed] == 0);
            if (needed) {
                assert(tsc_json_string_copy((const char *)data, t, output, needed, &copied) == TSC_ERR_SPACE);
                assert(copied == needed && output[0] == 0);
            }
            free(output);
        } else if (t->type == TSC_JSON_OBJECT) {
            rc = tsc_json_object_find((const char *)data, tokens, count, i, "", &index);
            assert(rc == TSC_OK || rc == TSC_AGAIN);
            if (rc == TSC_OK) assert(index > i && index < t->next);
        } else if (t->type == TSC_JSON_ARRAY) {
            rc = tsc_json_array_at(tokens, count, i, 0, &index);
            assert(rc == TSC_OK || rc == TSC_AGAIN);
            if (rc == TSC_OK) assert(index > i && index < t->next);
        } else if (t->type == TSC_JSON_NUMBER) {
            int64_t value;
            (void)tsc_json_int64((const char *)data, t, &value);
        } else if (t->type == TSC_JSON_TRUE || t->type == TSC_JSON_FALSE) {
            int value;
            assert(tsc_json_bool((const char *)data, t, &value) == TSC_OK);
            assert(value == (t->type == TSC_JSON_TRUE));
        }
    }
    /* Token exhaustion must leave the externally visible result empty. */
    size_t short_count = 99;
    assert(tsc_json_parse((const char *)data, size, tokens, count - 1, &short_count) != TSC_OK);
    assert(short_count == 0);
    return 0;
}
