#include "../src/control/json.h"
#include "check.h"

#include <limits.h>
#include <string.h>

#define TOKEN_CAPACITY 256

static size_t parse(const char *text, tsc_json_token *tokens)
{
    size_t count = SIZE_MAX;
    int rc = tsc_json_parse(text, strlen(text), tokens, TOKEN_CAPACITY, &count);
    if (rc != TSC_OK)
        fprintf(stderr, "JSON parse failed (%d): %s\n", rc, text);
    CHECK(rc == TSC_OK);
    CHECK(count != 0 && count <= TOKEN_CAPACITY);
    return count;
}

static void validate(const char *text, size_t length,
                       const tsc_json_token *tokens, size_t count)
{
    CHECK(count != 0 && tokens[0].parent == TSC_JSON_NONE);
    CHECK(tokens[0].next == count);
    for (size_t i = 0; i < count; ++i) {
        const tsc_json_token *token = &tokens[i];
        CHECK(token->start <= token->end && token->end <= length);
        CHECK(token->next > i && token->next <= count);
        if (i != 0) {
            CHECK(token->parent < i);
            const tsc_json_token *parent = &tokens[token->parent];
            CHECK(parent->type == TSC_JSON_OBJECT || parent->type == TSC_JSON_ARRAY);
            CHECK(parent->start < token->start && parent->end > token->end);
            CHECK(token->next <= parent->next);
        }
        if (token->type == TSC_JSON_STRING) {
            CHECK(token->start != 0 && token->end < length);
            CHECK(text[token->start - 1] == '"' && text[token->end] == '"');
            char decoded[1024];
            size_t decoded_length;
            CHECK(tsc_json_string_copy(text, token, decoded, sizeof(decoded),
                                        &decoded_length) == TSC_OK);
            CHECK(decoded_length <= (size_t)(token->end - token->start));
            CHECK(decoded[decoded_length] == '\0');
        } else if (token->type == TSC_JSON_ARRAY || token->type == TSC_JSON_OBJECT) {
            CHECK(token->end > token->start);
            CHECK(text[token->start] == (token->type == TSC_JSON_ARRAY ? '[' : '{'));
            CHECK(text[token->end - 1] == (token->type == TSC_JSON_ARRAY ? ']' : '}'));
        } else {
            CHECK(token->end > token->start);
            CHECK(token->next == i + 1);
        }
    }
}

static void navigation(void)
{
    const char text[] = " {\"Node\":{\"ID\":123,\"Name\":\"test\",\"Online\":true},"
        "\"Peers\":[{\"ID\":456},null,false,[1,2]],\"empty\":{},\"a\":[],"
        "\"escaped\\u006bey\":\"value\",\"duplicate\":1,\"duplicate\":2} \n";
    tsc_json_token tokens[TOKEN_CAPACITY];
    size_t count = parse(text, tokens);
    validate(text, strlen(text), tokens, count);
    CHECK(tokens[0].type == TSC_JSON_OBJECT && tokens[0].start == 1);
    size_t node, field, peers, element;
    CHECK(tsc_json_object_find(text, tokens, count, 0, "Node", &node) == TSC_OK);
    CHECK(node == 2 && tokens[node].type == TSC_JSON_OBJECT);
    CHECK(tsc_json_object_find(text, tokens, count, node, "ID", &field) == TSC_OK);
    int64_t integer;
    CHECK(tsc_json_int64(text, &tokens[field], &integer) == TSC_OK && integer == 123);
    CHECK(tsc_json_object_find(text, tokens, count, node, "Online", &field) == TSC_OK);
    int boolean;
    CHECK(tsc_json_bool(text, &tokens[field], &boolean) == TSC_OK && boolean == 1);
    CHECK(tsc_json_object_find(text, tokens, count, 0, "Peers", &peers) == TSC_OK);
    CHECK(tsc_json_array_at(tokens, count, peers, 0, &element) == TSC_OK);
    CHECK(tsc_json_object_find(text, tokens, count, element, "ID", &field) == TSC_OK);
    CHECK(tsc_json_int64(text, &tokens[field], &integer) == TSC_OK && integer == 456);
    CHECK(tsc_json_array_at(tokens, count, peers, 1, &element) == TSC_OK);
    CHECK(tokens[element].type == TSC_JSON_NULL);
    CHECK(tsc_json_array_at(tokens, count, peers, 2, &element) == TSC_OK);
    CHECK(tsc_json_bool(text, &tokens[element], &boolean) == TSC_OK && boolean == 0);
    CHECK(tsc_json_array_at(tokens, count, peers, 3, &element) == TSC_OK);
    CHECK(tsc_json_array_at(tokens, count, element, 1, &field) == TSC_OK);
    CHECK(tsc_json_int64(text, &tokens[field], &integer) == TSC_OK && integer == 2);
    field = SIZE_MAX;
    CHECK(tsc_json_array_at(tokens, count, peers, 4, &field) == TSC_AGAIN);
    CHECK(field == SIZE_MAX);
    CHECK(tsc_json_array_at(tokens, count, peers, SIZE_MAX, &field) == TSC_AGAIN);
    CHECK(tsc_json_object_find(text, tokens, count, 0, "missing", &field) == TSC_AGAIN);
    CHECK(field == SIZE_MAX);
    CHECK(tsc_json_object_find(text, tokens, count, 0, "escapedkey", &field) == TSC_OK);
    char output[16];
    size_t output_length;
    CHECK(tsc_json_string_copy(text, &tokens[field], output, sizeof(output),
                                &output_length) == TSC_OK);
    CHECK(output_length == 5 && strcmp(output, "value") == 0);
    CHECK(tsc_json_object_find(text, tokens, count, 0, "duplicate", &field) == TSC_OK);
    CHECK(tsc_json_int64(text, &tokens[field], &integer) == TSC_OK && integer == 1);
    CHECK(tsc_json_object_find(text, tokens, count, 0, "empty", &field) == TSC_OK);
    CHECK(tsc_json_object_find(text, tokens, count, field, "x", &element) == TSC_AGAIN);
    CHECK(tsc_json_object_find(text, tokens, count, 0, "a", &field) == TSC_OK);
    CHECK(tsc_json_array_at(tokens, count, field, 0, &element) == TSC_AGAIN);
}

static void strings(void)
{
    const char *const encoded[] = {
        "\"\"", "\"hello\"", "\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"",
        "\"\\u0000\\u001f\\u007f\\u0080\\u07ff\\u0800\\uffff\"",
        "\"\\uD800\\uDC00\\udbff\\udfff\\ud83d\\ude03\"",
        ("\"\xc2\x80\xdf\xbf\xe0\xa0\x80\xef\xbf\xbf"
         "\xf0\x90\x80\x80\xf4\x8f\xbf\xbf\""),
        "\"\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87\""
    };
    const char *const decoded[] = {
        "", "hello", "\"\\/\b\f\n\r\t",
        "\0\x1f\x7f\xc2\x80\xdf\xbf\xe0\xa0\x80\xef\xbf\xbf",
        "\xf0\x90\x80\x80\xf4\x8f\xbf\xbf\xf0\x9f\x98\x83",
        ("\xc2\x80\xdf\xbf\xe0\xa0\x80\xef\xbf\xbf"
         "\xf0\x90\x80\x80\xf4\x8f\xbf\xbf"),
        "\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87"
    };
    const size_t expected_lengths[] = {0, 5, 8, 13, 12, 18, 8};
    for (size_t i = 0; i < sizeof(encoded) / sizeof(encoded[0]); ++i) {
        tsc_json_token tokens[TOKEN_CAPACITY];
        size_t count = parse(encoded[i], tokens);
        CHECK(count == 1);
        char output[64];
        size_t length;
        CHECK(tsc_json_string_copy(encoded[i], tokens, NULL, 0, &length) == TSC_ERR_SPACE);
        CHECK(length == expected_lengths[i]);
        for (size_t capacity = 0; capacity <= length; ++capacity) {
            memset(output, 0x5a, sizeof(output));
            CHECK(tsc_json_string_copy(encoded[i], tokens, output, capacity,
                                        &length) == TSC_ERR_SPACE);
            CHECK(length == expected_lengths[i]);
            CHECK(output[0] == (capacity == 0 ? 0x5a : '\0'));
            CHECK(output[capacity] == 0x5a);
        }
        memset(output, 0x5a, sizeof(output));
        CHECK(tsc_json_string_copy(encoded[i], tokens, output, length + 1,
                                    &length) == TSC_OK);
        CHECK(memcmp(output, decoded[i], length) == 0);
        CHECK(output[length] == '\0' && output[length + 1] == 0x5a);
    }
    /* Escaped names compare by decoded bytes, including UTF-8. */
    const char text[] = "{\"\\u00e9\":1,\"\\u0000\":2,\"\":3,\"longer\":4}";
    tsc_json_token tokens[TOKEN_CAPACITY];
    size_t count = parse(text, tokens), value;
    CHECK(tsc_json_object_find(text, tokens, count, 0, "\xc3\xa9", &value) == TSC_OK);
    int64_t integer;
    CHECK(tsc_json_int64(text, &tokens[value], &integer) == TSC_OK && integer == 1);
    CHECK(tsc_json_object_find(text, tokens, count, 0, "", &value) == TSC_OK);
    CHECK(tsc_json_int64(text, &tokens[value], &integer) == TSC_OK && integer == 3);
    CHECK(tsc_json_object_find(text, tokens, count, 0, "long", &value) == TSC_AGAIN);
    CHECK(tsc_json_object_find(text, tokens, count, 0, "longer!", &value) == TSC_AGAIN);
}

static void numbers(void)
{
    const char *const valid[] = {"0", "-0", "123", "-987", "9223372036854775807",
        "-9223372036854775808", "0.0", "-1.25", "12e3", "0E+1", "1e-23",
        "9223372036854775808", "-9223372036854775809", "999999999999999999999999999"};
    const int64_t expected[] = {0, 0, 123, -987, INT64_MAX, INT64_MIN};
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        tsc_json_token tokens[TOKEN_CAPACITY];
        CHECK(parse(valid[i], tokens) == 1);
        CHECK(tokens[0].type == TSC_JSON_NUMBER);
        int64_t value = 44;
        int rc = tsc_json_int64(valid[i], tokens, &value);
        if (i < sizeof(expected) / sizeof(expected[0]))
            CHECK(rc == TSC_OK && value == expected[i]);
        else
            CHECK(rc == TSC_ERR_PROTOCOL && value == 44);
    }
    const char *const literals[] = {"true", "false", "null", " \r\n\ttrue \r\n\t"};
    for (size_t i = 0; i < sizeof(literals) / sizeof(literals[0]); ++i) {
        tsc_json_token tokens[TOKEN_CAPACITY];
        CHECK(parse(literals[i], tokens) == 1);
        int value = 123;
        int rc = tsc_json_bool(literals[i], tokens, &value);
        if (i == 2)
            CHECK(rc == TSC_ERR_PROTOCOL && value == 123);
        else
            CHECK(rc == TSC_OK && value == (i == 1 ? 0 : 1));
    }
}

static void malformed(void)
{
    const char *const invalid[] = {
        "x", "+1", "01", "-01", "--1", "-.1", ".1", "1.e2", "1e.x", "NaN",
        "Infinity", "0x10", "True", "FALSE", "nulx", "true false", "{}[]", "[]0",
        "[1,]", "[,1]", "[1 2]", "[1,,2]", "{,}", "{1:2}", "{true:1}",
        "{\"x\" 1}", "{\"x\":}", "{\"x\":1,}", "{\"x\":1 \"y\":2}", "[}", "{]",
        "\"a\nb\"", "\"\x01\"", "\"\\x20\"", "\"\\a\"", "\"\\u0x00\"",
        "\"\\ud800\"", "\"\\udc00\"", "\"\\udfff\"", "\"\\ud800x\"",
        "\"\\ud800\\ud800\"", "\"\\ud800\\u0000\"", "\"\\udbff\\uffff\"",
        "\"\x80\"", "\"\xc0\x80\"", "\"\xc1\xbf\"", "\"\xc2x\"",
        "\"\xe0\x80\x80\"", "\"\xed\xa0\x80\"", "\"\xed\xbf\xbf\"",
        "\"\xf0\x80\x80\x80\"", "\"\xf4\x90\x80\x80\"", "\"\xf5\x80\x80\x80\"",
        "\"\xff\"", "\v0", "\f0", "\xef\xbb\xbf{}", "{}x"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        tsc_json_token tokens[TOKEN_CAPACITY];
        size_t count = 123;
        int rc = tsc_json_parse(invalid[i], strlen(invalid[i]), tokens,
                                TOKEN_CAPACITY, &count);
        if (rc != TSC_ERR_PROTOCOL)
            fprintf(stderr, "Unexpected result %d for malformed JSON %s\n", rc, invalid[i]);
        CHECK(rc == TSC_ERR_PROTOCOL && count == 0);
    }
    const char *const incomplete[] = {"", " ", "{", "[", "{\"x\"", "{\"x\":",
        "{\"x\":1", "[1,", "-", "1.", "1e", "1E+", "1e-", "tru", "fals", "nul",
        "\"", "\"abc", "\"\\", "\"\\u", "\"\\u123", "\"\\ud800", "\"\\ud800\\",
        "\"\\ud800\\u", "\"\\ud800\\udc0", "\"\xc2", "\"\xe0\xa0", "\"\xf4\x8f\xbf"};
    for (size_t i = 0; i < sizeof(incomplete) / sizeof(incomplete[0]); ++i) {
        tsc_json_token tokens[TOKEN_CAPACITY];
        size_t count = 123;
        CHECK(tsc_json_parse(incomplete[i], strlen(incomplete[i]), tokens,
                              TOKEN_CAPACITY, &count) == TSC_ERR_TRUNCATED);
        CHECK(count == 0);
    }
    const char prefix[] = "{\"\xc3\xa9\":[true,false,null,-1.25e+3,\"\\ud83d\\ude03\"],\"a\":{}}";
    for (size_t i = 0; i < sizeof(prefix) - 2; ++i) {
        tsc_json_token tokens[TOKEN_CAPACITY];
        size_t count;
        CHECK(tsc_json_parse(prefix, i, tokens, TOKEN_CAPACITY, &count) == TSC_ERR_TRUNCATED);
        CHECK(count == 0);
    }
    const char embedded_nul[] = {'"', 'a', '\0', 'b', '"'};
    tsc_json_token tokens[TOKEN_CAPACITY];
    size_t count;
    CHECK(tsc_json_parse(embedded_nul, sizeof(embedded_nul), tokens,
                          TOKEN_CAPACITY, &count) == TSC_ERR_PROTOCOL);
    const char after_nul[] = {'0', '\0', '1'};
    CHECK(tsc_json_parse(after_nul, sizeof(after_nul), tokens,
                          TOKEN_CAPACITY, &count) == TSC_ERR_PROTOCOL);
}

static void bounds_and_arguments(void)
{
    const char text[] = "{\"a\":[1,{\"b\":\"c\"}],\"d\":true}";
    tsc_json_token tokens[TOKEN_CAPACITY];
    size_t needed = parse(text, tokens);
    for (size_t capacity = 0; capacity < needed; ++capacity) {
        memset(tokens, 0x5a, sizeof(tokens));
        size_t count = 123;
        CHECK(tsc_json_parse(text, strlen(text), tokens, capacity, &count) == TSC_ERR_SPACE);
        CHECK(count == 0);
        unsigned char sentinel[sizeof(*tokens)];
        memset(sentinel, 0x5a, sizeof(sentinel));
        CHECK(memcmp(&tokens[capacity], sentinel, sizeof(sentinel)) == 0);
    }
    size_t count;
    CHECK(tsc_json_parse(text, strlen(text), tokens, needed, &count) == TSC_OK);
    CHECK(count == needed);
    CHECK(tsc_json_parse(text, strlen(text), NULL, 0, &count) == TSC_ERR_SPACE);
    CHECK(tsc_json_parse(text, strlen(text), NULL, 1, &count) == TSC_ERR_ARGUMENT);
    CHECK(tsc_json_parse(NULL, 0, tokens, TOKEN_CAPACITY, &count) == TSC_ERR_ARGUMENT);
    CHECK(tsc_json_parse(text, strlen(text), tokens, TOKEN_CAPACITY, NULL) == TSC_ERR_ARGUMENT);
#if SIZE_MAX > UINT32_MAX
    CHECK(tsc_json_parse(text, (size_t)UINT32_MAX + 1, tokens, TOKEN_CAPACITY,
                          &count) == TSC_ERR_ARGUMENT);
#endif
    count = parse("[123,\"a\"]", tokens);
    size_t index;
    CHECK(tsc_json_array_at(NULL, count, 0, 0, &index) == TSC_ERR_ARGUMENT);
    CHECK(tsc_json_array_at(tokens, count, 0, 0, NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_json_array_at(tokens, count, count, 0, &index) == TSC_ERR_PROTOCOL);
    CHECK(tsc_json_array_at(tokens, count, 1, 0, &index) == TSC_ERR_PROTOCOL);
    CHECK(tsc_json_object_find("", tokens, count, 0, "a", &index) == TSC_ERR_PROTOCOL);
    CHECK(tsc_json_object_find(NULL, tokens, count, 0, "a", &index) == TSC_ERR_ARGUMENT);
    CHECK(tsc_json_object_find("", tokens, count, 0, NULL, &index) == TSC_ERR_ARGUMENT);
    int64_t integer;
    int boolean;
    CHECK(tsc_json_int64("", NULL, &integer) == TSC_ERR_ARGUMENT);
    CHECK(tsc_json_int64("", tokens, NULL) == TSC_ERR_ARGUMENT);
    CHECK(tsc_json_int64("", tokens, &integer) == TSC_ERR_PROTOCOL);
    CHECK(tsc_json_bool("", tokens, &boolean) == TSC_ERR_PROTOCOL);
    CHECK(tsc_json_bool("", NULL, &boolean) == TSC_ERR_ARGUMENT);
    char output[8];
    size_t length;
    CHECK(tsc_json_string_copy("", tokens, output, sizeof(output),
                                &length) == TSC_ERR_PROTOCOL);
    CHECK(output[0] == '\0' && length == 0);
    CHECK(tsc_json_string_copy("", tokens, NULL, 1, &length) == TSC_ERR_ARGUMENT);
    CHECK(tsc_json_string_copy(NULL, tokens, output, sizeof(output),
                                &length) == TSC_ERR_ARGUMENT);
    CHECK(tsc_json_string_copy("", tokens, output, sizeof(output), NULL) == TSC_ERR_ARGUMENT);

    /* Malformed token metadata cannot make navigation loop or leave its tree. */
    tokens[0].next = (uint32_t)count + 1;
    CHECK(tsc_json_array_at(tokens, count, 0, 0, &index) == TSC_ERR_PROTOCOL);
    tokens[0].next = (uint32_t)count;
    tokens[1].next = 1;
    CHECK(tsc_json_array_at(tokens, count, 0, 0, &index) == TSC_ERR_PROTOCOL);
}

static void deep_nesting(void)
{
    enum { DEPTH = 4096 };
    static char text[DEPTH * 2 + 2];
    static tsc_json_token tokens[DEPTH + 1];
    memset(text, '[', DEPTH);
    text[DEPTH] = '0';
    memset(text + DEPTH + 1, ']', DEPTH);
    size_t count;
    CHECK(tsc_json_parse(text, DEPTH * 2 + 1, tokens, DEPTH + 1, &count) == TSC_OK);
    CHECK(count == DEPTH + 1);
    for (size_t i = 0; i < DEPTH; ++i) {
        CHECK(tokens[i].start == i && tokens[i].end == DEPTH * 2 + 1 - i);
        CHECK(tokens[i].next == count);
        CHECK(tokens[i].parent == (i == 0 ? TSC_JSON_NONE : i - 1));
    }
    CHECK(tsc_json_parse(text, DEPTH * 2, tokens, DEPTH + 1, &count) == TSC_ERR_TRUNCATED);
}

static uint32_t random_state = 0x01234567u;

static uint32_t random_u32(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}

static void fuzz_smoke(void)
{
    const char alphabet[] = "{}[]:,\"\\-+0123456789.eEtruefalsnux \r\n\t";
    const char seed[] = "{\"a\":[true,false,null,1.5e2,{\"b\":\"\\u00e9\"}],\"c\":123}";
    for (unsigned iteration = 0; iteration < 100000; ++iteration) {
        char text[128];
        size_t length;
        if (iteration % 2 == 0) {
            length = random_u32() % sizeof(text);
            for (size_t i = 0; i < length; ++i) {
                uint32_t random = random_u32();
                text[i] = iteration % 4 == 0 ?
                    alphabet[random % (sizeof(alphabet) - 1)] : (char)random;
            }
        } else {
            length = sizeof(seed) - 1;
            memcpy(text, seed, length);
            unsigned changes = 1 + random_u32() % 4;
            for (unsigned i = 0; i < changes; ++i)
                text[random_u32() % length] = (char)random_u32();
            if (iteration % 5 == 0)
                length = random_u32() % (length + 1);
        }
        tsc_json_token tokens[TOKEN_CAPACITY];
        size_t count = SIZE_MAX;
        int rc = tsc_json_parse(text, length, tokens, TOKEN_CAPACITY, &count);
        if (rc == TSC_OK)
            validate(text, length, tokens, count);
        else {
            CHECK(rc == TSC_ERR_PROTOCOL || rc == TSC_ERR_TRUNCATED);
            CHECK(count == 0);
        }
    }
}

int main(void)
{
    navigation();
    strings();
    numbers();
    malformed();
    bounds_and_arguments();
    deep_nesting();
    fuzz_smoke();
    printf("control JSON tests passed; token storage = %zu bytes\n", sizeof(tsc_json_token));
    return 0;
}
