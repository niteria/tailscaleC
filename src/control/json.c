#include "json.h"

#include <limits.h>
#include <string.h>

static int whitespace(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static void skip_whitespace(const char *text, size_t length, size_t *position)
{
    while (*position < length && whitespace((unsigned char)text[*position]))
        ++*position;
}

static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return (int)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (int)(c - 'a') + 10;
    if (c >= 'A' && c <= 'F')
        return (int)(c - 'A') + 10;
    return -1;
}

static int hex4(const char *text, size_t length, size_t *position, uint32_t *value)
{
    uint32_t result = 0;
    for (unsigned i = 0; i < 4; ++i) {
        if (*position == length)
            return TSC_ERR_TRUNCATED;
        int digit = hex_digit((unsigned char)text[*position]);
        if (digit < 0)
            return TSC_ERR_PROTOCOL;
        result = (result << 4) | (unsigned)digit;
        ++*position;
    }
    *value = result;
    return TSC_OK;
}

static size_t utf8_encode(uint32_t value, unsigned char output[4])
{
    if (value <= 0x7f) {
        output[0] = (unsigned char)value;
        return 1;
    }
    if (value <= 0x7ff) {
        output[0] = (unsigned char)(0xc0u | (value >> 6));
        output[1] = (unsigned char)(0x80u | (value & 0x3fu));
        return 2;
    }
    if (value <= 0xffff) {
        output[0] = (unsigned char)(0xe0u | (value >> 12));
        output[1] = (unsigned char)(0x80u | ((value >> 6) & 0x3fu));
        output[2] = (unsigned char)(0x80u | (value & 0x3fu));
        return 3;
    }
    output[0] = (unsigned char)(0xf0u | (value >> 18));
    output[1] = (unsigned char)(0x80u | ((value >> 12) & 0x3fu));
    output[2] = (unsigned char)(0x80u | ((value >> 6) & 0x3fu));
    output[3] = (unsigned char)(0x80u | (value & 0x3fu));
    return 4;
}

/* Read one string character, preserving literal UTF-8 and decoding escapes. */
static int string_unit(const char *text, size_t length, size_t *position,
                        unsigned char output[4], size_t *width)
{
    if (*position == length)
        return TSC_ERR_TRUNCATED;
    unsigned char c = (unsigned char)text[(*position)++];
    if (c < 0x20 || c == '"')
        return TSC_ERR_PROTOCOL;
    if (c == '\\') {
        if (*position == length)
            return TSC_ERR_TRUNCATED;
        c = (unsigned char)text[(*position)++];
        switch (c) {
        case '"': case '\\': case '/': output[0] = c; break;
        case 'b': output[0] = '\b'; break;
        case 'f': output[0] = '\f'; break;
        case 'n': output[0] = '\n'; break;
        case 'r': output[0] = '\r'; break;
        case 't': output[0] = '\t'; break;
        case 'u': {
            uint32_t value;
            int rc = hex4(text, length, position, &value);
            if (rc != TSC_OK)
                return rc;
            if (value >= 0xdc00 && value <= 0xdfff)
                return TSC_ERR_PROTOCOL;
            if (value >= 0xd800 && value <= 0xdbff) {
                const char continuation[] = "\\u";
                for (size_t i = 0; i < 2; ++i) {
                    if (*position == length)
                        return TSC_ERR_TRUNCATED;
                    if (text[(*position)++] != continuation[i])
                        return TSC_ERR_PROTOCOL;
                }
                uint32_t low;
                rc = hex4(text, length, position, &low);
                if (rc != TSC_OK)
                    return rc;
                if (low < 0xdc00 || low > 0xdfff)
                    return TSC_ERR_PROTOCOL;
                value = 0x10000u + ((value - 0xd800u) << 10) + (low - 0xdc00u);
            }
            *width = utf8_encode(value, output);
            return TSC_OK;
        }
        default: return TSC_ERR_PROTOCOL;
        }
        *width = 1;
        return TSC_OK;
    }
    output[0] = c;
    if (c < 0x80) {
        *width = 1;
        return TSC_OK;
    }
    size_t bytes;
    if (c >= 0xc2 && c <= 0xdf)
        bytes = 2;
    else if (c >= 0xe0 && c <= 0xef)
        bytes = 3;
    else if (c >= 0xf0 && c <= 0xf4)
        bytes = 4;
    else
        return TSC_ERR_PROTOCOL;
    for (size_t i = 1; i < bytes; ++i) {
        if (*position == length)
            return TSC_ERR_TRUNCATED;
        unsigned char next = (unsigned char)text[(*position)++];
        if (next < 0x80 || next > 0xbf)
            return TSC_ERR_PROTOCOL;
        if (i == 1 && ((c == 0xe0 && next < 0xa0) ||
                       (c == 0xed && next > 0x9f) ||
                       (c == 0xf0 && next < 0x90) ||
                       (c == 0xf4 && next > 0x8f)))
            return TSC_ERR_PROTOCOL;
        output[i] = next;
    }
    *width = bytes;
    return TSC_OK;
}

static int read_string(const char *text, size_t length, size_t *position,
                        tsc_json_token *token)
{
    token->type = TSC_JSON_STRING;
    token->start = (uint32_t)++*position;
    for (;;) {
        if (*position == length)
            return TSC_ERR_TRUNCATED;
        if (text[*position] == '"') {
            token->end = (uint32_t)(*position)++;
            return TSC_OK;
        }
        unsigned char output[4];
        size_t width;
        int rc = string_unit(text, length, position, output, &width);
        if (rc != TSC_OK)
            return rc;
    }
}

static int digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

static int read_number(const char *text, size_t length, size_t *position)
{
    if (text[*position] == '-') {
        if (++*position == length)
            return TSC_ERR_TRUNCATED;
    }
    if (text[*position] == '0')
        ++*position;
    else if (text[*position] >= '1' && text[*position] <= '9') {
        do { ++*position; }
        while (*position < length && digit((unsigned char)text[*position]));
    } else
        return TSC_ERR_PROTOCOL;
    if (*position < length && text[*position] == '.') {
        if (++*position == length)
            return TSC_ERR_TRUNCATED;
        if (!digit((unsigned char)text[*position]))
            return TSC_ERR_PROTOCOL;
        do { ++*position; }
        while (*position < length && digit((unsigned char)text[*position]));
    }
    if (*position < length && (text[*position] == 'e' || text[*position] == 'E')) {
        if (++*position == length)
            return TSC_ERR_TRUNCATED;
        if (text[*position] == '+' || text[*position] == '-') {
            if (++*position == length)
                return TSC_ERR_TRUNCATED;
        }
        if (!digit((unsigned char)text[*position]))
            return TSC_ERR_PROTOCOL;
        do { ++*position; }
        while (*position < length && digit((unsigned char)text[*position]));
    }
    return TSC_OK;
}

static int read_literal(const char *text, size_t length, size_t *position,
                         const char *literal)
{
    for (size_t i = 0; literal[i] != '\0'; ++i) {
        if (*position == length)
            return TSC_ERR_TRUNCATED;
        if (text[(*position)++] != literal[i])
            return TSC_ERR_PROTOCOL;
    }
    return TSC_OK;
}

int tsc_json_parse(const char *text, size_t length, tsc_json_token *tokens,
                   size_t capacity, size_t *count)
{
    if (count == NULL)
        return TSC_ERR_ARGUMENT;
    *count = 0;
    if (text == NULL || (tokens == NULL && capacity != 0) ||
        length > TSC_JSON_NONE || capacity > TSC_JSON_NONE)
        return TSC_ERR_ARGUMENT;
    enum { VALUE, OBJECT_FIRST, ARRAY_FIRST, KEY, AFTER_VALUE } state = VALUE;
    size_t position = 0, used = 0;
    uint32_t parent = TSC_JSON_NONE;
    for (;;) {
        skip_whitespace(text, length, &position);
        if (position == length) {
            if (state == AFTER_VALUE && parent == TSC_JSON_NONE) {
                *count = used;
                return TSC_OK;
            }
            return TSC_ERR_TRUNCATED;
        }
        char c = text[position];
        if (state == OBJECT_FIRST || state == ARRAY_FIRST) {
            if ((state == OBJECT_FIRST && c == '}') ||
                (state == ARRAY_FIRST && c == ']')) {
                tokens[parent].end = (uint32_t)++position;
                tokens[parent].next = (uint32_t)used;
                parent = tokens[parent].parent;
                state = AFTER_VALUE;
                continue;
            }
            state = state == OBJECT_FIRST ? KEY : VALUE;
        }
        if (state == KEY) {
            if (c != '"')
                return TSC_ERR_PROTOCOL;
            if (used == capacity)
                return TSC_ERR_SPACE;
            tsc_json_token *token = &tokens[used++];
            token->parent = parent;
            token->next = (uint32_t)used;
            int rc = read_string(text, length, &position, token);
            if (rc != TSC_OK)
                return rc;
            skip_whitespace(text, length, &position);
            if (position == length)
                return TSC_ERR_TRUNCATED;
            if (text[position++] != ':')
                return TSC_ERR_PROTOCOL;
            state = VALUE;
            continue;
        }
        if (state == AFTER_VALUE) {
            if (parent == TSC_JSON_NONE)
                return TSC_ERR_PROTOCOL;
            tsc_json_type type = tokens[parent].type;
            if ((type == TSC_JSON_OBJECT && c == '}') ||
                (type == TSC_JSON_ARRAY && c == ']')) {
                tokens[parent].end = (uint32_t)++position;
                tokens[parent].next = (uint32_t)used;
                parent = tokens[parent].parent;
                continue;
            }
            if (c != ',')
                return TSC_ERR_PROTOCOL;
            ++position;
            state = type == TSC_JSON_OBJECT ? KEY : VALUE;
            continue;
        }
        if (used == capacity)
            return TSC_ERR_SPACE;
        uint32_t index = (uint32_t)used;
        tsc_json_token *token = &tokens[used++];
        token->start = (uint32_t)position;
        token->parent = parent;
        token->next = (uint32_t)used;
        if (c == '{' || c == '[') {
            token->type = c == '{' ? TSC_JSON_OBJECT : TSC_JSON_ARRAY;
            token->end = 0;
            ++position;
            parent = index;
            state = c == '{' ? OBJECT_FIRST : ARRAY_FIRST;
            continue;
        }
        int rc;
        if (c == '"')
            rc = read_string(text, length, &position, token);
        else if (c == '-' || digit((unsigned char)c)) {
            token->type = TSC_JSON_NUMBER;
            rc = read_number(text, length, &position);
        } else if (c == 't') {
            token->type = TSC_JSON_TRUE;
            rc = read_literal(text, length, &position, "true");
        } else if (c == 'f') {
            token->type = TSC_JSON_FALSE;
            rc = read_literal(text, length, &position, "false");
        } else if (c == 'n') {
            token->type = TSC_JSON_NULL;
            rc = read_literal(text, length, &position, "null");
        } else
            return TSC_ERR_PROTOCOL;
        if (rc != TSC_OK)
            return rc;
        if (token->type != TSC_JSON_STRING)
            token->end = (uint32_t)position;
        state = AFTER_VALUE;
    }
}

static int decode_string(const char *text, const tsc_json_token *token,
                           char *destination, size_t *length,
                           const char *expected, size_t expected_length,
                           int *matches)
{
    size_t position = token->start, output_length = 0;
    int equal = 1;
    while (position < token->end) {
        unsigned char bytes[4];
        size_t width;
        int rc = string_unit(text, token->end, &position, bytes, &width);
        if (rc != TSC_OK)
            return rc;
        if (destination != NULL)
            memcpy(destination + output_length, bytes, width);
        if (expected != NULL && (output_length > expected_length ||
            width > expected_length - output_length ||
            memcmp(expected + output_length, bytes, width) != 0))
            equal = 0;
        output_length += width;
    }
    if (destination != NULL)
        destination[output_length] = '\0';
    if (length != NULL)
        *length = output_length;
    if (matches != NULL)
        *matches = equal && output_length == expected_length;
    return TSC_OK;
}

int tsc_json_string_copy(const char *text, const tsc_json_token *token,
                         char *destination, size_t capacity, size_t *length)
{
    if (length != NULL)
        *length = 0;
    if (destination != NULL && capacity != 0)
        destination[0] = '\0';
    if (text == NULL || token == NULL || length == NULL ||
        (destination == NULL && capacity != 0))
        return TSC_ERR_ARGUMENT;
    if (token->type != TSC_JSON_STRING || token->start > token->end)
        return TSC_ERR_PROTOCOL;
    int rc = decode_string(text, token, NULL, length, NULL, 0, NULL);
    if (rc != TSC_OK)
        return rc;
    if (capacity <= *length)
        return TSC_ERR_SPACE;
    return decode_string(text, token, destination, NULL, NULL, 0, NULL);
}

static int valid_container(const tsc_json_token *tokens, size_t count,
                             size_t index, tsc_json_type type)
{
    return index < count && tokens[index].type == type &&
           tokens[index].next > index && tokens[index].next <= count;
}

int tsc_json_object_find(const char *text, const tsc_json_token *tokens,
                         size_t count, size_t object_index, const char *key,
                         size_t *value_index)
{
    if (text == NULL || tokens == NULL || key == NULL || value_index == NULL)
        return TSC_ERR_ARGUMENT;
    if (!valid_container(tokens, count, object_index, TSC_JSON_OBJECT))
        return TSC_ERR_PROTOCOL;
    size_t expected_length = strlen(key);
    size_t end = tokens[object_index].next;
    for (size_t index = object_index + 1; index < end;) {
        const tsc_json_token *name = &tokens[index];
        size_t value = index + 1;
        if (name->type != TSC_JSON_STRING || name->start > name->end ||
            name->parent != object_index || name->next != value || value >= end ||
            tokens[value].parent != object_index ||
            tokens[value].next <= value || tokens[value].next > end)
            return TSC_ERR_PROTOCOL;
        int matches;
        int rc = decode_string(text, name, NULL, NULL, key, expected_length, &matches);
        if (rc != TSC_OK)
            return rc;
        if (matches) {
            *value_index = value;
            return TSC_OK;
        }
        index = tokens[value].next;
    }
    return TSC_AGAIN;
}

int tsc_json_array_at(const tsc_json_token *tokens, size_t count,
                      size_t array_index, size_t element_index,
                      size_t *value_index)
{
    if (tokens == NULL || value_index == NULL)
        return TSC_ERR_ARGUMENT;
    if (!valid_container(tokens, count, array_index, TSC_JSON_ARRAY))
        return TSC_ERR_PROTOCOL;
    size_t end = tokens[array_index].next;
    for (size_t index = array_index + 1; index < end;) {
        if (tokens[index].parent != array_index || tokens[index].next <= index ||
            tokens[index].next > end)
            return TSC_ERR_PROTOCOL;
        if (element_index == 0) {
            *value_index = index;
            return TSC_OK;
        }
        --element_index;
        index = tokens[index].next;
    }
    return TSC_AGAIN;
}

int tsc_json_int64(const char *text, const tsc_json_token *token, int64_t *value)
{
    if (text == NULL || token == NULL || value == NULL)
        return TSC_ERR_ARGUMENT;
    if (token->type != TSC_JSON_NUMBER || token->start >= token->end)
        return TSC_ERR_PROTOCOL;
    size_t position = token->start;
    int negative = text[position] == '-';
    if (negative && ++position == token->end)
        return TSC_ERR_PROTOCOL;
    uint64_t limit = negative ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX;
    uint64_t result = 0;
    while (position < token->end) {
        unsigned char c = (unsigned char)text[position++];
        if (!digit(c))
            return TSC_ERR_PROTOCOL;
        unsigned number = c - '0';
        if (result > (limit - number) / 10)
            return TSC_ERR_PROTOCOL;
        result = result * 10 + number;
    }
    if (negative)
        *value = result == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)result;
    else
        *value = (int64_t)result;
    return TSC_OK;
}

int tsc_json_bool(const char *text, const tsc_json_token *token, int *value)
{
    if (text == NULL || token == NULL || value == NULL)
        return TSC_ERR_ARGUMENT;
    if (token->type != TSC_JSON_TRUE && token->type != TSC_JSON_FALSE)
        return TSC_ERR_PROTOCOL;
    *value = token->type == TSC_JSON_TRUE;
    return TSC_OK;
}
