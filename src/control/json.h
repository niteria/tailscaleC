#ifndef TAILSCALEC_CONTROL_JSON_H
#define TAILSCALEC_CONTROL_JSON_H

#include "tailscalec/tsc.h"

/* Internal bounded, zero-copy JSON parser. No allocation or recursive calls.
 * Tokens and input remain owned by the caller. All helpers require tokens from
 * a successful parse of the same, unchanged input. */
typedef enum {
    TSC_JSON_OBJECT = 1,
    TSC_JSON_ARRAY,
    TSC_JSON_STRING,
    TSC_JSON_NUMBER,
    TSC_JSON_TRUE,
    TSC_JSON_FALSE,
    TSC_JSON_NULL
} tsc_json_type;

#define TSC_JSON_NONE UINT32_MAX

typedef struct {
    tsc_json_type type;
    uint32_t start;  /* Inclusive input offset; strings exclude their quotes. */
    uint32_t end;    /* Exclusive input offset. */
    uint32_t parent; /* Immediate enclosing object/array, or TSC_JSON_NONE. */
    uint32_t next;   /* Index immediately following this entire subtree. */
} tsc_json_token;

/* Accept exactly one JSON value plus optional JSON whitespace. UTF-8 and UTF-16
 * surrogate escapes must encode valid Unicode scalar values. Duplicate object
 * member names are accepted; object_find returns the first occurrence.
 * A valid but incomplete prefix returns TSC_ERR_TRUNCATED, invalid syntax
 * TSC_ERR_PROTOCOL, and exhausted token storage TSC_ERR_SPACE. On failure
 * *count is zero and token storage contents are unspecified. */
int tsc_json_parse(const char *text, size_t length, tsc_json_token *tokens,
                   size_t capacity, size_t *count);

/* Lookup helpers return TSC_AGAIN if the member/index is absent. */
int tsc_json_object_find(const char *text, const tsc_json_token *tokens,
                         size_t count, size_t object_index, const char *key,
                         size_t *value_index);
int tsc_json_array_at(const tsc_json_token *tokens, size_t count,
                      size_t array_index, size_t element_index,
                      size_t *value_index);

/* Decode to UTF-8 and add a NUL terminator. *length excludes that terminator
 * and can include embedded NULs originating from escaped U+0000. For a valid
 * token, *length reports the required size even on TSC_ERR_SPACE. A zero-size
 * NULL destination may be used to query this length. On failure, a nonempty
 * destination is an empty string. Source and destination must not overlap. */
int tsc_json_string_copy(const char *text, const tsc_json_token *token,
                         char *destination, size_t capacity, size_t *length);
int tsc_json_int64(const char *text, const tsc_json_token *token, int64_t *value);
int tsc_json_bool(const char *text, const tsc_json_token *token, int *value);

#endif
