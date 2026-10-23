#ifndef TSC_CONTROL_PROJECT_H
#define TSC_CONTROL_PROJECT_H
#include "json.h"

/* Validate the entire MapResponse while retaining only consumed fields.
 * Policy values are retained verbatim except for insignificant whitespace.
 * Unknown metadata is bounded by nesting/scalar size, not total input size. */
typedef struct {
    char *output;
    size_t capacity, used, scalar_length;
    struct { unsigned char type, state, context, child, emitted; } frames[32];
    unsigned depth, started, complete, scalar, escaped, key, selected;
    /* Consume complete peer objects (source 1=Peers, 2=PeersChanged). Return
     * zero to reuse their JSON space after decoding, one to retain it. */
    int (*peer_handler)(void *, const char *, size_t, unsigned);
    void *peer_user;
    size_t peer_mark, peer_start;
    unsigned peer_depth, peer_prior;
    unsigned peer_source, peer_arrays_seen;
    int error;
    char text[512];
} tsc_json_project;
void tsc_json_project_init(tsc_json_project *p, char *out, size_t capacity);
int tsc_json_project_feed(void *user, const void *bytes, size_t length);
int tsc_json_project_finish(tsc_json_project *p);
#endif
