#include "project.h"
#include <string.h>

enum { SKIP, KEEP, ROOT, NODE, PEERS, PEERS_CHANGED };
enum { FIRST, KEY, COLON, VALUE, AFTER };

static int emit(tsc_json_project *p, const char *s, size_t n)
{
    if (p->used >= p->capacity || n >= p->capacity - p->used)
        return p->error = TSC_ERR_SPACE;
    memcpy(p->output + p->used, s, n);
    p->used += n;
    return TSC_OK;
}
static int space(unsigned char c)
{ return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

static unsigned field_context(unsigned parent, const char *name)
{
    if (parent == KEEP || parent == SKIP) return parent;
    if (parent == ROOT) {
        if (!strcmp(name, "Node")) return NODE;
        if (!strcmp(name, "Peers")) return PEERS;
        if (!strcmp(name, "PeersChanged")) return PEERS_CHANGED;
        if (!strcmp(name, "PacketFilter") || !strcmp(name, "PacketFilters") ||
            !strcmp(name, "ControlTime")) return KEEP;
#if TSC_ENABLE_DERP
        if (!strcmp(name, "DERPMap")) return KEEP;
#endif
    } else if (parent == NODE) {
        static const char *const names[] = {"ID", "Key", "DiscoKey", "Name",
            "Addresses", "Endpoints", "HomeDERP", "DERP", "KeyExpiry",
            "MachineAuthorized", "Expired", "Online"};
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
            if (!strcmp(name, names[i])) return KEEP;
    }
    return SKIP;
}

static int finish_scalar(tsc_json_project *p)
{
    tsc_json_token token;
    size_t count;
    int r = tsc_json_parse(p->text, p->scalar_length, &token, 1, &count);
    if (r) return p->error = r;
    if (p->key) {
        char name[64];
        size_t length;
        if (token.type != TSC_JSON_STRING || !p->depth)
            return p->error = TSC_ERR_PROTOCOL;
        unsigned parent = p->frames[p->depth - 1].context;
        r = tsc_json_string_copy(p->text, &token, name, sizeof(name), &length);
        unsigned child = parent == KEEP ? KEEP : SKIP;
        if (!r && strlen(name) == length) child = field_context(parent, name);
        else if (r != TSC_ERR_SPACE && r != TSC_OK) return p->error = r;
        if (parent == ROOT && (child == PEERS || child == PEERS_CHANGED)) {
            unsigned bit = child == PEERS ? 1u : 2u;
            if (p->peer_arrays_seen & bit) child = SKIP;
            else p->peer_arrays_seen |= bit;
        }
        p->frames[p->depth - 1].child = (unsigned char)child;
        p->frames[p->depth - 1].state = COLON;
        if (child != SKIP) {
            if (p->frames[p->depth - 1].emitted && emit(p, ",", 1)) return p->error;
            if (emit(p, p->text, p->scalar_length) || emit(p, ":", 1)) return p->error;
            p->frames[p->depth - 1].emitted = 1;
        }
    } else {
        if (p->selected != SKIP && emit(p, p->text, p->scalar_length)) return p->error;
        if (!p->depth) p->complete = 1;
    }
    p->scalar = 0;
    p->scalar_length = 0;
    return TSC_OK;
}

void tsc_json_project_init(tsc_json_project *p, char *out, size_t capacity)
{
    memset(p, 0, sizeof(*p));
    p->output = out;
    p->capacity = capacity;
    if (!out || !capacity) p->error = TSC_ERR_ARGUMENT;
    /* Do not touch output until input arrives: a sequential transport may
     * share its request storage with the response destination. */
}

int tsc_json_project_feed(void *user, const void *bytes, size_t length)
{
    tsc_json_project *p = user;
    const unsigned char *input = bytes;
    if (!p || (!bytes && length)) return TSC_ERR_ARGUMENT;
    if (p->error) return p->error;
    for (size_t i = 0; i < length;) {
        unsigned char c = input[i];
        if (p->scalar) {
            if (p->scalar == 2 && (space(c) || c == ',' || c == ']' || c == '}')) {
                if (finish_scalar(p)) return p->error;
                continue;
            }
            if (p->scalar_length == sizeof(p->text)) return p->error = TSC_ERR_SPACE;
            p->text[p->scalar_length++] = (char)c;
            ++i;
            if (p->scalar == 1) {
                if (p->escaped) p->escaped = 0;
                else if (c == '\\') p->escaped = 1;
                else if (c == '"' && finish_scalar(p)) return p->error;
            }
            continue;
        }
        if (space(c)) { ++i; continue; }
        if (!p->depth && p->complete) return p->error = TSC_ERR_PROTOCOL;
        if (p->depth) {
            unsigned d = p->depth - 1;
            unsigned state = p->frames[d].state, type = p->frames[d].type;
            if (state == FIRST || state == AFTER) {
                if ((type == '{' && c == '}') || (type == '[' && c == ']')) {
                    if (p->frames[d].context != SKIP && emit(p, (const char *)&input[i], 1)) return p->error;
                    if (p->peer_depth == p->depth) {
                        int keep = p->peer_handler(p->peer_user,
                            p->output + p->peer_start, p->used - p->peer_start, p->peer_source);
                        if (keep < 0) return p->error = keep;
                        if (!keep) {
                            p->used = p->peer_mark;
                            p->frames[d - 1].emitted = (unsigned char)p->peer_prior;
                        }
                        p->peer_depth = 0;
                    }
                    --p->depth;
                    if (!p->depth) p->complete = 1;
                    ++i;
                    continue;
                }
                if (state == AFTER) {
                    if (c != ',') return p->error = TSC_ERR_PROTOCOL;
                    p->frames[d].state = type == '{' ? KEY : VALUE;
                    ++i;
                    continue;
                }
                state = p->frames[d].state = type == '{' ? KEY : VALUE;
            }
            if (state == KEY) {
                if (c != '"') return p->error = TSC_ERR_PROTOCOL;
                p->key = 1; p->scalar = 1; p->escaped = 0;
                p->text[0] = '"'; p->scalar_length = 1;
                ++i;
                continue;
            }
            if (state == COLON) {
                if (c != ':') return p->error = TSC_ERR_PROTOCOL;
                p->frames[d].state = VALUE;
                ++i;
                continue;
            }
            if (state != VALUE) return p->error = TSC_ERR_PROTOCOL;
        }
        if (c != '{' && c != '[' && c != '"' && c != '-' &&
            c != 't' && c != 'f' && c != 'n' && (c < '0' || c > '9'))
            return p->error = TSC_ERR_PROTOCOL;
        unsigned context = ROOT;
        if (p->depth) {
            unsigned d = p->depth - 1;
            context = p->frames[d].type == '{' ? p->frames[d].child :
                (p->frames[d].context == PEERS || p->frames[d].context == PEERS_CHANGED) ? NODE : p->frames[d].context;
            if (p->peer_handler && (p->frames[d].context == PEERS || p->frames[d].context == PEERS_CHANGED) && c == '{') {
                p->peer_depth = p->depth + 1;
                p->peer_mark = p->used;
                p->peer_prior = p->frames[d].emitted;
                p->peer_source = p->frames[d].context == PEERS ? 1u : 2u;
            }
            if (p->frames[d].type == '[' && context != SKIP) {
                if (p->frames[d].emitted && emit(p, ",", 1)) return p->error;
                p->frames[d].emitted = 1;
            }
            p->frames[d].state = AFTER;
        } else if (p->started) return p->error = TSC_ERR_PROTOCOL;
        p->started = 1;
        if (c == '{' || c == '[') {
            if (p->depth == sizeof(p->frames) / sizeof(p->frames[0])) return p->error = TSC_ERR_SPACE;
            if ((context == ROOT || context == NODE) && c != '{') context = KEEP;
            if ((context == PEERS || context == PEERS_CHANGED) && c != '[') context = KEEP;
            if (p->peer_depth == p->depth + 1) p->peer_start = p->used;
            if (context != SKIP && emit(p, (const char *)&input[i], 1)) return p->error;
            unsigned d = p->depth++;
            p->frames[d].type = c;
            p->frames[d].state = FIRST;
            p->frames[d].context = (unsigned char)context;
            p->frames[d].child = SKIP;
            p->frames[d].emitted = 0;
        } else {
            p->key = 0; p->escaped = 0;
            p->selected = context;
            p->scalar = c == '"' ? 1 : 2;
            p->text[0] = (char)c;
            p->scalar_length = 1;
        }
        ++i;
    }
    return TSC_OK;
}

int tsc_json_project_finish(tsc_json_project *p)
{
    if (!p) return TSC_ERR_ARGUMENT;
    if (p->error) return p->error;
    if (p->scalar == 1) return p->error = TSC_ERR_TRUNCATED;
    if (p->scalar && finish_scalar(p)) return p->error;
    if (!p->complete || p->depth) return p->error = TSC_ERR_TRUNCATED;
    p->output[p->used] = 0;
    return TSC_OK;
}
