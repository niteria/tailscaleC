/* DERP wire protocol: tailscale.com/derp (BSD-3-Clause). This implementation
 * is independent C code, using the published framing and NaCl login format. */
#include "tailscalec/derp.h"

#if TSC_ENABLE_DERP

#include "tailscalec/crypto.h"
#include "tailscalec/nacl.h"
#include <stdio.h>
#include <string.h>

enum {
    ST_INITIAL, ST_HTTP, ST_SERVER_KEY, ST_SERVER_INFO, ST_READY, ST_FAILED
};
enum {
    F_SERVER_KEY = 1, F_CLIENT_INFO = 2, F_SERVER_INFO = 3, F_SEND = 4,
    F_RECEIVE = 5, F_KEEPALIVE = 6, F_PREFERRED = 7, F_GONE = 8,
    F_PING = 0x12, F_PONG = 0x13, F_HEALTH = 0x14, F_RESTART = 0x15
};

static uint32_t read32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void write32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static int fail(tsc_derp *d, int error)
{
    d->stage = ST_FAILED;
    d->error = error;
    tsc_crypto_zero(d->private_key, sizeof(d->private_key));
    tsc_crypto_zero(d->shared_key, sizeof(d->shared_key));
    return error;
}

static int pending(const tsc_derp *d)
{
    return d->transmit_offset < d->transmit_length;
}

static void frame_begin(tsc_derp *d, uint8_t type, size_t length)
{
    d->transmit_buffer[0] = type;
    write32(d->transmit_buffer + 1, (uint32_t)length);
    d->transmit_offset = 0;
    d->transmit_length = length + 5;
}

static void queue_pong(tsc_derp *d)
{
    frame_begin(d, F_PONG, 8);
    memcpy(d->transmit_buffer + 5, d->pending_pong, 8);
    d->has_pending_pong = 0;
}

int tsc_derp_init(tsc_derp *d, const uint8_t key[32])
{
    int status;
    if (!d || !key) return TSC_ERR_ARGUMENT;
    memset(d, 0, sizeof(*d));
    memcpy(d->private_key, key, 32);
    status = tsc_crypto_x25519_public(d->public_key, key);
    return status == TSC_OK ? TSC_OK : fail(d, status);
}

void tsc_derp_clear(tsc_derp *d)
{
    if (d) tsc_crypto_zero(d, sizeof(*d));
}

int tsc_derp_start(tsc_derp *d, const char *host)
{
    size_t i;
    int n;
    if (!d || d->stage != ST_INITIAL) return TSC_ERR_ARGUMENT;
    if (!host) {
        d->stage = ST_SERVER_KEY;
        return TSC_OK;
    }
    for (i = 0; i <= 260 && host[i]; ++i) {
        unsigned char c = (unsigned char)host[i];
        if (c <= 32 || c >= 127) return TSC_ERR_ARGUMENT;
    }
    if (!i || i > 260) return TSC_ERR_ARGUMENT;
    n = snprintf((char *)d->transmit_buffer, sizeof(d->transmit_buffer),
                 "GET /derp HTTP/1.1\r\nHost: %s\r\nUpgrade: DERP\r\n"
                 "Connection: Upgrade\r\n\r\n", host);
    if (n < 0 || (size_t)n >= sizeof(d->transmit_buffer)) return TSC_ERR_SPACE;
    d->transmit_length = (size_t)n;
    d->stage = ST_HTTP;
    return TSC_OK;
}

int tsc_derp_is_ready(const tsc_derp *d)
{
    return d && d->stage == ST_READY;
}

static int ascii_equal(const uint8_t *s, size_t n, const char *expected)
{
    size_t i;
    if (strlen(expected) != n) return 0;
    for (i = 0; i < n; ++i) {
        unsigned a = s[i], b = (unsigned char)expected[i];
        if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
        if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
        if (a != b) return 0;
    }
    return 1;
}

static int token_has(const uint8_t *s, size_t n, const char *token)
{
    size_t start = 0, end;
    while (start < n) {
        while (start < n && (s[start] == ' ' || s[start] == '\t' ||
                            s[start] == ',')) ++start;
        end = start;
        while (end < n && s[end] != ',') ++end;
        {
            size_t trimmed = end;
            while (trimmed > start && (s[trimmed-1] == ' ' ||
                                      s[trimmed-1] == '\t')) --trimmed;
            if (ascii_equal(s + start, trimmed - start, token)) return 1;
        }
        start = end + 1;
    }
    return 0;
}

static int parse_http(tsc_derp *d)
{
    const uint8_t *s = d->receive_buffer;
    size_t n = d->frame_used, i = 0, line_end, colon, value, end;
    int upgrade = 0, connection = 0;
    if (n < 16 || memcmp(s, "HTTP/1.1 101", 12) != 0 ||
        (s[12] != ' ' && s[12] != '\r')) return TSC_ERR_PROTOCOL;
    while (i + 1 < n && !(s[i] == '\r' && s[i+1] == '\n')) ++i;
    i += 2;
    while (i + 1 < n) {
        if (s[i] == '\r' && s[i+1] == '\n') break;
        line_end = i;
        while (line_end + 1 < n && !(s[line_end] == '\r' &&
                                      s[line_end+1] == '\n')) ++line_end;
        colon = i;
        while (colon < line_end && s[colon] != ':') ++colon;
        if (colon == i || colon == line_end) return TSC_ERR_PROTOCOL;
        value = colon + 1;
        while (value < line_end && (s[value] == ' ' || s[value] == '\t')) ++value;
        end = line_end;
        while (end > value && (s[end-1] == ' ' || s[end-1] == '\t')) --end;
        if (ascii_equal(s + i, colon - i, "upgrade"))
            upgrade |= token_has(s + value, end - value, "derp");
        if (ascii_equal(s + i, colon - i, "connection"))
            connection |= token_has(s + value, end - value, "upgrade");
        i = line_end + 2;
    }
    return upgrade && connection ? TSC_OK : TSC_ERR_PROTOCOL;
}

/* Strict bounded JSON syntax validation, without allocating a document tree.
 * ServerInfo is advisory; the authenticated JSON is exposed in READY so a
 * caller can apply future server fields/rate limits without a protocol change. */
typedef struct { const uint8_t *s; size_t n, i; } json_reader;

static void json_space(json_reader *j)
{
    while (j->i < j->n && (j->s[j->i] == ' ' || j->s[j->i] == '\t' ||
           j->s[j->i] == '\r' || j->s[j->i] == '\n')) ++j->i;
}

static int json_string(json_reader *j)
{
    if (j->i >= j->n || j->s[j->i++] != '"') return 0;
    while (j->i < j->n) {
        uint8_t c = j->s[j->i++];
        if (c == '"') return 1;
        if (c < 32) return 0;
        if (c == '\\') {
            size_t k;
            if (j->i >= j->n) return 0;
            c = j->s[j->i++];
            if (c != 'u') {
                if (!c || !strchr("\"\\/bfnrt", c)) return 0;
            } else {
                for (k = 0; k < 4; ++k) {
                    if (j->i >= j->n) return 0;
                    c = j->s[j->i++];
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                          (c >= 'A' && c <= 'F'))) return 0;
                }
            }
        }
    }
    return 0;
}

static int json_value(json_reader *j, unsigned depth)
{
    uint8_t c, closing;
    size_t start;
    if (depth > 16) return 0;
    json_space(j);
    if (j->i >= j->n) return 0;
    c = j->s[j->i];
    if (c == '"') return json_string(j);
    if (c == '{' || c == '[') {
        closing = c == '{' ? '}' : ']';
        ++j->i;
        json_space(j);
        if (j->i < j->n && j->s[j->i] == closing) { ++j->i; return 1; }
        for (;;) {
            if (c == '{') {
                if (!json_string(j)) return 0;
                json_space(j);
                if (j->i >= j->n || j->s[j->i++] != ':') return 0;
            }
            if (!json_value(j, depth + 1)) return 0;
            json_space(j);
            if (j->i >= j->n) return 0;
            if (j->s[j->i] == closing) { ++j->i; return 1; }
            if (j->s[j->i++] != ',') return 0;
            json_space(j);
        }
    }
    if (c == 't' || c == 'f' || c == 'n') {
        const char *word = c == 't' ? "true" : c == 'f' ? "false" : "null";
        size_t n = strlen(word);
        if (n > j->n - j->i || memcmp(j->s + j->i, word, n)) return 0;
        j->i += n;
        return 1;
    }
    if (c == '-') ++j->i;
    if (j->i >= j->n) return 0;
    if (j->s[j->i] == '0') ++j->i;
    else {
        start = j->i;
        while (j->i < j->n && j->s[j->i] >= '0' && j->s[j->i] <= '9') ++j->i;
        if (j->i == start) return 0;
    }
    if (j->i < j->n && j->s[j->i] == '.') {
        start = ++j->i;
        while (j->i < j->n && j->s[j->i] >= '0' && j->s[j->i] <= '9') ++j->i;
        if (j->i == start) return 0;
    }
    if (j->i < j->n && (j->s[j->i] == 'e' || j->s[j->i] == 'E')) {
        ++j->i;
        if (j->i < j->n && (j->s[j->i] == '+' || j->s[j->i] == '-')) ++j->i;
        start = j->i;
        while (j->i < j->n && j->s[j->i] >= '0' && j->s[j->i] <= '9') ++j->i;
        if (j->i == start) return 0;
    }
    return 1;
}

static int server_info(tsc_derp *d, tsc_derp_event *event)
{
    uint8_t nonce[24];
    json_reader j;
    int status;
    if (d->frame_length < 40) return TSC_ERR_PROTOCOL;
    memcpy(nonce, d->receive_buffer, sizeof(nonce));
    status = tsc_nacl_box_open_afternm(d->receive_buffer,
        d->receive_buffer + 24, d->frame_length - 24, nonce, d->shared_key);
    tsc_crypto_zero(nonce, sizeof(nonce));
    if (status != TSC_OK) return TSC_ERR_PROTOCOL;
    j.s = d->receive_buffer;
    j.n = d->frame_length - 40;
    j.i = 0;
    json_space(&j);
    if (j.i >= j.n || j.s[j.i] != '{' || !json_value(&j, 0))
        return TSC_ERR_PROTOCOL;
    json_space(&j);
    if (j.i != j.n) return TSC_ERR_PROTOCOL;
    /* The login box key is not used by steady-state DERP packet framing. */
    tsc_crypto_zero(d->shared_key, sizeof(d->shared_key));
    d->stage = ST_READY;
    event->type = TSC_DERP_EVENT_READY;
    event->data = d->receive_buffer;
    event->length = j.n;
    return TSC_OK;
}

static int process_frame(tsc_derp *d, tsc_derp_event *e)
{
    static const uint8_t magic[8] = { 'D','E','R','P',0xf0,0x9f,0x94,0x91 };
    static const char info[] = "{\"version\":2,\"CanAckPings\":true}";
    uint8_t *p = d->receive_buffer;
    uint32_t n = d->frame_length;
    int status;
    if (d->stage == ST_SERVER_KEY) {
        if (d->frame_type != F_SERVER_KEY || n < 40 || memcmp(p, magic, 8))
            return TSC_ERR_PROTOCOL;
        if (pending(d)) return TSC_AGAIN;
        memcpy(d->server_key, p + 8, 32);
        status = tsc_nacl_box_beforenm(d->shared_key, d->server_key, d->private_key);
        tsc_crypto_zero(d->private_key, 32);
        if (status != TSC_OK) return TSC_ERR_PROTOCOL;
        frame_begin(d, F_CLIENT_INFO, 32 + 24 + 16 + sizeof(info) - 1);
        memcpy(d->transmit_buffer + 5, d->public_key, 32);
        status = tsc_crypto_random(d->transmit_buffer + 37, 24);
        if (status != TSC_OK) return status;
        status = tsc_nacl_box_afternm(d->transmit_buffer + 61,
            (const uint8_t *)info, sizeof(info)-1, d->transmit_buffer + 37,
            d->shared_key);
        if (status != TSC_OK) return status;
        d->stage = ST_SERVER_INFO;
        return TSC_OK;
    }
    if (d->stage == ST_SERVER_INFO) {
        if (d->frame_type != F_SERVER_INFO) return TSC_ERR_PROTOCOL;
        return server_info(d, e);
    }
    if (d->stage != ST_READY) return TSC_ERR_PROTOCOL;
    switch (d->frame_type) {
    case F_RECEIVE:
        if (n < 32 || n - 32 > TSC_MAX_DATAGRAM_SIZE) return TSC_ERR_PROTOCOL;
        e->type = TSC_DERP_EVENT_PACKET;
        memcpy(e->peer_key, p, 32);
        e->data = p + 32;
        e->length = n - 32;
        break;
    case F_KEEPALIVE:
        if (n != 0) return TSC_ERR_PROTOCOL;
        break;
    case F_GONE:
        if (n < 32) return TSC_ERR_PROTOCOL;
        e->type = TSC_DERP_EVENT_PEER_GONE;
        memcpy(e->peer_key, p, 32);
        e->reason = n > 32 ? p[32] : 0;
        break;
    case F_PING:
        if (n < 8) return TSC_ERR_PROTOCOL;
        if (d->has_pending_pong) return TSC_AGAIN;
        memcpy(d->pending_pong, p, 8);
        d->has_pending_pong = 1;
        if (!pending(d)) queue_pong(d);
        break;
    case F_PONG:
        if (n < 8) return TSC_ERR_PROTOCOL;
        e->type = TSC_DERP_EVENT_PONG;
        e->data = p;
        e->length = 8;
        break;
    case F_HEALTH:
        e->type = TSC_DERP_EVENT_HEALTH;
        e->data = p;
        e->length = n;
        break;
    case F_RESTART:
        if (n < 8) return TSC_ERR_PROTOCOL;
        e->type = TSC_DERP_EVENT_RESTARTING;
        e->reconnect_in_ms = read32(p);
        e->retry_for_ms = read32(p + 4);
        break;
    case F_SERVER_KEY:
    case F_CLIENT_INFO:
    case F_SERVER_INFO:
    case F_SEND:
    case F_PREFERRED:
        return TSC_ERR_PROTOCOL;
    default:
        break; /* DERP explicitly permits unknown future frame types. */
    }
    return TSC_OK;
}

int tsc_derp_feed(tsc_derp *d, const void *data, size_t length,
                   size_t *consumed, tsc_derp_event *event)
{
    const uint8_t *p = data;
    size_t copied;
    int status;
    if (consumed) *consumed = 0;
    if (!d || (!data && length) || !consumed || !event) return TSC_ERR_ARGUMENT;
    memset(event, 0, sizeof(*event));
    if (d->stage == ST_FAILED) return d->error;
    if (d->stage == ST_INITIAL) return TSC_ERR_ARGUMENT;
    if (d->stage == ST_HTTP) {
        while (*consumed < length) {
            if (d->frame_used == TSC_DERP_MAX_HTTP_HEADER)
                return fail(d, TSC_ERR_SPACE);
            d->receive_buffer[d->frame_used++] = p[(*consumed)++];
            if (d->frame_used >= 4 && !memcmp(d->receive_buffer +
                d->frame_used - 4, "\r\n\r\n", 4)) {
                status = parse_http(d);
                if (status != TSC_OK) return fail(d, status);
                d->stage = ST_SERVER_KEY;
                d->frame_used = 0;
                break;
            }
        }
        if (d->stage == ST_HTTP) return TSC_AGAIN;
    }
    while (d->header_used < 5 && *consumed < length)
        d->frame_header[d->header_used++] = p[(*consumed)++];
    if (d->header_used < 5) return TSC_AGAIN;
    d->frame_type = d->frame_header[0];
    d->frame_length = read32(d->frame_header + 1);
    if (d->frame_length > TSC_DERP_MAX_FRAME_SIZE) return fail(d, TSC_ERR_SPACE);
    copied = d->frame_length - d->frame_used;
    if (copied > length - *consumed) copied = length - *consumed;
    if (copied) {
        memcpy(d->receive_buffer + d->frame_used, p + *consumed, copied);
        d->frame_used += copied;
        *consumed += copied;
    }
    if (d->frame_used < d->frame_length) return TSC_AGAIN;
    status = process_frame(d, event);
    if (status < 0) return fail(d, status);
    if (status == TSC_AGAIN) return status;
    d->header_used = 0;
    d->frame_used = 0;
    return TSC_OK;
}

int tsc_derp_output(const tsc_derp *d, const uint8_t **data, size_t *length)
{
    if (!d || !data || !length) return TSC_ERR_ARGUMENT;
    *data = NULL;
    *length = 0;
    if (d->stage == ST_FAILED) return d->error;
    if (!pending(d)) return TSC_AGAIN;
    *data = d->transmit_buffer + d->transmit_offset;
    *length = d->transmit_length - d->transmit_offset;
    return TSC_OK;
}

int tsc_derp_output_consumed(tsc_derp *d, size_t length)
{
    if (!d || length > d->transmit_length - d->transmit_offset)
        return TSC_ERR_ARGUMENT;
    if (d->stage == ST_FAILED) return d->error;
    d->transmit_offset += length;
    if (!pending(d)) {
        d->transmit_offset = d->transmit_length = 0;
        if (d->has_pending_pong) queue_pong(d);
    }
    return TSC_OK;
}

int tsc_derp_send(tsc_derp *d, const uint8_t destination_key[32],
                  const void *packet, size_t length)
{
    if (!d || !destination_key || (!packet && length)) return TSC_ERR_ARGUMENT;
    if (d->stage == ST_FAILED) return d->error;
    if (d->stage != ST_READY) return TSC_AGAIN;
    if (length > TSC_MAX_DATAGRAM_SIZE || length > 65536 ||
        length > TSC_DERP_MAX_FRAME_SIZE - 32) return TSC_ERR_SPACE;
    if (pending(d)) return TSC_AGAIN;
    frame_begin(d, F_SEND, length + 32);
    memcpy(d->transmit_buffer + 5, destination_key, 32);
    if (length) memcpy(d->transmit_buffer + 37, packet, length);
    return TSC_OK;
}

int tsc_derp_note_preferred(tsc_derp *d, int preferred)
{
    if (!d || (preferred != 0 && preferred != 1)) return TSC_ERR_ARGUMENT;
    if (d->stage == ST_FAILED) return d->error;
    if (d->stage != ST_READY || pending(d)) return TSC_AGAIN;
    frame_begin(d, F_PREFERRED, 1);
    d->transmit_buffer[5] = (uint8_t)preferred;
    return TSC_OK;
}

int tsc_derp_ping(tsc_derp *d, const uint8_t payload[8])
{
    if (!d || !payload) return TSC_ERR_ARGUMENT;
    if (d->stage == ST_FAILED) return d->error;
    if (d->stage != ST_READY || pending(d)) return TSC_AGAIN;
    frame_begin(d, F_PING, 8);
    memcpy(d->transmit_buffer + 5, payload, 8);
    return TSC_OK;
}

#endif
