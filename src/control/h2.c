/*
 * Minimal bounded HTTP/2 for TS2021. Frame and HPACK encoder adapted from
 * TailTiny/MicroLink ml_h2.c. Copyright (c) 2025-2026 Cameron Malone.
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "protocol.h"
#include <limits.h>
#include <string.h>

enum { DATA = 0, HEADERS = 1, PRIORITY = 2, RST_STREAM = 3, SETTINGS = 4,
       PUSH_PROMISE = 5, PING = 6, GOAWAY = 7, WINDOW_UPDATE = 8,
       CONTINUATION = 9 };
enum { END_STREAM = 1, ACK = 1, END_HEADERS = 4, PADDED = 8, PRIORITIZED = 32 };

typedef struct { uint32_t length, stream; uint8_t type, flags; } frame;

static uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

static void store32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

static int fail(tsc_h2 *h2, int status)
{
    h2->failed = 1;
    return status;
}

static int read_bytes(tsc_h2 *h2, void *buffer, size_t length)
{
    int result = tsc_noise_read_exact(h2->noise, buffer, length);
    return result == TSC_OK ? result : fail(h2, result);
}

static int discard(tsc_h2 *h2, size_t length)
{
    uint8_t scratch[256];
    while (length) {
        size_t chunk = length > sizeof(scratch) ? sizeof(scratch) : length;
        int result = read_bytes(h2, scratch, chunk);
        if (result != TSC_OK) return result;
        length -= chunk;
    }
    return TSC_OK;
}

static void parse_frame(const uint8_t bytes[9], frame *f)
{
    f->length = (uint32_t)bytes[0] << 16 | (uint32_t)bytes[1] << 8 | bytes[2];
    f->type = bytes[3]; f->flags = bytes[4];
    f->stream = load32(bytes + 5) & UINT32_C(0x7fffffff);
}

static int read_frame(tsc_h2 *h2, frame *f)
{
    uint8_t bytes[9];
    int result = read_bytes(h2, bytes, sizeof(bytes));
    if (result != TSC_OK) return result;
    parse_frame(bytes, f);
    /* We advertise the RFC default maximum receive frame size, 16384. */
    if (f->length > 16384) return fail(h2, TSC_ERR_PROTOCOL);
    return TSC_OK;
}

static int send_frame(tsc_h2 *h2, uint8_t type, uint8_t flags,
                       uint32_t stream, const void *payload, uint32_t length)
{
    uint8_t header[9];
    int result;
    header[0] = (uint8_t)(length >> 16); header[1] = (uint8_t)(length >> 8);
    header[2] = (uint8_t)length; header[3] = type; header[4] = flags;
    store32(header + 5, stream);
    result = tsc_noise_send(h2->noise, header, sizeof(header));
    if (result == TSC_OK && length)
        result = tsc_noise_send(h2->noise, payload, length);
    return result == TSC_OK ? result : fail(h2, result);
}

static int window_update(tsc_h2 *h2, uint32_t stream, uint32_t amount)
{
    uint8_t bytes[4];
    if (!amount) return TSC_OK;
    store32(bytes, amount);
    return send_frame(h2, WINDOW_UPDATE, 0, stream, bytes, sizeof(bytes));
}

/* Non-DATA protocol frames. Returns AGAIN for frames requiring the response
 * reader (HEADERS, DATA, CONTINUATION), otherwise OK/error. */
static int control_frame(tsc_h2 *h2, const frame *f)
{
    uint8_t bytes[8];
    int result;
    uint32_t value;
    switch (f->type) {
    case SETTINGS:
        if (f->stream || ((f->flags & ACK) && f->length) || f->length % 6)
            return fail(h2, TSC_ERR_PROTOCOL);
        if (f->flags & ACK) return TSC_OK;
        for (value = 0; value < f->length; value += 6) {
            unsigned id;
            uint32_t setting;
            result = read_bytes(h2, bytes, 6);
            if (result != TSC_OK) return result;
            id = (unsigned)bytes[0] << 8 | bytes[1];
            setting = load32(bytes + 2);
            if (id == 2 && setting > 1) return fail(h2, TSC_ERR_PROTOCOL);
            if (id == 4) {
                if (setting > INT32_MAX) return fail(h2, TSC_ERR_PROTOCOL);
                h2->tx_stream_window += (int64_t)setting - h2->server_initial_window;
                h2->server_initial_window = setting;
                if (h2->tx_stream_window > INT32_MAX)
                    return fail(h2, TSC_ERR_PROTOCOL);
            }
            if (id == 5) {
                if (setting < 16384 || setting > 16777215)
                    return fail(h2, TSC_ERR_PROTOCOL);
                h2->server_max_frame = setting;
            }
        }
        return send_frame(h2, SETTINGS, ACK, 0, NULL, 0);
    case PING:
        if (f->stream || f->length != 8) return fail(h2, TSC_ERR_PROTOCOL);
        result = read_bytes(h2, bytes, 8);
        if (result != TSC_OK || (f->flags & ACK)) return result;
        return send_frame(h2, PING, ACK, 0, bytes, 8);
    case WINDOW_UPDATE:
        if (f->length != 4) return fail(h2, TSC_ERR_PROTOCOL);
        result = read_bytes(h2, bytes, 4);
        if (result != TSC_OK) return result;
        value = load32(bytes) & UINT32_C(0x7fffffff);
        if (!value) return fail(h2, TSC_ERR_PROTOCOL);
        if (!f->stream) {
            h2->tx_connection_window += value;
            if (h2->tx_connection_window > INT32_MAX)
                return fail(h2, TSC_ERR_PROTOCOL);
        } else if (f->stream == h2->active_stream) {
            h2->tx_stream_window += value;
            if (h2->tx_stream_window > INT32_MAX)
                return fail(h2, TSC_ERR_PROTOCOL);
        } else if (f->stream >= h2->next_stream) {
            return fail(h2, TSC_ERR_PROTOCOL);
        }
        return TSC_OK;
    case DATA: case HEADERS: case CONTINUATION:
        return TSC_AGAIN;
    case RST_STREAM:
        if (f->length != 4 || !f->stream) return fail(h2, TSC_ERR_PROTOCOL);
        if (f->stream < h2->active_stream) return discard(h2, f->length);
        return fail(h2, TSC_ERR_PROTOCOL);
    case GOAWAY: case PUSH_PROMISE:
        return fail(h2, TSC_ERR_PROTOCOL);
    case PRIORITY:
        if (!f->stream || f->length != 5) return fail(h2, TSC_ERR_PROTOCOL);
        return discard(h2, f->length);
    default:
        return discard(h2, f->length); /* Extension frames are ignored. */
    }
}

static int hex_digit(uint8_t ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static void read_challenge(tsc_h2 *h2, const uint8_t *json, size_t length)
{
    static const char field[] = "\"nodeKeyChallenge\"";
    size_t i;
    for (i = 0; i + sizeof(field) - 1 < length; ++i) {
        size_t j, k;
        if (memcmp(json + i, field, sizeof(field) - 1)) continue;
        j = i + sizeof(field) - 1;
        while (j < length && (json[j] == ' ' || json[j] == '\t' ||
                             json[j] == '\r' || json[j] == '\n')) ++j;
        if (j == length || json[j++] != ':') return;
        while (j < length && (json[j] == ' ' || json[j] == '\t' ||
                             json[j] == '\r' || json[j] == '\n')) ++j;
        if (length - j < 74 || memcmp(json + j, "\"chalpub:", 9)) return;
        j += 9;
        for (k = 0; k < 32; ++k) {
            int a = hex_digit(json[j + 2 * k]), b = hex_digit(json[j + 2 * k + 1]);
            if (a < 0 || b < 0) return;
            h2->challenge[k] = (uint8_t)(a * 16 + b);
        }
        if (json[j + 64] == '"') h2->has_challenge = 1;
        return;
    }
}

int tsc_h2_start(tsc_h2 *h2, tsc_noise *noise)
{
    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    uint8_t settings[18] = {
        0, 1, 0, 0, 0, 0, /* HEADER_TABLE_SIZE = 0: bounded HPACK state. */
        0, 2, 0, 0, 0, 0, /* ENABLE_PUSH = 0. */
        0, 6, 0, 0, 0, 0  /* MAX_HEADER_LIST_SIZE. */
    };
    uint8_t first[9];
    frame f;
    int result;
    if (!h2 || !noise || !noise->ready) return TSC_ERR_ARGUMENT;
    memset(h2, 0, sizeof(*h2));
    h2->noise = noise;
    h2->next_stream = 1;
    h2->server_initial_window = 65535;
    h2->tx_stream_window = 65535;
    h2->tx_connection_window = 65535;
    h2->server_max_frame = 16384;
    store32(settings + 14, TSC_CONTROL_HEADER_SIZE);
    result = tsc_noise_send(noise, preface, sizeof(preface) - 1);
    if (result != TSC_OK) return fail(h2, result);
    result = send_frame(h2, SETTINGS, 0, 0, settings, sizeof(settings));
    if (result != TSC_OK) return result;
    result = read_bytes(h2, first, sizeof(first));
    if (result != TSC_OK) return result;
    if (!memcmp(first, "\xff\xff\xff" "TS", 5)) {
        uint32_t length = load32(first + 5);
        if (length > sizeof(h2->header_buffer)) return fail(h2, TSC_ERR_SPACE);
        result = read_bytes(h2, h2->header_buffer, length);
        if (result != TSC_OK) return result;
        read_challenge(h2, h2->header_buffer, length);
        result = read_frame(h2, &f);
        if (result != TSC_OK) return result;
    } else {
        parse_frame(first, &f);
    }
    if (f.type != SETTINGS || (f.flags & ACK) || f.length > 16384)
        return fail(h2, TSC_ERR_PROTOCOL);
    result = control_frame(h2, &f);
    if (result == TSC_OK) h2->ready = 1;
    return result;
}

static int encode_integer(uint8_t *out, size_t capacity, size_t *position,
                            uint32_t value, unsigned prefix, uint8_t tag)
{
    uint32_t limit = ((uint32_t)1 << prefix) - 1;
    if (*position >= capacity) return TSC_ERR_SPACE;
    if (value < limit) { out[(*position)++] = tag | (uint8_t)value; return TSC_OK; }
    out[(*position)++] = tag | (uint8_t)limit;
    value -= limit;
    while (value >= 128) {
        if (*position >= capacity) return TSC_ERR_SPACE;
        out[(*position)++] = (uint8_t)(value & 127) | 128;
        value >>= 7;
    }
    if (*position >= capacity) return TSC_ERR_SPACE;
    out[(*position)++] = (uint8_t)value;
    return TSC_OK;
}

static int literal(tsc_h2 *h2, size_t *position, uint32_t name,
                     const char *value)
{
    size_t length = strlen(value);
    int result = encode_integer(h2->header_buffer, sizeof(h2->header_buffer),
                                  position, name, 4, 0);
    if (result != TSC_OK || length > UINT32_MAX) return TSC_ERR_SPACE;
    result = encode_integer(h2->header_buffer, sizeof(h2->header_buffer),
                               position, (uint32_t)length, 7, 0);
    if (result != TSC_OK || length > sizeof(h2->header_buffer) - *position)
        return TSC_ERR_SPACE;
    memcpy(h2->header_buffer + *position, value, length);
    *position += length;
    return TSC_OK;
}

static int decode_integer(const uint8_t *data, size_t length, size_t *position,
                             unsigned prefix, uint32_t *value)
{
    uint32_t limit = ((uint32_t)1 << prefix) - 1;
    unsigned shift = 0;
    if (*position >= length) return TSC_ERR_PROTOCOL;
    *value = data[(*position)++] & limit;
    if (*value < limit) return TSC_OK;
    for (;;) {
        uint8_t byte;
        uint32_t part;
        if (*position >= length || shift >= 32) return TSC_ERR_PROTOCOL;
        byte = data[(*position)++];
        part = byte & 127;
        if (part > (UINT32_MAX - *value) >> shift) return TSC_ERR_PROTOCOL;
        *value += part << shift;
        if (!(byte & 128)) return TSC_OK;
        shift += 7;
    }
}

typedef struct { const uint8_t *data; size_t length; unsigned huffman; } string;

static int decode_string(const uint8_t *data, size_t length, size_t *position,
                            string *s)
{
    uint32_t size;
    int result;
    if (*position >= length) return TSC_ERR_PROTOCOL;
    s->huffman = data[*position] >> 7;
    result = decode_integer(data, length, position, 7, &size);
    if (result != TSC_OK || size > length - *position) return TSC_ERR_PROTOCOL;
    s->data = data + *position;
    s->length = size;
    *position += size;
    return TSC_OK;
}

/* Only :status needs decoding. RFC7541 Appendix B assigns '0'..'2' the
 * five-bit codes 00000..00010, and '3'..'9' the six-bit codes 011001..011111.
 * All other header values are skipped by their bounded encoded length. */
static int decode_status(const string *s, unsigned *status)
{
    unsigned value = 0, digits = 0;
    size_t bit = 0;
    if (!s->huffman) {
        size_t i;
        if (s->length != 3) return TSC_ERR_PROTOCOL;
        for (i = 0; i < 3; ++i) {
            if (s->data[i] < '0' || s->data[i] > '9') return TSC_ERR_PROTOCOL;
            value = value * 10 + s->data[i] - '0';
        }
    } else {
        if (s->length < 2 || s->length > 3) return TSC_ERR_PROTOCOL;
        while (digits < 3) {
            unsigned code = 0, n;
            for (n = 0; n < 5; ++n) {
                if (bit >= s->length * 8) return TSC_ERR_PROTOCOL;
                code = code * 2 + ((s->data[bit / 8] >> (7 - bit % 8)) & 1);
                ++bit;
            }
            if (code <= 2) value = value * 10 + code;
            else {
                if (bit >= s->length * 8) return TSC_ERR_PROTOCOL;
                code = code * 2 + ((s->data[bit / 8] >> (7 - bit % 8)) & 1);
                ++bit;
                if (code < 25 || code > 31) return TSC_ERR_PROTOCOL;
                value = value * 10 + code - 22;
            }
            ++digits;
        }
        if (s->length * 8 - bit > 7) return TSC_ERR_PROTOCOL;
        while (bit < s->length * 8) {
            if (!((s->data[bit / 8] >> (7 - bit % 8)) & 1))
                return TSC_ERR_PROTOCOL;
            ++bit;
        }
    }
    if (value < 100 || value > 599) return TSC_ERR_PROTOCOL;
    *status = value;
    return TSC_OK;
}

static int parse_headers(tsc_h2 *h2, size_t length)
{
    static const unsigned statuses[] = {200, 204, 206, 304, 400, 404, 500};
    const uint8_t *data = h2->header_buffer;
    size_t position = 0;
    unsigned found_status = 0;
    while (position < length) {
        uint8_t tag = data[position];
        uint32_t index;
        string name = {NULL, 0, 0}, value;
        int result;
        if (tag & 128) {
            result = decode_integer(data, length, &position, 7, &index);
            if (result != TSC_OK || !index || index > 61)
                return fail(h2, TSC_ERR_PROTOCOL);
            if (index >= 8 && index <= 14) {
                if (found_status++) return fail(h2, TSC_ERR_PROTOCOL);
                h2->status = statuses[index - 8];
            }
            continue;
        }
        if ((tag & 0xe0) == 0x20) {
            result = decode_integer(data, length, &position, 5, &index);
            if (result != TSC_OK || index) return fail(h2, TSC_ERR_PROTOCOL);
            continue; /* Encoder's dynamic table is constrained to zero. */
        }
        result = decode_integer(data, length, &position, (tag & 64) ? 6 : 4, &index);
        if (result != TSC_OK || index > 61) return fail(h2, TSC_ERR_PROTOCOL);
        if (!index) {
            result = decode_string(data, length, &position, &name);
            if (result != TSC_OK) return fail(h2, result);
        }
        result = decode_string(data, length, &position, &value);
        if (result != TSC_OK) return fail(h2, result);
        if ((index >= 8 && index <= 14) ||
            (!index && !name.huffman && name.length == 7 &&
                          !memcmp(name.data, ":status", 7))) {
            if (found_status++) return fail(h2, TSC_ERR_PROTOCOL);
            result = decode_status(&value, &h2->status);
            if (result != TSC_OK) return fail(h2, result);
        }
    }
    return TSC_OK;
}

static int response_headers(tsc_h2 *h2, frame *f, int *ended)
{
    size_t length = 0;
    uint8_t prefix[6];
    unsigned padding = 0;
    uint32_t available;
    int result;
    if (f->stream != h2->active_stream) return fail(h2, TSC_ERR_PROTOCOL);
    *ended = !!(f->flags & END_STREAM);
    available = f->length;
    if (f->flags & PADDED) {
        if (!available) return fail(h2, TSC_ERR_PROTOCOL);
        result = read_bytes(h2, prefix, 1);
        if (result != TSC_OK) return result;
        padding = prefix[0];
        --available;
    }
    if (f->flags & PRIORITIZED) {
        if (available < 5) return fail(h2, TSC_ERR_PROTOCOL);
        result = read_bytes(h2, prefix, 5);
        if (result != TSC_OK) return result;
        available -= 5;
    }
    if (padding > available) return fail(h2, TSC_ERR_PROTOCOL);
    available -= padding;
    for (;;) {
        if (available > sizeof(h2->header_buffer) - length)
            return fail(h2, TSC_ERR_SPACE);
        result = read_bytes(h2, h2->header_buffer + length, available);
        if (result != TSC_OK) return result;
        length += available;
        result = discard(h2, padding);
        if (result != TSC_OK) return result;
        if (f->flags & END_HEADERS) break;
        result = read_frame(h2, f);
        if (result != TSC_OK) return result;
        if (f->type != CONTINUATION || f->stream != h2->active_stream)
            return fail(h2, TSC_ERR_PROTOCOL);
        available = f->length;
        padding = 0;
    }
    return parse_headers(h2, length);
}

static int post(tsc_h2 *h2, const char *authority, const char *path,
    const void *request, size_t request_length, void *response,
    size_t response_capacity, size_t *response_length, unsigned *http_status,
    int map_mode, int (*sink)(void *, const void *, size_t), void *user)
{
    const uint8_t *request_bytes = request;
    uint8_t *response_bytes = response;
    size_t position = 0, sent = 0, map_length = 0;
    int result, ended = 0;
    frame f;
    uint8_t prefix[4], chunk_buffer[256];
    if (!h2 || !authority || !path || (!request && request_length) ||
        (!response && response_capacity && !sink) || !response_length || !http_status)
        return TSC_ERR_ARGUMENT;
    *response_length = 0; *http_status = 0;
    if (!h2->ready || h2->failed || h2->next_stream > INT32_MAX - 2)
        return TSC_ERR_IO;
    if (map_mode && response_capacity < 4) return TSC_ERR_SPACE;
    if (h2->stream_open) {
        const uint8_t cancel[4] = {0, 0, 0, 8};
        result = send_frame(h2, RST_STREAM, 0, h2->active_stream, cancel, 4);
        if (result != TSC_OK) return result;
        h2->stream_open = 0;
    }
    h2->active_stream = h2->next_stream;
    h2->next_stream += 2;
    h2->status = 0;
    h2->tx_stream_window = h2->server_initial_window;
    h2->header_buffer[position++] = 0x83; /* :method POST */
    h2->header_buffer[position++] = 0x86; /* :scheme http inside Noise */
    result = literal(h2, &position, 4, path);
    if (result == TSC_OK) result = literal(h2, &position, 1, authority);
    if (result == TSC_OK) result = literal(h2, &position, 31, "application/json");
    if (result != TSC_OK) return fail(h2, result);
    result = send_frame(h2, HEADERS, END_HEADERS | (!request_length ? END_STREAM : 0),
                       h2->active_stream, h2->header_buffer, (uint32_t)position);
    if (result != TSC_OK) return result;
    while (sent < request_length) {
        size_t chunk = request_length - sent;
        int64_t credit = h2->tx_connection_window < h2->tx_stream_window ?
                            h2->tx_connection_window : h2->tx_stream_window;
        if (credit <= 0) {
            result = read_frame(h2, &f);
            if (result != TSC_OK) return result;
            result = control_frame(h2, &f);
            if (result == TSC_AGAIN) return fail(h2, TSC_ERR_PROTOCOL);
            if (result != TSC_OK) return result;
            continue;
        }
        if (chunk > h2->server_max_frame) chunk = h2->server_max_frame;
        if ((uint64_t)chunk > (uint64_t)credit) chunk = (size_t)credit;
        result = send_frame(h2, DATA, sent + chunk == request_length ? END_STREAM : 0,
                           h2->active_stream, request_bytes + sent, (uint32_t)chunk);
        if (result != TSC_OK) return result;
        sent += chunk;
        h2->tx_connection_window -= (int64_t)chunk;
        h2->tx_stream_window -= (int64_t)chunk;
    }
    while (!ended) {
        result = read_frame(h2, &f);
        if (result != TSC_OK) return result;
        result = control_frame(h2, &f);
        if (result != TSC_AGAIN) {
            if (result != TSC_OK) return result;
            continue;
        }
        if (f.stream && (f.stream & 1) && f.stream < h2->active_stream) {
            /* Frames already in flight when a previous map stream was reset.
             * HPACK dynamic state is disabled, so old header blocks can be
             * discarded without changing the decoder state. */
            result = discard(h2, f.length);
            if (result == TSC_OK && f.type == DATA)
                result = window_update(h2, 0, f.length);
            if (result != TSC_OK) return result;
            continue;
        }
        if (f.type == HEADERS) {
            result = response_headers(h2, &f, &ended);
            if (result != TSC_OK) return result;
        } else if (f.type == DATA) {
            uint32_t length = f.length;
            unsigned padding = 0;
            if (f.stream != h2->active_stream || !h2->status)
                return fail(h2, TSC_ERR_PROTOCOL);
            if (f.flags & PADDED) {
                uint8_t byte;
                if (!length) return fail(h2, TSC_ERR_PROTOCOL);
                result = read_bytes(h2, &byte, 1);
                if (result != TSC_OK) return result;
                padding = byte; --length;
            }
            if (padding > length) return fail(h2, TSC_ERR_PROTOCOL);
            length -= padding;
            if (!map_mode || h2->status != 200) {
                if (length > response_capacity - *response_length)
                    return fail(h2, TSC_ERR_SPACE);
                if (length) {
                    result = sink ? discard(h2, length) :
                        read_bytes(h2, response_bytes + *response_length, length);
                    if (result != TSC_OK) return result;
                }
                *response_length += length;
            } else {
                while (length) {
                    size_t needed = *response_length < 4 ?
                                         4 - *response_length : map_length - *response_length;
                    size_t chunk = length < needed ? length : needed;
                    if (!chunk) {
                        result = discard(h2, length);
                        if (result != TSC_OK) return result;
                        break;
                    }
                    uint8_t *destination = response_bytes ? response_bytes + *response_length :
                        *response_length < 4 ? prefix + *response_length : chunk_buffer;
                    if (sink && *response_length >= 4 && chunk > sizeof(chunk_buffer))
                        chunk = sizeof(chunk_buffer);
                    result = read_bytes(h2, destination, chunk);
                    if (result != TSC_OK) return result;
                    if (sink && *response_length >= 4) {
                        result = sink(user, destination, chunk);
                        if (result != TSC_OK) return fail(h2, result);
                    }
                    *response_length += chunk;
                    length -= (uint32_t)chunk;
                    if (*response_length >= 4 && !map_length) {
                        const uint8_t *p = sink ? prefix : response_bytes;
                        uint32_t payload = (uint32_t)p[0] | (uint32_t)p[1] << 8 |
                            (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
                        if (!payload || payload > response_capacity - 4)
                            return fail(h2, payload ? TSC_ERR_SPACE : TSC_ERR_PROTOCOL);
                        map_length = (size_t)payload + 4;
                    }
                }
            }
            result = discard(h2, padding);
            if (result != TSC_OK) return result;
            result = window_update(h2, 0, f.length);
            if (result == TSC_OK)
                result = window_update(h2, h2->active_stream, f.length);
            if (result != TSC_OK) return result;
            ended = !!(f.flags & END_STREAM);
            if (map_mode && map_length && *response_length == map_length) {
                h2->stream_open = !ended;
                *http_status = h2->status;
                return TSC_OK;
            }
        } else {
            return fail(h2, TSC_ERR_PROTOCOL);
        }
    }
    if (!h2->status || (map_mode && h2->status == 200))
        return fail(h2, TSC_ERR_PROTOCOL);
    *http_status = h2->status;
    return TSC_OK;
}

int tsc_h2_post(tsc_h2 *h2, const char *authority, const char *path,
    const void *request, size_t request_length, void *response,
    size_t response_capacity, size_t *response_length, unsigned *http_status)
{
    return post(h2, authority, path, request, request_length, response,
                 response_capacity, response_length, http_status, 0, NULL, NULL);
}

int tsc_h2_post_map(tsc_h2 *h2, const char *authority, const char *path,
    const void *request, size_t request_length, void *response,
    size_t response_capacity, size_t *response_length, unsigned *http_status)
{
    return post(h2, authority, path, request, request_length, response,
                 response_capacity, response_length, http_status, 1, NULL, NULL);
}

int tsc_h2_post_map_stream(tsc_h2 *h2, const char *authority, const char *path,
    const void *request, size_t request_length, size_t maximum_json,
    int (*sink)(void *, const void *, size_t), void *user, unsigned *http_status)
{
    size_t received = 0;
    if (!sink || maximum_json > SIZE_MAX - 4) return TSC_ERR_ARGUMENT;
    return post(h2, authority, path, request, request_length, NULL,
        maximum_json + 4, &received, http_status, 1, sink, user);
}
