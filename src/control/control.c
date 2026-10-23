/* Portable TS2021 control client. Protocol interoperability informed by
 * Tailscale's controlbase/tailcfg documentation and TailTiny (MIT),
 * Copyright (c) 2025-2026 Cameron Malone. See the MIT notice in noise.c. */
#include "tailscalec/control.h"
#include "address.h"
#include "control_time.h"
#include "json.h"
#include "protocol.h"
#include "project.h"
#include "tailscalec/crypto.h"
#include "tailscalec/stream.h"
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TSC_CONTROL_VERSION 131
#define REQUEST_SIZE 4096

#if TSC_CONTROL_DYNAMIC_SCRATCH
typedef struct {
  union { char request[REQUEST_SIZE]; char response[TSC_CONTROL_RESPONSE_SIZE + 1]; };
  tsc_json_token tokens[TSC_CONTROL_JSON_TOKENS];
} control_scratch;
#endif

#if TSC_CONTROL_DYNAMIC_PEERS
typedef struct {
  tsc_control_peer *data;
  size_t count, capacity;
  int error;
} peer_batch;
#endif

typedef struct {
  tsc_control_config config;
  char host[256], authority[288];
  uint16_t port;
  int tls, connected, map_valid;
  tsc_stream stream;
  tsc_noise noise;
  tsc_h2 h2;
  tsc_endpoint endpoints[TSC_CONTROL_MAX_ENDPOINTS];
  uint8_t endpoint_types[TSC_CONTROL_MAX_ENDPOINTS];
  size_t endpoint_count;
  uint8_t node_public[32];
#if TSC_CONTROL_SINGLE_MAP
  /* Calls are serialized; refresh already fails closed on any error. Reuse
   * the old map while traffic is disabled instead of retaining two copies. */
  union { tsc_control_map map, next_map; };
#else
  tsc_control_map map, next_map;
#endif
  char error[160];
#if TSC_CONTROL_DYNAMIC_SCRATCH
  control_scratch *scratch;
  char *request, *response;
  tsc_json_token *tokens;
#else
  /* HTTP/2 sends the entire request before receiving the response. */
  union {
    char request[REQUEST_SIZE];
    char response[TSC_CONTROL_RESPONSE_SIZE + 1];
  };
  tsc_json_token tokens[TSC_CONTROL_JSON_TOKENS];
#endif
  size_t token_count;
  uint64_t request_started_ms, last_map_ms, last_clock_ms;
  unsigned request_has_clock, has_last_clock, map_has_control_time;
  int64_t map_control_time_ms;
#if TSC_CONTROL_DYNAMIC_PEERS
  peer_batch batches[2];
  unsigned streaming_peers;
  uint64_t stream_generation;
#endif
} control_impl;

static int scratch_open(control_impl *c) {
#if TSC_CONTROL_DYNAMIC_SCRATCH
  if (!c->scratch) {
    c->scratch = malloc(sizeof(*c->scratch));
    if (!c->scratch) return TSC_ERR_SPACE;
    c->request = c->scratch->request;
    c->response = c->scratch->response;
    c->tokens = c->scratch->tokens;
  }
#else
  (void)c;
#endif
  return TSC_OK;
}
static void scratch_close(control_impl *c) {
#if TSC_CONTROL_DYNAMIC_SCRATCH
  if (c->scratch) {
    tsc_crypto_zero(c->scratch, sizeof(*c->scratch));
    free(c->scratch);
    c->scratch = NULL;
    c->request = c->response = NULL;
    c->tokens = NULL;
    c->token_count = 0;
  }
#else
  (void)c;
#endif
}

typedef struct {
  char *out;
  size_t capacity, length;
  int error;
} writer;
static void put(writer *w, const char *s) {
  size_t n = strlen(s);
  if (w->error)
    return;
  if (n >= w->capacity - w->length) {
    w->error = TSC_ERR_SPACE;
    return;
  }
  memcpy(w->out + w->length, s, n + 1);
  w->length += n;
}
static void quoted(writer *w, const char *s) {
  static const char hex[] = "0123456789abcdef";
  put(w, "\"");
  if (s)
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
      char b[7] = {0};
      if (*p == '"' || *p == '\\') {
        b[0] = '\\';
        b[1] = (char)*p;
      } else if (*p < 32) {
        memcpy(b, "\\u00", 4);
        b[4] = hex[*p >> 4];
        b[5] = hex[*p & 15];
      } else
        b[0] = (char)*p;
      put(w, b);
    }
  put(w, "\"");
}
static void hexkey(const uint8_t key[32], char out[65]) {
  static const char h[] = "0123456789abcdef";
  for (unsigned i = 0; i < 32; i++) {
    out[i * 2] = h[key[i] >> 4];
    out[i * 2 + 1] = h[key[i] & 15];
  }
  out[64] = 0;
}
static int hexvalue(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}
static int decode_key(const char *s, const char *prefix, uint8_t out[32]) {
  size_t n = strlen(prefix);
  if (strncmp(s, prefix, n) != 0 || strlen(s + n) != 64)
    return TSC_ERR_PROTOCOL;
  for (unsigned i = 0; i < 32; i++) {
    int a = hexvalue(s[n + i * 2]), b = hexvalue(s[n + i * 2 + 1]);
    if (a < 0 || b < 0)
      return TSC_ERR_PROTOCOL;
    out[i] = (uint8_t)((a << 4) | b);
  }
  return TSC_OK;
}
static int fail(control_impl *c, int status, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  vsnprintf(c->error, sizeof(c->error), format, ap);
  va_end(ap);
  memset(&c->map.policy, 0, sizeof(c->map.policy));
  c->map.peer_count = 0;
  c->map_valid = 0;
  return status;
}
static int monotonic_now(control_impl *c, uint64_t *now) {
  if (!c->config.platform || !c->config.platform->monotonic_ms)
    return TSC_ERR_UNSUPPORTED;
  *now = c->config.platform->monotonic_ms(c->config.platform->user);
  if (c->has_last_clock && *now < c->last_clock_ms)
    return fail(c, TSC_ERR_PROTOCOL, "monotonic clock moved backwards");
  c->last_clock_ms = *now;
  c->has_last_clock = 1;
  return TSC_OK;
}
static int url(control_impl *c, const char *text) {
  if (!text)
    return TSC_ERR_ARGUMENT;
  const char *p;
  if (!strncmp(text, "https://", 8)) {
    c->tls = 1;
    c->port = 443;
    p = text + 8;
  } else if (!strncmp(text, "http://", 7)) {
    c->tls = 0;
    c->port = 80;
    p = text + 7;
  } else
    return TSC_ERR_ARGUMENT;
  const char *end = strchr(p, '/');
  if (!end)
    end = p + strlen(p);
  if (*end && strcmp(end, "/"))
    return TSC_ERR_UNSUPPORTED;
  size_t authority_length = (size_t)(end - p);
  if (!authority_length || authority_length >= sizeof(c->authority))
    return TSC_ERR_ARGUMENT;
  for (const char *q = p; q < end; q++)
    if ((unsigned char)*q <= 32 || *q == '@' || *q == '?' || *q == '#')
      return TSC_ERR_ARGUMENT;
  memcpy(c->authority, p, authority_length);
  c->authority[authority_length] = 0;
  const char *host = p, *hostend = end, *port = NULL;
  if (*p == '[') {
    host = p + 1;
    hostend = strchr(host, ']');
    if (!hostend || hostend >= end)
      return TSC_ERR_ARGUMENT;
    if (hostend + 1 < end) {
      if (hostend[1] != ':')
        return TSC_ERR_ARGUMENT;
      port = hostend + 2;
    }
  } else {
    for (const char *q = p; q < end; q++)
      if (*q == ':') {
        if (port)
          return TSC_ERR_ARGUMENT;
        hostend = q;
        port = q + 1;
      }
  }
  size_t n = (size_t)(hostend - host);
  if (!n || n >= sizeof(c->host))
    return TSC_ERR_ARGUMENT;
  memcpy(c->host, host, n);
  c->host[n] = 0;
  if (port) {
    unsigned value = 0;
    if (port == end)
      return TSC_ERR_ARGUMENT;
    for (const char *q = port; q < end; q++) {
      if (*q < '0' || *q > '9')
        return TSC_ERR_ARGUMENT;
      value = value * 10u + (unsigned)(*q - '0');
      if (value > 65535)
        return TSC_ERR_ARGUMENT;
    }
    if (!value)
      return TSC_ERR_ARGUMENT;
    c->port = (uint16_t)value;
  }
  return TSC_OK;
}
static int connect_stream(control_impl *c) {
  tsc_stream_options options = {c->config.timeout_ms, c->tls, c->config.ca_pem,
                                c->config.ca_pem_length};
  return tsc_stream_connect(&c->stream, c->host, c->port, &options);
}
static int write_all(control_impl *c, const void *buffer, size_t length) {
  const uint8_t *p = buffer;
  while (length) {
    size_t n = 0;
    int r = tsc_stream_write(&c->stream, p, length, &n, c->config.timeout_ms);
    if (r)
      return r;
    if (!n)
      return TSC_ERR_IO;
    p += n;
    length -= n;
  }
  return TSC_OK;
}
static int read_headers(control_impl *c, unsigned *status) {
  size_t n = 0;
  while (n < REQUEST_SIZE - 1) {
    size_t got = 0;
    int r = tsc_stream_read(&c->stream, c->request + n, 1, &got,
                            c->config.timeout_ms);
    if (r)
      return r;
    if (!got)
      return TSC_ERR_TRUNCATED;
    n++;
    c->request[n] = 0;
    if (n >= 4 && !memcmp(c->request + n - 4, "\r\n\r\n", 4))
      break;
  }
  if (n == REQUEST_SIZE - 1)
    return TSC_ERR_SPACE;
  unsigned major, minor, code;
  int consumed = 0;
  if (sscanf(c->request, "HTTP/%u.%u %u%n", &major, &minor, &code, &consumed) !=
          3 ||
      major != 1 || minor > 1 || code < 100 || code > 599 ||
      c->request[consumed] != ' ')
    return TSC_ERR_PROTOCOL;
  *status = code;
  return TSC_OK;
}
static int parse(control_impl *c, const char *json, size_t length) {
  return tsc_json_parse(json, length, c->tokens, TSC_CONTROL_JSON_TOKENS,
                        &c->token_count);
}
static int member(control_impl *c, const char *json, size_t parent,
                  const char *key, size_t *value) {
  return tsc_json_object_find(json, c->tokens, c->token_count, parent, key,
                              value);
}
static int string(control_impl *c, const char *json, size_t index, char *out,
                  size_t capacity) {
  size_t length = 0;
  int r = tsc_json_string_copy(json, &c->tokens[index], out, capacity, &length);
  if (!r && strlen(out) != length)
    return TSC_ERR_PROTOCOL;
  return r;
}
static int read_server_key(control_impl *c, uint8_t server_key[32]) {
  int r = connect_stream(c);
  if (r)
    return fail(c, r, "connecting to control server");
  int n = snprintf(
      c->request, REQUEST_SIZE,
      "GET /key?v=%u HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
      TSC_CONTROL_VERSION, c->authority);
  if (n < 0 || (size_t)n >= REQUEST_SIZE)
    r = TSC_ERR_SPACE;
  else
    r = write_all(c, c->request, (size_t)n);
  unsigned status = 0;
  if (!r)
    r = read_headers(c, &status);
  if (!r && status != 200)
    r = fail(c, TSC_ERR_PROTOCOL, "server key request returned HTTP %u",
             status);
  size_t used = 0;
  while (!r && used < TSC_CONTROL_RESPONSE_SIZE) {
    size_t got = 0;
    r = tsc_stream_read(&c->stream, c->response + used,
                        TSC_CONTROL_RESPONSE_SIZE - used, &got,
                        c->config.timeout_ms);
    if (r || !got)
      break;
    used += got;
  }
  tsc_stream_close(&c->stream);
  if (r)
    return fail(c, r, "receiving server key");
  if (used == TSC_CONTROL_RESPONSE_SIZE)
    return fail(c, TSC_ERR_SPACE, "server key response too large");
  c->response[used] = 0;
  r = parse(c, c->response, used);
  size_t item = 0;
  if (!r)
    r = member(c, c->response, 0, "publicKey", &item);
  if (r == TSC_AGAIN)
    r = member(c, c->response, 0, "PublicKey", &item);
  char key[80];
  if (!r)
    r = string(c, c->response, item, key, sizeof(key));
  if (!r)
    r = decode_key(key, "mkey:", server_key);
  return r ? fail(c, r, "invalid server public key") : TSC_OK;
}
static void base64(const uint8_t *data, size_t length, char *out) {
  static const char b64[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t n = 0;
  for (size_t i = 0; i < length; i += 3) {
    unsigned v = (unsigned)data[i] << 16;
    if (i + 1 < length)
      v |= (unsigned)data[i + 1] << 8;
    if (i + 2 < length)
      v |= data[i + 2];
    out[n++] = b64[(v >> 18) & 63];
    out[n++] = b64[(v >> 12) & 63];
    out[n++] = i + 1 < length ? b64[(v >> 6) & 63] : '=';
    out[n++] = i + 2 < length ? b64[v & 63] : '=';
  }
  out[n] = 0;
}
static int upgrade(control_impl *c, const uint8_t server_key[32]) {
  int r = connect_stream(c);
  if (r)
    return fail(c, r, "connecting for Noise upgrade");
  uint8_t initiation[101];
  char encoded[140];
  r = tsc_noise_handshake_start(&c->noise, &c->stream, TSC_CONTROL_VERSION,
                                c->config.machine_private_key, server_key,
                                initiation);
  c->noise.timeout_ms = c->config.timeout_ms;
  if (r)
    return fail(c, r, "creating Noise handshake");
  base64(initiation, sizeof(initiation), encoded);
  int n = snprintf(
      c->request, REQUEST_SIZE,
      "POST /ts2021 HTTP/1.1\r\nHost: %s\r\nUpgrade: "
      "tailscale-control-protocol\r\nConnection: Upgrade\r\nUser-Agent: "
      "tailscalec\r\nX-Tailscale-Handshake: %s\r\nContent-Length: 0\r\n\r\n",
      c->authority, encoded);
  if (n < 0 || (size_t)n >= REQUEST_SIZE)
    return fail(c, TSC_ERR_SPACE, "upgrade request too large");
  r = write_all(c, c->request, (size_t)n);
  unsigned status = 0;
  if (!r)
    r = read_headers(c, &status);
  if (r)
    return fail(c, r, "reading Noise HTTP upgrade");
  if (status != 101)
    return fail(c, TSC_ERR_PROTOCOL, "Noise upgrade returned HTTP %u", status);
  r = tsc_noise_handshake_finish(&c->noise);
  if (r)
    return fail(c, r, "authenticating Noise server");
  r = tsc_h2_start(&c->h2, &c->noise);
  if (r)
    return fail(c, r, "starting encrypted HTTP/2");
  return TSC_OK;
}
static void hostinfo(writer *w, control_impl *c) {
  put(w, "\"Hostinfo\":{\"Hostname\":");
  quoted(w, c->config.hostname ? c->config.hostname : "tailscalec");
  put(w, ",\"OS\":\"linux\",\"OSVersion\":\"tailscalec\",\"GoArch\":\"arm\","
         "\"NetInfo\":{\"PreferredDERP\":");
  char region[8];
  snprintf(region, sizeof(region), "%u", c->config.preferred_derp);
  put(w, region);
  put(w, "}}");
}
static int post(control_impl *c, const char *path, size_t request_length,
                size_t *length, int streaming) {
  unsigned status = 0;
  int r = (streaming ? tsc_h2_post_map : tsc_h2_post)(
      &c->h2, c->authority, path, c->request, request_length, c->response,
      TSC_CONTROL_RESPONSE_SIZE, length, &status);
  if (r)
    return fail(c, r, "control HTTP/2 request failed (%s)", path);
  c->response[*length] = 0;
  if (status != 200)
    return fail(c, TSC_ERR_PROTOCOL, "%s returned HTTP %u", path, status);
  return TSC_OK;
}
static int register_node(control_impl *c) {
  writer w = {c->request, REQUEST_SIZE, 0, 0};
  c->request[0] = 0;
  char key[65];
  hexkey(c->node_public, key);
  put(&w, "{\"Version\":131,\"NodeKey\":\"nodekey:");
  put(&w, key);
  put(&w, "\",");
  if (c->config.auth_key && c->config.auth_key[0]) {
    put(&w, "\"Auth\":{\"AuthKey\":");
    quoted(&w, c->config.auth_key);
    put(&w, "},");
  }
  if (c->h2.has_challenge) {
    uint8_t proof[32];
    int r =
        tsc_crypto_x25519(proof, c->config.node_private_key, c->h2.challenge);
    if (r)
      return fail(c, r, "computing node key challenge");
    hexkey(proof, key);
    tsc_crypto_zero(proof, sizeof(proof));
    put(&w, "\"NodeKeyChallengeResponse\":\"chalresp:");
    put(&w, key);
    put(&w, "\",");
  }
  hostinfo(&w, c);
  put(&w, "}");
  if (w.error)
    return fail(c, w.error, "registration request exceeds configured capacity");
  size_t length = 0;
  int r = post(c, "/machine/register", w.length, &length, 0);
  if (r)
    return r;
  r = parse(c, c->response, length);
  if (r)
    return fail(c, r, "malformed registration response");
  size_t index = 0;
  char text[160];
  if (member(c, c->response, 0, "Error", &index) == TSC_OK) {
    r = string(c, c->response, index, text, sizeof(text));
    if (r)
      return fail(c, r, "invalid registration error");
    if (text[0])
      return fail(c, TSC_ERR_PROTOCOL, "server rejected registration: %.110s",
                  text);
  }
  if (member(c, c->response, 0, "AuthURL", &index) == TSC_OK) {
    r = string(c, c->response, index, text, sizeof(text));
    if (r)
      return fail(c, r, "invalid authorization response");
    if (text[0])
      return fail(
          c, TSC_ERR_UNSUPPORTED,
          "interactive authorization required; provide a valid auth key");
  }
  int value = 0;
  if (member(c, c->response, 0, "NodeKeyExpired", &index) == TSC_OK) {
    r = tsc_json_bool(c->response, &c->tokens[index], &value);
    if (r || value)
      return fail(c, TSC_ERR_PROTOCOL, "node key expired");
  }
  r = member(c, c->response, 0, "MachineAuthorized", &index);
  if (r || tsc_json_bool(c->response, &c->tokens[index], &value) != TSC_OK ||
      !value)
    return fail(c, TSC_ERR_PROTOCOL, "machine is not authorized");
  return TSC_OK;
}

static int parse_addresses(control_impl *c, const char *json, size_t node,
                           tsc_control_peer *peer) {
  size_t addresses;
  int r = member(c, json, node, "Addresses", &addresses);
  if (r)
    return r == TSC_AGAIN ? TSC_ERR_PROTOCOL : r;
  if (c->tokens[addresses].type != TSC_JSON_ARRAY)
    return TSC_ERR_PROTOCOL;
  for (size_t i = addresses + 1; i < c->tokens[addresses].next;
       i = c->tokens[i].next) {
    char address[100];
    r = string(c, json, i, address, sizeof(address));
    if (r)
      return r;
    char *slash = strchr(address, '/');
    if (!slash)
      return TSC_ERR_PROTOCOL;
    *slash++ = 0;
    uint8_t bytes[16];
    unsigned family;
    r = tsc_control_ip_parse(address, bytes, &family);
    if (r)
      return r;
    if (family == 4) {
      if (strcmp(slash, "32"))
        return TSC_ERR_UNSUPPORTED;
      if (peer->has_ipv4)
        return TSC_ERR_UNSUPPORTED;
      memcpy(peer->ipv4, bytes, 4);
      peer->has_ipv4 = 1;
    } else {
      if (strcmp(slash, "128"))
        return TSC_ERR_UNSUPPORTED;
      if (peer->has_ipv6)
        return TSC_ERR_UNSUPPORTED;
      memcpy(peer->ipv6, bytes, 16);
      peer->has_ipv6 = 1;
    }
  }
  return peer->has_ipv4 || peer->has_ipv6 ? TSC_OK : TSC_ERR_PROTOCOL;
}
#if TSC_CONTROL_COMPACT_PEERS
static unsigned endpoint_rank(control_impl *c, const tsc_endpoint *ep) {
  const uint8_t *a = ep->address;
  if (a[0] == 127 || !a[0] || a[0] >= 224 || (a[0] == 169 && a[1] == 254)) return 0;
  int private_ip = a[0] == 10 || (a[0] == 172 && a[1] >= 16 && a[1] < 32) ||
                   (a[0] == 192 && a[1] == 168) || (a[0] == 100 && a[1] >= 64 && a[1] < 128);
  if (!private_ip) return 3;
  for (size_t i = 0; i < c->endpoint_count; ++i)
    if (c->endpoints[i].family == TSC_AF_IPV4 && !memcmp(c->endpoints[i].address, a, 3)) return 4;
  return 1;
}
#endif
static int parse_node(control_impl *c, const char *json, size_t index,
                       tsc_control_peer *peer) {
  memset(peer, 0, sizeof(*peer));
  peer->online = 1; /* Missing status is a hint of unknown, never a denial. */
  if (c->tokens[index].type != TSC_JSON_OBJECT)
    return TSC_ERR_PROTOCOL;
  size_t item;
  int64_t value;
  int r = member(c, json, index, "ID", &item);
  if (r || tsc_json_int64(json, &c->tokens[item], &value) != TSC_OK ||
      value <= 0)
    return TSC_ERR_PROTOCOL;
  peer->id = (uint64_t)value;
  char text[160];
  if (member(c, json, index, "Online", &item) == TSC_OK &&
      c->tokens[item].type != TSC_JSON_NULL) {
    int online;
    if (tsc_json_bool(json, &c->tokens[item], &online)) return TSC_ERR_PROTOCOL;
    peer->online = (unsigned)online;
  }
  r = member(c, json, index, "Key", &item);
  if (r)
    return TSC_ERR_PROTOCOL;
  r = string(c, json, item, text, sizeof(text));
  if (r)
    return r;
  r = decode_key(text, "nodekey:", peer->public_key);
  if (r)
    return r;
  if (member(c, json, index, "DiscoKey", &item) == TSC_OK) {
    r = string(c, json, item, text, sizeof(text));
    if (r)
      return r;
    if (text[0]) {
      r = decode_key(text, "discokey:", peer->disco_key);
      if (r)
        return r;
    }
  }
  if (TSC_CONTROL_PEER_NAME_SIZE > 1 && member(c, json, index, "Name", &item) == TSC_OK) {
    r = string(c, json, item, peer->name, sizeof(peer->name));
    if (r)
      return r;
  }
  r = parse_addresses(c, json, index, peer);
  if (r)
    return r;
  if (member(c, json, index, "HomeDERP", &item) == TSC_OK) {
    r = tsc_json_int64(json, &c->tokens[item], &value);
    if (r || value < 0 || value > 65535)
      return TSC_ERR_PROTOCOL;
    peer->home_derp = (uint16_t)value;
  } else if (member(c, json, index, "DERP", &item) == TSC_OK &&
             c->tokens[item].type != TSC_JSON_NULL) {
    /* Coordinators serving older capability versions use a magic IP:port. */
    r = string(c, json, item, text, sizeof(text));
    if (r)
      return r;
    if (text[0]) {
      tsc_endpoint derp;
      r = tsc_control_endpoint_parse(text, &derp);
      const uint8_t magic[] = {127, 3, 3, 40};
      if (r || derp.family != TSC_AF_IPV4 ||
          memcmp(derp.address, magic, sizeof(magic)))
        return TSC_ERR_PROTOCOL;
      peer->home_derp = derp.port;
    }
  }
  if (member(c, json, index, "Endpoints", &item) == TSC_OK &&
      c->tokens[item].type != TSC_JSON_NULL) {
    if (c->tokens[item].type != TSC_JSON_ARRAY)
      return TSC_ERR_PROTOCOL;
    for (size_t i = item + 1; i < c->tokens[item].next; i = c->tokens[i].next) {
      r = string(c, json, i, text, sizeof(text));
      if (r)
        return r;
      tsc_endpoint endpoint;
      r = tsc_control_endpoint_parse(text, &endpoint);
      if (r)
        return r;
#if !TSC_ENABLE_IPV6
      if (endpoint.family == TSC_AF_IPV6)
        continue;
#endif
      int duplicate = 0;
      for (size_t j = 0; j < peer->endpoint_count; j++) {
        tsc_endpoint previous = tsc_control_endpoint_load(&peer->endpoints[j]);
        if (tsc_endpoint_equal(&endpoint, &previous))
          duplicate = 1;
      }
      if (duplicate)
        continue;
      if (peer->endpoint_count >= TSC_CONTROL_MAX_ENDPOINTS) {
#if TSC_CONTROL_COMPACT_PEERS
        /* Candidate addresses are reachability hints, not authorization.
         * Keep a bounded set, preferring public/same-LAN paths over extra
         * bridges and virtual interfaces on larger machines. */
        size_t least = 0;
        unsigned rank = UINT_MAX;
        for (size_t j = 0; j < peer->endpoint_count; ++j) {
          tsc_endpoint candidate = tsc_control_endpoint_load(&peer->endpoints[j]);
          unsigned score = endpoint_rank(c, &candidate);
          if (score <= rank) { rank = score; least = j; }
        }
        if (endpoint_rank(c, &endpoint) > rank)
          tsc_control_endpoint_store(&peer->endpoints[least], &endpoint);
        continue;
#else
        return TSC_ERR_SPACE;
#endif
      }
      tsc_control_endpoint_store(&peer->endpoints[peer->endpoint_count++], &endpoint);
    }
  }
  return TSC_OK;
}
static int parse_policy(control_impl *c, const char *json) {
  tsc_policy *policy = &c->next_map.policy;
  memset(policy, 0, sizeof(*policy));
  size_t item;
  int r = member(c, json, 0, "PacketFilter", &item);
  if (r == TSC_OK) {
    r = tsc_policy_parse_json(policy,
                              (const uint8_t *)json + c->tokens[item].start,
                              c->tokens[item].end - c->tokens[item].start);
    if (r)
      return r;
  } else if (r != TSC_AGAIN)
    return r;
  r = member(c, json, 0, "PacketFilters", &item);
  if (r == TSC_AGAIN)
    return TSC_OK;
  if (r)
    return r;
  if (c->tokens[item].type == TSC_JSON_NULL)
    return TSC_OK;
  if (c->tokens[item].type != TSC_JSON_OBJECT)
    return TSC_ERR_PROTOCOL;
  size_t reset;
  if (tsc_json_object_find(json, c->tokens, c->token_count, item, "*",
                           &reset) == TSC_OK) {
    if (c->tokens[reset].type != TSC_JSON_NULL)
      return TSC_ERR_UNSUPPORTED;
    memset(policy, 0, sizeof(*policy));
  }
  /* A nonstreaming MapRequest supplies a fresh policy map. The sole base
   * set can replace the legacy PacketFilter; other named sets are appended.
   * Legacy+other named sets with base deletion is rejected conservatively. */
  size_t base;
  if (tsc_json_object_find(json, c->tokens, c->token_count, item, "base",
                           &base) == TSC_OK) {
    r = tsc_policy_parse_json(policy,
                              (const uint8_t *)json + c->tokens[base].start,
                              c->tokens[base].end - c->tokens[base].start);
    if (r)
      return r;
  }
  for (size_t k = item + 1; k < c->tokens[item].next;) {
    size_t value = k + 1;
    char name[128];
    r = string(c, json, k, name, sizeof(name));
    if (r)
      return r;
    if (strcmp(name, "*") && strcmp(name, "base") &&
        c->tokens[value].type != TSC_JSON_NULL) {
      r = tsc_policy_append_json(policy,
                                (const uint8_t *)json + c->tokens[value].start,
                                c->tokens[value].end - c->tokens[value].start);
      if (r)
        return r;
    }
    k = c->tokens[value].next;
  }
  return TSC_OK;
}
static int map_time(control_impl *c, const char *json) {
  c->map_has_control_time = 0;
  size_t item;
  int r = member(c, json, 0, "ControlTime", &item);
  if (r == TSC_AGAIN || (r == TSC_OK && c->tokens[item].type == TSC_JSON_NULL))
    return TSC_OK;
  if (r)
    return r;
  char text[64];
  r = string(c, json, item, text, sizeof(text));
  if (r)
    return r;
  int64_t millis;
  unsigned remainder, zero;
  r = tsc_control_time_parse(text, &millis, &remainder, &zero);
  if (r)
    return r;
  if (zero)
    return TSC_OK;
  c->map_control_time_ms = millis + (remainder ? 1 : 0);
  c->map_has_control_time = 1;
  return TSC_OK;
}
static int node_expiry(control_impl *c, const char *json, size_t node,
                       unsigned *has_expiry, uint64_t *deadline) {
  *has_expiry = 0;
  *deadline = 0;
  size_t item;
  int r = member(c, json, node, "KeyExpiry", &item);
  if (r == TSC_AGAIN || (r == TSC_OK && c->tokens[item].type == TSC_JSON_NULL))
    return TSC_OK;
  if (r)
    return r;
  char text[64];
  r = string(c, json, item, text, sizeof(text));
  if (r)
    return r;
  int64_t expiry;
  unsigned remainder, zero;
  r = tsc_control_time_parse(text, &expiry, &remainder, &zero);
  if (r || zero)
    return r;
  if (!c->map_has_control_time || !c->request_has_clock)
    return TSC_ERR_UNSUPPORTED;
  *has_expiry = 1;
  *deadline = c->request_started_ms;
  if (expiry > c->map_control_time_ms) {
    uint64_t delta = (uint64_t)(expiry - c->map_control_time_ms);
    if (delta > UINT64_MAX - *deadline)
      return TSC_ERR_PROTOCOL;
    *deadline += delta;
  }
  return TSC_OK;
}
#if TSC_ENABLE_DERP
static int derp_port(control_impl *c, const char *json, size_t node,
                     const char *name, uint16_t fallback, uint16_t *out) {
  size_t item;
  int r = member(c, json, node, name, &item);
  if (r == TSC_AGAIN) { *out = fallback; return TSC_OK; }
  int64_t value;
  if (r || tsc_json_int64(json, &c->tokens[item], &value) ||
      value < -1 || value > 65535)
    return TSC_ERR_PROTOCOL;
  *out = value < 0 ? 0 : value == 0 ? fallback : (uint16_t)value;
  return TSC_OK;
}
static int parse_derp_map(control_impl *c, const char *json) {
  size_t map, regions;
  int r = member(c, json, 0, "DERPMap", &map);
  if (r == TSC_AGAIN || (r == TSC_OK && c->tokens[map].type == TSC_JSON_NULL))
    return TSC_OK;
  if (r || c->tokens[map].type != TSC_JSON_OBJECT)
    return TSC_ERR_PROTOCOL;
  r = member(c, json, map, "Regions", &regions);
  if (r == TSC_AGAIN)
    return TSC_OK;
  if (r || c->tokens[regions].type != TSC_JSON_OBJECT)
    return TSC_ERR_PROTOCOL;
  for (size_t key = regions + 1; key < c->tokens[regions].next;) {
    size_t value = key + 1, item;
    if (c->next_map.derp_region_count == TSC_MAX_DERP_REGIONS)
      return TSC_ERR_SPACE;
    tsc_control_derp_region *region =
        &c->next_map.derp_regions[c->next_map.derp_region_count++];
    int64_t id;
    if (member(c, json, value, "RegionID", &item) ||
        tsc_json_int64(json, &c->tokens[item], &id) || id < 1 || id > 65535)
      return TSC_ERR_PROTOCOL;
    region->id = (uint16_t)id;
    for (size_t previous = 0; previous + 1 < c->next_map.derp_region_count; ++previous)
      if (c->next_map.derp_regions[previous].id == region->id)
        return TSC_ERR_PROTOCOL;
    size_t nodes;
    if (member(c, json, value, "Nodes", &nodes) ||
        c->tokens[nodes].type != TSC_JSON_ARRAY)
      return TSC_ERR_PROTOCOL;
    for (size_t n = nodes + 1; n < c->tokens[nodes].next; n = c->tokens[n].next) {
      if (region->node_count == TSC_MAX_DERP_NODES)
        return TSC_ERR_SPACE;
      tsc_control_derp_node *node = &region->nodes[region->node_count++];
      if (member(c, json, n, "HostName", &item) ||
          string(c, json, item, node->hostname, sizeof(node->hostname)) ||
          !node->hostname[0])
        return TSC_ERR_PROTOCOL;
      for (const char *p = node->hostname; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '.'))
          return TSC_ERR_PROTOCOL;
      if (member(c, json, n, "IPv4", &item) == TSC_OK) {
        char text[64]; unsigned family; uint8_t address[16];
        if (string(c, json, item, text, sizeof(text))) return TSC_ERR_PROTOCOL;
        if (text[0] && strcmp(text, "none")) {
          if (tsc_control_ip_parse(text, address, &family) || family != TSC_AF_IPV4)
            return TSC_ERR_PROTOCOL;
          memcpy(node->ipv4, address, 4); node->has_ipv4 = 1;
        }
      }
      if (derp_port(c, json, n, "DERPPort", 443, &node->derp_port) ||
          derp_port(c, json, n, "STUNPort", 3478, &node->stun_port))
        return TSC_ERR_PROTOCOL;
      if (member(c, json, n, "STUNOnly", &item) == TSC_OK) {
        int enabled;
        if (tsc_json_bool(json, &c->tokens[item], &enabled)) return TSC_ERR_PROTOCOL;
        node->stun_only = (unsigned)enabled;
      }
    }
    key = c->tokens[value].next;
  }
  return TSC_OK;
}
#endif

#if TSC_CONTROL_DYNAMIC_PEERS
static void stream_cleanup(control_impl *c) {
  for (unsigned i = 0; i < 2; ++i) {
    free(c->batches[i].data);
    memset(&c->batches[i], 0, sizeof(c->batches[i]));
  }
  c->streaming_peers = 0;
}
static void map_storage_clear(control_impl *c) {
  free(c->map.peers);
  c->map.peers = NULL;
  c->map.peer_count = c->map.peer_capacity = 0;
  stream_cleanup(c);
}
static void stream_begin(control_impl *c) {
  uint64_t generation = c->map.generation;
  map_storage_clear(c);
  memset(&c->map, 0, sizeof(c->map));
  c->map_valid = 0;
  c->stream_generation = generation;
  c->streaming_peers = 1;
}
static int stream_node(control_impl *c, peer_batch *batch, const char *json) {
  size_t item;
  int value;
  if (!member(c, json, 0, "Expired", &item)) {
    if (tsc_json_bool(json, &c->tokens[item], &value)) return TSC_ERR_PROTOCOL;
    if (value) return TSC_OK;
  }
  if (!member(c, json, 0, "MachineAuthorized", &item)) {
    if (tsc_json_bool(json, &c->tokens[item], &value)) return TSC_ERR_PROTOCOL;
    if (!value) return TSC_OK;
  }
  tsc_control_peer peer;
  int r = parse_node(c, json, 0, &peer);
  if (r) return r;
  r = member(c, json, 0, "KeyExpiry", &item);
  if (!r && c->tokens[item].type != TSC_JSON_NULL) {
    char text[64]; int64_t epoch; unsigned remainder, zero;
    r = string(c, json, item, text, sizeof(text));
    if (r) return r;
    r = tsc_control_time_parse(text, &epoch, &remainder, &zero);
    if (r) return r;
    if (!zero) { peer.has_expiry = 1; peer.staging_expiry_unix_ms = epoch; }
  } else if (r != TSC_OK && r != TSC_AGAIN) return r;
  if (batch->count == TSC_MAX_PEERS) return TSC_ERR_SPACE;
  if (batch->count == batch->capacity) {
    size_t capacity = batch->capacity + 8;
    if (capacity > TSC_MAX_PEERS) capacity = TSC_MAX_PEERS;
    tsc_control_peer *data = realloc(batch->data, capacity * sizeof(*data));
    if (!data) return TSC_ERR_SPACE;
    batch->data = data; batch->capacity = capacity;
  }
  batch->data[batch->count++] = peer;
  return TSC_OK;
}
static int projected_peer(void *user, const char *json, size_t length, unsigned source) {
  control_impl *c = user;
  if (source < 1 || source > 2) return TSC_ERR_ARGUMENT;
  peer_batch *batch = &c->batches[source - 1];
  if (!batch->error) {
    int r = parse(c, json, length);
    batch->error = r ? r : stream_node(c, batch, json);
  }
  /* Errors are retained separately: Peers takes precedence over PeersChanged
   * even when those fields arrive in the opposite order. */
  return 0;
}
static int install_streamed_peers(control_impl *c, const char *json, uint64_t now) {
  size_t item;
  unsigned source = 0;
  int r = member(c, json, 0, "Peers", &item);
  if (r == TSC_AGAIN || (!r && c->tokens[item].type == TSC_JSON_NULL)) {
    source = 1;
    r = member(c, json, 0, "PeersChanged", &item);
  }
  if (r == TSC_AGAIN || (!r && c->tokens[item].type == TSC_JSON_NULL)) return TSC_OK;
  if (r || c->tokens[item].type != TSC_JSON_ARRAY || c->tokens[item].next != item + 1)
    return TSC_ERR_PROTOCOL; /* Non-object array elements were not streamed. */
  peer_batch *batch = &c->batches[source];
  if (batch->error) return batch->error;
  c->next_map.peers = batch->data;
  c->next_map.peer_capacity = batch->capacity;
  batch->data = NULL;
  for (size_t i = 0; i < batch->count; ++i) {
    tsc_control_peer peer = c->next_map.peers[i];
    if (peer.has_expiry) {
      if (!c->map_has_control_time || !c->request_has_clock) return TSC_ERR_UNSUPPORTED;
      int64_t epoch = peer.staging_expiry_unix_ms;
      uint64_t deadline = c->request_started_ms;
      if (epoch > c->map_control_time_ms) {
        uint64_t delta = (uint64_t)(epoch - c->map_control_time_ms);
        if (delta > UINT64_MAX - deadline) return TSC_ERR_PROTOCOL;
        deadline += delta;
      }
      if (now >= deadline) continue;
      peer.expires_at_ms = deadline;
    }
    c->next_map.peers[c->next_map.peer_count++] = peer;
  }
  return TSC_OK;
}
#endif

static int parse_map(control_impl *c, const char *json, size_t length) {
#if TSC_CONTROL_DYNAMIC_PEERS
  uint64_t generation = c->stream_generation;
  if (!c->streaming_peers) return fail(c, TSC_ERR_ARGUMENT, "peer stream not started");
#else
  uint64_t generation = c->map.generation;
#endif
  int r = parse(c, json, length);
  if (r)
    return fail(c, r, "malformed map JSON or token capacity exceeded");
  if (c->tokens[0].type != TSC_JSON_OBJECT)
    return fail(c, TSC_ERR_PROTOCOL, "map is not an object");
  c->map_valid = 0;
#if !TSC_CONTROL_DYNAMIC_PEERS
  memset(&c->next_map, 0, sizeof(c->next_map));
#endif
  r = map_time(c, json);
  if (r)
    return fail(c, r, "invalid authenticated coordinator time");
  uint64_t now = c->request_started_ms;
  if (c->request_has_clock) {
    r = monotonic_now(c, &now);
    if (r)
      return r;
  }
  size_t node;
  tsc_control_peer self;
  r = member(c, json, 0, "Node", &node);
  if (r)
    return fail(c, TSC_ERR_PROTOCOL, "full map omitted own node");
  r = parse_node(c, json, node, &self);
  if (r)
    return fail(c, r, "invalid own node or address capacity exceeded");
  if (!tsc_crypto_equal(self.public_key, c->node_public, 32))
    return fail(c, TSC_ERR_PROTOCOL, "map contains another node's identity");
  size_t item;
  int authorized;
  if (member(c, json, node, "MachineAuthorized", &item) == TSC_OK &&
      (tsc_json_bool(json, &c->tokens[item], &authorized) != TSC_OK ||
       !authorized))
    return fail(c, TSC_ERR_PROTOCOL, "machine authorization revoked");
  if (member(c, json, node, "Expired", &item) == TSC_OK &&
      (tsc_json_bool(json, &c->tokens[item], &authorized) != TSC_OK ||
       authorized))
    return fail(c, TSC_ERR_PROTOCOL, "node key expired");
  memcpy(c->next_map.ipv4, self.ipv4, 4);
  memcpy(c->next_map.ipv6, self.ipv6, 16);
  c->next_map.has_ipv4 = self.has_ipv4;
  c->next_map.has_ipv6 = self.has_ipv6;
  c->next_map.node_id = self.id;
  c->next_map.home_derp = self.home_derp;
  if (!member(c, json, node, "Name", &item)) {
    r = string(c, json, item, c->next_map.name, sizeof(c->next_map.name));
    if (r) return fail(c, r, "invalid own node name");
  }
  r = node_expiry(c, json, node, &c->next_map.has_expiry,
                  &c->next_map.expires_at_ms);
  if (r)
    return fail(c, r, "cannot safely determine local key expiry");
  if (c->next_map.has_expiry && now >= c->next_map.expires_at_ms)
    return fail(c, TSC_ERR_PROTOCOL, "local node key expired");
#if TSC_CONTROL_DYNAMIC_PEERS
  r = install_streamed_peers(c, json, now);
  if (r) return fail(c, r, "invalid streamed peers or directory capacity exceeded");
  for (size_t i = 0; i < c->next_map.peer_count; ++i) {
    const tsc_control_peer *peer = &c->next_map.peers[i];
    if (peer->id == self.id || tsc_crypto_equal(peer->public_key, self.public_key, 32) ||
        (peer->has_ipv4 && self.has_ipv4 && !memcmp(peer->ipv4, self.ipv4, 4)) ||
        (peer->has_ipv6 && self.has_ipv6 && !memcmp(peer->ipv6, self.ipv6, 16)))
      return fail(c, TSC_ERR_PROTOCOL, "self identity or address listed as peer");
    for (size_t j = 0; j < i; ++j) {
      const tsc_control_peer *previous = &c->next_map.peers[j];
      if (peer->id == previous->id || tsc_crypto_equal(peer->public_key, previous->public_key, 32) ||
          (peer->has_ipv4 && previous->has_ipv4 && !memcmp(peer->ipv4, previous->ipv4, 4)) ||
          (peer->has_ipv6 && previous->has_ipv6 && !memcmp(peer->ipv6, previous->ipv6, 16)))
        return fail(c, TSC_ERR_PROTOCOL, "duplicate peer identity or address");
    }
  }
#else
  r = member(c, json, 0, "Peers", &item);
  /* Each fetch starts a new map stream. Tailscale sends its initial complete
   * peer set as PeersChanged, while Headscale uses Peers. This is not a delta
   * merge: no state from a previous stream may survive a full refresh. */
  if (r == TSC_AGAIN || (r == TSC_OK && c->tokens[item].type == TSC_JSON_NULL))
    r = member(c, json, 0, "PeersChanged", &item);
  if (r == TSC_OK && c->tokens[item].type != TSC_JSON_NULL) {
    if (c->tokens[item].type != TSC_JSON_ARRAY)
      return fail(c, TSC_ERR_PROTOCOL, "invalid peer array");
    for (size_t i = item + 1; i < c->tokens[item].next; i = c->tokens[i].next) {
      size_t state;
      int value;
      if (member(c, json, i, "Expired", &state) == TSC_OK) {
        if (tsc_json_bool(json, &c->tokens[state], &value) != TSC_OK)
          return fail(c, TSC_ERR_PROTOCOL, "invalid peer expiry state");
        if (value)
          continue;
      }
      if (member(c, json, i, "MachineAuthorized", &state) == TSC_OK) {
        if (tsc_json_bool(json, &c->tokens[state], &value) != TSC_OK)
          return fail(c, TSC_ERR_PROTOCOL, "invalid peer authorization state");
        if (!value)
          continue;
      }
      unsigned has_expiry;
      uint64_t deadline;
      r = node_expiry(c, json, i, &has_expiry, &deadline);
      if (r)
        return fail(c, r, "cannot safely determine peer key expiry");
      if (has_expiry && now >= deadline)
        continue;
      if (c->next_map.peer_count >= TSC_MAX_PEERS)
        return fail(c, TSC_ERR_SPACE, "peer map exceeds TSC_MAX_PEERS");
      tsc_control_peer *peer = &c->next_map.peers[c->next_map.peer_count];
      r = parse_node(c, json, i, peer);
      if (r)
        return fail(c, r, "invalid peer node or endpoint capacity exceeded");
      peer->has_expiry = has_expiry;
      peer->expires_at_ms = deadline;
      if (peer->id == self.id ||
          tsc_crypto_equal(peer->public_key, self.public_key, 32) ||
          (peer->has_ipv4 && self.has_ipv4 &&
           !memcmp(peer->ipv4, self.ipv4, 4)) ||
          (peer->has_ipv6 && self.has_ipv6 &&
           !memcmp(peer->ipv6, self.ipv6, 16)))
        return fail(c, TSC_ERR_PROTOCOL,
                    "self identity or address listed as peer");
      for (size_t j = 0; j < c->next_map.peer_count; j++) {
        tsc_control_peer *previous = &c->next_map.peers[j];
        if (peer->id == previous->id ||
            tsc_crypto_equal(peer->public_key, previous->public_key, 32) ||
            (peer->has_ipv4 && previous->has_ipv4 &&
             !memcmp(peer->ipv4, previous->ipv4, 4)) ||
            (peer->has_ipv6 && previous->has_ipv6 &&
             !memcmp(peer->ipv6, previous->ipv6, 16)))
          return fail(c, TSC_ERR_PROTOCOL,
                      "duplicate peer identity or address");
      }
      c->next_map.peer_count++;
    }
  } else if (r != TSC_AGAIN && r != TSC_OK)
    return fail(c, r, "invalid peers field");
#endif
#if TSC_ENABLE_DERP
  r = parse_derp_map(c, json);
  if (r)
    return fail(c, r, "DERP map malformed or exceeds configured capacity");
#endif
  r = parse_policy(c, json);
  if (r)
    return fail(c, r,
                "packet filter unsupported, malformed, or exceeds capacity");
  c->next_map.generation = generation + 1;
  c->map = c->next_map;
  c->map_valid = 1;
  c->last_map_ms = c->request_started_ms;
  c->error[0] = 0;
  return TSC_OK;
}
static int build_map_request(control_impl *c, int streaming,
                             size_t *request_length) {
  writer w = {c->request, REQUEST_SIZE, 0, 0};
  c->request[0] = 0;
  char key[65];
  hexkey(c->node_public, key);
  put(&w, "{\"Version\":131,\"NodeKey\":\"nodekey:");
  put(&w, key);
  put(&w, "\",\"DiscoKey\":\"discokey:");
  hexkey(c->config.disco_public_key, key);
  put(&w, key);
  put(&w, streaming ? "\",\"Stream\":true,"
                    : "\",\"Stream\":false,\"OmitPeers\":true,");
  put(&w, "\"KeepAlive\":false,\"Compress\":\"\",\"Endpoints\":[");
  for (size_t i = 0; i < c->endpoint_count; i++) {
    char endpoint[100];
    int r = tsc_control_endpoint_format(&c->endpoints[i], endpoint,
                                        sizeof(endpoint));
    if (r)
      return fail(c, r, "unsupported endpoint");
    if (i)
      put(&w, ",");
    quoted(&w, endpoint);
  }
  put(&w, "],\"EndpointTypes\":[");
  for (size_t i = 0; i < c->endpoint_count; i++) {
    if (i)
      put(&w, ",");
    char type[2] = {(char)('0' + c->endpoint_types[i]), 0};
    put(&w, type);
  }
  put(&w, "],");
  hostinfo(&w, c);
  put(&w, "}");
  if (w.error)
    return fail(c, w.error, "map request exceeds configured capacity");
  *request_length = w.length;
  return TSC_OK;
}
static int fetch_map(control_impl *c) {
  c->request_has_clock = 0;
  if (c->config.platform && c->config.platform->monotonic_ms) {
    int clock_result = monotonic_now(c, &c->request_started_ms);
    if (clock_result)
      return clock_result;
    c->request_has_clock = 1;
  }
  /* New coordinators ignore endpoint changes in streaming MapRequests. A
   * separate lightweight update also keeps the permanent map protocol small. */
  size_t request_length = 0, length = 0;
  int r = build_map_request(c, 0, &request_length);
  if (!r)
    r = post(c, "/machine/map", request_length, &length, 0);
  if (!r)
    r = build_map_request(c, 1, &request_length);
#if TSC_CONTROL_PROJECT_MAP
  tsc_json_project projection;
  tsc_json_project_init(&projection, c->response, TSC_CONTROL_RESPONSE_SIZE + 1);
#if TSC_CONTROL_DYNAMIC_PEERS
  stream_begin(c);
  projection.peer_handler = projected_peer;
  projection.peer_user = c;
#endif
  unsigned status = 0;
  if (!r)
    r = tsc_h2_post_map_stream(&c->h2, c->authority, "/machine/map", c->request,
        request_length, 131072, tsc_json_project_feed, &projection, &status);
  if (!r && status != 200) r = TSC_ERR_PROTOCOL;
  if (!r) r = tsc_json_project_finish(&projection);
  if (r) {
#if TSC_CONTROL_DYNAMIC_PEERS
    stream_cleanup(c);
#endif
    return fail(c, r, "streaming control transport/projection failed");
  }
  r = parse_map(c, c->response, projection.used);
#if TSC_CONTROL_DYNAMIC_PEERS
  stream_cleanup(c);
#endif
  return r;
#else
  if (!r)
    r = post(c, "/machine/map", request_length, &length, 1);
  if (r)
    return r;
  /* MapResponse framing is an uncompressed little-endian uint32 JSON size. */
  if (length < 4)
    return fail(c, TSC_ERR_TRUNCATED, "map response has no length prefix");
  const uint8_t *p = (const uint8_t *)c->response;
  uint32_t n = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
               ((uint32_t)p[3] << 24);
  if (n != length - 4)
    return fail(c, TSC_ERR_PROTOCOL, "unexpected map response length");
  return parse_map(c, c->response + 4, n);
#endif
}
int tsc_control_join(tsc_control *control, const tsc_control_config *config) {
  if (!control || !config || control->implementation ||
      config->endpoint_count > TSC_CONTROL_MAX_ENDPOINTS ||
      (config->endpoint_count && !config->endpoints))
    return TSC_ERR_ARGUMENT;
  control_impl *c = calloc(1, sizeof(*c));
  if (!c)
    return TSC_ERR_SPACE;
  control->implementation = c;
  c->config = *config;
  if (!c->config.timeout_ms)
    c->config.timeout_ms = 10000;
  if (c->config.timeout_ms > INT_MAX)
    return fail(c, TSC_ERR_ARGUMENT, "timeout exceeds INT_MAX");
  int r = url(c, config->url);
  if (r)
    return fail(c, r, "unsupported or invalid control URL");
  r = tsc_control_set_endpoints_typed(control, config->endpoints,
                                      config->endpoint_types, config->endpoint_count);
  if (r)
    return r;
  r = tsc_crypto_x25519_public(c->node_public, config->node_private_key);
  if (r)
    return fail(c, r, "invalid node private key");
  r = scratch_open(c);
  if (r) return fail(c, r, "control scratch allocation failed");
  uint8_t server_key[32];
  if (config->server_public_key) {
    memcpy(server_key, config->server_public_key, sizeof(server_key));
    r = TSC_OK;
  } else {
    r = read_server_key(c, server_key);
  }
  if (!r)
    r = upgrade(c, server_key);
  tsc_crypto_zero(server_key, sizeof(server_key));
  if (!r)
    r = register_node(c);
  if (!r)
    r = fetch_map(c);
  scratch_close(c);
  if (r) {
    tsc_stream_close(&c->stream);
    tsc_noise_clear(&c->noise);
    return r;
  }
  c->connected = 1;
  return TSC_OK;
}
int tsc_control_poll(tsc_control *control) {
  if (!control || !control->implementation)
    return TSC_ERR_ARGUMENT;
  control_impl *c = control->implementation;
  if (!c->connected)
    return fail(c, TSC_ERR_IO, "control is disconnected");
  int r = scratch_open(c);
  if (r) return fail(c, r, "control scratch allocation failed");
  r = fetch_map(c);
  scratch_close(c);
  if (r) {
    c->connected = 0;
    tsc_stream_close(&c->stream);
    tsc_noise_clear(&c->noise);
  }
  return r;
}
int tsc_control_expire(tsc_control *control) {
  if (!control || !control->implementation)
    return TSC_ERR_ARGUMENT;
  control_impl *c = control->implementation;
  if (!c->map_valid)
    return TSC_ERR_PROTOCOL;
  if (!c->config.platform || !c->config.platform->monotonic_ms) {
    if (c->map.has_expiry)
      return fail(c, TSC_ERR_UNSUPPORTED, "expiry clock unavailable");
    for (size_t i = 0; i < c->map.peer_count; i++)
      if (c->map.peers[i].has_expiry)
        return fail(c, TSC_ERR_UNSUPPORTED, "expiry clock unavailable");
    return TSC_OK;
  }
  uint64_t now;
  int r = monotonic_now(c, &now);
  if (r)
    return r;
  if (c->map.has_expiry && now >= c->map.expires_at_ms) {
    if (c->map.peer_count || c->map.policy.rule_count)
      c->map.generation++;
    return fail(c, TSC_ERR_PROTOCOL, "local node key expired");
  }
  size_t retained = 0;
  for (size_t i = 0; i < c->map.peer_count; i++) {
    if (c->map.peers[i].has_expiry && now >= c->map.peers[i].expires_at_ms)
      continue;
    if (retained != i)
      c->map.peers[retained] = c->map.peers[i];
    retained++;
  }
  if (retained != c->map.peer_count) {
    memset(c->map.peers + retained, 0,
           (c->map.peer_count - retained) * sizeof(c->map.peers[0]));
    c->map.peer_count = retained;
    c->map.generation++;
  }
  return TSC_OK;
}
int tsc_control_maintain(tsc_control *control, uint32_t max_age_ms) {
  if (!control || !control->implementation || !max_age_ms)
    return TSC_ERR_ARGUMENT;
  int r = tsc_control_expire(control);
  if (r)
    return r;
  control_impl *c = control->implementation;
  uint64_t now;
  r = monotonic_now(c, &now);
  if (r)
    return r;
  if (!c->connected)
    return fail(c, TSC_ERR_IO, "control is disconnected");
  if (now - c->last_map_ms < max_age_ms)
    return TSC_OK;
  return tsc_control_poll(control);
}
int tsc_control_set_endpoints(tsc_control *control,
                               const tsc_endpoint *endpoints, size_t count) {
  return tsc_control_set_endpoints_typed(control, endpoints, NULL, count);
}
int tsc_control_set_endpoints_typed(tsc_control *control,
    const tsc_endpoint *endpoints, const uint8_t *types, size_t count) {
  if (!control || !control->implementation ||
      count > TSC_CONTROL_MAX_ENDPOINTS || (count && !endpoints))
    return TSC_ERR_ARGUMENT;
  control_impl *c = control->implementation;
  for (size_t i = 0; i < count; i++) {
    if (types && types[i] > 5) return TSC_ERR_ARGUMENT;
    char buffer[100];
    int r = tsc_control_endpoint_format(&endpoints[i], buffer, sizeof(buffer));
    if (r)
      return fail(c, r, "invalid advertised endpoint");
  }
  if (count)
    memcpy(c->endpoints, endpoints, count * sizeof(*endpoints));
  for (size_t i = 0; i < count; ++i) c->endpoint_types[i] = types ? types[i] : 1;
  c->endpoint_count = count;
  return TSC_OK;
}
const tsc_control_map *tsc_control_get_map(const tsc_control *control) {
  if (!control || !control->implementation)
    return NULL;
  return &((const control_impl *)control->implementation)->map;
}
const char *tsc_control_last_error(const tsc_control *control) {
  if (!control || !control->implementation)
    return "control is not initialized";
  return ((const control_impl *)control->implementation)->error;
}
void tsc_control_close(tsc_control *control) {
  if (!control || !control->implementation)
    return;
  control_impl *c = control->implementation;
  tsc_stream_close(&c->stream);
  tsc_noise_clear(&c->noise);
  scratch_close(c);
#if TSC_CONTROL_DYNAMIC_PEERS
  map_storage_clear(c);
#endif
  tsc_crypto_zero(c, sizeof(*c));
  free(c);
  control->implementation = NULL;
}

size_t tsc_control_memory_size(void) { return sizeof(control_impl); }
size_t tsc_control_scratch_size(void) {
#if TSC_CONTROL_DYNAMIC_SCRATCH
  return sizeof(control_scratch);
#else
  return 0;
#endif
}
