#include "address.h"
#include <stdio.h>
#include <string.h>

static int digit(char c) { return c >= '0' && c <= '9' ? c - '0' : -1; }
static int hex(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}
static int ipv4(const char *text, uint8_t out[4]) {
  const char *p = text;
  for (unsigned n = 0; n < 4; n++) {
    unsigned v = 0, count = 0;
    while (digit(*p) >= 0) {
      v = v * 10u + (unsigned)digit(*p++);
      if (++count > 3 || v > 255)
        return TSC_ERR_PROTOCOL;
    }
    if (!count)
      return TSC_ERR_PROTOCOL;
    out[n] = (uint8_t)v;
    if (n < 3) {
      if (*p++ != '.')
        return TSC_ERR_PROTOCOL;
    }
  }
  return *p ? TSC_ERR_PROTOCOL : TSC_OK;
}
int tsc_control_ip_parse(const char *text, uint8_t out[16], unsigned *family) {
  if (!text || !out || !family)
    return TSC_ERR_ARGUMENT;
  memset(out, 0, 16);
  if (!strchr(text, ':')) {
    int r = ipv4(text, out);
    if (!r)
      *family = 4;
    return r;
  }
  uint8_t bytes[16] = {0};
  unsigned used = 0;
  int gap = -1;
  const char *p = text;
  if (*p == ':') {
    if (p[1] != ':')
      return TSC_ERR_PROTOCOL;
    gap = 0;
    p += 2;
  }
  while (*p) {
    if (used >= 16)
      return TSC_ERR_PROTOCOL;
    const char *start = p;
    unsigned value = 0, n = 0;
    while (hex(*p) >= 0) {
      value = (value << 4) | (unsigned)hex(*p++);
      if (++n > 4)
        return TSC_ERR_PROTOCOL;
    }
    if (*p == '.') {
      if (used > 12 || ipv4(start, bytes + used) != TSC_OK)
        return TSC_ERR_PROTOCOL;
      used += 4;
      p += strlen(p);
      break;
    }
    if (!n)
      return TSC_ERR_PROTOCOL;
    bytes[used++] = (uint8_t)(value >> 8);
    bytes[used++] = (uint8_t)value;
    if (!*p)
      break;
    if (*p++ != ':')
      return TSC_ERR_PROTOCOL;
    if (*p == ':') {
      if (gap >= 0)
        return TSC_ERR_PROTOCOL;
      gap = (int)used;
      p++;
      if (!*p)
        break;
    } else if (!*p)
      return TSC_ERR_PROTOCOL;
  }
  if (gap >= 0) {
    if (used >= 16)
      return TSC_ERR_PROTOCOL;
    unsigned missing = 16 - used;
    memmove(bytes + gap + missing, bytes + gap, used - (unsigned)gap);
    memset(bytes + gap, 0, missing);
  } else if (used != 16)
    return TSC_ERR_PROTOCOL;
  memcpy(out, bytes, 16);
  *family = 6;
  return TSC_OK;
}
int tsc_control_endpoint_parse(const char *text, tsc_endpoint *out) {
  char host[80];
  const char *port;
  size_t n;
  if (!text || !out)
    return TSC_ERR_ARGUMENT;
  if (text[0] == '[') {
    const char *end = strchr(text, ']');
    if (!end || end[1] != ':')
      return TSC_ERR_PROTOCOL;
    n = (size_t)(end - text - 1);
    port = end + 2;
    text++;
  } else {
    port = strrchr(text, ':');
    if (!port)
      return TSC_ERR_PROTOCOL;
    n = (size_t)(port - text);
    port++;
  }
  if (!n || n >= sizeof(host) || !*port)
    return TSC_ERR_PROTOCOL;
  memcpy(host, text, n);
  host[n] = 0;
  unsigned v = 0, count = 0;
  while (digit(*port) >= 0) {
    v = v * 10u + (unsigned)digit(*port++);
    if (++count > 5 || v > 65535)
      return TSC_ERR_PROTOCOL;
  }
  if (*port || !v)
    return TSC_ERR_PROTOCOL;
  unsigned family;
  memset(out, 0, sizeof(*out));
  int r = tsc_control_ip_parse(host, out->address, &family);
  if (r)
    return r;
  out->family = family == 4 ? TSC_AF_IPV4 : TSC_AF_IPV6;
  out->port = (uint16_t)v;
  return TSC_OK;
}
int tsc_control_endpoint_format(const tsc_endpoint *ep, char *out, size_t cap) {
  if (!ep || !out || !cap || !ep->port)
    return TSC_ERR_ARGUMENT;
  const uint8_t *a = ep->address;
  int n;
  if (ep->family == TSC_AF_IPV4)
    n = snprintf(out, cap, "%u.%u.%u.%u:%u", a[0], a[1], a[2], a[3], ep->port);
  else if (ep->family == TSC_AF_IPV6 && !ep->scope_id)
    n = snprintf(out, cap, "[%x:%x:%x:%x:%x:%x:%x:%x]:%u", (a[0] << 8) | a[1],
                 (a[2] << 8) | a[3], (a[4] << 8) | a[5], (a[6] << 8) | a[7],
                 (a[8] << 8) | a[9], (a[10] << 8) | a[11], (a[12] << 8) | a[13],
                 (a[14] << 8) | a[15], ep->port);
  else
    return TSC_ERR_UNSUPPORTED;
  return n < 0 || (size_t)n >= cap ? TSC_ERR_SPACE : TSC_OK;
}
