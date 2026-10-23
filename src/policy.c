#include "tailscalec/policy.h"

#include <string.h>

/* This schema-specific reader never constructs a JSON tree. The largest
 * temporary string is one IPv6 range; recursion and allocations are absent. */
typedef struct {
    const uint8_t *data;
    size_t length;
    size_t position;
} policy_reader;

static void whitespace(policy_reader *r)
{
    while (r->position < r->length) {
        uint8_t c = r->data[r->position];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        r->position++;
    }
}

static int consume(policy_reader *r, uint8_t c)
{
    whitespace(r);
    if (r->position == r->length || r->data[r->position] != c) return 0;
    r->position++;
    return 1;
}

static int literal_null(policy_reader *r)
{
    whitespace(r);
    if (r->length - r->position < 4 ||
        memcmp(r->data + r->position, "null", 4) != 0) return 0;
    r->position += 4;
    return 1;
}

static int hex_digit(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int string(policy_reader *r, char *out, size_t capacity)
{
    size_t used = 0;
    if (!consume(r, '"')) return TSC_ERR_PROTOCOL;
    while (r->position < r->length) {
        unsigned c = r->data[r->position++];
        if (c == '"') {
            if (used >= capacity) return TSC_ERR_SPACE;
            out[used] = '\0';
            return TSC_OK;
        }
        if (c < 0x20) return TSC_ERR_PROTOCOL;
        if (c == '\\') {
            if (r->position == r->length) return TSC_ERR_PROTOCOL;
            c = r->data[r->position++];
            switch (c) {
            case '"': case '\\': case '/': break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u': {
                unsigned value = 0;
                size_t i;
                if (r->length - r->position < 4) return TSC_ERR_PROTOCOL;
                for (i = 0; i < 4; i++) {
                    int digit = hex_digit(r->data[r->position++]);
                    if (digit < 0) return TSC_ERR_PROTOCOL;
                    value = (value << 4) | (unsigned)digit;
                }
                if (value == 0 || value > 0x7f) return TSC_ERR_UNSUPPORTED;
                c = value;
                break;
            }
            default: return TSC_ERR_PROTOCOL;
            }
        }
        if (c > 0x7f) return TSC_ERR_UNSUPPORTED;
        if (used + 1 >= capacity) return TSC_ERR_SPACE;
        out[used++] = (char)c;
    }
    return TSC_ERR_PROTOCOL;
}

static int number(policy_reader *r, unsigned limit, unsigned *out)
{
    unsigned value = 0;
    size_t start;
    whitespace(r);
    start = r->position;
    while (r->position < r->length) {
        uint8_t c = r->data[r->position];
        if (c < '0' || c > '9') break;
        if (value > limit / 10 ||
            (value == limit / 10 && (unsigned)(c - '0') > limit % 10))
            return TSC_ERR_PROTOCOL;
        value = value * 10 + (unsigned)(c - '0');
        r->position++;
    }
    if (r->position == start ||
        (r->position - start > 1 && r->data[start] == '0'))
        return TSC_ERR_PROTOCOL;
    *out = value;
    return TSC_OK;
}

static int ipv4(const char *begin, const char *end, uint8_t out[4])
{
    unsigned i;
    const char *p = begin;
    for (i = 0; i < 4; i++) {
        unsigned value = 0;
        const char *start = p;
        while (p < end && *p >= '0' && *p <= '9') {
            value = value * 10 + (unsigned)(*p - '0');
            if (value > 255) return TSC_ERR_PROTOCOL;
            p++;
        }
        if (p == start || (p - start > 1 && *start == '0'))
            return TSC_ERR_PROTOCOL;
        out[i] = (uint8_t)value;
        if (i != 3) {
            if (p == end || *p++ != '.') return TSC_ERR_PROTOCOL;
        }
    }
    return p == end ? TSC_OK : TSC_ERR_PROTOCOL;
}

static int ipv6(const char *begin, const char *end, uint8_t out[16])
{
    uint8_t address[16] = {0};
    const char *p = begin;
    size_t used = 0;
    size_t compression = 17;
    if (p == end) return TSC_ERR_PROTOCOL;
    if (*p == ':') {
        if (end - p < 2 || p[1] != ':') return TSC_ERR_PROTOCOL;
        compression = 0;
        p += 2;
    }
    while (p < end) {
        const char *start = p;
        const char *part_end = p;
        unsigned value = 0;
        size_t digits = 0;
        while (part_end < end && *part_end != ':') part_end++;
        if (memchr(start, '.', (size_t)(part_end - start)) != NULL) {
            if (used > 12 || ipv4(start, end, address + used) != TSC_OK)
                return TSC_ERR_PROTOCOL;
            used += 4;
            p = end;
            break;
        }
        while (p < part_end) {
            int digit = hex_digit((uint8_t)*p++);
            if (digit < 0 || ++digits > 4) return TSC_ERR_PROTOCOL;
            value = (value << 4) | (unsigned)digit;
        }
        if (!digits || used > 14) return TSC_ERR_PROTOCOL;
        address[used++] = (uint8_t)(value >> 8);
        address[used++] = (uint8_t)value;
        if (p == end) break;
        p++; /* first separator */
        if (p < end && *p == ':') {
            if (compression != 17) return TSC_ERR_PROTOCOL;
            compression = used;
            p++;
        } else if (p == end) return TSC_ERR_PROTOCOL;
    }
    if (compression != 17) {
        size_t tail = used - compression;
        if (used >= 16) return TSC_ERR_PROTOCOL;
        memmove(address + 16 - tail, address + compression, tail);
        memset(address + compression, 0, 16 - used);
    } else if (used != 16) return TSC_ERR_PROTOCOL;
    memcpy(out, address, 16);
    return TSC_OK;
}

static int address(const char *begin, const char *end, uint8_t out[16],
                   uint8_t *family)
{
    memset(out, 0, 16);
    if (memchr(begin, ':', (size_t)(end - begin))) {
        *family = TSC_AF_IPV6;
        return ipv6(begin, end, out);
    }
    *family = TSC_AF_IPV4;
    return ipv4(begin, end, out);
}

static void store_address(uint8_t *out, const uint8_t value[16], uint8_t family)
{
    /* An IPv4 build keeps no IPv6 address bytes. Its family tag makes such
     * entries nonmatching, after their complete syntax has been checked. */
    if (family == TSC_AF_IPV4) memcpy(out, value, 4);
#if TSC_ENABLE_IPV6
    else memcpy(out, value, 16);
#endif
}

static int prefix(const char *text, tsc_policy_prefix *out)
{
    const char *slash = strchr(text, '/');
    const char *end = text + strlen(text);
    const char *address_end = slash ? slash : end;
    const char *dash = memchr(text, '-', (size_t)(address_end - text));
    uint8_t parsed[16];
    uint8_t family;
    unsigned bits;
    unsigned maximum;
    int result;
    memset(out, 0, sizeof(*out));
    if (strcmp(text, "*") == 0) return TSC_OK;
    if (strncmp(text, "cap:", 4) == 0) return TSC_ERR_UNSUPPORTED;
    if (dash) {
        uint8_t last[16];
        uint8_t last_family;
        if (slash) return TSC_ERR_PROTOCOL;
        result = address(text, dash, parsed, &family);
        if (result != TSC_OK) return result;
        result = address(dash + 1, end, last, &last_family);
        if (result != TSC_OK) return result;
        if (family != last_family ||
            memcmp(parsed, last, family == TSC_AF_IPV4 ? 4u : 16u) > 0)
            return TSC_ERR_PROTOCOL;
        out->family = family;
        out->is_range = 1;
        store_address(out->address, parsed, family);
        store_address(out->end_address, last, family);
        return TSC_OK;
    }
    result = address(text, address_end, parsed, &family);
    if (result != TSC_OK) return result;
    out->family = family;
    store_address(out->address, parsed, family);
    maximum = family == TSC_AF_IPV4 ? 32 : 128;
    bits = maximum;
    if (slash) {
        const char *p = slash + 1;
        const char *start = p;
        bits = 0;
        while (p < end && *p >= '0' && *p <= '9') {
            bits = bits * 10 + (unsigned)(*p++ - '0');
            if (bits > maximum) return TSC_ERR_PROTOCOL;
        }
        if (p != end || p == start || (p - start > 1 && *start == '0'))
            return TSC_ERR_PROTOCOL;
    }
    out->bits = (uint8_t)bits;
    return TSC_OK;
}

/* Only semantically empty legacy/capability fields are accepted. */
static int empty_array(policy_reader *r)
{
    if (literal_null(r)) return TSC_OK;
    if (!consume(r, '[')) return TSC_ERR_UNSUPPORTED;
    return consume(r, ']') ? TSC_OK : TSC_ERR_UNSUPPORTED;
}

static int sources(policy_reader *r, tsc_policy_rule *rule)
{
    int result;
    if (literal_null(r)) return TSC_OK;
    if (!consume(r, '[')) return TSC_ERR_PROTOCOL;
    if (consume(r, ']')) return TSC_OK;
    do {
        char text[128];
        if (rule->source_count == TSC_MAX_FILTER_SOURCES) return TSC_ERR_SPACE;
        result = string(r, text, sizeof(text));
        if (result != TSC_OK) return result;
        result = prefix(text, &rule->sources[rule->source_count]);
        if (result != TSC_OK) return result;
        rule->source_count++;
        if (consume(r, ']')) return TSC_OK;
    } while (consume(r, ','));
    return TSC_ERR_PROTOCOL;
}

static int ports(policy_reader *r, tsc_policy_destination *destination)
{
    unsigned fields = 0;
    if (!consume(r, '{') || consume(r, '}')) return TSC_ERR_PROTOCOL;
    do {
        char key[16];
        unsigned value;
        unsigned field;
        int result = string(r, key, sizeof(key));
        if (result != TSC_OK) return result;
        if (!consume(r, ':')) return TSC_ERR_PROTOCOL;
        if (strcmp(key, "First") == 0) field = 1;
        else if (strcmp(key, "Last") == 0) field = 2;
        else return TSC_ERR_UNSUPPORTED;
        if (fields & field) return TSC_ERR_PROTOCOL;
        fields |= field;
        result = number(r, 65535, &value);
        if (result != TSC_OK) return result;
        if (field == 1) destination->first_port = (uint16_t)value;
        else destination->last_port = (uint16_t)value;
        if (consume(r, '}')) {
            if (fields != 3 || destination->first_port > destination->last_port)
                return TSC_ERR_PROTOCOL;
            return TSC_OK;
        }
    } while (consume(r, ','));
    return TSC_ERR_PROTOCOL;
}

static int destination(policy_reader *r, tsc_policy_destination *out)
{
    unsigned fields = 0;
    if (!consume(r, '{') || consume(r, '}')) return TSC_ERR_PROTOCOL;
    do {
        char key[16];
        unsigned field;
        int result = string(r, key, sizeof(key));
        if (result != TSC_OK) return result;
        if (!consume(r, ':')) return TSC_ERR_PROTOCOL;
        if (strcmp(key, "IP") == 0) field = 1;
        else if (strcmp(key, "Ports") == 0) field = 2;
        else if (strcmp(key, "Bits") == 0) field = 4;
        else return TSC_ERR_UNSUPPORTED;
        if (fields & field) return TSC_ERR_PROTOCOL;
        fields |= field;
        if (field == 1) {
            char text[128];
            result = string(r, text, sizeof(text));
            if (result == TSC_OK) result = prefix(text, &out->prefix);
        } else if (field == 2) result = ports(r, out);
        else result = literal_null(r) ? TSC_OK : TSC_ERR_UNSUPPORTED;
        if (result != TSC_OK) return result;
        if (consume(r, '}')) return (fields & 3) == 3 ? TSC_OK : TSC_ERR_PROTOCOL;
    } while (consume(r, ','));
    return TSC_ERR_PROTOCOL;
}

static int destinations(policy_reader *r, tsc_policy_rule *rule)
{
    int result;
    if (literal_null(r)) return TSC_OK;
    if (!consume(r, '[')) return TSC_ERR_PROTOCOL;
    if (consume(r, ']')) return TSC_OK;
    do {
        if (rule->destination_count == TSC_MAX_FILTER_DESTINATIONS)
            return TSC_ERR_SPACE;
        result = destination(r, &rule->destinations[rule->destination_count]);
        if (result != TSC_OK) return result;
        rule->destination_count++;
        if (consume(r, ']')) return TSC_OK;
    } while (consume(r, ','));
    return TSC_ERR_PROTOCOL;
}

static void default_protocols(tsc_policy_rule *rule)
{
    rule->protocols[1 / 8] |= (uint8_t)(1u << (1 % 8));
    rule->protocols[6 / 8] |= (uint8_t)(1u << (6 % 8));
    rule->protocols[17 / 8] |= (uint8_t)(1u << (17 % 8));
    rule->protocols[58 / 8] |= (uint8_t)(1u << (58 % 8));
}

static int protocols(policy_reader *r, tsc_policy_rule *rule)
{
    if (literal_null(r)) {
        default_protocols(rule);
        return TSC_OK;
    }
    if (!consume(r, '[')) return TSC_ERR_PROTOCOL;
    if (consume(r, ']')) {
        default_protocols(rule);
        return TSC_OK;
    }
    do {
        unsigned value;
        int result = number(r, 255, &value);
        if (result != TSC_OK) return result;
        rule->protocols[value / 8] |= (uint8_t)(1u << (value % 8));
        if (consume(r, ']')) return TSC_OK;
    } while (consume(r, ','));
    return TSC_ERR_PROTOCOL;
}

static int rule(policy_reader *r, tsc_policy_rule *out)
{
    unsigned fields = 0;
    if (!consume(r, '{')) return TSC_ERR_PROTOCOL;
    if (consume(r, '}')) return TSC_OK; /* empty rule grants nothing */
    do {
        char key[24];
        unsigned field;
        int result = string(r, key, sizeof(key));
        if (result != TSC_OK) return result;
        if (!consume(r, ':')) return TSC_ERR_PROTOCOL;
        if (strcmp(key, "SrcIPs") == 0) field = 1;
        else if (strcmp(key, "DstPorts") == 0) field = 2;
        else if (strcmp(key, "IPProto") == 0) field = 4;
        else if (strcmp(key, "SrcBits") == 0) field = 8;
        else if (strcmp(key, "CapGrant") == 0) field = 16;
        else return TSC_ERR_UNSUPPORTED;
        if (fields & field) return TSC_ERR_PROTOCOL;
        fields |= field;
        if (field == 1) result = sources(r, out);
        else if (field == 2) result = destinations(r, out);
        else if (field == 4) result = protocols(r, out);
        else result = empty_array(r);
        if (result != TSC_OK) return result;
        if (consume(r, '}')) {
            if (!(fields & 4)) default_protocols(out);
            return TSC_OK;
        }
    } while (consume(r, ','));
    return TSC_ERR_PROTOCOL;
}

int tsc_policy_append_json(tsc_policy *policy, const uint8_t *json, size_t length)
{
    policy_reader reader;
    int result = TSC_OK;
    if (!policy) return TSC_ERR_ARGUMENT;
    if (!json || policy->rule_count > TSC_MAX_FILTER_RULES) {
        memset(policy, 0, sizeof(*policy));
        return TSC_ERR_ARGUMENT;
    }
    reader.data = json;
    reader.length = length;
    reader.position = 0;
    if (!literal_null(&reader)) {
        if (!consume(&reader, '[')) result = TSC_ERR_PROTOCOL;
        else if (!consume(&reader, ']')) {
            do {
                if (policy->rule_count == TSC_MAX_FILTER_RULES) {
                    result = TSC_ERR_SPACE;
                    break;
                }
                memset(&policy->rules[policy->rule_count], 0,
                       sizeof(policy->rules[policy->rule_count]));
                result = rule(&reader, &policy->rules[policy->rule_count]);
                if (result != TSC_OK) break;
                policy->rule_count++;
                if (consume(&reader, ']')) break;
                if (!consume(&reader, ',')) {
                    result = TSC_ERR_PROTOCOL;
                    break;
                }
            } while (1);
        }
    }
    whitespace(&reader);
    if (result == TSC_OK && reader.position != length) result = TSC_ERR_PROTOCOL;
    if (result != TSC_OK) memset(policy, 0, sizeof(*policy));
    return result;
}

int tsc_policy_parse_json(tsc_policy *policy, const uint8_t *json, size_t length)
{
    if (!policy) return TSC_ERR_ARGUMENT;
    memset(policy, 0, sizeof(*policy));
    return tsc_policy_append_json(policy, json, length);
}

static int prefix_matches(const tsc_policy_prefix *p, unsigned family,
                          const uint8_t *address)
{
    unsigned whole;
    unsigned remainder;
    uint8_t mask;
    if (p->family == 0) return 1;
    if (p->family != family || p->bits > (family == 4 ? 32u : 128u)) return 0;
    if (p->is_range) {
        size_t length = family == TSC_AF_IPV4 ? 4u : 16u;
        return memcmp(address, p->address, length) >= 0 &&
               memcmp(address, p->end_address, length) <= 0;
    }
    whole = p->bits / 8;
    remainder = p->bits % 8;
    if (memcmp(p->address, address, whole) != 0) return 0;
    if (!remainder) return 1;
    mask = (uint8_t)(0xffu << (8 - remainder));
    return (p->address[whole] & mask) == (address[whole] & mask);
}

int tsc_policy_allows(const tsc_policy *policy, unsigned ip_version,
                      const uint8_t *src, const uint8_t *dst,
                      uint8_t ip_protocol, uint16_t destination_port)
{
    size_t i;
    if (!policy || !src || !dst || policy->rule_count > TSC_MAX_FILTER_RULES)
        return 0;
    if (ip_version != TSC_AF_IPV4 && ip_version != TSC_AF_IPV6) return 0;
#if !TSC_ENABLE_IPV6
    if (ip_version == TSC_AF_IPV6) return 0;
#endif
    for (i = 0; i < policy->rule_count; i++) {
        const tsc_policy_rule *r = &policy->rules[i];
        size_t s;
        size_t d;
        int source_matches = 0;
        if (r->source_count > TSC_MAX_FILTER_SOURCES ||
            r->destination_count > TSC_MAX_FILTER_DESTINATIONS) return 0;
        if (!(r->protocols[ip_protocol / 8] & (1u << (ip_protocol % 8))))
            continue;
        for (s = 0; s < r->source_count; s++)
            if (prefix_matches(&r->sources[s], ip_version, src)) {
                source_matches = 1;
                break;
            }
        if (!source_matches) continue;
        for (d = 0; d < r->destination_count; d++) {
            const tsc_policy_destination *target = &r->destinations[d];
            if (!prefix_matches(&target->prefix, ip_version, dst)) continue;
            if (target->first_port > target->last_port) continue;
            if (ip_protocol == 1 || ip_protocol == 58) return 1;
            if (ip_protocol == 6 || ip_protocol == 17 || ip_protocol == 132) {
                if (destination_port >= target->first_port &&
                    destination_port <= target->last_port) return 1;
            } else if (target->first_port == 0 && target->last_port == 65535)
                return 1;
        }
    }
    return 0;
}
