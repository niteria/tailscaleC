/* White-box tests exercise the complete bounded control map decoder and its
 * transactional failure behavior without a live coordinator. */
#include "../src/control/control.c"
#include <assert.h>

#define KEY1 "1111111111111111111111111111111111111111111111111111111111111111"
#define KEY2 "2222222222222222222222222222222222222222222222222222222222222222"
#define SELF                                                                   \
  "\"Node\":{\"ID\":1,\"Key\":\"nodekey:" KEY1                                 \
  "\",\"Addresses\":[\"100.64.0.10/32\",\"fd7a::a/"                            \
  "128\"],\"MachineAuthorized\":true}"
#define PEER                                                                   \
  "{\"ID\":2,\"Key\":\"nodekey:" KEY2 "\",\"DiscoKey\":\"discokey:" KEY2       \
  "\",\"Addresses\":[\"100.64.0.20/"                                           \
  "32\"],\"Endpoints\":[\"127.0.0.1:1234\",\"[::1]:1234\"],\"Name\":\"peer."   \
  "test.\",\"HomeDERP\":1}"
#define ALLOW                                                                  \
  "[{\"SrcIPs\":[\"100.64.0.20/32\"],\"DstPorts\":[{\"IP\":\"100.64.0.10/"     \
  "32\",\"Ports\":{\"First\":32123,\"Last\":32123}}],\"IPProto\":[17]}]"
static control_impl c;
static void reset(void) {
  memset(&c, 0, sizeof(c));
  memset(c.node_public, 0x11, 32);
}
static int decode(const char *json) {
  return parse_map(&c, json, strlen(json));
}

static void valid_maps(void) {
  reset();
  assert(decode("{" SELF ",\"PeersChanged\":[" PEER "]}") == TSC_OK);
  assert(c.map.peer_count == 1 && c.map.peers[0].home_derp == 1);
  assert(decode("{" SELF ",\"PeersChanged\":[]}") == TSC_OK);
  assert(c.map.peer_count == 0);
  reset();
  assert(decode("{" SELF ",\"Peers\":[" PEER "],\"PacketFilter\":" ALLOW "}") ==
         TSC_OK);
  assert(c.map.has_ipv4 && c.map.ipv4[3] == 10 && c.map.has_ipv6 &&
         c.map.node_id == 1);
  assert(c.map.peer_count == 1 && c.map.peers[0].ipv4[3] == 20 &&
         c.map.peers[0].home_derp == 1);
#if TSC_ENABLE_IPV6
  assert(c.map.peers[0].endpoint_count == 2);
#else
  assert(c.map.peers[0].endpoint_count == 1);
#endif
  uint8_t src[] = {100, 64, 0, 20}, dst[] = {100, 64, 0, 10};
  assert(tsc_policy_allows(&c.map.policy, 4, src, dst, 17, 32123));
  assert(!tsc_policy_allows(&c.map.policy, 4, src, dst, 17, 32124));
  assert(!tsc_policy_allows(&c.map.policy, 4, src, dst, 6, 32123));
  assert(c.map.generation == 1);
  assert(decode("{" SELF ",\"Peers\":[],\"PacketFilters\":{\"base\":" ALLOW
                "}}") == TSC_OK);
  assert(c.map.peer_count == 0 && c.map.policy.rule_count == 1 &&
         c.map.generation == 2);
  assert(decode("{" SELF ",\"PacketFilters\":{\"first\":" ALLOW
                ",\"second\":" ALLOW "}}") == TSC_OK);
  assert(c.map.policy.rule_count == 2);
  assert(decode("{" SELF ",\"PacketFilter\":" ALLOW
                ",\"PacketFilters\":{\"*\":null}}") == TSC_OK);
  assert(c.map.policy.rule_count == 0);
  assert(decode("{" SELF ",\"PacketFilter\":" ALLOW
                ",\"PacketFilters\":{\"base\":null}}") == TSC_OK);
  assert(c.map.policy.rule_count == 0);
  assert(decode("{" SELF ",\"Peers\":[{\"ID\":2,\"Expired\":true}]}") ==
             TSC_OK &&
         c.map.peer_count == 0);
  assert(
      decode("{" SELF ",\"Peers\":[{\"ID\":2,\"MachineAuthorized\":false}]}") ==
          TSC_OK &&
      c.map.peer_count == 0);
  assert(decode("{" SELF "}") == TSC_OK && c.map.policy.rule_count == 0);
}
static void fail_closed(void) {
  const char *bad[] = {
      "[]",
      "{}",
      "{\"Node\":null}",
      "{" SELF ",\"Peers\":[" PEER "," PEER "]}",
      "{" SELF ",\"Peers\":[{\"ID\":2,\"Key\":\"nodekey:" KEY2
      "\",\"Addresses\":[\"10.0.0.0/24\"]}]}",
      "{\"Node\":{\"ID\":1,\"Key\":\"nodekey:" KEY2
      "\",\"Addresses\":[\"100.64.0.10/32\"]}}",
      "{\"Node\":{\"ID\":1,\"Key\":\"nodekey:" KEY1
      "\",\"Addresses\":[\"100.64.0.10/32\"],\"MachineAuthorized\":false}}",
      "{\"Node\":{\"ID\":1,\"Key\":\"nodekey:" KEY1
      "\",\"Addresses\":[\"100.64.0.10/32\"],\"Expired\":true}}",
      "{" SELF ",\"PacketFilter\":[{\"SrcIPs\":[\"cap:unknown\"]}]}",
      "{" SELF ",\"PacketFilters\":{\"*\":[]}}",
      "{" SELF
      ",\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"UnknownAllow\":true}]}"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    reset();
    assert(decode("{" SELF ",\"Peers\":[" PEER "],\"PacketFilter\":" ALLOW
                  "}") == TSC_OK);
    assert(decode(bad[i]) < 0);
    assert(c.map.peer_count == 0 && c.map.policy.rule_count == 0 && c.error[0]);
  }
  reset();
  char *json =
      malloc((TSC_MAX_PEERS + 1) * (sizeof(PEER) + 2) + sizeof(SELF) + 100);
  assert(json);
  strcpy(json, "{" SELF ",\"Peers\":[");
  for (unsigned i = 0; i < TSC_MAX_PEERS + 1; i++) {
    char peer[256];
    if (i)
      strcat(json, ",");
    snprintf(peer, sizeof(peer),
             "{\"ID\":%u,\"Key\":\"nodekey:%064x\",\"Addresses\":[\"100.64.%u.%"
             "u/32\"]}",
             i + 2, i + 2, 1 + i / 250, i % 250 + 1);
    strcat(json, peer);
  }
  strcat(json, "]}");
  assert(decode(json) == TSC_ERR_SPACE);
  free(json);
}
static void tailscale_relays(void) {
  reset();
  assert(decode("{\"Node\":{\"ID\":1,\"Key\":\"nodekey:" KEY1
                "\",\"Addresses\":[\"100.64.0.10/32\"],"
                "\"Name\":\"l310.example.ts.net.\",\"DERP\":\"127.3.3.40:22\"}}") == TSC_OK);
  assert(c.map.home_derp == 22 && !strcmp(c.map.name, "l310.example.ts.net."));
  assert(decode("{\"Node\":{\"ID\":1,\"Key\":\"nodekey:" KEY1
                "\",\"Addresses\":[\"100.64.0.10/32\"],"
                "\"DERP\":\"192.0.2.1:22\"}}") == TSC_ERR_PROTOCOL);
#if TSC_ENABLE_DERP
  reset();
  assert(decode("{" SELF ",\"DERPMap\":{\"Regions\":{\"22\":{\"RegionID\":22,"
                "\"Nodes\":[{\"HostName\":\"derp22.example.com\",\"IPv4\":\"192.0.2.22\"},"
                "{\"HostName\":\"stun.example.com\",\"STUNOnly\":true,\"STUNPort\":3479},"
                "{\"HostName\":\"relay.example.com\",\"IPv4\":\"none\",\"DERPPort\":8443,\"STUNPort\":-1}]}}}}") == TSC_OK);
  assert(c.map.derp_region_count == 1);
  const tsc_control_derp_region *region = &c.map.derp_regions[0];
  assert(region->id == 22 && region->node_count == 3);
  assert(region->nodes[0].has_ipv4 && region->nodes[0].ipv4[3] == 22 &&
         region->nodes[0].derp_port == 443 && region->nodes[0].stun_port == 3478);
  assert(region->nodes[1].stun_only && region->nodes[1].stun_port == 3479);
  assert(!region->nodes[2].has_ipv4 && region->nodes[2].derp_port == 8443 &&
         region->nodes[2].stun_port == 0);
  assert(decode("{" SELF ",\"DERPMap\":{\"Regions\":{\"22\":{\"RegionID\":22,"
                "\"Nodes\":[{\"HostName\":\"evil\\r\\nHost\"}]}}}}") == TSC_ERR_PROTOCOL);
  assert(decode("{" SELF ",\"DERPMap\":{\"Regions\":{\"22\":{\"RegionID\":22,"
                "\"Nodes\":[{\"HostName\":\"relay.example.com\",\"DERPPort\":65536}]}}}}") == TSC_ERR_PROTOCOL);
  assert(decode("{" SELF "}") == TSC_OK && c.map.derp_region_count == 0);
#endif
  reset(); c.config.preferred_derp = 22;
  char output[1024]; writer w = {output, sizeof(output), 0, 0}; output[0] = 0;
  hostinfo(&w, &c);
  assert(!w.error && strstr(output, "\"PreferredDERP\":22"));
}
static void addresses_and_url(void) {
  uint8_t out[16];
  unsigned family;
  const char *good[] = {
      "0.0.0.0",         "255.255.255.255", "::", "::1", "2001:db8::a",
      "1:2:3:4:5:6:7:8", "::ffff:192.0.2.1"};
  for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++)
    assert(tsc_control_ip_parse(good[i], out, &family) == TSC_OK);
  const char *bad[] = {"",         "1.2.3",           "1.2.3.256",
                       "1.2.3.4x", "1::2::3",         ":::1",
                       "1:",       "1:2:3:4:5:6:7",   "1:2:3:4:5:6:7:8:9",
                       "00001::",  "::ffff:999.2.3.4"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    assert(tsc_control_ip_parse(bad[i], out, &family) < 0);
  tsc_endpoint ep, again;
  char encoded[100];
  assert(tsc_control_endpoint_parse("[2001:db8::1]:1234", &ep) == TSC_OK);
  assert(tsc_control_endpoint_format(&ep, encoded, sizeof(encoded)) == TSC_OK);
  assert(tsc_control_endpoint_parse(encoded, &again) == TSC_OK &&
         again.family == ep.family && again.port == ep.port &&
         !memcmp(again.address, ep.address, 16));
  assert(tsc_control_endpoint_parse("1.2.3.4:0", &ep) < 0);
  assert(tsc_control_endpoint_parse("1.2.3.4:65536", &ep) < 0);
  reset();
  assert(url(&c, "https://example.org:8443/") == TSC_OK && c.port == 8443 &&
         c.tls && strcmp(c.host, "example.org") == 0);
  assert(url(&c, "http://[::1]:1234") == TSC_OK && c.port == 1234 && !c.tls &&
         strcmp(c.host, "::1") == 0);
  assert(url(&c, "http://bad\r\nInjected") == TSC_ERR_ARGUMENT);
  assert(url(&c, "https://user:pass@host") < 0);
  assert(url(&c, "https://example.org/path") < 0);
  assert(url(&c, "https://example.org:99999999999999999999999") < 0);
}

static uint64_t fake_now;
static uint64_t clock_now(void *user) {
  (void)user;
  return fake_now;
}
static const tsc_platform fake_platform = {.monotonic_ms = clock_now};
#define SELF_EXPIRY                                                            \
  "\"Node\":{\"ID\":1,\"Key\":\"nodekey:" KEY1                                 \
  "\",\"Addresses\":[\"100.64.0.10/"                                           \
  "32\"],\"KeyExpiry\":\"2026-01-01T00:00:05Z\"}"
#define PEER_EXPIRY                                                            \
  "{\"ID\":2,\"Key\":\"nodekey:" KEY2                                          \
  "\",\"Addresses\":[\"100.64.0.20/"                                           \
  "32\"],\"KeyExpiry\":\"2026-01-01T00:00:02Z\"}"
#define CONTROL_TIME "\"ControlTime\":\"2026-01-01T00:00:00Z\""
static void reset_clock(uint64_t start, uint64_t received) {
  reset();
  c.config.platform = &fake_platform;
  c.request_has_clock = 1;
  c.request_started_ms = start;
  fake_now = received;
}
static void expiry_and_maintenance(void) {
  tsc_control handle = {&c};
  reset_clock(1000, 1100);
  assert(decode("{" SELF_EXPIRY "," CONTROL_TIME ",\"Peers\":[" PEER_EXPIRY
                "],\"PacketFilter\":" ALLOW "}") == TSC_OK);
  assert(c.map.has_expiry && c.map.expires_at_ms == 6000);
  assert(c.map.peer_count == 1 && c.map.peers[0].has_expiry &&
         c.map.peers[0].expires_at_ms == 3000);
  uint64_t generation = c.map.generation;
  fake_now = 2999;
  assert(tsc_control_expire(&handle) == TSC_OK && c.map.peer_count == 1 &&
         c.map.generation == generation);
  fake_now = 3000;
  assert(tsc_control_expire(&handle) == TSC_OK && c.map.peer_count == 0 &&
         c.map.generation == generation + 1 && c.map.policy.rule_count == 1);
  assert(tsc_control_expire(&handle) == TSC_OK &&
         c.map.generation == generation + 1);
  fake_now = 5999;
  assert(tsc_control_expire(&handle) == TSC_OK);
  fake_now = 6000;
  assert(tsc_control_expire(&handle) == TSC_ERR_PROTOCOL &&
         c.map.policy.rule_count == 0 && !c.map_valid);
  assert(tsc_control_expire(&handle) == TSC_ERR_PROTOCOL);
  /* Request time anchors expiry before network delay, with both fractional
   * boundaries rounded conservatively. */
  reset_clock(1000, 1010);
  assert(decode("{\"Node\":{\"ID\":1,\"Key\":\"nodekey:" KEY1
                "\",\"Addresses\":[\"100.64.0.10/"
                "32\"],\"KeyExpiry\":\"2026-01-01T00:00:00.100999999Z\"},"
                "\"ControlTime\":\"2026-01-01T00:00:00.000000001Z\"}") ==
         TSC_OK);
  assert(c.map.expires_at_ms == 1099);
  fake_now = 1099;
  assert(tsc_control_expire(&handle) == TSC_ERR_PROTOCOL);
  reset_clock(1000, 7000);
  assert(decode("{" SELF_EXPIRY "," CONTROL_TIME "}") == TSC_ERR_PROTOCOL);
  reset_clock(1000, 4000);
  assert(decode("{" SELF "," CONTROL_TIME ",\"Peers\":[" PEER_EXPIRY "]}") ==
             TSC_OK &&
         c.map.peer_count == 0);
  reset_clock(1000, 1100);
  assert(decode("{" SELF_EXPIRY "}") == TSC_ERR_UNSUPPORTED);
  reset();
  assert(decode("{" SELF_EXPIRY "," CONTROL_TIME "}") == TSC_ERR_UNSUPPORTED);
  reset();
  assert(decode("{\"Node\":{\"ID\":1,\"Key\":\"nodekey:" KEY1
                "\",\"Addresses\":[\"100.64.0.10/"
                "32\"],\"KeyExpiry\":\"0001-01-01T00:00:00Z\"}}") == TSC_OK &&
         !c.map.has_expiry);
  assert(tsc_control_expire(&handle) == TSC_OK);
  assert(tsc_control_maintain(&handle, 1000) == TSC_ERR_UNSUPPORTED);
  reset_clock(1000, 1100);
  assert(decode("{" SELF "," CONTROL_TIME "}") == TSC_OK);
  c.connected = 1;
  generation = c.map.generation;
  assert(tsc_control_maintain(&handle, 1000) == TSC_OK &&
         c.map.generation == generation);
  assert(tsc_control_maintain(&handle, 0) == TSC_ERR_ARGUMENT);
  fake_now = 1099;
  assert(tsc_control_expire(&handle) == TSC_ERR_PROTOCOL);
  fake_now = 1200;
  assert(tsc_control_expire(&handle) == TSC_ERR_PROTOCOL);
  reset_clock(UINT64_MAX - 5, UINT64_MAX - 5);
  assert(decode("{" SELF_EXPIRY "," CONTROL_TIME "}") == TSC_ERR_PROTOCOL);
}
int main(void) {
  valid_maps();
  fail_closed();
  tailscale_relays();
  addresses_and_url();
  expiry_and_maintenance();
  puts("control map tests passed");
  return 0;
}
