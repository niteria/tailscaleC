# tailscaleC

An embeddable C11 Tailscale protocol library for Linux/POSIX and ESP32/ESP-IDF.
Your program owns its identity, network connection and event loop. There is no
Go runtime, separate `tailscaled` process, TUN device or root requirement.

The library implements authenticated coordination, WireGuard transport,
application UDP, optional application TCP, peer discovery, STUN and a DERP
protocol engine. Compile-time switches remove optional modules, and explicit
capacities bound protocol storage. This is a new implementation with substantial
automated testing, not an independently audited replacement for the full
Tailscale client.

## Credits

The original version was provided by **Eryk Wieliczko
([@erykwieliczko](https://github.com/erykwieliczko))** to Bartosz Nitka
([@niteria](https://github.com/niteria)) as **public domain**. Thank you, Eryk!
See [credits and provenance](CREDITS.md) for the source import and subsequent
development.

## Configure the library

Select a header when configuring CMake, or edit [`config.h`](config.h):

```c
#define TSC_ENABLE_CLIENT 1
#define TSC_APP_UDP       1
#define TSC_APP_TCP       0
#define TSC_ENABLE_TLS   1
#define TSC_ENABLE_DISCO 1
#define TSC_ENABLE_DERP  0
#define TSC_ENABLE_STUN  0
#define TSC_ENABLE_IPV6  0

#define TSC_MAX_PEERS             8
#define TSC_MAX_UDP_PORTS         4
#define TSC_MAX_DATAGRAM_SIZE  1536
#define TSC_MTU               1280
#define TSC_CONTROL_RESPONSE_SIZE 32768
#define TSC_CONTROL_JSON_TOKENS    1024
```

This resembles [`profiles/client_lan.h`](profiles/client_lan.h): a client for
direct IPv4 UDP with authenticated discovery, without STUN or DERP. The
application advertises an underlying UDP endpoint reachable by its peers.

| Profile | Included functionality |
| --- | --- |
| [`profiles/full.h`](profiles/full.h) | Client, application UDP/TCP, TLS, DISCO, DERP, STUN, outer IPv6 |
| [`profiles/client_lan.h`](profiles/client_lan.h) | Client, application UDP, TLS, DISCO, direct IPv4 paths |
| [`profiles/embedded_udp.h`](profiles/embedded_udp.h) | LAN UDP client with 2 peers, smaller policy/map bounds and no application TCP |
| [`profiles/openbeken.h`](profiles/openbeken.h) | IPv4 native-stack port: streamed dynamic peer directory, bounded authenticated-session cache, compact endpoint storage |
| [`profiles/client_plain.h`](profiles/client_plain.h) | Small direct UDP client with Noise; no TLS, DISCO, STUN or DERP |
| [`profiles/tcp_only.h`](profiles/tcp_only.h) | Small IPv4 client with application TCP and TLS; application UDP/DISCO/STUN/DERP excluded |
| [`profiles/ipv4.h`](profiles/ipv4.h) | Underlying UDP adapter and IPv4 STUN; no tailnet client |
| [`profiles/minimal.h`](profiles/minimal.h) | Underlying IPv4 UDP adapter; no tailnet client or crypto/TLS dependency |

The repository's default `config.h` enables the full feature set.

`TSC_APP_TCP` controls TCP **inside** the tunnel. The coordinator still needs
an underlying TCP connection when application TCP is disabled. Enabling STUN
or DERP compiles those APIs; applications must drive STUN and supply the DERP
stream/relay integration. There is currently no automatic relay-server manager
or complete NAT traversal orchestration.

Use the same configuration for the library and every consumer: capacities and
feature flags change public structure layouts. The CMake target propagates the
selected header. For a direct compiler integration, consistently define
`TSC_CONFIG_HEADER` as a quoted header path, or consistently use the public
defaults in [`tailscalec/config.h`](include/tailscalec/config.h). Those fallback
defaults leave the tailnet client disabled; select your header explicitly when
embedding without CMake.

## Build on Linux / POSIX

Requirements: C11 compiler, CMake 3.20+, and OpenSSL 3 development headers for
the client/TLS profiles. Linux is verified; other POSIX systems need the BSD
socket, resolver, monotonic-clock and entropy interfaces used by the adapters.

```sh
cmake -S . -B build-full \
  -DCMAKE_BUILD_TYPE=Debug \
  -DTSC_CONFIG_HEADER="$PWD/profiles/full.h" \
  -DTSC_SANITIZERS=ON
cmake --build build-full --parallel
ctest --test-dir build-full --output-on-failure
```

Embed it in another CMake project:

```cmake
set(TSC_CONFIG_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/my_ts_config.h"
    CACHE FILEPATH "tailscaleC configuration")
add_subdirectory(path/to/tailscaleC)
target_link_libraries(my_program PRIVATE tailscalec::tailscalec)
```

For an installed package:

```sh
cmake --install build-full --prefix "$PWD/install"
```

Configure your consumer with `-DCMAKE_PREFIX_PATH=/path/to/install`, then use
`find_package(tailscalec CONFIG REQUIRED)` and link the same
`tailscalec::tailscalec` target. The package includes the exact configuration
used for its archive and propagates it to consumers.

The application UDP API operates inside the encrypted tailnet; `tsc_socket`
provides the separate underlying UDP transport. A typical setup is:

```c
#include <tailscalec/client.h>
#include <tailscalec/socket.h>

static tsc_client node;                 /* Large: keep off small task stacks. */
static tsc_udp app_port;
static tsc_socket outer = TSC_SOCKET_INITIALIZER;

static void receive(void *user, tsc_udp *socket, const tsc_endpoint *source,
                    const void *payload, size_t length)
{
    (void)user;
    /* Best-effort echo. TSC_AGAIN requires a later retry if delivery matters. */
    (void)tsc_udp_send(socket, source, payload, length);
}

/* identity is securely generated once, then restored from private storage.
 * advertised is this node's reachable UNDERLYING IPv4 address and UDP port. */
int join_echo(const tsc_identity *identity, const tsc_endpoint *advertised,
              const char *control_url, const char *auth_key)
{
    tsc_endpoint bind = { .family = TSC_AF_IPV4, .port = advertised->port };
    int rc = tsc_socket_open(&outer, &bind);
    if (rc != TSC_OK) return rc;
    tsc_client_config config = {
        .control_url = control_url, .auth_key = auth_key,
        .hostname = "my-c-program", .identity = identity,
        .platform = tsc_socket_platform(&outer),
        .tai64n_now = tsc_socket_tai64n_now,
        .endpoints = advertised, .endpoint_count = 1,
        .control_timeout_ms = 10000,
    };
    rc = tsc_client_init(&node, &config);
    if (rc == TSC_OK) rc = tsc_client_join(&node);
    if (rc == TSC_OK) rc = tsc_udp_open(&node, &app_port, 12345, receive, NULL);
    if (rc != TSC_OK) {
        tsc_client_close(&node);
        tsc_socket_close(&outer);
    }
    return rc;
}
```

After setup, call `tsc_client_poll(&node)` frequently from your event loop.
In the same task's control-maintenance step, call
`tsc_client_maintain(&node, 5000)` regularly to refresh maps once they reach five
seconds old. `tsc_client_refresh_map(&node)` forces an immediate refresh.
Control I/O can block when a refresh is due; packet polling is nonblocking.
Known local/peer key expiry is enforced on packet paths even between refreshes.
Expiry timers require elapsed time to include suspend; an adapter whose clock
pauses must refresh the authenticated map before resuming traffic.
Close the client and outer socket on shutdown. Configuration strings remain
borrowed until close. All calls on a client must be serialized on one task/thread.

The complete [`tailnet-udp`](examples/posix/tailnet_udp.c) example adds identity
persistence, error handling, sending, periodic map refresh and shutdown:

```sh
./build-full/tailnet-udp \
  --control-url https://headscale.example.com \
  --auth-key "$HEADSCALE_AUTH_KEY" \
  --state-file ./node.identity \
  --endpoint 192.168.1.50:41641 \
  --listen-port 12345 --echo --timeout 300
```

Use an endpoint actually reachable from your reference peer. A LAN endpoint
does not become internet-reachable by being advertised. Supply `--ca-file` for
a private HTTPS CA. HTTPS authenticates control-server key discovery; HTTP
without a pinned `--server-key` is only appropriate on a trusted test network.
The example requires owner-only permissions on its identity file. Omit the auth
key on later starts once that identity is registered.

For application TCP, see [`tailnet_tcp.c`](examples/posix/tailnet_tcp.c) and the
[TCP integration notes](src/tcp/README.md). Its bounded private lwIP instance is
independent of host sockets and ESP-IDF's native lwIP. Only one application TCP
stack may be initialized per process/firmware.

## ESP32 / ESP-IDF

The same protocol sources build as an ESP-IDF component. With ESP-IDF 5.x
activated, build the basic platform smoke test:

```sh
cd examples/esp32
idf.py set-target esp32s3
idf.py build
```

ESP32-S3 applications with PSRAM can opt into `TSC_TCP_EXTERNAL_RAM=1` in their
shared configuration and enable `CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY=y`.
This places the private TCP heap and packet pools in external BSS, preserving
internal RAM for task stacks and native peripheral/DMA allocations. It does not
change native ESP-IDF lwIP. The optional TCP sources use per-source private
include paths on the owning component, including with PlatformIO's ESP-IDF
frontend.

The control client accepts the initial peer list in either `Peers` (Headscale)
or `PeersChanged` (Tailscale) on each freshly opened map stream. The authenticated
map exposes bounded DERP regions/nodes and the local DNS name. Set
`tsc_client_config.preferred_derp` when an application manages a home relay;
legacy `DERP` magic endpoints and modern `HomeDERP` peer fields are decoded.
Applications still own TLS streams, relay reconnects and STUN advertisement.

For an existing project, add this repository's `components` directory to
`EXTRA_COMPONENT_DIRS` before including ESP-IDF's `project.cmake`, select
`TSC_CONFIG_HEADER`, and add `tailscalec` to your component's `REQUIRES`.

Your firmware supplies Wi-Fi/Ethernet initialization, persistent identity
storage, a correct clock and a secure entropy source. ESP-IDF's TLS certificate
bundle must be enabled, or explicit CA certificates must be supplied. WireGuard
timestamps must increase across reboots; a boot-only monotonic clock is not
sufficient. See the requirements in [`wireguard.h`](include/tailscalec/wireguard.h)
and [ESP-IDF's RNG documentation](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/random.html).

[Espressif's QEMU fork](https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32s3/api-guides/tools/qemu.html)
boots real ESP32-S3 Xtensa firmware. It emulates virtual Ethernet, not Wi-Fi.
The ordinary upstream QEMU executable may lack the `esp32s3` machine.

```sh
python "$IDF_PATH/tools/idf_tools.py" install qemu-xtensa
. "$IDF_PATH/export.sh"
python tools/check_qemu.py --build examples/esp32/build
```

The basic check verifies UDP loopback. The
[crypto firmware](examples/esp32_crypto/README.md) runs the provider's RFC
vectors, including the 1000-iteration X25519 vector. The
[TCP firmware](examples/esp32_tcp/README.md) runs portable TCP tests while
ESP-IDF's native UDP stack remains active. The
[ESP32 tailnet lab](examples/esp32_tailnet/README.md) boots real client firmware
against Headscale and an upstream Tailscale peer over virtual Ethernet:

```sh
python tools/check_esp32_tailnet.py --qemu /path/to/espressif/qemu-system-xtensa
```

This lab verifies binary UDP payloads, upstream-initiated UDP, a denied port,
malformed outer packets, map refresh, and identity restoration across two
emulated NVS boots. QEMU does not establish physical-board, Wi-Fi or hardware
entropy behavior.

## Memory and supported scope

Packet engines use caller-owned, bounded state. For example, the underlying
UDP adapter owns `TSC_MAX_DATAGRAM_SIZE + 1` receive bytes, the client owns
several packet buffers and per-peer WireGuard/discovery state, and the TCP
engine uses fixed pools and bounded connection buffers. Reducing peers, policy
rules, endpoints, ports and queue sizes changes real storage costs.

The control client's context size is reported by `tsc_control_memory_size()`.
The full profile retains bounded response bytes, JSON tokens, Noise record
buffers and current/staging maps. The small-memory OpenBeken profile streams
peer records into a dynamically sized, bounded directory, reuses one decoded
map and allocates temporary coordination scratch only during join/refresh.
Oversized maps, policies and frames return defined errors rather than silently
truncating access rules. Directory/history storage, scratch, OS sockets, TLS,
crypto providers and resolver calls have additional allocation/stack costs;
compile-time limits are not a complete firmware RAM guarantee.

Inspect object/context sizes for the configuration you actually built:

```sh
./build-full/memory-report
```

As a measured example, the ESP32-S3 UDP lab's constrained configuration used
about 9.6 KiB for its client object and 50 KiB for its control context, with
roughly 650 KiB of firmware and no PSRAM. See the
[example's measurements](examples/esp32_tailnet/README.md) for its configuration.
These figures exclude much of ESP-IDF's runtime RAM and are not the full
profile's budget.

Current boundaries:

- Application traffic is IPv4. Outer IPv6 and IPv6 STUN/policy parsing do not
  imply IPv6 application sockets.
- No MagicDNS resolver, exit node, subnet router, Tailscale SSH, Tailnet Lock,
  OS interface configuration or complete desktop-client feature set.
- Map updates are caller-scheduled full refreshes through `maintain` or
  `refresh_map`. A failed refresh disables application traffic until a
  successful refresh or rejoin; known key expiry is also enforced locally.
- Packet-filter support is deliberately bounded; unsupported constructs fail
  closed. See [`policy.h`](include/tailscalec/policy.h).
- DERP is a protocol engine with a caller-provided stream, deadlines and relay
  hooks. STUN probing and public endpoint advertisement are caller-managed.

## Testing

```sh
python3 tools/check_profiles.py
python3 tools/check_headscale_stun.py --probe build-full/stun-probe
python3 tools/check_headscale_client.py \
  --client build-full/tailnet-udp --tcp-client build-full/tailnet-tcp
```

CTest covers protocol vectors, malformed inputs, capacity limits, replay and
authentication rejection, policy enforcement and transport behavior. TCP tests
include bidirectional transfers with packet loss, duplication, reordering and
backpressure. Separate Go fixtures compare WireGuard, DISCO and DERP against
upstream implementations. The Headscale lab runs an isolated, pinned Headscale
server and upstream Tailscale peer; it uses no SaaS account or existing host
tailnet. Network labs require Docker and image downloads; the default CTest
suite does not. The `control_live` test is skipped unless its lab configuration
is provided explicitly.

See [architecture](docs/architecture.md),
[verification evidence and reproduction](docs/verification.md),
[interoperability commands and limits](tests/interop/README.md),
[fuzzing](tests/fuzz/README.md), and the TCP/ESP32 notes linked above for the
test boundaries. Automated tests and bounded fuzz campaigns do not replace a
security audit.

Eryk's original contribution was supplied as public domain; see
[credits and provenance](CREDITS.md). Subsequent original contributions are
[MIT licensed](LICENSE). Vendored code and derived protocol components retain
their upstream notices; see [third-party notices](THIRD_PARTY_NOTICES.md).
