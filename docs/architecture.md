# Architecture

An application supplies an existing network connection and drives the library
from one event loop. The library owns an embedded tailnet identity and protocol
state. Linux and ESP32 compile the same protocol sources; their clock, entropy,
crypto and underlying stream providers differ.

## Data flow

```text
application UDP API           optional private IPv4 TCP stack
         |                              |
         +-------- authenticated IPv4 --+
                         |
             client routing / policy / flows
                         |
                 WireGuard transport
                         |
       direct underlying UDP  /  caller-managed DERP

control registration + full maps --> peers, addresses, endpoint candidates,
                                     discovery keys and packet filters
```

`tsc_socket` is an **underlying network** UDP socket. `tsc_udp` is an
application port **inside the encrypted tailnet**. These are separate APIs;
the latter does not open an operating-system socket.

## Modules

| Module | Responsibilities and ownership |
| --- | --- |
| `client.h`, `src/client.c` | Caller-owned client, peer table, WireGuard/discovery integration, IPv4 source ownership, local delivery, policy and bounded reply-flow tracking |
| `control.h`, `src/control/` | Server key discovery, Noise/TS2021, sequential HTTP/2, registration, bounded JSON map parsing, peer/policy updates |
| `wireguard.h`, `src/wireguard/` | Allocation-free packet engine: handshake, session keys, cookie replies, replay protection, rekey/keepalive timers |
| `packet.h`, `src/packet.c` | IPv4/UDP framing, lengths and checksums |
| `policy.h`, `src/policy.c` | Fixed-capacity packet-filter rules; malformed, unsupported or oversized rules fail closed |
| `disco.h`, `src/discovery/` | Authenticated DISCO messages, bounded probes/candidates, direct-path validation and relay message hooks |
| `derp.h`, `src/derp/` | Incremental DERP v2 HTTP upgrade and frame engine; borrowed input events and bounded output backpressure |
| `stun.h`, `src/stun.c` | Transaction-matched STUN requests, IPv4/IPv6 mapped-address parsing, retries and finite deadlines |
| `tcp.h`, `src/tcp/` | Optional isolated, namespaced lwIP IPv4 TCP implementation with fixed pools and connection limits |
| `tsc.h`, `socket.h`, `platform/` | Nonblocking underlying UDP, clocks, entropy, resolver and platform sockets |
| `crypto.h`, `stream.h` | Provider-backed crypto and underlying TCP/TLS; OpenSSL on POSIX, mbedTLS on ESP-IDF |

The public `tsc_platform` callbacks support custom UDP, time and entropy adapters.
A port of the complete client also needs `tsc_crypto_*` and `tsc_stream_*`
providers. Supplying UDP callbacks alone does not port control transport or TLS.

## Client lifecycle and scheduling

1. Initialize networking, a secure RNG and persistent storage. Restore an
   existing identity or generate and securely store a new one. Establish a clock
   suitable for TLS and WireGuard timestamps.
2. Open an underlying UDP socket. Supply its platform callbacks and reachable
   advertised endpoints to `tsc_client_init()`. Init performs local setup only.
3. `tsc_client_join()` discovers/authenticates the coordinator key, registers the
   node and installs its initial map. Only a successful join enables traffic.
4. Open application UDP ports and/or connect the TCP stack's IP hooks. Call
   `tsc_client_poll()` frequently; call `tsc_tcp_poll()` at least every 250 ms
   when TCP is enabled. These calls process bounded input and timers without
   waiting for network traffic.
5. Call `tsc_client_maintain(client, max_age_ms)` regularly during a separate
   control-maintenance step on the same task. It refreshes the map when the
   specified age is reached. Use `tsc_client_refresh_map()` for an immediate
   refresh. Set new underlying endpoints after DHCP/STUN changes with
   `tsc_client_set_endpoints()` before refresh.
6. Close application state, the client and the underlying transport.

Join and refresh use synchronous control I/O with configured timeouts. Platform
DNS resolution may block outside the stream connection deadline. The map stream
stays open between refreshes to retain server-side online status; packet polling
does not consume an automatic stream of control changes. Refresh opens a new
full-map request on the encrypted connection. The maximum age parameter only
applies when maintenance is actually called; scheduling it remains the
application's responsibility.

Every call on a client/TCP instance must be serialized by the caller. There is
no implicit worker thread or task. Borrowed callback packets expire when their
callback returns. `TSC_AGAIN` means no progress or transient backpressure; callers
must retain application data and retry when its contract requires delivery.
Public structures permit static allocation, not direct field mutation or copying
live objects.

## Trust and packet acceptance

HTTPS verifies both the certificate chain and requested host identity. Without
an explicit CA, POSIX uses OpenSSL trust paths; ESP-IDF needs its enabled
certificate bundle. HTTP control transport still uses Noise, but a server key
discovered over HTTP requires a trusted network or an independently pinned key.

WireGuard receives authenticate before reporting inner plaintext or endpoint
rebinding. The client additionally checks the authenticated peer's source
address, local destination, packet framing/checksums and policy before invoking
an application handler. Outbound reply-flow tracking is bounded. Unsupported
packet-filter syntax, map capacity exhaustion and failed map updates disable
traffic until a valid map is installed; no fallback allows all traffic.

Packet polling, sends, direct receives and relay receives enforce known key
expiration locally using authenticated control time and the monotonic clock.
Expired peers lose their routes, WireGuard state and tracked flows. Expiration
of this node's key disables the whole application path. Control maintenance
cannot extend an expired key without a valid new coordinator map or rejoin.

WireGuard requires a timestamp strictly increasing across restarts. A secure
wall clock or persisted monotonic counter satisfies the interface; elapsed time
since boot does not. Monotonic time used for protocol timers is a separate
callback. The provided wall-clock adapter rejects clearly unsynchronized dates,
but the application still owns clock rollback prevention and entropy setup.
The timer clock must also count time spent suspended so key-expiry deadlines
remain valid. Linux prefers `CLOCK_BOOTTIME`; its `CLOCK_MONOTONIC` fallback
and other POSIX/MCU clocks may pause. With such an adapter, refresh the
authenticated map before allowing tailnet traffic after wake.

## Feature selection and memory

CMake evaluates the selected C configuration header and excludes disabled
protocol sources. Consumers receive that same header through the target's public
compile definitions. Headers and library objects compiled with different
settings have incompatible layouts and must not be mixed.

The principal storage controls are:

| Limit | Storage affected |
| --- | --- |
| `TSC_MAX_PEERS`, `TSC_CONTROL_MAX_ENDPOINTS` | Peer maps, WireGuard sessions, endpoint candidates and discovery state |
| `TSC_MAX_DATAGRAM_SIZE`, `TSC_MTU` | Underlying receive and client packet scratch buffers, maximum inner packet |
| `TSC_MAX_UDP_PORTS`, `TSC_MAX_FLOWS` | Application port table and bounded return-traffic tracking |
| `TSC_CONTROL_RESPONSE_SIZE`, `TSC_CONTROL_JSON_TOKENS` | Full response bytes and fixed JSON token table |
| `TSC_MAX_FILTER_RULES`, `TSC_MAX_FILTER_SOURCES`, `TSC_MAX_FILTER_DESTINATIONS` | Policy arrays in both installed and staging maps |
| `TSC_DISCO_MAX_PROBES` | Outstanding authenticated discovery transactions |
| `TSC_DERP_MAX_FRAME_SIZE`, `TSC_DERP_MAX_HTTP_HEADER` | DERP receive/transmit storage |
| `TSC_MAX_TCP_CONNECTIONS`, `TSC_MAX_TCP_LISTENERS`, `TSC_TCP_SEND_BUFFER`, `TSC_TCP_RECEIVE_BUFFER` | TCP handles, fixed arena/pools, receive rings and queued payload |
| `TSC_TCP_MSS` | TCP segment payload, default 536; can increase to tunnel MTU minus 40 with sufficient send/receive buffers |

The packet engines do not allocate an unbounded heap or queue. Control allocates
one fixed-size context containing current/staging maps, request/response buffers,
JSON tokens and fixed Noise/HTTP2 state. `tsc_control_memory_size()` reports that
context size; add `sizeof(tsc_client)`, owned socket/DERP/TCP objects, TCP private
pools, call stacks and provider costs when budgeting a program. JSON is bounded
but is not yet parsed directly from the stream into final state.

OpenSSL/mbedTLS, the platform stream adapter, OS/lwIP sockets and resolver have
their own heap/stack costs. A smaller feature header is therefore not by itself
a hard upper bound on total process or firmware RAM. Measure both code size and
peak heap/stack on the selected target and provider.

## Deliberate boundaries

The current application packet path and TCP stack handle IPv4 only. Outer IPv6,
STUN IPv6 decoding and IPv6 policy syntax are separate capabilities. IP
fragmentation/reassembly, automatic DERP selection/reconnection, complete NAT
orchestration, MagicDNS, subnet/exit routing, Tailscale SSH and Tailnet Lock are
outside the implemented application API.

WireGuard accepts responder cookie replies. Generating source-address-bound
responder cookie challenges is not exposed by the current packet API.

A LAN profile can remove STUN and DERP when peers have reachable direct
endpoints. It still needs coordinator registration, map updates, secure key
management and policy enforcement. DERP omission can prevent establishing a
path, not merely reduce throughput. The DERP engine accepts a caller-provided
authenticated stream and outputs encrypted packets through the client's relay
hooks; enabling the feature does not establish this stream automatically.
STUN must probe from the same underlying UDP socket whose mapped address is
advertised. Run it before the client's receive loop, or supply your own packet
demultiplexer; two independent pollers must not consume each other's datagrams.

The private TCP implementation supports one live stack per process/firmware.
It has its own namespaced lwIP symbols and fixed pools, leaving ESP-IDF's native
network stack separate. See [TCP bounds and integration](../src/tcp/README.md).

## Validation boundaries

CTest exercises deterministic protocol, malformed-input, resource-bound and
transport cases. Independent Go fixtures use upstream WireGuard, Tailscale
DISCO and DERP implementations. The private Headscale lab tests control and
encrypted application traffic against a separate upstream client without
modifying the developer's own Tailscale daemon or identity.

ESP32 tests compile the same core for Xtensa and boot the resulting ESP32-S3
firmware under Espressif QEMU. Virtual Ethernet tests exercise the guest's actual
ESP-IDF networking; they do not emulate Wi-Fi radio behavior or validate physical
entropy. Linux is the verified POSIX target. Headscale compatibility does not
establish compatibility with every SaaS feature or future protocol version.

See [the interoperability lab](../tests/interop/README.md),
[verification evidence](verification.md),
[fuzz campaigns](../tests/fuzz/README.md), and
[ESP32 crypto vectors](../examples/esp32_crypto/README.md) for reproducible
commands, requirements and the specific scope of each check.
