# Live protocol interoperability

The tests here contact independent upstream implementations. Unit tests remain
available through `ctest`; these labs need additional tools and take longer.

## Headscale and the upstream Tailscale client

On a Linux host with Docker, Python 3, CMake, Ninja, a C compiler, and OpenSSL 3
development files:

```sh
cmake -S . -B build-client -G Ninja \
  -DTSC_CONFIG_HEADER="$PWD/profiles/client_lan.h" -DTSC_SANITIZERS=ON
cmake --build build-client
python3 tools/check_headscale_client.py --client build-client/tailnet-udp
```

To exercise the optional application TCP stack too:

```sh
cmake -S . -B build-full -G Ninja \
  -DTSC_CONFIG_HEADER="$PWD/profiles/full.h" -DTSC_SANITIZERS=ON
cmake --build build-full
python3 tools/check_headscale_client.py \
  --client build-full/tailnet-udp --tcp-client build-full/tailnet-tcp
```

Docker needs access to the pinned images. The coordinator is Headscale 0.29.5;
the independent peer is upstream Tailscale 1.98.9, pinned by immutable image
digest in the script. A `python:3.11-slim` container supplies ordinary UDP and
TCP echo services beside the upstream peer.

The script creates a private Docker bridge, disposable users, an expiring auth
key, and two nodes. The C application runs directly on the host. The upstream
client uses `--tun=userspace-networking`, with all Linux capabilities dropped.
The test uses no host TUN device, host networking, host daemon socket,
or persisted Tailscale identity. Docker manages the isolated bridge routes;
the host's Tailscale routes and identity are never changed. It removes its own containers and network in
`finally`, including after an interrupted or failed test.

Assertions include:

- Registration over the real TS2021 Noise control channel and coordinator map.
- Exact encrypted UDP request/reply payloads of 1, 32, 512, and 1200 bytes.
- Three restarts with unchanged private identity bytes and IPv4 address, without
  supplying an auth key again, and without duplicate coordinator nodes.
- Owner-only permissions on persisted identity files.
- Allowed UDP port 32123 and denied port 32124. Both services are listening, so
  lack of an application at the denied port cannot make the test pass.
- Valid traffic while forged, truncated, empty, and oversized outer datagrams
  arrive at the C node.
- Rejection of an invalid fresh-node authentication key.
- A real coordinator key-expiry deadline enforced locally after the coordinator
  is stopped, before another map refresh can occur.
- Upstream-initiated UDP after a C-node restart, authenticated DISCO ping, and
  upstream status confirmation of direct traffic in both directions.
- With `--tcp-client`: exact 1-byte and 32789-byte TCP stream echoes, denied TCP
  port 32124, and an upstream-initiated binary stream through a restarted C
  listener. This exceeds the configured TCP buffers and exercises partial I/O.

The upstream user's SOCKS5 proxy provides UDP ASSOCIATE and TCP CONNECT into its
userspace network stack. Its outbound UDP proxy traffic does not establish a
usable return entry in that client's packet filter in this setup. The fixture
therefore explicitly allows UDP return traffic to the reference node's
ephemeral ports, excluding 32124. That exception applies only to reference IPv4
100.64.0.1; it does not relax the C node's inbound service rules.

This is a direct IPv4 LAN lab. It does not validate public-service registration,
NAT traversal across routers, DERP fallback in the integrated client, TLS to the
coordinator, IPv6 application packets, or actual radio hardware. The coordinator
uses HTTP on the disposable bridge; Noise still encrypts the control protocol.
Use a verified HTTPS coordinator or a pinned coordinator key outside this lab.
The placeholder STUN-only DERP region satisfies Headscale's nonempty-map
requirement and deliberately contacts no external relay.

The UDP example accepts `--map-refresh SECONDS` (default 5). Zero disables
periodic map refresh for diagnostics; the expiry test uses this after its
initial map has captured a future coordinator deadline. Expiry still executes
locally on every poll. Applications must schedule regular map maintenance.

To repeat only TCP restart recovery and offline expiry, append
`--recovery-only` to the full-profile command.

For diagnostics, `--directory /path/to/private-lab` keeps local identity and
output files after cleanup. `--hold 300` prepares the lab for external tools for
five minutes and stores its credentials in `lab.json` with mode 0600. Treat this
as a dedicated test directory. The script does not print its auth key.

## Other independent protocol peers

- `headscale.yaml` and `tools/check_headscale_stun.py`: real embedded Headscale
  STUN with temporary TLS certificates. This test alone does not test joining.
- `disco/run.py`: upstream Go DISCO parser, marshaller and NaCl over real UDP.
- `derp/run.py`: upstream Go DERP server and reference peer.
- `../wireguard_interop/`: upstream wireguard-go handshakes and transport.

Each smaller fixture documents its own prerequisites. DERP's socket/TLS
transport is supplied by the embedding application.
