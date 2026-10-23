# Verification

These checks were run during implementation. They exercise different layers;
passing a protocol fixture is not a claim that every feature works together on
every platform. Linux is the verified POSIX target. ESP32-S3 tests boot actual
Xtensa firmware under Espressif QEMU, not a host build with MCU functions mocked.

## Confirmed evidence

| Check | Evidence |
| --- | --- |
| Linux Clang, ASan + UBSan | Full configuration: 16 enabled CTest cases passed; the separate opt-in `control_live` case was skipped |
| Seven compile-time profiles, ASan + UBSan | Applicable tests passed in every profile; archive symbol audits confirmed module exclusion and symbol namespacing |
| Installed CMake package | A separate `find_package` consumer built and passed SHA-256 plus configuration/ABI checks against the installed full library |
| Six libFuzzer targets, ASan + UBSan | All completed successfully with 30 seconds per target: 29,347,359 executed inputs in total |
| WireGuard against unmodified upstream wireguard-go | Four cases: C/reference initiates, with/without a preshared key; 32 payloads each direction per case, 256 total |
| DISCO against upstream Go messages and NaCl | 200 ping/pong exchanges in each direction; authenticated node/endpoint binding and replay rejection |
| DERP against upstream Go server and peer | HTTP upgrade, authenticated login, ping/pong, 240 request/reply relays at sizes 0/1/7/40/148/1536 bytes |
| Headscale 0.29.5 + upstream Tailscale 1.98.9 | Real TS2021 registration/maps; encrypted UDP payloads of 1/32/512/1200 bytes; TCP streams of 1/32789 bytes; inbound UDP/TCP after restarting the C process with persisted identity |
| Control and policy failures | Invalid authentication rejected; real denied services receive no application data; malformed outer packets do not interrupt valid traffic; a real local key-expiry deadline stops traffic with Headscale offline |
| ESP32-S3 crypto | Shared RFC vectors on mbedTLS, including RFC 7748's 1000-iteration X25519 vector; guest reported `TSC_QEMU_CRYPTO_OK` |
| ESP32 full component build | All enabled protocol modules compiled for Xtensa; the platform UDP loopback firmware also passed in QEMU |
| ESP32-S3 private TCP/native lwIP coexistence | Shared portable TCP tests, sequence wrap, FIN/TIME_WAIT and callback/resource bounds; native UDP loopback before and after; guest reported `TSC_QEMU_TCP_OK` |
| ESP32-S3 full UDP client | Real Headscale/upstream-Tailscale traffic over virtual Ethernet; exact binary payloads, inbound UDP, denied port, malformed packets and map refresh; two boots restore NVS identity without a second auth key or duplicate node |
| Physical ESP32-S3 / real Tailscale coordinator (2026-10-18) | Epson L310 firmware enrolled a stable identity, decoded the real 27-peer map, and served IPP over WireGuard/private TCP on Wi-Fi. An A4 color poster completed through forced DERP with no direct UDP and zero USB errors; its appearance was user-confirmed. A bounded application relay queue, TLS reconnect/failover and STUN endpoint advertisement are supplied by the printer application, not automatically by the library. |

The ordinary TCP suite also uses independent packet encoding and two processes
exchanging 32,789 bytes in both directions with loss, duplication, reordering
and bounded-buffer backpressure. The MCU fixture runs the portable cases; its
own lab does not claim TCP-over-WireGuard interoperability with the upstream
peer.

The bounded fuzz run recorded these counts in `build-fuzz/summary.json`:

| Target | Executed inputs |
| --- | ---: |
| IPv4/UDP packet handling | 10,177,609 |
| STUN | 10,610,625 |
| Control JSON | 5,566,221 |
| Packet policy | 535,145 |
| DERP | 528,023 |
| DISCO | 1,929,736 |

## Reproduce on Linux

From the repository root, with Clang, CMake, OpenSSL 3 development files and
Python available:

```sh
cmake -S . -B build-clang \
  -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug \
  -DTSC_CONFIG_HEADER="$PWD/profiles/full.h" -DTSC_SANITIZERS=ON
cmake --build build-clang --parallel 4
ctest --test-dir build-clang --output-on-failure

python3 tools/check_profiles.py --sanitizers
```

The profile runner builds the seven configurations, runs their applicable
tests, reports object/context storage, and inspects archive symbols to check
that disabled modules have no exported implementation. Add `--sanitizers` to
apply ASan/UBSan to the profile builds as well.

The smaller independent peers require Go and initial module downloads:

```sh
(cd tests/wireguard_interop && go run . -peer ../../build-clang/test-wireguard-peer)
python3 tests/interop/disco/run.py --client build-clang/test-disco-live
python3 tests/interop/derp/run.py --client build-clang/test-derp-live
```

The integrated lab requires Linux Docker and the pinned container images:

```sh
python3 tools/check_headscale_stun.py --probe build-clang/stun-probe
python3 tools/check_headscale_client.py \
  --client build-clang/tailnet-udp --tcp-client build-clang/tailnet-tcp
```

See the [lab documentation](../tests/interop/README.md) for isolation, the
reference client's explicit UDP return policy, diagnostic files and exact
assertions. The lab leaves the developer's own Tailscale identity and daemon
alone. Its HTTP coordinator uses authenticated Noise on a disposable private
bridge; this does not prove an integrated HTTPS coordination session.

For bounded coverage-guided parser/authentication fuzzing with ASan/UBSan:

```sh
python3 tools/check_fuzz.py --seconds 30 --jobs 2
```

This requires Clang's libFuzzer runtime. Per-target logs, crash artifacts and
`summary.json` are retained under `build-fuzz/`; each target has its own
30-second campaign rather than a shared total budget. See the
[fuzzing notes](../tests/fuzz/README.md) for reproducible seed and run-count
options.

## Reproduce ESP32-S3 checks

Activate ESP-IDF 5.x and its Python environment. Install Espressif's QEMU fork
with an `esp32s3` machine, then use the build/run commands in:

- [Platform UDP smoke test](../README.md#esp32--esp-idf).
- [Crypto vectors](../examples/esp32_crypto/README.md).
- [Private TCP and native stack coexistence](../examples/esp32_tcp/README.md).
- [Headscale and upstream client over virtual Ethernet](../examples/esp32_tailnet/README.md).

Runners keep serial logs in their selected build directories and require
explicit guest success markers. The full tailnet runner additionally checks
bytes observed by the real upstream application, coordinator node counts,
stable address and NVS restoration. It builds and boots the firmware itself;
the other runners expect their example firmware to be built first.

## Limits of this evidence

No physical ESP32 board, Wi-Fi radio or hardware entropy quality was tested.
QEMU uses virtual Ethernet and the fixture's clock/entropy setup. It does not
establish compatibility with every ESP32 variant, non-Linux POSIX host or
Tailscale SaaS feature.

Application IPv6, fragmented IP traffic, automatic DERP management and complete
NAT traversal orchestration are not implemented. Independent DERP/STUN protocol
checks do not establish relay fallback or NAT traversal for the integrated
client. The integrated network labs use direct IPv4 paths.

Control maps are bounded full responses with a token table, not fully streaming
JSON-to-peer processing. The application must schedule control maintenance.
TLS/crypto/OS allocations remain outside packet-state limits. Resource figures
and QEMU free-heap values are configuration-specific, not a universal RAM cap.

The [fuzzing workflow](../tests/fuzz/README.md) covers six parser/authentication
boundaries. Bounded fuzzing, sanitizers, reference interoperability and extensive
tests reduce risk; none is a security audit or proof that all possible inputs
are safe.
