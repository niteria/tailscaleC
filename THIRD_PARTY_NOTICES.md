# Third-party notices

Project-original code and subsequent original contributions are dedicated to
the public domain under [CC0 1.0 Universal](LICENSE), at Eryk Wieliczko's request;
see [credits and provenance](CREDITS.md). Bundled and derived third-party code
retains the applicable upstream license and copyright notices.

| Component | Origin | License / location |
| --- | --- | --- |
| WireGuard protocol and BLAKE2s/HChaCha20 helpers | wireguard-lwIP, via TailTiny | BSD-3-Clause; `third_party/wireguard/LICENSE` and source notices |
| Noise/HTTP2 control transport adaptations | MicroLink / TailTiny | MIT; complete notices in `src/control/noise.c` and `src/control/h2.c` |
| NaCl box implementation | MicroLink / TailTiny, with source-level primitive notices | MIT and retained source notices; `src/discovery/LICENSE.tailtiny` |
| Optional application TCP stack | lwIP 2.2.1 | BSD-3-Clause; `src/tcp/lwip/LICENSE` and per-file notices |

The selected lwIP sources are namespaced to coexist with ESP-IDF's separate
network stack. `src/tcp/vendor.py` records the upstream revision and reproduces
the import; `src/tcp/README.md` describes the modifications.

POSIX builds use the system OpenSSL provider by default when crypto/TLS is
enabled; its license is supplied with that dependency. The portable mbedTLS
provider uses an application-supplied mbedTLS dependency with its own license.
ESP32 builds use ESP-IDF's mbedTLS provider and other SDK components, whose
licenses remain with the SDK.

Optional integration tests download pinned upstream Go WireGuard/Tailscale and
Headscale test dependencies. Their modules and images retain their own licenses;
they are not linked into the C library.
