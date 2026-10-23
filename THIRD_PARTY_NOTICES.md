# Third-party notices

The project's original code is MIT licensed; see `LICENSE`. Bundled and derived
code retains the applicable upstream license and copyright notices.

| Component | Origin | License / location |
| --- | --- | --- |
| WireGuard protocol and BLAKE2s/HChaCha20 helpers | wireguard-lwIP, via TailTiny | BSD-3-Clause; `third_party/wireguard/LICENSE` and source notices |
| Noise/control transport adaptations | MicroLink / TailTiny | MIT; complete notice in `src/control/noise.c` |
| NaCl box implementation | MicroLink / TailTiny, with source-level primitive notices | MIT and retained source notices; `src/discovery/LICENSE.tailtiny` |
| Optional application TCP stack | lwIP 2.2.1 | BSD-3-Clause; `src/tcp/lwip/LICENSE` and per-file notices |

The selected lwIP sources are namespaced to coexist with ESP-IDF's separate
network stack. `src/tcp/vendor.py` records the upstream revision and reproduces
the import; `src/tcp/README.md` describes the modifications.

POSIX builds use the system OpenSSL provider when crypto/TLS is enabled; its
license is supplied with that dependency. ESP32 builds use ESP-IDF's mbedTLS
provider and other SDK components, whose licenses remain with the SDK.

Optional integration tests download pinned upstream Go WireGuard/Tailscale and
Headscale test dependencies. Their modules and images retain their own licenses;
they are not linked into the C library.
