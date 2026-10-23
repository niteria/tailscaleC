WireGuard protocol core provenance
=================================

`src/wireguard/core.c` and `core.h` were adapted from Daniel Hope's
wireguard-lwIP implementation, as carried by TailTiny:
https://github.com/Asimmimx/tailtiny
commit 450ad519810f0a7560306e1389c65acf2c48828c,
components/tailtiny/components/wireguard_lwip/src/wireguard.{c,h}.
The BSD 3-clause copyright is retained in those sources and in LICENSE.

The adaptation removes lwIP, ESP-IDF, socket and static peer-array dependencies;
uses caller-owned peers and per-device callbacks/hashes; uses explicit endian
loads/stores; fixes unique-index collision handling, initialization-time rate
limiting and replay-window arithmetic; enlarges the replay window to64 packets;
and routes X25519/ChaCha20-Poly1305 through the shared crypto provider.

`crypto/refc/blake2s.{c,h}` is the RFC7693 reference implementation carried by
that project. RFC7693 AppendixD is an IETF Code Component under the Simplified BSD
license in LICENSE.RFC7693.
The local include path is adjusted to the portable internal crypto helpers;
finalization securely clears the hash context.

`crypto/refc/chacha20.{c,h}` is the upstream BSD-licensed implementation,
adapted from D.J. Bernstein's public-domain ChaCha reference code. It is used
only for HChaCha20 (the WireGuard cookie subkey derivation); authenticated
transport encryption uses OpenSSL/mbedTLS. Local changes correct the include
path and unsigned loop variable; HChaCha20 clears its local key state. Original copyright/license notices remain.

No x25519 or Poly1305 implementation from the reference project is included.
