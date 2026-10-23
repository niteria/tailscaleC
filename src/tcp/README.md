# Optional bounded TCP engine

`TSC_APP_TCP=1` enables an independent IPv4 TCP engine based on lwIP 2.2.1
(`STABLE-2_2_1_RELEASE`, commit `77dcd25a72509eb83f72b033d219b1d40cd8eb95`).
The upstream source is https://github.com/lwip-tcpip/lwip and its BSD-style license
is retained in `lwip/LICENSE` and every upstream source file.

This is application TCP **inside** the encrypted tunnel. The coordinator's
underlying TLS/TCP transport belongs to the platform/control components.

## Integration

Include `tailscalec/tcp.h`, statically allocate `tsc_tcp`, and initialize it with
the client's tailnet IPv4 address, an IP output callback, and a cryptographically
secure randomness callback. Attach `tsc_tcp_input` to the client's authenticated
IP handler, and send output through `tsc_client_send_ip`. Keep both engines in
the same event loop and call `tsc_tcp_poll` at least every 250 ms. Input and
output callbacks consume/copy packets synchronously; output must not recursively
call input or any other TCP API.

The CMake helper `tcp.cmake` creates an isolated OBJECT target. Only this target
sees the vendored headers. It inherits the owning target's compile definitions
and options, and its objects are included in the main library. ESP-IDF network
code continues to use ESP-IDF's own lwIP. All compiled vendor exports are
prefixed `tsc_lwip_`, and no native sockets or native lwIP netifs are modified.

## Bounds and restrictions

- One initialized TCP engine per process/firmware; a second init returns
  `TSC_ERR_SPACE`. Destroy releases all PCBs and permits reinitialization.
- IPv4 only. The outer transport may use either address family supported by the
  rest of the library. No IP fragmentation/reassembly is enabled.
- All APIs run from one caller task/thread. No worker threads, syscalls, or
  application heap allocations are used by this engine.
- `TSC_MAX_TCP_CONNECTIONS` bounds application connections, including pending
  accepts. Listeners are bounded separately by `TSC_MAX_TCP_LISTENERS`.
- `TSC_TCP_SEND_BUFFER` bounds queued TCP payload per PCB; it must be at least
  1072 bytes. `TSC_TCP_RECEIVE_BUFFER` bounds each connection's application ring
  and advertised receive window; it must be 536..65535 bytes. Send buffer must
  also fit 65535 bytes. The fixed MSS is 536 bytes.
- lwIP uses its **fixed internal arena and static pools**, never libc malloc.
  The arena is `connections * (send_buffer + 1024) + 4096` bytes. TCP PCB and
  segment pools, packet buffers, the output scratch packet, and receive rings
  consume additional bounded RAM. Out-of-order packets have a two-pbuf and
  receive-window limit per connection. Pool exhaustion drops/refuses packets
  and relies on normal TCP retransmission/backpressure.
- Resource limits do not reserve one pool slice for each peer: a busy peer can
  temporarily exhaust shared pools. No per-peer fairness guarantee is provided.
- `connect` is asynchronous; inspect state before writing. `send` and `receive`
  can transfer partial buffers. `TSC_AGAIN` means retry after processing input
  and timers. A successful receive of zero bytes means EOF.
- `shutdown` queues FIN behind pending writes and keeps receive available.
  For graceful full-duplex close, shut down writes, read EOF, then close the
  handle. An early `close` deliberately aborts and discards pending data.
- TCP ISNs use fresh secure random words. A randomness callback failure latches
  an I/O error and suppresses subsequent output; it does not use a weak fallback.
- Handles are array slots, not generation-tagged objects. After `close`, discard
  the handle: an old numeric value may later identify a new connection.

lwIP implements retransmission, congestion control, advertised receive windows,
out-of-order reassembly, checksums, SYN/FIN/RST handling, and TIME_WAIT. The
wrapper does not substitute a new minimal TCP implementation.

## Reproducing the vendored source

`port/namespace.h` records the exports selected for this build. Token-level
prefixing is required because lwIP uses `#ifndef function_name` to permit user
substitutes; defining simple rename macros alone would disable those functions.
Comments, strings (including include filenames), and licenses remain unchanged.

With an upstream checkout at the exact commit above, run:

```
python3 src/tcp/vendor.py /path/to/lwip --check
```

Without `--check`, the script refreshes the selected vendored files. When
changing enabled lwIP modules, regenerate/review the export list and audit `nm`
output: every defined vendor global must start with `tsc_lwip_` (sanitizers may
also emit `__odr_asan.tsc_lwip_*`).

## Tests

`tests/test_tcp.c` exercises argument/resource bounds and repeated lifecycle,
independently encoded TCP packets and checksum rejection, a manually implemented
wire peer (including 32-bit sequence wrap), graceful FIN handling and deferred
close after TIME_WAIT expiration, and two independent processes exchanging
32,789 bytes in both directions with backpressure. Its link simulator drops a
SYN and data packets, duplicates packets, and reverses packet order. These tests
do not require a TUN device, root, or a native TCP daemon. Upstream Tailscale
interoperability is exercised separately by the Headscale lab.

`examples/esp32_tcp` runs the shared portable cases as real ESP32-S3 firmware
under Espressif QEMU, including the independent wire peer and TIME_WAIT
lifecycle checks. Native ESP-IDF UDP loopback succeeds both before and after
the private TCP suite, exercising both lwIP instances in one target binary.
Its runner requires the firmware's `TSC_QEMU_TCP_OK` marker and records a boot
log. The POSIX fork/link simulator is excluded from this target fixture.
