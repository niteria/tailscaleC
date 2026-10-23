This ESP32-S3 firmware runs the portable, non-POSIX portion of the same
`tests/test_tcp.c` used on Linux. It exercises resource limits and lifecycle,
randomness failures, callback reentry, independently encoded TCP/checksum
validation, SYN/ACK handshake, binary data in both directions, sequence-number
wrap, FIN exchange, and delayed application close after TIME_WAIT expiration.
The private TCP engine and ESP-IDF's native lwIP are both present and active:
native UDP loopback runs before and after the private TCP tests.

With ESP-IDF activated:

```sh
idf.py -C examples/esp32_tcp -B build-esp32-tcp set-target esp32s3
idf.py -C examples/esp32_tcp -B build-esp32-tcp build
python examples/esp32_tcp/check_qemu.py \
    --qemu /path/to/espressif/qemu-system-xtensa
```

Use a Python interpreter with ESP-IDF's `esptool` installed. The runner requires
`TSC_QEMU_TCP_OK` and both native UDP checks, records `qemu-tcp.log` in the build
directory, and terminates QEMU. The same firmware can run on hardware with
`idf.py flash monitor`.

This isolated test uses deterministic randomness **only as a local test
fixture**; production `tsc_tcp_config.random_bytes` must use secure randomness.
No radio, external network, coordinator, WireGuard tunnel, or TLS connection is
needed here. The forked fault-injection stream tests remain POSIX-only; they
are excluded from this firmware. Full ESP32 Headscale interoperability has its
own fixture in `../esp32_tailnet`.
