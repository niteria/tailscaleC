This firmware runs the same `tests/test_crypto.c` used by the POSIX test suite
against the ESP32 mbedTLS provider, including RFC 7748's 1000-iteration X25519
vector, RFC 8439 authenticated-encryption vectors, SHA-256, HMAC, HKDF, invalid
authentication tags, and in-place buffer boundaries. It needs no tailnet or
network connection.

With ESP-IDF activated:

```sh
cd examples/esp32_crypto
idf.py set-target esp32s3
idf.py build
```

Then run from the repository root, using a Python interpreter with ESP-IDF's
`esptool` installed:

```sh
python examples/esp32_crypto/check_qemu.py \
    --build examples/esp32_crypto/build \
    --qemu /path/to/espressif/qemu-system-xtensa
```

The runner records `qemu-crypto.log`, requires `TSC_QEMU_CRYPTO_OK` from the real
Xtensa firmware, and terminates QEMU after completion. Use `idf.py flash monitor`
to run the same firmware on hardware. The standalone test enables the ADC
entropy source and disables the task watchdog while its long vector loop runs.
QEMU verifies protocol arithmetic and platform integration; it does not measure
physical entropy quality.
