# ESP32-S3 full-client interoperability in QEMU

This is real ESP-IDF Xtensa firmware using lwIP sockets, mbedTLS and the
portable tailscaleC client. Espressif QEMU's virtual OpenEth interface carries
traffic to a disposable Headscale coordinator and upstream Linux Tailscale
peer. The runner creates and removes its Docker lab without accessing the
host's Tailscale state.

From the repository root, with an activated ESP-IDF 5.x environment and Linux
Docker available:

```sh
python tools/check_esp32_tailnet.py --qemu /path/to/qemu-system-xtensa
```

Use Espressif's QEMU fork with the `esp32s3` machine and `open_eth` network
device. Optional arguments select the ESP-IDF directory, Python interpreter,
Xtensa toolchain directory, build directory and number of boots. For the
workspace's PlatformIO ESP-IDF installation:

```sh
IDF_PYTHON_CHECK_CONSTRAINTS=no build-esp32/venv/bin/python \
  tools/check_esp32_tailnet.py \
  --idf-python build-esp32/venv/bin/python \
  --toolchain-bin /home/bc/.platformio/packages/toolchain-xtensa-esp-elf/bin \
  --qemu build-tools/qemu/bin/qemu-system-xtensa
```

The runner requires successful authenticated registration, exact binary UDP
echoes of 1, 32, 512 and 1200 bytes through upstream Tailscale, rejection of
port 32124 by the coordinator's policy, a map refresh, and continued valid
traffic while malformed outer datagrams are injected. It checks the upstream
application's actual received bytes, then originates a binary UDP request from
the upstream peer and verifies the ESP32's exact reply. Its default second boot reuses emulated
NVS, restores the same identity, rejoins without an auth key, and must retain
the same address without creating another coordinator node.

`config.h` bounds the fixture to two peers, two UDP sockets, four tracked
flows and a 16 KiB coordination response. `sdkconfig.defaults` enables virtual
Ethernet and the required mbedTLS primitives. No PSRAM is required. The
firmware prints client/control storage, free/minimum heap and unused task
stack; these figures exclude memory used by the host emulator and Docker.

This test exercises direct IPv4 UDP and HTTP coordination protected by TS2021
Noise. It does not verify physical Wi-Fi, ESP32 hardware entropy, public
Tailscale coordination, TLS coordination, DERP, application TCP or IPv6 data
traffic. QEMU emulates the enabled entropy source, and the host supplies the
test clock. The library's own MCU crypto vectors are a separate fixture in
`../esp32_crypto`.

Generated credentials live only in an ignored, owner-only build directory;
the generated header is deleted after the run. ELF/flash artifacts still
contain the temporary lab credentials and private emulated NVS. Delete the
build directory when those diagnostic artifacts are no longer useful.

The example persists identity keys and handshake timestamps in NVS. Its
commit-per-handshake timestamp callback is deliberately simple for testing;
production firmware must budget flash endurance and protect persistent keys
(for example, with encrypted NVS).
