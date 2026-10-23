#!/usr/bin/env python3
"""Run native lwIP coexistence and portable TCP tests on ESP32-S3 firmware."""
import argparse
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import time


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=root / "build-esp32-tcp")
    parser.add_argument("--qemu", default="qemu-system-xtensa")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("Timeout must be positive")
    qemu = shutil.which(args.qemu)
    if not qemu:
        parser.error("Specify Espressif QEMU with --qemu /path/to/qemu-system-xtensa")
    build = args.build.resolve()
    if not (build / "flash_args").is_file():
        parser.error(f"Build the ESP32 TCP firmware first: {build}")
    subprocess.run([
        sys.executable, "-m", "esptool", "--chip", "esp32s3", "merge-bin",
        "--fill-flash-size", "4MB", "-o", "qemu-flash.bin", "@flash_args",
    ], cwd=build, check=True, timeout=30)
    process = subprocess.Popen([
        str(Path(qemu).resolve()), "-nographic", "-machine", "esp32s3",
        "-drive", "file=qemu-flash.bin,if=mtd,format=raw", "-no-reboot",
    ], cwd=build, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE)
    output = bytearray()
    passed = False
    log = build / "qemu-tcp.log"
    deadline = time.monotonic() + args.timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    output.extend(chunk)
                    log.write_bytes(output)
                if b"TSC_QEMU_TCP_OK" in output:
                    passed = True
                    break
                if any(marker in output for marker in
                       (b"fixture failed:", b"Guru Meditation", b"abort() was called")):
                    break
                if process.poll() is not None:
                    break
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            remaining, _ = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            remaining, _ = process.communicate(timeout=3)
        output.extend(remaining)
        log.write_bytes(output)
    decoded = output.decode(errors="replace").replace("\r", "")
    if not passed or decoded.count("Native ESP-IDF lwIP UDP loopback passed") != 2:
        sys.stderr.write(decoded)
        raise SystemExit("ESP32-S3 TCP/coexistence tests did not complete")
    for line in decoded.splitlines():
        if any(word in line for word in ("TCP", "Native ESP", "TSC_QEMU_")):
            print(line)
    print(f"ESP32-S3 QEMU TCP tests passed; log: {log}")


if __name__ == "__main__":
    main()
