#!/usr/bin/env python3
"""Boot the ESP32-S3 example in Espressif QEMU and check real lwIP UDP loopback.

Run with a Python interpreter that has ESP-IDF's esptool installed. The QEMU
executable must be Espressif's fork, with the esp32s3 machine.
"""
import argparse
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import time


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=root / "build-esp32")
    parser.add_argument("--qemu", default="qemu-system-xtensa")
    parser.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("Timeout must be positive")
    binary = shutil.which(args.qemu)
    if not binary:
        parser.error("Install Espressif's qemu-xtensa or specify --qemu /path/to/binary")
    binary = str(Path(binary).resolve())
    machines = subprocess.check_output([binary, "-machine", "help"], text=True, timeout=10)
    if not any(line.split() and line.split()[0] == "esp32s3" for line in machines.splitlines()):
        parser.error("This QEMU lacks esp32s3; use Espressif's fork")
    build = args.build.resolve()
    if not (build / "flash_args").is_file():
        parser.error(f"Build the ESP-IDF example first: {build}")
    subprocess.run([
        sys.executable, "-m", "esptool", "--chip", "esp32s3", "merge-bin",
        "--fill-flash-size", "4MB", "-o", "qemu-flash.bin", "@flash_args",
    ], cwd=build, check=True, timeout=30)
    process = subprocess.Popen([
        binary, "-nographic", "-machine", "esp32s3",
        "-drive", "file=qemu-flash.bin,if=mtd,format=raw", "-no-reboot",
    ], cwd=build, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        # Keep stdin open: QEMU disconnects the stdio UART on immediate EOF.
        stdin=subprocess.PIPE)
    output = bytearray()
    passed = False
    deadline = time.monotonic() + args.timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                for key, _ in selector.select(max(0, min(0.1, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        break
                    output.extend(chunk)
                if b"TSC_QEMU_TRANSPORT_OK" in output:
                    passed = True
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
        (build / "qemu-smoke.log").write_bytes(output)
    if not passed:
        sys.stderr.write(output.decode(errors="replace"))
        raise SystemExit("ESP32-S3 QEMU UDP test did not reach the success marker")
    for line in output.decode(errors="replace").splitlines():
        if any(word in line for word in ("storage:", "UDP loopback:", "TSC_QEMU_")):
            print(line)
    print(f"ESP32-S3 QEMU UDP loopback passed; boot log: {build / 'qemu-smoke.log'}")


if __name__ == "__main__":
    main()
