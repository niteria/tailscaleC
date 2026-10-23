#!/usr/bin/env python3
"""Boot the real ESP32-S3 crypto-vector firmware in Espressif QEMU."""
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
    parser.add_argument("--build", type=Path, default=root / "build-esp32-crypto")
    parser.add_argument("--qemu", default="qemu-system-xtensa")
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("Timeout must be positive")
    binary = shutil.which(args.qemu)
    if not binary:
        parser.error("Specify Espressif's QEMU with --qemu /path/to/qemu-system-xtensa")
    build = args.build.resolve()
    if not (build / "flash_args").is_file():
        parser.error(f"Build the crypto-vector firmware first: {build}")
    subprocess.run([
        sys.executable, "-m", "esptool", "--chip", "esp32s3", "merge-bin",
        "--fill-flash-size", "4MB", "-o", "qemu-flash.bin", "@flash_args",
    ], cwd=build, check=True, timeout=30)
    process = subprocess.Popen([
        str(Path(binary).resolve()), "-nographic", "-machine", "esp32s3",
        "-drive", "file=qemu-flash.bin,if=mtd,format=raw", "-no-reboot",
    ], cwd=build, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE)
    output = bytearray()
    passed = False
    deadline = time.monotonic() + args.timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    output.extend(chunk)
                    (build / "qemu-crypto.log").write_bytes(output)
                if b"TSC_QEMU_CRYPTO_OK" in output:
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
        (build / "qemu-crypto.log").write_bytes(output)
    if not passed:
        sys.stderr.write(output.decode(errors="replace"))
        raise SystemExit("ESP32-S3 crypto vectors did not reach the success marker")
    for line in output.decode(errors="replace").splitlines():
        if any(word in line for word in ("crypto", "Crypto", "X25519", "TSC_QEMU_")):
            print(line)
    print(f"ESP32-S3 QEMU crypto vectors passed; log: {build / 'qemu-crypto.log'}")


if __name__ == "__main__":
    main()
