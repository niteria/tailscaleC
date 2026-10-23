#!/usr/bin/env python3
"""Build and boot real ESP32-S3 firmware against disposable Headscale/Tailscale.

Requires Linux, Docker, ESP-IDF, its Python environment and Espressif QEMU.
Uses virtual Ethernet and QEMU user networking; does not use any host tailnet.
The default two boots reuse emulated NVS to verify identity persistence.
"""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from check_headscale_client import Lab, free_udp_port, output, receive_exact

ROOT = Path(__file__).resolve().parents[1]


def run_logged(arguments, *, directory, log, environment=None, timeout=600):
    with log.open("wb") as stream:
        result = subprocess.run(arguments, cwd=directory, env=environment,
                                stdout=stream, stderr=subprocess.STDOUT,
                                timeout=timeout)
    if result.returncode:
        # Never print generated header contents or secret-bearing argv.
        raise RuntimeError(f"{Path(arguments[0]).name} failed; diagnostic log: {log}")


def write_private_header(build, info, forwarded_port):
    private = build / "private"
    private.mkdir(mode=0o700, exist_ok=True)
    values = {
        "TSC_LAB_CONTROL_URL": info["control_url"],
        "TSC_LAB_AUTH_KEY": info["auth_key"],
        "TSC_LAB_REFERENCE_IP": info["reference_ip"],
        "TSC_LAB_ADVERTISE_IP": info["gateway"],
    }
    path = private / "lab_config.h"
    descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write("/* Generated ephemeral lab credentials. Do not commit. */\n")
        for name, value in values.items():
            stream.write(f"#define {name} {json.dumps(value)}\n")
        stream.write(f"#define TSC_LAB_FORWARD_PORT {forwarded_port}\n")
        stream.write(f"#define TSC_LAB_EPOCH {int(time.time())}\n")


def upstream_request(info, node_ip):
    # SOCKS5 UDP ASSOCIATE originates the request inside the genuine upstream
    # userspace Tailscale stack, rather than through host tailnet routing.
    with socket.create_connection((info["reference_address"], 1055), 5) as control:
        control.settimeout(5)
        control.sendall(b"\x05\x01\x00")
        if receive_exact(control, 2) != b"\x05\x00":
            raise AssertionError("Upstream SOCKS5 negotiation failed")
        control.sendall(b"\x05\x03\x00\x01" + bytes(6))
        if receive_exact(control, 4) != b"\x05\x00\x00\x01":
            raise AssertionError("Upstream SOCKS5 UDP associate failed")
        address = socket.inet_ntoa(receive_exact(control, 4))
        port = struct.unpack("!H", receive_exact(control, 2))[0]
        if address == "0.0.0.0":
            address = info["reference_address"]
        message = b"upstream-to-esp32-binary" + bytes(range(256)) + os.urandom(32)
        packet = b"\0\0\0\x01" + socket.inet_aton(node_ip) + struct.pack("!H", 32123) + message
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(0.5)
            deadline = time.monotonic() + 8
            while True:
                udp.sendto(packet, (address, port))
                try:
                    response, _ = udp.recvfrom(2048)
                    if response != packet:
                        raise AssertionError("ESP32 upstream-initiated UDP echo bytes differ")
                    return
                except socket.timeout:
                    if time.monotonic() >= deadline:
                        raise AssertionError("ESP32 did not reply to upstream-initiated UDP")


def boot(qemu, build, forwarded_port, timeout, iteration, info):
    command = [qemu, "-nographic", "-machine", "esp32s3", "-no-reboot",
               "-drive", "file=qemu-flash.bin,if=mtd,format=raw",
               "-nic", f"user,model=open_eth,hostfwd=udp:0.0.0.0:{forwarded_port}-:41641"]
    process = subprocess.Popen(command, cwd=build, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
    data = bytearray()
    deadline = time.monotonic() + timeout
    log = build / f"qemu-tailnet-{iteration}.log"
    passed = False
    upstream_checked = False
    stop = threading.Event()

    def inject_malformed():
        packets = [b"", b"\x01", b"\x01\0\0\0" + bytes(144),
                   b"\x02\0\0\0" + bytes(88), b"\x04\0\0\0" + bytes(28),
                   b"TS\xf0\x9f\x92\xac" + bytes(64), bytes(2048)]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            while not stop.wait(0.2):
                for packet in packets:
                    sock.sendto(packet, ("127.0.0.1", forwarded_port))

    injector = threading.Thread(target=inject_malformed, daemon=True)
    injector.start()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if chunk:
                        data.extend(chunk)
                        log.write_bytes(data)
                if not upstream_checked and b"UPSTREAM_UDP_READY" in data:
                    text = data.decode(errors="replace").replace("\r", "")
                    joined = re.findall(r"^JOINED ([0-9.]+)$", text, re.MULTILINE)
                    if len(joined) != 1:
                        raise AssertionError("Firmware did not expose a registered address")
                    upstream_request(info, joined[0])
                    upstream_checked = True
                if b"TSC_QEMU_TAILNET_OK" in data:
                    passed = True
                    break
                if b"TSC_QEMU_TAILNET_FAILED" in data or process.poll() is not None:
                    break
    finally:
        stop.set()
        injector.join(timeout=2)
        if process.poll() is None:
            process.terminate()
        try:
            remaining, _ = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            remaining, _ = process.communicate(timeout=3)
        data.extend(remaining)
        log.write_bytes(data)
    decoded = data.decode(errors="replace").replace("\r", "")
    if not passed:
        raise AssertionError(f"ESP32-S3 firmware did not complete; boot log: {log}\n{decoded[-10000:]}")
    for expected in ("UDP_BINARY_ECHO 1", "UDP_BINARY_ECHO 32", "UDP_BINARY_ECHO 512",
                     "UDP_BINARY_ECHO 1200", "UDP_DENIED_PORT 32124", "MAP_REFRESH_OK",
                     "UPSTREAM_UDP_ECHO_OK"):
        if expected not in decoded.splitlines():
            raise AssertionError(f"Missing {expected}; see {log}")
    joined = re.findall(r"^JOINED ([0-9.]+)$", decoded, re.MULTILINE)
    if len(joined) != 1:
        raise AssertionError(f"Expected one registered tailnet address; see {log}")
    for line in decoded.splitlines():
        if line.startswith(("IDENTITY ", "JOINED ", "UDP_", "UPSTREAM_", "MAP_", "MEMORY ", "TSC_QEMU_TAILNET_OK")):
            print(f"boot {iteration}: {line}", flush=True)
    if iteration > 1 and "IDENTITY restored" not in decoded:
        raise AssertionError("Second boot did not restore its persistent node identity")
    return joined[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build-esp32-tailnet")
    parser.add_argument("--idf-path", type=Path,
                        default=Path(os.environ.get("IDF_PATH", Path.home() / ".platformio/packages/framework-espidf")))
    parser.add_argument("--idf-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--toolchain-bin", type=Path,
                        help="Xtensa compiler directory if not already on PATH")
    parser.add_argument("--qemu", default="qemu-system-xtensa")
    parser.add_argument("--timeout", type=float, default=90,
                        help="wall-clock timeout per boot")
    parser.add_argument("--boots", type=int, default=2)
    args = parser.parse_args()
    def interrupted(_signal_number, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    if args.boots < 1 or args.timeout <= 0:
        parser.error("Boot count and timeout must be positive")
    qemu = shutil.which(args.qemu)
    if not qemu:
        parser.error("Specify Espressif QEMU with --qemu /path/to/qemu-system-xtensa")
    qemu = str(Path(qemu).resolve())
    if not (args.idf_path / "tools/cmake/project.cmake").is_file():
        parser.error("Set --idf-path or IDF_PATH to ESP-IDF 5.x")
    build = args.build.resolve()
    build.mkdir(parents=True, mode=0o700, exist_ok=True)
    build.chmod(0o700)  # Firmware embeds temporary credentials.
    environment = dict(os.environ, IDF_PATH=str(args.idf_path.resolve()), IDF_TARGET="esp32s3",
                       IDF_PYTHON_ENV_PATH=str(args.idf_python.absolute().parent.parent))
    paths = [str(args.idf_python.absolute().parent)]
    if args.toolchain_bin:
        paths.append(str(args.toolchain_bin.resolve()))
    environment["PATH"] = os.pathsep.join(paths + [environment.get("PATH", "")])
    for name in ("cmake", "ninja", "docker", "xtensa-esp32s3-elf-gcc"):
        if not shutil.which(name, path=environment["PATH"]):
            parser.error(f"Missing required executable: {name}")
    with tempfile.TemporaryDirectory(prefix="tailscalec-esp32-lab-") as temporary:
        lab = Lab(temporary)
        try:
            info = lab.start()
            port = free_udp_port()
            write_private_header(build, info, port)
            run_logged(["cmake", "-S", str(ROOT / "examples/esp32_tailnet"),
                        "-B", str(build), "-G", "Ninja", "-DIDF_TARGET=esp32s3",
                        f"-DPYTHON={args.idf_python.absolute()}", f"-DSDKCONFIG={build / 'sdkconfig'}"],
                       directory=ROOT, log=build / "configure.log", environment=environment)
            run_logged(["cmake", "--build", str(build), "--parallel", "4"], directory=ROOT,
                       log=build / "build.log", environment=environment)
            run_logged([str(args.idf_python.absolute()), "-m", "esptool", "--chip", "esp32s3",
                        "merge-bin", "--fill-flash-size", "4MB", "-o", "qemu-flash.bin", "@flash_args"],
                       directory=build, log=build / "merge.log", environment=environment)
            node_ip = None
            for iteration in range(1, args.boots + 1):
                address = boot(qemu, build, port, args.timeout, iteration, info)
                if node_ip is not None and address != node_ip:
                    raise AssertionError("Persistent NVS identity rejoined with a different tailnet IP")
                node_ip = address
                if len(lab.nodes()) != 2:
                    raise AssertionError("Expected only upstream reference and the ESP32 node")
            events = [json.loads(line) for line in output("docker", "logs", lab.echo_name).splitlines()
                      if line.startswith("{")]
            for length in (1, 32, 512, 1200):
                expected = bytes((index * 73 + length) & 255 for index in range(length)).hex()
                if not any(event.get("hex") == expected and event.get("port") == 32123 for event in events):
                    raise AssertionError(f"Real upstream service never received the {length}-byte binary payload")
            if any(event.get("port") == 32124 for event in events):
                raise AssertionError("Policy-denied data reached the real upstream service")
            print("ESP32-S3 QEMU + Headscale + upstream Tailscale interoperability passed.", flush=True)
            print(f"Verified binary UDP in both directions, denied port, malformed packets, map refresh and {args.boots} boots; logs: {build}")
        except BaseException:
            lab.diagnose()
            raise
        finally:
            lab.close()
            # The flash and ELF still contain ephemeral credentials, but the
            # entire build directory is owner-only and ignored by Git.
            (build / "private/lab_config.h").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
