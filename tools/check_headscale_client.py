#!/usr/bin/env python3
"""Test the C client against disposable Headscale and upstream Tailscale.

Linux + Docker required. Containers use userspace networking without TUN,
privileged mode, host networking, host state mounts, or access to tailscaled.
The coordinator uses HTTP only inside a private lab; its control connection is
still encrypted and authenticated with Noise. This is a direct-UDP LAN test,
not coverage of TLS, NAT traversal, DERP, or IPv6 data traffic.
Pass --tcp-client to additionally test application TCP.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import struct
import shutil
import signal
import threading
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

HEADSCALE = "ghcr.io/juanfont/headscale:0.29.5"
# Immutable upstream image; `tailscale version` reports 1.98.9.
TAILSCALE = "tailscale/tailscale@sha256:f15d5d3f4a68773a853180b72496f70ba614b64de0878c43fe3da39fe0afba47"
PYTHON = "python:3.11-slim"
ROOT = Path(__file__).resolve().parents[1]


def command(*arguments, timeout=30, check=True):
    result = subprocess.run(arguments, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        # Auth keys may appear in argv; don't reproduce the command on failure.
        raise RuntimeError(f"{arguments[0]} failed ({result.returncode}): "
                           f"{result.stderr[-6000:]}{result.stdout[-6000:]}")
    return result


def output(*arguments, timeout=30):
    return command(*arguments, timeout=timeout).stdout.strip()


class Lab:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.prefix = "tailscalec-interop-" + uuid.uuid4().hex[:10]
        self.network = None
        self.containers = []
        self.info = {}

    def container(self, suffix, *arguments):
        name = self.prefix + "-" + suffix
        output("docker", "create", "--name", name, "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", *arguments)
        self.containers.append(name)
        return name

    def headscale(self, *arguments):
        return output("docker", "exec", self.headscale_name, "headscale",
                      "--config", "/etc/headscale/config.yaml", *arguments)

    def tailscale(self, *arguments):
        return output("docker", "exec", self.reference_name, "tailscale",
                      "--socket=/tmp/tailscaled.sock", *arguments)

    def start(self):
        # Pull before creating any resources: a cold image download can exceed
        # normal command deadlines, and an interrupted pull must not leak labs.
        for image in (HEADSCALE, TAILSCALE, PYTHON):
            if command("docker", "image", "inspect", image, check=False).returncode:
                print("Fetching test image " + image, flush=True)
                output("docker", "pull", image, timeout=600)
        self.directory.chmod(0o700)
        fixture = self.directory / "fixtures"
        fixture.mkdir(exist_ok=True, mode=0o755)
        fixture.chmod(0o755)
        shutil.copyfile(ROOT / "tests/interop/client_headscale.yaml",
                        fixture / "config.yaml")
        shutil.copyfile(ROOT / "tests/interop/client_policy.json",
                        fixture / "policy.json")
        shutil.copyfile(ROOT / "tests/interop/client_derp.yaml",
                        fixture / "derp.yaml")
        self.network = self.prefix
        output("docker", "network", "create", self.network)
        self.headscale_name = self.container(
            "headscale", "--network", self.network, "--network-alias", "headscale",
            "--tmpfs", "/var/lib/headscale:rw,noexec,nosuid,size=64m",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", HEADSCALE,
            "--config", "/etc/headscale/config.yaml", "serve")
        output("docker", "cp", f"{fixture}/.",
               f"{self.headscale_name}:/etc/headscale")
        output("docker", "start", self.headscale_name)
        details = json.loads(output("docker", "inspect", self.headscale_name))[0]
        network = details["NetworkSettings"]["Networks"][self.network]
        address = network["IPAddress"]
        gateway = network["Gateway"]
        self.url = f"http://{address}:8080"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deadline = time.monotonic() + 20
        while True:
            try:
                with opener.open(self.url + "/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except (urllib.error.URLError, TimeoutError):
                if output("docker", "inspect", "--format", "{{.State.Running}}",
                          self.headscale_name) != "true":
                    raise RuntimeError("Headscale exited before becoming healthy")
            if time.monotonic() > deadline:
                raise RuntimeError("Headscale did not become healthy")
            time.sleep(0.1)
        user = json.loads(self.headscale("users", "create", "lab", "--output", "json"))
        user_id = str(user["id"])
        key = json.loads(self.headscale("preauthkeys", "create", "--user", user_id,
                                       "--reusable", "--expiration", "1h",
                                       "--output", "json"))["key"]
        self.reference_name = self.container(
            "reference", "--network", self.network,
            "--tmpfs", "/var/lib/tailscale:rw,noexec,nosuid,size=32m",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m",
            "--entrypoint", "tailscaled", TAILSCALE,
            "--tun=userspace-networking", "--state=/var/lib/tailscale/state",
            "--socket=/tmp/tailscaled.sock", "--port=41641",
            "--socks5-server=0.0.0.0:1055",
            "--no-logs-no-support")
        output("docker", "start", self.reference_name)
        deadline = time.monotonic() + 15
        while True:
            result = command("docker", "exec", self.reference_name, "tailscale",
                             "--socket=/tmp/tailscaled.sock", "status", "--json",
                             timeout=3, check=False)
            if result.returncode == 0:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Reference tailscaled socket never became ready")
            time.sleep(0.1)
        self.tailscale("up", "--login-server=http://headscale:8080",
                       "--auth-key=" + key, "--hostname=reference",
                       "--accept-dns=false", "--accept-routes=false",
                       "--netfilter-mode=off", "--timeout=20s")
        reference_ip = self.tailscale("ip", "-4")
        reference_details = json.loads(output("docker", "inspect", self.reference_name))[0]
        reference_address = reference_details["NetworkSettings"]["Networks"][self.network]["IPAddress"]
        self.echo_name = self.container(
            "echo", "--network", "container:" + self.reference_name,
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m",
            "--entrypoint", "python3", PYTHON, "-u", "/client_udp_echo.py")
        output("docker", "cp", str(ROOT / "tests/interop/client_udp_echo.py"),
               f"{self.echo_name}:/client_udp_echo.py")
        output("docker", "start", self.echo_name)
        deadline = time.monotonic() + 10
        while "READY" not in output("docker", "logs", self.echo_name):
            if time.monotonic() > deadline:
                raise RuntimeError("Reference UDP echo server did not become ready")
            time.sleep(0.1)
        self.info = {"control_url": self.url, "auth_key": key,
                     "gateway": gateway, "reference_ip": reference_ip,
                     "reference_address": reference_address,
                     "headscale_container": self.headscale_name,
                     "reference_container": self.reference_name,
                     "echo_container": self.echo_name,
                     "network": self.network}
        info_path = self.directory / "lab.json"
        descriptor = os.open(info_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(self.info, stream)
        version = self.tailscale("version").splitlines()[0]
        print(f"Headscale 0.29.5 + upstream Tailscale {version} ready; "
              f"reference {reference_ip}", flush=True)
        return self.info

    def nodes(self):
        return json.loads(self.headscale("nodes", "list", "--output", "json"))

    def diagnose(self):
        for name in self.containers:
            result = command("docker", "logs", "--tail", "40", name, check=False)
            lines = []
            for line in result.stdout.splitlines():
                if line.startswith("{"):
                    try:
                        event = json.loads(line)
                        if isinstance(event.get("hex"), str) and len(event["hex"]) > 64:
                            event["hex"] = event["hex"][:64] + "..."
                        line = json.dumps(event)
                    except (ValueError, AttributeError):
                        pass
                lines.append(line)
            print(f"--- {name} ---\n" + "\n".join(lines) + "\n" + result.stderr[-6000:],
                  flush=True)

    def close(self):
        for name in reversed(self.containers):
            command("docker", "rm", "--force", name, timeout=20, check=False)
        if self.network:
            command("docker", "network", "rm", self.network, timeout=20, check=False)


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", 0))
        return sock.getsockname()[1]




def connect_socks_tcp(info, node_ip, port):
    # The upstream SOCKS proxy imposes a 5s dial deadline, equal to WireGuard's
    # retry interval. A restarted peer may rekey at that exact boundary.
    for attempt in range(3):
        connection = socket.create_connection((info["reference_address"], 1055), 5)
        connection.settimeout(12)
        try:
            connection.sendall(b"\x05\x01\x00")
            if receive_exact(connection, 2) != b"\x05\x00":
                raise AssertionError("Reference SOCKS5 negotiation failed")
            connection.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(node_ip) + struct.pack("!H", port))
            header = receive_exact(connection, 4)
            if header == b"\x05\x00\x00\x01":
                receive_exact(connection, 6)
                return connection
            if header != b"\x05\x01\x00\x01" or attempt == 2:
                raise AssertionError(f"Reference SOCKS5 TCP connect failed: {header.hex()}")
        except BaseException:
            connection.close()
            raise
        connection.close()
    raise AssertionError("Reference SOCKS5 TCP retries exhausted")


def run_tcp_tests(lab, client, directory, info, state, node_ip):
    def arguments():
        port = free_udp_port()
        return [str(client), "--control-url", info["control_url"],
                "--state-file", str(state), "--name", "c-client", "--bind",
                f"0.0.0.0:{port}", "--endpoint", f"{info['gateway']}:{port}",
                "--listen-port", "32123"]
    for length in (1, 32789):
        message = ("tcp-" + uuid.uuid4().hex * 1100)[:length]
        result = command(*arguments(), "--send", f"{info['reference_ip']}:32123",
                         "--message", message, "--timeout", "15", timeout=30,
                         check=False)
        if any(marker in result.stderr for marker in ("AddressSanitizer", "LeakSanitizer", "runtime error:")):
            raise AssertionError("C TCP client sanitizer diagnostic: " + result.stderr)
        if result.returncode or f"JOINED {node_ip}" not in result.stdout or f"RECEIVED {length}\n" not in result.stdout:
            raise AssertionError(f"Real upstream TCP echo failed: {result.stdout}{result.stderr}")
    denied = command(*arguments(), "--send", f"{info['reference_ip']}:32124",
                     "--message", "denied-tcp", "--timeout", "12", timeout=27,
                     check=False)
    if any(marker in denied.stderr for marker in ("AddressSanitizer", "LeakSanitizer", "runtime error:")):
        raise AssertionError("C TCP client sanitizer diagnostic: " + denied.stderr)
    if "Timed out waiting for TCP reply." not in denied.stderr:
        raise AssertionError("TCP policy test failed for an unexpected reason: " + denied.stdout + denied.stderr)
    if denied.returncode != 1 or f"JOINED {node_ip}" not in denied.stdout or "SYN_SENT" not in denied.stdout or "RECEIVED " in denied.stdout:
        raise AssertionError("TCP denied-port policy failed: " + denied.stdout + denied.stderr)
    events = [json.loads(line) for line in output("docker", "logs", lab.echo_name).splitlines()
              if line.startswith("{")]
    if any(event["port"] == 32124 for event in events):
        raise AssertionError("Denied TCP/UDP port reached the real upstream application")
    check_reference_initiated_tcp(lab, client, directory, info, state, node_ip)


def check_reference_initiated_tcp(lab, client, directory, info, state, node_ip):
    def arguments():
        port = free_udp_port()
        return [str(client), "--control-url", info["control_url"],
                "--state-file", str(state), "--name", "c-client", "--bind",
                f"0.0.0.0:{port}", "--endpoint", f"{info['gateway']}:{port}",
                "--listen-port", "32123"]
    stdout_path, stderr_path = directory / "tcp-listener.stdout", directory / "tcp-listener.stderr"
    with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
        process = subprocess.Popen(arguments() + ["--echo", "--timeout", "30"],
                                   stdout=stdout, stderr=stderr)
        try:
            deadline = time.monotonic() + 15
            while "LISTENING 32123" not in stdout_path.read_text():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError("C TCP listener did not join: " + stdout_path.read_text() + stderr_path.read_text())
                time.sleep(0.05)
            # Wait for reference's streaming map to see the restarted endpoint.
            lab.tailscale("ping", "--c=1", "--timeout=3s", node_ip)
            with connect_socks_tcp(info, node_ip, 32123) as connection:
                message = bytes(range(256)) * 128 + b"tcp-stream-end"
                connection.sendall(message)
                if receive_exact(connection, len(message)) != message:
                    raise AssertionError("Upstream-initiated binary TCP echo did not match")
                connection.shutdown(socket.SHUT_WR)
                if connection.recv(1):
                    raise AssertionError("Expected orderly TCP EOF after half-close")
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            diagnostics = stderr_path.read_text()
            if process.returncode or any(marker in diagnostics for marker in
                    ("AddressSanitizer", "LeakSanitizer", "runtime error:")):
                raise AssertionError("C listener exited unexpectedly: " + diagnostics)



def check_local_key_expiry(lab, client, directory, info, state, node_ip):
    # Install the deadline before joining, so the first authenticated snapshot
    # contains it. No control refresh occurs during the subsequent offline test.
    node = next(node for node in lab.nodes() if node_ip in node.get("ip_addresses", []))
    expires = datetime.fromtimestamp(time.time() + 20, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lab.headscale("nodes", "expire", "--identifier", str(node["id"]),
                  "--expiry", expires, "--force")
    port = free_udp_port()
    stdout_path, stderr_path = directory / "expiry.stdout", directory / "expiry.stderr"
    arguments = [str(client), "--control-url", info["control_url"],
                 "--state-file", str(state), "--name", "c-client", "--bind",
                 f"0.0.0.0:{port}", "--endpoint", f"{info['gateway']}:{port}",
                 "--listen-port", "32123", "--echo", "--timeout", "35",
                 "--map-refresh", "0"]
    with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
        process = subprocess.Popen(arguments, stdout=stdout, stderr=stderr)
        try:
            deadline = time.monotonic() + 15
            while "LISTENING 32123" not in stdout_path.read_text():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError("C expiry listener did not join: " + stdout_path.read_text() + stderr_path.read_text())
                time.sleep(0.05)
            output("docker", "stop", "--time=1", lab.headscale_name)
            process.wait(timeout=25)
            diagnostics = stderr_path.read_text()
            if process.returncode != 1 or "local node key expired" not in diagnostics:
                raise AssertionError("Expected local expiry with coordinator unavailable: " +
                                     stdout_path.read_text() + diagnostics)
            if any(marker in diagnostics for marker in ("AddressSanitizer", "LeakSanitizer", "runtime error:")):
                raise AssertionError("Sanitizer diagnostic during expiry: " + diagnostics)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


def receive_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise AssertionError("Upstream SOCKS5 connection closed unexpectedly")
        data.extend(chunk)
    return bytes(data)


def check_reference_initiated_udp(lab, client, directory, info, state, node_ip):
    outer_port = free_udp_port()
    stdout_path = directory / "listener.stdout"
    stderr_path = directory / "listener.stderr"
    arguments = [str(client), "--control-url", info["control_url"],
                 "--state-file", str(state), "--name", "c-client",
                 "--bind", f"0.0.0.0:{outer_port}",
                 "--endpoint", f"{info['gateway']}:{outer_port}",
                 "--listen-port", "32123", "--echo", "--timeout", "30"]
    with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
        process = subprocess.Popen(arguments, stdout=stdout, stderr=stderr)
        try:
            deadline = time.monotonic() + 15
            while f"JOINED {node_ip}" not in stdout_path.read_text():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError("C UDP listener did not join: " +
                                         stdout_path.read_text() + stderr_path.read_text())
                time.sleep(0.05)
            # This CLI uses authenticated DISCO by default, not ICMP or TSMP.
            ping = lab.tailscale("ping", "--c=1", "--timeout=3s", node_ip)
            if "via" not in ping or "DERP" in ping:
                raise AssertionError("Upstream could not discover a direct C endpoint: " + ping)
            # SOCKS5 UDP ASSOCIATE makes the upstream userspace stack originate
            # the request. Ordinary host sockets cannot route into that stack.
            with socket.create_connection((info["reference_address"], 1055), 5) as control:
                control.sendall(b"\x05\x01\x00")
                if receive_exact(control, 2) != b"\x05\x00":
                    raise AssertionError("Reference SOCKS5 no-auth negotiation failed")
                control.sendall(b"\x05\x03\x00\x01" + bytes(6))
                header = receive_exact(control, 4)
                if header != b"\x05\x00\x00\x01":
                    raise AssertionError(f"Reference SOCKS5 UDP associate failed: {header.hex()}")
                address = socket.inet_ntoa(receive_exact(control, 4))
                port = struct.unpack("!H", receive_exact(control, 2))[0]
                if address == "0.0.0.0":
                    address = info["reference_address"]
                message = b"upstream-originated-" + uuid.uuid4().hex.encode()
                packet = b"\x00\x00\x00\x01" + socket.inet_aton(node_ip) + struct.pack("!H", 32123) + message
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(0.5)
                    deadline = time.monotonic() + 8
                    while True:
                        udp.sendto(packet, (address, port))
                        try:
                            response, _source = udp.recvfrom(2048)
                            if response[:10] != packet[:10] or response[10:] != message:
                                raise AssertionError("Upstream-initiated UDP echo bytes did not match")
                            break
                        except socket.timeout:
                            if time.monotonic() > deadline:
                                raise AssertionError("No reply to upstream-initiated encrypted UDP request")
            status = json.loads(lab.tailscale("status", "--json"))
            peer = next((peer for peer in (status.get("Peer") or {}).values()
                         if node_ip in peer.get("TailscaleIPs", [])), None)
            if not peer or not peer.get("CurAddr") or not peer.get("TxBytes") or not peer.get("RxBytes"):
                raise AssertionError("Upstream status did not confirm direct encrypted two-way traffic")
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            diagnostics = stderr_path.read_text()
            if process.returncode or any(marker in diagnostics for marker in
                    ("AddressSanitizer", "LeakSanitizer", "runtime error:")):
                raise AssertionError("C listener exited unexpectedly: " + diagnostics)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, default=ROOT / "build/tailnet-udp")
    parser.add_argument("--tcp-client", type=Path, help="optional tailnet-tcp example")
    parser.add_argument("--recovery-only", action="store_true",
                        help="test TCP restart recovery and offline key expiry only")
    parser.add_argument("--hold", type=int, default=0,
                        help="prepare lab for external diagnostics for this many seconds")
    parser.add_argument("--directory", type=Path,
                        help="diagnostic fixture directory (secrets are written mode 0600)")
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    for tool in ("docker",):
        if not shutil.which(tool):
            parser.error(f"Missing required tool: {tool}")
    if platform.system() != "Linux":
        parser.error("This lab needs a Linux host with access to Docker bridge addresses")
    if not args.hold and not args.client.is_file():
        parser.error(f"Build the client example first: {args.client}")
    if args.tcp_client and not args.tcp_client.is_file():
        parser.error(f"Build the TCP example first: {args.tcp_client}")
    if args.recovery_only and not args.tcp_client:
        parser.error("--recovery-only requires --tcp-client")
    temporary = None
    if args.directory:
        args.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory = args.directory
    else:
        temporary = tempfile.TemporaryDirectory(prefix="tailscalec-client-")
        directory = Path(temporary.name)
    lab = Lab(directory)
    try:
        info = lab.start()
        if args.hold:
            print(f"Private lab credentials: {directory / 'lab.json'}", flush=True)
            deadline = time.monotonic() + args.hold
            while time.monotonic() < deadline:
                time.sleep(min(1, deadline - time.monotonic()))
        elif args.recovery_only:
            run_recovery_tests(lab, args.client.resolve(), args.tcp_client.resolve(), directory, info)
        else:
            run_client_tests(lab, args.client.resolve(), directory, info,
                             args.tcp_client.resolve() if args.tcp_client else None)
    except BaseException:
        lab.diagnose()
        raise
    finally:
        lab.close()
        if temporary:
            temporary.cleanup()


def run_recovery_tests(lab, client, tcp_client, directory, info):
    state = directory / "identity.bin"
    port = free_udp_port()
    message = "prepare-persisted-session-" + uuid.uuid4().hex
    result = command(str(client), "--control-url", info["control_url"],
                     "--auth-key", info["auth_key"], "--state-file", str(state),
                     "--name", "c-client", "--bind", f"0.0.0.0:{port}",
                     "--endpoint", f"{info['gateway']}:{port}",
                     "--listen-port", "32123", "--send", f"{info['reference_ip']}:32123",
                     "--message", message, "--timeout", "15", timeout=30, check=False)
    if result.returncode or "RECEIVED " not in result.stdout or message not in result.stdout:
        raise AssertionError("Cannot prepare persisted WireGuard session: " + result.stdout + result.stderr)
    node_ip = next(line.split()[1] for line in result.stdout.splitlines() if line.startswith("JOINED "))
    print("PASS initial encrypted session for persisted identity", flush=True)
    check_reference_initiated_tcp(lab, tcp_client, directory, info, state, node_ip)
    print("PASS upstream-initiated binary TCP echo after persisted-identity restart", flush=True)
    check_local_key_expiry(lab, client, directory, info, state, node_ip)
    print("PASS local node-key expiry with coordinator offline and map refresh disabled", flush=True)
    print("Focused client recovery interoperability passed.", flush=True)


def run_client_tests(lab, client, directory, info, tcp_client=None):
    state = directory / "identity.bin"
    node_ip = None
    def mark(message):
        print("PASS " + message, flush=True)

    def invoke(message, destination_port=32123, *, auth=True,
               identity=state, malformed=False, expected=True, timeout=12,
               registration_expected=True, listen_port=32123):
        outer_port = free_udp_port()
        arguments = [str(client), "--control-url", info["control_url"],
                     "--state-file", str(identity), "--name", "c-client",
                     "--bind", f"0.0.0.0:{outer_port}",
                     "--endpoint", f"{info['gateway']}:{outer_port}",
                     "--listen-port", str(listen_port), "--send",
                     f"{info['reference_ip']}:{destination_port}",
                     "--message", message, "--timeout", str(timeout)]
        if auth:
            arguments += ["--auth-key", auth if isinstance(auth, str) else info["auth_key"]]
        stdout_path = directory / "invocation.stdout"
        stdout_file = stdout_path.open("w")
        process = subprocess.Popen(arguments, text=True, stdout=stdout_file,
                                   stderr=subprocess.PIPE)
        stop = threading.Event()
        worker = None
        if malformed:
            def inject():
                packets = [b"", b"\x01", b"\x01\x00\x00\x00" + bytes(144),
                           b"\x02\x00\x00\x00" + bytes(88),
                           b"\x04\x00\x00\x00" + bytes(28),
                           b"TS\xf0\x9f\x92\xac" + bytes(64),
                           bytes(2048), bytes(65507)]
                # Polling has not started while the coordinator join blocks.
                # Avoid filling the OS UDP queue before the C event loop runs.
                while not stop.wait(0.01):
                    if "LISTENING " in stdout_path.read_text():
                        break
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    while not stop.wait(0.02):
                        for packet in packets:
                            sock.sendto(packet, ("127.0.0.1", outer_port))
            worker = threading.Thread(target=inject, daemon=True)
            worker.start()
        try:
            _unused, stderr = process.communicate(timeout=timeout + 15)
            stdout_file.flush()
            stdout = stdout_path.read_text()
        except subprocess.TimeoutExpired:
            process.kill()
            _unused, stderr = process.communicate()
            stdout_file.flush()
            stdout = stdout_path.read_text()
            raise AssertionError(f"C client exceeded its bounded timeout: {stdout}{stderr}")
        finally:
            stop.set()
            if worker:
                worker.join(timeout=2)
            stdout_file.close()
        if any(marker in stderr for marker in ("AddressSanitizer", "LeakSanitizer", "runtime error:")):
            raise AssertionError("C client sanitizer diagnostic: " + stderr)
        if expected:
            if process.returncode or f" {message}" not in stdout or "RECEIVED " not in stdout:
                raise AssertionError(f"Encrypted UDP echo failed ({process.returncode}): "
                                     f"{stdout}{stderr}")
            if listen_port == 0:
                ports = [int(line.split()[1]) for line in stdout.splitlines()
                         if line.startswith("LISTENING ")]
                if len(ports) != 1 or not ports[0] or ports[0] == 32123:
                    raise AssertionError("Expected an allocated ephemeral UDP port: " + stdout)
            joined = [line.split()[1] for line in stdout.splitlines()
                      if line.startswith("JOINED ")]
            if len(joined) != 1:
                raise AssertionError(f"Expected one JOINED address: {stdout}")
            return joined[0]
        if registration_expected != ("JOINED " in stdout):
            raise AssertionError(f"Unexpected registration result: {stdout}{stderr}")
        if registration_expected and "Timed out waiting for UDP reply." not in stderr:
            raise AssertionError("UDP policy test failed for an unexpected reason: " + stdout + stderr)
        if not registration_expected and not any(marker in stderr for marker in
                ("/machine/register returned HTTP 400", "/machine/register returned HTTP 401",
                 "/machine/register returned HTTP 403", "server rejected registration:",
                 "interactive authorization required")):
            raise AssertionError("Authentication test failed without server rejection: " + stderr)
        if registration_expected and "SENT " not in stdout:
            raise AssertionError("Denied-port test did not actually transmit encrypted UDP: " + stdout + stderr)
        if process.returncode != 1 or "RECEIVED " in stdout:
            raise AssertionError(f"Denied packet unexpectedly succeeded: {stdout}{stderr}")
        return stdout, stderr

    # Actual peer encrypts and decrypts every payload. The service logs prove it
    # saw the exact application bytes, rather than a successful local send.
    for length in (1, 32, 512, 1200):
        message = ("p" + uuid.uuid4().hex * 40)[:length]
        joined = invoke(message)
        if node_ip is not None and joined != node_ip:
            raise AssertionError("Identity rejoin changed the allocated IPv4 address")
        node_ip = joined
        logs = output("docker", "logs", lab.echo_name)
        if not any(json.loads(line).get("hex") == message.encode().hex()
                   for line in logs.splitlines() if line.startswith("{")):
            raise AssertionError("Upstream UDP service did not receive the expected bytes")
    mark("encrypted UDP echoes (1,32,512,1200 bytes)")
    if invoke("ephemeral-client-return-policy", listen_port=0) != node_ip:
        raise AssertionError("Ephemeral UDP source changed node identity")
    mark("ephemeral UDP source receives only its tracked return traffic")
    original_identity = state.read_bytes()
    if state.stat().st_mode & 0o077:
        raise AssertionError("Persisted identity is accessible to group or other users")
    for index in range(3):
        if invoke(f"persistent-identity-{index}", auth=False) != node_ip:
            raise AssertionError("Restart without auth key did not retain node address")
        if state.read_bytes() != original_identity:
            raise AssertionError("Restart modified persisted identity keys")
        if len(lab.nodes()) != 2:
            raise AssertionError("Restart created duplicate Headscale nodes")
    mark("3 identity-preserving restarts without auth key")
    invoke("must-never-arrive-" + uuid.uuid4().hex,
           destination_port=32124, timeout=12, expected=False)
    echo_events = [json.loads(line) for line in output("docker", "logs", lab.echo_name).splitlines()
                   if line.startswith("{")]
    if any(event["port"] == 32124 for event in echo_events):
        raise AssertionError("Denied UDP port reached the real upstream application")
    mark("coordinator policy permits 32123 and blocks 32124")
    if invoke("malformed-packets-do-not-break-session", malformed=True) != node_ip:
        raise AssertionError("Malformed outer packets changed node identity")
    mark("valid traffic during truncated/oversized/forged outer datagrams")
    invalid_key = "hskey-auth-" + "0" * 12 + "-" + "0" * 64
    invoke("invalid-auth-must-fail", auth=invalid_key,
           identity=directory / "unauthorized-identity.bin", expected=False,
           registration_expected=False, timeout=3)
    if len(lab.nodes()) != 2:
        raise AssertionError("Invalid authentication created an authorized node")
    mark("fresh-node authentication rejects an invalid auth key")
    check_reference_initiated_udp(lab, client, directory, info, state, node_ip)
    mark("upstream-initiated UDP echo and authenticated DISCO direct-path ping")
    if tcp_client:
        run_tcp_tests(lab, tcp_client, directory, info, state, node_ip)
        mark("TCP stream echoes (1,32789 bytes), policy denial, upstream-initiated echo")
    check_local_key_expiry(lab, client, directory, info, state, node_ip)
    mark("local node-key expiry enforced while coordinator is unavailable")
    print("Headscale + upstream Tailscale encrypted-client interoperability passed.", flush=True)


if __name__ == "__main__":
    main()
