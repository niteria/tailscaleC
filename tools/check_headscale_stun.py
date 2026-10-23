#!/usr/bin/env python3
"""Exercise the C STUN module against disposable, self-hosted Headscale.

This checks STUN interoperability only, not registration or encrypted traffic.
Requires Docker, OpenSSL CLI, and a built STUN-enabled stun-probe executable.
"""
import argparse
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

IMAGE = "ghcr.io/juanfont/headscale:0.29.5"


def capture(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, default=root / "build/stun-probe")
    args = parser.parse_args()
    probe = args.probe.resolve()
    if not probe.is_file():
        parser.error(f"Build a STUN-enabled probe first: {probe}")
    for tool in ("docker", "openssl"):
        if not shutil.which(tool):
            parser.error(f"Missing required tool: {tool}")

    container = None
    with tempfile.TemporaryDirectory(prefix="tailscalec-headscale-") as temporary:
        config = Path(temporary)
        shutil.copyfile(root / "tests/interop/headscale.yaml", config / "config.yaml")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout", str(config / "key.pem"),
            "-out", str(config / "cert.pem"),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=30)
        # Test-only certificate; the root container has no DAC override cap.
        config.chmod(0o755)
        (config / "key.pem").chmod(0o644)
        try:
            # Ports are bound only to loopback and allocated by Docker. State is
            # in container tmpfs. No host TUN device, routes or daemon is touched.
            container = capture(
                "docker", "create", "--user", "0:0",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--tmpfs", "/var/lib/headscale:rw,noexec,nosuid,size=64m",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m",
                "--publish", "127.0.0.1::8080/tcp",
                "--publish", "127.0.0.1::3478/udp", IMAGE,
                "--config", "/etc/headscale/config.yaml", "serve")
            # Copy fixtures rather than bind-mounting host paths, so this also
            # works when Docker runs in a VM or a different mount namespace.
            capture("docker", "cp", f"{config}/.", f"{container}:/etc/headscale")
            capture("docker", "start", container)
            details = json.loads(capture("docker", "inspect", container))[0]
            ports = details["NetworkSettings"]["Ports"]
            tcp = ports["8080/tcp"][0]["HostPort"]
            udp = ports["3478/udp"][0]["HostPort"]
            context = ssl.create_default_context(cafile=str(config / "cert.pem"))
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=context))
            deadline = time.monotonic() + 20
            while True:
                try:
                    with opener.open(f"https://127.0.0.1:{tcp}/health", timeout=1) as response:
                        if response.status == 200:
                            break
                except (urllib.error.URLError, TimeoutError):
                    running = capture("docker", "inspect", "--format",
                                      "{{.State.Running}}", container)
                    if running != "true":
                        raise RuntimeError("Headscale exited before becoming healthy")
                if time.monotonic() >= deadline:
                    raise RuntimeError("Headscale did not become healthy within 20 seconds")
                time.sleep(0.1)
            print(f"Testing C STUN against {IMAGE}", flush=True)
            subprocess.run([str(probe), "127.0.0.1", udp], check=True, timeout=20)
            print("Headscale STUN interoperability passed (registration is not implemented).")
        except BaseException:
            if container:
                subprocess.run(["docker", "logs", "--tail", "30", container], timeout=10)
            raise
        finally:
            if container:
                subprocess.run(["docker", "rm", "--force", container],
                               check=True, stdout=subprocess.DEVNULL, timeout=20)


if __name__ == "__main__":
    main()
