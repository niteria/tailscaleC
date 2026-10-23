#!/usr/bin/env python3
"""Exercise the small streaming/mbedTLS profile against disposable Headscale.

Only the coordinator's port is published, on loopback. No host Tailscale state,
TUN interfaces, routes or device credentials are used.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import tempfile
import time
import urllib.request
import uuid


def run(*args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, timeout=60,
                          check=True, **kwargs).stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--serve", type=int, default=0, help="Keep a disposable hardware lab running for this many seconds")
    args = parser.parse_args()
    client = args.client.resolve() if args.client else None
    if not client and not args.serve:
        parser.error("--client or --serve is required")
    def terminate(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, terminate)
    name = "tsc-obk-control-" + uuid.uuid4().hex[:10]
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="tsc-obk-control-", dir=args.output.resolve().parent) as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        (root / "config.yaml").write_text(f"""
server_url: http://127.0.0.1:{port}
listen_addr: 0.0.0.0:8080
metrics_listen_addr: ""
grpc_listen_addr: 127.0.0.1:50443
disable_check_updates: true
noise:
  private_key_path: /var/lib/headscale/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: false
  urls: []
  paths: [/etc/headscale/derp.yaml]
  auto_update_enabled: false
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
log:
  level: warn
policy:
  mode: file
  path: /etc/headscale/policy.json
dns:
  magic_dns: false
  base_domain: lab.test
  override_local_dns: false
  nameservers:
    global: []
unix_socket: /var/lib/headscale/headscale.sock
unix_socket_permission: "0700"
""")
        (root / "policy.json").write_text(json.dumps({"acls": [
            {"action": "accept", "src": ["*"], "dst": ["*:*"]}]}))
        (root / "derp.yaml").write_text("""
regions:
  999:
    regionid: 999
    regioncode: local
    regionname: Local test
    nodes:
      - name: local-stun
        regionid: 999
        hostname: 127.0.0.1
        ipv4: 127.0.0.1
        stunport: 3478
        stunonly: true
""")
        image = "ghcr.io/juanfont/headscale:0.29.5"
        results = []
        try:
            run("podman", "run", "-d", "--name", name, "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "-p", f"127.0.0.1:{port}:8080",
                "--tmpfs", "/var/lib/headscale:rw,size=64m",
                "-v", f"{root}:/etc/headscale:ro", image,
                "--config", "/etc/headscale/config.yaml", "serve")
            url = f"http://127.0.0.1:{port}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            for _ in range(100):
                try:
                    with opener.open(url + "/health", timeout=1) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Headscale did not become ready: " + run("podman", "logs", name))
            def headscale(*command):
                return run("podman", "exec", name, "headscale", "--config",
                           "/etc/headscale/config.yaml", *command, "--output", "json")
            user = json.loads(headscale("users", "create", "lab"))["id"]
            auth = json.loads(headscale("preauthkeys", "create", "--user", str(user),
                                       "--reusable", "--expiration", "1h"))["key"]
            if args.serve:
                with opener.open(url + "/key?v=131", timeout=5) as response:
                    public_key = json.load(response)["publicKey"]
                session = {"container": name, "url": url, "auth_key": auth,
                           "server_key": public_key, "port": port}
                descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w") as f:
                    json.dump(session, f)
                print("Disposable coordinator ready on loopback port", port, flush=True)
                time.sleep(args.serve)
                return
            for peers in range(3):
                env = dict(os.environ, TSC_TEST_CONTROL_URL=url, TSC_TEST_AUTH_KEY=auth)
                result = run(str(client), env=env)
                if f"peers={peers} " not in result:
                    raise RuntimeError("Unexpected coordinator map: " + result)
                results.append(result)
                print(result, flush=True)
            nodes = json.loads(headscale("nodes", "list"))
            if len(nodes) != 3:
                raise RuntimeError("Expected three independent registered nodes")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps({"success": True, "image": image,
                "client": str(client), "joins_and_refreshes": results,
                "nodes": len(nodes)}, indent=2) + "\n")
        finally:
            subprocess.run(["podman", "rm", "-f", name], capture_output=True, timeout=20)


if __name__ == "__main__":
    main()
