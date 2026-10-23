#!/usr/bin/env python3
"""Exercise native C DISCO against upstream Go DISCO and NaCl over real UDP."""
import argparse
import json
from pathlib import Path
import selectors
import subprocess
import tempfile


def read_json(process, timeout):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise TimeoutError("Go DISCO fixture did not respond")
        return json.loads(process.stdout.readline())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True, type=Path)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="tailscalec-disco-") as temporary:
        server = Path(temporary) / "disco-server"
        subprocess.run(["go", "build", "-o", str(server), "server.go"],
                       cwd=fixture, check=True, timeout=300)
        with tempfile.TemporaryFile(mode="w+") as log:
            process = subprocess.Popen([str(server)], stdout=subprocess.PIPE,
                                       stderr=log, text=True)
            try:
                ready = read_json(process, 10)
                host, port = ready["address"].rsplit(":", 1)
                print("Testing against", ready["upstream"], flush=True)
                subprocess.run([str(args.client.resolve()), host, port,
                                ready["disco_key"], ready["node_key"]],
                               check=True, timeout=30)
                result = read_json(process, 10)
                if result != {"passed": True, "c_pings": 200, "c_pongs": 200}:
                    raise AssertionError(result)
                if process.wait(timeout=5) != 0:
                    raise RuntimeError("Go DISCO validation failed")
            except Exception:
                log.seek(0)
                print(log.read())
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


if __name__ == "__main__":
    main()
