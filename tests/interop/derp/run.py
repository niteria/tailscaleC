#!/usr/bin/env python3
"""Run the C DERP implementation against upstream Go DERP server and peer."""
import argparse
import json
from pathlib import Path
import selectors
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True, type=Path,
                        help="path to test-derp-live executable")
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    client = args.client.resolve()
    with tempfile.TemporaryDirectory(prefix="tailscalec-derp-") as temporary:
        server = Path(temporary) / "derp-server"
        subprocess.run(["go", "build", "-o", str(server), "server.go"],
                       cwd=fixture, check=True, timeout=300)
        with tempfile.TemporaryFile(mode="w+") as log:
            process = subprocess.Popen([str(server)], stdout=subprocess.PIPE,
                                       stderr=log, text=True)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    if not selector.select(15):
                        raise TimeoutError("Go DERP fixture did not respond")
                    ready = json.loads(process.stdout.readline())
                host, port = ready["address"].rsplit(":", 1)
                print("Testing against", ready["upstream"], flush=True)
                subprocess.run([str(client), host, port, ready["peer_key"]],
                               check=True, timeout=90)
            except Exception:
                log.seek(0)
                print(log.read())
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    main()
