#!/usr/bin/env python3
"""Tiny reference UDP and TCP services, run beside a userspace-networking tailscaled.

It listens on allowed and denied ports. Receiving a denied-port datagram is an
error in the integration assertions, not merely an absent service.
"""
import json
import selectors
import socket
import socketserver
import threading

class TCPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        try:
            while True:
                payload = self.request.recv(65535)
                if not payload:
                    break
                print(json.dumps({"protocol": "tcp", "port": self.server.server_address[1],
                                  "source": self.client_address[0], "length": len(payload),
                                  "hex": payload.hex()}), flush=True)
                self.request.sendall(payload)
        except (OSError, TimeoutError):
            pass


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


for port in (32123, 32124):
    server = TCPServer(("0.0.0.0", port), TCPEcho)
    threading.Thread(target=server.serve_forever, daemon=True).start()

selector = selectors.DefaultSelector()
for port in (32123, 32124):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    sock.setblocking(False)
    selector.register(sock, selectors.EVENT_READ)
print("READY", flush=True)
while True:
    for key, _ in selector.select():
        sock = key.fileobj
        payload, source = sock.recvfrom(65535)
        print(json.dumps({"protocol": "udp", "port": sock.getsockname()[1], "source": source[0],
                          "length": len(payload), "hex": payload.hex()}), flush=True)
        sock.sendto(payload, source)
