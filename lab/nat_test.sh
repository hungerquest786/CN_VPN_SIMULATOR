#!/bin/bash
# Section 5 test: shows the source address serverB sees, through the tunnel and directly.
# Start the server and a client with --split (or --full) first.
[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }
URL=http://10.0.3.3:8080

# Tiny web server in serverB: it answers every request with the address the request came from.
ip netns exec serverB python3 -c '
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"your source address: {self.client_address[0]}\n".encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(("10.0.3.3", 8080), H).serve_forever()' &
WEB=$!
trap 'kill $WEB 2>/dev/null' EXIT
sleep 1

# The normal network card of client1 (the one with the default route).
NIC=$(ip -n client1 route show default | awk '{print $5}')

echo "== through the tunnel (expect 10.0.3.2 = NAT)"
ip netns exec client1 curl -s -m 5 $URL || echo "failed (is the client running with --split or --full?)"
echo "== directly (expect 10.0.1.2); --interface $NIC skips the tun0 routes"
ip netns exec client1 curl -s -m 5 --interface $NIC $URL || echo "failed"
