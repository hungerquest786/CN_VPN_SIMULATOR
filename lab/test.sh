#!/bin/bash
# Checks the lab works.
[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }
echo "== ping client1 -> serverA"; ip netns exec client1 ping -c 3 -W 2 10.0.3.2
echo "== ping client1 -> serverB"; ip netns exec client1 ping -c 3 -W 2 10.0.3.3
echo "== traceroute client1 -> serverA (expect 10.0.1.1, 10.0.2.2, 10.0.3.2)"
if command -v traceroute >/dev/null; then
    ip netns exec client1 traceroute -n -w 2 10.0.3.2
else
    echo "traceroute missing: sudo apt install traceroute"
fi
for ns in client1 client2 client3 router1 router2 serverA serverB; do
    echo "== routes in $ns"; ip -n $ns route
done
