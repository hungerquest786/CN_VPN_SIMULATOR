#!/bin/bash
# Removes the whole lab. Safe to run twice.
[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }
for ns in client1 client2 client3 router1 router2 serverA serverB; do
    ip netns del $ns 2>/dev/null   # also removes the veth cables inside it
done
for br in br-s1 br-s3; do
    ip link del $br 2>/dev/null
done
echo "Lab removed."
