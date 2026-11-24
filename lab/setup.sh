#!/bin/bash
# Builds the lab: 7 namespaces, 2 bridges (switches), addresses, routes.
set -e
[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }
cd "$(dirname "$0")"
./teardown.sh >/dev/null 2>&1 || true   # start clean

# 1. namespaces
for ns in client1 client2 client3 router1 router2 serverA serverB; do
    ip netns add $ns
    ip -n $ns link set lo up
done

# 2. bridges (switches) live in the normal namespace, no IP on them
for br in br-s1 br-s3; do
    ip link add $br type bridge
    ip link set $br up
done

# connect NS to a bridge with a cable (veth): attach NS BRIDGE IP/MASK
attach() {
    local ns=$1 br=$2 ip=$3
    ip link add h-$ns type veth peer name eth0 netns $ns   # h-$ns stays on host
    ip link set h-$ns master $br up
    ip -n $ns addr add $ip dev eth0
    ip -n $ns link set eth0 up
}

# 3. clients side (10.0.1.0/24) on br-s1
attach router1 br-s1 10.0.1.1/24
attach client1 br-s1 10.0.1.2/24
attach client2 br-s1 10.0.1.3/24
attach client3 br-s1 10.0.1.4/24

# 4. servers side (10.0.3.0/24) on br-s3
attach router2 br-s3 10.0.3.1/24
attach serverA br-s3 10.0.3.2/24
attach serverB br-s3 10.0.3.3/24

# 5. router link (10.0.2.0/24): direct cable router1 eth1 <-> router2 eth1
ip link add eth1 netns router1 type veth peer name eth1 netns router2
ip -n router1 addr add 10.0.2.1/24 dev eth1
ip -n router2 addr add 10.0.2.2/24 dev eth1
ip -n router1 link set eth1 up
ip -n router2 link set eth1 up

# 6. routing
for r in router1 router2; do
    ip netns exec $r sysctl -qw net.ipv4.ip_forward=1
done
ip -n router1 route add 10.0.3.0/24 via 10.0.2.2
ip -n router2 route add 10.0.1.0/24 via 10.0.2.1
for c in client1 client2 client3; do ip -n $c route add default via 10.0.1.1; done
for s in serverA serverB;         do ip -n $s route add default via 10.0.3.1; done

echo "Lab is up. Run ./test.sh to check it."
