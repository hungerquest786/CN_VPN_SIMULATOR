#!/bin/bash
# Bad network on the router link (10.0.2.0/24), both directions.
# Usage: sudo ./netem.sh good|normal|bad|off|show
[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }
case "$1" in
    good)   OPTS="delay 10ms 2ms loss 0.1% rate 100mbit" ;;  # values chosen by us
    normal) OPTS="delay 50ms 10ms loss 1% rate 20mbit" ;;
    bad)    OPTS="delay 150ms 30ms loss 5% rate 5mbit" ;;
    off)    OPTS="" ;;
    show)   for r in router1 router2; do echo "== $r"; ip netns exec $r tc qdisc show dev eth1; done; exit 0 ;;
    *) echo "Usage: sudo $0 good|normal|bad|off|show"; exit 1 ;;
esac
for r in router1 router2; do          # each router shapes what it sends out
    if [ -z "$OPTS" ]; then
        ip netns exec $r tc qdisc del dev eth1 root 2>/dev/null
    else
        ip netns exec $r tc qdisc replace dev eth1 root netem $OPTS
    fi
done
echo "netem: $1 ${OPTS:+($OPTS)}"
