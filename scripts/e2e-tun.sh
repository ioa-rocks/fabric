#!/usr/bin/env bash
# End-to-end test of the TUN bridge (mode C): two nodes in separate network
# namespaces joined by a veth pair, each with a real fabric0 device, then
# ICMP and TCP across the overlay addresses. Needs root (netns + TUN); all
# state is throwaway — nothing touches ~/.config/fabric or real interfaces.
#
#   go build -o fabric ./cmd/fabric && sudo scripts/e2e-tun.sh
set -euo pipefail

FABRIC=${FABRIC:-$(cd "$(dirname "$0")/.." && pwd)/fabric}
[ -x "$FABRIC" ] || { echo "no binary at $FABRIC — go build -o fabric ./cmd/fabric first"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "needs root: sudo $0"; exit 1; }

export FABRIC_PASSPHRASE=e2e
WORK=$(mktemp -d)
PIDS=()
cleanup() {
  set +e
  kill "${PIDS[@]}" 2>/dev/null
  sleep 0.3
  ip netns del fabA 2>/dev/null
  ip netns del fabB 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "wiring two network namespaces (fabA <-veth-> fabB)"
ip netns add fabA
ip netns add fabB
ip link add vA type veth peer name vB
ip link set vA netns fabA
ip link set vB netns fabB
ip -n fabA link set lo up; ip -n fabA addr add 10.77.0.1/24 dev vA; ip -n fabA link set vA up
ip -n fabB link set lo up; ip -n fabB addr add 10.77.0.2/24 dev vB; ip -n fabB link set vB up

A() { ip netns exec fabA "$@"; }
B() { ip netns exec fabB "$@"; }

step "master: init + up in fabA"
"$FABRIC" init -state "$WORK/a" -name master -listen /ip4/10.77.0.1/tcp/4517
A "$FABRIC" up -state "$WORK/a" >"$WORK/a.log" 2>&1 &
PIDS+=($!)
sleep 2
ADDR=$(grep -o '/ip4/10.77.0.1[^ ]*' "$WORK/a.log" | head -1)
echo "bootstrap: $ADDR"

step "joiner: join from fabB, approve on master"
B "$FABRIC" join -state "$WORK/b" -name peer -listen /ip4/10.77.0.2/tcp/4517 -bootstrap "$ADDR" >"$WORK/join.log" 2>&1 &
PIDS+=($!)
sleep 2
FP=$("$FABRIC" pending -state "$WORK/a" | awk '{print $1; exit}')
"$FABRIC" approve -state "$WORK/a" "$FP"
sleep 4

step "joiner: up in fabB"
B "$FABRIC" up -state "$WORK/b" >"$WORK/b.log" 2>&1 &
PIDS+=($!)
sleep 3

step "TUN devices"
grep -h 'tun:' "$WORK/a.log" "$WORK/b.log"
grep -q 'tun: fabric0 up' "$WORK/a.log" || { echo "FAIL: master TUN did not come up"; exit 1; }
grep -q 'tun: fabric0 up' "$WORK/b.log" || { echo "FAIL: joiner TUN did not come up"; exit 1; }

step "ICMP across the overlay (master .1 -> peer .2)"
A ping -c 3 -W 3 100.64.0.2

step "ICMP with a near-MTU payload"
A ping -c 2 -W 3 -s 1300 100.64.0.2

step "TCP across the overlay"
B python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("100.64.0.2", 9999)); s.listen(1); s.settimeout(15)
c, addr = s.accept()
print("server: connection from", addr[0])
c.sendall(b"fabric-tun-e2e-ok\n"); c.close()
' &
PIDS+=($!)
sleep 1
GOT=$(A python3 -c '
import socket
s = socket.create_connection(("100.64.0.2", 9999), timeout=10)
print(s.recv(64).decode().strip())
')
echo "client received: $GOT"
[ "$GOT" = "fabric-tun-e2e-ok" ] || { echo "FAIL: TCP payload mismatch"; exit 1; }

step ".fabric DNS (ask the master's resolver for the peer's name)"
GOT_IP=$(A python3 -c '
import socket, struct
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x04peer\x06fabric\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(q, ("100.64.0.1", 53))
r, _ = s.recvfrom(512)
assert r[3] & 0x0f == 0, "rcode %d" % (r[3] & 0x0f)
print(socket.inet_ntoa(r[-4:]))
')
echo "peer.fabric -> $GOT_IP"
[ "$GOT_IP" = "100.64.0.2" ] || { echo "FAIL: DNS answered $GOT_IP"; exit 1; }

step "roster as the master sees it"
"$FABRIC" status -state "$WORK/a"

printf '\n\033[1;32mE2E OK: TCP and ICMP flow across the fabric overlay.\033[0m\n'
