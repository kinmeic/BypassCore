#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
PIDS=()

cleanup() {
	status=$?
  set +e
	if [ "$status" -ne 0 ]; then
		for log in "$TMP"/*.log; do
			[ -f "$log" ] || continue
			echo "===== $log ====="
			cat "$log"
		done
	fi
  for pid in "${PIDS[@]:-}"; do sudo kill "$pid" 2>/dev/null || true; done
  sudo ip netns del bc-client 2>/dev/null || true
  sudo ip netns del bc-server 2>/dev/null || true
  sudo ip link del bc-client 2>/dev/null || true
  sudo ip link del bc-server 2>/dev/null || true
  sudo ip rule del fwmark 1 table 100 2>/dev/null || true
  sudo ip -6 rule del fwmark 1 table 100 2>/dev/null || true
	if [ -f "$TMP/iptables.rules" ]; then sudo iptables-restore <"$TMP/iptables.rules"; fi
	if [ -f "$TMP/ip6tables.rules" ]; then sudo ip6tables-restore <"$TMP/ip6tables.rules"; fi
  rm -rf "$TMP"
	return "$status"
}
trap cleanup EXIT

go build -o "$TMP/bypasscore" "$ROOT/cmd/bypasscore"
go build -o "$TMP/netns-helper" "$ROOT/integration/netns/helper"
sudo iptables-save >"$TMP/iptables.rules"
sudo ip6tables-save >"$TMP/ip6tables.rules"

sudo ip netns add bc-client
sudo ip netns add bc-server
sudo ip link add bc-client type veth peer name eth0 netns bc-client
sudo ip link add bc-server type veth peer name eth0 netns bc-server
sudo ip addr add 10.10.0.1/24 dev bc-client
sudo ip addr add fd00:10::1/64 dev bc-client nodad
sudo ip addr add 10.20.0.1/24 dev bc-server
sudo ip addr add fd00:20::1/64 dev bc-server nodad
sudo ip link set bc-client up
sudo ip link set bc-server up

sudo ip netns exec bc-client ip link set lo up
sudo ip netns exec bc-client ip link set eth0 up
sudo ip netns exec bc-client ip addr add 10.10.0.2/24 dev eth0
sudo ip netns exec bc-client ip addr add fd00:10::2/64 dev eth0 nodad
sudo ip netns exec bc-client ip route add default via 10.10.0.1
sudo ip netns exec bc-client ip -6 route add default via fd00:10::1

sudo ip netns exec bc-server ip link set lo up
sudo ip netns exec bc-server ip link set eth0 up
sudo ip netns exec bc-server ip addr add 10.20.0.2/24 dev eth0
sudo ip netns exec bc-server ip addr add fd00:20::2/64 dev eth0 nodad
sudo ip netns exec bc-server ip route add default via 10.20.0.1
sudo ip netns exec bc-server ip -6 route add default via fd00:20::1
sudo ip netns exec bc-server iptables -A INPUT -p udp --dport 20000:21999 -j DROP

sudo sysctl -qw net.ipv4.ip_forward=1
sudo sysctl -qw net.ipv6.conf.all.forwarding=1
sudo sysctl -qw net.ipv4.conf.all.rp_filter=0
sudo sysctl -qw net.ipv4.conf.bc-client.rp_filter=0
sudo sysctl -qw net.ipv4.conf.bc-server.rp_filter=0

sudo ip rule add fwmark 1 table 100
sudo ip route add local 0.0.0.0/0 dev lo table 100
sudo ip -6 rule add fwmark 1 table 100
sudo ip -6 route add local ::/0 dev lo table 100

sudo iptables -t nat -A PREROUTING -i bc-client -d 10.20.0.2 -p tcp --dport 18080 -j REDIRECT --to-ports 12345
sudo iptables -t mangle -A PREROUTING -i bc-client -d 10.20.0.2 -p tcp --dport 18081 -j TPROXY --on-port 12346 --tproxy-mark 1/1
sudo iptables -t mangle -A PREROUTING -i bc-client -d 10.20.0.2 -p udp --dport 18082 -j TPROXY --on-port 12346 --tproxy-mark 1/1
sudo iptables -t mangle -A PREROUTING -i bc-client -d 10.20.0.2 -p udp --dport 18085 -j TPROXY --on-port 12347 --tproxy-mark 1/1
sudo iptables -t mangle -A PREROUTING -i bc-client -d 10.20.0.2 -p udp --dport 20000:21999 -j TPROXY --on-port 12346 --tproxy-mark 1/1
sudo ip6tables -t mangle -A PREROUTING -i bc-client -d fd00:20::2 -p tcp --dport 18083 -j TPROXY --on-port 12348 --tproxy-mark 1/1
sudo ip6tables -t mangle -A PREROUTING -i bc-client -d fd00:20::2 -p udp --dport 18084 -j TPROXY --on-port 12348 --tproxy-mark 1/1

sudo ip netns exec bc-server "$TMP/netns-helper" -mode serve -listen 0.0.0.0 -tcp-ports 18080,18081 -udp-ports 18082,18085 >"$TMP/server4.log" 2>&1 & PIDS+=("$!")
sudo ip netns exec bc-server "$TMP/netns-helper" -mode serve -listen :: -tcp-ports 18083 -udp-ports 18084 >"$TMP/server6.log" 2>&1 & PIDS+=("$!")
sudo ip netns exec bc-server "$TMP/netns-helper" -mode socks -listen 10.20.0.2:1080 >"$TMP/socks.log" 2>&1 & PIDS+=("$!")
sudo sh -c 'echo $$ >"$1"; exec "$2" -run -config "$3" -log-level warning' sh \
  "$TMP/bypass.pid" "$TMP/bypasscore" "$ROOT/integration/netns/config.json" >"$TMP/bypass.log" 2>&1 &
PIDS+=("$!")
for _ in $(seq 1 50); do
  [ -s "$TMP/bypass.pid" ] && break
  sleep 0.1
done
BYPASS_PID="$(cat "$TMP/bypass.pid")"
PIDS+=("$BYPASS_PID")
sleep 1
if ! sudo kill -0 "$BYPASS_PID"; then
  cat "$TMP/bypass.log"
  exit 1
fi

sudo ip netns exec bc-client "$TMP/netns-helper" -mode tcp-client -target 10.20.0.2:18080 -payload redirect-ok
sudo ip netns exec bc-client "$TMP/netns-helper" -mode tcp-client -target 10.20.0.2:18081 -payload tproxy-tcp-ok
sudo ip netns exec bc-client "$TMP/netns-helper" -mode udp-client -target 10.20.0.2:18082 -payload tproxy-udp-source-ok
sudo ip netns exec bc-client "$TMP/netns-helper" -mode tcp-client -target '[fd00:20::2]:18083' -payload ipv6-tcp-ok
sudo ip netns exec bc-client "$TMP/netns-helper" -mode udp-client -target '[fd00:20::2]:18084' -payload ipv6-udp-ok
sudo ip netns exec bc-client "$TMP/netns-helper" -mode udp-client -target 10.20.0.2:18085 -payload socks-udp-ok
sudo ip netns exec bc-client "$TMP/netns-helper" -mode dns-client -network udp -target 10.10.0.1:1053 -domain listener.test -want-ip 192.0.2.53
sudo ip netns exec bc-client "$TMP/netns-helper" -mode dns-client -network tcp -target 10.10.0.1:1053 -domain listener.test -want-ip 192.0.2.53
sudo ip netns exec bc-client "$TMP/netns-helper" -mode dns-client -network udp6 -target '[fd00:10::1]:1053' -domain listener6.test -want-ip 2001:db8::53
sudo ip netns exec bc-client "$TMP/netns-helper" -mode dns-client -network tcp6 -target '[fd00:10::1]:1053' -domain listener6.test -want-ip 2001:db8::53

sudo ip netns exec bc-client "$TMP/netns-helper" -mode flood -target 10.20.0.2 -start-port 20000 -count 1200
sleep 2
FD_COUNT="$(sudo find "/proc/$BYPASS_PID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
RSS_KB="$(sudo awk '/VmRSS:/ {print $2}' "/proc/$BYPASS_PID/status")"
test "$FD_COUNT" -le 2200
test "$RSS_KB" -le 196608
grep -q "UDP relay session limit reached" "$TMP/bypass.log"
sudo kill -0 "$BYPASS_PID"
echo "resource bounds: fd=$FD_COUNT rss_kb=$RSS_KB"
