#!/bin/sh
# generate-config.sh - interactively generate a BypassCore config.json.
#
# POSIX sh; works with bash, dash and OpenWrt's ash. Prompts for a SOCKS5
# inbound, an optional upstream proxy (SOCKS5 or HTTPS CONNECT), optional
# built-in DNS, then writes the config and validates it with the bypasscore
# binary when available.
#
# Usage: scripts/generate-config.sh [output-path]

set -u

die() {
	echo "error: $*" >&2
	exit 1
}

# prompt VAR "message" "default"
prompt() {
	_var=$1
	_msg=$2
	_default=${3:-}
	if [ -n "$_default" ]; then
		printf '%s [%s]: ' "$_msg" "$_default"
	else
		printf '%s: ' "$_msg"
	fi
	read -r _answer || exit 1
	if [ -z "$_answer" ]; then
		_answer=$_default
	fi
	eval "$_var=\$_answer"
}

# prompt_yesno "message" default(y|n) -> returns 0 for yes
prompt_yesno() {
	_msg=$1
	_default=${2:-y}
	prompt _yn "$_msg (y/n)" "$_default"
	case $_yn in
	y | Y | yes | YES) return 0 ;;
	*) return 1 ;;
	esac
}

# json_escape STRING -> prints a JSON-safe string literal (with quotes)
json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | awk 'BEGIN{printf "\""}{printf "%s", $0}END{printf "\""}'
}

is_port() {
	case $1 in
	'' | *[!0-9]*) return 1 ;;
	esac
	[ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

echo "BypassCore config generator"
echo "==========================="
echo

output=${1:-}
if [ -z "$output" ]; then
	prompt output "Output config path" "./config.json"
fi
[ -e "$output" ] && ! prompt_yesno "$output exists, overwrite?" "n" && die "aborted"

# --- SOCKS5 inbound ---
echo
echo "-- Local SOCKS5 inbound --"
prompt listen "Listen address" "127.0.0.1"
prompt port "Listen port" "1080"
is_port "$port" || die "invalid port: $port"
prompt network "Network (tcp or tcp,udp)" "tcp"

# --- Outbound ---
echo
echo "-- Upstream outbound --"
echo "  1) direct only (no upstream proxy)"
echo "  2) SOCKS5 upstream proxy"
echo "  3) HTTPS CONNECT upstream proxy"
prompt mode "Choose [1-3]" "1"

upstream_json=""
final_tag="direct"
case $mode in
2 | 3)
	[ "$mode" = "2" ] && protocol=socks || protocol=https
	prompt server "Upstream server (host:port)" ""
	[ -z "$server" ] && die "upstream server is required"
	settings=""
	if prompt_yesno "Does the upstream require authentication?" "n"; then
		prompt username "Username" ""
		prompt password "Password" ""
		settings="\"username\": $(json_escape "$username"), \"password\": $(json_escape "$password")"
	fi
	if [ "$protocol" = "https" ]; then
		host=${server%%:*}
		prompt tls_name "TLS server name" "$host"
		[ -n "$settings" ] && settings="$settings, "
		settings="${settings}\"tlsServerName\": $(json_escape "$tls_name")"
		if prompt_yesno "Enable HTTP/2 to the upstream?" "y"; then
			settings="$settings, \"enableHTTP2\": true"
		fi
	fi
	settings_json=""
	[ -n "$settings" ] && settings_json=",
        \"settings\": { $settings }"
	upstream_json=",
    {
      \"tag\": \"proxy\",
      \"mode\": \"proxy\",
      \"upstream\": {
        \"protocol\": \"$protocol\",
        \"server\": $(json_escape "$server")$settings_json
      }
    }"
	final_tag="proxy"
	;;
*) ;;
esac

# --- DNS ---
dns_json=""
echo
if prompt_yesno "Configure built-in DNS (multi-upstream, caching, DoH/DoT)?" "n"; then
	prompt dns_server "DNS upstream address (e.g. 8.8.8.8, tls://1.1.1.1:853, https://dns.google/dns-query)" "8.8.8.8"
	dns_json=",
  \"dns\": {
    \"servers\": [
      { \"address\": $(json_escape "$dns_server") }
    ]
  }"
fi

# --- Write config ---
cat >"$output" <<EOF
{
  "outbounds": [
    {
      "tag": "direct",
      "mode": "freedom"
    },
    {
      "tag": "block",
      "mode": "blackhole"
    }$upstream_json
  ],
  "routing": {
    "finalOutboundTag": "$final_tag"
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "type": "socks",
      "listen": $(json_escape "$listen"),
      "port": $port,
      "network": $(json_escape "$network")
    }
  ]$dns_json
}
EOF

echo
echo "Wrote $output"

# --- Validate with the bypasscore binary when available ---
binary=${BYPASSCORE_BIN:-}
if [ -z "$binary" ]; then
	script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
	for candidate in "$script_dir/../bin/bypasscore" "$(command -v bypasscore 2>/dev/null || true)"; do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			binary=$candidate
			break
		fi
	done
fi
if [ -n "$binary" ]; then
	if "$binary" -config "$output" -check-config; then
		echo "Config validated OK with $binary"
	else
		die "generated config failed validation"
	fi
else
	echo "bypasscore binary not found; skipping validation"
	echo "(set BYPASSCORE_BIN=/path/to/bypasscore to enable it)"
fi
