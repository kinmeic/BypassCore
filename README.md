# BypassCore

An independent Go transparent-proxy routing core. It can take the place of the
Xray-core routing component in passwall2: receive TPROXY traffic, recover the
domain through sniffing, match routing rules, and forward through an outbound.

## Features

- Transparent inbound: TCP REDIRECT (`SO_ORIGINAL_DST`) and UDP TPROXY
  (`IP_TRANSPARENT` + `IP_RECVORIGDSTADDR`)
- TLS/HTTP/QUIC sniffing: recover TLS SNI, HTTP Host, or QUIC Initial SNI from
  IP-only connections so domain rules also work for transparent traffic
- Rule matching by domain, IP (CIDR + GeoIP), port, network, protocol,
  inboundTag, user, process, and attributes
- GeoData rules with `geosite:` and `geoip:`, loading `geoip.dat` and
  `geosite.dat`
- Outbounds: `freedom` direct connections with source-IP/interface binding,
  `blackhole`, and a SOCKS5 `proxy` for naiveproxy or sing-box
- DNS subsystem with multiple upstreams, caching, domain routing, IP filtering,
  UDP, TCP, DoT (RFC 7858), and DoH (RFC 8484)
- Load balancing with random, round-robin, least-ping, and least-load policies,
  plus Observatory health checks
- Process matching on Linux, macOS, and Windows
- `domainStrategy`: `AsIs`, `IpIfNonMatch`, and `IpOnDemand`
- Daemon mode with graceful SIGINT/SIGTERM shutdown

## Quick start

```bash
# Build (outputs bin/bypasscore)
make build

# Show the version
./bin/bypasscore --version
./bin/bypasscore -V

# Reduce hot-path log volume in production
./bin/bypasscore -run -config config.json -log-level warning

# Start the daemon (TPROXY listeners, routing, and outbounds)
make run

# Demonstrate a routing decision
make run-test DEST="tcp:www.baidu.com:443"

# Demonstrate DNS resolution
make run-resolve DOMAIN=example.com

# Run Observatory probes
make observe
```

Run directly with the example configuration:

```bash
./bin/bypasscore -config examples/config.example.json -run
```

## Data path

```
iptables/nftables TPROXY/REDIRECT
  ↓
inbound listener (TCP: SO_ORIGINAL_DST / UDP: IP_RECVORIGDSTADDR)
  ↓ recover the original destination IP:port
sniffer (TLS SNI / HTTP Host / QUIC Initial → route-only domain)
  ↓
router.PickRoute → outboundTag
  ↓
outbound dialer:
  ├─ freedom:  direct net.Dial with source-IP/interface binding
  ├─ blackhole: drop
  └─ proxy:    SOCKS5 client → 127.0.0.1:<naiveproxy_port>
  ↓
transport.Bridge (bidirectional copy)
```

## Outbound model

Each outbound is a descriptor with optional binding metadata:

| Mode | Bind | Upstream | Meaning |
|---|---|---|---|
| `freedom` | — | — | Direct connection |
| `freedom` | interface + localIP | — | Multi-WAN routing (wan1/wan2) |
| `blackhole` | — | — | Drop the connection |
| `proxy` | — | SOCKS server | SOCKS5 → local naiveproxy |

```json
{"tag":"wan1","mode":"freedom","bind":{"interface":"en0","localIP":"192.168.1.2"}}
{"tag":"proxy","mode":"proxy","upstream":{"protocol":"socks","server":"127.0.0.1:1080"}}
```

## DNS subsystem

Multiple upstreams, domain routing, and caching are configured as follows:

```json
{
  "dns": {
    "servers": [
      {"address":"https://223.5.5.5/dns-query","domains":["domain:cn"],"tag":"cn"},
      {"address":"tls://1.1.1.1:853","tag":"cloudflare"},
      "localhost"
    ],
    "queryStrategy":"UseIP"
  }
}
```

| Address | Transport | Port |
|---|---|---|
| `localhost` | System resolver | — |
| `1.2.3.4:53` | UDP | 53 |
| `tcp://1.2.3.4:53` | Plain TCP (RFC 7766) | 53 |
| `tls://1.2.3.4:853` | DoT (RFC 7858) | 853 |
| `https://dns/dns-query` | DoH (RFC 8484) | 443 |
| `h2c://dns/dns-query` | DoH over cleartext HTTP/2 | 80 |

By default, upstream DNS connections use Router/Outbound just like normal
traffic, so they can use a selected WAN or SOCKS5 proxy. Use
`udp+local://`, `tcp+local://`, `tls+local://`, or `https+local://` for direct
queries outside the routing core. `localhost` always uses the system resolver.
DNS routing carries `protocol: dns` and a recursion guard, allowing dedicated
protocol or inboundTag rules.

## Configuration

See `examples/config.example.json` for a complete configuration containing
direct, blocked, multi-WAN, and proxy outbounds, TCP REDIRECT and UDP TPROXY
inbounds, routing, DNS, and Observatory settings.

## GeoData files

`geoip.dat` and `geosite.dat` are not included. To use `geosite:` or `geoip:`
rules, download them into the working directory or `$BYPASSCORE_ASSETS` from
[Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat).

## Project structure

The main packages are `app/inbound`, `app/dispatcher`, `app/dialer`,
`app/outbound`, `app/router`, `app/observatory`, and `app/dns`; protocol
sniffers live under `common/protocol`, outbound implementations under
`proxy`, shared interfaces under `features`, transport under `transport`, and
JSON configuration under `infra/conf`. The CLI entry point is
`cmd/bypasscore`.

## Linux integration tests

GitHub Actions validates a real network-namespace topology covering TCP
REDIRECT, TCP/UDP TPROXY, IPv6, SOCKS5 UDP, transparent reply source-address
restoration, and UDP session/FD/RSS resource limits. On a Linux host, run:

```bash
sudo integration/netns/run.sh
```
