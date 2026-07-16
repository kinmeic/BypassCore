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
- A local UDP/TCP DNS listening service with routed A/AAAA and raw
  MX/TXT/SRV/PTR/CAA forwarding through the same tagged outbound policy
- Load balancing with random, round-robin, least-ping, and least-load policies,
  plus Observatory health checks
- Process matching on Linux, macOS, and Windows
- `domainStrategy`: `AsIs`, `IpIfNonMatch`, and `IpOnDemand`
- Unix-socket HTTP/JSON control plane for live status, readiness, validation,
  reload, route explanation, DNS resolution, Observatory, and metrics
- Transactional runtime snapshots: routing, outbounds, DNS, Observatory, and
  non-binding inbound/metrics parameters reload without dropping old flows

## Quick start

```bash
# Build (outputs bin/bypasscore)
make build

# Show the version
./bin/bypasscore --version
./bin/bypasscore -V

# Machine-readable feature negotiation (config schema included)
./bin/bypasscore --capabilities --json

# Reduce hot-path log volume in production
./bin/bypasscore -run -config config.json -log-level warning

# Validate the complete configuration without opening listeners
./bin/bypasscore -check-config -config config.json

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
{"tag":"proxy","mode":"proxy","upstream":{"protocol":"socks","server":"127.0.0.1:1080","settings":{"udpMaxPacketBytes":8192}}}
```

## DNS subsystem

Multiple upstreams, domain routing, and caching are configured as follows:

```json
{
  "dns": {
    "servers": [
      {"address":"https://223.5.5.5/dns-query","domains":["domain:cn"],"tag":"cn"},
      {"address":"tls://1.1.1.1:853","tag":"cloudflare","outboundTag":"proxy"},
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
protocol or inboundTag rules. A server-level `outboundTag` bypasses synthetic
DNS routing rules and forces that upstream through the named outbound; config
validation rejects unknown tags.

Successful A/AAAA results can be emitted to a local Unix datagram consumer for
a lightweight nftables/NFTSet updater. Delivery is bounded and non-blocking;
the event contains `domain`, `ips`, `ttl`, `serverTag`, and `timestamp`:

```json
{"dnsResultEvents":{"socket":"/run/bypasscore/dns-results.sock","queueSize":1024,"maxDatagramBytes":8192}}
```

To expose the internal resolver to dnsmasq or LAN clients, add a DNS inbound:

```json
{
  "tag": "dns-in",
  "type": "dns",
  "listen": "127.0.0.1",
  "port": 1053,
  "network": "tcp,udp",
  "maxConcurrentQueries": 256,
  "maxTCPConnections": 128,
  "maxQueryBytes": 4096,
  "dnsAllowedClients": ["127.0.0.0/8", "192.168.0.0/16", "fd00::/8"],
  "dnsQueriesPerSecond": 200,
  "dnsQueryBurst": 400,
  "dnsGlobalQueriesPerSecond": 1000,
  "dnsGlobalQueryBurst": 2000,
  "dnsRawCacheEntries": 4096,
  "dnsRawCacheMaxTTLSeconds": 3600,
  "dnsRawCacheMaxBytes": 16777216,
  "dnsRules": [
    {"domain":["geosite:category-ads-all"],"action":"drop"},
    {"domain":["full:blocked.example"],"action":"return","rcode":3},
    {"qType":["TXT","MX"],"action":"direct"}
  ]
}
```

The listener implements standard UDP DNS and length-prefixed DNS over TCP. A
and AAAA records use the internal IP lookup/cache path. Other record types such
as MX, TXT, SRV, PTR and CAA are forwarded as validated DNS wire messages over
the selected UDP, TCP, DoT or DoH server, using the same tagged outbound and
domain policy. UDP replies honor the client's advertised EDNS size (capped at
4096 bytes) and set the truncation flag when a TCP retry is required. Binding
port 53 normally requires root privileges or `CAP_NET_BIND_SERVICE`.
`maxQueryBytes` limits memory used to parse one request and defaults to 4096.
If `listen` is omitted, a DNS inbound binds to `127.0.0.1` for safety.
For non-loopback listeners, use `dnsAllowedClients` to restrict IPv4/IPv6
CIDRs and configure the per-source `dnsQueriesPerSecond`/`dnsQueryBurst` token
bucket. Unauthorized or rate-limited UDP requests are dropped silently to
avoid creating a DNS reflection endpoint, and rate-limiter client state has a
hard memory bound. The global token bucket also limits spoofed-source floods.
DNS rules are ordered and support `direct`, `drop`, `return` and `hijack`;
`domain:`, `full:`, `regexp:` and `geosite:` matchers use the same parser as
routing rules. Validated non-A/AAAA wire responses are held in a bounded LRU
cache with TTL aging and query-ID restoration. A separate total-byte budget
(16 MiB by default) prevents large TCP/DoH answers from defeating the entry
count limit.

The same resolver can be exposed as encrypted DoT or HTTP/2 DoH. Both require
a PEM certificate and key; DoH defaults to `/dns-query`:

```json
{"tag":"dot-in","type":"dot","listen":"0.0.0.0","port":853,"network":"tcp","dnsCertificateFile":"server.crt","dnsKeyFile":"server.key","dnsAllowedClients":["192.168.0.0/16"]}
{"tag":"doh-in","type":"doh","listen":"0.0.0.0","port":8443,"network":"tcp","dnsCertificateFile":"server.crt","dnsKeyFile":"server.key","dnsDoHPath":"/dns-query","dnsAllowedClients":["192.168.0.0/16"]}
```

UDP TPROXY resource budgets can be tuned for the device:

```json
{
  "tag": "udp_tproxy",
  "type": "tproxy",
  "listen": "0.0.0.0",
  "port": 12345,
  "network": "udp",
  "udpMaxSessions": 1024,
  "udpMaxSessionsPerSource": 256,
  "udpSessionQueueBytes": 65536,
  "udpSessionQueuePackets": 64,
  "udpSessionIdleTimeoutSeconds": 120
}
```

The global and per-source limits work together so one client cannot consume
all sockets, goroutines, and queue memory. These are the defaults; memory-limited
OpenWrt devices can use smaller values.

TCP sniffing is bounded by `sniffingTimeoutMs` (default 500) and
`sniffingMaxBytes` (default 32768). QUIC/UDP sniffing is bounded by
`udpSniffWaitMs` (default 25) and `udpSniffMaxPackets` (default 4).

## Operations and observability

Set `metrics` to expose Prometheus metrics and health status. Loopback is the
safe default; a non-loopback address requires `allowedClients`. Pprof is
disabled unless explicitly enabled.

```json
{"metrics":{"listen":"127.0.0.1:9090","allowedClients":["127.0.0.0/8"],"enablePprof":false}}
```

Endpoints are `/healthz`, `/readyz`, `/metrics`, and, when enabled,
`/debug/pprof/`. `/healthz` is liveness; `/readyz` becomes successful only
after all configured inbounds have started.

Enable the local control plane (it never opens a TCP port):

```json
{"control":{"enabled":true,"socket":"/run/bypasscore/control.sock","mode":"0660","maxRequestBytes":1048576,"maxConcurrentRequests":32}}
```

It speaks HTTP/JSON over the Unix socket:

| Method and path | Purpose |
|---|---|
| `GET /v1/status` | Live revision/hash, listeners, DNS/outbound status, Observatory, last reload |
| `GET /v1/capabilities` | Version, config schema, feature list |
| `GET /v1/ready` | Structured readiness |
| `POST /v1/config/validate` | Validate a JSON config without activating it |
| `POST /v1/config/reload` | Transactionally activate a JSON config; empty body reloads `-config` |
| `POST /v1/route/explain` | Explain a route for `{"destination":"tcp:example.com:443"}` |
| `POST /v1/dns/resolve` | Resolve with the running DNS state |
| `GET /v1/observatory` | Current probe results |
| `GET /v1/metrics` | Metrics as JSON |

Example: `curl --unix-socket /run/bypasscore/control.sock http://localhost/v1/status`.
`SIGHUP` uses the same transactional reload path. A candidate runtime is fully
built and validated before one atomic swap. Existing TCP/UDP flows retain the
old snapshot and drain naturally; after 30 seconds the retired snapshot is
force-closed. Routing, outbounds, DNS, Observatory, DNS result events, and
inbound/metrics parameters can change live. Adding/removing listeners or
changing an inbound address, port, type, network, TLS files, DoH path, metrics
listen address, or control socket returns `restart_required` and leaves the
running revision intact.

Routing may declare an explicit default instead of a catch-all rule:

```json
{"routing":{"domainStrategy":"AsIs","finalOutboundTag":"proxy","rules":[]}}
```

Metrics include low-cardinality rule hits, active outbound connections,
upload/download bytes, outbound dial status/latency, DNS upstream status and
latency, sniff results, revision, and reload outcomes. On reload, series whose
configured tags no longer exist are removed to bound memory over the process
lifetime.

## Configuration

See `examples/config.example.json` for a complete configuration containing
direct, blocked, multi-WAN, and proxy outbounds, TCP REDIRECT and UDP TPROXY
inbounds, a local UDP/TCP DNS inbound, routing, DNS, and Observatory settings.

## GeoData files

`geoip.dat` and `geosite.dat` are not included. To use `geosite:` or `geoip:`
rules, download them into the working directory or `$BYPASSCORE_ASSETS` from
[Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat).

## Project structure

The main packages are `app/inbound` (transparent-proxy and DNS listeners),
`app/dispatcher`, `app/dialer`,
`app/outbound`, `app/router`, `app/observatory`, and `app/dns`; protocol
sniffers live under `common/protocol`, outbound implementations under
`proxy`, shared interfaces under `features`, transport under `transport`, and
JSON configuration under `infra/conf`. The CLI entry point is
`cmd/bypasscore`.

## Linux integration tests

GitHub Actions validates a real network-namespace topology covering TCP
REDIRECT, TCP/UDP TPROXY, IPv6, SOCKS5 UDP, transparent reply source-address
restoration, the UDP/TCP DNS listener over IPv4/IPv6, raw TXT forwarding,
UDP-to-TCP DNS truncation fallback, and UDP session/FD/RSS resource limits. On
a Linux host, run:

```bash
sudo integration/netns/run.sh
```
