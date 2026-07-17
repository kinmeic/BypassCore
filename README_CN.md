# BypassCore

一个独立的 Go 透明代理分流核心，替代 xray-core 在 passwall2 中的角色：tproxy 收流量 → sniffing 恢复域名 → 规则匹配路由 → outbound 拨号转发。

## 特性

- **透明代理入站**：TCP REDIRECT（SO_ORIGINAL_DST）+ UDP TPROXY（IP_TRANSPARENT + IP_RECVORIGDSTADDR）
- **TLS/HTTP/QUIC 嗅探**：从纯 IP 连接恢复域名（TLS SNI / HTTP Host / QUIC Initial），让 TCP/UDP 域名规则对透明代理流量生效
- **规则匹配引擎**：domain / IP(CIDR+GeoIP) / 端口 / 网络(TCP/UDP) / 协议 / inboundTag / user / process / 属性
- **GeoData 支持**：`geosite:` / `geoip:` 规则，支持 `geoip.dat` / `geosite.dat` 加载
- **3 种出站拨号器**：
  - `freedom` — 直连，支持源 IP / 接口绑定（多 WAN）
  - `blackhole` — 丢弃
  - `proxy` — SOCKS5 client 拨到本地 naiveproxy/sing-box 的 socks 端口
- **DNS 子系统**：多上游 DNS + 缓存 + 域名分流 + IP 过滤，UDP / TCP / DoT(RFC 7858) / DoH(RFC 8484)
- **DNS 监听服务**：通过普通 UDP/TCP 端口提供 A/AAAA 解析，并将 MX/TXT/SRV/PTR/CAA 等记录类型沿相同 tagged outbound 转发
- **负载均衡**：random / roundrobin / leastping / leastload + Observatory 健康探测
- **进程匹配**：按源进程名/路径分流（Linux/macOS/Windows）
- **domainStrategy**：AsIs / IpIfNonMatch / IpOnDemand
- **本地控制面**：只监听 Unix Socket 的 HTTP/JSON API，提供运行状态、readiness、配置校验/重载、路由解释、DNS 测试、Observatory 和指标
- **事务式运行时快照**：路由、outbound、DNS、Observatory 及不改变绑定的 inbound/metrics 参数可热更新，旧连接自然排空

## 快速开始

```bash
# 编译（产出 bin/bypasscore）
make build

# 查看版本
./bin/bypasscore --version
./bin/bypasscore -V

# 能力协商与配置 Schema（机器可读）
./bin/bypasscore --capabilities --json

# 生产环境可降低热路径日志量
./bin/bypasscore -run -config config.json -log-level warning

# 不打开端口，完整检查配置
./bin/bypasscore -check-config -config config.json

# daemon 模式（启动 tproxy 监听 + 路由 + 出站）
make run

# 路由决策演示
make run-test DEST="tcp:www.baidu.com:443"

# DNS 解析演示
make run-resolve DOMAIN=example.com

# Observatory 探测
make observe
```

直接运行：

```bash
./bin/bypasscore -config examples/config.example.json -run
```

示例配置见 `examples/config.example.json`。

## 数据面流程

```
iptables/nftables TPROXY/REDIRECT
  ↓
inbound listener (TCP: SO_ORIGINAL_DST / UDP: IP_RECVORIGDSTADDR)
  ↓ 恢复原始目标 IP:port
sniffer (TLS SNI / HTTP Host / QUIC Initial → routeOnly 域名)
  ↓
router.PickRoute → outboundTag
  ↓
outbound dialer:
  ├─ freedom:  net.Dial 直连 + 源IP/接口绑定
  ├─ blackhole: 丢弃
  └─ proxy:    SOCKS5 client → 127.0.0.1:<naiveproxy_port>
  ↓
transport.Bridge (双向拷贝)
```

## outbound 目标模型

每个 outbound 是带绑定元数据的配置描述符：

| Mode | bind | upstream | 含义 |
|---|---|---|---|
| `freedom` | — | — | 直连（direct） |
| `freedom` | ✅ interface + localIP | — | 多 WAN 分流（wan1/wan2） |
| `blackhole` | — | — | 丢弃 |
| `proxy` | — | ✅ socks server | SOCKS5 → 本地 naiveproxy |

```json
{"tag": "wan1", "mode": "freedom", "bind": {"interface": "en0", "localIP": "192.168.1.2"}}
{"tag": "proxy", "mode": "proxy", "upstream": {"protocol": "socks", "server": "127.0.0.1:1080", "settings": {"udpMaxPacketBytes": 8192}}}
```

## DNS 子系统

多上游 DNS + 域名分流 + 缓存：

```json
{
  "dns": {
    "servers": [
      {"address": "https://223.5.5.5/dns-query", "domains": ["domain:cn"], "tag": "cn"},
      {"address": "tls://1.1.1.1:853", "tag": "cloudflare", "outboundTag": "proxy"},
      "localhost"
    ],
    "queryStrategy": "UseIP"
  }
}
```

| address | 传输 | 端口 |
|---|---|---|
| `localhost` | 系统 resolver | — |
| `1.2.3.4:53` | UDP 明文 | 53 |
| `tcp://1.2.3.4:53` | TCP 明文 (RFC 7766) | 53 |
| `tls://1.2.3.4:853` | DoT (RFC 7858) | 853 |
| `https://dns/dns-query` | DoH (RFC 8484) | 443 |
| `h2c://dns/dns-query` | DoH over cleartext HTTP/2 | 80 |

默认情况下，上游 DNS 连接和普通流量一样经过 Router/Outbound，因此可以走
`freedom` 的指定 WAN 或 SOCKS5 proxy。需要明确绕过分流核心、直接查询的上游，
可使用 `udp+local://`、`tcp+local://`、`tls+local://`、`https+local://` 等
`+local` 形式；`localhost` 始终使用系统 resolver。DNS 路由上下文带有
`protocol: dns` 和防递归标志，可以用 protocol/inboundTag 规则单独选择出口。
每个 DNS server 还可直接配置 `outboundTag`，无需再生成隐藏 DNS 路由规则；
引用不存在的 outbound 会在配置校验阶段直接报错。

如需把解析结果交给轻量 NFTSet/nftables 消费者，可开启非阻塞 Unix datagram
事件出口。事件还包含单调递增 `sequence`、`configRevision`、过期时间及累计丢失数。
通道仍是 best-effort，但消费者发现断号后可通过 `GET /v1/dns/results` 全量同步当前
未过期结果；队列满、消费者离线或写入超时都不会阻塞 DNS：

```json
{"dnsResultEvents":{"socket":"/run/bypasscore/dns-results.sock","queueSize":256,"maxDatagramBytes":8192,"maxQueueBytes":1048576}}
```

如需向 dnsmasq 或局域网客户端提供内部解析服务，可增加一个 DNS inbound：

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
    {"domain": ["geosite:category-ads-all"], "action": "drop"},
    {"domain": ["full:blocked.example"], "action": "return", "rcode": 3},
    {"qType": ["TXT", "MX"], "action": "direct"}
  ]
}
```

监听器支持普通 UDP DNS 和带两字节长度帧的 TCP DNS。A/AAAA 查询使用内部 IP
解析与缓存路径；MX、TXT、SRV、PTR、CAA 等其他记录类型会作为经过校验的 DNS
wire message，经所选 UDP、TCP、DoT 或 DoH 服务器及相同 tagged outbound/域名策略
转发。UDP 响应会遵守客户端声明的 EDNS 报文大小（最大 4096 字节），需要 TCP
重试时设置截断标志。监听 53 端口通常需要 root 权限或 `CAP_NET_BIND_SERVICE`。
`maxQueryBytes` 用于限制单个请求解析时的内存占用，默认为 4096。
DNS inbound 未设置 `listen` 时会安全地默认监听 `127.0.0.1`。
监听非 loopback 地址时，建议用 `dnsAllowedClients` 限制可访问的 IPv4/IPv6
CIDR，并配置按源 IP 的 `dnsQueriesPerSecond`/`dnsQueryBurst`。未授权或限流的
UDP 请求会被静默丢弃，避免形成 DNS 反射入口；限流器的客户端状态数量也有硬上限。
全局 token bucket 还能限制伪造源地址的洪泛。DNS 规则按顺序执行，支持
`direct`、`drop`、`return`、`hijack`，域名语法与路由规则相同。非 A/AAAA 的
已校验 wire 响应进入有容量上限的 LRU 缓存，命中时会递减 TTL 并恢复请求 ID；
独立的总字节预算（默认 16 MiB）可防止大体积 TCP/DoH 响应绕过条目数限制。

同一个解析器也可以通过加密 DoT 或 HTTP/2 DoH 对外提供服务。两者都要求 PEM
证书和私钥，DoH 路径默认是 `/dns-query`：

```json
{"tag":"dot-in","type":"dot","listen":"0.0.0.0","port":853,"network":"tcp","dnsCertificateFile":"server.crt","dnsKeyFile":"server.key","dnsAllowedClients":["192.168.0.0/16"]}
{"tag":"doh-in","type":"doh","listen":"0.0.0.0","port":8443,"network":"tcp","dnsCertificateFile":"server.crt","dnsKeyFile":"server.key","dnsDoHPath":"/dns-query","dnsAllowedClients":["192.168.0.0/16"]}
```

UDP TPROXY 的资源预算可按设备内存和并发量配置：

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

全局上限和按源 IP 上限共同生效，防止单个客户端耗尽全部 socket、goroutine 和
队列内存。以上均为默认值；低内存 OpenWrt 设备可以适当调低。

TCP 嗅探可用 `sniffingTimeoutMs`（默认 500）和 `sniffingMaxBytes`（默认
32768）限制；QUIC/UDP 嗅探可用 `udpSniffWaitMs`（默认 25）和
`udpSniffMaxPackets`（默认 4）限制。

## 运维与可观测性

配置 `metrics` 后可提供 Prometheus 指标和健康状态。默认只监听 loopback；监听
非 loopback 地址时必须配置 `allowedClients`。pprof 默认关闭。

```json
{"metrics":{"listen":"127.0.0.1:9090","allowedClients":["127.0.0.0/8"],"enablePprof":false}}
```

端点为 `/healthz`、`/readyz`、`/metrics`，启用后还有 `/debug/pprof/`。
`/healthz` 只表示进程存活；`/readyz` 聚合每个 inbound 的实时状态。任一 TCP、UDP
或 DoH 服务循环意外退出都会标记该 inbound 为 failed，并让 daemon 退出，交由
procd/服务管理器重启。

本地控制面只使用 Unix Socket，不会开放 TCP 端口：

```json
{"control":{"enabled":true,"socket":"/run/bypasscore/control.sock","mode":"0660","maxRequestBytes":524288,"maxInflightRequestBytes":2097152,"maxConcurrentRequests":16}}
```

| 方法与路径 | 用途 |
|---|---|
| `GET /v1/status` | 当前 revision/hash、监听器、DNS/outbound 状态、Observatory、最近 reload |
| `GET /v1/capabilities` | 版本、配置 Schema、能力列表 |
| `GET /v1/ready` | 结构化 readiness |
| `POST /v1/config/validate` | 校验请求体中的 JSON 配置但不生效 |
| `POST /v1/config/reload` | 事务式加载请求体；空请求体重新读取 `-config` |
| `POST /v1/route/explain` | 解释 `{"destination":"tcp:example.com:443"}` 的真实路由 |
| `POST /v1/dns/resolve` | 使用当前运行实例解析 DNS |
| `GET /v1/observatory` | 当前探测结果 |
| `GET /v1/metrics` | JSON 指标 |
| `GET /v1/dns/results` | 供事件消费者重同步的有界、未过期 DNS 结果快照 |

调用示例：`curl --unix-socket /run/bypasscore/control.sock http://localhost/v1/status`。
Validate/Reload 共用一个不排队的 mutation 槽，并发请求会立即返回 `503 busy`。
Reload 支持 `If-Match: <revision-or-config-hash>`，旧写入者会得到
`409 revision_conflict`；请求体还受全局在途字节预算约束。
`SIGHUP` 也走同一条事务式重载路径：候选 runtime 先完整构建和校验，再一次原子
切换。已有 TCP/UDP 流量继续持有旧快照并自然排空，30 秒后仍未结束的旧快照会被
强制回收。routing、outbound、DNS、Observatory、DNS 结果事件以及不影响路由语义的
inbound 资源策略/metrics 参数均可热更新。增加/删除监听器，或修改 inbound tag、
sniffing、DNS action rules、地址、端口、类型、网络、TLS 文件、DoH path，以及 metrics 监听地址、control
socket 时会返回 `restart_required`，当前 revision 保持不变。

Routing 可用显式默认出口取代最后一条 catch-all 规则：

```json
{"routing":{"domainStrategy":"AsIs","finalOutboundTag":"proxy","rules":[]}}
```

指标包含低基数的 ruleTag 命中、outbound 当前连接数、上下行字节、拨号结果/延迟、
DNS 上游结果/延迟、sniff 结果、配置 revision 和 reload 结果。热重载后，已不在
当前配置中的 tag 对应 series 会被删除，避免长期运行时基数不断增长。

## config.json 结构

```json
{
  "outbounds": [
    {"tag": "direct", "mode": "freedom"},
    {"tag": "block", "mode": "blackhole"},
    {"tag": "wan1", "mode": "freedom", "bind": {"interface": "en0", "localIP": "192.168.1.2"}},
    {"tag": "proxy", "mode": "proxy", "upstream": {"protocol": "socks", "server": "127.0.0.1:1080"}}
  ],
  "inbounds": [
	{"tag": "dns-in", "type": "dns", "listen": "127.0.0.1", "port": 1053, "network": "tcp,udp"},
	{"tag": "tcp_redir", "type": "redirect", "listen": "0.0.0.0", "port": 12345, "network": "tcp", "sniffing": true},
	{"tag": "udp_tproxy", "type": "tproxy", "listen": "0.0.0.0", "port": 12345, "network": "udp", "sniffing": false}
  ],
  "routing": {"domainStrategy": "IpIfNonMatch", "rules": [...]},
  "dns": {"servers": [...], "hosts": {...}},
  "observatory": {"subject_selector": ["wan"], ...}
}
```

## GeoData 文件

`geoip.dat` / `geosite.dat` 不在仓库内。如需 `geosite:`/`geoip:` 规则，下载放置到工作目录或 `$BYPASSCORE_ASSETS`：

- https://github.com/Loyalsoldier/v2ray-rules-dat

## 项目结构

```
app/inbound/       tproxy/redirect 透明代理监听器 + 普通 UDP/TCP DNS 监听器
app/dispatcher/    数据面枢纽 (inbound → sniff → route → outbound)
app/dialer/        共享 Dialer 接口
app/outbound/      outbound 描述符 + Manager (tag 查找 + dialer factory)
app/router/        路由核心 (规则匹配 + PickRoute + balancer)
app/observatory/   出站健康探测
app/dns/           DNS 子系统 (多上游 + 缓存 + DoT/DoH)
proxy/freedom/     直连拨号器 (net.Dial + 源IP/接口绑定)
proxy/blackhole/   丢弃拨号器
proxy/socks/       SOCKS5 client 拨号器
common/protocol/tls/   TLS SNI 嗅探
common/protocol/http/  HTTP Host 嗅探
common/protocol/quic/  QUIC Initial 解密与 SNI 嗅探
common/            底层类型 (net/geodata/errors/...)
features/          特性接口 (Router/Dispatcher/Context/Manager/...)
transport/         Link + Bridge (双向连接拷贝)
infra/conf/        JSON 配置解析
cmd/bypasscore/    CLI 入口 (run/test/resolve/observe)
```

## Linux 内核集成测试

GitHub Actions 会在真实 network namespace 拓扑中验证 TCP REDIRECT、TCP/UDP
TPROXY、IPv6、SOCKS5 UDP、透明回复源地址恢复、IPv4/IPv6 UDP/TCP DNS 监听、
原始 TXT 转发、DNS UDP 截断后的 TCP 回退，以及 UDP session/FD/RSS 上限。
本地 Linux 主机可用 root 权限运行：

```bash
integration/netns/run.sh
```
