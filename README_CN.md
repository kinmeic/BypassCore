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
- **daemon 模式**：`bypasscore run -c config.json` 常驻，SIGINT/SIGTERM 优雅退出

## 快速开始

```bash
# 编译（产出 bin/bypasscore）
make build

# 查看版本
./bin/bypasscore --version
./bin/bypasscore -V

# 生产环境可降低热路径日志量
./bin/bypasscore -run -config config.json -log-level warning

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
{"tag": "proxy", "mode": "proxy", "upstream": {"protocol": "socks", "server": "127.0.0.1:1080"}}
```

## DNS 子系统

多上游 DNS + 域名分流 + 缓存：

```json
{
  "dns": {
    "servers": [
      {"address": "https://223.5.5.5/dns-query", "domains": ["domain:cn"], "tag": "cn"},
      {"address": "tls://1.1.1.1:853", "tag": "cloudflare"},
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
  "maxQueryBytes": 4096
}
```

监听器支持普通 UDP DNS 和带两字节长度帧的 TCP DNS。A/AAAA 查询使用内部 IP
解析与缓存路径；MX、TXT、SRV、PTR、CAA 等其他记录类型会作为经过校验的 DNS
wire message，经所选 UDP、TCP、DoT 或 DoH 服务器及相同 tagged outbound/域名策略
转发。UDP 响应会遵守客户端声明的 EDNS 报文大小（最大 4096 字节），需要 TCP
重试时设置截断标志。监听 53 端口通常需要 root 权限或 `CAP_NET_BIND_SERVICE`。
`maxQueryBytes` 用于限制单个请求解析时的内存占用，默认为 4096。
DNS inbound 未设置 `listen` 时会安全地默认监听 `127.0.0.1`。

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
TPROXY、IPv6、SOCKS5 UDP、透明回复源地址恢复、IPv4/IPv6 UDP/TCP DNS 监听，
以及 UDP session/FD/RSS 上限。
本地 Linux 主机可用 root 权限运行：

```bash
integration/netns/run.sh
```
