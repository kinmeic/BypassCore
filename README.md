# BypassCore

一个**独立的分流(routing)子系统**，专注于"规则匹配 → 路由决策"的通用引擎。

## 特性

- **完整的规则匹配引擎**：domain / IP(CIDR+GeoIP) / 端口 / 网络(TCP/UDP) / 协议 / inboundTag / user / process / 属性
- **DNS 子系统**：多上游 DNS + 缓存 + 域名分流 + IP 过滤，支持 UDP / TCP / DoT(RFC 7858) / DoH(RFC 8484) 四种传输
- **GeoData 支持**：`geosite:` / `geoip:` 规则，支持 `geoip.dat` / `geosite.dat` 加载
- **负载均衡**：random / roundrobin / leastping / leastload 四种策略 + Observatory 健康探测
- **进程匹配**：按源进程名/路径分流（支持 Linux/macOS/Windows）
- **路由 DNS 集成**：`domainStrategy` 支持 AsIs / IpIfNonMatch / IpOnDemand，域名不匹配时自动解析再匹配
- **outbound 描述符模型**：每个出站目标携带绑定信息（接口/本地IP/上游代理），支持 wan1/wan2 多 WAN 分流

## outbound 目标模型

每个 outbound 是带完整绑定元数据的配置描述符。`mode` 决定流量如何承载，`bind` 决定从哪个接口/IP 发出，`upstream` 指定上游代理服务器：

| Mode | bind | upstream | 含义 | 典型场景 |
|---|---|---|---|---|
| `freedom` | — | — | 直连 | 本机直出（`direct`） |
| `freedom` | ✅ interface + localIP | — | 绑定接口直连 | **多 WAN 分流（wan1/wan2）** |
| `blackhole` | — | — | 丢弃 | 阻断 |
| `proxy` | — | ✅ protocol + server | 经上游代理 | trojan/vless/socks 等服务器 |

`bind` 字段示例：
```json
{"tag": "wan1", "mode": "freedom", "bind": {"interface": "en0", "localIP": "192.168.1.2"}}
```
- `interface`：网络接口名（如 `en0`、`wan1`）—— L3 接口绑定
- `localIP`：源 IP（相当于 sendThrough）—— 从指定本地 IP 拨号

**wan1/wan2 就是一等公民**：它们是带 `bind` 绑定的 freedom outbound，路由规则和 balancer 都能引用它们，实现多 WAN 分流。

引擎只输出 tag 字符串，上层（客户端/网关/TUN）查 outbound 表后各自解释绑定语义 —— 这就是"通用规则引擎"。

## 快速开始

```bash
# 编译（产出 bin/bypasscore）
make build

# 路由决策演示（测试某目标会命中哪条规则、分流到哪个 outbound）
make run-test DEST="tcp:www.google.com:443"

# DNS 解析演示（通过配置的 DNS 子系统解析域名）
make run-resolve DOMAIN=example.com

# Observatory 探测演示
make observe
```

也可以直接运行编译后的二进制：

```bash
./bin/bypasscore -config examples/config.example.json -test "tcp:www.baidu.com:443"
./bin/bypasscore -config examples/config.example.json -resolve example.com
./bin/bypasscore -config examples/config.example.json -observe
```

示例配置见 `examples/config.example.json`（自包含，无需 geodata 文件）。

## DNS 子系统

完整的多上游 DNS 子系统，配置在 `dns` 段（见 `examples/config.example.json`）：

```json
{
  "dns": {
    "servers": [
      {"address": "https://223.5.5.5/dns-query", "domains": ["domain:cn"], "tag": "cn"},
      {"address": "tls://1.1.1.1:853", "tag": "cloudflare"},
      "localhost"
    ],
    "hosts": {"local.test": "127.0.0.1"},
    "queryStrategy": "UseIP",
    "disableCache": false,
    "enableParallelQuery": false
  }
}
```

### 传输协议

每个 server 的 `address` scheme 决定传输协议：

| address | 传输 | 端口 |
|---|---|---|
| `localhost` | 系统 resolver | — |
| `1.2.3.4:53` | UDP 明文 | 53 |
| `tcp://1.2.3.4:53` | TCP 明文 (RFC 7766) | 53 |
| `tls://1.2.3.4:853` | DoT (RFC 7858) | 853 |
| `https://dns/dns-query` | DoH (RFC 8484) | 443 |

> DNS 查询为本地直连模式（不经代理出站）。DoH/DoT 提供加密防污染，可配合域名分流实现 ChinaDNS 式效果。

### 功能

- **多上游 + 域名分流**：`domains` 字段指定仅某些域名走该上游
- **缓存**：带 TTL 缓存 + stale-cache 支持（`serveStale`/`serveExpiredTTL`）
- **IP 过滤**：`expectedIPs` / `unexpectedIPs` 过滤返回结果
- **静态映射**：`hosts` 段支持单/多 IP 和域名别名（CNAME 式链式解析）
- **查询策略**：`queryStrategy` 支持 UseIP / UseIPv4 / UseIPv6 / UseSys

## GeoData 文件

`geoip.dat` / `geosite.dat` 体积较大，不在仓库内。如需使用 `geosite:`/`geoip:` 规则，请下载放置到工作目录或 `$BYPASSCORE_ASSETS` 指定目录：

- geoip.dat / geosite.dat: https://github.com/Loyalsoldier/v2ray-rules-dat

未提供时，`geoip:`/`geosite:` 规则会报错，但纯 CIDR / domain 规则不受影响。

## 项目结构

核心分层：

```
common/         底层类型(net/geodata/errors/...)
features/       特性接口(Router/Dispatcher/Context/Manager/...)
app/            实现(router 分流核心 / outbound 描述符 / observatory 探测 / dns)
infra/conf/     JSON 配置解析
cmd/bypasscore     CLI 入口（编译产物 bin/bypasscore）
```
