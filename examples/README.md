# BypassCore 示例

## config.example.json

演示配置，展示 BypassCore 的完整分流能力：

### outbound 描述符
- `direct` / `block` — 直连 / 阻断
- `wan1` / `wan2` — 多 WAN，绑定到 en0/en1 接口和本地 IP
- `proxy` — 经 trojan 代理转发

### routing 规则
- `domain:cn` / `geosite:google` — 域名匹配
- `geoip:private` — GeoIP 匹配私网地址段
- `port: 80,443` — 端口匹配
- `process: curl` — 进程匹配（阻断 curl 的流量）
- 最后兜底 `proxy`

### observatory
- 探测所有 `wan` 前缀的 outbound（即 wan1、wan2），10s 间隔，并发探测

## 运行

```bash
# 从项目根目录
make run-test DEST="tcp:www.baidu.com:443"   # → 命中 domain:baidu.com → wan1
make run-test DEST="tcp:1.2.3.4:443"          # → 命中 port 443 → proxy
make observe                                   # → 探测 wan1/wan2 并打印延迟
```

## GeoData 文件（可选）

若要使用 `geosite:` / `geoip:` 规则，下载并放置到工作目录或 `$BYPASSCORE_ASSETS`：

```bash
# geoip.dat / geosite.dat
curl -LO https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
curl -LO https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
export BYPASSCORE_ASSETS=/path/to/dat/files
```

示例配置中 `geosite:google` 和 `geoip:private` 需要 geodata 文件；其余规则（`domain:`、`port`、`process`）无需 geodata 即可工作。
