# BypassCore 第二轮审计报告 — 数据平面模块

第一轮审计覆盖了路由/DNS/配置解析（见 `AUDIT.md`）。本轮覆盖**数据平面**新增代码：`proxy/`、`transport/`、`app/dispatcher/`、`app/inbound/`、`common/protocol/`、`cmd/` daemon 模式。

基线：`go vet ./...` 无输出。

---

## 一、正确性 (P1)

### P1-1 Sniffer 吞掉首包，TLS/HTTP 转发必然损坏 ⚠️⚠️⚠️
`app/dispatcher/sniffer.go:33` + `app/dispatcher/default.go:58`

```go
n, err := conn.Read(buf)   // 读取 ClientHello / HTTP 请求行
...
return domain              // 返回域名，但 buf 里的数据消失了
```
`Sniff` 从 inbound conn 读取了最多 4096 字节（TLS ClientHello 或 HTTP 请求行+头），提取域名后**丢弃数据**。`Dispatch` 随后把同一个 conn（已前进）传给 `transport.Bridge`，outbound 收到的是**缺少首包**的流——TLS 握手必然失败，HTTP 请求行丢失。注释声称"returned conn is a pre-pended wrapper"但实际没有包装。

**修复**：`Sniff` 应返回一个 prependConn（先回放缓冲字节，再透传底层 conn 的 Read）。

### P1-2 SO_BINDTODEVICE 在 connect 之后设置，TCP 接口绑定无效 ⚠️⚠️
`proxy/freedom/freedom.go:60-67` + `bind_linux.go:14-33`

```go
conn, err := dialer.DialContext(ctx, network, address)  // TCP 连接已建立
if err == nil {
    bindInterface(conn, h.bindIface)  // 事后设 SO_BINDTODEVICE → 无效
}
```
TCP 的四元组/路由在 connect 时已由内核固定。connect 之后再设 `SO_BINDTODEVICE` 不影响已有连接的出口接口。`wan1`/`wan2` 接口绑定对 TCP **静默失败**。源 IP 绑定（`LocalAddr`）在 connect 前设置，是正确的。

**修复**：用 `net.Dialer.Control(func(fd) { SetsockoptString(fd, SOL_SOCKET, SO_BINDTODEVICE, iface) })` 在 connect 前设置。

### P1-3 blackhole 返回 ErrClosed 而非 EOF，Bridge 每次都报错
`proxy/blackhole/blackhole.go:40-41`

```go
func (*closedConn) Read([]byte) (int, error)  { return 0, net.ErrClosed }
func (*closedConn) Write([]byte) (int, error) { return 0, net.ErrClosed }
```
注释说"Bridge will copy nothing and close the inbound"，但 `io.Copy` 不把 `net.ErrClosed` 当 EOF。`transport.Bridge` 返回非 nil error，dispatcher 每次丢弃连接都记错误日志。

**修复**：`Read` 返回 `(0, io.EOF)`；`Write` 返回 `(len(p), nil)`（接受并丢弃）。

---

## 二、健壮性 / 并发 (P2)

### P2-1 Sniffer 无读超时，server-speaks-first 协议和端口扫描导致 goroutine 泄漏
`app/dispatcher/sniffer.go:33`

`conn.Read(buf)` 无 deadline。客户端连上但不发包（端口扫描）或 SMTP/FTP/SSH 等服务端先说话的协议，dispatch goroutine 永久阻塞。

**修复**：加 4s 读超时，读后清除。

### P2-2 Listener.Close() 在有活跃连接时永久阻塞
`app/inbound/listener.go:77-88`

`Close()` 调 `cancel()` + `tcpListener.Close()` + `wg.Wait()`。但 `cancel` 不会关闭已接受的连接或中断 `transport.Bridge`（后者用无 context 的 `io.Copy`）。有活跃连接时 `handleConn` goroutine 卡在 `Dispatch`→`Bridge`，`wg.Wait()` 永不返回。daemon 收到 SIGINT 后无法优雅退出。

**修复**：追踪已接受的 conn，Close 时强制关闭。

### P2-3 SOCKS5 UDP 目标被当作 TCP CONNECT 发送
`proxy/socks/socks.go:71-74` + `221`

`dest.Network == UDP` 时 `network` 仍为 `"tcp"`，`buildConnectRequest` 总是发 `CMD=0x01`(CONNECT)，从不发 `CMD=0x03`(UDP ASSOCIATE)。UDP 流量被当作 TCP CONNECT 发给 SOCKS 服务器。

**修复**：UDP 目标应返回明确错误（"UDP over SOCKS not yet supported"）或实现 UDP ASSOCIATE。

### P2-4 fail() (os.Exit) 跳过所有 defer，DNS/Observatory 无优雅关闭
`cmd/bypasscore/main.go:279`

`main` 设了 `defer srv.Close()` / `defer observer.Close()`，但所有错误路径都走 `fail()`→`os.Exit(1)`，defer 不执行。DNS 后台 goroutine 和 observatory 探测被中途杀死。

**修复**：用 `defer` + 返回 error 的模式替代 `os.Exit`。

---

## 三、次要 (P3)

### P3-1 per-inbound Sniffing 字段是空操作
`app/inbound/listener.go:94-96`（代码不存在于 listener.go，但在 main.go:290-297 全局判断）

### P3-2 acceptLoop 在持久 Accept 错误时无退避
`app/inbound/listener.go:100-101` EMFILE 时紧密循环烧 CPU。

### P3-3 重复的 OutboundManager 接口（死代码）
`app/dispatcher/default.go:32-35` 与 `DialerManager`(123) 完全相同，前者未使用。

### P3-4 AsRoutingContext 对空 outbounds 切片 panic
`features/routing/session/context.go:157` `outbounds[len(outbounds)-1]` 无长度检查。

### P3-5 freedom 无默认拨号超时
`proxy/freedom/freedom.go:50` `&net.Dialer{}` 的 `Timeout=0`，ctx 无 deadline 时不可达主机永久挂起。

### P3-6 HTTP Host 嗅探对无括号 IPv6:port 处理不当
`common/protocol/http/http.go:39-51` `::1:8080` 返回整个字符串作为域名。

---

## 四、已验证无问题的模块

- `common/protocol/tls/tls.go` — 边界检查完整，分段处理正确。
- `app/inbound/original_dst_linux.go` — SO_ORIGINAL_DST 常量和 unsafe.Pointer 重解释正确。
- `app/inbound/original_dst_other.go` — 正确的 no-op stub。
- `app/dialer/dialer.go` — 纯接口定义。
- `transport/link.go` — 纯结构体/接口定义。
- `transport/bridge.go` — CloseWrite 半关闭逻辑正确；无 idle timeout 是标准 proxy 取舍。
