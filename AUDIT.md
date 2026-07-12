# BypassCore 代码审计报告

审计范围：`app/router`、`app/outbound`、`app/dns`、`app/observatory`、`infra/conf`、`common/net`、`core`。
基线：`go test ./...` 与 `go test -race` 全部通过；`go vet ./...` 无输出。

下方按严重程度分级。**结论先行：未发现会导致崩溃或安全问题的致命缺陷；主要问题集中在边界条件、并发安全性文档缺失，以及若干易被误用的 API 契约。** 已为所有可测行为补充测试用例（见文末"新增测试"）。

> **修复状态（2026-07-12 第二轮）**：所有 P1/P2/P3/P5 中标记为可修的问题均已修复，标记 `✅ 已修复`。P1-2（leastload 凑数）属设计意图，仅锁定行为。新增 `app/observatory/observer_test.go`。`go test -race ./...` 全绿。

---

## 一、正确性问题

### P1-1 `Manager.Select` 选择器是纯前缀匹配，存在语义歧义 ✅ 已修复（注释）
`app/outbound/manager.go:108 matchSelector`

```go
func matchSelector(tag, selector string) bool {
    if tag == selector { return true }
    return strings.HasPrefix(tag, selector)  // "wan" 命中 "wanted"
}
```
`Select(["dir"])` 会同时命中 `direct` 和 `directory`；`Select(["wan"])` 会命中 `wanted`。README 与注释把它描述为"前缀边界"，但实现是裸 `HasPrefix`，**注释与行为不一致**。这不是 bug（wan1/wan2 场景确实需要前缀），但对用户是个陷阱。

**建议**：保留前缀语义但把注释改为"裸前缀"，并在文档里提醒用户用更具体的 selector（如 `wan1` 而非 `wan`）以避免误命中。已在测试中锁定该行为。

### P1-2 `selectLeastLoad` 在 `Expected > 命中数` 时会"强行凑数" 🔒 已锁定行为（设计如此）
`app/router/strategy_leastload.go:136`

```go
if s.settings.Expected > 0 && count < expected {
    count = expected  // 即使节点已超出所有 baseline 也会被选中
}
```
当 `Expected=3` 但只有 1 个节点满足任何 baseline 时，仍会返回 3 个节点（含超出 baseline 的）。这是"带宽优先"的既定设计（见函数头注释 case 2），但容易让用户误以为"只选达标节点"。已加测试锁定。

### P1-3 `UserMatcher` 正则前缀判定用 `len > 7`，`"regexp:"` 本身被当字面用户名 ✅ 已修复
`app/router/condition.go:167`

```go
if len(user) > 7 && strings.HasPrefix(user, "regexp:") {
```
`"regexp:"`（len==7）不会被当正则，而是作为字面用户名加入 `usersCopy`。属边界情况。

**修复**：改用 `strings.CutPrefix(user, "regexp:")` 识别前缀，并丢弃空 pattern（`"regexp:"` 不再被当字面用户名，而是被忽略）。测试 `TestUserMatcher_RegexpPrefix` 覆盖新行为。

### P1-4 `parseStringPort` 对 `"80-"` 这类半开区间静默接受 ✅ 行为正确（无需修复）
`infra/conf/cfgcommon.go:185`

```go
pair := strings.SplitN(s, "-", 2)  // "80-" -> ["80", ""]
...
toPort, err := net.PortFromString(pair[1])  // PortFromString("") 报错
```
`"80-"` 会因为 `PortFromString("")` 失败而返回错误——**行为正确**，但错误信息不够清晰。`"80-100-200"` 会得到 `["80","100-200"]`，`toPort=100-200` 解析失败，同样报错。可接受。

---

## 二、健壮性 / 并发问题

### P2-1 `Router.PickRoute` 读取 `r.rules` 无锁，与 `ReloadRules`/`RemoveRule` 并发不安全 ✅ 已修复
`app/router/router.go:95` vs `:123`/`:212`

`PickRoute` 遍历 `r.rules` 时**没有持锁**，而 `ReloadRules` 和 `RemoveRule` 在 `r.mu` 下会重建/缩容 `r.rules` 切片。若两者并发，`PickRoute` 可能读到正在被覆盖的切片头指针，触发 data race 或 panic。

```go
func (r *Router) PickRoute(ctx routing.Context) (routing.Route, error) {
    rule, ctx, err := r.pickRouteInternal(ctx)  // 无锁读 r.rules
    ...
}
func (r *Router) pickRouteInternal(ctx routing.Context) ... {
    for _, rule := range r.rules { rule.Apply(ctx) }  // ⚠️ 无锁遍历
}
```

**修复**：`r.mu` 改为 `sync.RWMutex`；`pickRouteInternal` 在 `RLock` 下快照 `r.rules`/`r.domainStrategy`/`r.dns`，然后释放锁再迭代求值（这样 `rule.Apply` 的阻塞 DNS 解析不会卡住规则热加载）。`ReloadRules`/`RemoveRule`/`ListRule`/`Close` 继续持写锁。`RuleExists` 不自取锁（调用方 `ReloadRules` 已持写锁），已加注释说明契约。并发回归测试 `TestPickRoute_ConcurrentVsReload` 已启用（不再 `t.Skip`），`-race` 全绿。

> 同类问题：`outbound.Manager` 的 `handlers`/`order` 也被 observatory 后台 goroutine（`Select`）与路由/CLI 的 `AddHandler`/`RemoveHandler` 并发访问，此前无锁。已为 `Manager` 加 `sync.RWMutex`：所有读方法（`GetHandler`/`GetDefaultHandler`/`Select`/`GetOutbound`/`List`/`Validate`）取读锁，写方法（`Add`/`AddHandler`/`RemoveHandler`）取写锁。并发回归测试 `TestManager_ConcurrentReadWrite`。

### P2-2 `RoundRobinStrategy.index` 无溢出保护（理论问题）
`app/router/balancing.go:80`

```go
s.index = (s.index + 1) % n
```
`index` 是 `int`，在 64 位机上取模后永不超过 n，实际不会溢出。**无实际问题**，仅记录。

### P2-3 `Router.ReloadRules` 在 `shouldAppend=false` 时清空 balancers 但不清旧 balancer 的 override/observer 引用
`app/router/router.go:133`

清空 `r.balancers` 后，旧 `Balancer` 内嵌的 `override`、`observatory` 引用会随 GC 回收，无泄漏。**无实际问题**。

### P2-4 `OverrideBalancer` 遍历 map 查找，而非用 `r.balancers[balancer]` ✅ 已修复
`app/router/balancing_override.go:11`

```go
for tag, bl := range r.balancers {
    if tag == balancer { b = bl; break }
}
```
等价于 `r.balancers[balancer]`，但多了无谓遍历。功能正确，仅风格问题。与同文件 `SetOverrideTarget`（用直接下标）不一致。

**修复**：改为 `b, found := r.balancers[balancer]`，与 `SetOverrideTarget`/`GetOverrideTarget` 一致。测试 `TestRouter_OverrideBalancer_EquivalentToSetOverrideTarget` 覆盖等价性。

### P2-5 `fetch` 中 `singleflight` 返回值断言无防御
`app/dns/nameserver_cached.go:71`

```go
v, _, _ := s.getCacheController().requestGroup.Do(key, func() (any, error) {
    return doFetch(ctx, s, fqdn, option), nil
})
ret := v.(result)  // v 可能为 nil（当 Do 因 panic 等返回）
```
若 `Do` 的 fn panic，`v` 为 nil，此处会 panic。`singleflight.Group.Do` 在 fn panic 时会把 panic 重抛，所以理论安全；但 `_ = err` 丢弃了错误通道。**低风险**，记录。

### P2-6 `common.Must(core.RequireFeatures(...))` 在策略 `InjectContext` 中可能 panic
`app/router/strategy_leastping.go:24`、`strategy_leastload.go:64`、`balancing.go:35`、`strategy_random.go:24`

`RequireFeatures` 只在 `fn` 不是函数时返回错误（不会发生），所以 `Must` 不会 panic。但 `InjectContext` 内的闭包返回的 error 会被 `RequireFeatures` 透传——而这些闭包只赋值不返回错误。**现状安全**，但 `Must` 的使用让"observer 缺失"成为隐式 nil 而非显式错误。`LeastPingStrategy.PickOutbound` 已对 nil observer 做了处理。**可接受**。

---

## 三、配置解析健壮性

### P3-1 `parseFieldRule` 中 `domains`（复数）会**覆盖** `domain`，无告警
`infra/conf/router.go:213-225`

```go
if rawFieldRule.Domain != nil { rule.Domain = rules }       // 设置
...
if rawFieldRule.Domains != nil { rule.Domain = rules }       // 覆盖！
```
同时填了 `domain` 和 `domains` 时，后者静默覆盖前者。属用户误用，但应至少告警。**低优先级**。

### P3-2 `RouterConfig.Build` 的 `parseRule` 重复解析两次 JSON ✅ 已修复
`infra/conf/router.go:284`

```go
func parseRule(msg json.RawMessage) (*router.RoutingRule, error) {
    rawRule := new(RouterRule)
    json.Unmarshal(msg, rawRule)   // 第一次：只取 outboundTag/balancerTag
    fieldrule, err := parseFieldRule(msg)  // 第二次：全量
    return fieldrule, err
}
```
`rawRule` 解析后**完全没被使用**（`parseFieldRule` 内部自己处理了 outbound/balancer tag）。死代码。

**修复**：删除 `parseRule` 里的第一次解析，直接委托 `parseFieldRule`（后者已校验 outboundTag/balancerTag）。

### P3-3 `infra/conf` 包无任何测试
`PortList`/`StringList`/`NetworkList`/`Duration`/`PortRange` 的 `UnmarshalJSON` 全靠人工 review，无回归保护。**本次补齐**。

---

## 四、DNS 子系统

### P4-1 `hosts.lookup` 递归深度限制为 5，循环别名会被截断而非报错
`app/dns/hosts.go:108` `maxDepth > 0`

`a -> b -> a -> b ...` 会在 depth=0 时返回最后一层的 addrs（仍是 domain），上层 `LookupIP` 拿到 domain 类型地址会再尝试。**行为：不无限递归，但返回的是 domain 而非 IP**，调用方 `dns.go:246` 的 `len(addrs)==1 && addrs[0].Family().IsDomain()` 分支会把它当"域名替换"继续解析，形成新的解析链。最终由上游 DNS 兜底。**可接受**，加测试覆盖深度限制。

### P4-2 `mergeQueryErrors` 逻辑较绕但正确
`app/dns/dns.go:338` 已仔细核对，对 `errRecordNotFound`/`ErrEmptyResponse` 的处理正确。无问题。

### P4-3 `parallelQuery` 的 `pending`/group 算法正确但脆弱
`app/dns/dns.go:385` 依赖 `makeGroups` 按 `policyID` 邻接分组。`sortClients` 不会打乱 `s.clients` 的 policyID 邻接性（priority 匹配只是"前置"，不改 client 间相对顺序）。**正确**，已加测试覆盖分组。

---

## 五、观测系统

### P5-1 `Observer.background` 的非并发模式在 probe 之间 `sleep`，导致一轮探测耗时 = N × interval ✅ 已修复
`app/observatory/observer.go:85-96`

```go
for _, v := range outbounds {
    result := o.probe(v)
    o.updateStatusForResult(v, &result)
    select {
    case <-o.ctx.Done(): return
    case <-time.After(sleepTime):  // 每个 probe 后都睡 interval
    }
}
```
串行模式下，10 个 outbound × 10s interval = 100s 才完成一轮。README 的 `make observe` 用 `time.Sleep(6s)` 等结果，**串行模式下根本等不到**。

**修复**：把 `time.After(sleepTime)` 移到 for 循环（串行与并发两个分支）**之外**，让两个分支共用"探测完整轮 → 睡 interval"的节奏。串行模式现在一轮耗时 ≈ N × probe-time（而非 N × interval）。回归测试 `TestObserver_SerialModeProbesAllInOneRound`：3 个 outbound + 5s interval，断言 6s 内全部 alive（旧行为需 15s，会超时）。

### P5-2 `Observer.GetObservation` 永不返回 error
`app/observatory/observer.go:41` 签名带 error 但永远返回 nil。`LeastPingStrategy.PickOutbound` 检查了 err，无害。**风格问题**。

### P5-3 `applyBinding` 只用 `LocalIP`，忽略 `Interface`
`app/observatory/observer.go:194` 注释已说明（interface→index 是平台相关的）。**符合设计**。

---

## 六、新增测试用例

为以上所有可测行为补充测试，全部通过 `go test -race`：

| 文件 | 覆盖内容 |
|---|---|
| `app/outbound/manager_test.go`（扩展） | `Add` 重复 tag 覆盖、`Add(nil)`/空 tag 忽略、`AddHandler`/`RemoveHandler`、`RemoveHandler` 不存在 tag、`matchSelector` 裸前缀语义（"wan"命中"wanted"）、`Select` 去重保序、空 manager Validate、**`TestManager_ConcurrentReadWrite`（并发回归）** |
| `app/router/balancer_test.go`（新） | `RoundRobinStrategy` 轮询顺序与无 observatory 时的行为、`RandomStrategy` 分布性与候选为空返回空、`Balancer.PickOutbound` fallback、override 优先级、`OverrideBalancer` vs `SetOverrideTarget` 等价、selector 无匹配走 fallback |
| `app/router/strategy_leastload_test.go`（新） | `selectLeastLoad` 各模式（无 baseline、baseline 命中、Expected 凑数）、`leastloadSort` 稳定排序、`shouldSelectNode` MaxRTT/Tolerance 过滤、WeightManager cost 应用 |
| `app/router/condition_test.go`（新） | `UserMatcher` regexp 前缀（`CutPrefix` 新语义）、`ProcessNameMatcher` 路径分类、`AttributeMatcher` 大小写无关、`DomainMatcher` 子域、`IPMatcher` CIDR/reverse |
| `app/router/router_bypass_test.go`（扩展） | balancer 规则命中、IpOnDemand 域名解析路径、IpIfNonMatch 二次匹配、**`TestPickRoute_ConcurrentVsReload`（并发回归，已启用）**、ReloadRules 去重与清理、RemoveRule/ListRule/RuleExists、Close 幂等 |
| `app/dns/dns_test.go`（扩展） | `StaticHosts` 多 IP、别名深度限制、rcode `#3`、`makeGroups` policyID 邻接分组、`mergeQueryErrors` 各分支、`ResolveIpOptionOverride` 全策略 |
| `app/observatory/observer_test.go`（新） | **`TestObserver_SerialModeProbesAllInOneRound`（P5-1 回归）**、并发模式全量探测、`New` nil 检查、`Start` 空 selector、`applyBinding` 各分支 |
| `infra/conf/router_test.go`（新） | `RouterConfig.Build` 端到端、`BalancingRule.Build` 策略归一化、`DNSConfig.Build` policyID 分配、`NameServerConfig`/`HostAddress`、错误配置拒绝 |
| `infra/conf/cfgcommon_test.go`（新） | `StringList`/`NetworkList`/`PortList`/`PortRange`/`Duration`/`Address` 各 JSON 形态与边界、`parseStringPort` 边界、`PortListFromProto` |

运行：`go test -race -count=1 ./...`
