# wsnet

**实现中：协议、加密、载体（POST+SSE、WebSocket、TLS 外层）、SOCKS5、Local Forward、Hub 出站数据面、反向访问、多跳 chain 均已落地并有测试。** Rust 轻量代理，参考 [Xray-core](https://github.com/XTLS/Xray-core) 的职责分层，不声明线协议兼容或已验证抗封锁效果。

## 当前实现状态

| crate | 对应设计 | 状态 |
| --- | --- | --- |
| `wsnet-limits` | §4.1 §5 §7.5 §9.2 各项预算 | 完成；预算之间的关键关系为编译期断言，破坏即构建失败；`tests/budgets.rs` 逐项把预算压到边界 |
| `wsnet-protocol` | §4.1 canonical metadata、record framing | 完成；metadata 编解码自实现，拒绝重复键/浮点/超 i64 整数，先限长再分配 |
| `wsnet-crypto` | §4.2 §5.1 HKDF 方向密钥、nonce、AEAD 信封、HMAC | 完成；`PacketNo` 不透明，无法复用 nonce，且禁止回绕 |
| `wsnet-auth-store` | §4.2 传输 replay 窗口、§5.1 nonce 登记 | 完成；持久化与多实例共享存储未接 |
| `wsnet-operation` | §5.2 至多一次业务幂等表 | 完成 |
| `wsnet-stream` | §7.3 有界重排、§7.5 字节 credit | 完成；§7.3 的乱序 128 KiB / 128 块 / offset 前视三个预算全部强制 |
| `wsnet-transport` | §4.3 载体编码、§6.4 站点形态 | 完成（编解码层，无 I/O） |
| `wsnet-routing` | §7.1 §7.6 §9.3 destination union、路由、ACL | 完成 |
| `wsnet-registry` | §5.5 §7.6 §8 node lease 与服务目录 | 完成 |
| `wsnet-site` | §6.5 §9.1 正常站点与分阶段失败外观 | 完成 |
| `wsnet-config` | §10 TOML schema 与校验 | 完成 |
| `wsnet-session` | §4–§7 session 引擎：握手、sealing、replay、流多路复用、credit | 完成；载体无关，可在进程内两端对测 |
| `wsnet-socks` | §7.4 §7.6 SOCKS5 TCP CONNECT 与 UDP ASSOCIATE 服务端 | 完成（服务端协议与 association 生命周期） |
| `wsnet-forward` | §7.6 Local Forward TCP/UDP 与生命周期 | 完成 |
| `wsnet-control` | USAGE §1–§2 本地管理 IPC | 完成 |
| `wsnet-node` | §5.3 §5.5 §6 节点客户端：SOCKS5、Local Forward、多 Hub 转移、多跳中间节点 | **部分**：POST+SSE 与 WebSocket 载体均已实现并实测；Hub 会话断线由监督任务按退避重连；`via` 链的中转端已实现；**SOCKS5 UDP ASSOCIATE 未接** |
| `wsnet-hub` | §4.3 §4.4 §5 §8 §9 §11 Hub 服务端 | **部分**：认证、BindProof、lease、ACL、载体端点、出站数据面、反向访问、§8 `PeerList` 与多跳 chain 均实现；**UDP 出口未实现** |
| `wsnetd` / `wsnet` 二进制 | USAGE §2 | 完成：`wsnetd check/serve` 与 `wsnet check/run/status/services/forward/keygen` |

### 已知缺口（明确列出，避免把设计当成已实现）

- **UDP 尚未打通**：`wsnet-socks` 的 UDP ASSOCIATE 服务端、`wsnet-forward` 的 UDP association 表都有测试，但节点没有把 datagram 送进隧道的路径，Hub 出口也只拨 TCP。因此 `SocksBridge::udp_associate` 仍以明确的“本版本不支持”拒绝，而不是先答成功再让流量消失。接这一条需要四段：Hub 的 UDP 出口与 `Datagram` 路由、节点侧 `Proto::Udp` 流 API、SOCKS5 association 到隧道的映射、以及各自的超时/TTL/去重预算（§7.4）。
- **外层 TLS 已用等价实现验证，未用 nginx 实机验证**：本环境没有 nginx，`crates/wsnet-node/tests/tls_front.rs` 用同一个 TLS 库起一个字节级终止代理（不解析 HTTP，因此对 Hub 完全透明），断言整条载体在 TLS 后可用，并断言**默认信任库下同一个部署必须失败**——后者保证证书校验真的在跑，而不是被静默放过。运营商自建 CA 通过 `HttpTransportFactory::with_root_certificate` 接入。`wss://` 的自定义根尚未接线（WebSocket 载体只走公开根）。
- **WebSocket 载体的健康检查是"载体级"的**：§5.5 要的是一次认证往返。节点的探测顺序是先用 `BindProof` 做一次真实 upgrade（Hub 校验 MAC、nonce、会话存在），只有在它失败时才退回在现役 socket 上做控制帧往返。Hub 侧只有"认证出该会话的那个 socket"结束时才释放租约，所以探测可以来去而不打断会话——这一点由 `tests/ws_carrier.rs` 断言。
- `services list` 报告的是**Hub 按调用方 ACL 过滤后**广播的 `PeerList`，加上本节点自己发布、而 Hub 尚未回显的条目（后者按 Hub 是否已发过快照标 `Ready`/`Offline`）。节点不会伪造它看不到的远端目录。
- `wsnet-auth-store` 的持久化与多实例共享未接；Hub 重启后 replay 窗口与 nonce 登记从零开始。

### 实测记录

`cargo test --workspace` 为 **613 passed / 0 failed**，`cargo clippy --workspace --all-targets -- -D warnings` 干净。

**端到端验收**（均真实进程内跑真 Hub + 真节点，无桩）：

- `crates/wsnet-node/tests/end_to_end.rs`：SOCKS5 客户端的字节经 node → Hub → 目标 socket 回显，同一会话上连续三次请求都成功。
- `crates/wsnet-node/tests/reverse_access.rs`：调用方经 `[[forwards]]` 到达发布方本机服务；发布方 `allow_node_address` 是第二道闸（Hub 放行也不够）。
- `crates/wsnet-node/tests/multihop.rs`：`via=[A]` 把出口移到 A；`via=[A,B]` 走 client→H→A→H→B→target 的星型回转链；两条负例分别钉住"出口节点自身白名单"和"中间节点的本地同意"（`relay_forward` 默认关闭）。
- `crates/wsnet-node/tests/ws_carrier.rs`：强制使用 WebSocket 工厂，断言字节回显、健康检查不打断会话、第二条连接仍然可用。
- `crates/wsnet-node/tests/tls_front.rs`：TLS 终止代理前后各一条（可用 / 不可信必须被拒）。
- `crates/wsnet-node/tests/peer_directory.rs`：Hub 的 `PeerList` 在注册后立即到达调用方；无规则的节点看到的是**已知但为空**的目录，而不是泄漏；发布方退租后服务消失且版本号单调递增。
- `crates/wsnet-node/tests/supervisor.rs`：Hub 被杀后监督任务按 §5.5 的三次失败判定并重连；多 Hub 下新连接转移到第二个 Hub（用"第一个 Hub 必然拒绝、第二个必然成功"来证明选中的是哪个）。
- `crates/wsnet-limits/tests/budgets.rs`：把 replay 窗口、nonce 容量、重排字节/块/前视、credit、载体与 metadata 尺寸逐项压到恰好命中与超出一字节。

控制面同样实测通过：`wsnetd serve` + `wsnet run`，日志显示 `Auth`/`AuthOk` 握手、方向密钥派生、`Binding → HelloPending → Ready`，`wsnet status` 显示 `hub-a Ready`。

### 本轮修掉的真实缺陷（都由新增测试暴露）

1. **本地关闭 Hub 会话时从不发 `Bye`**：驱动收到 `Command::Close` 直接跳出循环，于是 Hub 一直保留该节点的 lease 与服务注册，直到会话 TTL 到期——期间它还会把调用方的 `Open` 桥到一条没人读的会话上。现在关闭是"宣告式"的：先发 `Bye` 并把记录刷进上行载体，再退出。
2. **§7.3 的三个重排预算只有声明没有实现**：`REORDER_MAX_BLOCKS`（128 块）与 `REORDER_MAX_OUT_OF_ORDER_BYTES`（128 KiB）在整个工作区没有任何代码引用，`ReorderBuffer` 只按总字节（256 KiB）设限，且对 offset 前视**完全没有**约束——对端可以在 offset 2^40 放一个 4 字节块，或塞进 129 个带洞的小块。现在三个预算都强制，并且 `with_limit` 被夹在 §7.3 的每方向总量之下。
3. **同一会话上第二个 `/w` 结束会杀掉会话**：会话表原先只支持单个 SSE owner，WebSocket 侧没有任何 owner 概念，于是任何一次带合法 `BindProof` 的 upgrade 结束时都会 `close_session`。这与 §6.2 "同一会话可有多个载体"的模型矛盾，也让"认证式健康探测"变成自杀操作。现在只有认证出该会话的那个 socket 结束时才释放租约。

此外，`wsnet-forward/tests/lifecycle.rs` 原先用 2 秒 connect 上限 + 30 毫秒固定 sleep，在机器负载高时会假失败。这些断言关心的是字节与拨号次数，不是延迟，因此改为具名常量（15 秒 / 200 毫秒）并在注释里说明它们是"卡死检测"而不是性能断言。

> Windows 提示：配置里的路径若含反斜杠需写成 `C:/...` 或 TOML 字面串 `'C:\...'`，否则会被当作转义序列（`invalid unicode 8-digit hex code`）。

构建与测试（Rust 1.75+；本仓库在 `x86_64-pc-windows-gnu` 上验证通过）：

```bash
cargo test --workspace                      # 全部单元与集成测试
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release
```

## 计划能力

- 标准 TLS/nginx + HTTPS POST、SSE（仅下行）、WebSocket 混合载体；业务数据可用 POST+SSE/POST响应作为真实备用通道，而非仅发送背景网页。
- SOCKS5 TCP CONNECT 与 UDP ASSOCIATE；Local Forward 访问命名反向服务/显式授权端口；受控同 Hub 多跳 chain。
- 单层消息保护、方向隔离 HKDF key、有效 nonce 不提前驱逐；传输 replay、业务 request_id 幂等和候选 attempt_id 分离。
- 字节 credit 背压与有界 offset 重排/恢复；TCP 不静默丢字节。
- 多 Hub 注册与**新连接**故障转移，不承诺存量 TCP/UDP association 跨 Hub 无缝迁移。
- 可配置 HTML/JS/CSS/动态API形态、正常站点与有界背景请求；混淆收益需测量，不保证不可识别。

## 使用边界（未来实现必须遵守）

- UDP 在可靠 TLS 载体上传输会受 TCP 队头阻塞影响，实时性不保证；association 与 SOCKS5 TCP 控制连接同生共死。
- 入口默认 loopback，非 loopback 必须认证与来源白名单；不要将 SOCKS5 直接暴露公网。
- 中继 ACL 默认拒绝，Hub 和出口双重校验；多跳时**每条 relay edge 各有 permit**，中间节点的 `relay_forward` 是它自己的同意，不能由 Hub 代替。发布本机服务不等于授予所有节点访问权。
- 外层 TLS 保留证书验证与前向保密。内部从简是复杂度/性能取舍，不是因为再次加密必然增加可观察密文熵。
- 密钥放权限受控文件、不进仓库或日志；疑似泄露时撤销 key_id、终止相关会话、经受信运维渠道分发替代密钥并重新认证。轮换不能补救已经泄露的历史内容。

## 文档

- [各端用法与 Local Forward 契约](docs/USAGE.md)：Hub/节点/SOCKS5、反向服务 CLI、配置、ACL、多 Hub 与 TCP/UDP 生命周期。
- [设计契约、验收设计测试清单与修复映射](docs/DESIGN.md)：§4–§11 正文契约，§12 待运行验收，§15 保留问题意图，附录 B review 修复映射。
- [GFW 历史资料与证据边界](docs/GFW-RESEARCH.md)：区分研究观察、二手说法和项目假设；本轮未做新联网调研。
