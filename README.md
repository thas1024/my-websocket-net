# wsnet

**实现中：协议、加密、载体、SOCKS5、Local Forward、Hub 与节点均已落地并有测试；Hub 出站数据面与部分载体路径仍未实现。** Rust 轻量代理，参考 [Xray-core](https://github.com/XTLS/Xray-core) 的职责分层，不声明线协议兼容或已验证抗封锁效果。

## 当前实现状态

| crate | 对应设计 | 状态 |
| --- | --- | --- |
| `wsnet-limits` | §4.1 §5 §7.5 §9.2 各项预算 | 完成；预算之间的关键关系为编译期断言，破坏即构建失败 |
| `wsnet-protocol` | §4.1 canonical metadata、record framing | 完成；metadata 编解码自实现，拒绝重复键/浮点/超 i64 整数，先限长再分配 |
| `wsnet-crypto` | §4.2 §5.1 HKDF 方向密钥、nonce、AEAD 信封、HMAC | 完成；`PacketNo` 不透明，无法复用 nonce，且禁止回绕 |
| `wsnet-auth-store` | §4.2 传输 replay 窗口、§5.1 nonce 登记 | 完成；持久化与多实例共享存储未接 |
| `wsnet-operation` | §5.2 至多一次业务幂等表 | 完成 |
| `wsnet-stream` | §7.3 有界重排、§7.5 字节 credit | 完成 |
| `wsnet-transport` | §4.3 载体编码、§6.4 站点形态 | 完成（编解码层，无 I/O） |
| `wsnet-routing` | §7.1 §7.6 §9.3 destination union、路由、ACL | 完成 |
| `wsnet-registry` | §5.5 §7.6 §8 node lease 与服务目录 | 完成 |
| `wsnet-site` | §6.5 §9.1 正常站点与分阶段失败外观 | 完成 |
| `wsnet-config` | §10 TOML schema 与校验 | 完成 |
| `wsnet-session` | §4–§7 session 引擎：握手、sealing、replay、流多路复用、credit | 完成；载体无关，可在进程内两端对测 |
| `wsnet-socks` | §7.4 §7.6 SOCKS5 TCP CONNECT 与 UDP ASSOCIATE | 完成 |
| `wsnet-forward` | §7.6 Local Forward TCP/UDP 与生命周期 | 完成 |
| `wsnet-control` | USAGE §1–§2 本地管理 IPC | 完成 |
| `wsnet-node` | §5.3 §5.5 §6 节点客户端：SOCKS5、Local Forward、多 Hub 新连接转移 | **部分**：POST+SSE 载体已实现但未测；**WebSocket 载体未实现**；HTTP 载体尚未实现 §4.4 `BindProof`；UDP ASSOCIATE 未接；无重连退避监督 |
| `wsnet-hub` | §4.3 §4.4 §5 §8 §9 §11 Hub 服务端 | **部分**：认证、BindProof、lease、ACL 与载体端点已实现；**出站数据面未实现**——通过授权的 `Open` 返回明确的 `OpenResult` 拒绝而非拨号 |
| `wsnetd` / `wsnet` 二进制 | USAGE §2 | 完成：`wsnetd check/serve` 与 `wsnet check/run/status/services/forward/keygen` |

### 已知缺口（明确列出，避免把设计当成已实现）

- **Hub 不拨号到目标**，因此当前无法端到端转发真实流量；这是最大的一处缺口。
- **节点侧的绑定载体未实现 `BindProof`**：Hub 要求绑定后的每个 `/m`、`/e`、`/w` 请求携带 `BindProof`，节点仍使用自定义 `x-wsnet-session` 头。实测结果为：节点能完成认证并进入 `HelloPending`，但随后的 `Hello` 被 Hub 以站点失败外观拒绝，因此**到达 `Ready` 与注册仍未打通**。这是当前唯一剩下的控制面阻塞点。
- 节点侧 WebSocket 载体、UDP ASSOCIATE、重连退避监督未实现。
- `services list` 只报告本节点发布的条目：节点的 `ServiceDirectory` 只支持 `contains` 查询，不支持枚举，因此没有伪造远端目录列表。
- 未做 nginx / TLS 实机验证；`wsnet-limits` 的 DoS 预算未压测。

### 实测记录

用真实二进制在 `127.0.0.1` 上跑通了：`wsnetd check/serve` 启动、`wsnet check/run` 连接、**`Auth`/`AuthOk` 握手成功并完成方向密钥派生**（日志 `wsnet hub session authenticated hub=hub-a`，随后 `Binding` → `HelloPending`）。这一路径调出了一个真实的对接缺陷：节点曾把 `Auth` 作为裸 canonical JSON 发送，而 Hub 按 §4.3 的载体分帧解码为 record，因此一律以站点 404 失败外观拒绝。已修复为「record + POST 载体分帧」，并同步修正了测试桩，使三处帧格式一致。

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
- 中继 ACL 默认拒绝，Hub 和出口双重校验；发布本机服务不等于授予所有节点访问权。
- 外层 TLS 保留证书验证与前向保密。内部从简是复杂度/性能取舍，不是因为再次加密必然增加可观察密文熵。
- 密钥放权限受控文件、不进仓库或日志；疑似泄露时撤销 key_id、终止相关会话、经受信运维渠道分发替代密钥并重新认证。轮换不能补救已经泄露的历史内容。

## 文档

- [各端用法与 Local Forward 契约](docs/USAGE.md)：Hub/节点/SOCKS5、反向服务 CLI、配置、ACL、多 Hub 与 TCP/UDP 生命周期。
- [设计契约、验收设计测试清单与修复映射](docs/DESIGN.md)：§4–§11 正文契约，§12 待运行验收，§15 保留问题意图，附录 B review 修复映射。
- [GFW 历史资料与证据边界](docs/GFW-RESEARCH.md)：区分研究观察、二手说法和项目假设；本轮未做新联网调研。

本轮仅文档修复与静态自查；**未实现功能、未运行协议测试**。文档中的默认预算是设计起点，需通过受控故障注入、内存/性能测试和部署兼容性测试后再讨论发布。
