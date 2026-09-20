# wsnet

**实现中：已完成 §4–§7 中不依赖 I/O 的部分，网络层尚未开始。** Rust 轻量代理，参考 [Xray-core](https://github.com/XTLS/Xray-core) 的职责分层，不声明线协议兼容或已验证抗封锁效果。

## 当前实现状态

已完成的部分全部有单元测试；**尚无任何网络层，因此当前还不能作为代理运行**。

| crate | 对应设计 | 状态 |
| --- | --- | --- |
| `wsnet-limits` | §4.1 §5 §7.5 各项预算 | 完成；预算之间的关键关系为编译期断言，破坏即构建失败 |
| `wsnet-protocol` | §4.1 canonical metadata、record framing | 完成；metadata 编解码为自实现，拒绝重复键/浮点/超 i64 整数，先限长再分配 |
| `wsnet-crypto` | §4.2 §5.1 HKDF 方向密钥、nonce、AEAD 信封、HMAC 输入 | 完成；`PacketNo` 不透明，无法复用 nonce，且禁止回绕 |
| `wsnet-auth-store` | §4.2 传输 replay 窗口、§5.1 nonce 登记 | 完成；持久化存储与多实例共享存储未接 |
| `wsnet-operation` | §5.2 至多一次业务幂等表 | 完成 |
| `wsnet-stream` | §7.3 有界重排、§7.5 字节 credit | 完成 |
| `wsnet-transport` | §4.3 载体编码、§6.4 站点形态 | 完成（编解码层，无 I/O） |
| `wsnet-socks`、`wsnet-forward`、`wsnet-routing`、`wsnet-registry`、`wsnet-site`、`wsnet-control` | §7–§9 §11 | **未开始** |

已覆盖的验收项：**T01、T02、T03、T05、T08、T10**，以及 T18/T20 中属于解析器的部分；对照见 `crates/wsnet-transport/tests/acceptance.rs`。其余验收项需要真实 socket、TLS、nginx 与受控故障注入，属于后续工作。

构建与测试（Rust 1.75+；本仓库在 `x86_64-pc-windows-gnu` 上验证通过）：

```bash
cargo test                                   # 200 个测试
cargo clippy --all-targets -- -D warnings    # 无警告
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
