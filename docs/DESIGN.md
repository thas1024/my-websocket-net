# wsnet — 混合载体轻量代理设计

> 状态：设计修订稿，尚未实现、未运行协议测试。本轮只修正文档，不代表部署或抗检测效果已验证。
> 参考 [Xray-core](https://github.com/XTLS/Xray-core) 的入站、出口、路由和传输分层思想；本协议不宣称与 Xray 线协议兼容。
> 保留已有 §15 的问题编号与关注点；修复进入原正文，§15 用于跟踪仍需实现验证的风险。

## 1. 概述

Rust 单节点程序同时支持 SOCKS5 入站、主动连接 Hub、受授权的出口及中转。Hub 维护节点和服务注册，通过标准 HTTPS POST、SSE、WebSocket 承载会话。所有公网载体必须经过正常证书验证的 TLS，推荐 nginx 终结 TLS，后端只监听 loopback/Unix socket。

### 1.1 设计原则与承诺边界

- **职能与载体解耦**：控制及业务数据均可走 WS 或 HTTPS 备用载体，SSE 仅下行。方向、截止时间与背压优先于随机选择。
- **加密从简**：外层 TLS 提供链路机密性，内部仅一层消息保护和认证，不增加自研多层密钥协商。方向隔离、防重放和标准 TLS 安全选项不能省略。
- **混淆是待测策略，不是不可区分性证明**：统一编码、随机请求、padding 和正常站点不能保证不被识别、封锁或关联。
- TLS 外的观察者仍可见 IP、部分握手信息、包长、方向和时序；通常看不到加密内的 URL、MIME、HTML/JS/CSS 明文。增加随机请求不等于降低外层密文熵。
- **有界可靠性**：限定单 Hub 存活会话内可恢复载体；跨 Hub 只恢复新连接。不承诺恰好一次或存量 TCP 无缝迁移。

### 1.2 载体与方向

| 载体 | 上行 | 下行 | 职能 |
| --- | --- | --- | --- |
| HTTPS POST `/m` | 有界批量消息 | 响应批量消息/有界长轮询 | 认证引导、控制、TCP/UDP 业务数据 |
| HTTPS GET `/e` | 仅订阅请求，不承载上行消息 | 标准 SSE 事件 | 认证后控制及业务数据 |
| WSS `/w` | 标准 WS 消息 | 标准 WS 消息 | 认证引导、控制、业务数据 |

POST 是有限请求，不意味着每次新建 TCP；HTTP/1.1 keepalive 与 HTTP/2 复用均可使用。SSE 不是认证发起通道，订阅必须携带独立绑定凭据。

### 1.3 与参考项目的关系

借鉴 inbound/outbound、路由规则、mux、reverse 的职责划分，不移植 VMess/VLESS 认证或声称等价安全性。网页与协议形态是可配置适配层，不是新增私有 TLS/WS 协议。

### 1.4 需求映射

| 需求 | 设计落点 |
| --- | --- |
| Rust、轻量、标准 nginx TLS/WS | §11、§14 |
| SOCKS5 正向代理、可选最终出口 | §7.1、§10 |
| 客户端既服务又中转、反向访问端口 | §2、§7.1、§7.6、§9.3、[USAGE](USAGE.md) |
| HTTPS/SSE/WS 混合、随机尝试 | §4、§6.1–§6.3、§6.7 |
| HTML/JS/CSS/API 形态及背景网页 | §6.4–§6.5 |
| 加密从简、认证、防重放 | §4.2、§5.1、§5.4 |
| 重放按协议阶段返回站点内容 | §4.4、§9.1 |
| TLS 指纹评估、连接/认证 DoS | §6.6、§9.2 |
| SOCKS5 UDP | §7.4 |
| 多跳 chain | §7.1 |
| 字节 credit 流控 | §7.5 |
| 弱网实际数据备用通道 | §6.7、§7.3 |
| 多 Hub 冗余及新连接故障转移 | §5.5 |
| 未解决问题意图、验收 | §15、§12 |

## 2. 架构与角色

```
程序 -- SOCKS5 TCP/UDP --> 节点 B
                           |
                      HTTPS/WSS/SSE
                           |
                    nginx -- Hub H -- 直接出口
                                |
                         同类混合载体
                                |
                         节点 A -- 外网/已授权本机服务
```

- 正向：B → H → target；节点出口：B → H → A → target。
- 反向：B → H → A → 已发布服务或 ACL 允许的地址端口。注册服务不自动授予任何人访问权。
- 所有节点具备受控中转能力，但不要求客户端都开放公网监听端口；NAT 后节点主动建立通道。
- 逻辑节点身份与 Hub 内会话分离。Hub 是可信明文中继；跨节点端到端保密不在 v1 范围。

## 3. 分层设计

```
SOCKS5 / 路由 / 服务授权
    ↓
流与 association（offset、credit、幂等、生命周期）
    ↓
认证消息 / 统一记录 / 单层消息保护
    ↓
载体调度与有界恢复（WS、POST、SSE/POST响应）
    ↓
标准 HTTP/TLS + nginx
```

传输 nonce、业务 offset、request_id、attempt_id 是四类不同的状态，禁止混用。HTML/JS/CSS 外壳只负责可逆编码；背景请求完全不进入代理流。

## 4. 统一消息与信封

### 4.1 消息与 framing

协议版本为 `v1`，握手绑定版本与能力列表；未知必需能力拒绝，不静默降级安全选项。以下是设计 wire 契约，不是已存在的 Rust 类型。

记录明文：`kind:u8 | metadata_len:u32be | canonical_metadata | payload_len:u32be | payload | padding_len:u16be | padding`。

- metadata 为规范 JSON：UTF-8、键排序、无重复键、整数不用浮点表示；签名所需整数用十进制字符串，以避免跨语言精度损失。签名输入字段有明确长度前缀。
- TCP `Data` metadata：`stream_id:u64, offset:u64`；offset 是本方向原始业务字节起点，不含 framing/padding。重传必须保持已分配分块边界。
- `Datagram`：`stream_id:u64, association_id, datagram_id:u64, destination/source_address, remaining_ttl_ms`；一条逻辑记录一份完整 UDP 数据报，不与 TCP offset 混用。`stream_id` 是该数据报所属的 **UDP route**（§7.4 里每个目标一条 route，一条 route 就是一条 UDP 流），没有它两端都无法判断这条数据报属于哪条 route：`association_id` 是本地用来把回复送回正确 SOCKS5 association 的标签，不是会话对象。地址以 `host` + `port` 传输，域名保持未解析由出口解析（§7.1）。
- `Fin{stream_id, final_offset}` 是半关闭；`Reset{stream_id, reason}` 是终止，不把 Reset 当半关闭。
- 单记录明文最大 96 KiB，TCP payload 默认最大 16 KiB，UDP 上限见 §7.4；metadata 最大 4 KiB、padding 最大 1 KiB。认证引导总长最大 4 KiB。先限长再分配/解码。

| 消息 | 作用 |
| --- | --- |
| `Auth{version,hub_id,key_id,node_id,attempt_id,ts,nonce,capabilities,mac}` | TLS 内认证引导，未有内部会话密钥 |
| `AuthOk{session_id,session_epoch,attempt_id,server_nonce,expires_at,capabilities,mac}` | 应答 MAC 绑定完整请求摘要及全部应答字段 |
| `Hello{request_id,services,capabilities}` / `HelloOk` | 注册完成屏障，HelloOk 前不接业务 Open |
| `Open{request_id,stream_id,proto,destination,via[]}` | 有限幂等建立；destination 是 `AddressTarget` / `ServiceTarget` / `NodeAddressTarget` 严格 union，见 §7.6 |
| `OpenResult{request_id,stream_id,status}` / `QueryResult{request_id}` | 返回或查询缓存执行结果 |
| `Ready{stream_id}` | 双方收流端已安装，可开始转发目标主动发送的数据 |
| `Progress{stream_id,received_offset,consumed_offset,limit_offset}` | 累计接收确认与字节 credit，见 §7.5 |
| `Resume{stream_id,received_offset}` | 单 Hub 同会话中通道恢复，不建立第二个目标 socket |
| `CancelCandidate{attempt_id}` / `Bye` | 候选清理 / 会话关闭 |
| `Ping` / `Pong` / `PeerList{revision,...}` | 保活、带版本注册快照；仅对授权范围可见 |

没有对外明文 `AuthErr` 代理错误对象；认证失败走 §9.1，合法客户端将未收到可验证 AuthOk 视为失败。认证后业务错误在保护记录内返回。

### 4.2 方向隔离密钥、nonce 与 replay

使用现成 HMAC-SHA256、HKDF-SHA256、ChaCha20-Poly1305，不自研密码算法。PSK 为每节点独立至少 32 随机字节，非弱口令。

```
transcript = SHA256(canonical(Auth without mac) || canonical(AuthOk without mac))
PRK = HKDF-Extract(salt = transcript, IKM = node_PSK)
K_c2s = HKDF-Expand(PRK, "wsnet/v1/msg/c2s" || transcript, 32)
K_s2c = HKDF-Expand(PRK, "wsnet/v1/msg/s2c" || transcript, 32)
K_bind = HKDF-Expand(PRK, "wsnet/v1/bind" || transcript, 32)
```

每方向全部载体共用一个原子 `packet_no:u64` 分配器（初值 0），nonce=`0x00000000:u32 | packet_no:u64be`。同方向所有消息类型共用此空间；不同方向使用不同 key。禁止按 WS/POST/SSE 各自从零计数，禁止计数回绕或恢复已失去计数状态的会话。

信封为 `version:u8 | session_epoch:16B | packet_no:u64be | ciphertext_and_tag`。AAD 为常量 `wsnet/v1` 加版本、Hub ID、session_id、session_epoch、方向及上述明文头的长度前缀编码；接收端在解密前均已知。完整消息类型/offset 在密文内认证，不依赖未解密的类型来猜 AAD。

- 接近 u64 上限前停止新分配，关闭旧会话并重新认证，产生新 transcript/key/epoch；stream_id、offset、datagram_id 同样禁止回绕。一个会话内 stream_id 不复用：客户端发起用奇数、Hub 发起用偶数，0 保留。
- 传输 replay 窗口：每方向维护高水位与最近 65,536 个 packet_no 位图（约 8 KiB/方向）；先验 AEAD，再原子检查/登记，允许窗口内未见乱序。已见或落后窗口的包不进入业务状态机；不能定期清空位图后重接受旧包。只允许接收高水位前方最多 65,536 的新号，超范围关闭该绑定并记录协议错误。
- 调度器限制仍可能投递的消息跨度小于 replay 窗口（默认至多 4,096 条待投递保护记录）；阻塞旧载体时取消其投递/按业务重传，不让后来的海量数据把合法控制挤出窗口。
- **传输重放不是业务幂等**：相同密文重复投递只丢弃；需要恢复响应的合法客户端使用新 packet_no 封装同一 request_id 或查询结果。不得用相同 nonce 加密不同内容；业务重传同一 Data 分块也重新 seal，保持 stream/offset 不变。
- AEAD 本身不提供持久化防重放或恰好一次执行。进程重启旧 session/key/epoch 一律失效，不能继续旧会话。

### 4.3 载体编码

| 载体 | framing / 编码 |
| --- | --- |
| WS | 一条 RFC6455 Binary message 一份完整信封；先由库重组 WS fragmentation，再解码；不把 TCP read 边界当消息边界 |
| POST body / response | 二进制 `envelope_len:u32be + envelope` 列表；每批解码后不超过 256 KiB、至多 64 记录 |
| SSE | `data: <base64(envelope)>` 加空行，每事件一份完整信封；先流式解析 SSE 行/事件，再 base64 解码；支持任意网络分块 |
| HTML/JS/CSS/JSON profile | 按协商的有界模板可逆装载同一信封列表，详见 §6.4；声明真实 Content-Type，不能仅改扩展名 |

编码膨胀后的 HTTP body 上限 1 MiB，SSE 单事件上限 160 KiB。遇截断、超长、非法 base64/重复 JSON key 时不执行部分业务命令。批处理每条记录有独立身份和结果，不把整个批次当事务。

### 4.4 端点、绑定凭据与阶段

sid 仅路由标识，不是 bearer 授权。Rust 客户端可自定义请求头，不受浏览器 EventSource 头部限制。

- `/m` 未认证模式仅接受 Auth 引导；认证后每个 POST 带 sid 与 `BindProof` 请求头：`channel_id, bind_nonce, expires_at, mac`，MAC 使用 K_bind，绑定 method、规范化 path、hub/session/epoch、channel_id、body hash 与到期时间。有效期默认 30 秒且不超过会话到期；服务端验证并原子登记 bind_nonce，一次性使用；鉴权完成前不取出 sid 队列。
- `/e` GET 与已有会话 `/w` upgrade 使用同一 BindProof（空 body hash）；每次重连用新 bind_nonce/channel_id。同会话 SSE 只允许一个活动订阅，替换先原子切 owner，再关闭旧订阅，不能让旧回调清除新 owner。
- 新 `/w` 可先完成合法标准升级，再在 5 秒内收一次 Auth Text；此时没有业务权限。认证成功后才切 Binary 记录。SSE 不能用来上送 Auth。
- `/m` 响应严格属于已认证 `(hub_id, session_id, epoch)` 队列，与 IP、HTTP/2 stream ID 无关；SSE `Last-Event-ID` 不作为凭据或隐式恢复授权。交付不等于确认，需按 §7.3 保留可恢复记录。
- 认证/绑定失败统一进入 §9.1 的对应协议阶段，不能某处返回 AuthErr、某处返回站点页。WS 已升级后只能 WS 帧/Close，不得再写 HTTP HTML；SSE 头已发送后只能 SSE 编码/结束。
- 会话材料放 header/body，不放 URL；nginx 与应用禁止日志记录 Authorization/BindProof/PSK/完整消息。头部凭据也需要脱敏，不能因不在 URL 就认为安全。

## 5. 认证与会话

### 5.1 认证与有效 nonce 保留

Auth 的 HMAC 绑定 §4.1 所有字段（规范编码含长度前缀），AuthOk 绑定完整 Auth 摘要和完整应答；恒定时间校验 MAC。TLS 内引导消息并非公网明文，但 nginx 与可信后端可见。

- 时间取 UTC Unix 秒，与时区无关；默认窗口 W=120 秒，允许部署配置 60–300 秒。时钟漂移大先修时钟，不以缩窗解决漂移。
- nonce 为 CSPRNG 32 字节；每个认证候选独立 nonce 与 attempt_id（§6.7）。同 Auth 在 POST 和 WS 重放仍是重放，不共享所谓竞争特权。
- 先限流/限长、校验字段和 HMAC，再在 `(hub_id,key_id,node_id,nonce)` 上**原子查重并登记**。登记成功并达到所需持久性后才返回成功、创建可用会话；并发副本最多一个登记成功。
- 记录保留至 `Auth.ts + W + 1 秒` 之后，包含未来时间戳的完整可接受区间；使用单调计时的保留期限，墙钟异常回拨时暂停新认证。默认每节点至多 65,536 条、单 Hub 全局条数及内存双限（初始预算 64 MiB，实际结构开销需压测）。
- **满载不得提前逐出仍有效记录**。只清理已超过最后可接受时刻的条目，容量不足拒绝新认证/进入有界站点响应。Bloom filter 可作优化但不能代替精确集合或授权判定；v1 不要求此优化。
- 单机部署用本地事务型持久登记（可选 SQLite/WAL，选型见 §14）；重启先加载未过期记录，所有旧会话失效。存储丢失/损坏时不声称抗重放仍成立：停止新认证至少 `2W + 安全裕量` 且确认时钟稳定，或轮换所有受影响 key_id 后重新开放。
- 多实例共享同一 hub_id 必须共享强一致、原子且满足保留期的登记存储；不可只靠各进程 LRU。共享存储不可用时 fail closed。v1 推荐单实例每 hub_id，多 Hub 独立信任域由 HMAC 的 hub_id 隔离，不把一次 Auth 跨 Hub 复用。

### 5.2 三类身份与业务幂等

| 标识 | 范围 / 作用 | 不能替代 |
| --- | --- | --- |
| packet_no | 每会话方向、全载体；AEAD nonce/replay | request_id、TCP offset |
| request_id | 同 Hub 同 epoch 内的业务操作标识 | 持久事务或全局恰好一次 |
| attempt_id | 每次认证/绑定候选；取消失败或落选候选 | 认证 nonce、业务 Open 身份 |

Open/Hello 使用 128-bit request_id。服务端原子登记 `request_id + operation_hash → Pending/Complete/Failed`。同 ID 同 hash 返回 Pending 或缓存结果，不再次拨号；同 ID 异内容返回认证后的冲突错误。默认最多 4,096 个记录/会话，Open 超时 10 秒；Pending 必须完成/失败后才能回收；Complete/Failed 至少保留 120 秒，满载拒绝新操作，不逐出仍在有效幂等窗口的结果。

窗口到期后的原 request_id 不允许当新操作重执行：会话维护有界已退休 ID tombstone（最多 65,536），满则停止接受新 Open 并重新建会话。断连/重启/跨 Hub 后无法判断某旧操作是否执行时报告“结果未知”，不自动重放应用写操作。客户端可 QueryResult；收到有效结果才返回 SOCKS5 success。去重只能提供上述窗口内至多一次执行及可查询结果，**不是恰好一次**。

### 5.3 生命周期与载体恢复

`Offline → Authenticating → Binding → HelloPending → Ready → Degraded → Ready/Closed`。

- 新认证绑定至少一个可双向收发的组合（WS，或 POST 上行+SSE/POST 响应下行）。HelloOk 是业务屏障，不强制 WS 与 SSE 都成功。
- 单载体损坏进入 Degraded，只在同 Hub 同 session/epoch 仍存在且状态完整时允许 §7.3 有界恢复，默认 grace=10 秒。
- grace 到期、会话失效、Hub/节点进程丢失：停止接收该会话新流、所有 pending 明确失败/结果未知、存量流 Reset，目标 socket 释放；失联一方靠本地超时回收。
- 服务注册随所属会话 lease 删除，重连需重发 Hello；旧流和旧 target socket 不随服务重注册复活。
- 认证与重连退避 1–30 秒并带抖动；配置/凭据错误停止忙重试并提示本地诊断。节点 SOCKS5 listener 可持续监听，但不可在不可用时伪报成功。

### 5.4 加密从简的正确理由

外层 TLS 密文已经接近高熵；不能从“内部多加一次密”推导出外界能直接看见更高熵。减少内部层数的理由是 CPU、包长开销、实现审计与可信 Hub 边界。

内部保留一次 AEAD 和方向隔离 HKDF，不自建复杂 ECDH/层层加密；不承诺 Hub 看不到明文。**不关闭标准 TLS 的前向保密、证书验证或安全协商**。公网认证/带副作用请求禁用 TLS 0-RTT。nginx 后端只在本机可信通道；跨机后端另用标准 TLS/mTLS，不允许把明文 HTTP 暴露公网。

PSK 泄露且攻击者持有内部握手/内部密文时可能解开历史内部保护；仅有外层 TLS 抓包不等于 PSK 就能解开采用前向保密的 TLS。轮换只能限制后续暴露，不能补救已取得的历史明文/内部密文。

### 5.5 多 Hub 冗余与故障转移

- servers 配置带稳定 hub_id、URL、priority 与独立 key_id。节点可同时向主/备用 Hub 注册，分别认证、分别维护 lease/session。
- v1 无 Hub 间注册复制、socket 迁移或跨 Hub chain；服务仅对该 Hub 内已注册且获授权的节点可见。要在备用 Hub 访问 A，A 和请求方都必须在备用 Hub Ready，且 ACL 配置齐备。
- 同一节点同一 Hub 默认一个活跃 epoch，新 Ready 注册原子取代旧注册；旧回调不得删除新 lease。不同 Hub 的同名节点不会被自动合并为同一会话。
- 健康检查使用有界 Ping/应用握手成功，不把静态网页 HTTP 200 当代理可用。连续 3 次超时才切换，新成功稳定 30 秒后才考虑回切，避免抖动。
- **故障转移只恢复新连接**。原 Hub 上存量 TCP/UDP association 不跨 Hub 迁移，应用需重连；不能宣称对 SOCKS5 会话透明不中断。未确认 Open 不跨 Hub 自动重做，防重复副作用。

## 6. 载体调度、网页形态与弱网

### 6.1 上行调度

C→S 可选 WS 或 HTTPS POST（包括协商的 profile POST 路径），不可选择 SSE。正常按会话测得 RTT/排队量加权随机；需要满足 credit、deadline、profile body 上限。控制/数据均可发送，不按功能永久固定载体。

### 6.2 下行调度

S→C 可选 WS、SSE 或当前/下一有界 POST 响应。没有活动 POST 时队列仍受 §7.5 预算，控制消息 deadline 不得被 1–3 秒随机轮询任意拖延。备用控制 POST 轮询最大等待 250 ms，SSE 可用时关闭不必要忙轮询。HTTP 复用不改变消息所属 sid。

### 6.3 基础传输策略

默认选择单个主载体组合以降低开销，WS 可优先但不是唯一数据载体。`data_fallback=true` 是 v1 需求；首次建流可选择 POST+SSE/POST response，WS 故障可同会话恢复。多个载体仍可能共用物理瓶颈，不保证独立路径或更低丢包。

### 6.4 网页形态与背景请求的区别

形态 profile 是应用层编码，不修改 HTTP/TLS/WS 标准。

| 类别 | 业务承载 | 处理 |
| --- | --- | --- |
| HTML / JS / CSS profile | 可在认证后的受控 POST 请求/响应中携带 base64 信封列表 | HTML 用数据模板，JS 用数据字面量，CSS 用专用注释块；版本化有界解析，不执行 JS、不任意渲染 HTML |
| 动态 JSON API profile | 可承载相同业务列表 | 真实 JSON schema，绑定请求体 hash；不能只改扩展名或 Content-Type |
| 普通网页/资源 GET、HEAD | **不承载业务** | 无 request_id/credit；内容即取即弃，不计为代理建连成功 |
| SSE | 下行业务记录 | `text/event-stream` 与标准事件 framing，不能把任意 HTML 直接当 SSE |

profile 路径由部署固定配置、能力协商绑定（如 `/transport/page`、`/transport/script`、`/transport/style`），nginx 精确转发这些路径到同一后端。不得随机猜未配置路径后把真实站点响应误认为业务成功。认证成功仍以可验证 AuthOk 为准，不以 MIME/200 判断。

背景请求仅发往自有或明确授权的同站资源，不默认访问第三方。默认关闭；开启时 2–15 秒范围内抖动、每会话最多 1 个、最多 4 KiB/s/全局独立预算，弱网自动暂停。对方返回的 JS 永不执行。此项不能保证模拟浏览器或降低密文熵。

### 6.5 正常 Web 站点与失败外观

部署可提供可浏览的首页、文章、CSS/JS、favicon、robots、sitemap 与标准 404；内容可注入而非所有实例固定模板。内置站点是降级外观，正常站点可由 nginx 独立提供。代理路径精确匹配后还必须鉴权，不能因路径匹配就分配目标连接。

未知路径按正常站点状态码/Content-Type 处理，不统一伪造 HTTP 200。状态码、缓存头、连接行为应与该站点一致；站点内容/随机性没有不可检测承诺。生产后端不公开监听；若需要直连后端，必须同样提供标准 TLS，不能绕过外层安全边界。

### 6.6 TLS 指纹与库选型边界

TLS ClientHello/ALPN 等可能用于分类；本仓库没有证明 GFW 对所有线路普遍按 JA3/JA4 封锁。JA3/JA4 是描述性特征，不是浏览器真实性证明。

Rust TLS 库默认行为不一定与浏览器相同；**uTLS 主要是 Go 生态，不把“uTLS crate”当现成依赖**。v1 使用可维护标准 TLS 栈，指纹 profile 是需独立验证的可选能力；不得为匹配指纹禁用证书验证或降级密码套件。

如评估 profile，必须一起检查 TLS 扩展、ALPN、HTTP 版本与 User-Agent 一致性；按会话固定已验证 profile，而非每请求乱换互相矛盾的浏览器头。nginx 是标准 TLS 服务器，但并不因此保证不可识别。

### 6.7 弱网多候选与业务数据备用

1. **认证候选**：最多 2 个独立 POST/WS 候选（正常先启动一个，超过 250 ms 可 hedge；弱网可同时启动），每个独立 attempt_id、Auth nonce、MAC、会话密钥。SSE 不参与上行认证。首个 AuthOk+绑定成功者成为 owner，落选者 CancelCandidate 或 10 秒 TTL 回收；不合并候选密码计数器。
2. **绑定候选**：同会话不同载体使用独立 BindProof。凭据 MAC 覆盖 profile path 与 body hash；不能把同一个绑定证明跨路径复制。
3. **业务命令重试**：同 request_id/op_hash、不同保护 packet_no；原子幂等表负责至多一次拨号与返回缓存结果。重复认证失败绝不能当合法命令重试豁免。
4. **实际数据 fallback**：WS 不通时，TCP Data 经 HTTPS POST 上行，经 SSE 下行；SSE 也不可用则由 POST 响应下行。可选 HTML/JS/CSS/API 编码均传同一记录，应用校验成功才算可用。分帧、offset、恢复和去重见 §7.3。
5. **有界竞争**：每会话最多 2 个候选、2 个在途数据 POST、1 个 SSE、1 个 WS；大流默认不复制整个 payload。仅恢复未确认分块，跨载体额外发送预算默认为最近 10 秒业务字节的 20%，初始探测突发最多 64 KiB；预算耗尽排队/退避，不能扩大并发挤占弱网。
6. 无控制进展超过 2 秒进入 Degraded；同 Hub 10 秒恢复窗口内只恢复现存目标 socket。所有载体失败则显式断流，不默默新拨号。目标应用数据可能包含不可重复的操作，禁止自动重放应用请求。

### 6.8 padding、时序和调度预算

padding 默认关闭，可在 0–1 KiB 有界字节区间采样，真实 payload_len 在认证消息内。`next_power_of_two` 仍是离散量化，不叫连续分布；任何分布的抗分类收益需要测量。padding 加背景请求合计不得超过配置额外预算。

控制消息不添加任意长随机延迟；交互流优先、小包有限合批，大流按字节公平轮转。UDP 排队过期即丢弃，TCP 无 credit 暂停读取。无业务时不强制制造流量；随机策略不得压倒可靠性和资源限制。

## 7. 数据面：TCP、UDP、多跳与背压

### 7.1 路由与多跳建立

SOCKS5 TCP CONNECT 支持 IPv4、IPv6、域名。规则按顺序首匹配，未匹配用 final：`direct`、`server` 或显式 `via[]`。域名原样交给出口解析，客户端不为远端代理偷偷本地解析；目标已是 IP 时无法恢复原域名，文档不承诺消除应用自身 DNS 泄漏。

`via=[]` 在 Hub 出口；`via=[A]` 在 A 出口；`via=[A,B]` 路径为 client→H→A→H→B→target。v1 是同 Hub 星型回转链，不是任意 mesh，可能增加带宽/RTT，非天然更匿名。

- Hub 检查全部 hop 身份、重复节点、自环、最大 4 跳、每边 ACL；各中转只转发剩余路由，递减 hop budget，不能改最终目标。节点间直连与跨 Hub chain 不在 v1 范围。
- Open 先进入 Pending，按 request_id 原子占位；从末端拨号/逐层安装流映射并保留有限资源。任何一跳失败/10 秒超时，逆序 Reset 已建映射并关闭 target socket，结果缓存为 Failed。
- 返回 OpenResult 成功前必须安装两侧接收状态；目标可能主动发 banner，先有限缓存（计入 credit），收到 Ready 后才转发，避免 Data 先于 OpenResult 触发未知流错误。
- 业务边界是 `(hub,epoch,stream_id,direction)`，不是 WS 连接；换载体 stream_id 不变。Hub 每相邻 leg 有独立流映射及 credit，不能无限吸收下游拥塞。
- 命名服务解析为发布节点配置的目标地址，Hub 与出口均授权。指定 `target` 和 `service` 同时存在即拒绝。

### 7.2 TCP 半关闭与失败

Fin 携带 final_offset；只有 `[0,final_offset)` 字节全部连续写给本地 TCP 后才 shutdown(Write)，不能因跨载体 Fin 先到而截断数据。另一方向继续传输。两方向 Fin 完成才释放；连接重置、超时、协议错误使用 Reset 并释放全部预算。

TCP 流的接收/发送缓冲满时背压，不静默丢字节，不把溢出当正常 Close。达到不可恢复上限只能显式 Reset，并向应用呈现失败。

### 7.3 数据备用载体、有界重排与恢复

所有载体使用 §4.3 统一 framing，TCP 分块按业务 offset 保序，密码 packet_no 与 offset 无关。

- 同会话每流每方向维持 `received_offset`（已经完整连续入本地有界缓冲的字节末端）与 `consumed_offset`（已经成功写给下一 TCP/下一 relay leg 的字节末端）。后者不表示目标业务提交事务。
- 常态单主载体；恢复期最多双载体重叠。接收按 offset 有限重排，默认每方向最多 256 KiB 总未消费字节，其中乱序部分最多 128 KiB / 128 块；数据只在连续且未交付过时写出。相同 offset/长度/内容为副本，可重新报告 Progress；同区间内容冲突或非规范部分重叠为协议错误，不拼接猜测。
- `[offset,end)` 不得越过已授予 limit_offset；已消费区间的迟到副本只丢弃，不重新交付；乱序缺口超过 10 秒或缓冲上限无法恢复则 Reset。不能先清空去重状态再接受旧块。
- 发送端保留所有 `received_offset` 之后未确认分块（默认每方向至多 256 KiB，计入会话总预算），收到认证的累计接收进展可释放副本；接收端既然确认入缓冲，在会话有效期间就必须保留/交付，否则应使会话失败，不能假装继续。
- timeout 起点为 `max(500ms,2×smoothed_RTT)`，指数回退上限 2 秒、同块最多 3 次恢复发送、会话恢复总窗口 10 秒。每次重发使用新 packet_no，保持原 stream/offset/payload。
- Resume/Progress 在优先控制通道传输；只承诺状态仍存活的同 Hub session 内恢复。进程/Hub 失效不恢复该流；禁止为“恢复”重新向目标拨号。
- POST 可在同一 HTTP/2 连接上并发，也可多个 HTTP/1.1 连接；TCP read、HTTP chunk、SSE event、WS fragmentation 都不等于业务数据分块边界。

### 7.4 SOCKS5 UDP ASSOCIATE

[SOCKS5 RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) 定义 UDP ASSOCIATE（CMD=0x03）。v1 支持本地 UDP 入站→可靠 TLS 载体→出口 UDP，不保证游戏/语音实时性。

- association 绑定创建它的 SOCKS5 **TCP 控制连接**；该连接关闭/认证退出立即注销 UDP 映射、停止接收并回收目标 socket，同时有 60 秒 idle 上限。
- BND.ADDR/BND.PORT 返回客户端实际可达的本机 UDP socket 地址；默认使用 TCP accepted local address 与实际 UDP port，IPv4/IPv6匹配。多网卡/NAT 可配置 `socks_udp_advertise` 明确地址，不依赖客户端把 `0.0.0.0`/`::` 解释为可达目标。
- 校验 UDP 来源 IP 与 TCP peer/已授权配置一致；来源端口已声明则固定，未声明只允许首个合法数据报锁定端口。association 不自动接受来源漂移；改变来源需要重新建立，防开放 UDP relay。
- 解析 `RSV=0,FRAG,ATYP,DST.ADDR,DST.PORT`。v1 不支持 SOCKS5 UDP 分片，**FRAG != 0 丢弃并计数**。支持 IPv4/IPv6/域名，域名在出口解析并检查实际 IP 的 ACL。
- 每 association 多目标分别维护 `(association_id,target tuple,route)` 映射和 datagram_id。出口仅把关联目标的响应转回原 association，携带实际响应来源地址；回到本地 SOCKS5 客户端时重建 UDP 头。无映射/来源不符响应丢弃，不能发给其他客户端。
- UDP payload 上限默认 60 KiB（加 SOCKS 头不得超过 UDP/记录上限），一数据报一 Datagram 记录；更大/截断一律丢弃，不拆成假 TCP 流。每 association 至多 64 个目标、32 个排队数据报/256 KiB，目标映射同时受 idle 回收。
- 默认发送队列 TTL=1,000 ms，可按用途配置 100–5,000 ms；每 hop 用单调时钟扣除排队耗时传递 remaining_ttl，不依赖主机墙钟同步。数据进入 TCP 内核缓冲后的网络等待不可精确撤回，故不能保证端到端实时 deadline。
- UDP 不做业务重传/双路复制；datagram_id 只用于同 epoch 的有界重复抑制，不保证交付。队列过期/超额可丢数据报并计数，与 TCP 不丢字节的规则区分。
- UDP-over-TCP 的主要代价是 **TCP 重传引发队头阻塞（HOL）及过期数据迟到**，不是 TCP 天然乱序。专用有界 UDP 队列与调度可减少对 TCP 交互流影响，但不消除此代价。

### 7.5 字节 credit、进展与控制预留

不用“64 帧即固定内存”或 nonce seq ACK 作为流控。每流每方向从 0 开始授予绝对 `limit_offset`，初值默认 256 KiB；发送必须满足 `offset + payload_len <= limit_offset`，且会话总未消费业务字节不超过 8 MiB（不足时减小新流初始 credit 或拒绝建立）。所有乱序/重传/映射内存另受进程硬上限。

接收端只有将连续数据成功写入下游之后才增加 consumed_offset，再授予 `limit_offset = consumed_offset + configured_window`，窗口不能超过自身已预留预算。received_offset 可先前进，用于释放发送副本；不能以“入队”冒充已消费并无限补 credit。

Progress 字段单调且满足 `consumed <= received <= sent_end`、授予额度不回退；处理重复/迟到只取合法累计值、不重复加 credit。`limit_offset - consumed_offset` 不得超过协商窗口。超额度数据属于协议错误；正常满缓冲只暂停上游 TCP read。

- 控制保留：每会话独立 64 KiB 控制队列，Progress/Resume/Reset/保活优先于数据，不消耗数据 credit；使用独立优先 POST 请求（不等待占用中的长轮询）或可用 WS，目标发送延迟不超过 100 ms；仍受认证速率上限。
- 每消费 32 KiB 或 50 ms 合并最新 Progress，空窗口时探测并周期重发最新累计值（500 ms，至多 10 秒恢复窗口），无需“ACK 的 ACK”；连续无进展则显式失败，而非永远卡死。
- 单流不可阻塞整条 reader：读包按已预留 per-flow 队列分发，流公平轮转、process memory cap 生效。TCP 网络级可靠性仍由底层完成，此层处理跨载体恢复和应用背压，不再重复实现拥塞控制。

### 7.6 Local Forward、服务选择器与可选 SOCKS 命名空间

标准 SOCKS5 CONNECT 只能表达地址和端口，不能无损表达“某节点发布的命名服务”。v1 因此明确分工：SOCKS5 用于普通地址代理；**Local Forward 是身份/服务型反向访问的正式入口**；虚拟域名仅为默认关闭的便利层。完整操作示例见 [USAGE.md](USAGE.md)。

`Open.destination` 是严格 union，恰好出现一种：

- `AddressTarget{host,port}`：普通 SOCKS 或 Hub/节点出口地址；`via[]` 决定最终拨号节点。
- `ServiceTarget{node_id,service_name,optional_service_revision}`：推荐的反向访问目标。Hub 解析当前 lease；最终发布节点按本地服务表再次解析，不接受调用方覆盖本机地址。
- `NodeAddressTarget{node_id,host,port}`：访问远端节点可见地址，默认拒绝，仅显式 `connect_node_address` ACL 可用。

Local Forward 在本机绑定 TCP/UDP listener；每个 TCP accept 创建独立 Open，成功收到 OpenResult+Ready 后才转发。远端失败时关闭该本地连接，不为通用 TCP 伪造 HTTP 响应；listener 可以保持 BOUND，服务恢复后仅新连接可用。服务 lease/revision 变化不复活旧 socket。

CLI 只经当前 OS 用户可访问的 Unix socket / Windows named pipe 控制运行中的节点，不开放公网管理 API。动态 forward 默认仅存内存；持久 forward 使用 `[[forwards]]` 配置。Local listener 默认 loopback；非 loopback 必须显式开启并配置来源 CIDR allowlist。

命名服务的 `via[]` 只包含中间节点，service publisher 是最终端。`hub="auto"` 仅选择调用方与发布方均 Ready、服务 lease 存在且 ACL 有效的健康 Hub；跨 Hub 只恢复新连接。raw node address 不因同节点已发布其他服务而自动获权。

可选 SOCKS 命名空间格式为 `svc.<node>.<service>.wsnet.invalid`，仅在 SOCKS5 `ATYP=DOMAIN` 且 remote-DNS 模式下解析为 ServiceTarget；不交本地 DNS、不映射 raw address、默认关闭。HTTPS 可能发生 SNI/证书名不匹配，因此 TLS 服务仍优先 Local Forward 配合应用自身主机名能力。

UDP Local Forward 固定远端 service/target，每个本地来源 tuple 建立有界 association，复用 §7.4 的来源校验、TTL、队列、datagram_id 与 HOL 规则；它不同于每数据报可携带不同目标的 SOCKS5 UDP ASSOCIATE。

## 8. Hub 中继与隔离

Hub 维护 sessions、node leases、service ACL、operation table、per-leg streams/credit；所有 key 都包含 Hub/session epoch。保护消息验真后再查业务状态，不能仅按 sid 或 IP 索引共享输出队列。

PeerList 只含调用者可见节点/服务，带 revision，迟到旧 revision 忽略。Hello/Open/Ready 有状态屏障，控制消息虽然可跨载体乱序，**不意味着没有顺序依赖**。未知合法流不任意新建；返回认证后的 Reset/错误，并保持其他流可用。

中转仍解密再封装到另一相邻会话；每 leg 有独立 nonce/key、offset 映射及信用窗口。上下游慢流、取消、失败必须传播并回收，不丢弃未确认 TCP 数据后声称成功。

## 9. 安全边界与失败响应

历史威胁依据见 [GFW-RESEARCH.md](GFW-RESEARCH.md) 和附录 A；没有新的联网验证。

### 9.1 认证失败按协议阶段一致响应

失败请求不能创建目标 socket、注册节点、读取受保护队列或执行命令。外观与正常站点的失败路径共用有界处理；这只是减少特定错误差异，不是不可区分性保证。

| 阶段 | 响应契约 |
| --- | --- |
| HTTP 尚未升级/发送 SSE 头 | 未认证、过期、重放、绑定失败统一选择该部署站点对应的 HTML/JSON/静态资源失败响应；状态码/Content-Type 合法一致，不返回 AuthErr/replay 原因；语法层超长/非法 HTTP 可由 nginx 正常返回 400/413 |
| WS 已升级且认证未成功 | 只能发送该站点合法的有限 WS 公开消息或 Close（正常结束用1000、协议违规用1002等符合状态）；不再发送 HTTP HTML，不无限保持僵尸连接 |
| SSE 已开始 | 仅公开的有界 SSE 事件/注释或正常结束；不能混入其他会话信封，也不能再改 HTTP status。SSE 上不存在客户端上送的重放消息，检测对象是订阅 BindProof |
| 已认证正常会话的密文副本 | 不再执行，丢弃副本；合法请求重试按 request_id/offset 返回累计状态。不把整条正常会话突然切成站点伪装流 |
| 已认证的业务授权失败 | 返回保护的 OpenResult/Reset；详细原因留本地脱敏日志，不把认证失败外观用作业务成功 |

响应尺寸、最大持续时间和速率与正常站点统一受 §9.2 限制。固定“升级后立即关闭”或全部200也可能形成特征，不作为安全证明。正常 TLS 会阻止简单跨连接重放应用明文的假设也不能替代内部 replay 检查；区分观察者能拿到的 TLS 密文与内部记录。

### 9.2 认证、连接与响应 DoS 防护

- nginx 和应用两层限制：按可信来源 IP、节点及全局令牌桶；不信任外部伪造 X-Real-IP/X-Forwarded-For，只接受已配置可信 nginx 提供的来源信息。
- 初始设计值：每 IP 20 个未认证连接、5 次认证/秒（burst10）、握手超时5秒、每会话256流；公网入口和进程有总连接/文件描述符/内存硬限，需压测调整。
- 先 HTTP/body/metadata 限长再 MAC/AEAD；内部对称原语成本低但分配、排队、重试与背景响应仍可放大资源消耗。
- 未认证失败外观最多16 KiB或5秒，不能无限 SSE/WS、不能代理任意第三方 URL。预算耗尽使用普通过载响应/关闭，安全与可用性优先，不为掩盖错误无限消耗。
- v1 不增加 PoW 挑战协议，避免额外复杂度/弱网开销；未来如需必须单独评估，不假定 PoW 就能解决 DDoS。
- nonce、request_id、绑定 nonce、重排、UDP映射分别有容量与到期策略，不能以驱逐有效安全记录换可用性。

### 9.3 默认拒绝 ACL 与入口安全

`relay_allow=[]` 为默认；这是 Hub 中转能力开关而不是完整授权。Hub 还需明确 `(caller,via hop,exit,target/service,proto,port/CIDR)` permit 规则，无匹配即拒绝。出口节点独立校验本地策略，注册服务不得绕过规则。

公网 egress 默认拒绝 loopback/private/link-local/云元数据等特殊地址；经显式发布的本机服务才按明确 allowlist 例外放行。域名解析后检查每个实际候选 IP，连接使用已检查地址，防 DNS 重绑定与重新解析绕过。链路变更不得自动放宽权限。

SOCKS5 默认 loopback。监听非 loopback 必須 username/password 加来源 allowlist，否则启动拒绝；RFC1929 口令本身不提供 LAN 加密，仍不能把入口直接开放公网。PSK/key_id 经权限受控文件或环境加载，不进日志/仓库；撤销 key_id 后终止其活动会话，替换密钥通过受信运维分发，不在旧受损信道明文广播新 secret。

## 10. 配置示例（设计 schema）

以下值用于明确边界，非已可运行配置；部署需要显式授权，默认拒绝是预期行为。

```toml
[server]
hub_id = "hub-a"
listen = "127.0.0.1:8443"
relay_allow = []
auth_window_secs = 120
auth_nonce_max_per_node = 65536
auth_nonce_store = "state/auth-nonces.sqlite"
decoy_site = "builtin"

[[nodes]]
id = "client-a"
key_id = "a-1"
secret_file = "secrets/client-a.key"
```

```toml
[client]
node_id = "client-a"
socks_listen = "127.0.0.1:1080"
udp_enabled = true
udp_max_payload_bytes = 61440
udp_queue_ttl_ms = 1000

[[servers]]
hub_id = "hub-a"
url = "https://a.example.com"
key_id = "a-1"
secret_file = "secrets/client-a-hub-a.key"
priority = 1

[[servers]]
hub_id = "hub-b"
url = "https://b.example.com"
key_id = "a-2"
secret_file = "secrets/client-a-hub-b.key"
priority = 2

[router]
final = "server" # direct/server；节点链用显式数组

[[router.rules]]
match = ["domain:*.internal.example"]
via = ["client-b", "client-c"]

[[services]]
name = "web"
proto = "tcp"
target = "127.0.0.1:8080" # 发布并不自动授权调用者

[[forwards]]
name = "a-web"
listen = "127.0.0.1:18080"
proto = "tcp"
hub = "auto"
via = []
destination = { type = "service", node = "client-a", name = "web" }

[socks_service_namespace]
enabled = false
suffix = "wsnet.invalid"

[transport]
data_fallback = true
max_candidates = 2
resume_grace_secs = 10
flow_window_bytes = 262144
session_window_bytes = 8388608
control_reserve_bytes = 65536
profiles = ["binary", "json", "html", "js", "css"]

[decoy]
enabled = false
interval_min_secs = 2
interval_max_secs = 15
max_bytes_per_sec = 4096
allowed_origins = ["https://a.example.com", "https://b.example.com"]
```

规则匹配与权限是独立步骤：路由选中了节点，不代表访问一定被允许。错误的 hub_id、节点缺失、未注册目标或无 ACL 应返回明确的本地/认证后失败，不能自动退回绕过策略的 direct。

## 11. nginx、HTTP 版本与部署

示例仅展示主路径；启用 profile 路径须在同一后端配置精确 location，不得改协议的标准握手。此示例未执行 nginx 配置测试。

```nginx
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/example/fullchain.pem;
    ssl_certificate_key /etc/ssl/example/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 1m;

    location / { root /srv/wsnet-site; try_files $uri $uri/ =404; }
    location = /m {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_read_timeout 30s;
    }
    location = /e {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 75s;
    }
    location = /w {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 75s;
    }
}
```

应用保活默认20秒，小于反代 idle timeout；负载变化不无限增加心跳/背景流量。所有业务/profile响应 no-store，不经共享 CDN缓存；普通站点静态资源可正常缓存。

nginx 是事件驱动，**不是一个 SSE 连接占一个 worker**。按 worker_connections、进程 FD 限额、客户端与 upstream socket、缓冲内存和 CPU 实测容量；HTTP/1.1 upstream keepalive 复用空闲连接，不能让多个同时活跃 SSE 共用一条 upstream TCP。WS 升级后同样长期占用 socket。

HTTP/2 需明确配置与协商，不是 nginx 版本升级自动开启；HTTP/2 stream ID 只在该连接内标识请求流，不是 wsnet session_id。前端 H2 可终结后转后端 H1.1，业务仍按认证的 sid/epoch 分流，无需为“短请求”禁用 H2。WS v1 基线使用 HTTP/1.1 RFC6455 upgrade，不假定所有 H2 中间件支持 extended CONNECT。

CDN 功能、套餐、超时/缓存/WAF限制随供应商配置变化，本轮未核实，不列固定“免费版100秒/必须Enterprise”等断言。部署验收分别测 WS upgrade、SSE flush、POST/profile 限长/缓存、连接寿命与来源头。per-message-deflate 默认不协商以控制压缩开销与攻击面，不以“浏览器默认不压缩”作为理由；浏览器行为与扩展协商需测。

## 12. 验收设计测试清单（均待实现后运行）

**本轮仅进行了文档静态检查；下列是计划，不是测试通过声明。** 正确性以受控故障注入/对照测试验证，不在真实外部目标上做无授权压力测试。

| ID | 场景与可判定预期 |
| --- | --- |
| T01 | 固定握手向量：两端派生相同 c2s/s2c key，两个方向 key 不同；同计数双向消息互不可反射，AAD换Hub/epoch验真失败 |
| T02 | 临近 packet_no/stream_id/offset 上限，禁止回绕或旧key重用；旧epoch重连消息拒绝 |
| T03 | 多线程/POST+WS 同Auth竞争，仅一次原子登记；满载仍在时间窗内旧Auth永不能因驱逐重获通过；未来timestamp覆盖最后可接受时刻 |
| T04 | nonce存储正常重启仍拒重放；存储丢失/不可用禁止新认证；多实例并发仅一成功，不共享hub_id时Auth跨Hub失败 |
| T05 | request_id同hash重复/响应丢失/跨载体重试只拨号一次且可查询；异hash拒绝；容量满拒新；窗口后不重执行；跨Hub结果未知不自动补做 |
| T06 | 独立Auth候选不同nonce/attempt；获胜者唯一、落选者释放；SSE不接受上行Auth；候选总数/时间预算不突破 |
| T07 | WS黑洞时关闭背景请求，真实字节仍经POST+SSE往返；再禁SSE后POST响应仍能传；HTML/JS/CSS/API模板可逆且不执行脚本 |
| T08 | 随机拆分HTTP chunk/SSE行/WS帧、错序/重复块、Fin先到：TCP字节流逐字节一致且只交付一次；冲突重叠/超限显式Reset |
| T09 | 同会话换载体不增加目标socket；恢复超10秒/3次重传/进程重启必须断流；内存与重排/重发预算不突破 |
| T10 | 慢消费者与多流公平性：按consumed_offset补credit；received确认不增加消费额度；重复/迟到Progress不超授信；控制队列仍可发Reset/Resume |
| T11 | UDP TCP控制关闭立即失效；来源IP/端口不匹配、FRAG非0、超大/截断/过期丢弃；IPv4/IPv6 BND地址可达；多目标响应不串association |
| T12 | UDP HOL故障注入记录排队/迟到/丢弃，不能宣称实时或零丢包；TCP在同负载不静默丢字节 |
| T13 | chain自环/重复/超4跳/无授权拒绝；中间一跳失败逆序释放；目标主动banner不早于Ready交付 |
| T14 | 主Hub失败：旧连接明确失败、新连接在备用Ready后成功；节点未注册备用时明确不可达；旧lease回调不删新注册 |
| T15 | 错sid、无/过期/重复BindProof、相同IP跨会话读取均拒绝；绑定后协议阶段响应合法、不把WS写成HTTP、不泄露其他sid记录 |
| T16 | 默认拒绝ACL、出口二次检查、DNS重绑定/特殊地址、非法SOCKS共享监听；仅显式允许的服务可访问 |
| T17 | DoS下连接/body/nonce/失败外观总预算成立；未知伪造来源头不能绕过限速；正常站点响应不无限保持 |
| T18 | nginx H1/H2 POST复用不会混sid，SSE及时flush，WS标准升级；profile路径全部精确配置、业务no-store；供应商限制按实测记录 |
| T19 | 标准TLS证书错误必须失败，保留前向保密；profile/UA/ALPN组合一致；padding/背景请求对性能及统计分布仅记录结果不推导不可识别 |
| T20 | 协议parser fuzz：长度整数溢出、重复key、非法base64、碎片/超长、未知版本，受限内存且无部分副作用 |
| T21 | Local Forward CLI 与静态配置生成相同 ServiceTarget；`:0` 返回实际端口；重复 name/listen 原子拒绝；动态项重启消失 |
| T22 | service offline/重注册/换 revision：listener 状态准确，新连接按新 lease，旧连接不复活；未经授权服务不出现在 services list |
| T23 | NodeAddressTarget 默认拒绝，仅显式 caller→node→host/port/proto ACL 通过；发布其他服务不产生横向权限 |
| T24 | 虚拟域名只在 ATYP=DOMAIN + remote-DNS 下解析；非法 slug、本地 DNS、raw address 编码拒绝；HTTPS 证书限制有明确诊断 |
| T25 | UDP Local Forward 来源 tuple/association/TTL/队列清理正确；多 Hub 仅新连接切换；非 loopback listener 无 allowlist 拒绝启动 |

## 13. 版本范围与非目标

- v1 设计范围：TLS保护、认证/replay/幂等、单Hub及同会话实际数据fallback、SOCKS5 TCP+UDP、Local Forward 命名服务/显式授权节点地址、受控同Hub chain、byte credit、多Hub新连接转移、可配置站点形态及有界背景请求。
- 原生 UDP/QUIC 隧道、跨 Hub chain、Hub 间会话/socket迁移、复杂自研 PFS/E2E、自动网页渲染与大规模行为模拟不在 v1 范围。TLS PFS 保持启用。
- TCP+TLS 是 nginx兼容与复杂度选择，不是“TCP一定安全、QUIC最难规避”的事实判断。ECH/QUIC 后续需重新核实标准支持与当时测量。
- 默认所有可选复杂混淆功能关闭或受限；不得通过未验证的“浏览器伪装”保证来替代认证、授权和限流。

## 14. Rust 模块规划（非现有代码）

推荐评估 Tokio、axum/hyper、tokio-tungstenite、rustls、serde/TOML、tracing；正式版本/依赖审计在实现前锁定。uTLS 为 Go 生态，Rust 指纹等效性需独立 PoC，不预设可直接移植。

模块职责：`protocol`(framing/version)、`crypto`(HKDF/nonce)、`auth_store`(原子防重放)、`operation`(幂等)、`transport`(WS/POST/SSE/profile)、`stream`(offset/credit)、`socks`(TCP/UDP association)、`forward`(Local TCP/UDP listener 与 ServiceTarget)、`control`(本地 IPC/CLI)、`routing`(chain/ACL)、`registry`(Hub lease)、`site`(公开响应)、`limits`(全局预算)。模块边界是设计，不创建 src/Cargo 文件。

## 15. 待解决问题与已知风险

> 保留用户已有未提交 §15 的全部问题编号与意图。以下“已落设计”只表示已修正文案，不表示实现、验证或风险已消失；原先错误建议在对应条目内纠正，不留作可执行指令。

### 15.1 设计层盲区

#### 15.1.1 「随机化 ≠ 不可区分」（统计 / 行为指纹）

P0，已落设计 §1.1/§6。TLS 外看不到 URL/MIME/渲染行为本身，只能在相应观察能力下分析统计关联；不能把具体浏览器请求图谱分类部署当已证事实。真实页面渲染保留为待评估选项，不升级为必做、也不声称能降低TLS密文熵。待验证 T19。

#### 15.1.2 内置假站可能成为集群指纹

P1，已落设计 §6.5。部署可注入正常站点内容；固定资源 hash 是潜在关联因素而非“最强代理证据”。待测公开响应与站点一致性；不自动生成任意第三方流量。

#### 15.1.3 padding 离散分布暴露特征

P1，已落设计 §6.8。`next_power_of_two` 仍产生离散档位，删除其“连续采样”建议；TLS分段与HTTP编码也会改变观察分布。默认关闭，可选有界字节区间采样，效果留 T19 对照测试。

#### 15.1.4 数据固定走 WS 是真实脆弱点

P1，已落设计 §6.7/§7.3。实际业务POST+SSE/POST响应fallback进入v1；不是只增加背景GET。仍有共享瓶颈、HOL和恢复预算限制，T07–T09待测。

#### 15.1.5 UDP-over-TCP 的实际效用需明确告知

P1，已落设计 §7.4 和 README。保留实时性风险意图，改为TCP HOL和过期数据迟到，不称天然乱序；不武断排除所有UDP用途。T11–T12待测。

### 15.2 安全层

#### 15.2.1 `relay_allow` 默认值过宽

P0，已落设计 §9.3/§10：默认[]，具体caller→hop→exit→target规则和出口二次校验仍是必要条件。T16待测。

#### 15.2.2 `secret` 轮换机制缺失

P1，已落设计 §5.4/§9.3：key_id、受信运维分发、撤销及关闭旧会话。撤销/短期双key过渡由部署显式批准，不用SecretRotate在旧信道分发新secret。PSK泄露对内部密文与外层TLS抓包的影响分开说明；轮换不能追回历史泄露。

#### 15.2.3 HMAC 时间窗 ±300s

P2，已落设计 §5.1：默认120秒/60–300秒可配、UTC、异常时钟暂停认证。时区不是Unix timestamp误差来源，收紧窗口也不能治NTP漂移。T03/T04待测。

#### 15.2.4 nonce 缓存的内存边界未明确

P0，已落设计 §5.1：精确集合+原子持久登记、有效期不提前逐出、条数/字节双限、故障fail closed。保留容量预算意图，不沿用“每节点4MiB必能容纳65,536条”未经压测的结构开销保证；Bloom不作为权威判断。T03/T04待测。

#### 15.2.5 SOCKS5 入站认证缺失

P1，已落设计 §9.3：非loopback认证+allowlist；RFC1929不加密局域网口令，不直接公网暴露。T16待测。

#### 15.2.6 SSE 长连接对 nginx worker 的消耗

P2，已落设计 §11。事件驱动worker服务多个连接，瓶颈是FD/socket/缓冲/CPU；HTTP/1.1 keepalive不能复用同时活跃SSE。保留容量压测问题，不再给“worker≥SSE并发×1.5”建议。T18待测。

### 15.3 协议细节

#### 15.3.1 POST `/m` 多会话并发的请求 / 响应归属

P1，已落设计 §4.4/§8，按认证hub/sid/epoch队列，HTTP/2 stream ID和来源IP不能替代sid。T15/T18待测。

#### 15.3.2 SOCKS5 UDP ASSOCIATE 的中继地址

P1，已落设计 §7.4，返回实际可达BND地址，不假定所有客户端都支持全零地址；NAT/多NIC显式advertise。使用专用RFC1928 UDP测试端，不用普通curl/Firefox TCP SOCKS成功替代UDP验收。T11待测。

#### 15.3.3 多跳 chain 的环路检测

P1，已落设计 §7.1：重复、自环、hop budget、逐边ACL与回滚。T13待测。

#### 15.3.4 服务断线时已发布服务的存量连接

P1，已落设计 §5.3/§5.5/§7.3。同Hub grace内可恢复载体，Hub/节点状态丢失则旧流失败；服务重注册不复活旧socket，跨Hub只恢复新连接。T09/T14待测。

#### 15.3.5 Ack 可靠性的隐含假设

P1，已落设计 §7.5：以累计received/consumed/limit offset取代nonce seq ACK；预留控制队列和定时重发进展，不等待下一Data充当ACK确认。预算/timeout耗尽显式失败。T10待测。

#### 15.3.6 反向服务缺少标准用户入口

P1，已落设计 §7.6 与 [USAGE.md](USAGE.md)：标准 SOCKS5 保持地址语义，Local Forward 作为节点/服务正式入口，虚拟域名默认关闭。补齐 ServiceTarget/NodeAddressTarget、服务发现过滤、生命周期、多 Hub、TCP/UDP 与非 loopback 边界。T21–T25待测。

### 15.4 工程实现前待定项

#### 15.4.1 Rust 技术栈选型

P2，§14给出候选，依赖版本/许可/维护性及Rust指纹能力仍待PoC。没有现成“uTLS crate”保证，不能为仿真混入未审计TLS实现。

#### 15.4.2 WS per-message-deflate

P2，§11默认不协商以限制压缩开销和攻击面；不声称所有浏览器默认不压缩。需测库的协商与拒绝路径，T18/T20待测。

#### 15.4.3 HTTP/2 多路复用与 POST 请求生命周期

P2，§11明确有限请求不等于短TCP；H2需配置/协商，H2 stream ID不等于sid。允许前端H2转后端H1.1，不为身份分流强制禁H2。T18待测。

#### 15.4.4 CDN 兼容性

P2，§11保留专项部署测试。删除未经核实的厂商套餐/100秒/强制Enterprise等断言；版本、地区、产品与配置需逐次以官方契约和实测确认。本轮没有联网查证。

### 15.5 文档与流程

保留原有整理意图：公开站点/profile/背景请求三类职责分明；报告按证据等级维护；后续需 SECURITY/CONTRIBUTING、变更记录和实现里程碑，但本轮不创建代码或扩大文件范围。未来更新GFW报告须记研究测量时间/地点/方法，而非将传闻补进“最新”结论。

### 15.6 优先级与关闭条件

P0：方向隔离、认证nonce持久原子保留、默认拒绝已落设计；必须 T01–T05/T16通过才进入发布评审。P1：实际fallback、credit、UDP、chain、多Hub边界已落设计；T07–T15待实现。P2：库/供应商/指纹/性能仍需PoC。P3：后续文档与运维流程补齐。没有任何条目因本轮文字修复被标成“协议测试已通过”。

## 附录 A：历史威胁证据与设计映射

完整来源与证据边界见 [GFW-RESEARCH.md](GFW-RESEARCH.md)。本轮只整理已有引用，没有新联网调研。DNS注入、HTTP Host/TLS SNI干扰、主动探测及区域差异有历史研究；QUIC Initial检测不等于破解完整QUIC/TLS会话。

| 风险 / 证据边界 | 设计响应 | 不承诺 |
| --- | --- | --- |
| 历史主动探测研究；不同协议探测方式不同 | §5认证/replay、§9阶段响应 | 仅靠错误外观即可隐藏代理身份 |
| SNI可见、地址/域名封锁 | §11标准TLS、明确部署边界 | 正常SNI或与站点同IP即可避免封锁 |
| TLS特征/包长时序可作分类；具体JA4/AI部署未核实 | §6.6候选评估与T19对照测试 | 已证GFW普遍部署某分类器、指纹相同等于浏览器 |
| 2024–2025论文报告QUIC Initial/SNI干扰 | v1为nginx兼容与复杂度选TCP+TLS | 全球首例、最活跃、TCP永远有效、ECH长期普适有效 |
| 区域与时间差异 | 多Hub新连接恢复、明确失败和测试观察 | 单地点测量代表全国当前所有线路 |

## 附录 B：本轮 review 修复映射

| review 类别 | 原正文修复 | 验收 |
| --- | --- | --- |
| 1 双向nonce重用 | §4.2方向HKDF、统一packet计数、溢出和epoch | T01–T02 |
| 2 有效nonce逐出/并发/重启 | §5.1持久原子登记、满载拒新、共享存储边界 | T03–T04 |
| 3 replay/幂等/候选混用 | §5.2与§6.7三类身份、窗口/结果未知 | T05–T06 |
| 4 弱网数据缺口 | §4.3、§6.7、§7.3实际POST/SSE fallback及预算 | T07–T09 |
| 5 Hub透明迁移承诺 | §5.3/§5.5新连接转移与注册可见性 | T09/T14 |
| 6 ACK/背压不完整 | §7.2/§7.5字节credit、累计消费与控制预留 | T08/T10 |
| 7 UDP细节 | §7.4TCP绑定/来源/FRAG/BND/多目标/过期/HOL | T11–T12 |
| 8 失败响应/授权 | §4.4/§9.1–§9.3绑定凭据、阶段一致、默认拒绝 | T15–T17 |
| 9 加密论据 | §1.1/§5.4标准TLS高熵与TLS PFS | T19 |
| 10 §15和研究事实 | §11/§14/§15逐项纠错，附录A和报告降格证据 | T18–T20及后续来源核实 |
| 11 反向服务用户入口 | §7.6 Local Forward + 可选虚拟域名；USAGE CLI/配置/生命周期 | T21–T25 |
