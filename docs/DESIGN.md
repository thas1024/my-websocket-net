# wsnet — 多协议随机分发（混淆）轻量代理设计文档

> 参考 [XTLS/Xray-core](https://github.com/XTLS/Xray-core)（"Penetrates Everything"）的流量伪装思想，
> 用 Rust 实现一个**轻量、可被 nginx 反代、多载体随机分发、支持节点中继与反向访问**的隧道代理。

## 1. 概述

wsnet 是一个 **Client-Server 星型拓扑 + 节点中继** 的代理：

- **服务端（wsnetd）**：中心枢纽（Hub）。本质是一个 HTTP 服务器，对外暴露三个**中性载体端点**：
  - `POST /m` —— 请求/响应载体；
  - `GET /e`  —— **SSE** 推送载体；
  - `GET /w`  —— **WebSocket** 全双工载体。
  它维护「在线节点 / 已发布服务」注册表，在节点间中继数据流，并具备**出口（egress）**能力。
- **客户端（wsnet）**：同时是「客户端」和「服务端」：
  - 作为**客户端**：对外暴露 **SOCKS5** 入站，把本机/局域网程序流量经隧道转发；
  - 作为**服务端**：接收服务端派发的连接请求，在本机建立 TCP 连接（反向访问），也作为**中转节点**代理其他节点流量。

因此「所有客户端均是服务端，能够作为中转节点代理流量」天然成立。

### 1.1 设计核心：协议不绑定职能，随机分发以实现混淆

传统做法把「认证 = HTTPS、控制 = 固定通道、数据 = WebSocket」——职能与协议一一绑定，特征明显。wsnet 的核心理念是 **职能与载体解耦**：

1. **统一消息**：认证、控制、数据都是同一种 `Message`（逻辑消息），序列化后统一用会话密钥做 **AEAD 信封** 加密。加密后，认证/控制/数据在字节层面**不可区分**。
2. **统一信封**：所有载体传输的是**同一格式**的加密信封（`nonce + ct`），只是文本载体用 base64/JSON、二进制载体用裸字节。
3. **随机分发**：每条消息在发送时，从**当前可用的载体集合**中**随机**选择一个承载，不做任何「某类消息固定走某协议」的绑定。

因此，观察者看到的只是「一个正常 HTTPS 网站，混着 POST 请求、SSE 长连接、WebSocket 长连接，三者在传统计上相似、且每会话随机变化的加密负载」，无法通过「协议 ↔ 职能」的对应关系来识别或阻断。

### 1.2 三个载体端点

| 端点 | 方法 | 连接 | 天然方向 | 可承载的消息 |
| --- | --- | --- | --- | --- |
| `/m` | POST | 短 | 双向（请求→响应） | 认证、控制；响应可捎带服务端→客户端消息 |
| `/e` | GET | 长（SSE） | S→C 推送 | 控制 |
| `/w` | GET(Upgrade) | 长（WS） | 双向 | 认证、控制、数据 |

> 三个端点都是标准协议、都走 TLS，且可挂在正常网站后面（nginx 把其余路径回落到真实站点），从外部看就是「一个带 API / SSE / WebSocket 的普通 HTTPS 网站」。

### 1.3 与 Xray-core 的对应关系

| Xray-core 概念 | wsnet 对应实现 |
| --- | --- |
| inbound（socks / vmess / vless） | 客户端内置 SOCKS5 入站 |
| outbound（freedom / vless / chain） | 路由规则 `direct` / `server` / `<node-id>` |
| VMess/VLESS 的 UUID 认证 | `node_id` + `secret` 的 HMAC 挑战认证 |
| fallback / 回落 | nginx 在非代理路径回落到真实站点 |
| transport（ws / grpc 等）多协议 | POST / SSE / WS 三载体随机分发 |
| mux（多路复用） | 数据面按 `stream_id` 多路复用 |
| routing（规则 + 最终 outbound） | 路由器 `rules` + `final` |
| reverse（bridge/portal 反向代理） | 服务发布（services）+ 经节点访问（via node） |
| 节点链式代理（chain） | `via = <node-id>` 经服务端中转 |

### 1.4 需求映射（Traceability）

| # | 需求 | 设计落点 |
| --- | --- | --- |
| 1 | Rust 技术栈、基于 WebSocket 的轻量代理 | §14 工程结构；数据面 WebSocket（§7） |
| 2 | 客户端经隧道经服务端代理上网 | §2 正向代理；§7.1（`via` 空 / `server`） |
| 3 | 其他节点经服务端反向访问客户端节点 | §2 反向访问；§7.1（`service` / `via=node`） |
| 4 | 客户端可设置最终上网节点 | §6 路由；`router.final` |
| 5 | 客户端对外暴露 SOCKS5 | §1 客户端 SOCKS5 入站；§10 配置 |
| 6 | 加密认证 | §5 认证与会话（HMAC + HKDF + AEAD） |
| 7 | 反向代理到另一客户端端口 | §7.1（`via=node` + `target=host:port`） |
| 8 | 所有客户端均为服务端、可中转 | §1「客户端 = 服务端」；§8 中继引擎 |
| 9 | 标准 WebSocket，可 nginx 反代 + TLS | §1.2 端点；§11 nginx 配置 |
| 10 | 非完全 WebSocket：HTTPS + SSE + WS 混搭 | §1.2 三载体；§6 随机分发 |
| 11 | 认证握手可走 HTTPS | §5.1（`POST /m` 认证） |
| 12 | 协议不绑定职能、随机性混淆 | §1.1、§6 |
| 13 | 掺杂无意义 HTML/JS/CSS 请求 | §6.4 伪装流量 |
| 14 | 正常 Web 站点伪装 | §6.5 |
| 15 | 防重放；重放时按协议类型返回伪装内容 | §5.1、§4.2、§9.1 |

## 2. 架构与角色

```
                         浏览器 / 普通用户
                              │
                    ┌─────────▼──────────┐
                    │  nginx（TLS 终结）   │   "/" 等路径 → 真实网站（回落）
                    │  /m /e /w → wsnetd  │
                    └─────────┬──────────┘
                              │ HTTPS/SSE/WS
                    ┌─────────▼──────────┐
                    │  wsnetd（Hub）      │
                    │  /m /e /w · 注册表  │
                    │  · 中继 · 出口       │
                    └───┬────────────┬────┘
              SSE+WS      │            │     SSE+WS
        ┌────────────────▼─┐        ┌─▼────────────────┐
        │ wsnet 客户端 A    │        │ wsnet 客户端 B     │
        │ - SOCKS5 :1080   │        │ - SOCKS5 :1080    │
        │ - 发布服务 web:8080│        │ - final = A       │
        │ - 可作为中转节点   │        │ - 可作为中转节点    │
        └──────┬───────────┘        └───────▲───────────┘
               │ 本机 TCP                   │ SOCKS5
               ▼                            │
        ┌──────────────┐           ┌────────┴──────────┐
        │ 本机 8080 服务 │           │ 浏览器 / curl / 程序 │
        └──────────────┘           └───────────────────┘
```

### 三种数据路径

1. **正向代理（客户端上网）**：`程序 → SOCKS5(客户端B) → 服务端 → 目标`。
2. **节点中转（chain）**：`程序 → SOCKS5(客户端B) → 服务端 → 客户端A → 目标`。
   B 把 A 设为「最终上网节点」，服务端只做信令 + 数据中继。
3. **反向访问**：`客户端B → 服务端 → 客户端A → 本机端口`。

## 3. 分层设计

```
┌───────────────────────────────────────────────┐
│ 应用层   SOCKS5 / TCP dial / 服务发布            │
├───────────────────────────────────────────────┤
│ 消息层   统一 Message（认证/控制/数据）            │
├───────────────────────────────────────────────┤
│ 加密层   HMAC 挑战 · HKDF 会话密钥 · AEAD 信封    │
├───────────────────────────────────────────────┤
│ 分发层   随机选择载体（POST / SSE / WS）          │
├───────────────────────────────────────────────┤
│ 传输层   HTTPS(1.1/2) · SSE · WS(RFC 6455)     │
├───────────────────────────────────────────────┤
│ 承载     TCP / (nginx →) TLS                  │
└───────────────────────────────────────────────┘
```

## 4. 统一消息与信封

### 4.1 消息（Message）

所有逻辑动作都建模为一个 `Message`。序列化格式：

```
[1 字节 kind][payload]
```

- `kind=0`：JSON 控制消息，`payload` = UTF-8 JSON；
- `kind=1`：`Data`（数据帧），`payload = [stream_id u32][raw bytes]`；
- `kind=2`：`Close`，`payload = [stream_id u32]`；
- `kind=3`：`Err`，`payload = [stream_id u32][code u8]`。

控制消息（JSON）枚举：

| 消息 | 方向 | 含义 |
| --- | --- | --- |
| `Auth {node_id, ts, nonce, sig}` | C→S | 认证（**唯一**不加密的引导消息，HMAC 签名） |
| `AuthOk {session_id, ts, sig_server, key_salt}` | S→C | 认证应答（明文，HMAC 签名） |
| `AuthErr {msg}` | S→C | 认证失败 |
| `Hello {version, services{}, encrypt_data}` | C→S | 上线 + 发布服务 + 声明数据加密 |
| `Connect {stream, target?, service?, via?, carrier?}` | 双向 | 申请建立数据流 |
| `ConnectResult {stream, ok, msg?}` | C→S | 出口节点回传拨号结果 |
| `ConnectOk {stream}` / `ConnectErr {stream, msg}` | S→C | 数据流建立结果 |
| `PeerList {nodes[]}` | S→C | 在线节点/服务快照 |
| `SvcOk {name}` / `SvcErr {name, msg}` | S→C | 服务发布结果 |
| `Ping {ts}` / `Pong {ts}` | 双向 | 心跳 |
| `Bye {reason}` | S→C | 服务端主动断开 |

### 4.2 信封（Envelope）

加密后的 `Message` 统一装进信封：

```
nonce (12 字节) + ct (AEAD 密文)
```

- **算法**：ChaCha20-Poly1305，密钥为 `session_key`（32 字节）。
- **nonce**（12 字节，两类布局**域分离**、永不碰撞）：
  - 控制消息：`[0xFF][0u8;3][counter u64]`，每个方向一个单调递增 `counter`；
  - 数据消息（`Data/Close/Err`）：`[dir u8][stream_id u32][seq u32][0u8;3]`，
    `dir`=`0`(C→S)/`1`(S→C)，`seq` 每 (dir, stream) 递增——保证**每流字节顺序**。
  - 首字节 `0xFF` 与 `0/1` 使两类 nonce 互不重叠：接收端凭 nonce 首字节即区分「控制/数据」，并天然防止跨类型替换。
- **AAD**：常量域分隔符 `"wsnet/v2"`。类型绑定由「nonce 域分离 + 明文首字节 `kind` 被 AEAD 认证」共同保证；
  接收端解密后按明文的 `kind` 字节分派，无需在解密前知晓类型。
- **接收端防重放**：控制消息按 `counter` 去重（允许跨载体乱序，用去重集而非顺序校验）；数据消息按 (dir, stream) 校验 `seq` 严格递增。命中重放时**静默丢弃**，并按 §9.1 的协议类型伪装响应策略处理（不回代理特有错误）。

### 4.3 载体帧格式（同一信封的三种编码）

| 载体 | 信封编码 |
| --- | --- |
| `POST /m` | 请求/响应 body = JSON `{"nonce":"<base64 12B>","ct":"<base64>"}`（可为数组以批量） |
| `GET /e` (SSE) | `data: <base64(JSON 信封)>` |
| `GET /w` (WS) | 一条 **Binary** WS 消息 = 裸信封 `[nonce 12B][ct...]` |

认证引导消息（`Auth`/`AuthOk`/`AuthErr`）**不加密**，直接以 JSON 传输：
- 走 `POST /m`：body/response 为 JSON；
- 走 `GET /w`：以 WS **Text** 消息传输。

### 4.4 端点契约（HTTP API 规格）

| 端点 | 方法 | 关联 | 请求体 | 响应体 | 说明 |
| --- | --- | --- | --- | --- | --- |
| `/m` | POST | 无（认证）或 `X-Wsnet-Sid`（控制） | 认证：明文 `Auth` JSON；控制：`[信封]` JSON 数组 | 认证：明文 `AuthOk/AuthErr` JSON；控制：`[信封]` JSON 数组（可为空） | 请求/响应载体 |
| `/e` | GET(SSE) | `?sid=` | - | `data: <base64(信封)>` 行 + `: ping` 注释心跳 | 服务端→客户端推送 |
| `/w` | GET(Upgrade) | 无（认证）或 `?sid=` | 认证：首条 **Text** = 明文 `Auth`；已认证：**Binary** = 信封 | 同左 | 全双工载体 |

- **认证入口二选一（客户端随机）**：`POST /m` 或 `GET /w`（首条 Text 消息）。`/e` 仅 S→C，不能作为认证入口。
- 用 `?sid=` 接入 `/w` 时，首条 **Binary** 帧必须是可用 `session_key` 解密的信封（可携带任意消息，如 `Ping`），作为「密钥持有证明」；解密失败立即断开。
- 认证后，`/m` 请求/响应体、`/e` 事件、`/w` 二进制帧全部为加密信封；`/m` 与 `/e` 用 JSON/base64 编码，`/w` 用裸字节。
- **错误约定**：业务失败统一 HTTP `200` + 失败消息（认证失败 `AuthErr`、连接失败 `ConnectErr`），避免状态码侧信道；仅协议违规（非法 JSON / 非法信封 / 缺 sid）返回 `400` 或直接断开。

## 5. 认证与会话（加密认证 + 随机载体）

### 5.1 握手流程

认证消息**可选走 POST 或 WS**（客户端随机选择，二者协议地位完全对等）：

```
client                                          server
  │  Auth {node_id, ts, nonce, sig} ──────────────►  (POST /m 或 WS Text)
  │     sig = HMAC-SHA256(secret, "auth"‖node_id‖ts‖nonce)
  │                                            校验：时间窗(±300s)、nonce 防重放、sig
  │  ◄──────────── AuthOk {session_id, ts, sig_server, key_salt}
  │     sig_server = HMAC-SHA256(secret, "authok"‖session_id‖ts‖key_salt)
  │  校验 sig_server（双向鉴权）
  │  双方派生会话密钥：
  │  session_key = HKDF-SHA256(ikm=secret, salt=nonce‖key_salt, info="wsnet/v2")
  │
  │  此后所有消息（认证/控制/数据）统一用 session_key 做 AEAD 信封
```

- `node_id` + `secret`：预共享凭据（服务端配置登记所有节点）。
- `nonce`/`key_salt`：本次握手随机量；`session_id`：服务端签发的会话标识。
- **防重放**：
  - 时间窗：`|now - ts| ≤ 300s`（可配），超窗即拒；
  - nonce 一次性缓存：按节点维护 `nonce → 过期时间`，命中即判定重放；带 TTL 自动逐出 + 容量上限（防内存耗尽）；
  - HMAC 绑定 `ts` 与 `nonce`：任何篡改都会导致签名校验失败。
- **双向鉴权**：`sig_server` 让客户端确认「服务端知道 secret」。
- **失败不泄露**：被判定重放或校验失败时，不返回代理特有错误，而按 §9.1 的协议类型伪装响应策略回应（静默、无特征）。

### 5.2 会话生命周期

1. 客户端随机选 POST 或 WS 发送 `Auth` → 得到 `session_id` + `session_key`。
2. 建立 `/w`（WS）与 `/e`（SSE）两个长连接（用 `session_id` 关联，首个信封证明密钥持有）。
3. `Hello`（走任一载体）→ 服务端登记「在线 + 数据面就绪」，此后才向其派发 `connect`。
4. 客户端维持一个 POST 轮询循环：有消息即发 `/m`，否则按随机抖动（1~3s）发空 `/m`，用于捎带服务端→客户端消息（见 §6.2）。
5. 任一长连接断开 → 整体重连：重发 `Auth` → 重开 `/w`/`/e` → 重发 `Hello`。

### 5.3 客户端运行状态机

```
            ┌──────────────────────────────┐
            │  OFFLINE（初始 / 重连退避）      │
            └──────────────┬───────────────┘
                           │ 随机选 POST 或 WS 发起 Auth
                           ▼
            ┌──────────────────────────────┐   AuthErr / 超时
            │  AUTHING                      │──► OFFLINE（退避 1s→30s）
            └──────────────┬───────────────┘
                           │ AuthOk → 派生 session_key
                           ▼
            ┌──────────────────────────────┐
            │  CONNECTING（开 /w + /e）      │
            └──────────────┬───────────────┘
                           │ /w 首帧密钥证明 + /e 就绪
                           ▼
            ┌──────────────────────────────┐   任一长连接断开 / Bye / 认证过期
            │  READY（发 Hello → 收发流量）   │──► OFFLINE
            └──────────────────────────────┘
```

- **退避重连**：指数退避 `1s → 2s → 4s → … → 30s` 封顶，成功建立后重置。
- **会话内常驻任务（7 类）**：`/w` 读、`/w` 写、`/e` 读、`POST /m` 轮询、心跳、伪装流量（§6.4）、SOCKS5 监听。
- **断线语义**：所有未完成流的 `pending` 一次性失败、本地流全部 `Close`；已发布服务在重发 `Hello` 时自动恢复注册。

## 6. 随机分发策略（混淆核心）

### 6.1 客户端 → 服务端（`C→S`）

对每条待发消息，从**当前可用载体**中等概率随机选择：

- 可用集 = `{WS(若 /w 已建立), POST}`；
- 选 POST：封装信封写入 `/m` 请求体；选 WS：封装信封作为 Binary 帧发送。
- **例外（正确性约束）**：`Data/Close/Err` 数据消息**固定走 WS**——多载体会破坏「每流字节顺序」，见 §7.3。

### 6.2 服务端 → 客户端（`S→C`）

服务端对每条待发消息，从可用载体中随机选择：

- 可用集 = `{WS, SSE, POST 响应}`；
- 选 WS → 立即写入 `/w`；选 SSE → 立即写入 `/e`；
- 选 POST 响应 → 进入该会话的**待发队列**，等下一次客户端 `/m` 请求时捎带返回（因此客户端需按随机抖动轮询 `/m`）。
- 数据消息固定走 WS。

### 6.3 随机源与可配置项

- 随机源：系统 CSPRNG（`rand::rngs::OsRng`）。
- `data_mix`（默认 `false`）：未来开启后，数据流在建立时可随机选「POST 分块上传 + SSE 下载」配对载体；v1 仅 WS（每流保序），`Connect.carrier` 字段已预留。

### 6.4 伪装流量（Decoy Traffic）：掺杂无意义的 HTML/JS/CSS 请求

在真实代理流量之间**随机掺杂无意义的静态资源请求**（HTML / JS / CSS / 图片 / JSON），使整体流量看起来像普通用户在浏览网页，进一步抹平代理特征：

- **服务端内置伪装资源**：wsnetd 默认提供一组极简但「像那么回事」的静态端点
  （`/index.html`、`/assets/style.css`、`/assets/app.js`、`/img/logo.svg`、`/favicon.ico`、`/api/status.json` 等），
  返回带正确 `Content-Type` 的少量真实内容。
- **客户端伪装请求器**：后台任务按**随机间隔**（默认 2~15s 抖动）随机挑一个资源发起 GET（偶发 HEAD/OPTIONS），
  并随机化请求头（浏览器 UA、Accept、Accept-Language、Referer 等），使每条请求都像真实浏览器发起的普通资源加载。
- **可扩展**：`decoy.extra_urls` 可配置指向真实站点的额外伪装目标，进一步提高真实性。
- 伪装请求**无意义**：内容即取即弃，仅用于混淆，不影响任何代理路径。
- **内置资源清单（服务端）**：`/index.html`、`/about.html`、`/assets/style.css`、`/assets/app.js`、`/assets/vendor.js`、`/img/logo.svg`、`/img/banner.png`、`/favicon.ico`、`/robots.txt`、`/manifest.json`、`/api/status.json`，均返回带正确 `Content-Type` 与 `Content-Length` 的少量内容。
- **请求头随机化**：从 UA 池随机取 `User-Agent`（现代 Chrome / Firefox / Safari / Edge 若干），并随机组合 `Accept`、`Accept-Language`、`Accept-Encoding`、`Referer`（指向本站其它页面）、`Cache-Control` 等；方法以 GET 为主，约 10% 概率 HEAD。
- **时机随机化**：发送间隔在 `[interval_min, interval_max]` 均匀随机，再叠加 ±30% 抖动，避免周期性特征。
- **与真实流量的交错**：伪装请求由独立任务发起，与代理流自然交错，不做任何同步或固定顺序。

### 6.5 Web 站点伪装（内置正常网站 + 统一回落）

除「nginx 回落到真实站点」外，wsnetd 内置一个**可独立浏览的多页面正常网站**，使**直连探测**（绕过 nginx）也看到正常站点，而非裸 404：

- **内置站点结构**：`/`（首页）、`/about.html`、`/posts/`（文章列表/详情）、`/assets/style.css`、`/assets/app.js`、`/img/*`、`/favicon.ico`、`/robots.txt`、`/sitemap.xml`、`/404.html`，各页面返回带正确 `Content-Type` 的少量真实 HTML。
- **路径匹配优先级**：代理端点（`/m /e /w`）> 内置站点/静态资源 > 404 页面。仅精确命中代理路径才走代理逻辑，其余一律按站点处理。
- **统一伪装响应**：任何**未匹配路径**一律返回内置 `404.html`（HTTP 404 + 正常 HTML），而非裸错误；`GET /` 返回首页。
- **回落目标可配**：`server.decoy_site`（默认 `builtin`）可选 `builtin`（内置站点）或 `none`；当 nginx 已在 `/` 回落真实站点时，可设 `none` 交由 nginx 处理。
- **与 nginx 分工**：nginx 负责「非代理路径 → 真实站点」，wsnetd 内置站点负责「绕过 nginx 的直连探测」，二者叠加后任何路径都看不到代理特征。

## 7. 数据面：流多路复用与半关闭

### 7.1 流建立（统一时序）

`Connect` 字段语义：

| 场景 | target | service | via |
| --- | --- | --- | --- |
| 服务端出口 | `host:port` | - | 空 / `"server"` |
| 经节点 A 出口（中转） | `host:port` | - | `"client-a"` |
| 反向访问 A 已发布服务 | - | `"web"` | `"client-a"` |
| 反向访问 A 某端口 | `host:port` | - | `"client-a"` |

**正向/中转/反向统一时序**（B 经 A 访问目标 `T`）：

```
B: Connect{stream:s1, target:T, via:A}  ──(随机载体)──► Server
Server: 立即 ack（不等待拨号）
Server: 分配 A 侧流 s2 ── Connect{stream:s2, target:T, caller:B} ──► A
A: 本机拨号 T ── ConnectResult{stream:s2, ok:true} ──► Server
Server: 建立中继映射 (B,s1)↔(A,s2) ── ConnectOk{stream:s1} ──► B
B ◄──Data(/w)──► Server ◄──Data(重编码 /w)──► A ◄──TCP──► T
任一侧 Close → 转发另一侧；两侧均关闭 → 释放映射
```

- **目标解析发生在出口节点**：`target` 域名由最终拨号的节点解析。
- **命名服务由服务端解析**：`service` 命中注册表后改写为 `target` 再下发。
- **流 ID 每连接独立**：服务端在两段 `/w` 上使用各自 `stream_id` 并维护双向映射。

### 7.2 半关闭

- 本地读侧 EOF → 发 `Close`（表示「我这边读结束」）；
- 收到 `Close` → `shutdown(Write)`（不再写，仍可读）；
- 两侧都结束 → 释放该流。对 HTTP 长连接、`rsync`、流式上传等依赖半关闭的协议是必要的。

### 7.3 为什么数据固定走 WS（v1）

`Data` 消息必须**按流保持字节顺序**。POST 与 SSE 是相互独立的 TCP 连接，跨载体无法保证同一流的到达顺序；WS 单连接天然保序，故 v1 数据固定走 WS。控制消息是小 JSON、无顺序要求，故可完全随机分发（这是混淆的主体）。未来通过 `Connect.carrier` + 每流重排缓冲，可实现**每个流**在不同载体上的随机化。

## 8. 服务端中继引擎

服务端维护：

- `sessions`：`session_id → Session{node_id, key, sse_tx, ws_tx, post_queue}`。
- `services`：`(node_id, name) → local_addr`。
- `relays`：`(session_id, stream_id) → 对端 (session_id, stream_id)`（含半关闭状态）。

`Data` 消息：查 `relays`，命中则**改写 stream_id 后转发**；未命中回 `Err`。会话断线 → 清理其所有流，向对端发 `Close`，广播新 `PeerList`。

## 9. 安全模型与威胁分析

> GFW 封锁原理的完整调研见 [附录 A](#附录-agfw-威胁模型与对抗映射) 与 [docs/GFW-RESEARCH.md](GFW-RESEARCH.md)。

| 威胁 | 对策 |
| --- | --- |
| 未授权接入 | `secret` + HMAC 挑战；错误即拒绝 |
| 重放攻击 | 时间窗 + nonce 一次性缓存；重放时按 §9.1 返回协议类型伪装内容（不泄露） |
| 中间人伪造服务端 | `sig_server` 反向签名（双向鉴权） |
| 传输窃听/篡改 | nginx TLS + 全部消息 AEAD（认证引导除外，其已带 HMAC） |
| `session_id` 从 URL 泄漏 | 首个信封用密钥 AEAD 绑定，仅知 sid 无法伪造 |
| 慢流拖垮整条连接 | 每流有界通道 + 溢出断开（`Err`） |
| 跨节点越权 | 服务端 `relay_allow` 白名单（默认 `"*"`） |
| 协议指纹识别 | 三载体随机分发 + 统一信封 + nginx 回落真实站点 |

**已知边界（v1）**：服务端是可信中继枢纽，可见明文（与 Xray 默认「服务端即出口」一致）；端到端（B↔A）加密列为未来工作。仅建议将 `secret` 用于受信网络。

### 9.1 重放 / 探测的伪装响应策略（按协议类型）

重放检测或校验失败时，**绝不返回代理特有错误**（否则等于向探测者确认「这里是一个代理」）。服务端按请求协议类型返回**合适的伪装内容**：

| 协议 / 端点 | 触发场景 | 伪装响应 |
| --- | --- | --- |
| HTTPS `POST /m` | Auth 重放 / 校验失败 / 非法 JSON | HTTP 200 + 正常 API 风格 JSON（如 `{"code":0,"data":null}`）或普通 404 HTML；不含 `AuthErr`/`replay` 等字样 |
| WebSocket `GET /w` | 重放的认证帧 / 非法首帧 / 密钥证明失败 | 完成升级后立即发送正常 `Close`（code 1000），或拒绝升级返回普通 HTML；不发送代理错误帧 |
| SSE `GET /e` | 无效 `sid` / 重放信封 | 返回正常 SSE 流：几条良性 `data:` 事件 + `: ping` 注释心跳，随后保持或正常结束；无异常终止 |
| 其它未匹配路径 | 任意探测 | 返回内置 `404.html` 或首页（见 §6.5） |

- **静默丢弃**：认证后的**控制消息重放**（AEAD counter 去重命中）静默丢弃，不回错误帧；必要时在随机延迟后按上表响应，避免时序特征。
- **响应不可区分性**：伪装响应与「正常失败」共用同一套响应，使重放者无法区分「被拒绝 / 目标不是代理 / 服务异常」。
- **日志脱敏**：重放 / 失败事件仅以计数与内部告警记录，不向对端泄露具体原因。

## 10. 配置示例

### 服务端 `server.toml`

```toml
[server]
listen = "0.0.0.0:8443"
relay_allow = ["*"]            # 允许作为 via 的节点；"*" 表示全部
ping_interval = 30
decoy = true                   # 提供内置伪装静态资源（/index.html 等）
decoy_site = "builtin"         # 内置正常网站：builtin | none

[[nodes]]
id = "client-a"
secret = "change-me-a"

[[nodes]]
id = "client-b"
secret = "change-me-b"
```

### 客户端 `client.toml`

```toml
[client]
node_id      = "client-a"
secret       = "change-me-a"
server       = "https://example.com"   # 基地址；自动拼 /m /e /w
socks_listen = "127.0.0.1:1080"
encrypt_data = true

[router]
final = "server"               # direct | server | <node-id>

[[router.rules]]
match = ["cidr:192.168.0.0/16"]
via   = "direct"

[services]                     # 反向访问：发布本机服务给其他节点
"web" = "127.0.0.1:8080"
"ssh" = "127.0.0.1:22"

[decoy]                        # 伪装流量：随机掺杂无意义 HTML/JS/CSS 请求
enabled      = true
interval_min = 2               # 秒（随机下界）
interval_max = 15              # 秒（随机上界）
extra_urls   = []              # 可选：额外外部伪装目标（真实站点）
```

## 11. nginx 反代 + TLS + 回落示例

```nginx
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # 回落：其余路径指向真实网站，增强伪装
    location / { proxy_pass http://127.0.0.1:8080; }

    location /m { proxy_pass http://127.0.0.1:8443; proxy_set_header X-Real-IP $remote_addr; }

    location /e {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_buffering off;              # SSE 必须关闭缓冲
        proxy_read_timeout 300s;
    }

    location /w {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
    }
}
```

## 12. 测试策略

- **单元测试**：
  - `msg`：`Message` 序列化/反序列化往返；控制消息 JSON 兼容性。
  - `crypto`：`auth_sig`/`auth_ok_sig` 正确性；`derive_session_key` 确定性；AEAD 加解密往返；nonce 重放 / 乱序拒绝。
  - `router`：`domain:` / `cidr:` 规则匹配、`final` 回退。
  - `socks5`：握手解析（IPv4 / 域名 / IPv6）、错误应答。
- **集成测试（in-process）**：启动 wsnetd 于随机端口 + 本地 echo TCP 服务，用协议级客户端模拟两个节点，验证：
  1. 认证成功 / 错误 secret 拒绝；
  2. 服务端出口（`via=server`）数据往返；
  3. 中转（`via=node`）数据往返（含半关闭）；
  4. 反向访问（命名服务 + 端口）；
  5. 随机分发下（多次运行）消息在三种载体间均能正确收发。
- **端到端测试**：真实 wsnet 客户端（SOCKS5）+ `curl --socks5` 经中转节点访问目标。
- **混淆自检**：抓包断言三种载体（POST/SSE/WS）的负载均无明文特征、伪装资源请求随机出现。
- **重放与伪装响应**：
  - 重放同一 `Auth`（含有效签名）→ 拒绝且响应无代理特征；
  - 重放认证后的控制信封 → 静默丢弃；
  - 对 `/m` `/w` `/e` 分别注入重放 / 非法请求 → 断言响应符合 §9.1 的协议类型伪装内容，且不含 `replay`/`auth` 等敏感字样。

## 13. 限制与未来工作

- **传输层约束**：v1 仅走 TCP + TLS（WS/SSE/POST），**不使用 QUIC/HTTP3**——规避当前最活跃的 QUIC-SNI 解密封锁面（见附录 A.3）；未来可评估 ECH 或 QUIC 载体。
- **UDP**：当前仅 TCP（SOCKS5 `CONNECT`）；未来支持 `UDP ASSOCIATE`。
- **数据面多载体随机化**：`data_mix` 开启后，每流可随机选「WS / POST 分块上传 + SSE 下载」，实现数据面的载体随机（需每流重排缓冲）。
- **端到端加密**：引入节点间 X25519 协商，实现 B↔A 全程加密（服务端不可读）。
- **动态路由**：`PeerList` 已就绪，未来做自动选路与故障转移。
- **滑动窗口流控**：替换 v1 的「有界通道 + 溢出断开」。
- **更多载体**：gRPC、HTTP/2 分帧、WebSocket 多路径等。

## 14. 工程结构

```
my-websocket-net/
├── Cargo.toml
├── docs/DESIGN.md
├── docs/GFW-RESEARCH.md
├── README.md
├── src/
│   ├── lib.rs
│   ├── msg.rs              # 统一 Message（认证/控制/数据；含 Data/Close/Err 帧）
│   ├── envelope.rs         # AEAD 信封（三种载体编码）
│   ├── crypto.rs           # HMAC 挑战 + HKDF + AEAD
│   ├── config.rs           # 配置加载
│   ├── router.rs           # 路由规则
│   ├── socks5.rs           # SOCKS5 入站
│   ├── pipe.rs             # 数据流管道（TCP↔帧）
│   ├── decoy.rs            # 伪装流量（无意义 HTML/JS/CSS 请求）
│   ├── server.rs           # 服务端（/m /e /w + 中继 + 随机分发）
│   ├── client.rs           # 客户端（会话 + POST/SSE/WS + socks + 中转）
│   └── bin/
│       ├── wsnetd.rs
│       └── wsnet.rs
└── tests/e2e.rs
```

## 附录 A：GFW 威胁模型与对抗映射

> 完整调研见 [docs/GFW-RESEARCH.md](GFW-RESEARCH.md)（2024–2025 学术与公开测量研究）。

### A.1 GFW 封锁手段归纳

| 类型 | 手段 | 原理 | 粒度 |
| --- | --- | --- | --- |
| 被动 | DNS 污染/劫持 | 注入伪造 DNS 应答 | 域名 |
| 被动 | IP 封锁/黑洞路由 | 黑名单 IP 丢包或黑洞 | IP:port |
| 被动 | SNI 明文检测 | TLS ClientHello 的 SNI 明文命中即注入 RST | 域名（双向 RST） |
| 被动 | HTTP Host 关键字过滤 | 明文 Host 头匹配 | URL |
| 被动 | TLS 指纹（JA3/JA4） | 握手特征识别「非正常 HTTPS」 | 协议/工具 |
| 被动 | 协议指纹 | 识别 OpenVPN/WireGuard/SS/VMess 等 | 协议 |
| 被动 | 统计/熵/时序分析 | AI/ML 识别「加密但非正常 HTTPS」 | 连接/流 |
| 主动 | 握手重放探测 | 重放合法握手，观察是否返回「正确协议响应」 | 服务器 IP:port |
| 主动 | 端口枚举 | 逐端口建立连接探测 | 服务器 |
| 新兴 | QUIC SNI 解密封锁 | 大规模解密 QUIC Initial 做 SNI 封锁（2024-04 起） | 域名 |

### A.2 对抗映射

| GFW 手段 | wsnet 对抗设计 | 章节 |
| --- | --- | --- |
| 主动探测 + 握手重放 | 防重放 + 按协议类型返回伪装内容 | §5.1、§4.2、§9.1 |
| 协议指纹识别 | 三载体随机分发 + 统一 AEAD 信封（不可区分） | §1.1、§6 |
| 统计/熵/时序分析 | 伪装流量 + 正常站点（降低高熵特征） | §6.4、§6.5 |
| SNI/DPI 明文检测 | 标准 WS + nginx TLS + 正常域名 SNI | §11 |
| QUIC SNI 解密封锁 | v1 仅 TCP+TLS，不依赖 QUIC | §13、A.3 |
| IP:port 粒度封锁 | wsnetd 与正常 HTTPS 站点同 IP（回落） | §6.5、§11 |
| 探测响应确认 | 伪装响应与「正常失败」不可区分 | §9.1 |

### A.3 关键设计决策

1. **传输层（v1）**：仅使用 TCP + TLS（WS/SSE/POST），**不启用 QUIC/HTTP3**。依据：GFW 自 2024-04 起对 QUIC 做 SNI 级解密封锁（全球首例，90% 在 <1s 内生效），是当前最活跃、最难规避的攻击面；TCP+TLS 的 WS/SSE/POST 可稳定穿过 nginx 且 SNI 为正常域名。**代价**：牺牲 QUIC 的 0-RTT / 多路复用性能。**未来**：评估 ECH（截至 2025 初 GFW 不封锁含 ECH 的 QUIC）或对 QUIC 载体做 SNI 分片。
2. **IP 身份**：wsnetd 应部署在**正常 HTTPS 站点同 IP**（nginx 同端口回落），避免出现「仅代理特征」的独立 IP，降低 IP:port 粒度封锁风险。
3. **主动探测对抗优先级**：把「重放时按协议类型返回伪装内容」（§9.1）作为**必需项**而非可选——GFW 主动探测正是通过「重放握手观察响应」来确认代理身份，响应的不可区分性是第一道防线。
