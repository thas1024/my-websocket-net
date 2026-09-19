# wsnet 各端用法与 Local Forward 设计契约

> 状态：设计稿，尚未实现。以下命令、配置和输出是预期接口，不代表当前仓库已有可执行程序。

## 1. 各端职责

| 端 | 用法 |
| --- | --- |
| nginx / Web 站点 | 公网监听 443、终结标准 TLS；精确转发 wsnet 载体路径，其他路径提供正常站点 |
| Hub（规划二进制 `wsnetd`） | 认证节点、维护 lease/服务目录/ACL、编排流与中转，可作为直接出口 |
| 节点（规划二进制 `wsnet`） | 主动连接一个或多个 Hub，提供本地 SOCKS5、发布服务、接受授权出口/中转请求 |
| 本地应用 | 通过 SOCKS5 访问普通地址；通过 Local Forward 访问“节点 + 服务名” |
| 本地管理 CLI | 仅经本机 IPC 控制运行中的 `wsnet`，查看服务并增删临时 forward，不开放公网管理 API |

## 2. 计划 CLI

```text
wsnetd check --config /etc/wsnet/server.toml
wsnetd serve --config /etc/wsnet/server.toml

wsnet check --config ~/.config/wsnet/client.toml
wsnet run --config ~/.config/wsnet/client.toml
wsnet status
wsnet services list [--hub HUB] [--node NODE]
wsnet forward add ...
wsnet forward list
wsnet forward remove NAME
wsnet keygen --node NODE
```

`wsnet status/services/forward` 通过 Unix domain socket（Windows 为 named pipe）访问同一用户的本地守护进程。IPC 文件权限默认仅当前 OS 用户可读写；不得把该控制接口绑定公网 TCP。

动态 `forward add` 默认只存内存，进程重启即消失；持久 forward 写进配置文件 `[[forwards]]`，CLI 不自动改写主配置。

## 3. Hub 与节点启动

### 3.1 Hub

```bash
wsnetd check --config /etc/wsnet/server.toml
wsnetd serve --config /etc/wsnet/server.toml
```

Hub 后端只监听 loopback / Unix socket，由 nginx 对外暴露标准 HTTPS、SSE、WebSocket。节点凭据和 ACL 必须显式配置，默认不允许任意节点互为中转。

### 3.2 节点

```bash
wsnet check --config ~/.config/wsnet/client.toml
wsnet run --config ~/.config/wsnet/client.toml
```

节点主动连接 Hub；NAT 后节点无需开放公网端口。普通应用把代理设置为本地 SOCKS5：

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

使用 `socks5-hostname` 让域名由最终出口解析；应用已自行解析为 IP 时，wsnet 无法恢复原域名。

## 4. 为什么反向服务不用自定义 SOCKS5 字段

标准 SOCKS5 CONNECT 只能表达“目标地址 + 端口”，不能原生表达“`client-a` 节点发布的 `web` 服务”。向 SOCKS5 请求增加私有字段会破坏浏览器、curl 等现有客户端兼容性。

因此 v1 明确分工：

- **SOCKS5**：普通域名/IP 代理和 UDP ASSOCIATE；
- **Local Forward**：节点身份 + 命名服务或显式授权的节点地址；
- **虚拟域名**：可选便利层，默认关闭，不作为正式入口。

二者最终都转换成相同的内部 `Open` 目标选择器。

## 5. Local Forward

### 5.1 推荐：命名服务

服务发布方 `client-a`：

```toml
[[services]]
name = "web"
proto = "tcp"
target = "127.0.0.1:8080"
```

访问方创建本地 forward：

```bash
wsnet forward add \
  --name a-web \
  --listen 127.0.0.1:18080 \
  --node client-a \
  --service web \
  --proto tcp \
  --hub auto
```

使用：

```bash
curl http://127.0.0.1:18080
```

路径：

```text
应用 → 127.0.0.1:18080 → 本地 wsnet → Hub → client-a → 127.0.0.1:8080
```

配置等价形式：

```toml
[[forwards]]
name = "a-web"
listen = "127.0.0.1:18080"
proto = "tcp"
hub = "auto"
via = []
destination = { type = "service", node = "client-a", name = "web" }
```

`listen = "127.0.0.1:0"` 表示由操作系统分配端口，CLI 输出实际地址。Local Forward 默认只允许 loopback；非 loopback 必须显式开启并配置来源 CIDR allowlist。

### 5.2 显式远端端口

满足“反向访问另一客户端端口”的最低层能力，但默认关闭：

```bash
wsnet forward add \
  --name a-ssh \
  --listen 127.0.0.1:10022 \
  --node client-a \
  --target 127.0.0.1:22 \
  --proto tcp
```

等价目标：

```toml
destination = { type = "node_address", node = "client-a", host = "127.0.0.1", port = 22 }
```

必须有专门的 `connect_node_address` ACL。命名服务优先，因为发布方固定目标，调用方不能任意探测节点内网。

### 5.3 多跳

`via` 仅表示中间节点；命名服务的发布节点是最终端：

```toml
[[forwards]]
name = "a-web-via-b-c"
listen = "127.0.0.1:18081"
proto = "tcp"
hub = "hub-a"
via = ["client-b", "client-c"]
destination = { type = "service", node = "client-a", name = "web" }
```

路径：

```text
调用节点 → Hub → client-b → Hub → client-c → Hub → client-a/web
```

每条边与最终服务访问都必须单独授权；重复节点、自环及超过最大跳数的链直接拒绝。

## 6. 服务选择器与内部协议

`Open` 的 destination 是严格 union，恰好出现一种：

```text
ServiceTarget {
  node_id,
  service_name,
  optional_service_revision
}

NodeAddressTarget {
  node_id,
  host,
  port
}

AddressTarget {
  host,
  port
}
```

- `ServiceTarget`：Local Forward 首选；Hub 解析当前 lease，最终节点按自身服务表再次解析，不接受调用方覆盖本机地址。
- `NodeAddressTarget`：显式访问节点可见地址，默认拒绝，需专门 ACL。
- `AddressTarget`：普通 SOCKS/Hub 出口地址；`via[]` 决定最终拨号节点。
- 指定 service 与 raw target 并存、目标 node 不一致、旧 service revision、未知 service 均拒绝。

服务目录返回 `hub_id、node_id、service_name、proto、revision、状态`，并且只展示当前调用方有权发现的服务。

## 7. Forward 生命周期

本地 listener 与远端状态分离：

| 状态 | 含义 |
| --- | --- |
| `BOUND` | 本地 TCP/UDP socket 已绑定，不代表远端在线 |
| `READY` | 选定 Hub 上发布节点 Ready、服务存在且 ACL 允许 |
| `DEGRADED` | Hub/载体异常，仍可能在同 Hub grace 内恢复 |
| `OFFLINE` | 发布节点或服务不在线；新连接快速失败 |
| `DENIED` | ACL 拒绝；不会自动 direct 绕过 |
| `ERROR` | 本地绑定或配置错误 |

TCP listener 每次 `accept` 创建独立 `Open(request_id, stream_id, destination, via)`：

1. 本地 socket 建立后先暂停读取或仅在小预算内缓存；
2. 等待受保护的 `OpenResult` 和 `Ready`；
3. 成功后开始双向转发；
4. 失败则关闭该本地 socket，并在本地状态/日志提供原因；通用 TCP forward 不伪造 HTTP 响应；
5. 服务重新注册后仅恢复**新连接**，不复活旧 TCP socket。

服务 lease 绑定发布节点的 Hub session。相同服务名重新注册到不同 target 后，新连接使用新 revision；已有连接保持原 socket 或按断线规则失败。

## 8. 多 Hub 行为

`hub = "auto"` 只在满足以下条件的 Hub 中选择：

- 调用节点已经 Ready；
- 服务发布节点也在该 Hub Ready；
- service lease 存在且 ACL 允许；
- Hub 健康检查通过。

主 Hub 失败时：

- Local Forward 的本地 listener 可保持绑定；
- 存量 TCP/UDP association 明确失败，不跨 Hub 迁移；
- 新连接可在备用 Hub 重新建立；
- 发布方没有注册到备用 Hub 时返回 `OFFLINE`，不得自动改为 direct。

## 9. UDP Local Forward

固定远端 UDP 服务可使用：

```bash
wsnet forward add \
  --name a-dns \
  --listen 127.0.0.1:15353 \
  --node client-a \
  --service dns \
  --proto udp
```

Local UDP Forward 与 SOCKS5 UDP ASSOCIATE 不同：前者目标固定；后者每个 SOCKS UDP 数据报可携带不同目标。

每个本地来源 tuple 建立有界 association，复用设计文档 §7.4 的来源校验、TTL、队列、datagram_id、多目标隔离和 HOL 风险规则。Local UDP Forward 不保证游戏、语音或 QUIC 实时性。

## 10. 可选虚拟域名

默认关闭，可配置：

```toml
[socks_service_namespace]
enabled = false
suffix = "wsnet.invalid"
```

格式：

```text
svc.<node>.<service>.wsnet.invalid
```

只有 SOCKS5 请求以 `ATYP=DOMAIN` 发送该名字时才解释为 `ServiceTarget`；客户端不得把它交给本地 DNS。示例必须使用 remote-DNS 模式：

```bash
curl --socks5-hostname 127.0.0.1:1080 http://svc.client-a.web.wsnet.invalid
```

限制：

- node/service 只能使用规范化 ASCII slug；禁止路径、端口或任意地址编码；
- 只映射命名服务，不映射 raw node address；
- HTTPS 服务常出现 SNI/证书名不匹配，因此 TLS 服务优先使用 Local Forward 配合应用自身的目标主机名能力；
- 该命名空间只是便利层，不影响 ACL，也不能成为服务发现泄露渠道。

## 11. ACL

至少区分以下权限：

```toml
[[acl]]
caller = "client-b"
action = "connect_service"
node = "client-a"
service = "web"
proto = "tcp"
allow = true

[[acl]]
caller = "client-b"
action = "connect_node_address"
node = "client-a"
host_cidr = "127.0.0.1/32"
ports = [22]
proto = "tcp"
allow = true
```

多跳还需每条 relay edge 的独立 permit。Hub 先检查，最终发布/出口节点再次检查本地服务和目标；服务目录只返回调用方被允许发现的项。

## 12. 待实现验收

- CLI 与静态配置产生相同 `Open` 目标选择器。
- `listen=:0` 返回可连接的实际端口；重复 name/listen 原子拒绝。
- 服务 offline/重注册/换 revision 时，只影响符合生命周期约定的新连接。
- raw node address 默认拒绝，仅显式 ACL 生效。
- 虚拟域名只接受 SOCKS ATYP=DOMAIN；本地 DNS 路径不能误匹配。
- UDP forward 来源隔离、TTL、队列和 association 清理符合 §7.4。
- 多 Hub 仅恢复新连接，不迁移存量 socket。
- 非 loopback listener 无来源 allowlist 时拒绝启动。
