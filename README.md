# wsnet

基于 **HTTPS + SSE + WebSocket 混合协议** 的轻量代理（Rust），参考 [XTLS/Xray-core](https://github.com/XTLS/Xray-core) 的流量伪装思想。

## 特性（设计阶段）

- 多载体随机分发（POST / SSE / WebSocket），协议不绑定职能、随机性混淆
- 加密认证（HMAC 挑战 + HKDF 会话密钥 + ChaCha20-Poly1305 AEAD）
- 客户端 SOCKS5 入站；支持节点中继、反向访问、可配置最终上网节点路由
- 标准 WebSocket，可被 nginx 反代 + TLS
- 伪装流量（随机掺杂无意义 HTML/JS/CSS 请求）

## 文档

- 设计文档：[docs/DESIGN.md](docs/DESIGN.md)
- GFW 封锁原理调研：[docs/GFW-RESEARCH.md](docs/GFW-RESEARCH.md)

## 状态

当前处于**设计阶段**，尚未开始编码实现。
