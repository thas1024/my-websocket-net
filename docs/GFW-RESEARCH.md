# GFW（中国防火长城）封锁原理调研报告

> 调研时间：2025 年；数据来源：2024–2025 年发表的学术论文与公开测量研究（USENIX Security 2025、gfw.report、DomainTools、arxiv 等）。
> 用途：为 wsnet 代理的**抗检测 / 抗封锁**设计提供威胁模型依据。

## 1. 概述

GFW（Great Firewall，防火长城）是一套**模块化、分层、区域分布式**的国家级网络审查系统，核心由**深度包检测（DPI）模块 + 动态封锁名单 + 主动探测**构成，部署在骨干网与省级运营商网关。它已从早期的「IP 封锁 / DNS 污染 / 关键字过滤」演进为**主动探测 + 流量指纹识别 + AI/ML 辅助分析**的综合体系。

> 来源：[DomainTools — Inside the Great Firewall Part 2](https://dti.domaintools.com/research/inside-the-great-firewall-part-2-technical-infrastructure)、[wallmama — 翻墙与科学上网指南](https://www.wallmama.com/comment-page-2)

## 2. 封锁手段分类

### 2.1 被动封锁（流量经过时检测，最常见）

| 手段 | 原理 | 粒度 / 特征 |
| --- | --- | --- |
| **DNS 污染 / 劫持** | 向 DNS 查询注入伪造应答，返回污染 IP；对 DoH/DoT 按 IP:port + SNI 封锁 | 域名级 |
| **IP 封锁 / 黑洞路由** | 黑名单 IP 直接丢包或路由黑洞；实际按 **IP:port 元组**（非仅 IP）封锁 | IP:port 级 |
| **SNI 明文检测** | TLS ClientHello 的 SNI 扩展为明文，命中黑名单域名即注入 TCP RST | 域名级，双向 RST |
| **HTTP Host 关键字过滤** | 明文 HTTP 的 Host 头关键字匹配 | URL 级 |
| **TLS 指纹（JA3/JA4）** | 不解密，靠握手特征识别「加密但不是正常 HTTPS」的流量 | 协议 / 工具级 |
| **协议指纹** | 识别 OpenVPN、WireGuard、Shadowsocks、VMess、Trojan 的握手 / 统计特征 | 协议级 |

**DNS 污染细节**：注入的伪造应答具有可辨识的固定特征（TTL、IPID 模式）；注入是**双向**的，境外 DNS 途经中国时也会被污染，导致大量国外递归解析器缓存被污染。GFW 的一个 DNS 计算集群约 360 个节点，每节点每秒处理约 2800 个 DNS 包。

> 来源：[DNS 污染 / TCP 重置详解](https://blog.luckysix.cc/2024/08/25/%E7%BF%BB%E5%A2%99%E8%BD%AF%E4%BB%B6%E7%9A%84%E5%AF%B9%E6%89%8B%E9%95%BF%E5%9F%8E%E9%98%B2%E7%81%AB%E5%A2%99-GFW-%E6%98%AF%E5%A6%82%E4%BD%95%E6%A3%80%E6%B5%8B%E5%92%8C%E5%B0%81%E9%94%81%E6%B5%81%E9%87%8F%E7%9A%84)、[游戏和谐 Wiki — GFW](https://ggame.gledos.science/censorship/%E6%8A%80%E6%9C%AF/GFW.html)

### 2.2 主动探测（Active Probing）—— 与「防重放」需求直接相关

这是对代理服务器最具威胁的一类：**GFW 伪装成客户端，主动连接疑似代理服务器**，识别后封锁。手段包括：

- **握手重放**：捕获一段合法客户端流量（如 VMess / Shadowsocks 的认证头），再主动重放到服务器；若服务器给出「正确协议响应」，即确认是代理 → 封 IP:port。
- **端口枚举**：对可疑 IP 的每个端口逐一建立连接探测（Tor bridge 曾因此被逐端口封锁）。
- 首次系统揭示于 2015 年 IMC 论文；至今仍是主流手段。

> 来源：[How the Great Firewall Discovers Hidden Circumvention Servers (IMC 2015)](https://conferences2.sigcomm.org/imc/2015/papers/p445.pdf)、[Wikipedia — Great Firewall](https://en.wikipedia.org/wiki/Great_Firewall)、[arxiv 2503.02018](https://arxiv.org/html/2503.02018v1)

**与 wsnet 设计的对应**：wsnet §9.1「重放时按协议类型返回伪装内容」正是对抗此机制——若重放探测得到代理特有错误，等于自报身份；返回与正常服务无异的伪装内容，探测者就无法确认目标身份。

### 2.3 统计 / 行为分析（被动，AI/ML 强化）

- **熵分析**：代理加密流量通常呈高熵（随机），与真实 TLS 结构化内容不同。
- **包长 / 时序特征**：对流量模式、包长度、时间特征做机器学习分类。
- 2023–2024 起越来越多使用 AI/ML 流量识别，动态判断「加密但非正常 HTTPS 流量」。

> 来源：[wallmama](https://www.wallmama.com/comment-page-2)

## 3. 2024–2025 最新趋势

1. **QUIC / HTTP3 的 SNI 封锁（全球首例）**：2024-04-07 起，GFW 开始**大规模解密 QUIC Initial 包**做 SNI 级封锁，采用独立于其他机制的封锁名单；90% 的封锁在 <1s 内生效，封锁强度与算力相关（高负载时审查效率下降）。
   - 关键缺陷：解密开销大，中等流量负载即削弱封锁效果，并可被滥用阻断任意 UDP 流量。
   - 2025-03-13 起，境外发起的 QUIC 流量不再触发封锁（部分缓解）。
2. **ECH 成为有效对抗**：截至 2025 初，GFW **不封锁**含 ECH（Encrypted ClientHello）的 QUIC。
3. **区域化 / 协作式审查**：出现独立的「河南墙」等区域系统，封锁策略与骨干网 GFW 不完全同步。
4. **TCP 非合规行为 / 双向 RST**：2024 研究证实 GFW 会双向注入 RST，可被外部测量；封锁存在「评分」机制，先前连接被封锁会影响后续连接。
5. **2025 年新动作**：8 月屏蔽境外 443 端口、屏蔽 Let's Encrypt 的 CRL 域名。

> 来源：[USENIX Security 2025 — QUIC SNI Censorship](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib) / [中文版](https://gfw.report/publications/usenixsecurity25/zh)、[gfw.report — 墙中之墙](https://gfw.report/publications/sp25/zh)、[Medium — Inside the Great Firewall](https://medium.com/btcvpn/inside-the-great-firewall-how-chinas-censorship-machine-really-works-and-how-to-beat-it-b92b3be410a2)、[Wikipedia](https://en.wikipedia.org/wiki/Great_Firewall)

## 4. 时间线（关键节点）

| 时间 | 事件 |
| --- | --- |
| 2002 起 | DNS 污染出现 |
| 2011 前 | 主要靠关键字过滤 + IP 黑名单 |
| 2015 | 主动探测机制被系统揭示 |
| 2019–2020 | IP 封锁 / DNS 污染 / 关键字过滤为主 |
| 2020–2021 | 普遍使用主动探测（V2Ray、Shadowsocks 握手） |
| 2021–2022 | DPI 增强，监控 TLS1.3+ESNI |
| 2023–2024 | AI/ML 流量识别；分布式封锁（省市不同步） |
| 2024-04-07 | GFW 开始 QUIC SNI 解密封锁 |
| 2025-03-13 | 境外 QUIC 流量不再触发封锁 |
| 2025-08-20 | 屏蔽境外 443 端口 |

> 来源：[wallmama](https://www.wallmama.com/comment-page-2)、[游戏和谐 Wiki](https://ggame.gledos.science/censorship/%E6%8A%80%E6%9C%AF/GFW.html)、[USENIX 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib)

## 5. 对 wsnet 设计的映射

| GFW 手段 | wsnet 对抗设计 |
| --- | --- |
| 主动探测 + 握手重放 | §9.1 按协议类型伪装响应 + 防重放（nonce 缓存 / AEAD counter） |
| 协议指纹识别 | §6 三载体随机分发 + 统一 AEAD 信封（不可区分） |
| 统计 / 熵 / 时序分析 | §6.4 伪装流量 + §6.5 正常站点（降低高熵特征） |
| SNI / DPI 明文检测 | §11 标准 WS + nginx TLS + 正常域名 SNI |
| QUIC SNI 解密封锁 | v1 走 TCP+TLS+WS（不依赖 QUIC）；未来评估 ECH |
| IP:port 粒度封锁 | wsnetd 与正常 HTTPS 站点同 IP（回落），避免独立特征 IP |

## 6. 参考资料

- [Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib)
- [揭示并绕过中国防火长城基于 SNI 的 QUIC 封锁机制（中文）](https://gfw.report/publications/usenixsecurity25/zh)
- [墙中之墙：中国地区性审查的兴起 (gfw.report, S&P 2025)](https://gfw.report/publications/sp25/zh)
- [Inside the Great Firewall Part 2: Technical Infrastructure (DomainTools)](https://dti.domaintools.com/research/inside-the-great-firewall-part-2-technical-infrastructure)
- [How the Great Firewall Discovers Hidden Circumvention Servers (IMC 2015)](https://conferences2.sigcomm.org/imc/2015/papers/p445.pdf)
- [Advancing Obfuscation Strategies to Counter China's Great Firewall (arxiv 2503.02018)](https://arxiv.org/html/2503.02018v1)
- [Inside the Great Firewall: How China's Censorship Machine Really Works (Medium/BTCVPN)](https://medium.com/btcvpn/inside-the-great-firewall-how-chinas-censorship-machine-really-works-and-how-to-beat-it-b92b3be410a2)
- [翻墙软件的对手长城防火墙 GFW 是如何检测和封锁流量的（星宇博客）](https://blog.luckysix.cc/2024/08/25/%E7%BF%BB%E5%A2%99%E8%BD%AF%E4%BB%B6%E7%9A%84%E5%AF%B9%E6%89%8B%E9%95%BF%E5%9F%8E%E9%98%B2%E7%81%AB%E5%A2%99-GFW-%E6%98%AF%E5%A6%82%E4%BD%95%E6%A3%80%E6%B5%8B%E5%92%8C%E5%B0%81%E9%94%81%E6%B5%81%E9%87%8F%E7%9A%84)
- [Great Firewall (Wikipedia)](https://en.wikipedia.org/wiki/Great_Firewall) / [防火长城 (维基百科)](https://zh.wikipedia.org/zh-hans/%E9%98%B2%E7%81%AB%E9%95%BF%E5%9F%8E)
- [GFW — 游戏和谐 Wiki](https://ggame.gledos.science/censorship/%E6%8A%80%E6%9C%AF/GFW.html)
- [墙妈妈 — 翻墙与科学上网指南](https://www.wallmama.com/comment-page-2)
