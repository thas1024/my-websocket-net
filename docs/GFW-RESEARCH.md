# GFW 封锁机制：历史资料梳理与证据边界

> 状态：对仓库已有调研报告的证据降格与技术纠错，不是新的联网调研。本轮未访问外部来源、未做网络测量，链接沿用已有引用。
> 时间范围：主要引用 2015 及 2024–2025 年研究；发表时间不等于测量时间，旧观察不能推断当前全网政策。
> 用途：为 [设计文档](DESIGN.md) 提供有条件的威胁背景，不证明本项目已具备抗识别或抗封锁能力。

## 1. 如何阅读本报告

区分四种证据：① 协议规范事实；② 已引用论文报告的特定时间/测量点观察；③ 二手博客/媒体说法；④ 本项目待验证假设。下文不将③④写成已证部署事实。具体数字、线路和实验条件应在未来复核原文后引用；本轮不新增“最新”结论。

“GFW”通常用于统称多种网络干扰现象。不能仅凭单条连接超时断言是GFW，也不能从论文测到不同注入行为推导精确组织、全国硬件规模、统一评分系统或某个厂商产品部署。区域、运营商、方向、协议与时间均可能不同。

## 2. 机制、证据和限制

### 2.1 DNS、HTTP、TLS 与地址干扰

| 机制 | 可支持的表述 | 限制 |
| --- | --- | --- |
| DNS 注入 | 历史研究与资料报告过伪造DNS应答及污染现象 | TTL/IPID特征、设备规模和吞吐不是当前稳定常量；本报告删除旧节点数量/吞吐数字的当前事实表述 |
| HTTP Host / TLS SNI检测 | 已引用区域审查论文讨论明文Host、未使用ECH时可见的TLS ClientHello SNI与RST注入 | Host是主机名，不等于完整URL；HTTPS内URL通常不可见；TLS1.3本身并不自动隐藏普通SNI |
| TCP RST / 丢包 | 文献报告存在注入RST和后续连接受影响等行为 | 丢包不能单独证明黑洞路由；残留阻断不等于已证“全局评分机制” |
| IP / IP:port等粒度 | 不同机制和历史测量可出现不同粒度阻断 | 不能统一写成“实际都按IP:port”；同正常站点共IP不能保证免封 |

主要历史引用：[区域审查研究（S&P 2025，中文）](https://gfw.report/publications/sp25/zh)。本文仅保留文献所报告的有限观察，不断言其适用于所有当前线路。

### 2.2 主动探测与重放

[IMC 2015 论文](https://conferences2.sigcomm.org/imc/2015/papers/p445.pdf) 对疑似规避服务的主动探测作系统研究，可作为“对端可能发送探测/重放请求”的威胁模型依据。并非所有协议都能用同一种握手重放识别，也不能把“目前仍是主流、所有端口都会枚举”当本文新测结论。

标准TLS观察者通常不能把一条连接中的应用明文直接从TLS密文读出再重放；内部认证记录被日志/端点泄露、代理终结TLS或协议本身不使用TLS是不同攻击条件。应用仍需防重放，但须说明攻击者拥有的是TLS密文、内部记录还是凭据。

返回普通站点内容能减少特定错误差异，不保证身份不可确认：正常服务差异、长度、时序和状态行为仍可能被关联。设计中的防重放、业务幂等与响应外观必须分别验收。

### 2.3 TLS 指纹、熵与行为分析

- TLS ClientHello特征、ALPN、包长/方向/时序可用于分类；JA3/JA4是特征表示，不是浏览器身份的密码学证明。
- 现有仓库引用不足以证明GFW在所有线路广泛部署JA4或某AI/ML分类器；“2023–2024起普遍AI识别”等表述降为**未验证说法**。
- TLS应用密文本身已接近高熵，不能声称真实HTTPS密文是低熵结构化内容、内部再加密就显著升高外部可见熵，或HTML背景请求可降低TLS密文熵。
- 不具备TLS终结能力的中间观察者通常看不到URL、Cookie、MIME、JS是否执行；可能看到它们在尺寸/时序上的间接效应，但不能将推测写成已证浏览器请求图谱检测部署。
- 指纹profile、padding和背景请求是本项目实验方向，不是实证对策；额外流量还可能恶化弱网或产生新的特征。

## 3. QUIC、ECH 与地区差异的历史观察

[USENIX Security 2025 页面](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib) 与[中文论文页面](https://gfw.report/publications/usenixsecurity25/zh) 报告从2024年4月起观察到针对QUIC的SNI干扰，并讨论2025年3月的行为变化。以下必须保留边界：

- QUIC Initial的初始密钥由公开信息推导，观察者解析其中ClientHello不等于破解TLS 1.3或解密完整QUIC应用会话。
- 论文中的封锁比例、响应时间、残留时间、地域和方向条件不外推为当前全国统一数值；本轮删除无上下文“90%小于1秒”“最活跃最难规避”“全球首例”等设计依据。
- ECH用于保护ClientHello中的敏感字段，但其可用性取决于客户端、DNS配置、服务端与网络策略。旧实验“某些ECH流量当时未触发”不能变成“ECH不封锁”“长期普适有效”。本轮没有验证当前ECH状态。
- 区域研究支持对地域/线路差异保持警惕，不证明所有地区协调方式或内部拓扑。
- “2025年全国/全球境外443全面封锁”“Let's Encrypt CRL普遍封锁”等仅有二手线索，本报告**不作为已证事实或版本设计依据**；若后续讨论，需列出明确日期、持续时间、地区、目标和对照测量。

## 4. 可追踪的历史线索（非完整演进史）

| 发表/观察时间 | 保留内容 | 证据边界 |
| --- | --- | --- |
| 2015 IMC | 主动探测研究 | 历史协议/测量环境，不据此宣布当下统一探测规则 |
| 2024–2025测量、2025发表 | QUIC Initial/SNI相关干扰论文 | 限论文报告的时间、测量点、方向及协议条件 |
| 2025 S&P | 区域审查差异研究 | 不从局部结论推导全国组织结构或永久策略 |

删除旧报告中未经逐项证明的“2002→2025各阶段主要策略”“AI普及时间线”。未来修订应记 source URL、发表时间、实际测量时段、地点/方向、方法与复现状态；本轮复现状态均为未复现。

## 5. 对 wsnet 的有限设计映射

| 风险 | 本项目选择 | 不能声称 |
| --- | --- | --- |
| 主动探测/内部记录重放 | 原子nonce登记、方向key隔离、协议阶段失败外观 | 一个正常Close/HTML响应就能隐藏代理 |
| TLS/统计特征分类 | 可维护标准TLS、profile一致性评估、限预算对照测试 | 已模拟真实浏览器或已对抗特定分类器 |
| 单载体失败/网络质量差 | 实际POST+SSE/POST响应数据fallback、offset/credit、有界恢复 | 背景请求成功即业务成功；随机复制必然提升质量 |
| 地址/域名可见性 | 保留标准证书验证、明确Hub部署边界 | 正常域名、共IP或TLS可规避IP/SNI封锁 |
| 多线路与区域变化 | 多Hub注册，新连接故障转移 | 跨Hub迁移存量TCP或自动恢复未知业务副作用 |
| QUIC相关历史观察 | v1选TCP+TLS以控制复杂度并兼容nginx | TCP比QUIC天然安全、ECH必有效 |

规范内容以 [DESIGN.md](DESIGN.md) 的 §4–§12 为准；本文是背景，不为未测试功能背书。

## 6. 来源分级与待核实列表

### 优先复核的原始研究入口（本轮未重新访问）

- [QUIC SNI Censorship，USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib)
- [QUIC SNI 研究中文页](https://gfw.report/publications/usenixsecurity25/zh)
- [区域审查研究中文页，S&P 2025](https://gfw.report/publications/sp25/zh)
- [Active Probing，IMC 2015 PDF](https://conferences2.sigcomm.org/imc/2015/papers/p445.pdf)

### 保留为二手/待核实线索，不直接用于现状断言

- [DomainTools 基础设施分析](https://dti.domaintools.com/research/inside-the-great-firewall-part-2-technical-infrastructure)：内部部署/JA3说法需核实来源链与覆盖范围。
- [arXiv 2503.02018](https://arxiv.org/html/2503.02018v1)：预印本/综述线索，应追原始测量。
- [Medium/BTCVPN 文章](https://medium.com/btcvpn/inside-the-great-firewall-how-chinas-censorship-machine-really-works-and-how-to-beat-it-b92b3be410a2)：ECH普适结论不可直接采用。
- [Wikipedia](https://en.wikipedia.org/wiki/Great_Firewall)：百科用于索引原始研究，不当最新测量。
- [游戏和谐 Wiki](https://ggame.gledos.science/censorship/%E6%8A%80%E6%9C%AF/GFW.html)：443/CRL等事件线索需限定时地和对照复核。
- [墙妈妈](https://www.wallmama.com/comment-page-2)：AI普及/技术演进时间线不作为本项目已证依据。

## 7. 本轮修订与验证状态

修正了TLS熵与可见性、Host/URL粒度、QUIC Initial含义；将JA4/AI普遍部署、ECH长期有效、全面443封锁、精确设备吞吐与全局评分等断言删除或降格。保留历史研究入口和与设计的双向链接。

没有新联网调研、抓包、协议测试或封锁复现；仅文档静态自查。后续证据更新不能用未经限定的博客结论自动改变安全默认值。
