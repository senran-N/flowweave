# FlowWeave 最小可部署代理预注册

## 目标与非目标

第一版产品入口固定为“受控目标 TCP 转发”，不是通用 VPN：

```text
本地 TCP 应用 -> flowweave-proxy client -> TLS 1.3 MPQUIC -> flowweave-proxy server -> 固定 TCP 目标
```

它必须真实复用已经通过 A/B 的 NoQ MPQUIC 数据面、Cubic 默认调度和 v6.9 跨路径恢复，但不把实验器、netem、临时证书或基准 magic 带进产品协议。第一版不做 TUN、UDP 转发、SOCKS5、动态 DNS 目标、远程管理界面、用户数据库或自动更新；这些能力会显著扩大攻击面，应在最小闭环通过后另名设计。

## 固定安全边界

- 传输只使用 NoQ/rustls 的标准 TLS 1.3。服务端从磁盘读取 DER 证书链中的单张叶证书和 PKCS#8 DER 私钥；客户端从独立 CA DER 建立信任根，并使用配置中的 `server_name` 做标准名称校验。禁止 insecure verifier、自签名自动信任、跳过主机名或自创加密。
- 应用授权使用至少 32 字节、最多 256 字节的随机令牌文件。令牌只在 TLS 加密 STREAM 内发送；客户端和服务端配置只保存令牌文件路径。Unix 上令牌文件和服务端私钥不得有任何 group/other 权限，比较使用常量时间字节比较。
- 服务端只允许一个预配置 `allowed_target`，且必须是显式 IP:port。客户端请求中的目标必须逐字节解析为同一个 SocketAddr；授权失败、目标不匹配、畸形长度和版本错误都在连接目标前拒绝。第一版不接受域名目标，避免 DNS 重绑定和开放代理。
- 客户端本地监听必须是 loopback 地址。若未来需要 LAN 共享，必须另加显式访问控制，不能在本版用一个布尔开关绕过。
- 配置文件使用严格的 `key=value` 文本：未知键、重复键、缺失键、空值和非法地址全部拒绝；相对证书/令牌路径相对配置文件目录解析。日志不得输出令牌、私钥内容或完整应用载荷。
- 产品默认启用经过正式 A 组验证的 `CrossPathRecoveryWithStreamProgressSnapshot`，保留 3 秒 PathIdle、MPQUIC 3 PTO 标识保留、同路 PATH_ACK、标准拥塞控制与 TLS 边界。不得为代理另设未经基准验证的短超时或调度器。

## 线协议 v1

每条本地 TCP 连接对应一条 QUIC 双向 STREAM。客户端先发送固定请求：

```text
magic[4] = "FWX1"
token_len: u16 big-endian
target_len: u16 big-endian
token[token_len]
target_utf8[target_len]
```

`token_len` 必须在 `[32,256]`，`target_len` 必须在 `[1,128]`，总请求有固定上限。服务端验证后连接唯一允许目标，并返回一个字节：`0` 成功，非零为版本/格式/授权/目标/上游连接失败。只有收到成功字节后客户端才转发本地应用数据。

成功后两个方向分别使用异步背压拷贝；任一方向 EOF 只关闭对应写半边，另一方向可继续 drain。QUIC STREAM 结束、TCP reset、连接关闭或任务取消都必须释放两端资源，不创建后台重连器或隐藏重试。一个 STREAM 的失败不能关闭其他已授权 STREAM；QUIC 连接失败则客户端进程退出，由 systemd 等外部监督器按部署策略重启。

## 配置合同

服务端必需键：

```text
listen=0.0.0.0:4433
certificate_der=/etc/flowweave/server.cert.der
private_key_der=/etc/flowweave/server.key.der
token_file=/etc/flowweave/token
previous_token_file=/etc/flowweave/token.previous
allowed_target=127.0.0.1:22
```

客户端必需键：

```text
listen=127.0.0.1:10022
server=proxy.example.com:4433
server_name=proxy.example.com
ca_certificate_der=/etc/flowweave/ca.cert.der
token_file=/etc/flowweave/token
target=127.0.0.1:22
```

客户端可选 `primary_local_ip` 和逗号分隔的 `additional_local_ips`。只设置 primary 时客户端 UDP Endpoint 直接绑定该 IP；每个 additional IP 使用同一远端 SocketAddr 打开 `Available` 路径。真实 Endpoint 测试发现，Linux 上绑定单一地址的 UDP socket 无法接收发往其他本地地址的路径验证响应；因此 primary 与 additional 同时存在时，产品先用通配 socket 完成 TLS，引导后把 primary 和全部 additional 逐条作为显式源 IP 打开，全部验证成功后关闭临时 Path 0。这个引导路径不接收本地代理流量。任一路打开或引导路径关闭失败都使启动失败，不能静默退化后仍宣称多路径已配置；最终产品路径最多八条。

## 验收与回退

实现完成前不得宣称可部署。至少需要以下自动测试：

- 严格配置解析、相对路径、未知/重复键和 loopback 监听限制；
- 令牌/私钥权限、令牌长度和常量时间验证路径；
- 请求编解码的长度上限、错误 magic、错误令牌和错误目标在上游连接前拒绝；
- 本地真实 TCP echo 经客户端、TLS MPQUIC、服务端和固定目标双向完整传输；
- 多个并发 STREAM 相互隔离，一个上游失败不终止其他流；
- 客户端使用错误 CA 或错误 `server_name` 时 TLS 必须失败；
- 默认产品传输配置确实启用 v6.9 恢复、Cubic、MPQUIC 和 keepalive，同时不启用任何 B 组实验传感器。

部署样例必须包含 DER 证书生成步骤、随机令牌生成、目录权限、server/client 配置和 systemd 单元。任何安全或端到端测试失败都先修正本版，不通过放宽权限、关闭证书验证或扩大允许目标补救。

## 2026-07-13 实现与验收结果

第一版最小代理现已实现，但范围仍严格停留在本文件预注册的固定 TCP 目标：

- `src/proxy.rs` 实现严格配置、相对路径、DER 证书/PKCS#8 私钥、Unix 私密文件权限、常量时间令牌比较、固定目标验证、产品 transport、服务端连接/STREAM accept、客户端 DNS/TLS/多路径启动和双向半关闭背压转发。
- `src/bin/flowweave-proxy.rs` 提供 `server <config>` 与 `client <config>` 两个入口；客户端 QUIC 连接失败会退出，不包含隐藏重连器。
- 产品 transport 直接调用既有 v6.9 配置：Cubic、NoQ 默认顺序、`CrossPathRecoveryWithStreamProgressSnapshot`、3 秒 PathIdle、200 ms 逐路径 keepalive、MPQUIC；`declared_backlogged_epoch_sensor` 保持关闭。
- 远端 Connection ID 在 TLS 确认后可能短暂尚未到达。实现只对 `RemoteCidsExhausted` 做最长 1 秒、每 10 ms 一次的有界等待；路径验证、地址族、路径额度和其他错误仍立即导致启动失败。
- 自动测试已真实跑通标准 TLS/MPQUIC 双路径和 8 条并发 TCP/QUIC STREAM；错误 magic、错误令牌和错误目标均在上游 listener 收到连接前被拒绝；第二条流的固定上游连接失败不会终止第一条既有流；错误 CA 和错误 `server_name` 均无法启动客户端。
- `deploy/` 已提供 server/client 严格配置样例、两份加固 systemd 单元，以及 CA/叶证书/PKCS#8 DER、随机二进制令牌、权限、启动、诊断和回退步骤。

当前针对代理的 10 项库测试、代理二进制测试、release 构建、Clippy `-D warnings`、隔离临时根目录中的 systemd 单元验证和 `git diff --check` 均通过。该结论只说明最小固定目标代理闭环可构建、可配置和可本地端到端运行；尚未在真实公网主机、真实 Wi-Fi/蜂窝双接口或长期负载下做部署 soak，因此不能扩张为通用 VPN 或生产 SLA 声明。

## 2026-07-13 冻结后的第一批运行保护

在 `v0.1.0-lab` 标签之后，第一批产品化改动只收紧本地资源与等待边界，不改变 `FWX1` 请求格式、固定目标、TLS、恢复算法或路径合同：

- 服务端显式限制为最多 64 条同时存活的 QUIC 连接；没有连接配额时直接拒绝新的 Initial，不先创建握手任务。
- 服务端传输参数只允许每条连接同时打开 64 条远端双向流，并把远端单向流额度设为零。客户端同样拒绝服务端发起任何双向或单向流。
- 客户端最多同时处理 64 条本地 TCP 连接；配额耗尽后接受并立即关闭超额 socket，避免任务和待开 QUIC 流无界堆积。
- DNS/TLS、QUIC 流打开和固定上游 TCP 连接使用 10 秒截止；请求头、令牌/目标验证响应使用 5 秒截止。可靠 TCP relay 本身不设置业务空闲超时，避免误杀长期静默的 SSH 等合法连接。
- 两份 systemd 单元增加 `TasksMax=512` 与 `MemoryMax=1G`，继续保留 `LimitNOFILE=65536` 和原有隔离项。
- 三项新真实异步测试分别证明：只发部分请求头的慢流在上游连接前被拒绝；连接配额为一时第二次 TLS 握手被拒绝；客户端流配额为一时第二条本地 TCP 被及时关闭而首流保持存活。

该批运行保护完成时代理库测试为 13 项、根项目为 71 项非忽略测试。它没有把共享令牌升级成逐客户端身份，也不能阻止持有合法 TLS/令牌的一方主动占满固定配额；后续 M1.4 已补齐共享令牌轮换与撤销，但逐客户端身份和配额归属仍需另名设计。

## 2026-07-13 M1.2 运行事件与有界退出

M1.2 不改变 `FWX1`、固定目标、TLS、v6.9 恢复或 A/B/C 冻结算法，只补齐运行生命周期：

- 所有运行事件逐行输出为 `flowweave.runtime.v1` JSON，固定记录时间、级别、角色、事件、稳定连接 ID、路径 ID 和原因码；观察地址、令牌、私钥、密钥路径和应用载荷不进入结构化事件。
- client/server 各自维护活动/累计连接和流、配额拒绝、五类超时、上游错误、应用上下行字节及优雅/强制退出的原子计数；每 10 秒和退出前输出快照，嵌入调用方也可直接读取。
- 根运行任务、连接和流改为受管任务树。SIGTERM/Ctrl-C 先停止新接入，现有流最多 drain 10 秒；超时后关闭 Endpoint、终止残余任务并保证活动计数归零。
- 三项真实网络测试分别证明 JSONL 可解析且不含测试令牌/私钥标识/载荷、关闭后拒绝新接入但既有流完整结束、drain 超时后强制退出并清零活动计数。

## 2026-07-13 M1.3 本地 soak 与健康门控

M1.3 先实现不依赖公网资源、但能直接迁移到部署主机的基础设施：

- `flowweave-proxy-observe` 增量读取 JSONL，检查必需字段、schema、失败原因、连接/流生命周期、最终活动量和累计指标。严格模式默认对失败、强制退出、拒绝、超时和上游错误零容忍，任何放宽都必须显式提供数值阈值。
- `flowweave-proxy-soak` 在权限收紧的临时目录生成测试凭据，启动真实 TLS/MPQUIC server/client、两条 loopback 路径和固定 echo 上游，以可配置并发持续创建确定性载荷流；它不缓存完整日志，而把每条事件直接送入同一个增量门控。
- soak 只有在逐流回显完整、尝试数等于完成数、错误为零、两端应用字节一致、原子指标归零且 JSONL 门控无违反项时才输出 `stage_pass=true`。
- `PROXY_SOAK.md` 明确规定单机结果不能外推到真实 Wi-Fi/蜂窝、公网 NAT 或生产 SLA。后续已用受控客户端和公网服务端完成同出口双接口门控；两个独立运营商出口只作为更强故障隔离声明的后续证据。

新增 5 项观测门控测试和 2 项 soak 测试；最新代理数据面测试仍为 16 项，根项目非忽略库测试为 `78/78`。最终代码的默认 60 秒 release 运行完成 16,615 条 64 KiB 流，client/server 各记录 16,615 条流和 `1,088,880,640` 上下行应用字节，失败、拒绝、超时、上游错误和强制退出均为 0；增量门控处理 66,489 条事件，非法 JSON、超限行、schema 错误、字段错误、生命周期缺口和健康违反项均为 0。该结果仍只属于单机 loopback 实现验收，不是公网长期证据。

随后完成的 30 分钟同一物理出口公网双接口 soak 使用两张接口、两条源策略路由和两个隔离 NAT，服务端确认两条产品路径建立；`7,031/7,031` 条流和双向 `230,391,808` 应用字节全部通过，失败、超时、拒绝、上游错误和强制退出均为零。该结果足以解除当前开发阶段的公网双路径阻塞，但不等于两个独立运营商出口或生产 SLA。

## 2026-07-14 M1.4 令牌轮换与撤销

M1.4 按 [`PROXY_ROTATION.md`](PROXY_ROTATION.md) 的代码前合同实现，不改变 `FWX1`、TLS、固定目标、16 项原子指标或冻结的 NoQ 数据面：

- 服务端新增可选 `previous_token_file`，最多同时接受两个令牌；相同内容去重，未配置时继续兼容原单令牌部署。
- 客户端仍只发送一个 `token_file`。两端通过 SIGHUP 或 `ProxyRuntime::reload_tokens()` 先完整读取并验证文件，再用一次写锁替换内存状态；任一文件失败时旧状态继续有效。
- 每条新服务端 STREAM 对当前集合的全部位置完成比较，不按首个匹配短路；每条新客户端 TCP 流克隆当时令牌，已授权流不持锁且不受之后撤销影响。
- `credentials_reloaded` 与 `credentials_reload_failed` 事件只输出令牌种类、有效令牌数或稳定失败码，不输出令牌、路径或派生值。失败重载复用现有 `max_runtime_failures` 门槛。
- systemd server/client 单元增加 `ExecReload=/bin/kill -HUP $MAINPID`；部署从两个同内容服务端槽开始，按“服务端重叠、客户端切换、服务端撤销”三步轮换。

真实 TLS/MPQUIC 测试已证明：当前与上一令牌均可授权；非法服务端或客户端重载保留旧状态且运行任务继续；客户端在同一 QUIC 连接上切换新令牌；服务端撤销后旧令牌的新流被拒绝、新令牌新流成功，而撤销前已经授权的旧流继续完整回显。共享令牌仍不是逐客户端身份系统，后者继续留在本阶段范围之外。

M1.4 完成时根项目全目标测试为 `86/86`；其中代理运行时 20 项、观察门控 6 项、soak 5 项。NoQ Proto `470/470` 与 NoQ `33/33` 非忽略测试继续通过，全目标 Clippy `-D warnings` 和 release 全二进制构建通过。最终 60 秒 release 回归 soak 完成 `15,411/15,411` 条 64 KiB 流，上传和回显各 `1,009,975,296` 字节，61,674 条事件全部合法，失败、拒绝、超时、上游错误和强制退出均为零，`stage_pass=true`。后续 M2.0 VPN 纯内存核心把当前根项目全目标测试增加到 `94/94`，但不改变 M1.4 固定代理的验收结论。
