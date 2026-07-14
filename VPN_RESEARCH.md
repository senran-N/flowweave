# FlowWeave 生产 VPN 路线与 M2.0 合同

## 目标

本路线把当前固定目标 TCP 代理扩展为可长期部署的网络隧道，而不是把实验入口改名为 VPN。最终产品必须同时保留：

- `fixed-tcp`：现有受控固定目标代理，继续使用 `FWX1`；
- `vpn`：Linux 首版三层 TUN 隧道，承载 IPv4、IPv6、TCP、UDP、ICMP 和其他合法 IP 流量；
- 共同的 TLS 1.3、严格证书名称校验、多路径 QUIC、结构化观测、安装升级和回退能力。

“工程成熟度接近 Hysteria 2”指安全默认、配置可审计、故障可诊断、安装和升级可重复、长期运行有证据。它不表示复制 Hysteria 协议，也不提前承诺相同平台覆盖、吞吐或生产 SLA。

## 当前差距审计

| 能力 | 当前证据 | 生产 VPN 所需状态 |
| --- | --- | --- |
| 数据面 | `FWI1`、真实重组、有界队列、双方 NoQ DATAGRAM、包设备桥接和真实 TUN 已在隔离三 namespace 中串通 UDP、TCP、双栈 ICMP、精确 MTU、连续代际、外层失联、READY 后 policy routing、IPv4 NAT 与 IPv6 无 NAT | 更完整故障矩阵和无全局队头阻塞 |
| 身份 | mTLS、证书指纹、双证书轮换、禁用和在线撤销已完成；独立产品进程在 READY 前装配并交叉验证证书、私钥、CA 与身份预算 | 身份运维工具、在线重载和长期多客户端攻击门控 |
| 会话 | 单活动代际、成功后替换、地址漂移拒绝、启动失败回滚、旧运行器退出、唯一包设备读者租约和单客户端 Endpoint 生命周期已完成 | 有界指数退避、网络恢复、路径重建和离线包丢弃计数 |
| 地址与策略 | 静态虚拟 IPv4/IPv6、源地址防伪、双向 ACL、每身份配额、客户端 `ACCEPT` 工厂、独立 TUN 路由表，以及只匹配启用身份精确地址的服务端 forwarding/NAT 已完成隔离验证 | 管理流量豁免策略和 DNS 接管 |
| 权限 | 非 root、无可重新启用的 `CAP_NET_ADMIN`、`NoNewPrivileges` 数据进程只附着既有 TUN 的边界已实测；独立 root helper 已事务化准备/清理 TUN，并激活/撤销 client policy routes 与 server nft/sysctl；Type=notify 安装单元只让短命 `+` helper 获得 root | 真实宿主特权安装验收、发行版兼容和升级/回退权限审计 |
| 运维 | fixed-tcp 首次安装/systemd/JSONL/健康门控；VPN 已有非特权产品命令、严格 READY/systemd notify、版本化网络事务、client/server 安装单元和失败恢复说明 | DNS、升级迁移、自动回退、配置检查和告警出口 |
| 验证 | fixed-tcp soak、真实 mTLS/FWC1/DATAGRAM loopback，隔离真实 TUN 的 UDP/TCP/ICMP/MTU/失联/`SIGKILL`，产品进程 READY/正常停止/断链非零退出，UID 外层逃生，IPv4 NAT/IPv6 无 NAT，route/rule/nft/sysctl 冲突、漂移和崩溃恢复，以及真实 user-systemd 的五类启动/退出顺序 | 多路径切换、独立出口、多日和跨版本门控 |

因此不能复用 `FWX1` 冒充 VPN。VPN 使用独立 ALPN、独立配置类型和独立线协议；固定代理保持兼容。

## M2.0 威胁模型

### 必须抵御

- 未持有受信客户端证书的一方建立 VPN 会话；
- 合法客户端伪造其他客户端的虚拟源地址；
- 畸形、重叠、超长或永不完成的分片消耗服务端内存；
- 单客户端通过连接、包速率、重组、发送队列或日志放大耗尽全局资源；
- 旧会话和新重连会话同时写入同一虚拟地址；
- 配置、日志、崩溃信息泄露私钥、令牌、完整用户载荷或敏感地址清单；
- 默认路由切换把外层 QUIC 连接重新送入隧道形成路由环；
- 安装或退出中断后遗留错误默认路由、NAT 规则或宽松设备权限；
- 新版本无法读取旧配置、无法回退，或静默改变安全默认值。

### 本阶段不声称抵御

- 已取得客户端私钥或服务端 root 权限的攻击者；
- 终端自身恶意软件、流量分析、全球被动对手或抗审查伪装；
- 未经配置允许的站点审查绕过和匿名性；
- 内核、rustls、NoQ 或密码原语中的未知漏洞。

这些边界必须出现在最终用户文档中，不能用“VPN”一词隐去。

## 架构决定

### Linux 首版与权限隔离

第一份可部署版本只声明 Linux。macOS、Windows、Android 和 iOS 必须分别实现并通过平台门控后再加入支持列表。

网络配置由独立的 root oneshot 单元完成：创建持久 TUN、设置所有者、虚拟地址、路由和服务端 NAT/forwarding，并记录可精确撤销的状态。数据进程继续以 `flowweave` 用户运行，不持有 `CAP_NET_ADMIN`。不得把主服务直接改成常驻 root，也不得用 setuid 二进制隐藏权限。

客户端接管流量前必须先让专用 `flowweave` UID 高优先级查询原 main table；产品自身的 DNS、QUIC 和多源路径因此不依赖动态服务端地址 host route。普通流量只查询 FlowWeave 独立表，未命中的选择性目标继续回落 main。失败时不提交 tunnel lookup rule；停止和回退只删除 sidecar 精确记录且语义完全匹配的对象，不清空宿主机现有 nftables、路由表或 DNS 配置。

### 独立 VPN TLS 身份

VPN ALPN 固定为 `flowweave-vpn/1`。服务端证书继续由客户端独立 CA 和 `server_name` 验证；服务端另外要求客户端证书，由独立 client CA 验证。

服务端使用客户端叶证书 DER 的 SHA-256 指纹查找身份记录。一个逻辑身份可在轮换重叠期配置两个指纹，但一个指纹只能属于一个身份。身份记录至少绑定：

- 稳定 `client_id`；
- 允许的虚拟 IPv4 `/32` 和可选 IPv6 `/128`；
- 允许的目标 CIDR/私网访问策略；
- 连接数、包速率、带宽和重组内存上限；
- 启用/禁用状态。

共享令牌只保留给 `fixed-tcp` 兼容模式，不作为 VPN 身份后端。VPN v1 禁止 0-RTT 应用数据，避免重放语义进入地址和会话建立。

### IP 数据面使用 QUIC DATAGRAM

每个 TUN IP 包使用 QUIC DATAGRAM 传输，而不是把所有流量写进一条可靠 STREAM。理由：

- IP 层本来允许丢包和乱序；内层 TCP 自行恢复，UDP 保持原语义；
- QUIC DATAGRAM 仍受 TLS 1.3、拥塞控制、pacing、MTU 和反放大约束；
- 不产生跨流全局可靠队头阻塞；
- NoQ 可在第一条路径拥塞或不可用时选择其他已验证路径，保留多路径传输能力。

QUIC DATAGRAM 的最小可用载荷不足以保证容纳 1280 字节 IPv6 包，因此 FlowWeave 必须在 IP 层之下提供分片/重组，不能把 TUN MTU 简单降到 IPv6 最小链路 MTU以下后假装兼容。

### `FWI1` IP 分片格式

每个 QUIC DATAGRAM 只包含一个 FlowWeave IP 分片：

```text
magic[4] = "FWI1"
packet_id: u32 big-endian
total_len: u16 big-endian
fragment_offset: u16 big-endian
payload[datagram_len - 12]
```

固定规则：

- 线格式可表达的 IP 包长度为 `1..=65535`；每条会话还必须服从 `ACCEPT.max_ip_packet_len`，真正写入 TUN 前继续通过 IPv4/IPv6 头和长度检查；
- 分片 payload 不得为空，`offset + payload_len` 不得超过 `total_len`；
- 单包最多 64 个分片。发送端只有在 QUIC DATAGRAM 上限至少为 1036 字节时才启动，从而保证最大 IP 包也可在 64 片内表达；
- 同一 `packet_id` 的 `total_len` 必须一致；完全相同的重复片可忽略，任何重叠或冲突都会丢弃整包；
- 每连接最多同时重组 1024 个包、总计 8 MiB，默认 3 秒过期；达到上限时淘汰最旧未完成包并计数；
- `packet_id` 只在一条已认证 QUIC 连接内有意义。重连建立新代际后清空旧重组状态。

`FWI1` 不自创加密或完整性校验；它只在已认证的 QUIC 1-RTT DATAGRAM 内出现。

### IP 校验和防伪

进入 TUN 前必须检查：

- 版本只能是 IPv4 或 IPv6；
- IPv4 IHL 和 `total_length`、IPv6 `payload_length + 40` 必须与实际包长一致；
- VPN v1 拒绝 IPv6 jumbogram；
- 客户端上行源地址必须等于其身份绑定的虚拟地址；
- 服务端下行按目标虚拟地址选择唯一活动身份；未知目标不得广播；
- 组播、广播、链路本地和私网访问按显式策略处理，不因认证成功自动放行。

### 控制流与会话代际

每条 VPN QUIC 连接建立后必须先在可靠双向 STREAM 上完成有界 `HELLO/ACCEPT`，再启用 DATAGRAM。控制流协商协议版本、能力、最大 IP 包、分片载荷和分配地址；服务端返回由证书身份决定的结果，客户端不能自行申请任意地址。

控制消息使用独立 `FWC1` 格式，单条最多 256 字节：

```text
magic[4] = "FWC1"
format_version: u8 = 1
message_type: u8 = HELLO(1) | ACCEPT(2) | REJECT(3)
body_len: u16 big-endian
body[body_len]
```

`HELLO` 固定声明客户端支持的最低/最高 wire version、IPv4/IPv6/分片/强制多路径能力、最大 IP 包和最大 QUIC DATAGRAM。`ACCEPT` 固定返回最高共同版本、最终能力、分片参数、非零会话代际，以及客户端/服务端的点对点 IPv4 和/或 IPv6 地址。`REJECT` 只返回稳定原因码和可选重试秒数，不返回内部错误字符串。

- v1 必须同时具备分片和已协商 MPQUIC，且至少启用 IPv4 或 IPv6；
- 最大 IP 包不得低于 1280，DATAGRAM 上限不得低于 1036；
- 协商后的最大 IP 包长必须同时约束双方出站完整包和入站 `FWI1.total_len`；入站超限仍先消耗外层 DATAGRAM 额度，并清除同 packet-id 的既有重组状态；
- 地址必须成对出现，不能是未指定、loopback、链路本地、组播或广播，客户端与服务端地址不得相同；
- 未知 magic、控制格式版本、消息类型、能力位、非零保留位或长度尾随全部拒绝；
- 版本选择只取双方区间的最高交集，没有交集就返回 `unsupported_version`，不得猜测解析。

同一 `client_id` 默认只允许一个活动代际。新连接完成 mTLS 和 `ACCEPT` 后才原子替换旧代际并关闭旧连接；失败的新连接不能踢掉健康旧连接。

### 重连与离线行为

客户端保持 TUN 存活并由内部 supervisor 重连：初始 250 ms、指数增长到 30 秒、加入随机抖动，网络恢复事件可提前唤醒。不得无限缓存离线流量：发送队列按包数和字节双重限制，满或断线时丢弃并增加稳定指标。重连成功后不重放旧 IP 包。

服务端地址重新解析、证书验证、全部配置路径验证和会话建立都必须重新执行。不得在失败时关闭 TLS 校验、静默退化到单路径后仍报告多路径已配置，或切换到未授权服务器。

## 可观测性与隐私

VPN 在现有 JSONL 基础上增加独立 schema 或明确事件字段，至少记录：

- 认证成功/拒绝、脱敏 `client_id`、会话代际和重连次数；
- TUN 上下行包/字节、QUIC 分片、重组完成/过期/冲突、队列丢弃；
- 源地址防伪、ACL、速率和资源上限拒绝；
- 当前路径数、路径变化、离线时长、升级版本和最终活动量。

默认日志不得记录完整 IP 包、DNS 查询内容、客户端证书、私钥、令牌或完整远端地址。需要流级诊断时必须使用显式短时开关并在文档中说明隐私影响。

## 升级与兼容

- `fixed-tcp/FWX1` 与 `vpn/FWI1` 使用不同模式和 ALPN；任一端不得猜测协议；
- 配置文件增加显式 `config_version`，升级器只执行已知的单向迁移并保留备份；
- VPN 线协议使用明确版本协商，服务端可在一个发布窗口同时支持当前版和上一版；
- 数据库或身份文件写入采用临时文件、fsync、同目录 rename；
- 每个发布候选必须验证旧客户端连新服务端、新客户端连旧服务端的预期结果，以及升级中断后的回退。

## 分阶段门槛

### M2.0：协议与纯内存核心

- 固化本文件；
- 实现 `FWI1` 分片、乱序重组、超时/内存/片数上限和 IP 头检查；
- 模糊/属性测试证明任意输入不 panic、不越界、不超过资源合同。

当前进度：`FWI1` 编解码、IPv4/IPv6 长度检查、乱序与重复重组、冲突整包丢弃、64 片/1024 包/8 MiB/3 秒上限和可观测计数已实现；`FWC1` HELLO/ACCEPT/REJECT、版本交集、能力和虚拟地址检查也已实现。真实 loopback QUIC 已验证 TLS 1.3 mTLS、独立客户端 CA、叶证书 SHA-256 指纹注册、未知/禁用身份拒绝、强制 MPQUIC/DATAGRAM 能力及双向控制 STREAM；三连接场景证明失败候选不扰动健康旧会话，成功候选完成 `ACCEPT` 后才原子替换旧代际。严格 JSON 身份文件支持双指纹轮换槽、地址/指纹冲突拒绝、ACL/资源上限、受保护文件权限和失败保留旧注册表；成功禁用、删除活动指纹或修改策略会撤销并关闭当前代际。

数据热路径现已从会话协调器中拆出：每个身份使用独立速率锁，每个活动代际持有自己的双向 `VpnDataPathHandle` 和真实 `VpnReassembler`，不同身份逐包处理不争用全局互斥锁；同一身份跨证书/重连共享 token bucket。外层 `FWI1` DATAGRAM 在解析前按次数和字节计费，随后统一执行严格解码、身份内淘汰、全局原子字节/未完成包预算、重组和完整 IP 策略。完成、重复、冲突、长度改变、超时、淘汰、代际替换、禁用、释放和 Drop 的账本回收均有确定性测试；20,000 组对抗序列逐步核对本地实际缓冲与全局账本完全相等，两个身份锁隔离测试也已通过。

真实 NoQ DATAGRAM 运行器也已接线：上行/下行完整 IP 包通过包数和字节双重有界队列与未来 TUN 侧隔离；出站整包的所有 fragment 以一个原子 token-bucket 批次准入，避免只发半包前就部分扣额；实际发送使用等待型 DATAGRAM 背压，入站队列满则丢新包并继续读取 QUIC。运行器包含 250 ms 默认重组过期 tick、取消安全、连接/代际终止原因、packet-id 耗尽保护和脱敏原子指标；同一数据句柄只能绑定一次。客户端正式工厂现从受验证的 `VpnAccept`、本地 ACL 和资源上限创建已激活句柄，直接绑定服务端分配的 IPv4/IPv6、会话代际和协商最大 IP 包长，不构造虚假证书指纹或 `VpnIdentity`。工厂自身跨代际持有速率桶、全局重组预算和指标，候选重连与旧会话重叠时不能各拿一整份额度。

真实 loopback 组合测试现已串通 TLS 1.3 mTLS、`FWC1` 客户端/受管服务端握手、双方数据句柄和双方 NoQ DATAGRAM 运行器：分片 IPv4 上行、IPv6 下行均完成，协商 `1280` 字节时 `1281` 字节包被运行器拒绝，服务端关闭及成功代际替换都会让旧运行器退出。独立边界测试还证明入站超限声明会在外层计费后清除同 packet-id 旧分片并把全局账本归零。M2.1 后续已把这些部件、包设备桥接、真实 UDP 监听、DNS、显式源 IP 路径、真实 TUN、最小网络 helper 和独立产品进程放进同一隔离纵切；这证明产品生命周期地基成立，但不包含宿主机默认路由、NAT、DNS 或生产运维，因此仍不是可部署 VPN。

原始包/控制核心的独立 `cargo-fuzz` 此前在 stable、`sanitizer none` 下连续 60 秒完成 84,831,505 次覆盖率执行，零 crash、timeout 或资源不变量失败；后续身份 JSON 与双向策略各完成一次 10 秒增量覆盖率门控。新的集成数据路径已经加入同一 fuzz 入口并通过锁定编译；当前环境缺少 `cargo-fuzz` 子命令，只能用普通 release libFuzzer 构建执行 10 秒断言门控，完成 12,966,959 次且零 crash/timeout，但该构建明确没有覆盖率插桩，不能冒充新的覆盖率证据。集成热路径的正式 `cargo-fuzz` 覆盖率复跑和 nightly + AddressSanitizer 仍未完成，因此 M2.0 尚未关闭。

### M2.1：Linux 单客户端 TUN 纵切

- 独立 `vpn-server` / `vpn-client` 配置和 ALPN；
- root 网络准备单元 + 非特权主进程；
- 本地 namespace 中 IPv4、IPv6、TCP、UDP、ICMP 端到端；
- MTU、分片、乱序、丢包和退出清理门控。

第一小步固定为“预附着包设备桥接”，不创建或配置真实 TUN：

- 常驻数据进程只接收一个已经附着到 `IFF_TUN | IFF_NO_PI`、可由当前用户访问的文件描述符；本层只把它切为 nonblocking 并交给 Tokio readiness，不执行 `TUNSETIFF`、地址、路由、NAT、forwarding 或 DNS 操作；
- 每次设备 read 必须对应一个完整 IP 包，最大读缓冲由会话协商上限决定并额外留 1 字节用于识别超限/截断；空包、超限包和运行器队列满都只丢当前包并计数，不阻塞另一个方向；
- 设备下行 write 必须一次写完整包；部分写不能被拆成第二个“续包”，而是稳定失败并停止本代际；
- 桥接器同时监督设备上行、设备下行和 DATAGRAM 运行器。任一真实故障、连接结束或显式停止都会唤醒其他任务、保留原始停止原因并有界归还队列额度；离线期间不重放旧包；
- 第一轮测试使用 Unix packet socket 作为不需 root 的真实文件描述符替身，验证包边界和双向桥接；真实 TUN、namespace 路由与清理留到后续独立门控。

当前地基：真实 NoQ DATAGRAM 双向运行器、有界 TUN 边界队列、分片批次准入、周期过期、稳定终止报告和客户端 `ACCEPT` 数据句柄工厂已完成组合 loopback 验证。上述“预附着包设备桥接”第一小步也已实现：只对传入 fd 设置 nonblocking，Unix packet socket 实测保持双向包边界；超限包被丢弃后后续合法包继续传输，运行器队列满只丢当前设备包并精确计数，代际 stale 原因能穿透到桥接报告，设备写失败会停止本代际且不产生续包。后续第六至第十三小步又完成真实 namespace 端到端矩阵、TUN/root route 网络事务、非特权 `flowweave-vpn server|client` 生命周期、READY 后 client policy routing、显式 server forwarding/NAT 和 Type=notify 安装编排；仍需实现 DNS、真实宿主安装验收与长期恢复。

第二小步固定严格产品配置和“只附着既有 TUN”边界：

- server/client 使用各自的版本化 JSON，`config_version` 当前只能为 `1`；最大 1 MiB、必须是普通受保护文件，允许部署为 root-owned、仅 group 可读的 `0640`，但拒绝 group 写/执行和任何 other 权限；未知、重复、缺失字段全部拒绝，引用的相对路径只按配置文件目录解析，不在解析阶段读取密钥、解析 DNS 或触碰网络；
- server 固定包含 UDP `listen`、服务端证书/私钥、客户端 CA、身份文件、`tun_name`、`tun_mtu`、最大 DATAGRAM 和全局重组字节/未完成包上限；
- client 固定包含 `server`、严格 `server_name`、服务端 CA、客户端证书/私钥、`tun_name`、`tun_mtu`、最大 DATAGRAM、至少一组预期客户端/服务端 IPv4 或 IPv6 隧道地址对、本地目标 CIDR、逐客户端速率/重组上限、全局重组上限，以及可选 primary/additional 外层源 IP；
- `tun_name` 只能是 1～15 字节的安全 ASCII 接口名；`tun_mtu` 同时作为 `HELLO/ACCEPT.max_ip_packet_len` 和包设备桥接上限，必须在 `1280..=65535`；每个隧道地址族必须成对出现、地址合法且客户端/服务端不同，本地 ACL 只能引用已配置预期地址的族，路径 IP 不得重复或混合地址族；
- 常驻进程拒绝 real/effective/saved UID 任一为 0、inheritable/permitted/effective/ambient 任一集合中的 `CAP_NET_ADMIN`，并强制 `NoNewPrivileges`；附着前用 `if_nametoindex` 证明接口已存在并核对接口已启用、实际 MTU 与配置精确一致，再打开固定字符设备 `/dev/net/tun`，只请求精确名称的 `IFF_TUN | IFF_NO_PI`；附着后用 `TUNGETIFF` 复核名称和 flags，并再次核对 index、状态与 MTU。竞态消失只能失败，不能由数据进程重建；
- 真实附着测试只能在一次性 user+network namespace 中由临时管理身份创建持久 TUN，再降为 device owner、清空 capability bounding/inheritable/ambient 集合并设置 `NoNewPrivileges` 后执行；主网络空间不运行创建、地址或路由命令。测试已证明 root、未封闭提权、接口未启用、MTU 不一致和不存在接口全部失败，正确 owner 能附着既有 TUN。

第二小步实现证据：server/client 示例均通过严格解析；产品配置单元测试覆盖未知/重复字段、版本、只读 group 权限、group 写/other 权限拒绝、路径逃逸、地址族、CIDR、资源上限、非法监听/远端地址和 Debug 脱敏。真实 TUN 门控由 `scripts/run_vpn_tun_lab.sh` 执行，只在临时 namespace 中创建 `fwvpn0`。本步没有把 TUN 与 QUIC 运行器组合，也没有地址、路由、NAT、forwarding 或 DNS 修改，因此仍不是可部署 VPN。

第三小步固定“先完整预检，再触碰网络”的静态启动装配：

- server 读取单张 DER 叶证书、私有 PKCS#8 DER 私钥、客户端 CA 和严格身份文件，构造 TLS 1.3 mTLS、v6.9/Cubic/NoQ 默认产品传输、服务端协商、共享全局预算、DATAGRAM 与桥接配置；
- client 读取服务端 CA、客户端 DER 证书和私有 PKCS#8 DER 私钥，依据预期隧道地址对构造严格 `server_name` TLS、地址族 HELLO、跨重连数据工厂、DATAGRAM 与桥接配置；后续运行时必须把 `ACCEPT` 四个地址与这些预期值精确比较；
- 凭据必须是非空普通文件且不超过 1 MiB，私钥拒绝 group/other 权限；CA 语法、证书/私钥匹配、客户端瞬时路径数和服务端“每身份重组上限不得大于全局预算”全部在 DNS、UDP、TUN 之前失败；
- 错误和 Debug 只报告稳定文件角色与原因，不输出凭据路径、远端地址、证书内容或私钥内容。

本步仍只生成内存中的静态启动上下文，不创建 Endpoint、不解析 DNS、不执行握手或附着 TUN。下一步才把这些已验证部件组装为单客户端非特权运行核心。

第四小步固定“单客户端连接运行核心”，仍不负责创建 Endpoint 或配置网络：

- 调用方必须提供已经完成 QUIC/TLS 握手的 `Connection` 和长期持有的 `VpnPacketDevice`；运行核心只为当前代际克隆设备句柄，不取得创建 TUN、地址、路由、NAT、forwarding 或 DNS 的权限；
- 服务端先执行受管 `FWC1` 握手并提交活动代际，再按 `ACCEPT` 的最终包长启动 DATAGRAM 和包桥接；握手后的任何装配失败都必须撤销当前代际并用稳定应用关闭码结束连接；
- 客户端必须在构造数据句柄或启动包桥接前，把 `ACCEPT` 的客户端/服务端 IPv4/IPv6 地址与本地预期值逐项精确比较；成功后 DATAGRAM 和包桥接上限使用协商值，不使用仅来自本地配置的较大上限；
- 每个 bootstrap 同一时刻只允许一个运行核心。租约由公开运行对象与实际桥接 worker 共同持有；即使调用方直接丢弃运行对象，也必须等旧 worker 真正退出后才允许下一代际读取同一 TUN；
- `shutdown`、连接自然结束和 `Drop` 都会关闭连接；服务端只用 `client_id + generation` 条件释放当前活动代际，不能误删已经替换它的新代际；错误、Debug 和最终报告不输出 client ID、分配地址、远端地址或凭据路径。

第四小步实现证据：真实 TLS 1.3 mTLS/MPQUIC 测试已由双方产品 bootstrap 完成 `FWC1`、客户端工厂、服务端受管代际、双方 DATAGRAM 和双方包桥接，Unix packet socket 上的 1280 字节 IPv4 上行与 1500 字节 IPv6 下行均逐字节一致；双方停止后桥接报告闭合，服务端当前代际被释放。把客户端预期地址改为与服务端分配不一致时，客户端在数据面启动前失败，服务端随后观察连接结束并释放代际。租约测试还证明运行对象和 worker 任一仍存活时都不能取得第二个读者。该测试仍未把真实 TUN 附着和 QUIC 数据面放进同一个 namespace。

第五小步预注册为“Endpoint 生命周期”，在 root oneshot 和真实路由之前完成：

- 服务端只绑定严格配置中的显式 UDP `listen`，使用有界 TLS/握手截止，一次只交给单客户端运行核心一条已确认连接；拒绝或失败连接必须回到 accept 循环，活动连接结束后才允许下一条连接取得 TUN；
- 客户端在有界期限内重新解析 `server`，继续使用严格 `server_name`，按配置的 primary/additional 源 IP 建立并验证路径；任一路径配置失败都不能静默宣称多路径成功；
- Endpoint、连接、控制握手和桥接必须有单一所有者及明确关闭顺序；启动失败不得遗留 UDP socket、活动代际、DATAGRAM worker 或 TUN 读者；本小步先固定单次连接与有限重试边界，不提前实现无限后台重连；
- 测试先用 loopback 的真实 UDP Endpoint 覆盖服务端连续拒绝/成功、客户端 DNS/名称/源地址错误、握手超时、连接关闭和同一预附着包设备的下一代际复用；通过后才在一次性 namespace 中与真实 TUN 组合。

第五小步实现证据：

- 服务端从严格配置中的非零显式 UDP `listen` 启动真实 NoQ Endpoint；一次只运行一个包桥接代际，活动期间新 `Incoming` 会立即 `refuse`，禁用身份的 `FWC1 REJECT` 和握手/装配失败不会终止 accept 循环。停止时先关闭新接入和 Endpoint，再有界等待当前连接与 Endpoint 进入 draining；报告分开计数传输失败/超时、确认失败/超时、忙时拒绝、会话拒绝、启动失败、正常完成、worker 失败和强制回收。
- 客户端每次启动都在有界期限内调用系统 DNS，过滤非法或与显式源 IP 不同地址族的结果、去重并最多尝试 4 个地址；每个地址的 TLS 建立、确认和全部显式路径共用一个总截止。`server_name` 继续交给 rustls 标准校验，没有 IP 成功后关闭名称校验的回退。
- primary 与 additional 同时存在时，客户端只用通配 socket 引导 TLS，随后逐条验证所有显式源 IP 并关闭临时 Path 0；只有 additional 时保留系统选择的引导路并增加显式路径；任何路径失败都会关闭整个候选 Endpoint，不能静默缩成单路。
- 客户端 Endpoint 运行对象持有 Endpoint 与连接核心，`shutdown`/`wait` 返回连接和 Endpoint draining 报告，直接 `Drop` 也会关闭 Endpoint。错误类型只保留稳定阶段、`io::ErrorKind` 和无地址的 NoQ 错误分类；Debug 不输出解析后的服务端地址、本地源地址或 `ACCEPT` 隧道地址。
- 真实 UDP loopback 测试使用 `localhost` DNS、`127.0.0.1/127.0.0.2` 两条显式源路径和同一双方 Unix packet socket 包设备：先禁用身份得到一次受控拒绝，再启用身份连续完成两个代际；活动期第二连接被服务端忙时拒绝，两个成功代际分别逐字节传输 1280 字节 IPv4 上行和 1500 字节 IPv6 下行，停止后服务端活动代际均释放且 Endpoint draining 闭合。另两项反例证明未配置在主机上的 `192.0.2.44` 源地址在 bind 阶段失败，UDP 黑洞在 75 ms 测试截止内失败，二者错误均不包含地址。

第五小步仍是 library API，包设备仍由测试直接提供，且没有无限后台重连。第六小步固定为：在 `scripts/run_vpn_tun_lab.sh` 的一次性 user+network namespace 内，把同一套 Endpoint 生命周期与真实预附着 TUN 放进一场测试，先只配置点对点 IPv4/IPv6 地址和隔离路由，验证原始包、退出清理和下一代际复用；通过后再扩展 TCP、UDP、ICMP、服务端 forwarding/NAT 和 root oneshot，不在主网络空间试接。

第六小步实现证据：

- 脚本现在额外创建临时 mount namespace，并用私有 `/run/netns` 在同一 rootless user namespace 内建立 `fwserver` 与 `fwclient` 两个独立 network namespace；两者仅通过一对 veth 的 `192.0.2.0/30` 外层链路相连，各自拥有一个 owner 为 UID 1000、MTU 1500、`IFF_TUN | IFF_NO_PI` 的 `fwvpn0`。主网络空间没有接口、地址或路由变化。
- 管理阶段只在临时 namespace 中配置 `10.77.0.1/32 ↔ 10.77.0.2/32`、`fd77::1/128 ↔ fd77::2/128` 和对应 host route；没有默认路由、forwarding、NAT 或 DNS。server/client 数据测试进程随后均以 real/effective/saved UID 1000、空 bounding/inheritable/permitted/effective/ambient capability、`NoNewPrivileges` 运行，并各自通过产品附着层重新打开既有 TUN。
- 服务端从严格 JSON 绑定 veth 地址上的真实 UDP Endpoint，客户端使用显式 veth 源 IP；双方完成 TLS 1.3 mTLS、MPQUIC、`FWC1`、DATAGRAM 和包桥接。普通 UDP socket 分别绑定两端隧道 IPv4/IPv6 地址，以 `1300～1400` 字节确定性 payload 验证四个方向：IPv4 上行、IPv4 下行、IPv6 上行、IPv6 下行；这些包大于单个 1200 字节 FlowWeave DATAGRAM 的净载荷，实际覆盖 `FWI1` 分片/重组，而接收 payload 和隧道对端源地址均精确匹配。
- 第一代际关闭后，服务端确认活动代际释放；客户端与服务端都继续持有同一个 `VpnAttachedTun`，第二代际在不重建接口或地址的情况下再次完成 1300 字节 IPv4 上行。两代停止后 Endpoint draining 均闭合，活动代际为空；双方丢弃长期句柄后还能再次附着同一 TUN，证明旧 worker、租约和 fd 已完成清理。
- 同一专用脚本仍逐项运行原有 root、`NoNewPrivileges`、接口 down、MTU 和不存在接口反例。新增测试按设计在普通 `cargo test` 中 ignored，只有隔离脚本设置角色与临时目录后才运行；准备、server 和 client 三个进程任一失败都会终止其余进程并清理临时目录与 namespace。

第六小步完成的真实 IPv4/IPv6 UDP 与分片纵切，已经由下面第七、八小步继续补齐常见协议、MTU、外层中断和异常退出清理；随后第九小步把内层地址/host route 收敛为 root 网络事务，第十、十一小步补齐产品 READY 与客户端默认/选择性路由事务，第十二小步完成服务端 forwarding/NAT。DNS 仍必须按后续独立合同实现。

第七小步先固定常见协议与 MTU 合同，不和故障恢复混在一次改动：

- IPv4 内层 TCP 由客户端显式绑定 `10.77.0.2` 主动连接服务端 `10.77.0.1`，发送至少 256 KiB 带序号确定性数据后半关闭写方向；服务端必须读到 EOF、逐字节校验、完整回显并半关闭，客户端必须读到完全相同的 EOF 闭合数据。该连接同时证明 SYN/ACK、上行和下行都经过真实 TUN。
- IPv4 与 IPv6 ICMP echo 都必须从客户端隧道地址发往服务端隧道地址；测试进程继续无 capability 且启用 `NoNewPrivileges`，只允许使用内核 unprivileged ping socket，不能靠恢复 `CAP_NET_RAW` 过线。每族固定 2 个 echo、1 秒间隔、5 秒总截止，退出码必须为零。
- IPv4 UDP payload `1472` 字节和 IPv6 UDP payload `1452` 字节分别形成精确 1500 字节 IP 包，必须双向成功；随后在 socket 上强制 PMTU discovery/DF，IPv4 `1473` 与 IPv6 `1453` payload 必须由本地内核以 `EMSGSIZE` 拒绝，不能被 IP 分片或 FlowWeave 静默截断。
- 所有新增流量继续复用第一代际的同一个真实 TUN 与 Endpoint；原有 `1300～1400` 字节 `FWI1` 分片、第二代际和退出重附着门控不得删除。完成协议/MTU门控后，连接中断和异常退出清理使用下一份独立合同。

第七小步实现证据：

- 客户端用 `TcpSocket` 先绑定 `10.77.0.2`，再经 TUN 主动连接服务端 `10.77.0.1:6200`；发送 256 KiB 确定性 payload 后半关闭写方向。服务端从 `10.77.0.2` 接受连接、读到 EOF、逐字节核对、完整回显并半关闭；客户端读到相同 EOF 闭合 payload。该流和同期 UDP 共享同一个第一代际，没有专用旁路。
- 客户端临时 network namespace 的 `ping_group_range` 只放行 GID 1000；数据进程仍为空 capability 且 `NoNewPrivileges`。iputils 明确使用 unprivileged ping socket，IPv4 `10.77.0.2 → 10.77.0.1` 与 IPv6 `fd77::2 → fd77::1` 各完成 2 个 echo，退出码为零；没有恢复文件 capability、setuid 或 `CAP_NET_RAW`。
- IPv4 UDP payload `1472` 与 IPv6 payload `1452` 在上行和下行四个方向均完整到达，分别形成精确 1500 字节 IP 包。随后客户端分别设置 `IP_MTU_DISCOVER/IPV6_MTU_DISCOVER = IP_PMTUDISC_DO`；`1473/1453` 字节 payload 都在本地 `send_to` 返回 `EMSGSIZE`，对端没有收到截断或隐式 IP 分片包。
- 原有四方向 `1300～1400` 字节 `FWI1` 分片、第二代际和双方退出后重新附着仍同时通过；组合脚本总运行时间约 3 秒，没有增加主网络空间副作用。

第八小步预注册为外层中断与异常退出：VPN 产品传输新增独立的 10 秒 QUIC connection idle timeout，双方继续每路径 200 ms keepalive，并保持 v6.9 的 3 秒 PathIdle 与 3 PTO 路径状态保留不变；这给“所有路径均失联”一个明确产品上限，不改变 A 组换路算法。在第三代际完成控制握手后，由临时管理身份把 client veth 设为 down，不发送 QUIC close；双方必须在 15 秒测试截止内让 DATAGRAM/桥接停止、服务端活动代际归零且 TUN 可重新附着。随后分别强制终止 client 和 server 数据进程，脚本必须回收另一个进程、私有 `/run/netns`、veth、TUN、状态目录和子 namespace。该步不得通过缩短 v6.9 的 3 秒 PathIdle、关闭 TLS 校验或给数据进程恢复 capability 来过线。

第八小步实现证据：

- server/client 的 VPN 产品 transport 都显式设置 10 秒 QUIC connection idle timeout；静态门控同时核对两侧配置。原有 3 秒逐路径 PathIdle、3 PTO 路径状态保留和 200 ms keepalive 没有改变。
- 第三代际完成 mTLS、`FWC1` 和数据面装配后，客户端写入一次性故障标记，由仍在临时 user/network namespace 内的管理 helper 把 `fwclient0` 设为 down。双方没有发送 QUIC close，仍在 15 秒固定截止内停止 DATAGRAM/桥接，服务端活动代际归零；停止原因稳定归类为连接关闭或连接失败。包含前两代协议/MTU 门控的整场运行约 12.86 秒。
- 脚本恢复 veth 后，以同样的 UID 1000、空 capability 与 `NoNewPrivileges` 分别启动持有 server/client Endpoint 和 TUN 的进程。客户端被 `SIGKILL` 后服务端仍存活，随后服务端也被 `SIGKILL`；两侧再次用同一无特权身份附着各自 `fwvpn0` 均成功，证明不可执行析构的异常退出仍由内核回收 TUN fd 和独占租约。
- 所有就绪标记等待都有固定上限，任一阶段失败都会终止残余 helper/client/server；外层 trap 继续删除私有 `/run/netns`、veth、TUN、状态目录和子 namespace。主网络空间没有接口、地址、路由、NAT、forwarding 或 DNS 变化。

第八小步关闭了 M2.1 的第一组失联与进程异常退出门控，但还不等于产品重连或可部署 VPN。其后第九小步先实现 root helper 的版本化状态、幂等 prepare/cleanup 和失败回滚；内部 supervisor、多路径恢复和长期 soak 仍归 M2.3。

第九小步预注册为“最小特权网络事务”，本步仍只准备点对点 TUN 地址与对端 host route，不配置默认路由、策略路由、NAT、forwarding 或 DNS：

- 新增独立 `flowweave-vpn-net` root helper；常驻 VPN 数据进程仍以非 root、空 capability 和 `NoNewPrivileges` 运行。helper 只接受 `prepare-client <product-config> <state> <owner-uid|@owner-user>`、`prepare-server <product-config> <state> <owner-uid|@owner-user>` 与 `cleanup <state>`；数字 UID 必须是规范非零十进制，用户名选择器使用严格 ASCII 语法和 NSS 查询且同样拒绝 root。不提供任意接口、地址、路由或 shell 参数入口。
- 网络意图必须从现有严格 VPN product config 派生，避免维护第二份地址真值。client 使用预期本端地址作为 TUN `/32`、`/128` 地址，并只添加预期服务端 host route；server 从严格 identity registry 取得服务端地址和全部已分配客户端 host route。供 root helper 与数据进程共享的 product config/identity 文件必须为普通、非符号链接、root-owned、group-readable 且不可被 group 写或被 other 访问，二者 group 必须一致；该 group 作为 TUN owner GID，显式 owner UID 与 group 共同进入计划指纹。私钥文件仍维持更严格的私有权限。
- 状态文件 schema 单独固定为 version 1、最大 64 KiB、root-owned `0600`，记录规范化计划指纹、角色、TUN 名称/MTU、owner、地址、路由、随机所有权 token、临时接口名、接口 index 与 `preparing|prepared` 阶段。状态目录必须为 root-owned 且不可被 group/other 写；同目录 lock file 使用非阻塞独占锁拒绝并发 prepare/cleanup。
- prepare 必须先原子持久化 `preparing` journal，再以随机临时名和 `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL` 创建持久 TUN，设置 owner/alias/MTU/地址/host route/up，最后原子 rename 为配置名称并提交 `prepared`。任一步失败都只按 journal 中的 token、ifindex 和名称回滚本事务拥有的接口；状态写入使用同目录临时文件、`fsync`、rename 和目录 `fsync`。
- 重复 prepare 只有在规范化计划指纹相同，且真实接口的名称、index、TUN 类型、持久/PI/多队列 flags、alias、MTU、up 状态、地址与 host route 全部匹配时才返回 `already_prepared`；计划冲突或漂移必须失败，不能覆盖现有状态。发现未完成的 `preparing` journal 时，先证明资源归属并回滚，再重新开始。
- cleanup 不重新读取可能已改变或丢失的产品配置，只使用 root 状态；只有 alias token、ifindex、名称和 TUN 类型共同匹配才撤销持久性并删除接口。接口已消失时可清除上次 cleanup 留下的状态；归属不明、状态损坏、活动 TUN 仍被数据进程占用或任何删除失败时保留状态并失败，不能删除同名外部接口。
- 真实门控只能在一次性 user+mount+network namespace 中运行，覆盖首次 prepare、重复 prepare、状态冲突、既有同名接口拒绝、路由冲突触发的中途回滚、cleanup、重复 cleanup、所有权 alias 漂移拒绝和数据进程附着。主网络空间不运行 helper。

第九小步实现证据：

- `flowweave-vpn-net` 已实现上述命令。client 计划直接由严格 product config 的预期地址对派生；server 计划由 product config 引用的严格 identity registry 派生。规范化计划排序并去重地址/host route，SHA-256 指纹同时绑定角色、TUN、MTU、解析后的 owner UID 和 root-owned 配置 group GID；安装单元使用 `@flowweave`，避免把发行版分配的服务 UID 错当成固定 1000。Debug 与稳定错误不输出地址、token 或指纹。
- product config 与 identity 文件的通用加载边界现允许只读 group 权限，仍拒绝 group 写/执行和所有 other 权限；root helper 额外要求两者 root-owned、group-readable、同 group 且非符号链接。私钥读取边界没有放宽，仍要求更严格的私有权限。
- helper 使用固定受信 `iproute2` 路径且清空环境，不经过 shell；TUN 本身通过 `/dev/net/tun` ioctl 以 `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL` 创建，再设置 owner/group/persist。地址和路由只接受派生出的 `/32`、`/128` host 项，不存在任意用户参数进入 `ip` 参数列表。
- root-owned `0600` 状态通过同目录临时文件、文件 `fsync`、rename 和目录 `fsync` 更新；lock file 使用 `flock(LOCK_EX|LOCK_NB)`。`preparing` journal 在任何网络变更前落盘，随机 128-bit token 同时形成接口 alias，临时接口名另取 48-bit 碰撞域并在创建前检查；成功 rename 后才提交 `prepared`。
- `scripts/run_vpn_network_lab.sh` 在一次性 user+mount+network namespace 中真实通过：非 root 调用拒绝、非法 owner UID、并发锁、首次/重复 client prepare、无 capability/`NoNewPrivileges` 数据进程附着、活动 fd 阻止 cleanup、配置指纹冲突、额外地址漂移、模拟 `preparing` 崩溃恢复、alias 归属漂移拒绝、cleanup/重复 cleanup、既有同名外部 TUN 保护、预置路由冲突后的临时 TUN/状态完整回滚，以及 server 计划的双栈地址与客户端 host route。
- 原有 `scripts/run_vpn_tun_lab.sh` 的双 namespace Endpoint 纵切也已改由该 helper 分别准备 server/client TUN，不再手写内层地址和 host route；全部 UDP/TCP/ICMP/MTU/失联/`SIGKILL` 门控完成后，helper 在两侧 cleanup 并证明接口消失。主网络空间仍无网络副作用。

第九小步完成的是可审计的最小点对点网络事务，还没有修改主机默认流量。原计划随后扩展路由事务；启动顺序审计发现，若在客户端完成 QUIC bootstrap 前接管流量，外层连接可能被导回尚未工作的 TUN，因此先建立第十小步 READY 合同。

进一步审计启动顺序后，第十小步调整为先建立产品进程与 READY 合同：客户端在 primary+additional 同时配置时会先用通配 bootstrap Path 完成 TLS，再打开显式源路径并关闭 Path 0；若 systemd 在此之前激活 VPN 路由，bootstrap QUIC 可能被导回尚未工作的 TUN。因此路由激活必须等待客户端明确 READY，不能只等待 TUN prepare 成功。

第十小步预注册为“非特权产品进程与可验证 READY”：

- 新增独立 `flowweave-vpn server <config>` 与 `flowweave-vpn client <config>`；它们不创建接口、不修改地址/路由/NAT/forwarding/DNS，也不调用 privileged helper。进程先完成严格 bootstrap，再以现有边界附着 helper 已准备的 TUN；root、残留 `CAP_NET_ADMIN`、未设置 `NoNewPrivileges`、错误 owner/MTU/flags 均继续失败。
- server READY 只能在真实 UDP Endpoint 绑定成功且 accept worker 已启动后发出；client READY 必须晚于 DNS、标准 TLS 名称校验、MPQUIC、全部显式路径验证、`FWC1 ACCEPT` 地址精确比对、DATAGRAM 和包桥接启动。该顺序是后续 systemd `ExecStartPost` 或独立 route activator 的唯一许可点。
- 若存在 `NOTIFY_SOCKET`，进程发送不含地址/身份的 `READY=1` 与 `STOPPING=1`；无 notify socket 时继续运行，并在 stdout 只输出稳定的 `ready` / `stopped` 行供隔离门控使用。无论哪种路径，错误与 Debug 不输出配置路径、解析地址、隧道地址、证书或 token。
- SIGTERM 与 Ctrl-C 必须先发送 STOPPING，再请求 Endpoint/连接/桥接停止并等待现有有界 drain；server/client 的 clean stop 都要求 Endpoint draining 成功。Endpoint 或连接在未收到本地停止请求时自然结束必须返回稳定非零错误，不能打印 `stopped` 冒充正常服务。
- 第十小步仍不实现后台重连：client 外层失联会按 10 秒 connection idle 上限结束并以非零状态退出；后续 M2.3 supervisor 才负责指数退避、网络恢复与路由状态联动。server 保持顺序接入循环直到本地停止。
- 真实门控复用第九小步 helper 准备的双 namespace TUN：启动产品 server/client、分别观察 READY，完成双栈大 ICMP 或 UDP 流量，SIGTERM client 后确认 server 保持运行，再 SIGTERM server；双方必须 `stopped`、退出码为零、TUN 可由 helper cleanup。另一路切断外层 veth，client 必须非零退出且不得发送正常 stopped。

第十小步实现证据：

- 新增 `flowweave-vpn server <config>` 与 `flowweave-vpn client <config>`。二进制只调用严格 bootstrap、既有 TUN 附着和 Endpoint/runtime，不调用 privileged helper；错误路径只输出稳定脱敏错误。
- `VpnPacketBridge`、客户端连接 runtime 和双方 Endpoint 增加可分离的 shutdown request 与取消安全 join。客户端 Endpoint 在连接任务刚结束、Endpoint drain 尚未完成时保留完成报告，信号竞态重新 join 不会丢状态或 panic。
- server 在 Endpoint 绑定和 accept worker 启动后发 READY；client 只在 DNS、TLS 1.3 名称验证、MPQUIC、显式路径、`FWC1 ACCEPT` 地址精确比对、DATAGRAM 和包桥接全部成功后发 READY。filesystem 与 abstract Unix datagram 两类 `NOTIFY_SOCKET` 均有单元测试，通知内容不带网络或身份值。
- SIGTERM/Ctrl-C 在 DNS/QUIC 启动阶段会取消尚未 READY 的连接尝试；运行期则先通知 STOPPING，再请求桥接、连接和 Endpoint 有界停止。clean stop 只有资源收敛后才输出 `stopped`。SIGHUP 当前同样先有界收敛，再返回稳定 `vpn_process_reload_unsupported`，不会伪装为正常停止。Endpoint 或客户端连接自行结束均为非零错误。
- `scripts/run_vpn_tun_lab.sh` 已在一次性 user+mount+network namespace 中真实运行产品 server/client：双方均为 UID/GID 1000、空 capability、`NoNewPrivileges`。client 在外层不可达、尚未 READY 的连接阶段收到 SIGTERM 后 5 秒内零退出，只输出 `stopped` 而不误报 `ready`；正常 READY 后 IPv4/IPv6 各三次 1300 字节 ICMP 全部往返。SIGTERM client 后只输出一次 `stopped`、零退出且 server 保持运行；server 随后同样正常停止。重启双方并切断 client 外层 veth 后，client 按既定 10 秒 connection idle 边界非零退出、没有 `stopped`，server 保持运行并在链路恢复后有界停止；最终 helper cleanup 证明两端 TUN 消失。主网络空间无网络副作用。

第十小步关闭了“谁运行数据面、何时允许接管路由、怎样区分正常停止与故障”这一基础合同，但没有让主机流量进入隧道。下一步恢复路由事务工作：扩展同一 journal/归属模型支持客户端选择性策略路由和外层 QUIC 逃生路由，并让 route activator 只在 client READY 后提交、在进程失败或停止时原子撤销；随后才实现服务端 forwarding/NAT，DNS 继续单独处理。

第十一小步预注册为“READY 后客户端策略路由事务”：

- 不把 DNS 解析出的服务端 IP 固化为逃生路由。客户端数据进程使用专用非零 UID；route activator 先为该 UID 安装高优先级 `lookup main` 规则，使产品自身的 DNS、QUIC、keepalive 和全部显式源路径继续走原网络。由 TUN 注入、没有该 socket UID 的普通主机流量再进入 FlowWeave 独立路由表。该模型避免 DNS 漂移、服务端多地址和双出口源地址与 root helper 形成第二份真值。
- client `allowed_destinations` 是路由选择与数据面 ACL 的同一真值。独立表只添加这些规范 CIDR 指向已归属的 TUN；随后用一个无 selector 的高优先级 lookup rule 查询该表，未命中的目标继续落回 main。`0.0.0.0/0` / `::/0` 因而形成全隧道，较窄 CIDR 形成选择性隧道；local rule 仍保持最高优先级。
- 路由状态使用与 TUN state 相同的非阻塞 lock 和 root-only 原子写边界，但保存在独立版本化 sidecar，记录网络计划指纹、TUN 名称/index、owner UID、规范目的 CIDR、随机未占用 table、相邻 rule priority、route metric 和 ownership protocol。`activating|active` journal 必须在任何 policy route 变更前落盘；cleanup 即使没有产品配置也能按 sidecar 精确撤销。
- 激活顺序固定为 UID 逃生 rule → 独立表 routes → tunnel lookup rule；最后一条 rule 才让普通流量进入 TUN。撤销和失败回滚使用相反顺序，先移除 tunnel rule 恢复 main，再删除 routes，最后删除 UID rule。任何既有 priority/table 冲突、额外 route/rule、字段漂移或重复项都失败并保留状态，不覆盖或删除外部网络对象。
- `activate-client` 只能由 Type=notify systemd 单元的 `ExecStartPost` 或等价受控 route activator 在 client READY 后调用；`deactivate-client` 由 `ExecStopPost` 在正常停止、启动失败和异常退出后调用。helper 本身仍不信任 stdout 文本，也不启动数据进程；本步实验脚本先显式模拟该时序，第十三小步再由安装单元固化。
- 隔离门控必须证明 READY 前没有 policy rule；READY 后普通 UID/根流量命中 TUN 表，而产品 UID 到服务端外层地址仍命中 main 且真实 QUIC/TUN 双栈流量继续；重复激活/撤销幂等，`activating` 崩溃可恢复，配置冲突和 route/rule 漂移失败，客户端正常/异常退出后撤销恢复原路由，最终 TUN cleanup 不遗留 sidecar、rule 或 table。该步不启用服务端 forwarding/NAT，也不声称公网全隧道可用。

第十一小步实现证据：

- `flowweave-vpn-net` 新增 `activate-client <product-config> <state>` 与 `deactivate-client <state>`。激活重新读取 root-owned 配置，先验证其 TUN 计划指纹与既有 prepared state 完全一致，再从同一 `allowed_destinations` 派生规范 CIDR；不接受任意 table、priority、UID、CIDR 或 shell 参数。
- client route sidecar schema 固定为 version 1、最大 64 KiB、root-owned `0600`，与 TUN state 共用同一非阻塞 lock。sidecar 记录双重 SHA-256 指纹、TUN name/index、owner UID、CIDR、随机空闲 table、相邻 priority、metric 和 protocol；Debug 与稳定错误不输出目的网络或指纹。
- helper 在 IPv4/IPv6 各自安装产品 UID `lookup main` rule，再把规范 CIDR 以显式 metric/protocol 加入独立表，最后才添加 tunnel lookup rule。选择 table/priority 前同时检查两族现有 rules 与 table；active 验证要求对象集合精确相等，额外 selector、重复 rule、额外 route、字段漂移或外部占用均失败。
- rollback/deactivate 先检查当前对象仍是 sidecar 记录的精确子集，再按 tunnel rule → routes → UID rule 顺序删除；`cleanup` 会先调用同一撤销路径，再处理持久 TUN。`activating` journal 即使配置随后改变，也先按旧 state 安全回滚，再按新配置重新激活。
- `scripts/run_vpn_network_lab.sh` 已真实通过首次/重复 activate、首次/重复 deactivate、active 配置冲突、额外 route、额外带 selector rule、完整安装后模拟 `activating` 崩溃并按新 CIDR 恢复，以及 cleanup 自动移除 sidecar/table/rules；已有 TUN 锁、漂移、活动 fd、alias 和中途失败门控继续通过。
- `scripts/run_vpn_tun_lab.sh` 在真实产品 client 输出 READY 后才调用 activate：route lookup 证明 UID 0 到外层服务端地址命中 `fwvpn0`，产品 UID 1000 仍命中原 `fwclient0`；随后双栈 1300 字节 ICMP 继续通过，证明 QUIC 没有自锁。正常 SIGTERM 与外层断链非零退出后都调用 deactivate，原 main 路由恢复，最终 cleanup 无 sidecar/rule/table/TUN 遗留。主网络空间无副作用。

第十一小步完成的是可回滚的客户端流量接管原语；下面预注册的第十二小步现已实现并通过隔离门控。两端事务具备后，下一步用 Type=notify systemd 把 prepare → data READY → activate 与 stop/failure → deactivate → cleanup 串成可安装、可回退单元。DNS 继续后置。

第十二小步预注册为“显式启用的服务端 forwarding/NAT 事务”：

- server product config 增加可选 `forwarding` 对象；缺省即禁用，root helper 不猜测服务器用途。对象固定包含 `manage_sysctls`、`ipv4_masquerade`、`ipv6_masquerade` 三个布尔值。masquerade 只能对实际配置了对应隧道地址族的身份启用；IPv6 NAT 必须显式选择，不能因 ULA 自动开启。
- `manage_sysctls=false` 是安全默认：激活只在 `net.ipv4.ip_forward` / `net.ipv6.conf.all.forwarding` 对所需地址族已经为 1 时继续，且永不修改。`manage_sysctls=true` 只适合明确作为路由器的受控主机；journal 记录原值，单实例全局锁和专属 nft table 防止两个 FlowWeave server 争用，撤销只在实时值仍符合本事务预期时恢复原值。文档必须说明全局 forwarding 可能影响非 VPN 接口，不能静默替用户开启。
- 不把出口接口写进配置。专属 `inet` nft table 只匹配已归属 TUN：按 identity registry 的精确客户端 IPv4/IPv6 源地址允许 TUN→非 TUN 新建/既有/关联流量，只允许非 TUN→TUN 的 established/related 返回流量，并显式 drop 其他涉及 TUN 的转发；宿主既有 nftables 仍可在其他 base chain 中进一步拒绝。
- NAT 只为显式启用的地址族生成 postrouting masquerade，并再次匹配 identity registry 的精确客户端源地址。未启用 NAT 的全球路由前缀或受控私网访问只做 forwarding，返回路由由管理员提供；helper 不添加任意公网默认路由或清空现有防火墙。
- server forwarding sidecar 使用与 TUN state 相同的 lock、root-only 原子写和计划指纹，阶段为 `activating|active|deactivating`。任何副作用前先写 journal；nft table、chains 和 rules 都带随机 ownership comment。active state 另存去除 volatile handle/metainfo 后的规范 JSON SHA-256，重复激活、撤销和 cleanup 必须同时验证对象集合、comments 与 fingerprint，额外 chain/rule 或表达式漂移一律失败。
- 激活只能在 server READY 后由 systemd `ExecStartPost` 调用。创建 nft table 后才按显式策略确认/开启 forwarding；撤销先停止本事务管理的 forwarding，再删除仍被证明归属的 table。启动失败、进程异常退出和 cleanup 都走同一恢复路径；主数据进程继续不持有 `CAP_NET_ADMIN`。
- 三 namespace 门控新增 `client ↔ server ↔ internet` 拓扑：证明 IPv4 masquerade 后 internet 只观察服务端外层地址，显式 IPv6 无 NAT 时按返回 route 保留客户端隧道源地址；同时覆盖 sysctl disabled 拒绝、显式管理/恢复、既有 nft table 冲突、额外 rule/表达式漂移、`activating|deactivating` 崩溃恢复和 cleanup 无遗留。该步仍不提供 DNS 接管或安装级 systemd。

第十二小步实现证据：

- `VpnServerProductConfig.forwarding` 缺省/`null` 均禁用，显式对象严格要求三个布尔字段；`flowweave-vpn-net activate-server|deactivate-server` 和 cleanup 共用 root-only v1 `.forwarding` sidecar、TUN state lock 与 `/run/flowweave-vpn-forwarding.lock`。启用地址从 identity registry 中 `enabled=true` 的精确客户端地址派生，NAT 请求缺少对应启用地址族时直接拒绝。
- helper 使用固定 `table inet flowweave_vpn` 和随机 table/chain/rule ownership comments；forward/postrouting chain、所有表达式与对象集合都按预期 JSON 精确验证，active state 保存去除 `metainfo`/`handle` 后的 SHA-256。额外 rule、同 comment 错误表达式、既有 table、计划漂移或 sysctl 漂移均拒绝，不清空其他 ruleset。
- `manage_sysctls=false` 在任何 journal/nft 副作用前确认所需 forwarding 已开启；`true` 记录各族原值，table 原子建立后才置 1，撤销先按安全条件恢复原值再删除已证明归属的 table。`activating|deactivating` 模拟崩溃、重复调用和 cleanup 都已幂等收敛。
- `scripts/run_vpn_network_lab.sh` 在私有 `0755` tmpfs `/run` 和一次性 network namespace 中通过 sysctl disabled 无遗留、外部管理、显式管理/恢复、全局锁、既有 table、配置冲突、额外规则、表达式漂移、两阶段崩溃恢复与 cleanup；`scripts/run_vpn_tun_lab.sh` 的三 namespace 真实产品门控证明 IPv4 internet 观察端只看到服务端 `198.51.100.1`，IPv6 观察端保留 `fd77::2` 并由显式 route 返回，正常/异常停止后 table、sidecar 与 sysctl 均恢复。

第十二小步完成了两端可回滚的网络事务，但尚未决定谁在真实服务生命周期中调用它们。第十三小步固定为“安装级 Type=notify 生命周期编排”：

- 新增独立 client/server systemd 单元。常驻 `ExecStart` 固定以 `User=flowweave`、`Group=flowweave` 运行；只有 `prepare-*`、`activate-*`、`deactivate-*` 和 `cleanup` 使用 `+` 前缀执行短命 root 网络事务，不能给数据进程 capability 或把整个服务改为 root。
- 启动顺序固定为 `ExecStartPre prepare → ExecStart 数据进程 → READY=1 → ExecStartPost activate`。`Type=notify` 和 `NotifyAccess=main` 保证子进程不能伪造 READY；客户端路由和服务端 forwarding 都不能在数据进程完成真实 bootstrap 前提交。
- 不配置 `ExecStop=`。systemd 先向主进程发送终止信号并等待其有界收敛，再执行两条有序 `ExecStopPost=`：先 `deactivate` 恢复主机流量路径，再 `cleanup` 删除 TUN。该路径必须覆盖 prepare 失败、READY 前失败、activate 失败、运行中异常退出、正常停止和重启。
- client/server 状态路径固定为 `/run/flowweave-vpn-client.network.json` 与 `/run/flowweave-vpn-server.network.json`。单元使用既有 journal 的幂等、漂移拒绝和崩溃恢复，不另建第二套网络状态；root helper 新增 `@owner-user` 选择器，通过 NSS 在每台主机解析服务 UID，不能假定 1000。
- 主进程必须保持空 `CapabilityBoundingSet`、空 `AmbientCapabilities`、`NoNewPrivileges`、`DevicePolicy=closed` 且只允许 `/dev/net/tun rw`；同时限制地址族、namespace、proc、内核 tunable、文件系统、任务数、fd 和内存。加固不能阻止短命 root helper 完成受审计网络事务。
- 真实生命周期门控使用当前用户的 systemd manager 和临时 unit，不触碰网络。它必须逐项证明正常停止、prepare 失败、READY 前失败、activate 失败和运行中异常退出的准确顺序，并证明 helper 命令不继承主进程的 `NoNewPrivileges`、数据进程会继承。正式单元的 root 身份和 hardening 由静态合同测试锁定。

第十三小步实现证据：

- 新增 `deploy/flowweave-vpn-client.service` 与 `deploy/flowweave-vpn-server.service`。两者均为 `Type=notify`，带 90 秒启动、30 秒停止、有限自动重启/start-limit、资源上限和主进程加固；`ExecStopPost` 顺序固定为 `deactivate → cleanup`。
- `flowweave-vpn-net prepare-*` 兼容原有规范数字 UID，并支持严格的 `@flowweave` NSS 解析；拒绝 root、缺失账户、非法用户名和非规范数字。解析后的真实 UID继续进入网络计划指纹，账户映射变化不会静默复用旧状态。
- `src/vpn_product_process.rs` 的静态合同测试逐行验证两个正式 unit 的 READY 类型、用户、所有 privileged 前缀、常驻命令无 `+`、无自定义 `ExecStop=`、两段清理顺序和关键 hardening，防止后续编辑把 root 权限扩散到数据进程。
- `tests/vpn_systemd_lab.rs`、临时 unit fixture 和 `scripts/run_vpn_systemd_lab.sh` 已通过真实 user systemd manager 连续验证五种场景。正常路径为 `prepare → data_start → data_ready → activate → data_stopped → deactivate → cleanup`；四种失败路径都在不误报成功的情况下执行 `deactivate → cleanup`。
- 动态门控同时从 `/proc/self/status` 证明数据进程 `NoNewPrivs=1`、有效 capability 为零，而带 `+` 的 helper 不继承该限制。user manager 本身不能把 helper 提升为 root，因此正式 root 身份仍由 system unit 静态合同约束；测试没有伪造这一边界。
- 两个正式 unit 的 `systemd-analyze security --offline=yes` 暴露评分均为 `3.0 OK`。本步没有为了降低评分加入尚未经过真实 QUIC/TUN 安装验证的 syscall 白名单。

至此，M2.1 的数据面、最小特权网络事务和安装生命周期骨架已经闭合，但仍不等于生产可部署 VPN：DNS 接管与回退、内部长期重连、真实宿主特权安装/卸载、发行版兼容、多日 soak 和跨版本升级回退证据仍缺失。

### M2.2：逐客户端身份与多租户隔离

- mTLS、指纹身份、静态地址、ACL、禁用和双证书轮换；
- 同地址/同身份冲突、源地址伪造、配额和公平性测试；
- 身份操作工具不打印私钥并支持原子回退。

当前地基：mTLS、指纹注册、双指纹重叠、禁用、静态地址、目标 CIDR、严格身份文件、单活动代际、成功后替换、在线撤销、跨代际共享速率桶、服务端按身份数据句柄、客户端 `ACCEPT` 工厂、外层 fragment 准入、真实重组、协商包长、原子全局账本、源地址防伪、双向 ACL 和真实 NoQ DATAGRAM 运行器已接入真实 TUN 产品进程。身份运维工具、SIGHUP 原子重载和长期多客户端攻击矩阵仍未完成。详见 `VPN_IDENTITY.md`。

### M2.3：重连和网络切换

- 内部 supervisor、DNS 重解析、代际替换、队列丢弃和路径重建；
- Wi-Fi/蜂窝切换、NAT rebinding、服务端重启、证书轮换和长时间静默连接故障注入。

### M2.4：运维产品化

- 安装/卸载、配置检查、升级/回退、日志轮转、指标导出和告警样例；
- nftables/route/DNS 状态可审计且异常退出后可恢复；
- 依赖、许可证、SBOM、漏洞扫描和最小权限审计。

### M2.5：生产声明门控

- 独立运营商双出口、多客户端、多小时和多天 soak；
- 真实 TCP/UDP/IPv6 应用、MTU 黑洞、限速/丢包/乱序和资源攻击矩阵；
- 当前版/上一版滚动升级与回退；
- 所有失败条件、支持平台和未证明边界写入发布说明。

只有 M2.0～M2.5 全部有可复现证据时，才允许把 VPN 模式称为生产可部署。中间版本只能标记为实验或试点。
