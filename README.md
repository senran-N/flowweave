# FlowWeave / 织流

FlowWeave 是一个 Rust 编写的实验性多路径 QUIC 项目，研究如何把 Wi-Fi、移动网络或多条宽带编织成一条连接。当前仓库同时包含可部署的固定目标 TCP 代理、隔离坏网络实验场、Hysteria 2.9.3 与 Linux MPTCP 公平对照和原始基准证据。

当前阶段不是通用 VPN 产品。已经完成的范围是：

- A：单条路径失效时保持原 MPQUIC 连接继续传输；
- B：在锁定的持续单流合同中聚合两条线路；
- C：在锁定的高丢包实时消息合同中降低尾延迟和丢失；
- Linux MPTCP 对照：A 正式正向 `0/5`、反向 `1/5` 完整闭环，FlowWeave 按连续性分支胜出；B 的 MPTCP 平衡/异构中位为 `29.089/27.561 Mbit/s`，与 FlowWeave 的 `26.580/27.509` 没有达到任一方双场景领先 15% 的胜出线；
- 一个只允许显式固定 TCP 目标的 TLS 1.3 MPQUIC 客户端/服务端代理；
- VPN 的 mTLS 身份、控制协商、客户端/服务端数据句柄、真实 NoQ DATAGRAM、包设备桥接、单客户端 Endpoint 生命周期、最小 root 网络 helper，以及独立的非特权 `flowweave-vpn server|client` 产品进程；隔离网络空间门控已接通 DNS、严格名称校验、显式源 IP 路径、真实 TLS 1.3 mTLS、`FWC1`、IPv4/IPv6 UDP/TCP/ICMP、精确 MTU、连续代际、`SIGKILL` 后 TUN 重附着、READY、客户端 policy routing，以及显式启用且可回滚的服务端 forwarding/IPv4 NAT。客户端由进程级 TUN packet pump 和内部 supervisor 跨越首次连接及后续代际：可恢复的首次连接失败和 READY 后断线都以 250 ms 起步、30 秒封顶的随机指数退避重新执行 DNS、TLS、全部显式路径和 `FWC1`，离线包立即丢弃并计数；可在本地确定的配置、协议或资源不变量错误仍快速失败。非特权 `NETLINK_ROUTE` 监听把 link/address/route 恢复事件作为提前重试提示，保留 250 ms 防抖、服务端 retry-after 下限和原定时器兜底；离线事件不会绕过完整连接验证。在线时 route 新增只排空，link/address 恢复会先等待 250 ms，再换用新 UDP socket，并按配置槽位逐条“验证新 PathId 与显式源 IP、收到旧 PathId `Abandoned` 后提交”；成功波次在 5 秒内合并后续 DAD/address 事件。真实 `fwnat` namespace 门控把第二条 outer path 的 SNAT 映射从固定端口 40000 切到 40001，证明同一客户端 PID、同一 QUIC stable ID 和同一 `FWC1` session generation 内两条 PathId 都完成原位替换，双栈 TUN 流量继续通过且没有 `connection_lost`/`reconnected`。完整代际重连门控仍覆盖客户端先启动/服务端后出现、身份撤销/恢复、单外层接口 down/up、服务端进程重启和离线 SIGTERM，并证明退避增长到至少 8 秒后真实 link-up 会提前唤醒；systemd 的 90 秒启动截止会在始终未 READY 时触发反向清理。服务端身份和客户端 TLS 凭据都可通过各自的同步非特权控制 socket 原子 reload；客户端有效候选在同一 PID/TUN pump 内切换到新的严格 mTLS/FWC1 代际，错误候选保留旧健康会话。DNS 接管、真实宿主安装验收和长期多客户端故障矩阵仍未完成。

完整结论、适用边界和不能外推的范围见 [PROJECT.md](PROJECT.md)，英文项目概览见 [ABOUT.md](ABOUT.md)。实验合同见 [BENCHMARK.md](BENCHMARK.md)，Linux MPTCP 预注册与结果见 [MPTCP_COMPARISON.md](MPTCP_COMPARISON.md) 和 [MPTCP_RESULTS.md](MPTCP_RESULTS.md)，代理持续负载合同见 [PROXY_SOAK.md](PROXY_SOAK.md)，令牌轮换合同见 [PROXY_ROTATION.md](PROXY_ROTATION.md)，生产 VPN 地基合同见 [VPN_RESEARCH.md](VPN_RESEARCH.md)，VPN 身份与轮换合同见 [VPN_IDENTITY.md](VPN_IDENTITY.md)，部署步骤见 [deploy/README.md](deploy/README.md)。

## 快速验证

需要 Rust 1.88.0。仓库根目录的 `rust-toolchain.toml` 会在使用 rustup 时自动选择该版本。

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
./scripts/verify_evidence.sh
```

Linux 主机具备 rootless user namespace、`/etc/subuid`/`/etc/subgid` 映射和 `ip`、`nft`、`flock`、`setpriv`、`jq` 时，可额外运行真实 TUN 隔离门控：

```bash
./scripts/run_vpn_systemd_lab.sh
./scripts/run_vpn_network_lab.sh
./scripts/run_vpn_tun_lab.sh
```

第一条命令使用真实 user systemd manager 和临时 unit 验证 READY、失败回滚与 `ExecStopPost` 顺序，不修改网络；后两条只在一次性 user+mount+network namespace 中修改网络。

普通本地双路径功能实验：

```bash
cargo run --bin flowweave-lab
```

构建最小代理：

```bash
cargo build --release --bin flowweave-proxy
```

运行默认 60 秒本地 TLS/MPQUIC soak，并输出一份 JSON 健康报告：

```bash
cargo run --release --bin flowweave-proxy-soak
```

检查已经保存的代理 JSONL（单个服务角色示例）：

```bash
cargo run --release --bin flowweave-proxy-observe -- \
  verify proxy.jsonl --require-role client
```

## 安全边界

- 产品入口使用标准 TLS 1.3、独立 CA 和严格 `server_name` 校验，没有跳过证书验证的产品开关。
- 服务端只连接配置中的唯一 `allowed_target`，客户端只监听 loopback；它不是开放代理、SOCKS5、TUN 或任意 UDP 转发器。
- 代理运行事件使用稳定的 `flowweave.runtime.v1` JSONL；原子指标快照可从日志和 `ProxyRuntime::metrics_snapshot()` 读取，事件不记录令牌、私钥或应用载荷。
- 服务端可在重叠期接受两个文件令牌，客户端和服务端通过 SIGHUP 原子重载；失败保留旧状态，撤销只影响新流。
- SIGTERM 和 Ctrl-C 会先停止新接入，再给现有流最多 10 秒完成传输；超过截止时间才强制终止残余任务。
- `scripts/run_netem_lab.sh` 只允许在一次性隔离网络命名空间中运行；不要绕过它直接对真实网卡执行实验命令。
- `scripts/run_vpn_tun_lab.sh` 只在一次性 user+mount+network namespace 中运行：先验证 root、未封闭提权、接口未启用、MTU 不一致和接口不存在都会失败，再创建彼此隔离的 client/server/internet 网络空间、专项阶段的 NAT router、outer/出口 veth 与两端真实 TUN，以无 capability、`NoNewPrivileges` 的 UID 1000 运行 Endpoint 与产品进程；门控除既有启动取消、双栈大包、forwarding/NAT、身份恢复、完整重连、离线停止和清理矩阵外，还真实删除/恢复第二条源路由、切换固定 SNAT 端口，并机器核对同 stable ID/generation、旧/新 PathId、显式源地址和 nft 计数。主网络空间不创建接口、路由、nft table 或修改 sysctl。
- `scripts/run_vpn_network_lab.sh` 只在一次性 user+mount+network namespace 中运行 `flowweave-vpn-net`：验证 root-owned/group-readable 配置、版本状态、并发锁、幂等 prepare/cleanup、客户端 policy route 与服务端 forwarding/NAT 激活/撤销、中途回滚、崩溃恢复、route/rule/nft 表达式漂移、sysctl 管理与恢复、同名/alias/既有 nft table 归属保护和活动数据 fd 拒绝清理；主网络空间不运行 helper。
- `scripts/run_vpn_systemd_lab.sh` 使用真实 user systemd manager 和自动清理的临时 unit，覆盖正常停止、prepare 失败、READY 前立即失败、READY 前启动超时、activate 失败、运行中异常退出，以及实际 `flowweave-vpn reload-server` 的成功/失败；它动态验证 `prepare → READY → activate`、超时终止、同步 reload、`deactivate → cleanup` 与 `NoNewPrivileges` 分界，不执行任何网络命令。
- 私钥、令牌、真实证书、Hysteria 下载二进制和 Cargo 构建目录不得提交到仓库。

## 仓库地图

- `src/proxy.rs`、`src/bin/flowweave-proxy.rs`：固定目标代理；
- `src/vpn.rs`：由 DATAGRAM 运行器和包桥接接入真实 TUN 的 `FWI1` IP 包解析、分片与有界重组核心；
- `src/vpn_active_session.rs`：单活动代际、成功后替换、在线撤销、关闭码和身份重载协调；
- `src/vpn_control.rs`：VPN 专用 `FWC1` 控制消息、版本协商、能力和虚拟地址确认；
- `src/vpn_client_data_path.rs`：客户端用可复用工厂从 `FWC1 ACCEPT` 和本地 ACL 构造正式数据句柄，跨重连共享速率、内存预算和指标，不伪造服务端身份记录；
- `src/vpn_datagram_runtime.rs`：真实 NoQ DATAGRAM 双向收发、包/字节双重有界队列、周期过期、取消安全和稳定运行指标；
- `src/vpn_data_path.rs`：逐身份无全局逐包锁的数据句柄，闭合外层 DATAGRAM 计费、双向重组、原子全局账本和完整 IP 策略；
- `src/vpn_data_policy.rs`：上行源地址防伪、双向目标 ACL 和下行虚拟地址归属检查；
- `src/vpn_identity.rs`：证书指纹身份、双指纹轮换、虚拟地址、目标 CIDR 和每身份资源合同；
- `src/vpn_identity_config.rs`：严格 JSON 身份文件、只读 group 部署边界和失败保留旧状态的原子注册表替换；
- `src/vpn_packet_bridge.rs`：Linux 预附着包文件描述符与 DATAGRAM 运行器之间的双向桥接；客户端进程级 packet pump 在全部连接代际之外持续独占 TUN reader，在线时只向当前代际转交，离线时不缓存、不重放并累计包/字节丢弃；本层不创建 TUN 或修改路由；
- `src/vpn_product_config.rs`：版本化 server/client JSON、受保护文件权限、路径、接口、预期客户端/服务端隧道地址对、ACL 和资源上限的严格校验；允许 root-owned、仅 group 可读的 `0640` 部署，但仍拒绝 group 写和任何 other 权限；
- `src/vpn_network.rs`、`src/vpn_network/client_routes.rs`、`src/vpn_network/server_forwarding.rs`、`src/bin/flowweave-vpn-net.rs`：从同一 product config/identity 真值派生双栈 TUN、client `allowed_destinations` 和启用身份的精确服务端转发地址集合；以 root-only 版本状态、计划指纹、随机 alias/table/priority/metric/protocol/ownership comment、独占锁和原子 journal 完成幂等 prepare/cleanup、READY 后 activate/deactivate、崩溃恢复及归属保护。产品 UID 高优先级查 main，普通流量才查询独立 TUN 表；服务端专属 `inet flowweave_vpn` table 只允许受控 TUN 转发，并按显式地址族选择 masquerade；
- `src/vpn_network_event.rs`：非特权 `NETLINK_ROUTE` link/address/route 恢复提示、严格有界消息解析、在线事件排空、离线退避提前唤醒和监听失败后的定时器降级；
- `src/vpn_product_endpoint.rs`：服务端显式 UDP 监听与单活动连接循环、客户端 DNS/严格名称/有限地址尝试/显式源 IP 路径建立、握手截止、忙时拒绝和有界 Endpoint 清理；运行对象另提供脱敏 stable ID/session/path 快照和同连接 socket rebind，按配置槽位先验证新路径与源 IP、再等待旧路径 `Abandoned`，不调用会清空显式源地址的通用 network-change 路径；
- `src/vpn_product_process.rs`、`src/bin/flowweave-vpn.rs`：非特权 server/client 产品生命周期、严格 READY 时序、systemd notify 和稳定 stdout 状态行。客户端在首次 READY 前及之后都只对明确定义的网络/远端可恢复错误做随机指数退避并重建完整 Endpoint；在线 link/address 恢复则在同一连接内原位替换显式路径，并用 250 ms settle 与 5 秒成功波次合并避免 route/DAD 事件重复 rebind；客户端 TLS 凭据 reload 可在在线、建连或离线退避阶段提交，变化时保持同一 PID/TUN pump 并建立新 mTLS/FWC1 代际；配置、协议、TUN/pump、本地资源不变量或 worker 故障快速失败，不执行 privileged 网络操作；
- 服务端产品进程在 owner-only RuntimeDirectory 中提供固定有界身份 reload socket；`flowweave-vpn reload-server` 同步返回候选提交结果，坏 JSON、全局预算超限、地址拓扑或 forwarding 集合漂移均保留旧状态并失败，指纹轮换/撤销和兼容策略变化原子生效；
- 客户端在独立 owner-only RuntimeDirectory 中提供凭据 reload socket；`flowweave-vpn reload-client` 只接受配置完全不变且证书、PKCS#8 私钥和服务端 CA 全部可装配的候选，不匹配或权限错误保留旧健康会话，内容未变幂等成功，内容变化则同步提交给后续连接并立即启动受控代际切换；
- `src/vpn_product_runtime.rs`：在解析 DNS、打开 UDP 或附着 TUN 前完成凭据、身份和传输预检，并在调用方提供已建立连接与已附着包设备后，组装单客户端 `FWC1`、活动代际、协商 DATAGRAM 和双向包桥接；地址漂移、重复 TUN 读者和启动失败均会关闭并回收，产品连接另有 10 秒总空闲上限用于所有路径失联收敛；
- `src/vpn_tun.rs`：Linux 非特权数据进程只附着已存在、已启用且 MTU 精确匹配的 `IFF_TUN | IFF_NO_PI`，拒绝 root、可重新启用的 `CAP_NET_ADMIN` 和未设置 `NoNewPrivileges` 的进程；
- `src/vpn_quota.rs`：跨代际共享 token bucket、逐身份速率隔离和全局重组字节/未完成包原子上限；
- `src/vpn_session.rs`：真实 mTLS QUIC 上的 `FWC1` 控制握手、强制 MPQUIC/DATAGRAM 和稳定拒绝原因；
- `src/vpn_tls.rs`：TLS 1.3 双向证书、独立 CA、VPN ALPN 和叶证书指纹提取；
- `src/proxy_observe.rs`、`src/proxy_soak.rs`：JSONL 健康门控和本地持续负载运行器；
- `src/mptcp.rs`、`src/bin/flowweave-mptcp-comparison.rs`、`scripts/run_mptcp_comparison.sh`：真实 Linux `IPPROTO_MPTCP`、严格 TLS 1.3、`MPTCP_INFO`、双地址 nft 计费和不可覆盖 A/B 矩阵；
- `PROXY_ROTATION.md`：共享令牌无重启轮换、失败和撤销语义；
- `src/lib.rs`、`src/realtime*.rs`、`src/hysteria.rs`：实验与测量逻辑；
- `tests/network_lab.rs`：需要隔离网络空间的正式矩阵和诊断；
- `tests/vpn_tun_lab.rs` 与 `scripts/run_vpn_tun_lab.sh`：TUN 权限反例，以及隔离 client/server/internet 与临时 NAT router 中真实 TUN + Endpoint/产品进程的 UDP、TCP、双栈无特权 ICMP、精确/超 MTU、连续代际、READY、IPv4 NAT、IPv6 无 NAT、同连接双 outer-path/NAT rebinding、身份恢复、完整重连、netlink 提前唤醒、服务端重启、离线停止与 `SIGKILL` 清理门控；
- `tests/vpn_network_lab.rs`：只由专用脚本运行的“无特权数据进程持有 TUN 时 privileged cleanup 必须失败”门控；
- `tests/vpn_systemd_lab.rs`、`tests/fixtures/flowweave-vpn-systemd-lab.service.in` 与 `scripts/run_vpn_systemd_lab.sh`：真实 user-systemd 生命周期及同步 reload 门控；正式 client/server unit 的 root helper 边界、主进程权限、reload socket 和清理顺序另由静态合同测试锁定；
- `benchmark-results/`：不可覆盖的原始 CSV 与 SHA-256 清单；
- `third_party/noq*`：固定 NoQ 1.0.1 源码及逐文件记录的 FlowWeave 补丁；
- `deploy/`：固定目标代理单元，以及 VPN 的 Type=notify client/server 试点单元、严格配置样例和部署/恢复说明。

## 当前限制

实验室结果不等于生产 SLA。仓库已有默认 60 秒的单机真实 TLS/MPQUIC soak、可配置 JSONL 阈值检查、共享令牌无重启轮换，以及带限速、应用字节预算和周期检查点的公网 workload/echo 部署入口；现已完成同一物理出口下“两张接口 + 两条源路由 + 两个 NAT”的 30 分钟真实公网双路径 soak。Linux MPTCP 对照证明 FlowWeave 的黑洞完整恢复更强，但持续单流聚合没有全面领先 MPTCP；该结论只覆盖 Linux default scheduler + Cubic，不覆盖 OpenMPTCProuter、其他 path manager 或真实双运营商。VPN 已完成逐客户端身份、活动代际、在线撤销、按身份分片的数据热路径、外层 `FWI1` 准入、真实重组、原子全局账本和双向 ACL；客户端会精确比对 `FWC1 ACCEPT` 中的四个隧道地址，并让协商后的最大 IP 包和 DATAGRAM 长度实际约束双方数据面。独立 `flowweave-vpn server|client` 已把严格配置、TUN 附着、Endpoint、READY、systemd notify、信号收敛，以及 READY 前和 READY 后的选择性内部重试组成非特权产品生命周期；隔离内核门控还证明同一已连接 QUIC 可在真实 SNAT 映射变化时逐条替换两条显式源路径，stable ID、`FWC1` generation 和客户端 PID 均保持，旧 PathId 明确进入 `Abandoned`，双栈流量不中断为整连接重连。另一组代际门控让同一 PID 在身份撤销/恢复、单外层接口 down/up 和服务端进程重启后重新完成严格 TLS/MPQUIC/FWC1，离线 TUN 包不缓存且可计数，离线 SIGTERM 仍有界零退出；同一门控现又用第二张真实 CA 签发客户端证书证明在线凭据 reload 会在原 PID/TUN pump 内建立新代际，不匹配候选不扰动旧会话，旧指纹撤销后新建旧证书会话明确失败，离线 reload 新证书可恢复。上述实验都没有修改主网络空间，也尚未在真实宿主执行特权安装验收。DNS 接管、多客户端长期压力、跨版本升级和外部告警投递仍未完成，因此当前 VPN 仍只适合带恢复通道的受控试点。两个独立运营商出口只保留为运营商级故障隔离声明边界；多小时/多天证据仍待完成。C 组编码器目前也是实验入口，不是通用实时媒体协议。

## Codex 与 GPT-5.6 的使用方式

FlowWeave 采用“人工确定目标与验收边界，AI 协助实现、分析和复核”的开发方式。Codex 和 GPT-5.6 没有替代真实测试，也没有被用来生成或保存生产密钥、令牌及用户流量。

### Codex

Codex 作为仓库级工程代理参与了以下工作：

- 阅读现有 Rust 代码、设计文档和失败时间线，把任务拆分为可验证的小改动；
- 协助实现与重构 MPQUIC 恢复、QUIC DATAGRAM、VPN 控制面与数据面、身份配额、TUN 桥接和进程生命周期代码；
- 编写或补充单元测试、集成测试、网络命名空间门控、systemd 生命周期测试及基准脚本；
- 运行 `cargo fmt`、`cargo test`、`cargo clippy` 和证据校验命令，根据真实输出继续修正问题；
- 维护 README、实验合同、部署说明、第三方源码记录和公开发布材料，并在公开仓库前辅助检查秘密与许可证边界。

### GPT-5.6

GPT-5.6 主要作为推理与评审模型使用：

- 帮助把项目目标固定为换网连续性、双路聚合和高丢包实时传输三组可测合同；
- 分析实验时间线和反例，定位 ACK 反馈路径、PTO、路径空闲、重传队列及流控恢复之间的因果关系；
- 评审 `FWC1`/`FWI1` 协议、mTLS 身份、地址防伪、资源上限、权限隔离和失败回滚设计；
- 比较 FlowWeave、Hysteria 2.9.3 与 Linux MPTCP 的原始结果，协助区分已证明结论、无决定性差异和不能外推的范围；
- 检查项目叙述是否与保存的 CSV、JSONL、SHA-256 清单及测试结果一致，避免依据单次最好成绩作结论。

### 人工验证与责任边界

项目负责人决定最终需求、风险边界、基准门槛、开源许可和公开操作。AI 生成或建议的代码必须经过差异审阅，并由确定性测试或真实隔离网络实验验证后才作为项目证据；没有通过正式门槛的候选会被保留为失败证据或从产品路径删除。所有性能数字均来自仓库保存的实际运行结果，而不是由模型估算或编造。

## 许可证

Copyright 2026 senran-N。

FlowWeave 以 [Apache License 2.0](LICENSE) 开源。`third_party/` 中的第三方源码保留各自的许可证，来源、版本和修改说明见 [third_party/README.md](third_party/README.md)。
