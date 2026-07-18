# FlowWeave 与 Linux MPTCP 公平对照合同

## 为什么先测 MPTCP

MPTCP 是 FlowWeave 在 A（原连接故障切换）和 B（双路聚合）上的最接近标准化对手。Hysteria 2.9.3 是强单路径 QUIC 代理基线，但不原生同时使用两条路径；因此已有 Hysteria 结果不能替代真正的多路径协议对照。

本文件在首次 MPTCP 结果文件产生前固定实验题目、运行身份、结果文件名和结论规则。失败结果不得删除或用相同文件名重跑。当前工作区未创建独立 Git 预注册提交，因此本文件只构成本轮本地预注册边界；若以后更换内核、iproute2、调度器、TLS 包装或题目，必须使用新合同和新结果文件。

## 固定实现与安全边界

- MPTCP：Linux 内核 RFC 8684 实现；本轮固定运行身份为 `Linux 7.0.11-arch1-1`。
- 路径管理：内核 path manager；`subflows=2`、`add_addr_accepted=2`。
- 调度器：`net.mptcp.scheduler=default`，不得因结果不好切换调度器。
- 拥塞控制：`net.ipv4.tcp_congestion_control=cubic`。
- iproute2：本轮固定为 `7.0.0`；使用 `ip mptcp` 配置第二本地地址。
- 应用连接必须使用 `socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)`，并用 `MPTCP_INFO` 证明收到远端 key、未回退普通 TCP。
- MPTCP 之上使用标准 TLS 1.3、临时独立 CA/叶证书和严格 `localhost` 名称校验；禁止裸明文 MPTCP 与 FlowWeave 的 TLS/MPQUIC 数字直接比较。
- TLS 0-RTT 关闭；A/B 都使用同一条 TLS 连接和同一条 MPTCP meta socket。
- 不测试抗审查、流量伪装或开放代理能力。

## 固定拓扑

实验只能通过专用的 `scripts/run_mptcp_comparison.sh` 进入一次性 rootless user+network namespace；该脚本复用现有网络实验的 loopback `prio + netem + tbf` 题目，主网络空间不得修改 qdisc、MPTCP endpoint、sysctl 或 nftables。

- MPTCP 初始子流：客户端源地址 `127.0.0.3`，服务端 `127.0.0.1`；映射到线路一 qdisc。
- 第二子流：客户端源地址 `127.0.0.4`，仍连接同一服务端地址和端口；映射到线路二 qdisc。
- `127.0.0.4` 只配置 `subflow` endpoint，不配置 backup；两条子流都可承载普通数据。
- 每项开始前清空 endpoint、重新设置 limits，并重置两条 netem 队列及固定随机种子。
- nftables 只在隔离 namespace 内按客户端源/目标地址及服务端 TCP 端口计数，不改写、丢弃或重定向数据。

该映射继续使用 FlowWeave/Hysteria 正式实验已有的 loopback `prio + netem + tbf` 题目，不建立一个只对 MPTCP 有利的新物理拓扑。

## A：原 MPTCP 连接故障切换

题目与 `BENCHMARK.md` A 组保持一致：

- 线路一：20 ms、0.1% 丢包、20 Mbit/s；
- 线路二：80 ms、1% 丢包、20 Mbit/s；
- 同一条 TLS/MPTCP 连接持续传输 30 秒；
- 第 10 秒把线路一改为 100% 丢包，不主动关闭子流；
- 正向（客户端到服务端）和反向（服务端到客户端）分别运行；
- 固定种子为 `1101/2201` 至 `1105/2205`；
- 每条应用记录为 16 KiB，包含连续序号、确定性内容和摘要；接收端必须返回最终记录数和字节数，不能只凭 socket 仍存活判定成功。

接线 smoke 每个方向只运行第一组种子。只有以下基础设施条件全部成立，才允许运行正式五种子矩阵：

- TLS 版本精确为 1.3，证书名称校验开启；
- `MPTCP_INFO` 表明没有 TCP fallback，并已收到远端 key；
- 故障注入前实际存在至少两个子流；
- 两个地址的 TCP 计数器均观察到子流流量；
- 故障前已有完整应用记录到达；
- 序号、摘要、内容和最终反向响应没有基础设施错误。

正式结果不因 MPTCP 性能较差而删除或重跑。连续性成功必须同时满足：原 meta socket 未替换、故障后有数据到达、全部记录正确、最终响应闭合。

与已冻结 FlowWeave v6.9 结果的结论规则：

- FlowWeave 正向/反向基准分别为 `10/10`，恢复间隔中位 `576.98/615.11 ms`。
- 若 MPTCP 任一方向不能达到 `5/5` 连续性，FlowWeave 在本合同 A 组胜出。
- 若双方两个方向都全胜，只有 FlowWeave 两个方向的恢复间隔中位都至少低 30%，才判 FlowWeave 胜；反向条件同理才判 MPTCP 胜。
- 其他情况记为无决定性差异，不根据单次最好成绩改规则。

预注册文件：

```text
benchmark-results/2026-07-14-linux-mptcp-a-smoke-v1.csv
benchmark-results/2026-07-14-linux-mptcp-a-formal-10-v1.csv
```

## B：持续单流双路聚合

与 FlowWeave B 正式合同使用相同两种场景：

1. 平衡：15 Mbit/s、20 ms、0.1% + 15 Mbit/s、20 ms、0.1%；
2. 异构：8 Mbit/s、15 ms、0.1% + 25 Mbit/s、50 ms、0.1%。

每轮固定运行三个参赛项：

1. MPTCP 仅线路一：初始地址 `127.0.0.3`，不配置额外 endpoint；
2. MPTCP 仅线路二：初始地址 `127.0.0.4`，不配置额外 endpoint；
3. MPTCP 双路：初始地址 `127.0.0.3`，`127.0.0.4` 配置为额外 subflow。

每项使用同一条持续 TLS/MPTCP 字节流，预热 2 秒；smoke 测量 5 秒，formal 测量 20 秒。接收端按完整 16 KiB 记录完成时刻计入半开测量窗口。参赛顺序按场景和轮次轮换；每项前重置相同 qdisc 和种子。

基础设施门槛：

- TLS 1.3、严格证书验证、MPTCP 未 fallback；
- 单路项恰好一个子流，且只有目标地址承载 TCP；
- 双路项至少两个子流，两个地址都出现 TCP 包；
- writer 在测量起止均存活；
- 所有记录、摘要、最终响应和字节总量闭合；
- 测量窗口不少于合同值。

MPTCP 自身聚合门槛继续使用 FlowWeave B 的绝对规则：每个场景至少 4/5 轮比当轮最佳单路快 15%，并且双路测量窗口中两条地址各承担至少 10% 的总 IPv4 字节。TCP/MPTCP 可变选项使 nft L3 字节不能与 NoQ 的 UDP payload 字节逐项等同，因此本轮记录两者但不据此宣布跨协议线速胜者；任何跨协议额外流量结论必须另做统一 pcap 口径。

与已冻结 FlowWeave 数字的吞吐结论使用对称规则：

- FlowWeave 平衡/异构中位为 `26.580/27.509 Mbit/s`。
- 只有 FlowWeave 在两个场景的中位数都至少高 15%，才判 FlowWeave B 胜。
- 只有 MPTCP 在两个场景的中位数都至少高 15%，才判 MPTCP B 胜。
- 其余结果记为无决定性差异。

预注册文件：

```text
benchmark-results/2026-07-14-linux-mptcp-b-smoke-v1.csv
benchmark-results/2026-07-14-linux-mptcp-b-formal-30-v1.csv
```

## 为什么本轮不做 C

MPTCP 提供可靠有序字节流，没有 QUIC DATAGRAM 对等原语。直接把 FlowWeave v12 的 2-of-3 实时消息编码移植到 MPTCP，会比较另一套上层分帧、丢弃和纠删协议，而不是 MPTCP 本身；把实时消息写进可靠 MPTCP 流又会把可靠队头阻塞当作不公平弱点。

因此本轮只关闭 A/B 的真正多路径协议缺口。若以后比较实时媒体，应另行预注册统一的 RTP/UDP/FEC 应用合同，并选择支持 UDP 或 IP 隧道的 MPTCP 产品层实现。

## 失败与回退

- smoke 若暴露 socket fallback、子流没有建立、地址走错 qdisc、TLS 未严格校验或计数器不闭合，保留 CSV 并停止 formal。
- 性能或连续性失败属于有效对照结果，不得当作基础设施失败重跑。
- 已存在的结果文件一律拒绝覆盖；修复基础设施必须使用 `v2` 新文件和补充合同。
- 不修改 FlowWeave、Hysteria 的历史 CSV，不用本轮 MPTCP 结果反向调整 A/B 门槛。
