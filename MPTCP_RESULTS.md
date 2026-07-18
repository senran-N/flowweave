# FlowWeave 与 Linux MPTCP 正式对照结果

## 结论

2026-07-14 按 [MPTCP_COMPARISON.md](MPTCP_COMPARISON.md) 的预注册合同完成 Linux MPTCP A/B 对照。运行身份为 Linux `7.0.11-arch1-1`、iproute2 `7.0.0`、内核 path manager、default scheduler、Cubic；所有连接都由真实 `IPPROTO_MPTCP` socket 建立，在其上使用严格证书名称校验的 TLS 1.3。四份 smoke/formal CSV 的基础设施门槛全部通过，没有 TCP fallback，双路项在测量前和测量后都保持两个子流。

- A：FlowWeave 按原业务连接连续性分支胜出。MPTCP 正向 `0/5`、反向 `1/5` 完整闭环；唯一成功场恢复间隔为 `2199.883 ms`。FlowWeave v6.9 正反向各 `10/10` 完整闭环且逐场严格 `<1 s`。
- B：无决定性差异。MPTCP 平衡/异构双路中位为 `29.089/27.561 Mbit/s`，FlowWeave 为 `26.580/27.509 Mbit/s`。MPTCP 在平衡场景高约 `9.4%`，异构场景高约 `0.2%`，没有任何一方在两个场景都达到预注册的 `15%` 优势。

因此新证据把项目的相对优势收窄得更准确：FlowWeave 当前最明确的优势是黑洞故障后的有界完整会话恢复；持续单流容量聚合并不全面领先标准 Linux MPTCP。

## A：黑洞故障后的完整闭环

题目保持 30 秒持续 TLS 字节流，第 10 秒把 20 ms / 0.1% / 20 Mbit/s 主路改为 100% 丢包，80 ms / 1% / 20 Mbit/s 备用路保持可用。正反两个方向各运行五固定种子。

| 方向 | MPTCP 完整闭环 | 有效恢复间隔 | FlowWeave v6.9 |
|---|---:|---:|---:|
| 客户端到服务端 | `0/5` | 无完整样本 | `10/10`，中位 `576.98 ms` |
| 服务端到客户端 | `1/5` | `2199.883 ms` | `10/10`，中位 `615.11 ms` |

十场 MPTCP 都在故障后从线路二交付了新的、序号和内容校验正确的应用记录，说明内核确实建立并使用了第二子流，并非接线或 path-manager 失败；但只有一场在合同截止前完成全部记录和最终反向响应。正式判定要求“数据恢复 + 全部内容闭合 + 最终响应闭合”，因此不能把部分继续传输写成原业务连接连续成功。

所有正式行的 `infrastructure_pass=true`；故障前后 `subflows_total=2`，线路二故障后 IPv4 计数非零。

## B：持续单流聚合

每项使用同一条 TLS/MPTCP 连接、16 KiB 确定性记录、2 秒预热和 20 秒接收端计时窗口。每轮依次轮换仅线路一、仅线路二和 default scheduler 双路，两个场景各五固定种子。

### 平衡 15+15 Mbit/s

- MPTCP 双路五轮：`28.120 / 29.354 / 29.482 / 28.669 / 29.089 Mbit/s`；中位 `29.089 Mbit/s`。
- 单路中位：线路一 `14.653 Mbit/s`，线路二 `14.627 Mbit/s`。
- 双路逐轮 `5/5` 高于当轮最佳单路至少 15%。
- 两路 IPv4 字节份额保持在约 `48.1%～50.0% / 50.0%～51.9%`。
- FlowWeave 冻结中位 `26.580 Mbit/s`，约为 MPTCP 的 `91.4%`；MPTCP 高约 `9.4%`，未达到 15% 胜出线。

### 异构 8+25 Mbit/s

- MPTCP 双路五轮：`27.169 / 28.557 / 26.769 / 27.989 / 27.561 Mbit/s`；中位 `27.561 Mbit/s`。
- 单路中位：线路一 `7.890 Mbit/s`，线路二 `23.814 Mbit/s`。
- 双路逐轮 `4/5` 高于当轮最佳单路至少 15%，通过 MPTCP 自身聚合门槛。
- 慢路/快路 IPv4 字节份额约为 `26.5%～28.8% / 71.2%～73.5%`，与 8:25 容量比例方向一致。
- FlowWeave 冻结中位 `27.509 Mbit/s`，约为 MPTCP 的 `99.8%`，两者基本持平。

CSV 同时记录 nft IPv4 字节和 MPTCP_INFO 计数，但 TCP/MPTCP 可变选项与 NoQ UDP payload 的统计层级不同；本轮不据此宣布跨协议额外线速胜者。需要精确比较时应另行预注册统一 pcap/L3 口径。

## 证据文件

- `benchmark-results/2026-07-14-linux-mptcp-a-smoke-v1.csv`：2 个数据行，SHA-256 `eecf7215331fb2a60c828b9523a3d01a26a5b9922aabcb8e3cacd7f7ca647ed5`。
- `benchmark-results/2026-07-14-linux-mptcp-a-formal-10-v1.csv`：10 个数据行，SHA-256 `525064bc594d077bf85e962b4fe39c255b8994f6c10e5412cc70930e343fb6f4`。
- `benchmark-results/2026-07-14-linux-mptcp-b-smoke-v1.csv`：6 个数据行，SHA-256 `be4f51dea337b85d209fcc043150e3eb91ce4efbd03de54f9b7e3f872fd2b5cd`。
- `benchmark-results/2026-07-14-linux-mptcp-b-formal-30-v1.csv`：30 个数据行，SHA-256 `ab288f7e0b9d0e0f0d49d3264b5ba533db7a8dd92cc6c9f4ce3041770aebfdb2`。
- 预注册合同最终 SHA-256：`964918fc125cc4bb0c43b563b02a2284fcaa08ea757575960bd0131407af46e2`。

每个 CSV 都先写表头，再逐场重写当前完整观测集合；已有文件由入口拒绝覆盖。接线诊断不写正式结果文件。

## 适用边界

- 这是 Linux 内核 MPTCP default scheduler + Cubic 的结果，不代表所有 MPTCP 调度器、userspace path manager、mptcpd 或 OpenMPTCProuter 产品配置。
- 两端位于同一隔离 network namespace，通过不同 loopback 源地址进入两条独立 netem 队列；它与已有 FlowWeave/Hysteria 正式题目保持一致，但不替代真实双运营商出口。
- MPTCP 上层增加了标准 TLS 1.3，以避免拿裸明文 MPTCP 和 FlowWeave 的 TLS/MPQUIC 直接比较。
- 本轮不做 C：MPTCP 没有 QUIC DATAGRAM 对等原语，实时媒体必须另锁统一的 UDP/RTP/FEC 产品层合同。
