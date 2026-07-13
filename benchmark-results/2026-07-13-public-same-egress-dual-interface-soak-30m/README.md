# 30 分钟公网同出口双接口 soak

## 结论

提交 `af2dc04` 在一个受控公网服务端和一个临时双接口客户端环境之间完成了 30 分钟 TLS/MPQUIC soak。客户端两张接口分别使用独立源策略路由和两个 Docker NAT，但最终共享同一个物理公网出口。服务端确认产品路径 1、2 均建立；workload、客户端严格健康门控和服务端严格健康门控全部通过。

这项证据证明公网双接口、双源路由、双 NAT、TLS、令牌授权、固定 echo 目标、持续并发建流、传输重试、应用字节完整性和优雅退出能够共同稳定运行 30 分钟。它不证明两个独立运营商出口，也不替代真实 Wi-Fi + 蜂窝故障或跨运营商长期 soak。

## Workload

- 配置时限：1,800 秒；
- 实际耗时：`1,800.205` 秒；
- worker：4；
- 单流载荷：16,384 字节；
- 全局应用上传上限：512,000 bit/s；
- 双向应用字节预算：230,400,000 字节；
- 停止原因：`application_byte_budget_exhausted`；
- 启动/完成流：`7,031 / 7,031`；
- 失败/超时流：`0 / 0`；
- 上传/回显：`115,195,904 / 115,195,904` 字节；
- 已预留双向应用字节：230,391,808；
- 剩余不可容纳完整流的预算：8,192 字节；
- 平均应用上传速率：511,923 bit/s；
- 最终 `stage_pass=true`。

## 路径与传输

服务端在同一连接上记录：

```text
path_id=1 change=established
path_id=2 change=established
path_id=0 change=abandoned reason=remote_abandoned
path_id=0 change=discarded lost_bytes=0 lost_packets=0
```

产品路径在运行中出现 `available ↔ backup` 状态切换，但没有产品路径被 abandoned 或 discarded，应用 workload 没有失败。客户端连接汇总 UDP 为发送 122,607,669 字节、接收 129,924,209 字节；相对 230,391,808 字节双向应用数据，传输总量高约 9.61%。客户端记录 `lost_bytes=235,618`，服务端记录 `lost_bytes=11,703,197`；QUIC 完成重试后全部 7,031 条应用流仍逐字节闭合，因此不能把这些传输丢失字节误写成应用数据丢失。

## 严格健康门控

客户端：

- 14,255 条合法 `flowweave.runtime.v1` 事件；
- 1 条连接、7,031 条流全部闭合；
- 185 个指标快照、3 个路径事件；
- 拒绝、超时、上游错误、任务失败、强制退出均为零；
- 最终活动连接/流为零；
- `healthy=true`，0 违反项。

服务端：

- 14,277 条合法 `flowweave.runtime.v1` 事件；
- 1 条连接、7,031 条流全部闭合；
- 197 个指标快照、13 个路径事件；
- 拒绝、超时、上游错误、任务失败、强制退出均为零；
- 最终活动连接/流为零；
- `healthy=true`，0 违反项。

## 文件

- `workload.jsonl`：每分钟检查点、预算停止事件和最终 workload 报告；
- `client-runtime.jsonl` / `server-runtime.jsonl`：两端结构化运行事件；
- `client-health.json` / `server-health.json`：严格健康门控结果；
- `client-network.txt`：两张接口、源规则和到测试服务端的两条路由；
- `binary-sha256.txt`、`commit.txt`、Rust/内核版本：构建与环境身份；
- `SHA256SUMS`：本目录证据文件校验值。

VPN 在本轮全程关闭。测试结束后客户端优雅退出码为 0，服务端和 echo 服务已停止并取消开机自启，临时容器、Docker 网络、源策略路由和临时客户端配置均已删除。
