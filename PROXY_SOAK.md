# FlowWeave 代理 M1.3 soak 与健康门控合同

本文件在实现前固定 M1.3 的本地可复现验收边界。它只验证代理在单机真实 TLS/MPQUIC、持续建流、数据完整性、结构化事件和有界退出下能否稳定运行；回环地址不代表真实 Wi-Fi、蜂窝、公网 NAT、运营商路由或生产 SLA。

## 1. JSONL 健康门控

`flowweave-proxy-observe` 读取 `flowweave.runtime.v1` JSONL，并输出 `flowweave.observe.v1` 单行 JSON。严格门控默认要求：

- 每个非空输入行都是合法 JSON，schema、时间戳、级别、角色和事件字段类型正确；
- 单行最多 64 KiB；检查器在读取阶段丢弃超限行并报告违反项，避免异常日志无界占用内存；
- 被要求的 client/server 角色都出现 `runtime_started`、最终 `metrics_snapshot` 和 `shutdown_complete`；
- `connection_started`/`connection_finished`、`stream_started`/`stream_finished` 数量闭合；
- 最终活动连接和活动流均为零；
- `runtime_failed`、`shutdown_forced`、超时、上游错误和配额拒绝不超过命令行阈值；
- 默认阈值均为零，放宽必须显式写在执行命令和保存的报告中。

检查器只汇总固定字段和稳定原因码，不回显未知字段，因此不会把未来误写入事件的应用内容复制到健康报告。

## 2. 本地 soak

`flowweave-proxy-soak` 在临时目录生成测试 CA/证书/令牌，启动真实固定目标服务端和客户端，以多条并发本地 TCP 流持续传输确定性载荷，并逐流校验完整回显；最终输出 `flowweave.proxy-soak.v1` 单行 JSON。默认合同为：

- 60 秒；
- 4 个并发工作器；
- 每条流 64 KiB；
- 流间隔 10 ms；
- loopback 上显式建立两条 MPQUIC 路径；
- 停止工作负载后先优雅关闭客户端，再关闭服务端；
- 使用内存中的增量 JSONL 汇总器执行“client + server、零容忍”健康门控。

短时自动测试只验证运行器接线，不能替代默认 60 秒合同。正式本地证据必须保存命令、最终 JSON 报告、提交 SHA、内核和 Rust 版本。长于 60 秒的试验可以提高置信度，但不能降低任何健康条件。

## 3. 通过与失败

一次 soak 只有同时满足以下条件才通过：

- 至少完成一条流，工作负载错误为零，发送与回显字节完全一致；
- client/server 最终活动连接和流归零，且没有强制退出；
- JSONL 严格门控没有违反项；
- 运行器自身、echo 上游和所有工作任务都已回收。

任何失败都保留为失败，不通过扩大配额、关闭 TLS 校验、缩短载荷或忽略事件补救。先修复确定性本地失败，再进入真实双接口部署。

## 4. 真实公网阶段

公网阶段必须在两台受控主机和至少两个真实客户端出口上复用相同事件 schema 与健康门控，并额外记录接口、路由、NAT、路径建立/放弃、持续时间和外部可达性。未执行该阶段前，项目继续明确写作“尚未证明真实公网双接口长期 soak”。
