# 第三方源码说明

## NoQ Proto

- 项目：https://github.com/n0-computer/noq
- 包名和版本：noq-proto 1.0.1
- crates.io 包校验值：aa6c890013591e709a3e45dd53501351b7e27e7ff3c7e9fc3dce43e300e7e9d3
- 上游 Git 提交：340e9c7da0d60eda6f5c7ffa7a36d20ed8d793fd
- 许可证：MIT OR Apache-2.0

third_party/noq-proto 最初来自本机 Cargo 已校验的官方发布包。

没有提交 Cargo 缓存标记 .cargo-ok 和自动生成的 .cargo_vcs_info.json；后者记录的上游提交号已写在上面。除此之外，首次引入的 68 个文件与官方发布包逐文件 SHA-256 一致。

## 修改纪律

- 官方源码的原样引入单独提交。
- 后续只允许为 FlowWeave 当前可测目标做最小修改。
- 每个偏离上游的文件和原因都要追加记录在这里。
- 上游升级时先恢复官方版本、运行全部测试，再重新评估补丁，不能把旧补丁盲目叠上去。

## 当前偏离上游

以下文件组成 FlowWeave 当前可撤销、可审计的测量与 ACK-ECF 候选补丁，其他上游文件仍保持原样：

- `src/connection/stats.rs`：分别统计每条路径首次发送和重传的 STREAM 数据字节。
- `src/connection/send_buffer.rs`：让统计逻辑判断下一段数据是否来自重传队列。
- `src/connection/streams/state.rs`：在实际编码 STREAM 帧时累计首次数据和重传数据。
- `src/config/transport.rs`、`src/config/mod.rs`、`src/lib.rs`：增加并公开唯一非默认策略 `AckEcf`；默认值仍是 NoQ 官方行为。
- `src/connection/scheduler.rs`：实现 ACK 交付率窗口、指数平滑、完成时间公式、探测上限和等待判断；数学部分可独立测试。
- `src/connection/paths.rs`：每个路径 4-tuple 保存自己的应用交付率状态；迁移时重置，避免旧线路样本污染新线路。
- `src/connection/spaces.rs`、`src/connection/packet_builder.rs`：只标记真正含 STREAM 或应用 Datagram 的已发送包，使纯控制包不能训练调度器。
- `src/connection/mod.rs`：聚合每个 ACK 事件里的应用字节；先按官方顺序处理控制流量，再仅对应用数据执行 ACK-ECF；默认、单路径和 Available/Backup 语义不变。
- `src/tests/multipath.rs`：验证测量统计、默认行为、真实 ACK 学习、探测、预计完成时间、等待/回退、控制包隔离、Backup 和单路径语义。

轮询、最低 RTT、预计最早送达和交付速率加权都已经按基准结果完整删除，不保留失败算法开关。ACK-ECF 没有修改 TLS、路径验证、拥塞控制或 pacing 算法；它尚未通过真实短筛，失败时必须像前四个候选一样完整删除。2026-07-11 接入后已实际运行 NoQ 396 项单元测试、3 项文档测试和 Clippy，全部通过且零警告。
