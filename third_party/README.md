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

以下 4 个文件为 FlowWeave 的可审计测量补丁，其他上游文件仍保持原样：

- `src/connection/stats.rs`：分别统计每条路径首次发送和重传的 STREAM 数据字节。
- `src/connection/send_buffer.rs`：让统计逻辑判断下一段数据是否来自重传队列。
- `src/connection/streams/state.rs`：在实际编码 STREAM 帧时累计首次数据和重传数据。
- `src/tests/multipath.rs`：验证首次数据与重传数据会被分开统计。

轮询、最低 RTT、预计最早送达和交付速率加权都已经按基准结果完整删除；NoQ 当前恢复官方调度行为，不保留失败算法开关。测量补丁没有修改 TLS、线路验证、拥塞控制、pacing、发包顺序或 Backup/Available 的协议语义。2026-07-11 清场后已实际运行 NoQ 380 项单元测试、3 项文档测试和 Clippy，全部通过且零警告。
