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

以下 8 个文件为 FlowWeave 的最小多路径调度与可审计测量补丁，其他上游文件仍保持原样：

- `src/config/transport.rs`：增加 `Default`、`RoundRobin`、`EarliestDelivery` 三种可配置策略；默认值保持 NoQ 原行为。曾实验的 `MinRtt` 因五种子筛选失败已删除。
- `src/config/mod.rs`：公开导出调度策略类型。
- `src/lib.rs`：从 `noq-proto` 顶层公开导出调度策略类型。
- `src/connection/mod.rs`：先发送路径专属控制包，再按策略选择应用数据路径；首选路径受拥塞或 pacing 限制时继续尝试其他合格路径。
- `src/connection/stats.rs`：分别统计每条路径首次发送和重传的 STREAM 数据字节。
- `src/connection/send_buffer.rs`：让统计逻辑判断下一段数据是否来自重传队列。
- `src/connection/streams/state.rs`：在实际编码 STREAM 帧时累计首次数据和重传数据。
- `src/tests/multipath.rs`：验证默认行为、轮询、预计送达时间、拥塞回退、备用路径、单路径语义和首次数据统计。

补丁没有修改 TLS、线路验证、拥塞控制算法、pacing 算法或 Backup/Available 的协议语义。2026-07-11 已运行 NoQ 全部 386 项单元测试和 3 项文档测试，结果全部通过。
