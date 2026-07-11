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

以下 8 个文件为 FlowWeave 当前实验快照中的可审计补丁，其他上游文件仍保持原样：

- `src/config/transport.rs`：增加默认关闭的 `cross_path_pto_reinjection` 通用配置，同一 NoQ 版本可公平运行官方基线和候选。
- `src/connection/mod.rs`：在逐路径 Data PTO 后把仍在途的 STREAM 范围加入全局重传队列一次；可疑路径暂停普通数据，只有对冲后发送的探针被确认才恢复，最终路径放弃仍使用官方规则。
- `src/connection/paths.rs`：保存本地 PTO 恢复探针的包号边界；它不进入线协议，也不发送公开 `PATH_STATUS`。
- `src/connection/send_buffer.rs`：区分首次与重传数据；重复、重叠和乱序 ACK 只计算新确认字节，并取消已经无用的待发重复范围。
- `src/connection/stats.rs`：分别统计每条路径首次/重传 STREAM 字节，以及 PTO 对冲次数和新入队载荷字节。
- `src/connection/streams/send.rs`：把“流是否完成”和“本次新确认字节数”一起返回，防止两个副本的 ACK 重复扣账。
- `src/connection/streams/state.rs`：按新确认字节更新连接账目，并让重传接口报告本次真正新加入队列的载荷。
- `src/tests/multipath.rs`：验证测量、默认关闭、单路径保护、首次/重复 PTO、备用路接管、拥塞窗口、纯 FIN、两种 ACK 顺序、旧 ACK 不得错误恢复主路等确定性边界。

轮询、最低 RTT、预计最早送达、交付速率加权和 ACK-ECF 都已经按基准结果完整删除；NoQ 当前仍保持官方调度行为，不保留失败调度开关。PTO 对冲是独立的数据恢复机制，不参与 B 组容量调度。BBR3 只读容量接口曾在实验快照 `29f0ec2` 中验证，但没有通过 2 MiB 五种子短筛，随后已完整删除。
