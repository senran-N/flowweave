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

以下 12 个文件为 FlowWeave 当前实验快照中的可审计补丁，其他上游文件仍保持原样：

- `src/config/transport.rs`：增加默认关闭的 PTO、abandoned、ACK 进展和有界 ACK 逃生四项跨路径恢复配置，同一 NoQ 版本可分别复现官方基线与每个候选。
- `src/connection/mod.rs`：在逐路径 Data PTO、路径 abandoned 或一个完整 PTO 没有新 ACK 进展时，把仍在途的 STREAM 范围加入全局重传队列一次。ACK 进展截止不被后续发包推迟，触发后原路径只探活、普通数据让给已验证备用路；探针确认后才恢复调度。恢复候选还可在实际承载 STREAM 恢复数据的备用路请求一次立即反馈，让该路带回其他路径累计 PATH_ACK；普通探测不会改变 ACK 路由。标准 LossDetection、公开 PATH_STATUS、路径空闲和 3 PTO 清场保持不变。另记录恢复与反馈路径，并修复 GSO 小分段越界问题。
- `src/connection/packet_builder.rs`：在包真正发送并登记后启动 ACK 进展纪元；后续包只登记在途状态，不移动既有恢复截止。另保留 GSO 小分段收尾修复。
- `src/connection/paths.rs`：保存跨路径恢复探针包号边界、ACK 进展纪元起点和 O(1) 在途 STREAM 帧计数；这些都不进入线协议，也不发送公开 `PATH_STATUS`。
- `src/connection/qlog.rs`：给独立 ACK 进展恢复定时器提供可识别的 qlog 名称。
- `src/connection/send_buffer.rs`：区分首次与重传数据；重复、重叠和乱序 ACK 只计算新确认字节，并取消已经无用的待发重复范围；另只读暴露累计确认前沿、最低待重传 offset 和待重传字节。
- `src/connection/spaces.rs`：逐路径判断本路径待发 ACK，让 Backup 路径可以发送 ACK-only 包，同时不把其他开放路径的 ACK 错当成本路径工作；有界逃生会为下一次累计确认保存唯一指定的返回路径，发送或失效后立即清理。
- `src/connection/stats.rs`：分别统计每条路径首次/重传 STREAM 字节、loss/PTO、abandoned 与 ACK 进展恢复尝试、三类对冲载荷、同路/跨路 PATH_ACK，以及 ACK 逃生请求和实际返回；另只读暴露当前 PTO、在途字节/包、应用数据包表、PTO 计数、两只恢复定时器，以及逐流 `R/H/A/Q` 数据级状态。
- `src/connection/streams/send.rs`：把“流是否完成”和“本次新确认字节数”一起返回，防止两个副本的 ACK 重复扣账。
- `src/connection/streams/state.rs`：按新确认字节更新连接账目，让重传接口报告本次真正新加入队列的载荷，并向只读诊断汇总逐流连续接收、最高接收、累计确认和待重传状态；确定性反例覆盖“前面有洞、后面已到、另有待重传”。
- `src/connection/timer.rs`：增加独立逐路径 ACK 进展恢复定时器，并排在标准 LossDetection 之后处理同刻到期事件。
- `src/tests/multipath.rs`：验证测量、四项默认关闭、单路径保护、PTO/abandoned/ACK 进展恢复、截止不滑动、每纪元一次、备用路接管、拥塞窗口、纯 FIN、两种 ACK 顺序和旧 ACK 边界；另证明 PTO 与 ACK 进展恢复都能请求一次 ACK 逃生、正常开放路径仍同路确认，并回归空包发送循环。

轮询、最低 RTT、预计最早送达、交付速率加权和 ACK-ECF 都已经按基准结果完整删除；NoQ 当前仍保持官方调度行为，不保留失败调度开关。PTO 对冲是独立的数据恢复机制，不参与 B 组容量调度。BBR3 只读容量接口曾在实验快照 `29f0ec2` 中验证，但没有通过 2 MiB 五种子短筛，随后已完整删除。
