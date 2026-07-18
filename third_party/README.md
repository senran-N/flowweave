# 第三方源码说明

## v0.1.0-lab 冻结复核

2026-07-13 使用本机 Cargo registry 中已通过校验的 1.0.1 发布包重新比较：`noq-1.0.1.crate` SHA-256 为 `4bf95190af1bd4a00a10e8255ca0c8ddd9e9a9f5e79151d7a7eb6d56aff5dc89`，`noq-proto-1.0.1.crate` 为 `aa6c890013591e709a3e45dd53501351b7e27e7ff3c7e9fc3dce43e300e7e9d3`。排除 Cargo 缓存标记和构建目录后，高层 NoQ 只有下文记录的 6 个文件不同；NoQ Proto 有下文记录的 23 个偏离路径，其中包含新增的 `declared_epoch_sensor.rs`。没有发现未登记的 vendor 漂移。

## NoQ

- 项目：https://github.com/n0-computer/noq
- 包名和版本：noq 1.0.1
- crates.io 包校验值：4bf95190af1bd4a00a10e8255ca0c8ddd9e9a9f5e79151d7a7eb6d56aff5dc89
- 上游 Git 提交：340e9c7da0d60eda6f5c7ffa7a36d20ed8d793fd
- 许可证：MIT OR Apache-2.0

`third_party/noq` 来自本机 Cargo 已校验的官方发布包。没有保留 Cargo 缓存标记或自动生成的 `.cargo_vcs_info.json`；发布包校验值和其中记录的上游提交号固定在上面。

### NoQ 当前偏离上游

- `Cargo.toml`：让 vendor 的高层 crate 明确使用相邻的 `third_party/noq-proto`，避免高层 API 与底层定向 DATAGRAM 能力版本错位。
- `Cargo.lock`：随上述本地 path patch 去掉 `noq-proto` 的 registry source/checksum，其他锁定依赖不变；这是 Cargo 对本地源码替换的机械结果。
- `src/connection.rs`：增加 `Connection::send_datagram_on_path`、`Connection::send_datagram_on_path_wait`、`Connection::send_datagram_on_path_separate`、`Connection::send_datagram_on_path_separate_wait`、`SendDatagramOnPath` 与 `SendDatagramOnPathError`。同步与异步入口都保留普通 DATAGRAM 的禁用、过大和背压语义，并把不可用目标路径单独报告为 `PathUnavailable`。`separate` 入口只要求该应用 DATAGRAM 不与另一应用 DATAGRAM 共用 QUIC 包；ACK/控制帧仍可共包，且不绕过目标路径 cwnd、pacing、MTU、反放大或发送缓冲。另让内部 rebind 事件区分“只更新 UDP sender”和“同时执行通用 network change”；默认 `Endpoint::rebind` 语义不变。
- `src/endpoint.rs`：增加 `Endpoint::rebind_preserving_paths`。它原子换用新 UDP socket 并更新所有连接 sender，但不调用会清空路径显式 `local_ip` 的通用 `handle_network_change(None)`；仅供产品层随后逐条 ping、迁移或替换全部路径，错误时仍保留旧 socket。
- `src/lib.rs`：公开导出定向 DATAGRAM 的 future 和错误类型；内部 `ConnectionEvent::Rebind` 另携带是否执行通用 network-change 的布尔合同。
- `src/tests.rs`：用真实异步 Endpoint 建立两条路径，证明相同负载分别从主路与 Backup 路各发送一份，并证明路径关闭后高层 API 返回正确错误。

### TLS 安全边界

NoQ 官方发布包原样包含 `examples/insecure_connection.rs`，专门演示 rustls 的不安全自定义证书验证器；NoQ Proto 的上游 rustls 适配层也通过 `dangerous().with_custom_certificate_verifier(...)` 安装调用方提供的验证器。这两处均与 crates.io 1.0.1 原件一致，不是 FlowWeave 补丁。根项目不会构建、安装或调用该示例；产品客户端只使用 `ClientConfig::with_root_certificates`、独立 CA DER 和标准 `server_name`，release `flowweave-proxy` 中也不包含 `SkipServerVerification`。因此“无 insecure verifier”指 FlowWeave 产品和实验入口的实际配置，而不是声称上游库没有提供高级自定义验证 API。

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

## NoQ Proto 当前偏离上游

以下 23 个文件与 crates.io 官方发布包存在差异；其中 21 个承载默认关闭或当前合同需要的补丁，另外 2 个只有 `cargo fmt` 排版变化。其他上游文件仍保持原样：

- `src/config/transport.rs`：增加默认关闭的 PTO、abandoned、ACK 进展、有界 ACK 逃生和关键反馈路径交接五项跨路径恢复配置，同一 NoQ 版本可分别复现官方基线与每个候选。
- `src/connection/datagrams.rs`：让发送队列元素携带可选 `PathId` 与默认关闭的独立应用包边界标记，增加 `Datagrams::send_on_path`、`Datagrams::send_on_path_separate` 与 `SendDatagramOnPathError`；精确目标可以是 Backup 路径，但必须已验证且开放。路径关闭会丢弃该路径未发副本并释放缓冲，普通未指定 DATAGRAM 的调度语义和普通定向 DATAGRAM 的共包行为保持不变。若 separate 帧前已有应用 DATAGRAM，则请求新包；写入 separate 帧后停止继续写应用 DATAGRAM。
- `src/connection/declared_epoch_sensor.rs`：增加默认关闭的 B 组诊断传感器。只有应用显式声明一次固定 250 ms cohort 组成的 backlogged epoch 时，才按原发送路径记录首次 STREAM 字节及其及时/迟到 ACK；它不改变调度、拥塞控制或产品代理默认配置。
- `src/connection/mod.rs`：在逐路径 Data PTO、路径 abandoned 或一个完整 PTO 没有新 ACK 进展时，把仍在途的 STREAM 范围加入全局重传队列一次。ACK 进展截止不被后续发包推迟，触发后原路径只探活、普通数据让给已验证备用路；探针确认后才恢复调度。恢复候选还可在实际承载 STREAM 恢复数据的备用路请求一次立即反馈，让该路带回其他路径累计 PATH_ACK；独立的新候选会在接收端暂时把这条已验证恢复路提升为 Available、其他路降为 Backup，使 `MAX_STREAM_DATA` 等全连接反馈不再被故障优先路取走；非首选路的恢复探针到达后恢复交接前状态，避免一次误判永久改写 PATH_STATUS。标准 LossDetection、路径空闲和 3 PTO 清场保持不变。另记录恢复与反馈路径，并修复 GSO 小分段越界问题。C 组接线还区分路径专属的 ACK-eliciting、拥塞受控数据，使显式定向 DATAGRAM 只在目标路径满足 cwnd、pacing、MTU 和反放大条件时构包；构包循环同时执行可选的应用 DATAGRAM 前后包边界。
- `src/connection/packet_builder.rs`：在包真正发送并登记后启动 ACK 进展纪元；后续包只登记在途状态，不移动既有恢复截止。另保留 GSO 小分段收尾修复。
- `src/connection/paths.rs`：保存跨路径恢复探针包号边界、ACK 进展纪元起点和 O(1) 在途 STREAM 帧计数；这些都不进入线协议，也不发送公开 `PATH_STATUS`。另把既有 `PathId::as_u32` 设为公开只读 accessor，供产品层输出不含地址的稳定路径观测。
- `src/connection/qlog.rs`：给独立 ACK 进展恢复定时器提供可识别的 qlog 名称。
- `src/connection/send_buffer.rs`：区分首次与重传数据；重复、重叠和乱序 ACK 只计算新确认字节，并取消已经无用的待发重复范围；另只读暴露累计确认前沿、最低待重传 offset 和待重传字节。
- `src/connection/spaces.rs`：逐路径判断本路径待发 ACK，让 Backup 路径可以发送 ACK-only 包，同时不把其他开放路径的 ACK 错当成本路径工作；有界逃生会为下一次累计确认保存唯一指定的返回路径，发送或失效后立即清理。另把目标路径待发 DATAGRAM 计入该路径的可发送工作，未指定 DATAGRAM 仍只服从普通数据调度。
- `src/connection/state.rs`：只有 `cargo fmt` 造成的导入排版变化，没有行为修改。
- `src/connection/stats.rs`：分别统计每条路径首次/重传 STREAM 字节、loss/PTO、abandoned 与 ACK 进展恢复尝试、三类对冲载荷、同路/跨路 PATH_ACK，以及 ACK 逃生请求和实际返回；另只读暴露当前 PTO、在途字节/包、应用数据包表、PTO 计数、两只恢复定时器，以及逐流 `R/H/A/Q` 数据级状态。
- `src/connection/streams/mod.rs`：当连接级或流级信用耗尽时重新排队标准 `DATA_BLOCKED` / `STREAM_DATA_BLOCKED` 义务，使 A 组恢复后的流控反馈不会静默丢失。
- `src/connection/streams/recv.rs`：在双方协商后，按应用有序读取前沿排队单调 `STREAM_PROGRESS`，并保证只报告真正向前推进的 offset。
- `src/connection/streams/send.rs`：把“流是否完成”和“本次新确认字节数”一起返回，防止两个副本的 ACK 重复扣账。
- `src/connection/streams/state.rs`：按新确认字节更新连接账目，让重传接口报告本次真正新加入队列的载荷，并向只读诊断汇总逐流连续接收、最高接收、累计确认和待重传状态；确定性反例覆盖“前面有洞、后面已到、另有待重传”。
- `src/connection/timer.rs`：增加独立逐路径 ACK 进展恢复定时器，并排在标准 LossDetection 之后处理同刻到期事件。
- `src/frame.rs`：定义并编解码实验性 `STREAM_PROGRESS` 帧，同时补齐恢复时需要重发的标准 BLOCKED 帧编码路径。
- `src/lib.rs`：公开导出 `SendDatagramOnPathError`，供高层 NoQ 保留精确错误语义。
- `src/packet.rs`：只有 `cargo fmt` 造成的测试导入排版变化，没有行为修改。
- `src/tests/encode_decode.rs`：把实验性 `STREAM_PROGRESS` 纳入通用帧编解码往返测试。
- `src/tests/mod.rs`：验证 `STREAM_PROGRESS` 必须双边协商，并证明它可在包 ACK 缺失时单调退休已由应用读取的数据义务。
- `src/tests/multipath.rs`：验证测量、五项默认关闭、单路径保护、PTO/abandoned/ACK 进展恢复、截止不滑动、每纪元一次、备用路接管、拥塞窗口、纯 FIN、两种 ACK 顺序和旧 ACK 边界；另证明历史 ACK 逃生不会改路径状态，新候选才会把恢复路提升为反馈主路、让 `MAX_STREAM_DATA` 从该路发送，并在原路恢复探针成功后还原之前状态。C 组测试还覆盖 Backup 定向发送不污染主路、同一负载精确双路落位、未知/未验证/已关闭路径拒绝、关闭路径释放背压，以及定向 DATAGRAM 不绕过 cwnd；新增反例证明两个普通定向 DATAGRAM 仍可共用一个 UDP 包，而一个普通帧加两个 separate 帧会使用三个 UDP 包。
- `src/transport_parameters.rs`：增加实验性 `STREAM_PROGRESS` 传输参数，只有双方显式启用时才允许发送数据级进展帧。

轮询、最低 RTT、预计最早送达、交付速率加权和 ACK-ECF 都已经按基准结果完整删除；NoQ 当前仍保持官方调度行为，不保留失败调度开关。v11 的 DATAGRAM priority API、队列字段和专用测试也已完整删除；上游原有的 STREAM priority 不属于该失败候选。PTO 对冲是独立的数据恢复机制，不参与 B 组容量调度。BBR3 只读容量接口曾在实验快照 `29f0ec2` 中验证，但没有通过 2 MiB 五种子短筛，随后已完整删除。
