# FlowWeave / 织流

FlowWeave 是一个 Rust 编写的实验性多路径 QUIC 项目，研究如何把 Wi-Fi、移动网络或多条宽带编织成一条连接。当前仓库同时包含可部署的固定目标 TCP 代理、隔离坏网络实验场、Hysteria 2.9.3 公平对照和原始基准证据。

当前阶段不是通用 VPN 产品。已经完成的范围是：

- A：单条路径失效时保持原 MPQUIC 连接继续传输；
- B：在锁定的持续单流合同中聚合两条线路；
- C：在锁定的高丢包实时消息合同中降低尾延迟和丢失；
- 一个只允许显式固定 TCP 目标的 TLS 1.3 MPQUIC 客户端/服务端代理；
- VPN 的 mTLS 身份、控制协商、客户端/服务端数据句柄和真实 loopback DATAGRAM 地基，但尚未接入 TUN。

完整结论、适用边界和不能外推的范围见 [PROJECT.md](PROJECT.md)。实验合同见 [BENCHMARK.md](BENCHMARK.md)，代理持续负载合同见 [PROXY_SOAK.md](PROXY_SOAK.md)，令牌轮换合同见 [PROXY_ROTATION.md](PROXY_ROTATION.md)，生产 VPN 地基合同见 [VPN_RESEARCH.md](VPN_RESEARCH.md)，VPN 身份与轮换合同见 [VPN_IDENTITY.md](VPN_IDENTITY.md)，部署步骤见 [deploy/README.md](deploy/README.md)。

## 快速验证

需要 Rust 1.88.0。仓库根目录的 `rust-toolchain.toml` 会在使用 rustup 时自动选择该版本。

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
./scripts/verify_evidence.sh
```

普通本地双路径功能实验：

```bash
cargo run --bin flowweave-lab
```

构建最小代理：

```bash
cargo build --release --bin flowweave-proxy
```

运行默认 60 秒本地 TLS/MPQUIC soak，并输出一份 JSON 健康报告：

```bash
cargo run --release --bin flowweave-proxy-soak
```

检查已经保存的代理 JSONL（单个服务角色示例）：

```bash
cargo run --release --bin flowweave-proxy-observe -- \
  verify proxy.jsonl --require-role client
```

## 安全边界

- 产品入口使用标准 TLS 1.3、独立 CA 和严格 `server_name` 校验，没有跳过证书验证的产品开关。
- 服务端只连接配置中的唯一 `allowed_target`，客户端只监听 loopback；它不是开放代理、SOCKS5、TUN 或任意 UDP 转发器。
- 代理运行事件使用稳定的 `flowweave.runtime.v1` JSONL；原子指标快照可从日志和 `ProxyRuntime::metrics_snapshot()` 读取，事件不记录令牌、私钥或应用载荷。
- 服务端可在重叠期接受两个文件令牌，客户端和服务端通过 SIGHUP 原子重载；失败保留旧状态，撤销只影响新流。
- SIGTERM 和 Ctrl-C 会先停止新接入，再给现有流最多 10 秒完成传输；超过截止时间才强制终止残余任务。
- `scripts/run_netem_lab.sh` 只允许在一次性隔离网络命名空间中运行；不要绕过它直接对真实网卡执行实验命令。
- 私钥、令牌、真实证书、Hysteria 下载二进制和 Cargo 构建目录不得提交到仓库。

## 仓库地图

- `src/proxy.rs`、`src/bin/flowweave-proxy.rs`：固定目标代理；
- `src/vpn.rs`：尚未接入 TUN 的 `FWI1` IP 包解析、分片与有界重组核心；
- `src/vpn_active_session.rs`：单活动代际、成功后替换、在线撤销、关闭码和身份重载协调；
- `src/vpn_control.rs`：VPN 专用 `FWC1` 控制消息、版本协商、能力和虚拟地址确认；
- `src/vpn_client_data_path.rs`：客户端用可复用工厂从 `FWC1 ACCEPT` 和本地 ACL 构造正式数据句柄，跨重连共享速率、内存预算和指标，不伪造服务端身份记录；
- `src/vpn_datagram_runtime.rs`：真实 NoQ DATAGRAM 双向收发、包/字节双重有界队列、周期过期、取消安全和稳定运行指标；
- `src/vpn_data_path.rs`：逐身份无全局逐包锁的数据句柄，闭合外层 DATAGRAM 计费、双向重组、原子全局账本和完整 IP 策略；
- `src/vpn_data_policy.rs`：上行源地址防伪、双向目标 ACL 和下行虚拟地址归属检查；
- `src/vpn_identity.rs`：证书指纹身份、双指纹轮换、虚拟地址、目标 CIDR 和每身份资源合同；
- `src/vpn_identity_config.rs`：严格 JSON 身份文件、私有权限和失败保留旧状态的原子注册表替换；
- `src/vpn_quota.rs`：跨代际共享 token bucket、逐身份速率隔离和全局重组字节/未完成包原子上限；
- `src/vpn_session.rs`：真实 mTLS QUIC 上的 `FWC1` 控制握手、强制 MPQUIC/DATAGRAM 和稳定拒绝原因；
- `src/vpn_tls.rs`：TLS 1.3 双向证书、独立 CA、VPN ALPN 和叶证书指纹提取；
- `src/proxy_observe.rs`、`src/proxy_soak.rs`：JSONL 健康门控和本地持续负载运行器；
- `PROXY_ROTATION.md`：共享令牌无重启轮换、失败和撤销语义；
- `src/lib.rs`、`src/realtime*.rs`、`src/hysteria.rs`：实验与测量逻辑；
- `tests/network_lab.rs`：需要隔离网络空间的正式矩阵和诊断；
- `benchmark-results/`：不可覆盖的原始 CSV 与 SHA-256 清单；
- `third_party/noq*`：固定 NoQ 1.0.1 源码及逐文件记录的 FlowWeave 补丁；
- `deploy/`：systemd 单元、配置样例和部署说明。

## 当前限制

实验室结果不等于生产 SLA。仓库已有默认 60 秒的单机真实 TLS/MPQUIC soak、可配置 JSONL 阈值检查、共享令牌无重启轮换，以及带限速、应用字节预算和周期检查点的公网 workload/echo 部署入口；现已完成同一物理出口下“两张接口 + 两条源路由 + 两个 NAT”的 30 分钟真实公网双路径 soak。VPN 已完成逐客户端身份、活动代际、在线撤销、按身份分片的数据热路径、外层 `FWI1` 准入、真实重组、原子全局账本和双向 ACL；客户端现在能直接从受验证的 `FWC1 ACCEPT` 建立数据句柄，双方协商的最大 IP 包长会在收发两端实际执行。真实 loopback 组合测试已串通 TLS 1.3 mTLS、控制握手、受管服务端会话、客户端工厂和双方 NoQ DATAGRAM 运行器，并验证 IPv4 上行、IPv6 下行、超限拒绝及旧运行器退出。产品 client/server 命令、TUN 设备、路由/NAT 和 DNS 仍未接入。两个独立运营商出口只保留为运营商级故障隔离声明边界；多小时/多天证据、跨版本升级、外部指标存储与告警投递仍待完成。C 组编码器目前也是实验入口，不是通用实时媒体协议。

本仓库当前尚未声明开源许可证；在许可证确定前，不应把第三方许可证误认为 FlowWeave 自身的授权。
