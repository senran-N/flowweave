# FlowWeave / 织流

FlowWeave 是一个 Rust 编写的实验性多路径 QUIC 项目，研究如何把 Wi-Fi、移动网络或多条宽带编织成一条连接。当前仓库同时包含可部署的固定目标 TCP 代理、隔离坏网络实验场、Hysteria 2.9.3 公平对照和原始基准证据。

当前阶段不是通用 VPN 产品。已经完成的范围是：

- A：单条路径失效时保持原 MPQUIC 连接继续传输；
- B：在锁定的持续单流合同中聚合两条线路；
- C：在锁定的高丢包实时消息合同中降低尾延迟和丢失；
- 一个只允许显式固定 TCP 目标的 TLS 1.3 MPQUIC 客户端/服务端代理。

完整结论、适用边界和不能外推的范围见 [PROJECT.md](PROJECT.md)。实验合同见 [BENCHMARK.md](BENCHMARK.md)，部署步骤见 [deploy/README.md](deploy/README.md)。

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

## 安全边界

- 产品入口使用标准 TLS 1.3、独立 CA 和严格 `server_name` 校验，没有跳过证书验证的产品开关。
- 服务端只连接配置中的唯一 `allowed_target`，客户端只监听 loopback；它不是开放代理、SOCKS5、TUN 或任意 UDP 转发器。
- `scripts/run_netem_lab.sh` 只允许在一次性隔离网络命名空间中运行；不要绕过它直接对真实网卡执行实验命令。
- 私钥、令牌、真实证书、Hysteria 下载二进制和 Cargo 构建目录不得提交到仓库。

## 仓库地图

- `src/proxy.rs`、`src/bin/flowweave-proxy.rs`：固定目标代理；
- `src/lib.rs`、`src/realtime*.rs`、`src/hysteria.rs`：实验与测量逻辑；
- `tests/network_lab.rs`：需要隔离网络空间的正式矩阵和诊断；
- `benchmark-results/`：不可覆盖的原始 CSV 与 SHA-256 清单；
- `third_party/noq*`：固定 NoQ 1.0.1 源码及逐文件记录的 FlowWeave 补丁；
- `deploy/`：systemd 单元、配置样例和部署说明。

## 当前限制

实验室结果不等于生产 SLA。真实公网双接口、长期 soak、升级兼容、客户端身份轮换和生产级可观测性仍待完成。C 组编码器目前也是实验入口，不是通用实时媒体协议。

本仓库当前尚未声明开源许可证；在许可证确定前，不应把第三方许可证误认为 FlowWeave 自身的授权。
