# v0.1.0-lab 冻结说明

`v0.1.0-lab` 是 FlowWeave 从算法实验转向真实网络试用前的证据与实现冻结点。该标签应同时包含：

- A 组 v6.9 双向故障切换实现与正式结果；
- B 组 Cubic + NoQ 默认持续单流正式结果；
- C 组 v12 `2-of-3` 实时编码实现与正式结果；
- Hysteria 2.9.3 的 A/B/C 固定对照；
- 固定目标 TCP 代理、部署样例和本地真实 TLS 测试；
- 固定的 NoQ 1.0.1 / NoQ Proto 1.0.1 源码与 FlowWeave 补丁说明。

## 冻结边界

- `benchmark-results/` 中共有 135 个 CSV，合计 395,651,552 字节。
- 全部 CSV 的相对路径和 SHA-256 固定在 `benchmark-results/SHA256SUMS`。
- 原始结果不得覆盖、补行或以同一合同重跑。后续实验必须使用新的文件名和新的预注册合同。
- Cargo 构建目录、真实证书、私钥、令牌和下载的 Hysteria 二进制不属于冻结内容。

关键正式证据：

| 目标 | FlowWeave 正式文件 | 对照文件 |
|---|---|---|
| A | `2026-07-12-stream-progress-snapshot-v6-9-formal-20-summary.csv` | `2026-07-13-hysteria-2-9-3-a-formal-20.csv` |
| B | `2026-07-13-b-cubic-noq-continuous-formal-v1.csv` | `2026-07-13-hysteria-2-9-3-b-formal-40-v2.csv` |
| C | `2026-07-13-c-bbr3-no-gso-compact7-two-of-three-global-40-3-v12-formal-5.csv` | `2026-07-13-hysteria-2-9-3-c-formal-20-v2.csv` |

## 恢复与验收

从标签做干净检出后运行：

```bash
./scripts/verify_evidence.sh
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release --bin flowweave-proxy
```

2026-07-13 冻结前已完成两组验证：

- 只读 Docker `rust:1.88.0-bookworm`：根项目 65 个库测试与 3 个普通网络测试通过，73 个隔离网络测试按设计忽略；Clippy 零警告；release 代理构建成功；NoQ Proto 470 项和高层 NoQ 33 项非忽略测试通过。
- 本机 Rust 1.96.0：格式检查、同一根项目测试矩阵、Clippy 和 release 代理构建全部通过。
- `./scripts/verify_evidence.sh` 校验 135 个 CSV 全部通过。

隔离网络正式矩阵耗时较长且需要 Linux 网络命名空间，不作为普通检出的默认测试。对应入口、不可覆盖规则和运行时长见 `PROJECT.md`、`BENCHMARK.md` 与 `scripts/run_netem_lab.sh`。

## 版本兼容声明

该冻结点使用 Rust 1.88.0、NoQ 1.0.1 和 NoQ Proto 1.0.1。FlowWeave 的恢复实现包含实验性 `STREAM_PROGRESS` 协商，代理客户端与服务端应使用同一冻结版本；当前尚未承诺跨版本线协议兼容。

## 下一阶段

冻结完成后不再新增 A/B/C 历史候选。下一里程碑是固定目标代理的运行保护、可观测性和真实双接口 24 小时/7 天试点。
