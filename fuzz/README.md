# FlowWeave fuzz targets

本目录不是产品二进制。它使用 `cargo-fuzz` 和 libFuzzer 持续攻击无需 root 的 VPN 包、`FWC1` 控制消息、严格身份 JSON、双向源地址/ACL 策略，以及包含逐身份限速、双向重组、全局原子账本和清理不变量的集成数据路径。

首次准备独立 fuzz 工具链后运行。AddressSanitizer 门控需要 nightly Rust：

```bash
cargo install cargo-fuzz --version 0.13.2 --locked
cargo fuzz run vpn_reassembly --fuzz-dir fuzz -- \
  -dict=fuzz/vpn_reassembly.dict
```

只有 stable 编译器时可执行带覆盖率但不带 sanitizer 的门控；它能寻找 panic 和资源不变量失败，但不能替代 nightly + AddressSanitizer：

```bash
cargo fuzz run vpn_reassembly --fuzz-dir fuzz --sanitizer none -- \
  -max_total_time=60 \
  -max_len=8192 \
  -timeout=5 \
  -dict=fuzz/vpn_reassembly.dict
```

完整发布门控使用 nightly、AddressSanitizer、固定时间和 artifact 目录：

```bash
cargo fuzz run vpn_reassembly --fuzz-dir fuzz -- \
  -max_total_time=60 \
  -max_len=8192 \
  -timeout=5 \
  -dict=fuzz/vpn_reassembly.dict \
  -artifact_prefix=fuzz/artifacts/vpn_reassembly/
```

任何 crash、timeout、OOM 或资源不变量失败都必须保留最小化输入并先修复；不得只把输入加入忽略列表。正式 CI 接入前，本目录只能证明 fuzz 入口和本地短门控存在，不能声称已经完成持续模糊测试或 sanitizer 覆盖。

2026-07-14 在加入身份 JSON 入口后执行了一次 stable、`sanitizer none` 的 10 秒增量门控：3,975,712 次执行，最终 `cov 896 / ft 2560`，零 crash、timeout 或资源不变量失败。它补充但不替代此前 60 秒 84,831,505 次的包/控制核心门控，也不替代 nightly + AddressSanitizer。

同日加入 IPv4/IPv6 双向数据策略入口后再次执行 10 秒增量门控：3,865,653 次执行，新增 1,144 个 corpus 单元，峰值 RSS 50 MiB，零 crash、timeout 或资源不变量失败。

同日随后把集成 `VpnDataPathHandle` 加入 fuzz 入口。锁定 fuzz 工程编译通过；当前 shell 缺少 `cargo-fuzz` 子命令，因此只用普通 release libFuzzer 构建执行了 10 秒断言门控：12,966,959 次、零 crash/timeout。该普通构建明确报告没有覆盖率插桩，所以这条结果只证明运行期不变量没有被现有 corpus/变异击穿，不能替代新增入口的正式 coverage-guided 复跑，更不能替代 nightly + AddressSanitizer。
