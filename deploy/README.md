# FlowWeave 最小代理部署

当前入口只转发一个固定 TCP 目标：本地应用连接客户端 loopback TCP 端口，客户端通过标准 TLS 1.3 MPQUIC 连接服务端，服务端只允许配置中的唯一 `allowed_target`。它不是 TUN、SOCKS5、开放代理或 UDP 转发器。

`vpn-server.json.example`、`vpn-client.json.example` 和 `vpn-identities.json.example` 已经是代码可严格校验的未来 VPN 配置合同，但目前没有 systemd 单元或产品命令会读取它们。仓库只在一次性隔离 network namespace 中验证了“封闭提权能力的非 root 进程附着已由管理身份准备好的 TUN”；尚未配置真实地址、默认路由、NAT 或 DNS。不要把这些样例当成可部署 VPN 入口；身份格式与剩余边界见 [VPN_IDENTITY.md](../VPN_IDENTITY.md) 和 [VPN_RESEARCH.md](../VPN_RESEARCH.md)。

客户端样例中的 `expected_client_ipv4/ipv6` 与 `expected_server_ipv4/ipv6` 必须和服务端身份文件对该客户端的静态分配完全一致。它们不是让客户端自行申请地址：服务端证书身份仍是最终授权来源；这些预期值用于未来 root oneshot 在主进程启动前配置 TUN，并让数据进程在 `FWC1 ACCEPT` 后拒绝任何配置漂移。

开发机可运行以下只读/隔离门控：

```bash
cargo test vpn_product_config -- --nocapture
cargo test vpn_product_runtime -- --nocapture
./scripts/run_vpn_tun_lab.sh
```

第二条命令需要 Linux 的 `unshare`、`ip`、`setpriv`、`jq` 以及当前用户的 `/etc/subuid`、`/etc/subgid` 映射。脚本会先证明已经离开主网络空间，临时创建 `fwvpn0`，验证 root、未设置 `NoNewPrivileges`、接口 down、MTU 不一致和不存在接口均被拒绝，再以无 capability 的设备 owner 完成附着；退出后整个网络空间消失。

## 1. 构建和安装

在源码目录使用 Rust 1.88 或更高版本：

```bash
cargo test proxy --lib
cargo build --release --bin flowweave-proxy --bin flowweave-proxy-observe
sudo install -o root -g root -m 0755 target/release/flowweave-proxy /usr/local/bin/flowweave-proxy
sudo install -o root -g root -m 0755 target/release/flowweave-proxy-observe /usr/local/bin/flowweave-proxy-observe
sudo useradd --system --home-dir /nonexistent --shell /usr/bin/nologin flowweave
sudo install -d -o root -g flowweave -m 0750 /etc/flowweave
```

若 `flowweave` 用户已存在，`useradd` 的“already exists”错误可以忽略。服务端和客户端通常位于不同主机，两边都安装同一个二进制和各自的 systemd 单元。

## 2. 生成 CA、服务端证书和 PKCS#8 DER 私钥

以下命令在可信管理机执行。把 `proxy.example.com` 替换为客户端实际连接且可解析到服务端的名称；证书 SAN 和客户端 `server_name` 必须完全匹配。

```bash
umask 077
mkdir -p flowweave-pki
cd flowweave-pki

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ca.key.pem
openssl req -x509 -new -sha256 -days 3650 \
  -key ca.key.pem \
  -subj '/CN=FlowWeave private CA' \
  -out ca.cert.pem

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out server.key.pem
openssl req -new -sha256 \
  -key server.key.pem \
  -subj '/CN=proxy.example.com' \
  -addext 'subjectAltName=DNS:proxy.example.com' \
  -out server.csr.pem
openssl x509 -req -sha256 -days 825 \
  -in server.csr.pem \
  -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial \
  -copy_extensions copy \
  -out server.cert.pem

openssl x509 -in server.cert.pem -outform DER -out server.cert.der
openssl pkcs8 -topk8 -nocrypt -in server.key.pem -outform DER -out server.key.der
openssl x509 -in ca.cert.pem -outform DER -out ca.cert.der
openssl rand 48 > token
cp token token.previous
```

不要把 `ca.key.pem` 放到服务端或客户端。服务端需要 `server.cert.der`、`server.key.der`、`token` 和初始内容相同的 `token.previous`；客户端只需要 `ca.cert.der` 和同一份 `token`。令牌应通过已有的安全通道传输，不能粘贴进配置、命令行或日志。

## 3. 服务端配置

服务端开放的是 UDP，不是 TCP。把文件安装到服务端：

```bash
sudo install -o root -g flowweave -m 0640 server.conf.example /etc/flowweave/server.conf
sudo install -o root -g root -m 0644 server.cert.der /etc/flowweave/server.cert.der
sudo install -o flowweave -g flowweave -m 0400 server.key.der /etc/flowweave/server.key.der
sudo install -o flowweave -g flowweave -m 0400 token /etc/flowweave/token
sudo install -o flowweave -g flowweave -m 0400 token.previous /etc/flowweave/token.previous
sudo install -o root -g root -m 0644 flowweave-server.service /etc/systemd/system/flowweave-server.service
```

编辑 `/etc/flowweave/server.conf`：

- `listen` 是 QUIC/UDP 监听地址；防火墙和云安全组必须允许该 UDP 端口。
- `allowed_target` 必须是服务端可连接的显式 IP:port。服务端拒绝域名和客户端请求的其他目标，因此不会退化成开放代理。
- `previous_token_file` 是可选的第二令牌槽。建议从首次部署就配置，并让两个文件初始内容相同，以便之后无重启轮换。
- 私钥和令牌在 Unix 上不得有任何 group/other 权限；启动时会检查并拒绝宽松权限。

启用服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now flowweave-server.service
sudo systemctl status flowweave-server.service
```

## 4. 客户端配置

把文件安装到客户端：

```bash
sudo install -o root -g flowweave -m 0640 client.conf.example /etc/flowweave/client.conf
sudo install -o root -g root -m 0644 ca.cert.der /etc/flowweave/ca.cert.der
sudo install -o flowweave -g flowweave -m 0400 token /etc/flowweave/token
sudo install -o root -g root -m 0644 flowweave-client.service /etc/systemd/system/flowweave-client.service
```

编辑 `/etc/flowweave/client.conf`：

- `listen` 必须是 loopback TCP 地址。
- `server` 可使用 DNS 名称和 UDP 端口；`server_name` 必须匹配证书 SAN，程序没有跳过验证的开关。
- `target` 必须与服务端的 `allowed_target` 解析成同一个 SocketAddr。
- 不配置路径 IP 时，操作系统选择主路径源地址。
- `primary_local_ip` 单独使用时，UDP Endpoint 直接绑定该地址。
- 同时配置 primary 和 additional 时，程序先用通配 UDP socket 完成 TLS，引导后逐条验证所有显式源 IP，再关闭临时路径；任何配置路径失败都会使客户端启动失败。最多保留八条产品路径。
- 所有路径 IP 必须已经配置在主机接口上、属于同一地址族，并能到达同一服务端地址。FlowWeave 不负责添加地址、路由或策略路由。

启用服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now flowweave-client.service
sudo systemctl status flowweave-client.service
```

应用随后连接客户端的本地 TCP 端口。例如示例配置把本地 `127.0.0.1:10022` 转发到服务端唯一允许的 `127.0.0.1:22`。

### 无重启令牌轮换

客户端和服务端都支持 `systemctl reload`，它发送 `SIGHUP` 并原子替换内存令牌。重载失败时旧状态继续有效，进程、QUIC 连接和既有流不会退出；撤销只影响之后创建的新流。完整安全合同见 [PROXY_ROTATION.md](../PROXY_ROTATION.md)。

准备一份通过安全通道分发的 `token.new`，然后按以下顺序执行。每次都先在目标目录安装临时文件，再在同一文件系统内重命名，避免重载读到原地覆盖的中间状态：

```bash
# 1. 服务端进入旧+新重叠期
sudo install -o flowweave -g flowweave -m 0400 token.new /etc/flowweave/.token.previous.next
sudo mv -f /etc/flowweave/.token.previous.next /etc/flowweave/token.previous
sudo systemctl reload flowweave-server.service

# 2. 客户端的新流改用新令牌
sudo install -o flowweave -g flowweave -m 0400 token.new /etc/flowweave/.token.next
sudo mv -f /etc/flowweave/.token.next /etc/flowweave/token
sudo systemctl reload flowweave-client.service

# 3. 验证客户端新流成功后，在服务端撤销旧令牌
sudo install -o flowweave -g flowweave -m 0400 token.new /etc/flowweave/.token.next
sudo mv -f /etc/flowweave/.token.next /etc/flowweave/token
sudo systemctl reload flowweave-server.service
```

服务端最后两个槽内容相同并自动去重为一个有效令牌。若日志出现 `credentials_reload_failed`，不要继续下一步；修复文件、所有者、权限或长度后重新 reload。不要通过重启掩盖一次未解释的轮换失败。

## 5. 验证与排错

```bash
journalctl -u flowweave-server.service -f
journalctl -u flowweave-client.service -f
ss -lunp | grep 4433
ss -ltnp | grep 10022
```

常见拒绝原因：

- `server_name` 与证书 SAN 不匹配，或客户端装错 CA；TLS 必须失败。
- 私钥/令牌可被 group 或 other 读取；收紧为 `0400` 后重启。
- 客户端 `listen` 不是 loopback；本版拒绝 LAN 暴露。
- `target` 与服务端 `allowed_target` 不同；服务端在连接上游之前拒绝。
- additional IP 没有配置在本机、路由不通或与服务端地址族不同；客户端按合同拒绝静默降级。
- 防火墙只开放了 TCP；FlowWeave 外层传输使用 QUIC/UDP。

运行事件逐行输出为 JSON（JSONL），schema 固定为 `flowweave.runtime.v1`。每条记录至少包含 `schema`、`ts_unix_ms`、`level`、`role` 和 `event`；`connection_started`、`connection_finished` 与 `path_changed` 使用 NoQ 的连接稳定 ID 和路径 ID 关联生命周期。路径事件只报告状态、原因和丢包计数，不记录观察到的地址。这些结构化运行事件不输出令牌、私钥、配置中的密钥路径或应用载荷。

主要事件包括：

- `runtime_started`：监听已就绪；
- `connection_started` / `connection_finished`：QUIC 连接生命周期与汇总 UDP 字节、丢失字节；
- `stream_started` / `stream_finished`：代理流结果和成功流的上下行字节；
- `connection_rejected` / `stream_rejected`：固定并发上限触发；
- `path_changed`：路径建立、放弃、丢弃或远端状态变化；
- `metrics_snapshot`：每 10 秒以及退出前输出一次原子计数快照；
- `credentials_reloaded` / `credentials_reload_failed`：脱敏的令牌重载结果；
- `shutdown_started` / `shutdown_forced` / `shutdown_complete`：drain 截止、超时原因、实际耗时及是否强制关闭。

`metrics_snapshot` 包含活动/累计连接与流、配额拒绝、DNS/TLS/请求/开流/上游连接超时、上游错误、应用上下行字节和优雅/强制退出次数。嵌入库的调用方也可通过 `ProxyRuntime::metrics_snapshot()` 读取同一组原子计数；`ProxyRuntime::shutdown()` 完成后返回最终快照。

SIGHUP 只重载令牌。SIGTERM 和 Ctrl-C 会触发有界优雅退出：服务端先禁止新 QUIC 连接，客户端先关闭本地 TCP listener，现有代理流最多继续 drain 10 秒；到期仍未完成时关闭 QUIC Endpoint、终止残余任务并把 `forced_shutdowns` 加一。systemd 样例的 `TimeoutStopSec=15s` 给程序的 10 秒窗口留出清理余量。客户端 QUIC 连接意外失效时进程仍会以失败状态退出，由 `Restart=on-failure` 执行外部重启；程序内部没有隐藏重连器。

当前运行保护是固定产品合同，不从配置文件放大：服务端最多同时处理 64 条 QUIC 连接，每条连接最多允许 64 条客户端双向流且拒绝所有单向流；客户端最多同时转发 64 条本地 TCP 连接，超额连接会立即关闭。DNS/TLS、打开 QUIC 流和上游 TCP 连接的截止为 10 秒，代理请求头与授权响应截止为 5 秒。systemd 样例另设置 `TasksMax=512` 与 `MemoryMax=1G`；若真实试点触发这些上限，应先记录负载、RSS、活动连接和失败原因，再通过新版本审计调整，不能临时删除保护后继续运行。

## 6. JSONL 健康门控与本地 soak

查看仍在运行的单个客户端服务时，允许生命周期保持打开，但仍检查 JSON、schema、失败、拒绝和超时阈值：

```bash
journalctl -u flowweave-client.service -o cat --since '10 minutes ago' \
  | flowweave-proxy-observe summary - \
      --require-role client \
      --allow-open-runtime
```

服务完成一次受控停止后，可执行严格门控。默认要求生命周期闭合、最终活动量归零，并且失败、强制退出、拒绝、超时和上游错误全部为零：

```bash
journalctl -u flowweave-client.service -o cat --since '2026-07-13 18:00:00' \
  | flowweave-proxy-observe verify - --require-role client
```

阈值只能显式放宽，例如 `--max-rejections 2`、`--max-timeouts 1`；数值按每个角色分别计算，命令和输出 JSON 应与故障记录一起保存。输入中的非 JSON 行、超过 64 KiB 的单行、错误 schema、缺字段事件或未闭合连接/流会直接使 `verify` 返回非零。

源码树还提供单机本地 soak。它生成临时测试证书和令牌，启动真实 server/client、两条 loopback MPQUIC 路径和固定 echo 上游，持续创建并校验代理流；最终报告同时检查应用字节、原子指标和完整 JSONL 生命周期：

```bash
cargo run --release --bin flowweave-proxy-soak -- \
  --duration-secs 60 \
  --workers 4 \
  --payload-bytes 65536 \
  --inter-flow-delay-ms 10 \
  > /tmp/flowweave-proxy-soak-report.json
git rev-parse HEAD
rustc --version
uname -srmo
```

退出码为零且报告中的 `stage_pass=true` 才算通过。该命令只证明单机回环合同，不代表真实 Wi-Fi/蜂窝、公网 NAT 或生产 SLA；完整边界见 [PROXY_SOAK.md](../PROXY_SOAK.md)。

真实公网阶段使用独立的 `public-workload` 和 loopback `echo-server` 模式，带应用限速、双向应用字节预算、周期检查点、中途失败报告和专用清理边界。一个受控客户端环境和一台受控公网测试服务器即可验证双接口/双路径实现；两个独立运营商出口只在宣称运营商级链路故障隔离时才是额外证据要求，不再阻塞当前开发。部署步骤见 [public-soak/README.md](public-soak/README.md)。

## 7. 回退

停止并移除单元不会修改系统网络配置：

```bash
sudo systemctl disable --now flowweave-client.service
sudo systemctl disable --now flowweave-server.service
sudo rm -f /etc/systemd/system/flowweave-client.service
sudo rm -f /etc/systemd/system/flowweave-server.service
sudo systemctl daemon-reload
```

是否删除 `/etc/flowweave` 由管理员决定。私钥和令牌删除前应先确认没有其他部署复用；CA 私钥应始终保留在可信管理机或按组织密钥销毁流程处理。
