# FlowWeave 真实公网 soak 部署

这个目录提供专用于实验的服务名、配置目录和清理边界。它不会覆盖通用的 `flowweave-server.service`，也不会自动修改主机防火墙。公网双路径实现验证只需要一个受控客户端环境和一个受控公网服务端；客户端可以使用同一物理出口上的两张受控接口/两条源路由。只有要进一步宣称独立运营商链路故障隔离时，才需要两条独立公网出口。

数据链路为：本地 workload → loopback TCP client → 双出口 MPQUIC/UDP → 公网 server → 服务端 loopback echo。echo 服务拒绝绑定非 loopback 地址，因此不会暴露成公网回显器；代理服务端仍只允许固定目标 `127.0.0.1:48080`。

## 1. 服务端 bundle

在可信构建机运行：

```bash
cargo build --release --bin flowweave-proxy --bin flowweave-proxy-soak --bin flowweave-proxy-observe
mkdir -p /tmp/flowweave-public-soak-bundle
install -m 0755 target/release/flowweave-proxy /tmp/flowweave-public-soak-bundle/
install -m 0755 target/release/flowweave-proxy-observe /tmp/flowweave-public-soak-bundle/
install -m 0755 target/release/flowweave-proxy-soak /tmp/flowweave-public-soak-bundle/
```

按上级部署文档生成私有 CA、服务端 DER 证书、PKCS#8 DER 私钥和 48 字节令牌。若直接使用服务端 IP，证书 SAN 必须写作 `IP:服务端公网地址`，客户端 `server_name` 使用同一个 IP。把以下文件放进 bundle：

- `server.conf`：以 `server.conf.example` 为模板；
- `server.cert.der`、`server.key.der`、`token`；可选提供 `token.previous`，未提供时安装器会从 `token` 安全初始化同内容的第二槽；
- 三个 release 二进制。

将整个 `deploy/public-soak` 目录和 bundle 通过已有 SSH 安全通道上传到测试服务器，然后在服务器执行：

```bash
sudo ./install-server.sh /path/to/flowweave-public-soak-bundle
```

安装器只创建以下专用状态：

- `/usr/local/libexec/flowweave-public-soak/`；
- `/etc/flowweave-public-soak/`；
- `flowweave-public-soak-echo.service`；
- `flowweave-public-soak-server.service`。

安装器不开放端口。需另行确认云防火墙和主机防火墙只允许实验所需的 QUIC/UDP 端口；不要开放 echo 的 TCP 48080，因为它只应在 loopback 上可达。

服务端与客户端代理单元均支持 `systemctl reload` 进行无重启令牌轮换；公网 soak 使用与通用部署相同的三步重叠/切换/撤销流程，详见上级 [PROXY_ROTATION.md](../../PROXY_ROTATION.md)。

## 2. 客户端双路径

以 `client.conf.example` 创建客户端配置。`primary_local_ip` 和 `additional_local_ips` 必须是客户端上真实存在且能分别路由到服务端的源地址。家庭宽带与手机 4G/5G USB 共享可提供更强的独立出口证据；同一出口下的两张接口、源策略路由和隔离 NAT 仍可验证 FlowWeave 的真实双路径建立、长时间数据完整性和运行稳定性，但不能外推为运营商故障隔离。

绑定源地址不等于自动建立策略路由。启动前必须确认两个源地址到同一服务端都能独立到达，并且观察到不同的公网 NAT 地址。FlowWeave 不修改系统路由。

配置好源策略路由后，可先运行仓库中的只读检查器；它不修改接口或路由：

```bash
scripts/verify_dual_egress.sh FIRST_LOCAL_IP SECOND_LOCAL_IP FLOWWEAVE_SERVER_IP
```

检查器的严格模式要求两个源地址实际存在、到服务端选择不同接口，并通过各自源地址观察到不同公网 IP；它适用于独立出口声明。若当前阶段使用同一公网出口，应保存两张接口、两条源路由、两个 NAT 和服务端 `path_id` 建立证据，并明确把结论限定为“同出口双接口 soak”，不伪装成独立运营商测试。

客户端代理就绪后，执行安全默认 workload：

```bash
set -o pipefail
flowweave-proxy-soak public-workload \
  --client-address 127.0.0.1:10080 \
  --duration-secs 1800 \
  --workers 1 \
  --payload-bytes 16384 \
  --upload-rate-kbps 512 \
  --application-byte-budget 230400000 \
  --checkpoint-secs 60 \
  | tee flowweave-public-soak.jsonl
```

预算统计上传与回显两个方向的应用字节，不包含 QUIC/TLS、UDP/IP 头、握手、ACK 和重传开销。因此它是应用层安全护栏，不是运营商计费字节的硬上限；移动网络试验应额外预留传输开销空间。任一连接、I/O、超时或完整性失败都会停止新流，输出 `failure_detected` 和最终失败报告。Ctrl-C/SIGTERM 会输出 `interrupted` 最终报告，并判为未完成。

## 3. 证据与清理

同时保存客户端 workload JSONL、两端 `flowweave.runtime.v1` 日志、健康门控结果、接口/路由、两条出口的公网 NAT 地址、提交 SHA、内核和 Rust 版本。停止后分别对客户端和服务端日志执行严格 `flowweave-proxy-observe verify`。

服务端实验结束后，在上传的目录执行：

```bash
sudo ./remove-server.sh --confirm
```

清理器只触碰上述公网 soak 专用单元、配置和二进制；不会删除 `flowweave` 系统用户，不会操作通用 FlowWeave 服务，也不会修改防火墙。
