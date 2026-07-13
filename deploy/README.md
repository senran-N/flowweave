# FlowWeave 最小代理部署

当前入口只转发一个固定 TCP 目标：本地应用连接客户端 loopback TCP 端口，客户端通过标准 TLS 1.3 MPQUIC 连接服务端，服务端只允许配置中的唯一 `allowed_target`。它不是 TUN、SOCKS5、开放代理或 UDP 转发器。

## 1. 构建和安装

在源码目录使用 Rust 1.88 或更高版本：

```bash
cargo test proxy --lib
cargo build --release --bin flowweave-proxy
sudo install -o root -g root -m 0755 target/release/flowweave-proxy /usr/local/bin/flowweave-proxy
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
```

不要把 `ca.key.pem` 放到服务端或客户端。服务端只需要 `server.cert.der`、`server.key.der` 和 `token`；客户端只需要 `ca.cert.der` 和同一份 `token`。令牌应通过已有的安全通道传输，不能粘贴进配置、命令行或日志。

## 3. 服务端配置

服务端开放的是 UDP，不是 TCP。把文件安装到服务端：

```bash
sudo install -o root -g flowweave -m 0640 server.conf.example /etc/flowweave/server.conf
sudo install -o root -g root -m 0644 server.cert.der /etc/flowweave/server.cert.der
sudo install -o flowweave -g flowweave -m 0400 server.key.der /etc/flowweave/server.key.der
sudo install -o flowweave -g flowweave -m 0400 token /etc/flowweave/token
sudo install -o root -g root -m 0644 flowweave-server.service /etc/systemd/system/flowweave-server.service
```

编辑 `/etc/flowweave/server.conf`：

- `listen` 是 QUIC/UDP 监听地址；防火墙和云安全组必须允许该 UDP 端口。
- `allowed_target` 必须是服务端可连接的显式 IP:port。服务端拒绝域名和客户端请求的其他目标，因此不会退化成开放代理。
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

日志只报告配置、TLS、路径、状态码和 I/O 错误，不输出令牌、私钥或完整应用载荷。客户端 QUIC 连接失效时进程退出，由 systemd 的 `Restart=on-failure` 执行外部重启；程序内部没有隐藏重连器。

## 6. 回退

停止并移除单元不会修改系统网络配置：

```bash
sudo systemctl disable --now flowweave-client.service
sudo systemctl disable --now flowweave-server.service
sudo rm -f /etc/systemd/system/flowweave-client.service
sudo rm -f /etc/systemd/system/flowweave-server.service
sudo systemctl daemon-reload
```

是否删除 `/etc/flowweave` 由管理员决定。私钥和令牌删除前应先确认没有其他部署复用；CA 私钥应始终保留在可信管理机或按组织密钥销毁流程处理。
