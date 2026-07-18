# FlowWeave 部署

本目录同时包含固定目标 TCP 代理的可复现部署入口，以及 Linux VPN 的受控试点单元。固定目标代理只转发配置中的唯一 TCP 目标；VPN 单元会创建 TUN，并可按显式配置接管客户端路由或启用服务端 forwarding/NAT。两者不是同一个产品合同，也都不是开放代理或 SOCKS5 服务。

`vpn-server.json.example`、`vpn-client.json.example` 和 `vpn-identities.json.example` 是代码严格校验的 VPN 配置合同，并由独立的 `flowweave-vpn server|client` 非特权产品进程读取。该进程只附着 root helper 已准备的 TUN，不创建接口或修改地址、路由、NAT、forwarding、DNS；服务端在 UDP Endpoint 已启动后 READY，客户端只在 DNS、严格 TLS 名称校验、MPQUIC、显式路径、`FWC1 ACCEPT`、DATAGRAM 和包桥接全部完成后 READY。`flowweave-vpn-net` root helper 从同一配置派生两端点对点 TUN、client `allowed_destinations` policy routes，以及显式启用的 server forwarding/NAT；三类事务均使用 root-only 版本状态、计划指纹、随机归属标记、独占锁和原子 journal 完成幂等 prepare/cleanup/activate/deactivate、失败回滚与崩溃恢复。

`flowweave-vpn-client.service` 与 `flowweave-vpn-server.service` 现已把这些边界串成 `prepare → 非特权数据进程 READY → activate`，并让所有停止和失败路径按 `deactivate → cleanup` 收敛。只有短命、带 `+` 前缀的网络事务绕过 `User=flowweave` 和主进程沙箱；常驻数据进程保持空 capability、`NoNewPrivileges` 和只允许 `/dev/net/tun` 的设备边界。服务端另在 systemd 创建的 `0700` RuntimeDirectory 中提供 `0600` 身份 reload socket，`ExecReload` 仍以非特权用户同步等待真实提交结果。客户端对首次 READY 前和 READY 后的网络/远端可恢复失败都会在原进程内重建完整 Endpoint；离线 TUN 包立即丢弃而不在下一代际重放，policy route 只在首次 READY 后激活并保持到正常或不可恢复退出。client unit 已在 `RestrictAddressFamilies` 中显式允许 `AF_NETLINK`，但不增加 capability：link/address/route 恢复提示只能提前结束退避，监听不可用时原定时器继续工作。正式客户端 unit 用 `TimeoutStartSec=90s` 限制始终无法首次 READY 的单次激活，超时终止后仍执行反向清理和既定重启策略。真实 user-systemd 门控已覆盖正常停止、prepare 失败、READY 前立即失败与启动超时、activate 失败、运行中异常退出，以及 reload 成功/失败后主进程存活；正式单元另有静态权限合同和离线安全审计。DNS 接管、多客户端长期压力、跨版本升级/回退和真实宿主安装验收仍未完成，因此这些单元只能用于有恢复通道的受控试点，不能据此宣称生产 VPN。身份格式与剩余边界见 [VPN_IDENTITY.md](../VPN_IDENTITY.md) 和 [VPN_RESEARCH.md](../VPN_RESEARCH.md)。

客户端单元现在也由 systemd 创建独立 `0700` RuntimeDirectory 和 `0600` reload socket；非特权 `ExecReload` 同步提交本地 TLS 候选。错误配置、权限、CA 或证书/私钥组合保留旧健康连接；有效变化在同一客户端 PID、TUN packet pump、配额和 route sidecar 内触发新的严格 mTLS/MPQUIC/`FWC1` 代际。命令成功只证明本地候选已进入内存，必须再观察 `vpn_client_credentials_active` 和真实流量才能确认服务端接受新指纹。

已连接客户端收到在线 link/address 恢复提示时，不会直接销毁 Endpoint：它先等待 250 ms 让地址和源路由收敛，再换 UDP socket，并按配置槽位逐条验证带原显式源 IP 的新 PathId；只有新路径建立后才关闭旧路径并等待 `Abandoned`。一次成功后的 5 秒内合并同一 link-up 的 DAD/address 通知，普通 route 新增只排空。该过程保持 QUIC stable ID 和 `FWC1` session generation；失败会增加脱敏计数，后续连接真正结束时仍回到完整 DNS/TLS/MPQUIC/FWC1 重连合同。

客户端样例中的 `expected_client_ipv4/ipv6` 与 `expected_server_ipv4/ipv6` 必须和服务端身份文件对该客户端的静态分配完全一致。它们不是让客户端自行申请地址：服务端证书身份仍是最终授权来源；root helper 现在使用同一字段准备最小 TUN，数据进程在 `FWC1 ACCEPT` 后继续拒绝任何配置漂移。

`primary_local_ip` 与 `additional_local_ips` 是 outer path 的既有源地址，不由 FlowWeave 配置。所有地址必须属于同一族并能到达同一服务端；运行期 link/address 恢复会在 250 ms settle 后重新验证每个显式槽位，因此对应 source-policy route 也必须在这个窗口内恢复。产品不会凭接口名猜路由，也不会把失败的显式路径静默改成系统默认源地址。

开发机可运行以下只读/隔离门控：

```bash
cargo test vpn_product_config -- --nocapture
cargo test vpn_product_runtime -- --nocapture
./scripts/run_vpn_systemd_lab.sh
./scripts/run_vpn_network_lab.sh
./scripts/run_vpn_tun_lab.sh
```

`run_vpn_systemd_lab.sh` 使用当前会话的真实 user systemd manager 和临时 unit，只验证 READY/失败/清理顺序与 `NoNewPrivileges` 分界，不触碰网络；trap 会删除 unit、二进制副本和状态目录。后两条命令需要 Linux 的 `unshare`、mount namespace、`ip`、`nft`、`flock`、`ping`、`setpriv`、`jq` 以及当前用户的 `/etc/subuid`、`/etc/subgid` 映射。network 脚本专测 privileged TUN、policy-route、forwarding/NAT 事务的锁、幂等、冲突、漂移、sysctl 原值恢复、活动 fd、崩溃恢复、归属保护和中途回滚；TUN 脚本用同一 helper 准备 client/server/internet 和专项 `fwnat` 嵌套 network namespace。除既有 UDP/TCP/ICMP/MTU/失联/`SIGKILL`、路由接管、forwarding/NAT、身份恢复与完整重连矩阵外，它还删除并恢复第二条 outer link/source route，把真实固定 SNAT 从端口 40000 改为 40001，要求同一客户端 PID、QUIC stable ID 和 `FWC1` generation 内两个 PathId 都原位替换，旧路径 `Abandoned`、显式源验证、nft 新映射计数和双栈 TUN 流量同时成立，且不得出现整连接重连日志。所有等待都有上限，退出后私有 `/run` mount、nft table、sysctl 变化与全部网络空间消失。

同一 TUN 门控还生成两张由同一客户端 CA 签发、密钥不同的真实叶证书：证书/私钥错配 reload 必须拒绝且旧双栈流量继续；服务端登记重叠指纹后，客户端同步 reload 必须在原 PID/TUN pump 中建立新 QUIC/FWC1 代际；服务端删除旧指纹后，重新提交旧凭据的新会话必须收到 `unauthorized`，进程留在离线退避并能通过同一控制 socket reload 新凭据恢复。最后再主动撤销/恢复当前新指纹，原有离线丢包和身份恢复门控继续成立。

VPN 配置与身份文件应安装为 `root:flowweave 0640`：数据进程只有读取权，root helper 额外要求 root owner、同一非零 group、无符号链接且 group 不可写；私钥文件仍保持更严格的 `flowweave:flowweave 0400`。helper 当前命令合同为：

```bash
flowweave-vpn-net prepare-client /etc/flowweave/vpn-client.json /run/flowweave-vpn-client.network.json @flowweave
flowweave-vpn-net prepare-server /etc/flowweave/vpn-server.json /run/flowweave-vpn-server.network.json @flowweave
flowweave-vpn-net activate-client /etc/flowweave/vpn-client.json /run/flowweave-vpn-client.network.json
flowweave-vpn-net activate-server /etc/flowweave/vpn-server.json /run/flowweave-vpn-server.network.json
flowweave-vpn-net deactivate-client /run/flowweave-vpn-client.network.json
flowweave-vpn-net deactivate-server /run/flowweave-vpn-server.network.json
flowweave-vpn-net cleanup /run/flowweave-vpn-client.network.json
flowweave-vpn-net cleanup /run/flowweave-vpn-server.network.json
```

服务端样例把 `forwarding` 设为 `null`，因此 `activate-server` 只返回稳定结果 `disabled`，不触碰 nftables 或 sysctl。只有明确需要本机充当 VPN 路由器时才配置对象：

```json
"forwarding": {
  "manage_sysctls": false,
  "ipv4_masquerade": true,
  "ipv6_masquerade": false
}
```

`manage_sysctls=false` 是安全默认：所需地址族的 `net.ipv4.ip_forward` / `net.ipv6.conf.all.forwarding` 必须已由管理员设为 `1`，helper 永不修改。`manage_sysctls=true` 会记录原值、激活时置 `1`、撤销时仅在实时值仍符合本事务预期时恢复；这些是 network namespace 级全局开关，可能影响非 VPN 接口，只应在明确作为路由器的受控主机使用。IPv4/IPv6 masquerade 各自必须显式开启，IPv6 不会因为使用 ULA 自动 NAT；未启用 NAT 的地址族需要管理员提供返回路由。helper 不接受单一出口接口、不添加默认路由、不清空既有 ruleset，固定使用带随机 ownership comment 的 `table inet flowweave_vpn`，因此同一 network namespace 只允许一个受管服务端实例。

非特权数据进程的当前命令合同为：

```bash
flowweave-vpn server /etc/flowweave/vpn-server.json
flowweave-vpn client /etc/flowweave/vpn-client.json
flowweave-vpn reload-server /run/flowweave-vpn-server/reload.sock
flowweave-vpn reload-client /run/flowweave-vpn-client/reload.sock
```

无 `NOTIFY_SOCKET` 时，成功就绪与正常停止分别在 stdout 输出唯一稳定行 `ready`、`stopped`；存在 systemd notify socket 时还会发送 `READY=1`、`STOPPING=1` 和不含网络身份的启动/重连 `STATUS`。SIGTERM/Ctrl-C 在 DNS/QUIC 尝试或退避等待中都会立即取消且不误报 `ready`。首次连接立即尝试一次；DNS/地址暂不可用、网络性连接或握手暂时失败、可恢复路径验证失败，以及非协议违规类服务端拒绝会使用 250 ms 起步、30 秒封顶的随机指数退避重试，并尊重更长的 `retry_after_secs`。离线时，非特权 netlink 的 link 可用、地址/路由新增或事件丢失提示可在至少 250 ms 后提前结束等待；服务端 retry-after 仍不可绕过，且下一步始终重新执行完整 DNS/TLS/MPQUIC/FWC1。在线时，link/address/事件丢失触发上述同连接显式路径替换，route 新增只观察；日志 `vpn_client_connection_active`、`vpn_client_path_active`、`vpn_client_path_replaced`、`vpn_client_network_paths_rebound|failed` 只含 stable ID、generation、slot、PathId、布尔校验和计数，不含接口名或地址。进程报告另累计 `network_path_rebinds`、`network_path_replacements`、`network_path_rebind_failures`。监听失败只增加脱敏诊断并降级到原定时器。无效名称、QUIC 版本或 TLS 证书/名称校验失败、协议/地址合同不兼容、TUN/pump、本地资源不变量或 worker 故障仍快速返回非零；首次 READY 后真正的连接关闭/失败、活动代际 stale、DATAGRAM 发送失败或 packet-id 耗尽继续使用完整 Endpoint 重连，stdout 仍只出现一次 `ready`。客户端 SIGHUP 与正式 `reload-client` 都执行同一候选校验，后者可同步区分提交/拒绝；变化后的 `credential_generation`、reload/失败/activation 计数和 `vpn_client_credentials_reloaded|active|reload_failed` 日志均不包含证书、私钥、路径、地址或身份。

正式 Type=notify 单元只在主进程发送 `READY=1` 后运行 `activate-*`。没有单独的 `ExecStop=`：systemd 先终止并等待数据进程退出，再按声明顺序执行两条 `ExecStopPost=`，先撤销路由/forwarding，后清理 TUN。`ExecStopPost=` 同时覆盖 prepare 失败、READY 前失败、activate 失败、正常停止、异常退出和重启。状态保存在 `/run/flowweave-vpn-{client,server}.network.json` 及其 sidecar；若 helper 因外部漂移拒绝清理，不得手工删除状态文件后强行继续，应先查明并恢复它所记录对象的归属。

## VPN 受控试点安装

以下步骤只适用于 Linux systemd 主机，并要求管理员保留带外控制台或等价恢复通道。客户端样例默认包含 `0.0.0.0/0` 和 `::/0`；首次试点应先把客户端配置和服务端对应身份的 `allowed_destinations` 同时缩窄为一个可验证测试网段，确认停止与回退后再评估全隧道。FlowWeave 当前不管理 DNS，应用仍使用宿主 DNS 配置，可能产生 DNS 泄漏或在全隧道路由下失效。

在源码目录构建并安装两个二进制和对应 unit：

```bash
cargo build --release --bin flowweave-vpn --bin flowweave-vpn-net
getent group flowweave >/dev/null || sudo groupadd --system flowweave
id -u flowweave >/dev/null 2>&1 || \
  sudo useradd --system --gid flowweave --home-dir /nonexistent --shell /usr/bin/nologin flowweave
sudo install -d -o root -g flowweave -m 0750 /etc/flowweave
sudo install -d -o root -g root -m 0755 /usr/local/share/doc/flowweave
sudo install -o root -g root -m 0755 target/release/flowweave-vpn /usr/local/bin/flowweave-vpn
sudo install -o root -g root -m 0755 target/release/flowweave-vpn-net /usr/local/bin/flowweave-vpn-net
sudo install -o root -g root -m 0644 VPN_RESEARCH.md /usr/local/share/doc/flowweave/VPN_RESEARCH.md
```

服务端安装真实配置、身份、证书和私钥；客户端安装自己的配置、证书和私钥。样例中的占位名称、证书指纹和地址不能直接用于运行：

```bash
# 服务端主机
sudo install -o root -g flowweave -m 0640 deploy/vpn-server.json.example /etc/flowweave/vpn-server.json
sudo install -o root -g flowweave -m 0640 deploy/vpn-identities.json.example /etc/flowweave/vpn-identities.json
sudo install -o root -g root -m 0644 vpn-server.cert.der vpn-client-ca.cert.der /etc/flowweave/
sudo install -o flowweave -g flowweave -m 0400 vpn-server.key.der /etc/flowweave/vpn-server.key.der
sudo install -o root -g root -m 0644 deploy/flowweave-vpn-server.service /etc/systemd/system/flowweave-vpn-server.service

# 客户端主机
sudo install -o root -g flowweave -m 0640 deploy/vpn-client.json.example /etc/flowweave/vpn-client.json
sudo install -o root -g root -m 0644 vpn-server-ca.cert.der vpn-client.cert.der /etc/flowweave/
sudo install -o flowweave -g flowweave -m 0400 vpn-client.key.der /etc/flowweave/vpn-client.key.der
sudo install -o root -g root -m 0644 deploy/flowweave-vpn-client.service /etc/systemd/system/flowweave-vpn-client.service
```

受控安装仍建议先启动并验证服务端，再启动客户端；客户端先启动时会内部重试，但正式 unit 的 90 秒启动截止不会无限等待。`systemctl start` 只有在数据进程 READY 且网络激活成功后才返回成功；完成真实流量、路由和停止清理验证后再 `enable`：

```bash
sudo systemctl daemon-reload
sudo systemctl start flowweave-vpn-server.service
sudo systemctl status flowweave-vpn-server.service

sudo systemctl start flowweave-vpn-client.service
sudo systemctl status flowweave-vpn-client.service
# 客户端主机
ip rule show
# 服务端主机；仅 forwarding 对象已启用时存在
sudo nft list table inet flowweave_vpn

# 两端验证通过后，分别启用开机启动
sudo systemctl enable flowweave-vpn-server.service
sudo systemctl enable flowweave-vpn-client.service
```

### 服务端身份在线重载

只在同目录、同文件系统内原子替换身份文件，然后调用同步 reload；命令返回零才确认候选已进入内存。若返回 `vpn_server_reload_rejected`，服务端已明确拒绝候选，旧注册表和健康会话继续有效。若返回 connect/I/O/timeout/invalid-response 类错误，结果是不确定的：服务端可能已经提交，只是响应丢失；检查 journal 中的 `vpn_server_identity_reloaded` 或 `vpn_server_identity_reload_failed:*`，并在服务仍 active 时安全重试同一候选。磁盘文件从不自动回退，重启前必须取得一次明确成功的 reload：

```bash
sudo install -o root -g flowweave -m 0640 vpn-identities.next.json \
  /etc/flowweave/.vpn-identities.next
sudo mv -f /etc/flowweave/.vpn-identities.next /etc/flowweave/vpn-identities.json
sudo systemctl reload flowweave-vpn-server.service
sudo journalctl -u flowweave-vpn-server.service -n 50 --no-pager
```

在线允许证书指纹重叠/撤销、`client_id` 归属、目标 ACL 和 limits 变化，但仍要服从服务端全局重组预算。以下变化会同步返回非零并要求受控重启，因为它们会改变 root helper 已提交的 TUN 或 nft 真值：

- 服务端虚拟 IPv4/IPv6；
- 任一客户端虚拟地址的增加、删除或迁移；
- 已配置 forwarding 时，改变 enabled 身份的地址集合，例如直接把身份从 `true` 改为 `false`。

证书轮换顺序为：先把新指纹加入同一身份的第二槽并 reload 服务端；再把新客户端叶证书和匹配的 PKCS#8 私钥分别暂存到原文件所在目录，完成两次 rename 后同步 reload 客户端；只有 journal 出现新一代 `vpn_client_credentials_active` 且真实流量通过，才从服务端身份删除旧指纹并再次 reload。增加第二指纹不会中断旧会话；客户端本地坏候选也不会关闭旧健康会话；有效变化会在同一进程/TUN pump 中有界关闭旧 QUIC 后建立新代际，因此仍有一个短暂、不缓存包的连接切换窗口。删除正在使用的指纹会立即以 `identity_revoked` 关闭当前连接。

客户端 reload 要求 product config 解析结果完全不变，只允许现有 `server_ca_der`、`certificate_der` 和 `private_key_der` 路径的文件内容变化。以下示例假定配置仍引用 `/etc/flowweave/vpn-client.cert.der` 和 `/etc/flowweave/vpn-client.key.der`；先保存可回退副本，并确认新证书指纹已在服务端重叠槽生效：

```bash
sudo install -o root -g root -m 0644 /etc/flowweave/vpn-client.cert.der \
  /etc/flowweave/vpn-client.cert.rollback.der
sudo install -o flowweave -g flowweave -m 0400 /etc/flowweave/vpn-client.key.der \
  /etc/flowweave/vpn-client.key.rollback.der

sudo install -o root -g root -m 0644 vpn-client.next.cert.der \
  /etc/flowweave/.vpn-client.cert.next
sudo install -o flowweave -g flowweave -m 0400 vpn-client.next.key.der \
  /etc/flowweave/.vpn-client.key.next
sudo mv -f /etc/flowweave/.vpn-client.cert.next /etc/flowweave/vpn-client.cert.der
sudo mv -f /etc/flowweave/.vpn-client.key.next /etc/flowweave/vpn-client.key.der
sudo systemctl reload flowweave-vpn-client.service
sudo journalctl -u flowweave-vpn-client.service -n 80 --no-pager
```

明确的 `vpn_client_reload_rejected` 表示候选没有提交，旧内存凭据和健康会话仍有效；修复磁盘文件后可重试。connect/I/O/timeout/invalid-response 与服务端控制一样表示提交结果不确定，应先检查 `vpn_client_credentials_reloaded` / `vpn_client_credentials_reload_failed:*`，再幂等重试同一候选。命令返回零表示本地内存提交成功，不表示服务端已经授权；`vpn_client_credentials_active:credential_generation=...`、新的 connection/session 观测和真实流量才是完成证据。若新凭据在服务端仍未授权，客户端保持原 PID 离线退避且 reload socket 继续可用；在撤销旧服务端指纹前可安装回退文件并再次 reload。详细身份合同见 [VPN_IDENTITY.md](../VPN_IDENTITY.md)。

服务端 `forwarding: null` 时不存在 `flowweave_vpn` nft table，属于预期禁用状态。停止 unit 会自动先撤销网络接管再删除 TUN。若 unit 文件损坏或已被移除，可使用同一幂等 helper 做恢复；命令失败时保留状态并排查，不能用删除 journal 代替归属验证：

```bash
sudo systemctl stop flowweave-vpn-client.service
sudo /usr/local/bin/flowweave-vpn-net deactivate-client /run/flowweave-vpn-client.network.json
sudo /usr/local/bin/flowweave-vpn-net cleanup /run/flowweave-vpn-client.network.json

sudo systemctl stop flowweave-vpn-server.service
sudo /usr/local/bin/flowweave-vpn-net deactivate-server /run/flowweave-vpn-server.network.json
sudo /usr/local/bin/flowweave-vpn-net cleanup /run/flowweave-vpn-server.network.json
```

以下第 1～7 节仍是固定目标 TCP 代理的部署流程。

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
