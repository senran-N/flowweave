# 2026-07-13 公网同出口双接口 smoke

## 结论

在关闭会拦截原始 UDP 的本地 VPN 后，FlowWeave 完成了真实公网 TLS/MPQUIC 单接口 smoke，以及“两张客户端接口、两条源策略路由、两个 Docker NAT、同一个物理公网出口”的双路径 smoke。双路径运行中服务端明确观察到产品路径 1 和路径 2 建立，临时引导路径 0 被正常放弃并丢弃；最终 workload 15/15 条流完整回显，零失败、零超时，`stage_pass=true`。

该结果证明公网 TLS、令牌授权、固定目标、MPQUIC 路径验证、双接口源路由、NAT、持续建流、字节完整性和有界退出能够共同工作。它不证明两个独立运营商出口，也不替代 Wi-Fi + 蜂窝切换、跨运营商故障或长时间 soak。

## 环境

- 源码提交：`c464385`；
- 客户端：Ubuntu VirtualBox，单一物理出口；
- 临时接口：`172.30.10.2` 与 `172.30.20.2`；
- 临时源路由：表 101 经第一 Docker bridge，表 102 经第二 Docker bridge；
- 服务端：受控 Ubuntu 24.04.4 LTS 公网测试机；
- 外层传输：TLS 1.3 MPQUIC/UDP；
- 固定目标：服务端 loopback TCP echo；
- 测试结束后容器、两张 Docker 网络和临时配置均已删除。

## 双路径证据

服务端为同一连接记录了：

```text
path_id=1 change=established
path_id=2 change=established
path_id=0 change=abandoned reason=remote_abandoned
path_id=0 change=discarded lost_bytes=0 lost_packets=0
```

公网 workload 最终报告的稳定字段为：

```json
{
  "schema": "flowweave.proxy-public-soak.v1",
  "event": "final",
  "stage_pass": true,
  "stop_reason": "duration_elapsed",
  "configured_duration_ms": 10000,
  "elapsed_ms": 10426,
  "workers": 1,
  "payload_bytes": 16384,
  "upload_rate_bps": 512000,
  "application_byte_budget": 2000000,
  "attempted_flows": 15,
  "completed_flows": 15,
  "failed_flows": 0,
  "timed_out_flows": 0,
  "reserved_application_bytes": 491520,
  "sent_bytes": 245760,
  "echoed_bytes": 245760,
  "carrier_overhead_included": false
}
```

客户端最终代理指标为一条连接、15 条流、上传与下载各 245,760 字节、零拒绝、零超时、零上游错误、一次优雅退出和零强制退出。

## VPN 诊断

VPN 开启时客户端发出了 QUIC UDP，但服务端抓不到 UDP 443/4433/8443；只有 UDP 53 经另一个中继源地址到达。关闭 VPN 后，原配置的 UDP 4433 立即完成 TLS/QUIC 握手。因此本轮阻断来自本地 VPN/代理路径，而不是测试服务器进程或主机防火墙。

## 后续边界

下一阶段只能在具备两条真实独立出口时完成，例如家庭宽带加手机 4G/5G、两台分别位于不同网络的受控客户端，或能够明确绑定两个 WAN 的专用路由器。若短期无法提供该条件，项目应保留“同出口公网双接口已证明、独立双出口尚未证明”的准确表述。
