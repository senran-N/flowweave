#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "remove-server.sh 必须以 root 运行" >&2
  exit 2
fi

if [[ ${1:-} != "--confirm" || $# -ne 1 ]]; then
  echo "用法：$0 --confirm" >&2
  echo "该操作会停止公网 soak 服务并删除专用配置、证书私钥和令牌。" >&2
  exit 2
fi

systemctl disable --now flowweave-public-soak-server.service 2>/dev/null || true
systemctl disable --now flowweave-public-soak-echo.service 2>/dev/null || true
rm -f /etc/systemd/system/flowweave-public-soak-server.service
rm -f /etc/systemd/system/flowweave-public-soak-echo.service
rm -rf /etc/flowweave-public-soak
rm -rf /usr/local/libexec/flowweave-public-soak
systemctl daemon-reload
systemctl reset-failed flowweave-public-soak-server.service flowweave-public-soak-echo.service 2>/dev/null || true

echo "公网 soak 服务端专用文件已清理；flowweave 系统用户和防火墙规则未改动。"
