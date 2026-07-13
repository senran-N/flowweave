#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "install-server.sh 必须以 root 运行" >&2
  exit 2
fi

if [[ $# -ne 1 ]]; then
  echo "用法：$0 BUNDLE_DIR" >&2
  exit 2
fi

bundle_dir=$(realpath "$1")
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
required_files=(
  flowweave-proxy
  flowweave-proxy-observe
  flowweave-proxy-soak
  server.conf
  server.cert.der
  server.key.der
  token
)

for file in "${required_files[@]}"; do
  if [[ ! -f "${bundle_dir}/${file}" ]]; then
    echo "缺少部署文件：${bundle_dir}/${file}" >&2
    exit 2
  fi
done

if ! getent group flowweave >/dev/null; then
  groupadd --system flowweave
fi
if ! id -u flowweave >/dev/null 2>&1; then
  useradd --system --gid flowweave --home-dir /nonexistent --shell /usr/sbin/nologin flowweave
fi

install -d -o root -g root -m 0755 /usr/local/libexec/flowweave-public-soak
install -o root -g root -m 0755 "${bundle_dir}/flowweave-proxy" /usr/local/libexec/flowweave-public-soak/flowweave-proxy
install -o root -g root -m 0755 "${bundle_dir}/flowweave-proxy-observe" /usr/local/libexec/flowweave-public-soak/flowweave-proxy-observe
install -o root -g root -m 0755 "${bundle_dir}/flowweave-proxy-soak" /usr/local/libexec/flowweave-public-soak/flowweave-proxy-soak

install -d -o root -g flowweave -m 0750 /etc/flowweave-public-soak
install -o root -g flowweave -m 0640 "${bundle_dir}/server.conf" /etc/flowweave-public-soak/server.conf
install -o root -g root -m 0644 "${bundle_dir}/server.cert.der" /etc/flowweave-public-soak/server.cert.der
install -o flowweave -g flowweave -m 0400 "${bundle_dir}/server.key.der" /etc/flowweave-public-soak/server.key.der
install -o flowweave -g flowweave -m 0400 "${bundle_dir}/token" /etc/flowweave-public-soak/token
if [[ -f "${bundle_dir}/token.previous" ]]; then
  previous_token_source="${bundle_dir}/token.previous"
else
  previous_token_source="${bundle_dir}/token"
fi
install -o flowweave -g flowweave -m 0400 "${previous_token_source}" /etc/flowweave-public-soak/token.previous

install -o root -g root -m 0644 "${script_dir}/flowweave-public-soak-echo.service" /etc/systemd/system/flowweave-public-soak-echo.service
install -o root -g root -m 0644 "${script_dir}/flowweave-public-soak-server.service" /etc/systemd/system/flowweave-public-soak-server.service

systemctl daemon-reload
systemctl enable --now flowweave-public-soak-echo.service
systemctl enable --now flowweave-public-soak-server.service
systemctl --no-pager --full status flowweave-public-soak-echo.service flowweave-public-soak-server.service

echo "安装完成。脚本没有修改主机防火墙或云防火墙；请单独确认 server.conf 中的 QUIC/UDP 端口已放行。"
