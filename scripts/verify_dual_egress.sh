#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "用法：$0 LOCAL_IP_A LOCAL_IP_B FLOWWEAVE_SERVER_IP [PUBLIC_IP_URL]" >&2
  exit 2
fi

local_ip_a=$1
local_ip_b=$2
server_ip=$3
public_ip_url=${4:-https://api.ipify.org}

for command in ip curl; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "缺少命令：${command}" >&2
    exit 2
  fi
done

assigned_addresses=$(ip -o addr show | awk '{print $4}' | cut -d/ -f1)
for source_ip in "${local_ip_a}" "${local_ip_b}"; do
  if ! grep -Fxq "${source_ip}" <<<"${assigned_addresses}"; then
    echo "本机接口上不存在地址：${source_ip}" >&2
    exit 1
  fi
done

route_a=$(ip route get "${server_ip}" from "${local_ip_a}")
route_b=$(ip route get "${server_ip}" from "${local_ip_b}")
device_a=$(awk '{for (index = 1; index <= NF; index++) if ($index == "dev") {print $(index + 1); exit}}' <<<"${route_a}")
device_b=$(awk '{for (index = 1; index <= NF; index++) if ($index == "dev") {print $(index + 1); exit}}' <<<"${route_b}")

if [[ -z ${device_a} || -z ${device_b} ]]; then
  echo "无法从源地址路由中识别接口" >&2
  exit 1
fi
if [[ ${device_a} == "${device_b}" ]]; then
  echo "两个源地址仍通过同一接口 ${device_a}，不满足双接口条件" >&2
  exit 1
fi

public_a=$(curl --interface "${local_ip_a}" --connect-timeout 10 --max-time 20 --fail --silent --show-error "${public_ip_url}")
public_b=$(curl --interface "${local_ip_b}" --connect-timeout 10 --max-time 20 --fail --silent --show-error "${public_ip_url}")

if [[ -z ${public_a} || -z ${public_b} ]]; then
  echo "公网地址检测返回空结果" >&2
  exit 1
fi
if [[ ${public_a} == "${public_b}" ]]; then
  echo "两个接口观察到同一公网地址 ${public_a}，不能证明独立出口" >&2
  exit 1
fi

printf '双出口只读检查通过\n'
printf 'A local=%s dev=%s public=%s\n' "${local_ip_a}" "${device_a}" "${public_a}"
printf 'B local=%s dev=%s public=%s\n' "${local_ip_b}" "${device_b}" "${public_b}"
printf 'server=%s\n' "${server_ip}"
