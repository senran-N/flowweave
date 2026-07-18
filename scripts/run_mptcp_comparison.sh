#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
mode="${1:-wire}"

case "$mode" in
    wire|a-smoke|a-formal|b-smoke|b-formal)
        ;;
    *)
        echo "用法：$0 [wire|a-smoke|a-formal|b-smoke|b-formal]" >&2
        exit 2
        ;;
esac

for required_command in cargo ip nft readlink sysctl tc unshare uname; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        echo "缺少 MPTCP 对照所需命令：$required_command" >&2
        exit 1
    fi
done

if [[ "$(cat /proc/sys/net/mptcp/enabled 2>/dev/null || true)" != "1" ]]; then
    echo "当前内核没有启用 MPTCP" >&2
    exit 1
fi

cd "$repo_root"
cargo build --release --bin flowweave-mptcp-comparison

parent_netns="$(readlink /proc/self/ns/net)"
FLOWWEAVE_MPTCP_MODE="$mode" FLOWWEAVE_PARENT_NETNS="$parent_netns" \
    unshare --user --map-root-user --net -- bash -c '
set -euo pipefail

ip link set lo up
sysctl -q -w net.mptcp.enabled=1
sysctl -q -w net.mptcp.path_manager=kernel
sysctl -q -w net.mptcp.scheduler=default
sysctl -q -w net.ipv4.tcp_congestion_control=cubic

tc qdisc add dev lo root handle 1: prio bands 3
tc qdisc add dev lo parent 1:1 handle 10: netem limit 10000 delay 1ms
tc qdisc add dev lo parent 1:2 handle 20: netem limit 10000 delay 1ms

tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip src 127.0.0.3/32 flowid 1:1
tc filter add dev lo protocol ip parent 1: prio 2 u32 match ip dst 127.0.0.3/32 flowid 1:1
tc filter add dev lo protocol ip parent 1: prio 3 u32 match ip src 127.0.0.4/32 flowid 1:2
tc filter add dev lo protocol ip parent 1: prio 4 u32 match ip dst 127.0.0.4/32 flowid 1:2
tc filter add dev lo protocol ip parent 1: prio 20 u32 match u32 0 0 flowid 1:3

export FLOWWEAVE_MPTCP_LAB=1
exec ./target/release/flowweave-mptcp-comparison "$FLOWWEAVE_MPTCP_MODE"
'
