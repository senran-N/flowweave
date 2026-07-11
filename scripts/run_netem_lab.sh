#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

for required_command in unshare ip tc cargo readlink; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        echo "缺少实验所需命令：$required_command" >&2
        exit 1
    fi
done

cd "$repo_root"

parent_netns="$(readlink /proc/self/ns/net)"

FLOWWEAVE_PARENT_NETNS="$parent_netns" unshare --user --map-root-user --net -- bash -c '
set -euo pipefail

ip link set lo up

tc qdisc add dev lo root handle 1: prio bands 3
tc qdisc add dev lo parent 1:1 handle 10: netem delay 1ms
tc qdisc add dev lo parent 1:2 handle 20: netem delay 1ms

tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip src 127.0.0.2/32 flowid 1:2
tc filter add dev lo protocol ip parent 1: prio 2 u32 match ip dst 127.0.0.2/32 flowid 1:2
tc filter add dev lo protocol ip parent 1: prio 3 u32 match u32 0 0 flowid 1:1

export FLOWWEAVE_NETEM_LAB=1
cargo test --test network_lab -- --ignored --nocapture --test-threads=1
'
