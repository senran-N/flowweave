#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
result_path="$repo_root/benchmark-results/2026-07-13-b-separated-ingress-observability-v1-smoke.csv"

for required_command in cargo getconf ip nsenter readlink tc unshare; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        echo "缺少 B ingress 实验所需命令：$required_command" >&2
        exit 1
    fi
done

if [[ -e "$result_path" ]]; then
    echo "拒绝覆盖历史 B ingress 结果：$result_path" >&2
    exit 1
fi

cd "$repo_root"
cargo build --release --bin b_ingress_observability

parent_netns="$(readlink /proc/self/ns/net)"
FLOWWEAVE_PARENT_NETNS="$parent_netns" unshare --user --map-root-user --net -- bash -c '
set -euo pipefail

unshare --net -- sleep infinity &
receiver_pid=$!
cleanup() {
    kill "$receiver_pid" 2>/dev/null || true
    wait "$receiver_pid" 2>/dev/null || true
}
trap cleanup EXIT

for attempt in 1 2 3 4 5; do
    if [[ -e "/proc/$receiver_pid/ns/net" ]]; then
        break
    fi
    sleep 0.1
done
if [[ ! -e "/proc/$receiver_pid/ns/net" ]]; then
    echo "接收网络命名空间没有就绪" >&2
    exit 1
fi

ip link add fwbs1 type veth peer name fwbr1
ip link add fwbs2 type veth peer name fwbr2
ip link set fwbr1 netns "$receiver_pid"
ip link set fwbr2 netns "$receiver_pid"

ip link set lo up
ip addr add 10.241.1.1/30 dev fwbs1
ip addr add 10.241.2.1/30 dev fwbs2
ip link set dev fwbs1 mtu 1500 up
ip link set dev fwbs2 mtu 1500 up

nsenter -t "$receiver_pid" -n -- ip link set lo up
nsenter -t "$receiver_pid" -n -- ip addr add 10.241.1.2/30 dev fwbr1
nsenter -t "$receiver_pid" -n -- ip addr add 10.241.2.2/30 dev fwbr2
nsenter -t "$receiver_pid" -n -- ip link set dev fwbr1 mtu 1500 up
nsenter -t "$receiver_pid" -n -- ip link set dev fwbr2 mtu 1500 up

tc qdisc add dev fwbs1 root handle 10: tbf rate 8mbit burst 32kb peakrate 8001kbit minburst 1600 latency 100ms
tc qdisc add dev fwbs1 parent 10:1 handle 11: netem limit 10000 delay 15ms loss 0.1% seed 1101
tc qdisc add dev fwbs2 root handle 20: tbf rate 25mbit burst 32kb peakrate 25001kbit minburst 1600 latency 100ms
tc qdisc add dev fwbs2 parent 20:1 handle 21: netem limit 10000 delay 50ms loss 0.1% seed 2201

export FLOWWEAVE_B_INGRESS_LAB=1
export FLOWWEAVE_B_INGRESS_RECEIVER_PID="$receiver_pid"
export FLOWWEAVE_B_INGRESS_VERSION=v1

set +e
./target/release/b_ingress_observability
status=$?
set -e

tc -s qdisc show dev fwbs1
tc -s qdisc show dev fwbs2
nsenter -t "$receiver_pid" -n -- ip -s link show dev fwbr1
nsenter -t "$receiver_pid" -n -- ip -s link show dev fwbr2
exit "$status"
'
