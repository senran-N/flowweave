#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

mode="${1:-smoke}"
case "$mode" in
    smoke)
        test_name="controlled_bad_network_lab"
        ;;
    screen)
        test_name="scheduler_five_seed_screening_lab"
        ;;
    bbr-sensor)
        test_name="bbr_capacity_five_seed_lab"
        ;;
    long)
        test_name="scheduler_long_duration_benchmark_lab"
        ;;
    *)
        echo "用法：$0 [smoke|screen|bbr-sensor|long]" >&2
        exit 2
        ;;
esac

for required_command in unshare ip tc cargo readlink getconf; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        echo "缺少实验所需命令：$required_command" >&2
        exit 1
    fi
done

cd "$repo_root"

parent_netns="$(readlink /proc/self/ns/net)"

FLOWWEAVE_LAB_MODE="$mode" FLOWWEAVE_LAB_TEST="$test_name" FLOWWEAVE_PARENT_NETNS="$parent_netns" unshare --user --map-root-user --net -- bash -c '
set -euo pipefail

ip link set lo up

tc qdisc add dev lo root handle 1: prio bands 3
tc qdisc add dev lo parent 1:1 handle 10: netem delay 1ms
tc qdisc add dev lo parent 1:2 handle 20: netem delay 1ms

tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip src 127.0.0.2/32 flowid 1:2
tc filter add dev lo protocol ip parent 1: prio 2 u32 match ip dst 127.0.0.2/32 flowid 1:2
tc filter add dev lo protocol ip parent 1: prio 3 u32 match u32 0 0 flowid 1:1

export FLOWWEAVE_NETEM_LAB=1
if [[ "$FLOWWEAVE_LAB_MODE" == "long" ]]; then
    cargo test --release --test network_lab "$FLOWWEAVE_LAB_TEST" -- --ignored --nocapture --test-threads=1
else
    cargo test --test network_lab "$FLOWWEAVE_LAB_TEST" -- --ignored --nocapture --test-threads=1
fi
'
