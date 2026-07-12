#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

mode="${1:-smoke}"
case "$mode" in
    smoke)
        test_name="controlled_bad_network_lab"
        ;;
    failover)
        test_name="failover_five_seed_screening_lab"
        ;;
    formal-a)
        test_name="failover_formal_bidirectional_lab"
        ;;
    diagnose-a)
        test_name="failover_timeline_diagnostic_lab"
        ;;
    diagnose-no-pto)
        test_name="failover_no_pto_diagnostic_lab"
        ;;
    diagnose-abandon)
        test_name="failover_abandon_reinjection_diagnostic_lab"
        ;;
    diagnose-ack-progress)
        test_name="failover_ack_progress_reinjection_diagnostic_lab"
        ;;
    diagnose-ack-escape-representative)
        test_name="failover_ack_escape_representative_diagnostic_lab"
        ;;
    screen)
        test_name="scheduler_five_seed_screening_lab"
        ;;
    long)
        test_name="scheduler_long_duration_benchmark_lab"
        ;;
    *)
        echo "用法：$0 [smoke|failover|formal-a|diagnose-a|diagnose-no-pto|diagnose-abandon|diagnose-ack-progress|diagnose-ack-escape-representative|screen|long]" >&2
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
if [[ "$FLOWWEAVE_LAB_MODE" == "long" || "$FLOWWEAVE_LAB_MODE" == "formal-a" || "$FLOWWEAVE_LAB_MODE" == "diagnose-a" || "$FLOWWEAVE_LAB_MODE" == "diagnose-no-pto" || "$FLOWWEAVE_LAB_MODE" == "diagnose-abandon" || "$FLOWWEAVE_LAB_MODE" == "diagnose-ack-progress" || "$FLOWWEAVE_LAB_MODE" == "diagnose-ack-escape-representative" ]]; then
    cargo test --release --test network_lab "$FLOWWEAVE_LAB_TEST" -- --ignored --nocapture --test-threads=1
else
    cargo test --test network_lab "$FLOWWEAVE_LAB_TEST" -- --ignored --nocapture --test-threads=1
fi
'
