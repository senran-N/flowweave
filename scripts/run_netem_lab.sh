#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

mode="${1:-smoke}"
case "$mode" in
    smoke)
        test_name="controlled_bad_network_lab"
        ;;
    c-v3-wire)
        test_name="c_pair_xor_global_10_2_v3_wire_latency_smoke_lab"
        ;;
    c-controller-gate)
        test_name="c_small_datagram_controller_gate_v1_smoke_lab"
        ;;
    c-v4-smoke)
        test_name="c_bbr3_pair_xor_global_10_2_v4_smoke_lab"
        ;;
    c-v4-formal)
        test_name="c_bbr3_pair_xor_global_10_2_v4_formal_lab"
        ;;
    c-v12-smoke)
        test_name="c_bbr3_no_gso_compact7_two_of_three_global_40_3_v12_smoke_lab"
        ;;
    c-v12-formal)
        test_name="c_bbr3_no_gso_compact7_two_of_three_global_40_3_v12_formal_lab"
        ;;
    c-v2-smoke)
        test_name="c_batched_duplication_v2_five_message_smoke_lab"
        ;;
    c-v2-formal)
        test_name="c_batched_duplication_v2_five_message_formal_lab"
        ;;
    hysteria-c-wire)
        test_name="hysteria_c_wiring_lab"
        ;;
    hysteria-c-smoke)
        test_name="hysteria_c_smoke_lab"
        ;;
    hysteria-c-formal)
        test_name="hysteria_c_formal_lab"
        ;;
    hysteria-b-smoke)
        test_name="hysteria_b_smoke_lab"
        ;;
    hysteria-b-formal)
        test_name="hysteria_b_formal_lab"
        ;;
    hysteria-a-wire)
        test_name="hysteria_a_wiring_lab"
        ;;
    hysteria-a-smoke)
        test_name="hysteria_a_smoke_lab"
        ;;
    hysteria-a-formal)
        test_name="hysteria_a_formal_lab"
        ;;
    failover)
        test_name="failover_five_seed_screening_lab"
        ;;
    formal-a)
        test_name="failover_formal_bidirectional_lab"
        ;;
    formal-gap-watch)
        test_name="failover_feedback_gap_watch_formal_bidirectional_lab"
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
    diagnose-second-gap)
        test_name="failover_second_gap_stream_state_diagnostic_lab"
        ;;
    diagnose-feedback-handoff)
        test_name="failover_feedback_handoff_representative_diagnostic_lab"
        ;;
    diagnose-feedback-handoff-1103)
        test_name="failover_feedback_handoff_seed_1103_diagnostic_lab"
        ;;
    diagnose-feedback-handoff-1104)
        test_name="failover_feedback_handoff_seed_1104_diagnostic_lab"
        ;;
    diagnose-feedback-snapshot-1104)
        test_name="failover_feedback_snapshot_seed_1104_diagnostic_lab"
        ;;
    diagnose-feedback-snapshot-stability)
        test_name="failover_feedback_snapshot_seed_1104_stability_lab"
        ;;
    diagnose-feedback-snapshot-response-stability)
        test_name="failover_feedback_snapshot_seed_1104_response_stability_lab"
        ;;
    diagnose-feedback-probe-stability)
        test_name="failover_feedback_probe_seed_1104_stability_lab"
        ;;
    diagnose-feedback-evidence-stability)
        test_name="failover_feedback_evidence_seed_1104_stability_lab"
        ;;
    diagnose-feedback-evidence-response-stability)
        test_name="failover_feedback_evidence_seed_1104_response_stability_lab"
        ;;
    diagnose-feedback-gap-rescue-stability)
        test_name="failover_feedback_gap_rescue_seed_1104_stability_lab"
        ;;
    diagnose-feedback-gap-watch-stability)
        test_name="failover_feedback_gap_watch_seed_1104_stability_lab"
        ;;
    diagnose-application-progress-failures)
        test_name="failover_application_progress_formal_failures_diagnostic_lab"
        ;;
    diagnose-application-progress-stability)
        test_name="failover_application_progress_seed_1104_stability_lab"
        ;;
    diagnose-application-progress-age)
        test_name="failover_application_progress_age_seed_1104_smoke_lab"
        ;;
    diagnose-application-progress-age-stability)
        test_name="failover_application_progress_age_seed_1104_stability_lab"
        ;;
    diagnose-application-progress-deadline)
        test_name="failover_application_progress_deadline_seed_1104_smoke_lab"
        ;;
    diagnose-application-progress-deadline-stability)
        test_name="failover_application_progress_deadline_seed_1104_stability_lab"
        ;;
    diagnose-application-progress-version)
        test_name="failover_application_progress_version_seed_1104_smoke_lab"
        ;;
    diagnose-application-progress-version-stability)
        test_name="failover_application_progress_version_seed_1104_stability_lab"
        ;;
    diagnose-application-progress-version-failures)
        test_name="failover_application_progress_version_formal_failures_lab"
        ;;
    diagnose-stream-progress-reverse-8)
        test_name="failover_stream_progress_reverse_round_8_lab"
        ;;
    diagnose-stream-progress-failures)
        test_name="failover_stream_progress_formal_failures_lab"
        ;;
    diagnose-stream-progress-stability)
        test_name="failover_stream_progress_seed_1104_stability_lab"
        ;;
    diagnose-multi-flight-budget)
        test_name="failover_multi_flight_budget_seed_1104_smoke_lab"
        ;;
    diagnose-multi-flight-failures)
        test_name="failover_multi_flight_budget_formal_failures_lab"
        ;;
    diagnose-stable-multi-flight)
        test_name="failover_stable_multi_flight_seed_1104_smoke_lab"
        ;;
    diagnose-stable-multi-flight-failures)
        test_name="failover_stable_multi_flight_formal_failures_lab"
        ;;
    diagnose-stable-multi-flight-stability)
        test_name="failover_stable_multi_flight_seed_1104_stability_lab"
        ;;
    diagnose-delivery-gap-watch-reverse-8)
        test_name="failover_delivery_gap_watch_reverse_round_8_lab"
        ;;
    diagnose-delivery-gap-watch)
        test_name="failover_delivery_gap_watch_seed_1104_smoke_lab"
        ;;
    diagnose-delivery-gap-watch-failures)
        test_name="failover_delivery_gap_watch_formal_failures_lab"
        ;;
    diagnose-delivery-gap-watch-stability)
        test_name="failover_delivery_gap_watch_seed_1104_stability_lab"
        ;;
    diagnose-alternative-stability-reverse-8)
        test_name="failover_alternative_stability_reverse_round_8_lab"
        ;;
    diagnose-alternative-stability)
        test_name="failover_alternative_stability_seed_1104_smoke_lab"
        ;;
    diagnose-alternative-stability-failures)
        test_name="failover_alternative_stability_formal_failures_lab"
        ;;
    diagnose-alternative-stability-stability)
        test_name="failover_alternative_stability_seed_1104_stability_lab"
        ;;
    diagnose-alternative-stability-formal)
        test_name="failover_alternative_stability_formal_bidirectional_lab"
        ;;
    diagnose-stream-progress-snapshot-forward-10)
        test_name="failover_stream_progress_snapshot_forward_round_10_lab"
        ;;
    diagnose-stream-progress-snapshot)
        test_name="failover_stream_progress_snapshot_seed_1104_smoke_lab"
        ;;
    diagnose-stream-progress-snapshot-failures)
        test_name="failover_stream_progress_snapshot_formal_failures_lab"
        ;;
    diagnose-stream-progress-snapshot-stability)
        test_name="failover_stream_progress_snapshot_seed_1104_stability_lab"
        ;;
    diagnose-stream-progress-snapshot-formal)
        test_name="failover_stream_progress_snapshot_formal_bidirectional_lab"
        ;;
    screen)
        test_name="scheduler_five_seed_screening_lab"
        ;;
    long)
        test_name="scheduler_long_duration_benchmark_lab"
        ;;
    b-controller-gate)
        test_name="b_noq_bbr3_controller_gate_v1_smoke_lab"
        ;;
    b-declared-epoch)
        test_name="b_declared_backlogged_epoch_v1_smoke_lab"
        ;;
    b-continuous-formal)
        test_name="b_cubic_noq_continuous_formal_v1_lab"
        ;;
    *)
        echo "用法：$0 [smoke|c-v3-wire|c-controller-gate|c-v4-smoke|c-v4-formal|c-v12-smoke|c-v12-formal|c-v2-smoke|c-v2-formal|hysteria-c-wire|hysteria-c-smoke|hysteria-c-formal|hysteria-b-smoke|hysteria-b-formal|hysteria-a-wire|hysteria-a-smoke|hysteria-a-formal|failover|formal-a|formal-gap-watch|diagnose-a|diagnose-no-pto|diagnose-abandon|diagnose-ack-progress|diagnose-ack-escape-representative|diagnose-second-gap|diagnose-feedback-handoff|diagnose-feedback-handoff-1103|diagnose-feedback-handoff-1104|diagnose-feedback-snapshot-1104|diagnose-feedback-snapshot-stability|diagnose-feedback-snapshot-response-stability|diagnose-feedback-probe-stability|diagnose-feedback-evidence-stability|diagnose-feedback-evidence-response-stability|diagnose-feedback-gap-rescue-stability|diagnose-feedback-gap-watch-stability|diagnose-application-progress-failures|diagnose-application-progress-stability|diagnose-application-progress-age|diagnose-application-progress-age-stability|diagnose-application-progress-deadline|diagnose-application-progress-deadline-stability|diagnose-application-progress-version|diagnose-application-progress-version-stability|diagnose-application-progress-version-failures|diagnose-stream-progress-reverse-8|diagnose-stream-progress-failures|diagnose-stream-progress-stability|diagnose-multi-flight-budget|diagnose-multi-flight-failures|diagnose-stable-multi-flight|diagnose-stable-multi-flight-failures|diagnose-stable-multi-flight-stability|diagnose-delivery-gap-watch-reverse-8|diagnose-delivery-gap-watch|diagnose-delivery-gap-watch-failures|diagnose-delivery-gap-watch-stability|diagnose-alternative-stability-reverse-8|diagnose-alternative-stability|diagnose-alternative-stability-failures|diagnose-alternative-stability-stability|diagnose-alternative-stability-formal|diagnose-stream-progress-snapshot-forward-10|diagnose-stream-progress-snapshot|diagnose-stream-progress-snapshot-failures|diagnose-stream-progress-snapshot-stability|diagnose-stream-progress-snapshot-formal|screen|long|b-controller-gate|b-declared-epoch|b-continuous-formal]" >&2
        exit 2
        ;;
esac

for required_command in unshare ip tc cargo readlink getconf; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        echo "缺少实验所需命令：$required_command" >&2
        exit 1
    fi
done

hysteria_binary=""
case "$mode" in
    hysteria-*)
        for required_command in nft sha256sum; do
            if ! command -v "$required_command" >/dev/null 2>&1; then
                echo "缺少 Hysteria 对照所需命令：$required_command" >&2
                exit 1
            fi
        done
        hysteria_binary="$("$script_dir/prepare_hysteria.sh")"
        ;;
esac

cd "$repo_root"

parent_netns="$(readlink /proc/self/ns/net)"

FLOWWEAVE_LAB_MODE="$mode" FLOWWEAVE_LAB_TEST="$test_name" FLOWWEAVE_PARENT_NETNS="$parent_netns" FLOWWEAVE_HYSTERIA_BIN="$hysteria_binary" unshare --user --map-root-user --net -- bash -c '
set -euo pipefail

ip link set lo up

tc qdisc add dev lo root handle 1: prio bands 3
tc qdisc add dev lo parent 1:1 handle 10: netem delay 1ms
tc qdisc add dev lo parent 1:2 handle 20: netem delay 1ms

tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip src 127.0.0.3/32 flowid 1:3
tc filter add dev lo protocol ip parent 1: prio 2 u32 match ip dst 127.0.0.3/32 flowid 1:3
tc filter add dev lo protocol ip parent 1: prio 3 u32 match ip src 127.0.0.4/32 flowid 1:3
tc filter add dev lo protocol ip parent 1: prio 4 u32 match ip dst 127.0.0.4/32 flowid 1:3
tc filter add dev lo protocol ip parent 1: prio 10 u32 match ip src 127.0.0.2/32 flowid 1:2
tc filter add dev lo protocol ip parent 1: prio 11 u32 match ip dst 127.0.0.2/32 flowid 1:2
tc filter add dev lo protocol ip parent 1: prio 20 u32 match u32 0 0 flowid 1:1

export FLOWWEAVE_NETEM_LAB=1
if [[ "$FLOWWEAVE_LAB_MODE" == "hysteria-c-wire" || "$FLOWWEAVE_LAB_MODE" == "hysteria-c-smoke" || "$FLOWWEAVE_LAB_MODE" == "hysteria-c-formal" || "$FLOWWEAVE_LAB_MODE" == "hysteria-b-smoke" || "$FLOWWEAVE_LAB_MODE" == "hysteria-b-formal" || "$FLOWWEAVE_LAB_MODE" == "hysteria-a-wire" || "$FLOWWEAVE_LAB_MODE" == "hysteria-a-smoke" || "$FLOWWEAVE_LAB_MODE" == "hysteria-a-formal" || "$FLOWWEAVE_LAB_MODE" == "long" || "$FLOWWEAVE_LAB_MODE" == "b-controller-gate" || "$FLOWWEAVE_LAB_MODE" == "b-declared-epoch" || "$FLOWWEAVE_LAB_MODE" == "b-continuous-formal" || "$FLOWWEAVE_LAB_MODE" == "c-v3-wire" || "$FLOWWEAVE_LAB_MODE" == "c-controller-gate" || "$FLOWWEAVE_LAB_MODE" == "c-v4-smoke" || "$FLOWWEAVE_LAB_MODE" == "c-v4-formal" || "$FLOWWEAVE_LAB_MODE" == "c-v12-smoke" || "$FLOWWEAVE_LAB_MODE" == "c-v12-formal" || "$FLOWWEAVE_LAB_MODE" == "c-v2-smoke" || "$FLOWWEAVE_LAB_MODE" == "c-v2-formal" || "$FLOWWEAVE_LAB_MODE" == "formal-a" || "$FLOWWEAVE_LAB_MODE" == "formal-gap-watch" || "$FLOWWEAVE_LAB_MODE" == "diagnose-a" || "$FLOWWEAVE_LAB_MODE" == "diagnose-no-pto" || "$FLOWWEAVE_LAB_MODE" == "diagnose-abandon" || "$FLOWWEAVE_LAB_MODE" == "diagnose-ack-progress" || "$FLOWWEAVE_LAB_MODE" == "diagnose-ack-escape-representative" || "$FLOWWEAVE_LAB_MODE" == "diagnose-second-gap" || "$FLOWWEAVE_LAB_MODE" == "diagnose-feedback-handoff" || "$FLOWWEAVE_LAB_MODE" == "diagnose-feedback-handoff-1103" || "$FLOWWEAVE_LAB_MODE" == "diagnose-feedback-handoff-1104" || "$FLOWWEAVE_LAB_MODE" == "diagnose-feedback-snapshot-1104" || "$FLOWWEAVE_LAB_MODE" == "diagnose-feedback-snapshot-stability" || "$FLOWWEAVE_LAB_MODE" == "diagnose-feedback-snapshot-response-stability" || "$FLOWWEAVE_LAB_MODE" == "diagnose-feedback-probe-stability" || "$FLOWWEAVE_LAB_MODE" == "diagnose-feedback-evidence-stability" || "$FLOWWEAVE_LAB_MODE" == "diagnose-feedback-evidence-response-stability" || "$FLOWWEAVE_LAB_MODE" == "diagnose-feedback-gap-rescue-stability" || "$FLOWWEAVE_LAB_MODE" == "diagnose-feedback-gap-watch-stability" || "$FLOWWEAVE_LAB_MODE" == "diagnose-application-progress-failures" || "$FLOWWEAVE_LAB_MODE" == "diagnose-application-progress-stability" || "$FLOWWEAVE_LAB_MODE" == "diagnose-application-progress-age" || "$FLOWWEAVE_LAB_MODE" == "diagnose-application-progress-age-stability" || "$FLOWWEAVE_LAB_MODE" == "diagnose-application-progress-deadline" || "$FLOWWEAVE_LAB_MODE" == "diagnose-application-progress-deadline-stability" || "$FLOWWEAVE_LAB_MODE" == "diagnose-application-progress-version" || "$FLOWWEAVE_LAB_MODE" == "diagnose-application-progress-version-stability" || "$FLOWWEAVE_LAB_MODE" == "diagnose-application-progress-version-failures" ]]; then
    cargo test --release --test network_lab "$FLOWWEAVE_LAB_TEST" -- --ignored --nocapture --test-threads=1
else
    cargo test --test network_lab "$FLOWWEAVE_LAB_TEST" -- --ignored --nocapture --test-threads=1
fi
'
