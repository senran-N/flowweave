#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
USER_NAME=$(id -un)
HOST_NETNS=$(readlink /proc/self/ns/net)
SUBUID_START=$(awk -F: -v user="$USER_NAME" '$1 == user { print $2; exit }' /etc/subuid)
SUBGID_START=$(awk -F: -v user="$USER_NAME" '$1 == user { print $2; exit }' /etc/subgid)

if [ -z "$SUBUID_START" ] || [ -z "$SUBGID_START" ]; then
    echo "当前用户缺少 /etc/subuid 或 /etc/subgid 映射，无法运行 VPN 网络事务实验" >&2
    exit 1
fi

cd "$ROOT_DIR"
cargo build --bin flowweave-vpn-net
NETWORK_BINARY="$ROOT_DIR/target/debug/flowweave-vpn-net"
TEST_BINARY=$(
    cargo test --test vpn_network_lab --no-run --message-format=json |
        jq -r 'select(.profile.test == true and .target.name == "vpn_network_lab") | .executable' |
        tail -n 1
)

if [ ! -x "$NETWORK_BINARY" ] || [ -z "$TEST_BINARY" ] || [ ! -x "$TEST_BINARY" ]; then
    echo "无法定位 VPN 网络事务二进制或测试二进制" >&2
    exit 1
fi

LAB_BINARY=$(mktemp /tmp/flowweave-vpn-net.XXXXXX)
LAB_TEST_BINARY=$(mktemp /tmp/flowweave-vpn-net-test.XXXXXX)
LAB_DIR=$(mktemp -d /tmp/flowweave-vpn-net-lab.XXXXXX)
trap 'rm -f "$LAB_BINARY" "$LAB_TEST_BINARY"; rm -rf "$LAB_DIR"' EXIT HUP INT TERM
install -m 0755 "$NETWORK_BINARY" "$LAB_BINARY"
install -m 0755 "$TEST_BINARY" "$LAB_TEST_BINARY"
install -m 0600 deploy/vpn-client.json.example "$LAB_DIR/vpn-client.json"
install -m 0600 deploy/vpn-server.json.example "$LAB_DIR/vpn-server.json"
install -m 0600 deploy/vpn-identities.json.example "$LAB_DIR/vpn-identities.json"
jq '.forwarding = {
        "manage_sysctls": false,
        "ipv4_masquerade": true,
        "ipv6_masquerade": false
    }' \
    deploy/vpn-server.json.example >"$LAB_DIR/vpn-server.forwarding-external.json"
jq '.forwarding = {
        "manage_sysctls": true,
        "ipv4_masquerade": true,
        "ipv6_masquerade": false
    }' \
    deploy/vpn-server.json.example >"$LAB_DIR/vpn-server.forwarding-managed.json"
jq '.forwarding = {
        "manage_sysctls": true,
        "ipv4_masquerade": false,
        "ipv6_masquerade": false
    }' \
    deploy/vpn-server.json.example >"$LAB_DIR/vpn-server.forwarding-no-nat.json"
jq '.forwarding = {
        "manage_sysctls": true,
        "ipv4_masquerade": true,
        "ipv6_masquerade": true
    }' \
    deploy/vpn-server.json.example >"$LAB_DIR/vpn-server.forwarding-ipv6-nat.json"
chmod 0600 "$LAB_DIR"/vpn-server.forwarding-*.json

unshare \
    --user \
    --map-root-user \
    --map-users "1000:${SUBUID_START}:1" \
    --map-groups "1000:${SUBGID_START}:1" \
    --mount \
    --net \
    --fork \
    sh -eu -c '
        current_netns=$(readlink /proc/self/ns/net)
        if [ "$current_netns" = "$3" ]; then
            echo "VPN 网络事务实验拒绝在宿主网络空间运行" >&2
            exit 1
        fi
        mount --make-rprivate /
        mount -t tmpfs -o mode=0755 tmpfs /run
        mount -t sysfs sysfs /sys
        ip link set lo up

        chown 0:1000 \
            "$4/vpn-client.json" \
            "$4/vpn-server.json" \
            "$4/vpn-server.forwarding-external.json" \
            "$4/vpn-server.forwarding-managed.json" \
            "$4/vpn-server.forwarding-no-nat.json" \
            "$4/vpn-server.forwarding-ipv6-nat.json" \
            "$4/vpn-identities.json"
        chmod 0640 \
            "$4/vpn-client.json" \
            "$4/vpn-server.json" \
            "$4/vpn-server.forwarding-external.json" \
            "$4/vpn-server.forwarding-managed.json" \
            "$4/vpn-server.forwarding-no-nat.json" \
            "$4/vpn-server.forwarding-ipv6-nat.json" \
            "$4/vpn-identities.json"
        chown 0:1000 "$4"
        chmod 0710 "$4"
        mkdir "$4/state" "$4/data"
        chmod 0700 "$4/state"
        chown 1000:1000 "$4/data"
        chmod 0700 "$4/data"

        holder_pid=
        lab_directory=$4
        cleanup_lab() {
            if [ -n "$holder_pid" ] && kill -0 "$holder_pid" 2>/dev/null; then
                kill -KILL "$holder_pid" 2>/dev/null || true
                wait "$holder_pid" 2>/dev/null || true
            fi
            ip link del dev fwvpn0 2>/dev/null || true
            ip route del 10.77.0.1/32 dev lo 2>/dev/null || true
            rm -rf "$lab_directory/data" 2>/dev/null || true
        }
        trap cleanup_lab EXIT
        trap "exit 1" HUP INT TERM

        expect_failure() {
            expected=$1
            shift
            failure_status=0
            "$@" >"$lab_directory/failure.stdout" 2>"$lab_directory/failure.stderr" || failure_status=$?
            if [ "$failure_status" -eq 0 ]; then
                echo "预期失败的 VPN 网络事务意外成功" >&2
                exit 1
            fi
            if ! grep -Fqx "$expected" "$lab_directory/failure.stderr"; then
                cat "$lab_directory/failure.stderr" >&2 || true
                echo "VPN 网络事务失败原因不匹配" >&2
                exit 1
            fi
        }

        expect_failure_prefix() {
            expected_prefix=$1
            shift
            failure_status=0
            "$@" >"$lab_directory/failure.stdout" 2>"$lab_directory/failure.stderr" || failure_status=$?
            if [ "$failure_status" -eq 0 ]; then
                echo "预期失败的 VPN 网络事务意外成功" >&2
                exit 1
            fi
            if ! grep -Fq "$expected_prefix" "$lab_directory/failure.stderr"; then
                cat "$lab_directory/failure.stderr" >&2 || true
                echo "VPN 网络事务失败前缀不匹配" >&2
                exit 1
            fi
        }

        expect_failure \
            vpn_network_invalid_owner_uid \
            "$1" prepare-client "$4/vpn-client.json" "$4/state/client.json" 0
        expect_failure \
            vpn_network_not_root \
            setpriv \
                --no-new-privs \
                --bounding-set=-all \
                --inh-caps=-all \
                --ambient-caps=-all \
                --reuid=1000 \
                --regid=1000 \
                --clear-groups \
                "$1" cleanup "$4/state/nonroot.json"

        : >"$4/state/client.json.lock"
        chmod 0600 "$4/state/client.json.lock"
        exec 9>"$4/state/client.json.lock"
        flock -n 9
        expect_failure \
            vpn_network_state_busy \
            "$1" prepare-client "$4/vpn-client.json" "$4/state/client.json" 1000
        flock -u 9

        first=$(
            "$1" prepare-client "$4/vpn-client.json" "$4/state/client.json" 1000
        )
        test "$first" = prepared
        repeated=$(
            "$1" prepare-client "$4/vpn-client.json" "$4/state/client.json" 1000
        )
        test "$repeated" = already_prepared

        activated=$(
            "$1" activate-client "$4/vpn-client.json" "$4/state/client.json"
        )
        test "$activated" = activated
        test -f "$4/state/client.json.routes"
        route_table=$(jq -r .route_table "$4/state/client.json.routes")
        route_protocol=$(jq -r .route_protocol "$4/state/client.json.routes")
        uid_priority=$(jq -r .uid_rule_priority "$4/state/client.json.routes")
        tunnel_priority=$(jq -r .tunnel_rule_priority "$4/state/client.json.routes")
        ip -N -j -4 rule show | jq -e \
            --argjson priority "$uid_priority" \
            --arg protocol "$route_protocol" \
            '"'"'.[] | select(.priority == $priority and .uid_start == 1000 and .uid_end == 1000 and .table == "254" and .protocol == $protocol)'"'"' \
            >/dev/null
        ip -N -j -4 rule show | jq -e \
            --argjson priority "$tunnel_priority" \
            --arg table "$route_table" \
            --arg protocol "$route_protocol" \
            '"'"'.[] | select(.priority == $priority and .table == $table and .protocol == $protocol)'"'"' \
            >/dev/null
        ip -N -j -4 route show table "$route_table" | jq -e \
            --arg protocol "$route_protocol" \
            '"'"'.[] | select(.dst == "default" and .dev == "fwvpn0" and .protocol == $protocol)'"'"' \
            >/dev/null
        ip -N -j -6 route show table "$route_table" | jq -e \
            --arg protocol "$route_protocol" \
            '"'"'.[] | select(.dst == "default" and .dev == "fwvpn0" and .protocol == $protocol)'"'"' \
            >/dev/null
        active_repeated=$(
            "$1" activate-client "$4/vpn-client.json" "$4/state/client.json"
        )
        test "$active_repeated" = already_active

        cp "$4/vpn-client.json" "$4/vpn-client.route-original.json"
        jq ".allowed_destinations = [\"198.51.100.0/24\", \"::/0\"]" \
            "$4/vpn-client.json" >"$4/vpn-client.route-changed.json"
        chown 0:1000 "$4/vpn-client.route-changed.json"
        chmod 0640 "$4/vpn-client.route-changed.json"
        mv "$4/vpn-client.route-changed.json" "$4/vpn-client.json"
        expect_failure \
            vpn_client_route_state_conflict \
            "$1" activate-client "$4/vpn-client.json" "$4/state/client.json"
        mv "$4/vpn-client.route-original.json" "$4/vpn-client.json"
        chown 0:1000 "$4/vpn-client.json"
        chmod 0640 "$4/vpn-client.json"

        route_metric=$(jq -r .route_metric "$4/state/client.json.routes")
        ip -4 route add 203.0.113.0/24 \
            dev fwvpn0 \
            table "$route_table" \
            proto "$route_protocol" \
            metric "$route_metric"
        expect_failure \
            vpn_client_route_state_drift \
            "$1" activate-client "$4/vpn-client.json" "$4/state/client.json"
        ip -4 route del 203.0.113.0/24 \
            dev fwvpn0 \
            table "$route_table" \
            proto "$route_protocol" \
            metric "$route_metric"

        ip -4 rule add \
            priority "$tunnel_priority" \
            to 203.0.113.0/24 \
            lookup "$route_table" \
            protocol "$route_protocol"
        expect_failure \
            vpn_client_route_state_drift \
            "$1" deactivate-client "$4/state/client.json"
        ip -4 rule del \
            priority "$tunnel_priority" \
            to 203.0.113.0/24 \
            lookup "$route_table" \
            protocol "$route_protocol"

        jq ".phase = \"activating\"" \
            "$4/state/client.json.routes" >"$4/state/client.routes.recover.json"
        chmod 0600 "$4/state/client.routes.recover.json"
        mv "$4/state/client.routes.recover.json" "$4/state/client.json.routes"
        cp "$4/vpn-client.json" "$4/vpn-client.route-recover-original.json"
        jq ".allowed_destinations = [\"198.51.100.0/24\", \"::/0\"]" \
            "$4/vpn-client.json" >"$4/vpn-client.route-recover-changed.json"
        chown 0:1000 "$4/vpn-client.route-recover-changed.json"
        chmod 0640 "$4/vpn-client.route-recover-changed.json"
        mv "$4/vpn-client.route-recover-changed.json" "$4/vpn-client.json"
        route_recovered=$(
            "$1" activate-client "$4/vpn-client.json" "$4/state/client.json"
        )
        test "$route_recovered" = recovered_and_activated
        test "$(jq -r .phase "$4/state/client.json.routes")" = active
        jq -e \
            '"'"'.destination_networks == ["198.51.100.0/24", "::/0"]'"'"' \
            "$4/state/client.json.routes" \
            >/dev/null
        mv "$4/vpn-client.route-recover-original.json" "$4/vpn-client.json"
        chown 0:1000 "$4/vpn-client.json"
        chmod 0640 "$4/vpn-client.json"

        deactivated=$("$1" deactivate-client "$4/state/client.json")
        test "$deactivated" = deactivated
        test ! -e "$4/state/client.json.routes"
        inactive_repeated=$("$1" deactivate-client "$4/state/client.json")
        test "$inactive_repeated" = already_inactive

        setpriv \
            --no-new-privs \
            --bounding-set=-all \
            --inh-caps=-all \
            --ambient-caps=-all \
            --reuid=1000 \
            --regid=1000 \
            --clear-groups \
            env \
                FLOWWEAVE_VPN_NETWORK_LAB=1 \
                FLOWWEAVE_HOST_NETNS="$3" \
                FLOWWEAVE_VPN_NETWORK_HOLD_MARKER="$4/data/hold.ready" \
                "$2" \
                --ignored \
                --exact attached_data_process_blocks_privileged_cleanup \
                --nocapture \
            >"$4/holder.log" 2>&1 &
        holder_pid=$!
        holder_ready=0
        holder_attempts=0
        while [ "$holder_attempts" -lt 200 ]; do
            if [ -f "$4/data/hold.ready" ]; then
                holder_ready=1
                break
            fi
            if ! kill -0 "$holder_pid" 2>/dev/null; then
                break
            fi
            holder_attempts=$((holder_attempts + 1))
            sleep 0.05
        done
        if [ "$holder_ready" -ne 1 ]; then
            cat "$4/holder.log" >&2 || true
            echo "无特权 TUN 持有进程未就绪" >&2
            exit 1
        fi
        expect_failure \
            vpn_network_interface_busy \
            "$1" cleanup "$4/state/client.json"
        test -f "$4/state/client.json"
        ip link show dev fwvpn0 >/dev/null
        kill -KILL "$holder_pid"
        wait "$holder_pid" 2>/dev/null || true
        holder_pid=

        cp "$4/vpn-client.json" "$4/vpn-client.original.json"
        jq ".expected_server_ipv4 = \"10.77.0.9\"" \
            "$4/vpn-client.json" >"$4/vpn-client.changed.json"
        chown 0:1000 "$4/vpn-client.changed.json"
        chmod 0640 "$4/vpn-client.changed.json"
        mv "$4/vpn-client.changed.json" "$4/vpn-client.json"
        expect_failure \
            vpn_network_state_conflict \
            "$1" prepare-client "$4/vpn-client.json" "$4/state/client.json" 1000
        mv "$4/vpn-client.original.json" "$4/vpn-client.json"
        chown 0:1000 "$4/vpn-client.json"
        chmod 0640 "$4/vpn-client.json"

        ip addr add 10.77.0.9/32 dev fwvpn0
        expect_failure \
            vpn_network_state_drift \
            "$1" prepare-client "$4/vpn-client.json" "$4/state/client.json" 1000
        ip addr del 10.77.0.9/32 dev fwvpn0

        temporary_name=$(jq -r .temporary_tun_name "$4/state/client.json")
        ip link set dev fwvpn0 name "$temporary_name"
        jq ".phase = \"preparing\"" \
            "$4/state/client.json" >"$4/state/client.recover.json"
        chmod 0600 "$4/state/client.recover.json"
        mv "$4/state/client.recover.json" "$4/state/client.json"
        recovered=$(
            "$1" prepare-client "$4/vpn-client.json" "$4/state/client.json" 1000
        )
        test "$recovered" = recovered_and_prepared
        ip link show dev fwvpn0 >/dev/null

        ownership_token=$(jq -r .ownership_token "$4/state/client.json")
        ip link set dev fwvpn0 alias foreign-owner
        expect_failure \
            vpn_network_interface_ownership_mismatch \
            "$1" cleanup "$4/state/client.json"
        test -f "$4/state/client.json"
        ip link show dev fwvpn0 >/dev/null
        ip link set dev fwvpn0 alias "flowweave-vpn-net:v1:$ownership_token"

        cleanup_activated=$(
            "$1" activate-client "$4/vpn-client.json" "$4/state/client.json"
        )
        test "$cleanup_activated" = activated
        cleanup_route_table=$(jq -r .route_table "$4/state/client.json.routes")
        cleanup_uid_priority=$(jq -r .uid_rule_priority "$4/state/client.json.routes")
        cleanup_tunnel_priority=$(jq -r .tunnel_rule_priority "$4/state/client.json.routes")
        cleaned=$("$1" cleanup "$4/state/client.json")
        test "$cleaned" = cleaned
        test ! -e "$4/state/client.json.routes"
        for family in -4 -6; do
            ip -N -j "$family" rule show | jq -e \
                --argjson uid_priority "$cleanup_uid_priority" \
                --argjson tunnel_priority "$cleanup_tunnel_priority" \
                --arg table "$cleanup_route_table" \
                '"'"'[.[] | select(.priority == $uid_priority or .priority == $tunnel_priority or .table == $table)] | length == 0'"'"' \
                >/dev/null
            ip -N -j "$family" route show table all | jq -e \
                --arg table "$cleanup_route_table" \
                '"'"'[.[] | select(.table == $table)] | length == 0'"'"' \
                >/dev/null
        done
        already_clean=$("$1" cleanup "$4/state/client.json")
        test "$already_clean" = already_clean

        ip tuntap add dev fwvpn0 mode tun user 1000 group 1000
        expect_failure \
            vpn_network_interface_exists \
            "$1" prepare-client "$4/vpn-client.json" "$4/state/client.json" 1000
        ip link show dev fwvpn0 >/dev/null
        ip link del dev fwvpn0

        ip route add 10.77.0.1/32 dev lo
        expect_failure_prefix \
            vpn_network_ip_command:AddRoute: \
            "$1" prepare-client "$4/vpn-client.json" "$4/state/client.json" 1000
        if ip link show dev fwvpn0 >/dev/null 2>&1; then
            echo "失败回滚遗留最终 TUN" >&2
            exit 1
        fi
        if ip -o link show | grep -Fq "fwv"; then
            echo "失败回滚遗留临时 TUN" >&2
            exit 1
        fi
        if [ -e "$4/state/client.json" ]; then
            echo "失败回滚遗留状态文件" >&2
            exit 1
        fi
        ip route show exact 10.77.0.1/32 dev lo | grep -Fq 10.77.0.1
        ip route del 10.77.0.1/32 dev lo

        server=$(
            "$1" prepare-server "$4/vpn-server.json" "$4/state/server.json" 1000
        )
        test "$server" = prepared
        ip addr show dev fwvpn0 | grep -Fq "10.77.0.1/32"
        ip -6 addr show dev fwvpn0 | grep -Fq "fd77::1/128"
        ip route show exact 10.77.0.2/32 dev fwvpn0 | grep -Fq 10.77.0.2
        ip -6 route show exact fd77::2/128 dev fwvpn0 | grep -Fq fd77::2
        server_repeated=$(
            "$1" prepare-server "$4/vpn-server.json" "$4/state/server.json" 1000
        )
        test "$server_repeated" = already_prepared

        forwarding_disabled=$(
            "$1" activate-server "$4/vpn-server.json" "$4/state/server.json"
        )
        test "$forwarding_disabled" = disabled
        test ! -e "$4/state/server.json.forwarding"
        if nft list table inet flowweave_vpn >/dev/null 2>&1; then
            echo "禁用的服务端 forwarding 意外创建 nft table" >&2
            exit 1
        fi

        echo 0 >/proc/sys/net/ipv4/ip_forward
        echo 0 >/proc/sys/net/ipv6/conf/all/forwarding
        expect_failure \
            vpn_server_ipv4_forwarding_disabled \
            "$1" activate-server \
                "$4/vpn-server.forwarding-external.json" \
                "$4/state/server.json"
        test ! -e "$4/state/server.json.forwarding"
        if nft list table inet flowweave_vpn >/dev/null 2>&1; then
            echo "IPv4 forwarding 拒绝路径遗留 nft table" >&2
            exit 1
        fi
        echo 1 >/proc/sys/net/ipv4/ip_forward
        expect_failure \
            vpn_server_ipv6_forwarding_disabled \
            "$1" activate-server \
                "$4/vpn-server.forwarding-external.json" \
                "$4/state/server.json"
        test ! -e "$4/state/server.json.forwarding"
        if nft list table inet flowweave_vpn >/dev/null 2>&1; then
            echo "IPv6 forwarding 拒绝路径遗留 nft table" >&2
            exit 1
        fi
        echo 1 >/proc/sys/net/ipv6/conf/all/forwarding
        externally_managed=$(
            "$1" activate-server \
                "$4/vpn-server.forwarding-external.json" \
                "$4/state/server.json"
        )
        test "$externally_managed" = activated
        external_deactivated=$(
            "$1" deactivate-server "$4/state/server.json"
        )
        test "$external_deactivated" = deactivated
        test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1
        test "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 1

        echo 0 >/proc/sys/net/ipv4/ip_forward
        echo 0 >/proc/sys/net/ipv6/conf/all/forwarding
        nft add table inet flowweave_vpn
        expect_failure \
            vpn_server_forwarding_table_conflict \
            "$1" activate-server \
                "$4/vpn-server.forwarding-managed.json" \
                "$4/state/server.json"
        nft delete table inet flowweave_vpn

        : >/run/flowweave-vpn-forwarding.lock
        chmod 0600 /run/flowweave-vpn-forwarding.lock
        exec 8>/run/flowweave-vpn-forwarding.lock
        flock -n 8
        expect_failure \
            vpn_server_forwarding_busy \
            "$1" activate-server \
                "$4/vpn-server.forwarding-managed.json" \
                "$4/state/server.json"
        flock -u 8

        forwarding_activated=$(
            "$1" activate-server \
                "$4/vpn-server.forwarding-managed.json" \
                "$4/state/server.json"
        )
        test "$forwarding_activated" = activated
        test -f "$4/state/server.json.forwarding"
        test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1
        test "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 1
        nft -j list table inet flowweave_vpn | jq -e \
            '"'"'[.nftables[] | select(.table or .chain or .rule)] | length == 10'"'"' \
            >/dev/null
        forwarding_repeated=$(
            "$1" activate-server \
                "$4/vpn-server.forwarding-managed.json" \
                "$4/state/server.json"
        )
        test "$forwarding_repeated" = already_active

        expect_failure \
            vpn_server_forwarding_state_conflict \
            "$1" activate-server \
                "$4/vpn-server.forwarding-ipv6-nat.json" \
                "$4/state/server.json"

        nft add rule inet flowweave_vpn forward counter comment foreign-rule
        expect_failure \
            vpn_server_forwarding_state_drift \
            "$1" activate-server \
                "$4/vpn-server.forwarding-managed.json" \
                "$4/state/server.json"
        foreign_handle=$(nft -j list table inet flowweave_vpn | jq -r \
            '"'"'.nftables[] | select(.rule.comment == "foreign-rule") | .rule.handle'"'"')
        nft delete rule inet flowweave_vpn forward handle "$foreign_handle"
        test "$(
            "$1" activate-server \
                "$4/vpn-server.forwarding-managed.json" \
                "$4/state/server.json"
        )" = already_active

        nft list table inet flowweave_vpn >"$4/flowweave-vpn.saved.nft"
        ownership_token=$(jq -r .ownership_token "$4/state/server.json.forwarding")
        forward_v4_comment="flowweave-vpn-forwarding:v1:$ownership_token:rule:forward-v4-out"
        forward_v4_handle=$(nft -j list table inet flowweave_vpn | jq -r \
            --arg comment "$forward_v4_comment" \
            '"'"'.nftables[] | select(.rule.comment == $comment) | .rule.handle'"'"')
        nft delete rule inet flowweave_vpn forward handle "$forward_v4_handle"
        nft add rule inet flowweave_vpn forward \
            iifname fwvpn0 ip saddr 10.77.0.2 accept \
            comment "\"$forward_v4_comment\""
        expect_failure \
            vpn_server_forwarding_state_drift \
            "$1" deactivate-server "$4/state/server.json"
        nft delete table inet flowweave_vpn
        nft -f "$4/flowweave-vpn.saved.nft"
        test "$(
            "$1" activate-server \
                "$4/vpn-server.forwarding-managed.json" \
                "$4/state/server.json"
        )" = recovered_and_activated

        jq '"'"'.phase = "activating" | .nft_table_fingerprint = null'"'"' \
            "$4/state/server.json.forwarding" \
            >"$4/state/server.forwarding.recover.json"
        chmod 0600 "$4/state/server.forwarding.recover.json"
        mv \
            "$4/state/server.forwarding.recover.json" \
            "$4/state/server.json.forwarding"
        forwarding_recovered=$(
            "$1" activate-server \
                "$4/vpn-server.forwarding-no-nat.json" \
                "$4/state/server.json"
        )
        test "$forwarding_recovered" = recovered_and_activated
        test "$(jq -r .phase "$4/state/server.json.forwarding")" = active
        nft -j list table inet flowweave_vpn | jq -e \
            '"'"'[.nftables[] | select(.rule.comment | strings | contains("masquerade"))] | length == 0'"'"' \
            >/dev/null
        test "$(
            "$1" deactivate-server "$4/state/server.json"
        )" = deactivated
        test "$(cat /proc/sys/net/ipv4/ip_forward)" = 0
        test "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0

        test "$(
            "$1" activate-server \
                "$4/vpn-server.forwarding-managed.json" \
                "$4/state/server.json"
        )" = activated
        jq '"'"'.phase = "deactivating"'"'"' \
            "$4/state/server.json.forwarding" \
            >"$4/state/server.forwarding.deactivating.json"
        chmod 0600 "$4/state/server.forwarding.deactivating.json"
        mv \
            "$4/state/server.forwarding.deactivating.json" \
            "$4/state/server.json.forwarding"
        echo 0 >/proc/sys/net/ipv4/ip_forward
        echo 0 >/proc/sys/net/ipv6/conf/all/forwarding
        nft delete table inet flowweave_vpn
        forwarding_deactivation_recovered=$(
            "$1" deactivate-server "$4/state/server.json"
        )
        test "$forwarding_deactivation_recovered" = recovered_interrupted_deactivation
        test ! -e "$4/state/server.json.forwarding"

        test "$(
            "$1" activate-server \
                "$4/vpn-server.forwarding-managed.json" \
                "$4/state/server.json"
        )" = activated
        server_cleaned=$("$1" cleanup "$4/state/server.json")
        test "$server_cleaned" = cleaned
        test ! -e "$4/state/server.json.forwarding"
        test "$(cat /proc/sys/net/ipv4/ip_forward)" = 0
        test "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0
        if nft list table inet flowweave_vpn >/dev/null 2>&1; then
            echo "服务端 cleanup 遗留 nft table" >&2
            exit 1
        fi
    ' sh "$LAB_BINARY" "$LAB_TEST_BINARY" "$HOST_NETNS" "$LAB_DIR"
