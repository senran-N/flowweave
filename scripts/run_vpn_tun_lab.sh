#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
USER_NAME=$(id -un)
HOST_NETNS=$(readlink /proc/self/ns/net)
SUBUID_START=$(awk -F: -v user="$USER_NAME" '$1 == user { print $2; exit }' /etc/subuid)
SUBGID_START=$(awk -F: -v user="$USER_NAME" '$1 == user { print $2; exit }' /etc/subgid)

if [ -z "$SUBUID_START" ] || [ -z "$SUBGID_START" ]; then
    echo "当前用户缺少 /etc/subuid 或 /etc/subgid 映射，无法运行 rootless TUN 实验" >&2
    exit 1
fi

cd "$ROOT_DIR"
TEST_BINARY=$(
    cargo test --test vpn_tun_lab --no-run --message-format=json |
        jq -r 'select(.profile.test == true and .target.name == "vpn_tun_lab") | .executable' |
        tail -n 1
)

if [ -z "$TEST_BINARY" ] || [ ! -x "$TEST_BINARY" ]; then
    echo "无法定位 vpn_tun_lab 测试二进制" >&2
    exit 1
fi

# target/ 位于用户主目录内，降权后的 namespace 用户可能没有目录穿越权限。
# 将只读测试二进制暂存到所有用户可穿越的 /tmp，退出时无条件清理。
LAB_BINARY=$(mktemp /tmp/flowweave-vpn-tun-lab.XXXXXX)
LAB_STATE_DIR=$(mktemp -d /tmp/flowweave-vpn-endpoint-lab.XXXXXX)
trap 'rm -f "$LAB_BINARY"; rm -rf "$LAB_STATE_DIR"' EXIT HUP INT TERM
install -m 0755 "$TEST_BINARY" "$LAB_BINARY"

unshare \
    --user \
    --map-root-user \
    --map-users "1000:${SUBUID_START}:1" \
    --map-groups "1000:${SUBGID_START}:1" \
    --mount \
    --net \
    --fork \
    sh -eu -c '
        mount --make-rprivate /
        mount -t tmpfs tmpfs /run
        mkdir -p /run/netns
        current_netns=$(readlink /proc/self/ns/net)
        if [ "$current_netns" = "$2" ]; then
            echo "TUN 实验拒绝在宿主网络空间运行" >&2
            exit 1
        fi
        ip tuntap add dev fwvpn0 mode tun user 1000

        env \
            FLOWWEAVE_TUN_LAB=1 \
            FLOWWEAVE_HOST_NETNS="$2" \
            "$1" \
            --ignored \
            --exact root_process_is_rejected_before_tun_access \
            --nocapture

        setpriv \
            --bounding-set=-all \
            --inh-caps=-all \
            --ambient-caps=-all \
            --reuid=1000 \
            --regid=1000 \
            --clear-groups \
            env \
                FLOWWEAVE_TUN_LAB=1 \
                FLOWWEAVE_HOST_NETNS="$2" \
                "$1" \
                --ignored \
                --exact process_without_no_new_privileges_is_rejected \
                --nocapture

        ip link set dev fwvpn0 mtu 1500
        setpriv \
            --no-new-privs \
            --bounding-set=-all \
            --inh-caps=-all \
            --ambient-caps=-all \
            --reuid=1000 \
            --regid=1000 \
            --clear-groups \
            env \
                FLOWWEAVE_TUN_LAB=1 \
                FLOWWEAVE_HOST_NETNS="$2" \
                "$1" \
                --ignored \
                --exact down_tun_is_rejected_before_attach \
                --nocapture

        ip link set dev fwvpn0 up
        setpriv \
            --no-new-privs \
            --bounding-set=-all \
            --inh-caps=-all \
            --ambient-caps=-all \
            --reuid=1000 \
            --regid=1000 \
            --clear-groups \
            env \
                FLOWWEAVE_TUN_LAB=1 \
                FLOWWEAVE_HOST_NETNS="$2" \
                "$1" \
                --ignored \
                --exact existing_tun_is_attached_only_by_unprivileged_owner \
                --nocapture

        ip link del dev fwvpn0
        env \
            FLOWWEAVE_TUN_LAB=1 \
            FLOWWEAVE_HOST_NETNS="$2" \
            FLOWWEAVE_TUN_ENDPOINT_ROLE=prepare \
            FLOWWEAVE_TUN_ENDPOINT_DIR="$3" \
            "$1" \
            --ignored \
            --exact real_tun_endpoint_protocol_mtu_and_connection_loss \
            --nocapture
        chown -R 1000:1000 "$3"/*
        chown 0:1000 "$3"
        chmod 0770 "$3"

        ip netns add fwserver
        ip netns add fwclient
        ip link add fwserver0 type veth peer name fwclient0
        ip link set fwserver0 netns fwserver
        ip link set fwclient0 netns fwclient

        ip netns exec fwserver ip link set lo up
        ip netns exec fwserver ip link set fwserver0 up
        ip netns exec fwserver ip addr add 192.0.2.1/30 dev fwserver0
        ip netns exec fwserver ip tuntap add dev fwvpn0 mode tun user 1000
        ip netns exec fwserver ip link set dev fwvpn0 mtu 1500 up
        ip netns exec fwserver ip addr add 10.77.0.1/32 dev fwvpn0
        ip netns exec fwserver ip -6 addr add fd77::1/128 dev fwvpn0 nodad
        ip netns exec fwserver ip route add 10.77.0.2/32 dev fwvpn0
        ip netns exec fwserver ip -6 route add fd77::2/128 dev fwvpn0

        ip netns exec fwclient ip link set lo up
        ip netns exec fwclient ip link set fwclient0 up
        ip netns exec fwclient ip addr add 192.0.2.2/30 dev fwclient0
        ip netns exec fwclient ip tuntap add dev fwvpn0 mode tun user 1000
        ip netns exec fwclient ip link set dev fwvpn0 mtu 1500 up
        ip netns exec fwclient ip addr add 10.77.0.2/32 dev fwvpn0
        ip netns exec fwclient ip -6 addr add fd77::2/128 dev fwvpn0 nodad
        ip netns exec fwclient ip route add 10.77.0.1/32 dev fwvpn0
        ip netns exec fwclient ip -6 route add fd77::1/128 dev fwvpn0
        ip netns exec fwclient sh -c '"'"'echo "1000 1000" > /proc/sys/net/ipv4/ping_group_range'"'"'

        server_pid=
        client_pid=
        fault_pid=
        cleanup_endpoint_lab() {
            if [ -n "$fault_pid" ] && kill -0 "$fault_pid" 2>/dev/null; then
                kill "$fault_pid" 2>/dev/null || true
                wait "$fault_pid" 2>/dev/null || true
            fi
            if [ -n "$client_pid" ] && kill -0 "$client_pid" 2>/dev/null; then
                kill "$client_pid" 2>/dev/null || true
                wait "$client_pid" 2>/dev/null || true
            fi
            if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
                kill "$server_pid" 2>/dev/null || true
                wait "$server_pid" 2>/dev/null || true
            fi
            ip netns del fwclient 2>/dev/null || true
            ip netns del fwserver 2>/dev/null || true
        }
        trap cleanup_endpoint_lab EXIT
        trap "exit 1" HUP INT TERM

        wait_for_endpoint_marker() {
            marker=$1
            process_pid=$2
            process_log=$3
            description=$4
            marker_attempts=0
            while [ "$marker_attempts" -lt 200 ]; do
                if [ -f "$marker" ]; then
                    return 0
                fi
                if ! kill -0 "$process_pid" 2>/dev/null; then
                    break
                fi
                marker_attempts=$((marker_attempts + 1))
                sleep 0.05
            done
            cat "$process_log" >&2 || true
            echo "$description 未在固定截止内就绪" >&2
            return 1
        }

        (
            fault_attempts=0
            while [ "$fault_attempts" -lt 400 ]; do
                if [ -f "$3/fault.ready" ]; then
                    ip netns exec fwclient ip link set fwclient0 down
                    exit 0
                fi
                fault_attempts=$((fault_attempts + 1))
                sleep 0.05
            done
            echo "等待外层断网注入标记超时" >&2
            exit 1
        ) >"$3/fault.log" 2>&1 &
        fault_pid=$!

        ip netns exec fwserver \
            setpriv \
                --no-new-privs \
                --bounding-set=-all \
                --inh-caps=-all \
                --ambient-caps=-all \
                --reuid=1000 \
                --regid=1000 \
                --clear-groups \
                env \
                    FLOWWEAVE_TUN_LAB=1 \
                    FLOWWEAVE_HOST_NETNS="$2" \
                    FLOWWEAVE_TUN_ENDPOINT_ROLE=server \
                    FLOWWEAVE_TUN_ENDPOINT_DIR="$3" \
                    "$1" \
                    --ignored \
                    --exact real_tun_endpoint_protocol_mtu_and_connection_loss \
                    --nocapture \
            >"$3/server.log" 2>&1 &
        server_pid=$!

        ready=0
        attempts=0
        while [ "$attempts" -lt 100 ]; do
            if [ -f "$3/server.ready" ]; then
                ready=1
                break
            fi
            if ! kill -0 "$server_pid" 2>/dev/null; then
                break
            fi
            attempts=$((attempts + 1))
            sleep 0.05
        done
        if [ "$ready" -ne 1 ]; then
            cat "$3/server.log" >&2 || true
            echo "真实 TUN Endpoint 服务端未就绪" >&2
            exit 1
        fi

        client_status=0
        ip netns exec fwclient \
            setpriv \
                --no-new-privs \
                --bounding-set=-all \
                --inh-caps=-all \
                --ambient-caps=-all \
                --reuid=1000 \
                --regid=1000 \
                --clear-groups \
                env \
                    FLOWWEAVE_TUN_LAB=1 \
                    FLOWWEAVE_HOST_NETNS="$2" \
                    FLOWWEAVE_TUN_ENDPOINT_ROLE=client \
                    FLOWWEAVE_TUN_ENDPOINT_DIR="$3" \
                    "$1" \
                    --ignored \
                    --exact real_tun_endpoint_protocol_mtu_and_connection_loss \
                    --nocapture || client_status=$?
        if [ "$client_status" -ne 0 ]; then
            cat "$3/server.log" >&2 || true
            cat "$3/fault.log" >&2 || true
            exit "$client_status"
        fi
        if ! wait "$fault_pid"; then
            fault_pid=
            cat "$3/fault.log" >&2 || true
            cat "$3/server.log" >&2 || true
            exit 1
        fi
        fault_pid=
        if ! wait "$server_pid"; then
            server_pid=
            cat "$3/server.log" >&2 || true
            exit 1
        fi
        server_pid=

        ip netns exec fwclient ip link set fwclient0 up
        rm -f \
            "$3/cleanup.server.ready" \
            "$3/cleanup.client.ready" \
            "$3/cleanup.server.log" \
            "$3/cleanup.client.log"

        ip netns exec fwserver \
            setpriv \
                --no-new-privs \
                --bounding-set=-all \
                --inh-caps=-all \
                --ambient-caps=-all \
                --reuid=1000 \
                --regid=1000 \
                --clear-groups \
                env \
                    FLOWWEAVE_TUN_LAB=1 \
                    FLOWWEAVE_HOST_NETNS="$2" \
                    FLOWWEAVE_TUN_CLEANUP_ROLE=server \
                    FLOWWEAVE_TUN_ENDPOINT_DIR="$3" \
                    "$1" \
                    --ignored \
                    --exact real_tun_endpoint_process_cleanup \
                    --nocapture \
            >"$3/cleanup.server.log" 2>&1 &
        server_pid=$!
        wait_for_endpoint_marker \
            "$3/cleanup.server.ready" \
            "$server_pid" \
            "$3/cleanup.server.log" \
            "异常退出清理服务端"

        ip netns exec fwclient \
            setpriv \
                --no-new-privs \
                --bounding-set=-all \
                --inh-caps=-all \
                --ambient-caps=-all \
                --reuid=1000 \
                --regid=1000 \
                --clear-groups \
                env \
                    FLOWWEAVE_TUN_LAB=1 \
                    FLOWWEAVE_HOST_NETNS="$2" \
                    FLOWWEAVE_TUN_CLEANUP_ROLE=client \
                    FLOWWEAVE_TUN_ENDPOINT_DIR="$3" \
                    "$1" \
                    --ignored \
                    --exact real_tun_endpoint_process_cleanup \
                    --nocapture \
            >"$3/cleanup.client.log" 2>&1 &
        client_pid=$!
        wait_for_endpoint_marker \
            "$3/cleanup.client.ready" \
            "$client_pid" \
            "$3/cleanup.client.log" \
            "异常退出清理客户端"

        if ! kill -KILL "$client_pid"; then
            cat "$3/cleanup.client.log" >&2 || true
            exit 1
        fi
        if wait "$client_pid"; then
            echo "客户端收到 SIGKILL 后意外成功退出" >&2
            exit 1
        fi
        client_pid=
        if ! kill -0 "$server_pid" 2>/dev/null; then
            cat "$3/cleanup.server.log" >&2 || true
            echo "客户端被强制终止后服务端进程意外退出" >&2
            exit 1
        fi

        if ! kill -KILL "$server_pid"; then
            cat "$3/cleanup.server.log" >&2 || true
            exit 1
        fi
        if wait "$server_pid"; then
            echo "服务端收到 SIGKILL 后意外成功退出" >&2
            exit 1
        fi
        server_pid=

        for endpoint_namespace in fwclient fwserver; do
            ip netns exec "$endpoint_namespace" \
                setpriv \
                    --no-new-privs \
                    --bounding-set=-all \
                    --inh-caps=-all \
                    --ambient-caps=-all \
                    --reuid=1000 \
                    --regid=1000 \
                    --clear-groups \
                    env \
                        FLOWWEAVE_TUN_LAB=1 \
                        FLOWWEAVE_HOST_NETNS="$2" \
                        FLOWWEAVE_TUN_CLEANUP_ROLE=reattach \
                        FLOWWEAVE_TUN_ENDPOINT_DIR="$3" \
                        "$1" \
                        --ignored \
                        --exact real_tun_endpoint_process_cleanup \
                        --nocapture
        done
    ' sh "$LAB_BINARY" "$HOST_NETNS" "$LAB_STATE_DIR"
