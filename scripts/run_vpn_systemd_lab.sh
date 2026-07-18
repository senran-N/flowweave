#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
UNIT_DIRECTORY="$RUNTIME_DIR/systemd/user"
UNIT_NAME="flowweave-vpn-systemd-lab-$$.service"
UNIT_PATH="$UNIT_DIRECTORY/$UNIT_NAME"
LAB_DIRECTORY=$(mktemp -d "$RUNTIME_DIR/flowweave-vpn-systemd-state.XXXXXX")
LAB_BINARY=$(mktemp "$RUNTIME_DIR/flowweave-vpn-systemd-lab.XXXXXX")
LAB_PRODUCT_BINARY=$(mktemp "$RUNTIME_DIR/flowweave-vpn-systemd-product.XXXXXX")

cleanup_lab() {
    systemctl --user stop "$UNIT_NAME" >/dev/null 2>&1 || true
    systemctl --user reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
    rm -f "$UNIT_PATH" "$LAB_BINARY" "$LAB_PRODUCT_BINARY"
    rm -rf "$LAB_DIRECTORY"
    systemctl --user daemon-reload >/dev/null 2>&1 || true
}
trap cleanup_lab EXIT HUP INT TERM

cd "$ROOT_DIR"
cargo build --bin flowweave-vpn
PRODUCT_BINARY="$ROOT_DIR/target/debug/flowweave-vpn"
TEST_BINARY=$(
    cargo test --test vpn_systemd_lab --no-run --message-format=json |
        jq -r 'select(.profile.test == true and .target.name == "vpn_systemd_lab") | .executable' |
        tail -n 1
)
if [ ! -x "$PRODUCT_BINARY" ] || [ -z "$TEST_BINARY" ] || [ ! -x "$TEST_BINARY" ]; then
    echo "无法定位 flowweave-vpn 或 vpn_systemd_lab 测试二进制" >&2
    exit 1
fi
if ! systemctl --user show-environment >/dev/null 2>&1; then
    echo "当前会话没有可用的 user systemd manager" >&2
    exit 1
fi
install -m 0755 "$TEST_BINARY" "$LAB_BINARY"
install -m 0755 "$PRODUCT_BINARY" "$LAB_PRODUCT_BINARY"
mkdir -p "$UNIT_DIRECTORY"
sed \
    -e "s|@LAB_DIRECTORY@|$LAB_DIRECTORY|g" \
    -e "s|@ENV_BINARY@|$(command -v env)|g" \
    -e "s|@PRODUCT_BINARY@|$LAB_PRODUCT_BINARY|g" \
    -e "s|@TEST_BINARY@|$LAB_BINARY|g" \
    tests/fixtures/flowweave-vpn-systemd-lab.service.in >"$UNIT_PATH"
chmod 0600 "$UNIT_PATH"
systemctl --user daemon-reload

write_environment() {
    scenario=$1
    {
        echo "FLOWWEAVE_VPN_SYSTEMD_LAB=1"
        echo "FLOWWEAVE_VPN_SYSTEMD_SCENARIO=$scenario"
        echo "FLOWWEAVE_VPN_SYSTEMD_DIR=$LAB_DIRECTORY"
        echo "XDG_RUNTIME_DIR=$RUNTIME_DIR"
    } >"$LAB_DIRECTORY/environment"
    chmod 0600 "$LAB_DIRECTORY/environment"
}

stage_sequence() {
    awk '{print $1}' "$LAB_DIRECTORY/lifecycle.log" | paste -sd, -
}

expect_sequence() {
    expected=$1
    actual=$(stage_sequence)
    if [ "$actual" != "$expected" ]; then
        cat "$LAB_DIRECTORY/lifecycle.log" >&2 || true
        echo "systemd 生命周期顺序不匹配：$actual" >&2
        exit 1
    fi
}

reset_scenario() {
    scenario=$1
    systemctl --user stop "$UNIT_NAME" >/dev/null 2>&1 || true
    systemctl --user reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
    rm -f \
        "$LAB_DIRECTORY/lifecycle.log" \
        "$LAB_DIRECTORY/unexpected-exit.trigger"
    write_environment "$scenario"
}

expect_start_failure() {
    if systemctl --user start "$UNIT_NAME" \
        >"$LAB_DIRECTORY/systemctl.stdout" \
        2>"$LAB_DIRECTORY/systemctl.stderr"; then
        echo "预期失败的 systemd VPN 生命周期意外启动成功" >&2
        exit 1
    fi
}

expect_reload_failure() {
    if systemctl --user reload "$UNIT_NAME" \
        >"$LAB_DIRECTORY/systemctl.stdout" \
        2>"$LAB_DIRECTORY/systemctl.stderr"; then
        echo "预期失败的 systemd VPN reload 意外成功" >&2
        exit 1
    fi
}

start_successfully() {
    if ! systemctl --user start "$UNIT_NAME" \
        >"$LAB_DIRECTORY/systemctl.stdout" \
        2>"$LAB_DIRECTORY/systemctl.stderr"; then
        cat "$LAB_DIRECTORY/systemctl.stderr" >&2 || true
        systemctl --user status "$UNIT_NAME" --no-pager >&2 || true
        journalctl --user -u "$UNIT_NAME" -n 100 --no-pager >&2 || true
        cat "$LAB_DIRECTORY/lifecycle.log" >&2 || true
        exit 1
    fi
}

reset_scenario normal
start_successfully
expect_sequence prepare,data_start,data_ready,activate
grep -Fq "prepare uid=$(id -u) capabilities=0000000000000000 no_new_privileges=0" \
    "$LAB_DIRECTORY/lifecycle.log"
grep -Fq "data_start uid=$(id -u) capabilities=0000000000000000 no_new_privileges=1" \
    "$LAB_DIRECTORY/lifecycle.log"
systemctl --user reload "$UNIT_NAME"
expect_sequence prepare,data_start,data_ready,activate,reload_caller,reload
grep -Fq "reload_caller uid=$(id -u) capabilities=0000000000000000 no_new_privileges=1" \
    "$LAB_DIRECTORY/lifecycle.log"
systemctl --user stop "$UNIT_NAME"
expect_sequence prepare,data_start,data_ready,activate,reload_caller,reload,data_stopped,deactivate,cleanup

reset_scenario reload_failure
start_successfully
expect_reload_failure
expect_sequence prepare,data_start,data_ready,activate,reload_caller,reload
systemctl --user is-active --quiet "$UNIT_NAME"
systemctl --user stop "$UNIT_NAME"
expect_sequence prepare,data_start,data_ready,activate,reload_caller,reload,data_stopped,deactivate,cleanup

reset_scenario prepare_failure
expect_start_failure
expect_sequence prepare,deactivate,cleanup

reset_scenario before_ready_failure
expect_start_failure
expect_sequence prepare,data_start,data_before_ready_failure,deactivate,cleanup

reset_scenario before_ready_timeout
expect_start_failure
expect_sequence prepare,data_start,data_waiting_before_ready,data_stopped,deactivate,cleanup

reset_scenario activate_failure
expect_start_failure
expect_sequence prepare,data_start,data_ready,activate,data_stopped,deactivate,cleanup

reset_scenario unexpected_exit
start_successfully
expect_sequence prepare,data_start,data_ready,activate
: >"$LAB_DIRECTORY/unexpected-exit.trigger"
attempts=0
while [ "$attempts" -lt 200 ]; do
    if [ -f "$LAB_DIRECTORY/lifecycle.log" ] \
        && [ "$(stage_sequence)" = \
            prepare,data_start,data_ready,activate,data_unexpected_exit,deactivate,cleanup ]; then
        break
    fi
    attempts=$((attempts + 1))
    sleep 0.05
done
expect_sequence prepare,data_start,data_ready,activate,data_unexpected_exit,deactivate,cleanup
echo "vpn_systemd_lifecycle_lab_passed"
