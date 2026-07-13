#!/usr/bin/env bash
set -euo pipefail

version="2.9.3"
expected_sha256="66dbdb0608f25f3057b433afe975a9fc1af2ca8e512479e294988b3ef363d6c1"
cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/flowweave/hysteria/$version"
binary="$cache_root/hysteria-linux-amd64"
url="https://github.com/apernet/hysteria/releases/download/app/v$version/hysteria-linux-amd64"

verify_binary() {
    local actual
    actual="$(sha256sum "$binary" | awk '{print $1}')"
    [[ "$actual" == "$expected_sha256" ]]
}

if [[ -e "$binary" ]] && ! verify_binary; then
    echo "拒绝使用哈希不匹配的 Hysteria 缓存：$binary" >&2
    exit 1
fi

if [[ ! -e "$binary" ]]; then
    for command_name in curl sha256sum awk chmod mv mktemp; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "缺少准备 Hysteria 所需命令：$command_name" >&2
            exit 1
        fi
    done

    mkdir -p "$cache_root"
    temporary="$(mktemp "$cache_root/.hysteria-linux-amd64.XXXXXX")"
    trap 'rm -f "$temporary"' EXIT
    curl -fL --retry 3 --output "$temporary" "$url"
    actual="$(sha256sum "$temporary" | awk '{print $1}')"
    if [[ "$actual" != "$expected_sha256" ]]; then
        echo "Hysteria 2.9.3 下载哈希不匹配" >&2
        exit 1
    fi
    chmod 0755 "$temporary"
    mv "$temporary" "$binary"
    trap - EXIT
fi

if ! verify_binary; then
    echo "Hysteria 2.9.3 最终哈希校验失败" >&2
    exit 1
fi

version_output="$("$binary" version)"
if [[ "$version_output" != *$'Version:\tv2.9.3'* ]]; then
    echo "Hysteria 二进制没有报告预期版本 v2.9.3" >&2
    exit 1
fi

printf '%s\n' "$binary"
