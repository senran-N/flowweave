#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MANIFEST="benchmark-results/SHA256SUMS"
if [[ ! -f "$MANIFEST" ]]; then
    echo "缺少证据校验清单：$MANIFEST" >&2
    exit 1
fi

sha256sum --check --strict --quiet "$MANIFEST"

expected_count="$(wc -l < "$MANIFEST")"
actual_count="$(find benchmark-results -maxdepth 1 -type f -name '*.csv' -printf '.' | wc -c)"
if [[ "$actual_count" != "$expected_count" ]]; then
    echo "证据文件数量不一致：清单 $expected_count，目录 $actual_count" >&2
    exit 1
fi

echo "FlowWeave 证据校验通过：$actual_count 个 CSV"
