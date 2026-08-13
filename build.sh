#!/usr/bin/env bash

set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output_path="${1:-${project_dir}/caforge}"
version="${VERSION:-dev}"

if ! command -v go >/dev/null 2>&1; then
    echo "错误：未找到 Go，请先安装 Go 1.26 或更高版本。" >&2
    exit 1
fi

mkdir -p -- "$(dirname -- "${output_path}")"

echo "正在构建 CAForge ${version}..."
(
    cd -- "${project_dir}"
    go build \
        -buildvcs=false \
        -trimpath \
        -ldflags "-s -w -X main.version=${version}" \
        -o "${output_path}" \
        ./cmd/caforge
)

echo "构建完成：${output_path}"
