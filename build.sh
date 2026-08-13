#!/usr/bin/env bash

set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output_path="${1:-${project_dir}/caforge}"

if ! command -v go >/dev/null 2>&1; then
    echo "错误：未找到 Go，请先安装 Go 1.26 或更高版本。" >&2
    exit 1
fi

version="${VERSION:-$(git -C "${project_dir}" describe --tags --always --dirty 2>/dev/null || echo dev)}"
commit="${COMMIT:-$(git -C "${project_dir}" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
build_date="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

case "${version}" in
    *[!A-Za-z0-9._-]*)
        echo "错误：版本号只能包含字母、数字、点、下划线和连字符：${version}" >&2
        exit 1
        ;;
esac

mkdir -p -- "$(dirname -- "${output_path}")"

echo "正在构建 CAForge ${version}..."
(
    cd -- "${project_dir}"
    go build \
        -buildvcs=false \
        -trimpath \
        -ldflags "-s -w -X caforge/internal/version.Version=${version} -X caforge/internal/version.Commit=${commit} -X caforge/internal/version.BuildDate=${build_date}" \
        -o "${output_path}" \
        ./cmd/caforge
)

echo "构建完成：${output_path}"
