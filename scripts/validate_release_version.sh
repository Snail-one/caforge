#!/usr/bin/env bash

set -euo pipefail

version="${1:-}"
if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
    echo "错误：Release 版本必须以 v 开头并使用语义化格式，例如 v1.2.3 或 v1.2.3-rc.1：${version}" >&2
    exit 1
fi

printf '%s\n' "${version}"
