#!/usr/bin/env bash

set -euo pipefail

release_tag="${RELEASE_TAG:?RELEASE_TAG is required}"
target_sha="${TARGET_SHA:-HEAD}"
repository="${GITHUB_REPOSITORY:-unknown/caforge}"
output_path="${1:-release-notes.md}"

if git rev-parse --verify --quiet "refs/tags/${release_tag}" >/dev/null; then
    target="refs/tags/${release_tag}"
else
    target="${target_sha}"
fi

previous_tag="$(
    git tag --merged "${target}" --list 'v*' --sort=-version:refname |
        awk -v current="${release_tag}" '$0 != current && !found { print; found = 1 }'
)"

if [[ -n "${previous_tag}" ]]; then
    range="${previous_tag}..${target}"
else
    range="${target}"
fi

{
    printf '## 本次更新\n\n'
    first_commit="$(git rev-list --max-count=1 --no-merges "${range}")"
    if [[ -n "${first_commit}" ]]; then
        git log "${range}" --no-merges --format='%H%x09%s' --no-decorate |
            while IFS=$'\t' read -r commit subject; do
                short_commit="${commit:0:7}"
                subject="$(printf '%s' "${subject}" | sed -e 's/^[[:space:]]*//' -e 's/^[•*-][[:space:]]*//')"
                if [[ -z "${subject}" ]]; then
                    subject="无标题提交"
                fi
                printf -- '- %s ([`%s`](https://github.com/%s/commit/%s))\n' \
                    "${subject}" "${short_commit}" "${repository}" "${commit}"
            done
    else
        printf '本版本未检测到新的提交。\n'
    fi
} > "${output_path}"

printf 'Release notes generated: %s\n' "${output_path}"
