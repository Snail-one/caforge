#!/bin/sh

set -eu

REPOSITORY="Snail-one/caforge"
RELEASE="${CAFORGE_VERSION:-latest}"
BINARY_NAME="${CAFORGE_BINARY_NAME:-caforge}"
MODE="install"
TEMP_DIR=""
STAGED_FILE=""

RESET=""
BOLD=""
ORANGE=""
BLUE=""
GREEN=""
YELLOW=""
RED=""

init_colors() {
	if [ "${NO_COLOR+set}" = "set" ]; then
		return
	fi
	if [ "${FORCE_COLOR:-0}" != "1" ]; then
		[ "${TERM:-}" != "dumb" ] || return
		[ -t 1 ] || return
	fi
	escape="$(printf '\033')"
	RESET="${escape}[0m"
	BOLD="${escape}[1m"
	ORANGE="${escape}[38;5;208m"
	BLUE="${escape}[34m"
	GREEN="${escape}[32m"
	YELLOW="${escape}[33m"
	RED="${escape}[31m"
}

banner() {
	printf '%s%s%s\n' "$BOLD$ORANGE" "╭─ CAForge" "$RESET"
	printf '%s│ %s%s\n' "$ORANGE" "$1" "$RESET"
	printf '%s%s%s\n\n' "$ORANGE" "╰──────────────────────────────────────────────" "$RESET"
}

step() { printf '%s[步骤]%s %s\n' "$ORANGE" "$RESET" "$*"; }
info() { printf '%s[信息]%s %s\n' "$BLUE" "$RESET" "$*"; }
result() { printf '%s[结果]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s[警告]%s %s\n' "$YELLOW" "$RESET" "$*"; }
fail() {
	printf '%s[错误]%s %s\n' "$RED" "$RESET" "$*" >&2
	exit 1
}

release_card() {
	printf '\n%s%s%s\n' "$BOLD$ORANGE" "╭─ CAForge" "$RESET"
	printf '%s│ %s%s%s\n' "$ORANGE" "$BOLD$ORANGE" "发布信息" "$RESET"
	printf '%s│ %s平台：%s%s/%s\n' "$ORANGE" "$BLUE" "$RESET" "$OS" "$ARCH"
	printf '%s│ %s当前版本：%s%s\n' "$ORANGE" "$BLUE" "$RESET" "$1"
	printf '%s│ %s目标版本：%s%s\n' "$ORANGE" "$BLUE" "$RESET" "$2"
	printf '%s│ %s执行操作：%s%s\n' "$ORANGE" "$BLUE" "$RESET" "$3"
	printf '%s%s%s\n' "$ORANGE" "╰──────────────────────────────────────────────" "$RESET"
}

usage() {
	printf '%s\n' \
		'用法：' \
		'  sh scripts/install.sh [版本]' \
		'  sh scripts/install.sh uninstall' \
		'' \
		'不指定版本时安装或更新到最新正式版本；也可指定标签，例如 v1.0.0。' \
		'卸载只删除 CAForge 程序，不删除 ~/.caforge 或 CAFORGE_HOME 中的 CA 数据。' \
		'' \
		'可选环境变量：' \
		'  CAFORGE_VERSION       安装的发布标签，默认为 latest' \
		'  CAFORGE_INSTALL_DIR   安装目录，默认为 ~/.local/bin' \
		'  CAFORGE_BINARY_NAME   安装后的命令名，默认为 caforge'
}

cleanup() {
	if [ -n "$STAGED_FILE" ]; then
		rm -f "$STAGED_FILE"
	fi
	if [ -n "$TEMP_DIR" ]; then
		rm -rf "$TEMP_DIR"
	fi
}

trap cleanup 0
trap 'exit 1' HUP INT TERM

case "${1:-}" in
	-h|--help)
		usage
		exit 0
		;;
	uninstall|--uninstall)
		MODE="uninstall"
		;;
	"") ;;
	*) RELEASE="$1" ;;
esac

init_colors

[ -n "${HOME:-}" ] || fail "无法确定用户主目录，请设置 HOME"
INSTALL_DIR="${CAFORGE_INSTALL_DIR:-${HOME}/.local/bin}"

case "$BINARY_NAME" in
	""|*/*) fail "命令名不能为空或包含路径分隔符" ;;
esac
case "$INSTALL_DIR" in
	/*) ;;
	*) fail "安装目录必须是绝对路径：$INSTALL_DIR" ;;
esac

TARGET="${INSTALL_DIR}/${BINARY_NAME}"
DATA_HOME="${CAFORGE_HOME:-${HOME}/.caforge}"

if [ "$MODE" = "uninstall" ]; then
	banner "自身卸载"
	step "检查安装状态"
	if [ ! -e "$TARGET" ] && [ ! -L "$TARGET" ]; then
		info "程序文件不存在：$TARGET"
		result "CAForge 当前未安装，无需卸载。"
		exit 0
	fi

	current="未知"
	if [ -x "$TARGET" ]; then
		current_line="$("$TARGET" --version 2>/dev/null | sed -n '1p' || true)"
		current="$(printf '%s\n' "$current_line" | awk '$1 == "caforge" { print $2; exit }')"
		[ -n "$current" ] || current="未知"
	fi
	info "当前版本：$current"
	info "程序路径：$TARGET"
	info "CA 数据：$DATA_HOME（保留，不会删除）"
	printf '\n'
	warn "卸载后命令将不可用，但所有 CA、私钥、证书和 CRL 数据都会保留。"
	printf '确认卸载？请输入 y 或 yes，其他输入取消： '
	IFS= read -r answer || answer=""
	case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
		y|yes) ;;
		*) result "已取消卸载，未修改任何文件。"; exit 0 ;;
	esac

	step "卸载程序"
	rm -f "$TARGET"
	[ ! -e "$TARGET" ] && [ ! -L "$TARGET" ] || fail "无法删除程序文件：$TARGET"
	result "CAForge 卸载完成。"
	info "CA 数据已保留：$DATA_HOME"
	exit 0
fi

banner "自身安装与更新"

case "$RELEASE" in
	*[!A-Za-z0-9._-]*) fail "版本号包含不支持的字符：$RELEASE" ;;
esac

case "$(uname -s)" in
	Linux) OS="linux" ;;
	Darwin) OS="darwin" ;;
	*) fail "不支持的操作系统：$(uname -s)" ;;
esac
case "$(uname -m)" in
	x86_64|amd64) ARCH="amd64" ;;
	aarch64|arm64) ARCH="arm64" ;;
	*) fail "不支持的处理器架构：$(uname -m)" ;;
esac

for required in awk chmod install mktemp mv sed tr uname; do
	command -v "$required" >/dev/null 2>&1 || fail "缺少必要命令：$required"
done

if command -v curl >/dev/null 2>&1; then
	download() {
		curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 --output "$2" "$1"
	}
	download_asset() {
		curl --fail --location --show-error --retry 3 --connect-timeout 15 --progress-bar --output "$2" "$1"
	}
elif command -v wget >/dev/null 2>&1; then
	download() {
		wget --quiet --tries=3 --timeout=15 --output-document="$2" "$1"
	}
	download_asset() {
		wget --tries=3 --timeout=15 --output-document="$2" "$1"
	}
else
	fail "需要 curl 或 wget 才能下载安装包"
fi

if command -v sha256sum >/dev/null 2>&1; then
	file_sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
	file_sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
	fail "需要 sha256sum 或 shasum 才能校验安装包"
fi

release_version_from_checksums() {
	awk -v os="$OS" -v arch="$ARCH" '
		{
			name = $2
			sub(/^\*/, "", name)
			prefix = "caforge_" os "_" arch "_"
			if (index(name, prefix) == 1) {
				version = substr(name, length(prefix) + 1)
				if (found != "" && found != version) mismatch = 1
				found = version
			}
		}
		END {
			if (found == "" || mismatch) exit 1
			print found
		}
	' "$1"
}

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/caforge-install.XXXXXX")"
step "检查发布版本"
if [ "$RELEASE" = "latest" ]; then
	metadata="${TEMP_DIR}/release.json"
	release_version=""
	if download "https://api.github.com/repos/${REPOSITORY}/releases/latest" "$metadata"; then
		release_version="$(sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$metadata" | sed -n '1p')"
	fi
	if [ -n "$release_version" ]; then
		info "最新正式版本：$release_version"
	else
		warn "GitHub Releases API 不可用，正在通过 checksums.txt 获取版本"
		checksum_file="${TEMP_DIR}/checksums.txt"
		download "https://github.com/${REPOSITORY}/releases/latest/download/checksums.txt" "$checksum_file" || fail "无法获取最新版本信息"
		release_version="$(release_version_from_checksums "$checksum_file")" || fail "checksums.txt 中没有唯一有效的版本号"
		info "最新正式版本：$release_version"
	fi
	latest_release=true
else
	release_version="$RELEASE"
	latest_release=false
	info "指定发布版本：$release_version"
fi
case "$release_version" in
	""|*[!A-Za-z0-9._-]*) fail "发布版本无效：$release_version" ;;
esac

asset="caforge_${OS}_${ARCH}_${release_version}"
download_base="https://github.com/${REPOSITORY}/releases/download/${release_version}"
asset_file="${TEMP_DIR}/${asset}"
checksum_file="${TEMP_DIR}/checksums.txt"

if [ ! -s "$checksum_file" ] && ! download "${download_base}/checksums.txt" "$checksum_file"; then
	legacy_checksum="checksums_${release_version}.txt"
	checksum_file="${TEMP_DIR}/${legacy_checksum}"
	warn "该版本使用旧版校验文件名，正在兼容处理"
	download "${download_base}/${legacy_checksum}" "$checksum_file" || fail "无法下载发布校验文件"
fi

expected="$(awk -v asset="$asset" '$2 == asset || $2 == "*" asset { print $1; exit }' "$checksum_file")"
[ "${#expected}" -eq 64 ] || fail "校验文件中没有 $asset 的有效 SHA-256"
case "$expected" in
	*[!0-9A-Fa-f]*) fail "校验文件中的 SHA-256 格式无效" ;;
esac

current_display="未安装"
action="安装"
if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
	current_release=""
	if [ -x "$TARGET" ]; then
		current_line="$("$TARGET" --version 2>/dev/null | sed -n '1p' || true)"
		current_release="$(printf '%s\n' "$current_line" | awk '$1 == "caforge" { print $2; exit }')"
	fi
	current_display="${current_release:-未知}"
	if [ "$current_release" = "$release_version" ]; then
		current_sha256="$(file_sha256 "$TARGET")"
		if [ "$current_sha256" = "$expected" ]; then
			release_card "$current_display" "$release_version" "无需更新"
			if [ "$latest_release" = true ]; then
				result "当前已是最新正式版本，无需更新。"
			else
				result "当前已是指定版本，无需更新。"
			fi
			exit 0
		fi
		action="修复安装"
		warn "版本号一致但程序校验失败，将重新下载修复"
	else
		action="更新"
	fi
fi

release_card "$current_display" "$release_version" "$action"
printf '\n'
step "下载发布文件"
info "正在下载：$asset"
download_asset "${download_base}/${asset}" "$asset_file"
result "发布文件下载完成"

printf '\n'
step "校验发布文件"
actual="$(file_sha256 "$asset_file")"
[ "$actual" = "$expected" ] || fail "发布文件 SHA-256 校验失败，旧程序未被修改"
result "SHA-256 校验通过"

chmod 0755 "$asset_file"
downloaded_line="$("$asset_file" --version 2>/dev/null | sed -n '1p' || true)"
downloaded_release="$(printf '%s\n' "$downloaded_line" | awk '$1 == "caforge" { print $2; exit }')"
[ "$downloaded_release" = "$release_version" ] || fail "下载程序的版本与目标版本不一致，旧程序未被修改"

printf '\n'
step "安装程序"
info "正在写入：$TARGET"
install -d -m 0755 "$INSTALL_DIR"
STAGED_FILE="${INSTALL_DIR}/.${BINARY_NAME}.new.$$"
install -m 0755 "$asset_file" "$STAGED_FILE"
mv -f "$STAGED_FILE" "$TARGET"
STAGED_FILE=""

result "CAForge ${action}完成：$TARGET"
info "版本：$release_version"
case ":${PATH:-}:" in
	*":${INSTALL_DIR}:"*) ;;
	*) warn "安装目录不在 PATH 中，请添加：$INSTALL_DIR" ;;
esac
