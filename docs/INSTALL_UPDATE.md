# CAForge 安装、更新与卸载

CAForge 使用 `scripts/install.sh` 统一完成首次安装、更新、指定版本安装、损坏程序修复和卸载。`caforge update` 与 `caforge uninstall` 会安全下载该脚本并调用它，不在程序内部重复实现 Release 解析逻辑。

## 默认位置

```text
程序：~/.local/bin/caforge
数据：~/.caforge
```

程序和 CA 数据彼此独立。更新只替换程序；卸载只删除程序，不会删除根 CA、中间 CA、任何私钥、签发记录、OpenSSL 索引或 CRL。

可通过环境变量覆盖位置：

```text
CAFORGE_INSTALL_DIR   程序安装目录，默认 ~/.local/bin
CAFORGE_BINARY_NAME   程序文件名，默认 caforge
CAFORGE_VERSION       正式 Release 标签，默认 latest
CAFORGE_HOME          CA 数据目录，默认 ~/.caforge
```

## 安装

```sh
curl -fsSL https://raw.githubusercontent.com/Snail-one/caforge/main/scripts/install.sh | sh
```

指定版本：

```sh
curl -fsSL https://raw.githubusercontent.com/Snail-one/caforge/main/scripts/install.sh |
  CAFORGE_VERSION=v1.0.0 sh
```

脚本支持：

- Linux amd64、Linux arm64
- macOS amd64、macOS arm64

## 更新

```sh
caforge update
```

更新顺序：

```text
获取最新正式 Release
  → 识别操作系统和 CPU 架构
  → 下载 checksums.txt
  → 比较现有程序版本与 SHA-256
  → 下载新程序到临时目录
  → 校验 SHA-256
  → 执行新程序并验证内嵌版本
  → 写入同目录临时文件
  → 原子替换正式程序
```

下载、校验、版本验证或临时写入失败时，原程序不会被修改。版本号与目标版本相同且 SHA-256 一致时直接退出；版本相同但文件校验不一致时重新下载修复。

历史 Release 使用 `checksums_<版本>.txt` 时，安装脚本会自动兼容；新 Release 统一使用 `checksums.txt`。

## 卸载

```sh
caforge uninstall
```

卸载前会显示：

- 当前程序版本
- 将删除的程序绝对路径
- 明确保留的 CA 数据目录

只有输入 `y` 或 `yes` 才会删除程序。其他输入均取消卸载。卸载完成后 CA 数据仍保留，可在重新安装 CAForge 后继续使用。

也可直接运行：

```sh
sh scripts/install.sh --uninstall
```

## 安全边界

- 管理脚本通过 HTTPS 从 `Snail-one/caforge` 的 `main` 分支获取，执行前限制为 1 MiB，并验证脚本头。
- Release 二进制必须通过对应 `checksums.txt` 中的 SHA-256 校验。
- 新程序必须能够执行，且报告的版本必须与目标 Release 标签一致。
- 正式目标路径只在所有验证通过后替换。
- 卸载绝不递归删除 `CAFORGE_HOME`。

如果安装到系统目录，可显式指定目录并自行提供所需权限：

```sh
CAFORGE_INSTALL_DIR=/usr/local/bin sh scripts/install.sh
```
