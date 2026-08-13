# CAForge

CAForge 是一个使用 Go 编写的本地、单用户 CA 管理工具。它通过中文交互式终端菜单管理根 CA、中间 CA、服务器/客户端证书、吊销状态和 CRL，不需要 root 权限，也不启动网络服务。

## 安装、更新与卸载

安装脚本支持 Linux/macOS 的 amd64/arm64，默认安装到 `/usr/local/bin/caforge`：

```sh
curl -fsSL https://raw.githubusercontent.com/Snail-one/caforge/main/scripts/install.sh | sudo sh
```

安装后可通过相同脚本或 CAForge 命令更新到最新正式版本：

```sh
sudo caforge update
```

更新会先获取 `checksums.txt`，比较当前版本和文件 SHA-256；需要更新时先下载到临时目录，校验通过并确认新程序版本后再原子替换。当前程序损坏但版本号相同时会自动修复。

卸载需要输入 `y` 或 `yes` 确认，只删除程序文件，始终保留 `~/.caforge` 或 `CAFORGE_HOME` 中的根 CA、中间 CA、私钥、证书、索引和 CRL：

```sh
sudo caforge uninstall
```

也可以直接运行管理脚本，并可指定正式版本：

```sh
sudo sh scripts/install.sh
sudo sh scripts/install.sh v1.0.0
sudo sh scripts/install.sh --uninstall
```

完整流程和可选环境变量见 [安装、更新与卸载文档](docs/INSTALL_UPDATE.md)。`/usr/local/bin` 通常已包含在系统 `PATH` 中。

安装、更新和卸载因需要写入 `/usr/local/bin` 而使用 `sudo`；CAForge 正常运行和管理当前用户的 `~/.caforge` 时不要使用 `sudo`。

## 从源码构建与运行

需要 Go 1.26。无需安装 `make`，直接运行构建脚本：

```sh
./build.sh
./caforge
```

可选地指定输出路径和版本号：

```sh
VERSION=1.0.0 ./build.sh ./dist/caforge
```

数据默认保存在 `~/.caforge`。可在测试或隔离环境中覆盖：

```sh
CAFORGE_HOME=/path/to/private/directory ./caforge
```

支持 `update`、`uninstall`、`--help`、`--version` 和 `-v`。主菜单显示构建版本徽标，版本命令同时显示提交、构建时间、Go 版本和运行平台：

```text
caforge v1.0.0
commit: abc1234
build date: 2026-08-13T12:00:00Z
go: go1.26.5
platform: linux/amd64
```

设置 `NO_COLOR=1` 可关闭 ANSI 颜色；非终端输出和 `TERM=dumb` 也会自动关闭颜色。

## 交互界面

终端界面采用统一的橙色主视觉和 `CAForge › 功能 › 子功能` 面包屑标题；数字快捷键使用蓝色，返回项使用黄色，操作说明使用灰色，成功、警告和危险状态分别使用绿色、黄色和红色。菜单状态徽标及说明列按可见字符宽度对齐，中文不会破坏布局。

所有菜单使用 `0/q` 返回（同时兼容 `exit`），主菜单使用 `0/q` 退出。输入提示统一使用橙色 `❯`，详情和操作结果使用信息卡展示。设置 `CLICOLOR_FORCE=1` 可在非终端输出中强制启用颜色，但 `NO_COLOR` 始终优先。

CA 详情支持查看并复制根 CA/中间 CA 的公开证书和完整公开链、查看签发记录、停用或重新启用 CA、通过父根 CA 吊销中间 CA，以及删除没有下级和签发记录的空 CA。CA 私钥不会在查看功能中显示。根 CA 没有上级，不能吊销，只能停用或由客户端从信任库移除。

菜单编号、证书模板、密钥算法、有效天数、SAN、文件路径、确认文字和重复口令均在当前步骤校验。输入错误时会说明原因并原地重新提示，只有明确输入 `0`、`q` 或 `exit` 才返回上层菜单。每个可选操作都会同时显示用途、兼容性或安全影响。

## 安全与兼容性

- CA 私钥始终使用带口令的 PKCS#8：PBES2、AES-256-CBC、PBKDF2-HMAC-SHA-256、600,000 次迭代。
- 数据根目录及私钥目录权限为 `0700`，私钥和含私钥的导出文件为 `0600`。
- 每个 CA 维护独立的 OpenSSL 风格 `openssl.cnf`、`index.txt`、`serial`、`crlnumber`、`newcerts` 和 CRL 文件。
- 服务器证书必须包含 DNS 或 IP SAN；CSR 会验证签名和密钥强度，不复制未知扩展或 CA 权限请求。
- 吊销不可撤销，成功吊销后立即更新 PEM 和 DER CRL。

在备份整个 `CAFORGE_HOME` 前请确保备份介质同样受到强访问控制；遗失 CA 私钥口令无法恢复。

## 验证

```sh
go mod verify
go test ./...
go vet ./...
```

端到端测试会执行根 CA → 中间 CA → 服务器/客户端证书 → CSR → 续期 → 吊销 → CRL → PKCS#12，并在可用时调用 OpenSSL 验证证书链和 CRL。

## GitHub 自动化

- 推送 `v*` 标签会运行仅包含“编译”和“发布”两个 Job 的正式流水线，生成四个平台二进制、固定名称的 `checksums.txt`、提交说明和 GitHub Release。
- Dependabot 每周检查 Actions 与 Go Modules 更新。

发布示例：

```sh
git tag v1.0.0
git push origin v1.0.0
```

完整的触发方式、产物命名、权限模型和失败恢复说明见 [GitHub CI/CD 文档](docs/CI_CD.md)。
