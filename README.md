# CAForge

CAForge 是一个使用 Go 编写的本地、单用户 CA 管理工具。它通过中文交互式终端菜单管理根 CA、中间 CA、服务器/客户端证书、吊销状态和 CRL，不需要 root 权限，也不启动网络服务。

## 构建与运行

需要 Go 1.26：

```sh
make build
./caforge
```

数据默认保存在 `~/.caforge`。可在测试或隔离环境中覆盖：

```sh
CAFORGE_HOME=/path/to/private/directory ./caforge
```

支持 `--help` 和 `--version`，不提供自动化子命令。设置 `NO_COLOR=1` 可关闭 ANSI 颜色；非终端输出和 `TERM=dumb` 也会自动关闭颜色。

## 安全与兼容性

- CA 私钥始终使用带口令的 PKCS#8：PBES2、AES-256-CBC、PBKDF2-HMAC-SHA-256、600,000 次迭代。
- 数据根目录及私钥目录权限为 `0700`，私钥和含私钥的导出文件为 `0600`。
- 每个 CA 维护独立的 OpenSSL 风格 `openssl.cnf`、`index.txt`、`serial`、`crlnumber`、`newcerts` 和 CRL 文件。
- 服务器证书必须包含 DNS 或 IP SAN；CSR 会验证签名和密钥强度，不复制未知扩展或 CA 权限请求。
- 吊销不可撤销，成功吊销后立即更新 PEM 和 DER CRL。

在备份整个 `CAFORGE_HOME` 前请确保备份介质同样受到强访问控制；遗失 CA 私钥口令无法恢复。

## 验证

```sh
make test
make vet
make race
```

端到端测试会执行根 CA → 中间 CA → 服务器/客户端证书 → CSR → 续期 → 吊销 → CRL → PKCS#12，并在可用时调用 OpenSSL 验证证书链和 CRL。
