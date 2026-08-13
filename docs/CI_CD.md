# CAForge GitHub CI/CD

CAForge 使用一条精简的正式 Release 流水线，只包含矩阵编译和 GitHub Release 发布，并根据 CAForge 的本地跨平台用途覆盖 Linux 和 macOS。

## 正式发布

`.github/workflows/release.yml` 支持两种触发方式：

```bash
git tag v1.0.0
git push origin v1.0.0
```

也可以在 Actions 页面手动运行 `release`，输入 `v1.0.0` 格式的 `tag_name`。

发布流程为：

```text
四平台并行构建
  └── 汇总 Artifact
        └── SHA-256 校验和
              └── Release Notes
                    └── GitHub Release
```

建议正式版本采用 `v主版本.次版本.修订版本`，也可以使用 `v1.0.0-rc.1` 形式的预发布后缀。

## Release 产物

以 `v1.0.0` 为例：

```text
caforge_linux_amd64_v1.0.0
caforge_linux_arm64_v1.0.0
caforge_darwin_amd64_v1.0.0
caforge_darwin_arm64_v1.0.0
checksums_v1.0.0.txt
```

所有二进制使用相同的版本、完整提交 SHA 和提交时间，并通过 `-trimpath`、`CGO_ENABLED=0` 构建。

发布说明由两部分组成：`scripts/generate_release_notes.sh` 列出上一个版本以来的直接提交，GitHub 原生 Release Notes 补充 Pull Request、贡献者和比较链接。

## 权限与失败处理

- Build Job 只有只读权限。
- 只有最终 Release Job 拥有 `contents: write`。
- 任一平台构建失败都会阻止发布。
- Artifact 缺失、校验和生成失败或 Release Notes 失败都会阻止发布。
- 同一版本的发布不会相互取消或并发执行。
- 发布失败且源码未改变时，应重新运行失败的 Job，不应移动已公开使用的标签。

仓库或组织策略必须允许 GitHub Actions 为 Release Job 使用 `contents: write`。建议为 `main` 配置分支保护，并在发布标签前于本地执行完整测试。

## 依赖自动更新

`.github/dependabot.yml` 每周一（Asia/Shanghai）检查 GitHub Actions 和 Go Modules，并分别合并为分组 Pull Request。

## 发布前检查

```bash
go mod verify
go test ./...
go vet ./...
VERSION=v1.0.0 ./build.sh /tmp/caforge
/tmp/caforge --version
```
