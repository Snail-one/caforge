package selfupdate

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"
)

const (
	InstallScriptURL = "https://raw.githubusercontent.com/Snail-one/caforge/main/scripts/install.sh"
	maxScriptSize    = 1024 * 1024
)

func Run(arguments ...string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	return run(client, InstallScriptURL, os.Stdin, os.Stdout, os.Stderr, arguments...)
}

func run(client *http.Client, scriptURL string, stdin io.Reader, stdout, stderr io.Writer, arguments ...string) error {
	response, err := client.Get(scriptURL)
	if err != nil {
		return fmt.Errorf("下载 CAForge 管理脚本失败: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 CAForge 管理脚本失败: HTTP %d %s", response.StatusCode, http.StatusText(response.StatusCode))
	}
	if response.ContentLength > maxScriptSize {
		return fmt.Errorf("CAForge 管理脚本超过 %d 字节限制", maxScriptSize)
	}

	var downloaded bytes.Buffer
	if _, err = io.Copy(&downloaded, io.LimitReader(response.Body, maxScriptSize+1)); err != nil {
		return fmt.Errorf("读取 CAForge 管理脚本失败: %w", err)
	}
	data := downloaded.Bytes()
	if len(data) > maxScriptSize {
		return fmt.Errorf("CAForge 管理脚本超过 %d 字节限制", maxScriptSize)
	}
	if !bytes.HasPrefix(data, []byte("#!/bin/sh\n")) {
		return fmt.Errorf("下载内容不是有效的 CAForge 管理脚本")
	}

	temporary, err := os.CreateTemp("", "caforge-action-*.sh")
	if err != nil {
		return fmt.Errorf("创建 CAForge 管理脚本临时文件失败: %w", err)
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err = temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("设置 CAForge 管理脚本权限失败: %w", err)
	}
	if _, err = temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("保存 CAForge 管理脚本失败: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return fmt.Errorf("保存 CAForge 管理脚本失败: %w", err)
	}

	command := exec.Command("sh", append([]string{path}, arguments...)...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if err = command.Run(); err != nil {
		return fmt.Errorf("CAForge 管理脚本执行失败: %w", err)
	}
	return nil
}
