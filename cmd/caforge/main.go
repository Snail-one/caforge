package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"caforge/internal/app"
	"caforge/internal/selfupdate"
	"caforge/internal/store"
	"caforge/internal/ui"
	"caforge/internal/version"
)

func main() {
	if handled := handleArgs(os.Args[1:]); handled {
		return
	}
	home := os.Getenv("CAFORGE_HOME")
	if home == "" {
		userHome, e := os.UserHomeDir()
		if e != nil {
			fatal(e)
		}
		home = filepath.Join(userHome, ".caforge")
	}
	repo, e := store.New(home)
	if e != nil {
		fatal(e)
	}
	if e = app.New(ui.NewConsole(), repo).Run(); e != nil {
		fatal(e)
	}
}

func handleArgs(arguments []string) bool {
	if len(arguments) == 0 {
		return false
	}
	if len(arguments) != 1 {
		fatal(fmt.Errorf("参数数量无效；请使用 caforge --help 查看用法"))
	}
	switch strings.ToLower(arguments[0]) {
	case "--version", "-v", "version":
		fmt.Println(version.Info())
	case "--help", "-h", "help":
		printUsage()
	case "update":
		view := ui.NewConsole()
		view.Info("正在从仓库获取 CAForge 管理脚本")
		view.Info("脚本地址：" + selfupdate.InstallScriptURL)
		if err := selfupdate.Run(); err != nil {
			fatal(err)
		}
	case "uninstall", "--uninstall":
		view := ui.NewConsole()
		view.Info("正在从仓库获取 CAForge 管理脚本")
		view.Info("脚本地址：" + selfupdate.InstallScriptURL)
		if err := selfupdate.Run("--uninstall"); err != nil {
			fatal(err)
		}
	default:
		fatal(fmt.Errorf("未知参数 %q；请使用 caforge --help 查看用法", arguments[0]))
	}
	return true
}

func printUsage() {
	fmt.Println(`CAForge - 本地 CA 管理工具

用法：
  caforge
  caforge update
  caforge uninstall
  caforge --version

命令：
  update       更新 /usr/local/bin/caforge，并校验 SHA-256
  uninstall    卸载程序，保留全部 CA 数据
  --version    显示版本和构建信息
  --help       显示帮助

安装、更新和卸载通常需要 sudo；正常运行不需要 root。
数据目录默认为 ~/.caforge，可用 CAFORGE_HOME 覆盖。`)
}

func fatal(err error) { ui.NewConsole().Error(err); os.Exit(1) }
