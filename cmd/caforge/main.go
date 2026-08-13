package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"caforge/internal/app"
	"caforge/internal/store"
	"caforge/internal/ui"
	"caforge/internal/version"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "CAForge - 本地 CA 管理工具\n\n用法: caforge [--help] [--version|-v]\n\n数据目录默认为 ~/.caforge，可用 CAFORGE_HOME 覆盖。\n")
	}
	showVersion := flag.Bool("version", false, "显示版本")
	showShortVersion := flag.Bool("v", false, "显示版本")
	flag.Parse()
	if *showVersion || *showShortVersion {
		fmt.Println(version.Info())
		return
	}
	if flag.NArg() != 0 {
		ui.NewConsole().Error(fmt.Errorf("caforge 不提供自动化子命令；请直接运行交互菜单"))
		os.Exit(2)
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
func fatal(err error) { ui.NewConsole().Error(err); os.Exit(1) }
