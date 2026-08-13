package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestNavigationAndNoColor(t *testing.T) {
	var out bytes.Buffer
	term := New(strings.NewReader("x\n"), &out, false, nil)
	term.Header("主菜单 / 测试")
	v, err := term.Ask("选择: ")
	if err != nil || v != "x" {
		t.Fatalf("%q %v", v, err)
	}
	term.Success("完成")
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("color emitted when disabled")
	}
	if !IsBack("Q") || !IsBack("0") || !IsBack("exit") || IsBack("1") {
		t.Fatal("back navigation mismatch")
	}
}

func TestHomeHeaderIncludesVersion(t *testing.T) {
	var out bytes.Buffer
	term := New(strings.NewReader(""), &out, false, nil)
	term.HomeHeader("v9.8.7")
	for _, want := range []string{"CAForge", "本地 CA 管理工具", "版本 v9.8.7"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("主菜单标题缺少 %q：\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("禁用颜色时不应输出 ANSI 转义序列")
	}
}

func TestTargetPaletteAndMenuAlignment(t *testing.T) {
	var out bytes.Buffer
	term := New(strings.NewReader(""), &out, true, nil)
	term.MenuOptionHint("1", "创建根 CA", "自签名信任锚")
	term.MenuOptionHint("2", "创建中间 CA", "由根 CA 签发")
	term.MenuOptionStatus("3", "证书管理", term.LabelBadge("12 张", true))
	term.MenuExit("0/q", "返回")

	got := out.String()
	for _, want := range []string{blue, green, yellow, gray, "-- 自签名信任锚"} {
		if !strings.Contains(got, want) {
			t.Fatalf("目标 UI 输出缺少 %q：%q", want, got)
		}
	}
	plain := stripANSI(got)
	lines := strings.Split(strings.TrimSuffix(plain, "\n"), "\n")
	firstHint := strings.Index(lines[0], "--")
	secondHint := strings.Index(lines[1], "--")
	if displayWidth(lines[0][:firstHint]) != displayWidth(lines[1][:secondHint]) {
		t.Fatalf("说明列未对齐：\n%s", plain)
	}
}

func TestCardsAndPromptFollowTargetStyle(t *testing.T) {
	var out bytes.Buffer
	term := New(strings.NewReader("yes\n"), &out, true, nil)
	term.PrintSuccessCard("签发完成", CardField{Label: "序列号", Value: "1000", Detail: "已写入索引"})
	ok, err := term.Confirm("是否继续？")
	if err != nil || !ok {
		t.Fatalf("Confirm() = %v, %v", ok, err)
	}
	got := out.String()
	for _, want := range []string{bold + green, blue, gray, bold + orange + "❯ ", "（y/N）"} {
		if !strings.Contains(got, want) {
			t.Fatalf("卡片或提示缺少 %q：%q", want, got)
		}
	}
}

func TestNoColorTakesPrecedenceOverForce(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("CLICOLOR_FORCE", "1")
	term := NewConsole()
	if term.color {
		t.Fatal("NO_COLOR 必须优先于 CLICOLOR_FORCE")
	}
}

func stripANSI(input string) string {
	for _, code := range []string{reset, bold, dim, orange, blue, green, yellow, red, gray} {
		input = strings.ReplaceAll(input, code, "")
	}
	return input
}
