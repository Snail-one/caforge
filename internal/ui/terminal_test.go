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
	if !IsBack("Q") || !IsBack("0") || IsBack("1") {
		t.Fatal("back navigation mismatch")
	}
}
