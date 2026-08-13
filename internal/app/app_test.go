package app

import (
	"bytes"
	"strings"
	"testing"

	"caforge/internal/store"
	"caforge/internal/ui"
	"caforge/internal/version"
)

func TestScriptedMenuCreatesRootAndExits(t *testing.T) {
	previousVersion := version.Version
	version.Version = "v9.8.7"
	t.Cleanup(func() { version.Version = previousVersion })
	// Main/CA/Create root, accept default algorithm and validity, confirm password,
	// return from CA menu, then exit the application.
	in := strings.NewReader("1\n1\n测试根\n\n\nsecret\nsecret\n0\n0\n")
	var out bytes.Buffer
	repo, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = New(ui.New(in, &out, false, nil), repo).Run(); err != nil {
		t.Fatal(err)
	}
	items, err := repo.ListAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name != "测试根" {
		t.Fatalf("authorities: %#v", items)
	}
	if !strings.Contains(out.String(), "[成功] 根 CA 已创建") {
		t.Fatalf("missing success output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "版本 v9.8.7") {
		t.Fatalf("主菜单缺少版本徽标：\n%s", out.String())
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("non-color UI emitted ANSI")
	}
}
