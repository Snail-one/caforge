package app

import (
	"bytes"
	"strings"
	"testing"

	"caforge/internal/domain"
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
	if !strings.Contains(out.String(), "根 CA 创建完成") {
		t.Fatalf("missing success output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "版本 v9.8.7") {
		t.Fatalf("主菜单缺少版本徽标：\n%s", out.String())
	}
	for _, want := range []string{"创建、查看和选择签发机构", "生成密钥签发或导入 CSR", "查询、续期和导出证书", "永久吊销证书并管理 CRL"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("主菜单缺少用途说明 %q：\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("non-color UI emitted ANSI")
	}
}

func TestFormInputsRetryInPlace(t *testing.T) {
	// Empty required value, invalid/out-of-range index, invalid days, then valid values.
	var out bytes.Buffer
	view := ui.New(strings.NewReader("\n有效名称\nabc\n9\n2\nnope\n-1\n30\n"), &out, false, nil)
	a := &App{ui: view}

	name, err := a.askRequired("名称: ", true)
	if err != nil || name != "有效名称" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	index, err := a.askIndex("编号: ", 3)
	if err != nil || index != 2 {
		t.Fatalf("index=%d err=%v", index, err)
	}
	days, err := a.days("天数 [397]: ", 397)
	if err != nil || days != 30 {
		t.Fatalf("days=%d err=%v", days, err)
	}

	got := out.String()
	for _, want := range []string{"此项不能为空", "1 到 3", "请输入正整数天数"} {
		if !strings.Contains(got, want) {
			t.Fatalf("重试提示缺少 %q：\n%s", want, got)
		}
	}
}

func TestChoicesAndPasswordRetryInPlace(t *testing.T) {
	var out bytes.Buffer
	view := ui.New(strings.NewReader("bad\n2\n9\n1\n\nsecret\nwrong\nsecret\nsecret\n"), &out, false, nil)
	a := &App{ui: view}

	profile, err := a.chooseProfile()
	if err != nil || profile != domain.Client {
		t.Fatalf("profile=%q err=%v", profile, err)
	}
	algorithm, err := a.chooseAlgorithm(false)
	if err != nil || algorithm != domain.ECDSAP256 {
		t.Fatalf("algorithm=%q err=%v", algorithm, err)
	}
	password, err := a.confirmedPassword("口令: ")
	if err != nil || string(password) != "secret" {
		t.Fatalf("password=%q err=%v", password, err)
	}

	got := out.String()
	if strings.Count(got, "无效选项") < 2 {
		t.Fatalf("选项未就地重试：\n%s", got)
	}
	for _, want := range []string{"口令不能为空", "两次口令不一致"} {
		if !strings.Contains(got, want) {
			t.Fatalf("口令重试提示缺少 %q：\n%s", want, got)
		}
	}
}
