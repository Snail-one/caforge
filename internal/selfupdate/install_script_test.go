package selfupdate

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallScriptSyntaxAndHelp(t *testing.T) {
	script := filepath.Join("..", "..", "scripts", "install.sh")
	if output, err := exec.Command("sh", "-n", script).CombinedOutput(); err != nil {
		t.Fatalf("安装脚本语法错误: %v\n%s", err, output)
	}
	output, err := exec.Command("sh", script, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("安装脚本帮助失败: %v\n%s", err, output)
	}
	for _, want := range []string{"安装或更新", "uninstall", "CAFORGE_INSTALL_DIR", "不删除 ~/.caforge"} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("安装脚本帮助缺少 %q：\n%s", want, output)
		}
	}
}

func TestInstallScriptUninstallRequiresConfirmationAndKeepsData(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	installDir := filepath.Join(home, ".local", "bin")
	dataHome := filepath.Join(home, ".caforge")
	if err = os.MkdirAll(installDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(dataHome, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(installDir, "caforge")
	if err = os.WriteFile(binary, []byte("#!/bin/sh\nprintf 'caforge v1.0.0\\n'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	dataFile := filepath.Join(dataHome, "keep-me")
	if err = os.WriteFile(dataFile, []byte("private CA data"), 0600); err != nil {
		t.Fatal(err)
	}

	run := func(input string) string {
		command := exec.Command("sh", script, "--uninstall")
		command.Stdin = strings.NewReader(input)
		command.Env = append(os.Environ(),
			"HOME="+home,
			"CAFORGE_INSTALL_DIR="+installDir,
			"CAFORGE_HOME="+dataHome,
			"NO_COLOR=1",
		)
		output, runErr := command.CombinedOutput()
		if runErr != nil {
			t.Fatalf("卸载脚本失败: %v\n%s", runErr, output)
		}
		return string(output)
	}

	if output := run("n\n"); !strings.Contains(output, "已取消卸载") {
		t.Fatalf("取消卸载输出异常：\n%s", output)
	}
	if _, err = os.Stat(binary); err != nil {
		t.Fatalf("取消卸载删除了程序: %v", err)
	}
	if output := run("yes\n"); !strings.Contains(output, "卸载完成") || !strings.Contains(output, "CA 数据已保留") {
		t.Fatalf("确认卸载输出异常：\n%s", output)
	}
	if _, err = os.Stat(binary); !os.IsNotExist(err) {
		t.Fatalf("程序未被删除: %v", err)
	}
	if contents, readErr := os.ReadFile(dataFile); readErr != nil || string(contents) != "private CA data" {
		t.Fatalf("卸载修改了 CA 数据: data=%q err=%v", contents, readErr)
	}
}

func TestInstallScriptVerifiesAndAtomicallyInstallsRelease(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("安装脚本仅支持 Linux 和 macOS")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	installDir := filepath.Join(home, ".local", "bin")
	releaseDir := filepath.Join(home, "release")
	fakeBinDir := filepath.Join(home, "fake-bin")
	for _, directory := range []string{releaseDir, fakeBinDir} {
		if err = os.MkdirAll(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}

	version := "v9.8.7"
	asset := fmt.Sprintf("caforge_%s_%s_%s", runtime.GOOS, runtime.GOARCH, version)
	binaryContents := []byte("#!/bin/sh\nprintf 'caforge v9.8.7\\n'\n")
	if err = os.WriteFile(filepath.Join(releaseDir, asset), binaryContents, 0755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binaryContents)
	if err = os.WriteFile(filepath.Join(releaseDir, "checksums.txt"), []byte(fmt.Sprintf("%x  %s\n", digest, asset)), 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(releaseDir, "release.json"), []byte("{\n  \"tag_name\": \"v9.8.7\"\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	fakeCurl := `#!/bin/sh
out=""
url=""
while [ "$#" -gt 0 ]; do
	case "$1" in
		--output) out="$2"; shift 2 ;;
		*) url="$1"; shift ;;
	esac
done
case "$url" in
	*/releases/latest) source_file="$FAKE_RELEASE_DIR/release.json" ;;
	*/checksums.txt) source_file="$FAKE_RELEASE_DIR/checksums.txt" ;;
	*) source_file="$FAKE_RELEASE_DIR/${url##*/}" ;;
esac
cp "$source_file" "$out"
`
	if err = os.WriteFile(filepath.Join(fakeBinDir, "curl"), []byte(fakeCurl), 0755); err != nil {
		t.Fatal(err)
	}

	run := func() string {
		command := exec.Command("sh", script)
		command.Env = append(os.Environ(),
			"HOME="+home,
			"CAFORGE_INSTALL_DIR="+installDir,
			"FAKE_RELEASE_DIR="+releaseDir,
			"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"NO_COLOR=1",
		)
		output, runErr := command.CombinedOutput()
		if runErr != nil {
			t.Fatalf("安装脚本失败: %v\n%s", runErr, output)
		}
		return string(output)
	}

	if output := run(); !strings.Contains(output, "SHA-256 校验通过") || !strings.Contains(output, "安装完成") {
		t.Fatalf("安装输出异常：\n%s", output)
	}
	installed := filepath.Join(installDir, "caforge")
	contents, err := os.ReadFile(installed)
	if err != nil || string(contents) != string(binaryContents) {
		t.Fatalf("安装程序不正确: data=%q err=%v", contents, err)
	}
	if output := run(); !strings.Contains(output, "无需更新") {
		t.Fatalf("重复更新未检测到相同版本和校验：\n%s", output)
	}
	matches, err := filepath.Glob(filepath.Join(installDir, ".caforge.new.*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("遗留暂存文件: %v err=%v", matches, err)
	}
}
