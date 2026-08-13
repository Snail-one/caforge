package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestInfo(t *testing.T) {
	oldVersion, oldCommit, oldBuildDate := Version, Commit, BuildDate
	Version, Commit, BuildDate = "v1.2.3", "abc1234", "2026-08-13T12:00:00Z"
	t.Cleanup(func() { Version, Commit, BuildDate = oldVersion, oldCommit, oldBuildDate })

	info := Info()
	for _, want := range []string{
		"caforge v1.2.3\n",
		"commit: abc1234\n",
		"build date: 2026-08-13T12:00:00Z\n",
		"go: " + runtime.Version() + "\n",
		"platform: " + runtime.GOOS + "/" + runtime.GOARCH,
	} {
		if !strings.Contains(info, want) {
			t.Fatalf("版本信息缺少 %q：\n%s", want, info)
		}
	}
}
