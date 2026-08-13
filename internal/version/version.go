package version

import (
	"fmt"
	"runtime"
)

// These values are replaced by -ldflags for release builds.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Info keeps the first line stable for scripts while exposing useful build
// diagnostics on the remaining lines.
func Info() string {
	return fmt.Sprintf(
		"caforge %s\ncommit: %s\nbuild date: %s\ngo: %s\nplatform: %s/%s",
		Version,
		Commit,
		BuildDate,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
	)
}
