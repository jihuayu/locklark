package desktop

import (
	"strings"
	"sync"

	"github.com/egoist/mygo"
)

// desktopVersionLabel distinguishes a packaged release from a development
// build. MyGo injects the configured version only when the app is packaged.
func desktopVersionLabel() string {
	if version := strings.TrimSpace(mygo.App.Version()); version != "" {
		return version
	}
	return "开发版"
}

var canSelfUpdate = sync.OnceValue(func() bool {
	return desktopVersionLabel() != "开发版" && mygo.Updater.Enabled()
})

func desktopCanSelfUpdate() bool {
	return canSelfUpdate()
}
