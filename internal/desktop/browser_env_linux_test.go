package desktop

import (
	"os"
	"testing"

	"github.com/jihuayu/locklark/internal/browserhost"
)

func TestNativeBrowserAccessibilityEnvironment(t *testing.T) {
	for _, browser := range []browserhost.Browser{browserhost.Chromium, browserhost.Firefox, "other"} {
		t.Run(string(browser), func(t *testing.T) {
			t.Setenv("NO_AT_BRIDGE", "1")
			t.Setenv("GTK_MODULES", "system-choice")
			t.Setenv("AT_SPI_BUS_ADDRESS", "system-bus-choice")
			if e := restoreBrowserAccessibility(browser); e != nil {
				t.Fatal(e)
			}
			_, present := os.LookupEnv("NO_AT_BRIDGE")
			if present != (browser == "other") {
				t.Fatal("wrong browser accessibility environment")
			}
			if os.Getenv("GTK_MODULES") != "system-choice" || os.Getenv("AT_SPI_BUS_ADDRESS") != "system-bus-choice" {
				t.Fatal("unrelated system accessibility setting changed")
			}
		})
	}
}
