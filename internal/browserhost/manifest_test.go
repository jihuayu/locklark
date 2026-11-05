package browserhost

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestAllowlistAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "native host")
	if os.WriteFile(host, []byte("fixture"), 0700) != nil {
		t.Fatal("host")
	}
	for _, browser := range []string{"chrome", "edge", "firefox"} {
		raw, e := Manifest(browser, host)
		if e != nil {
			t.Fatal(e)
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil || m["path"] != host {
			t.Fatal("manifest")
		}
		if browser == "firefox" {
			if m["allowed_origins"] != nil || len(m["allowed_extensions"].([]any)) != 1 {
				t.Fatal("Firefox allowlist")
			}
		} else {
			if m["allowed_extensions"] != nil || m["allowed_origins"].([]any)[0] != "chrome-extension://"+ChromiumID+"/" {
				t.Fatal("Chromium allowlist")
			}
		}
	}
	output := filepath.Join(dir, HostName+".json")
	if Register("chrome", host, output, false) != nil || Register("chrome", host, output, false) == nil || Register("chrome", host, output, true) != nil {
		t.Fatal("overwrite policy")
	}
	for _, bad := range []string{"relative", "/tmp/invalid\npath", ""} {
		if _, e := Manifest("chrome", bad); e == nil {
			t.Fatal("bad path")
		}
	}
}
