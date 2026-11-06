package browserhost

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// trustedTempDir returns a fresh temporary directory only when the same
// ownership checks used by registration accept its ancestry. Some sandboxes
// place /home and /tmp under a foreign uid; registration correctly refuses
// every path there, so skip instead of weakening the production checks.
func trustedTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	requireTrustedTempDir(t, dir)
	return dir
}

// requireTrustedTempDir applies the same guard to an existing fixture
// directory. Tests that can still exercise negative registration cases use
// this after those assertions but before their success paths.
func requireTrustedTempDir(t *testing.T, dir string) {
	t.Helper()
	if trustedRegistrationParent(dir) != nil {
		t.Skip("temporary directory ancestry is not owner-controlled in this sandbox")
	}
}

func TestManifestAllowlistAndNoOverwrite(t *testing.T) {
	dir := trustedTempDir(t)
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
