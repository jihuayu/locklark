package browserhost

import (
	"path/filepath"
	"runtime"
	"testing"
)

// The Safari helper is the only native host with a fixed identity pair and a
// single legal argv. These are policy-only checks: they never launch a helper
// and they assert nothing about a real Safari installation.
func TestSafariLaunchPolicyDarwin(t *testing.T) {
	if err := validateSafariLaunchForOS([]string{"--safari-browser"}, "darwin"); err != nil {
		t.Fatalf("exact Safari argv must be accepted on darwin: %v", err)
	}
	for _, args := range [][]string{
		nil,
		{},
		{"--safari-browser", "--safari-browser"},
		{"--safari-browser", "extra"},
		{"extra", "--safari-browser"},
		{"--safari-browser "},
		{"--safari-browser=true"},
		{"--safari"},
		{""},
		{"chrome-extension://" + ChromiumID + "/"},
		{FirefoxID},
		{SafariID},
		{filepath.Join(t.TempDir(), HostName+".json"), FirefoxID},
	} {
		if err := validateSafariLaunchForOS(args, "darwin"); err == nil {
			t.Fatalf("Safari launch must refuse args %q on darwin", args)
		}
	}
}

func TestSafariLaunchRefusedOnOtherHosts(t *testing.T) {
	for _, goos := range []string{"linux", "windows", "freebsd", "js", ""} {
		if err := validateSafariLaunchForOS([]string{"--safari-browser"}, goos); err != ErrProtocol {
			t.Fatalf("Safari launch must be refused on %q, got %v", goos, err)
		}
	}
}

func TestSafariLaunchRefusedOnThisHost(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin accepts the fixed Safari argv by policy")
	}
	if err := ValidateLaunch(Safari, []string{"--safari-browser"}); err != ErrProtocol {
		t.Fatalf("compiled Safari mode must refuse on %s, got %v", runtime.GOOS, err)
	}
	// Nothing else may turn into a Safari approval on this host.
	for _, args := range [][]string{
		nil,
		{"--safari-browser", ""},
		{"--safari-browser", FirefoxID},
		{"chrome-extension://" + ChromiumID + "/"},
		{filepath.Join(t.TempDir(), HostName+".json"), FirefoxID},
	} {
		if err := ValidateLaunch(Safari, args); err != ErrProtocol {
			t.Fatalf("Safari must refuse args %q on %s, got %v", args, runtime.GOOS, err)
		}
	}
}

// The existing Chromium/Firefox launch policy must not gain Safari behaviour.
func TestExistingLaunchPolicyUnaffectedBySafari(t *testing.T) {
	if err := validateLaunchForOS(Chromium, []string{"chrome-extension://" + ChromiumID + "/"}, "darwin"); err != nil {
		t.Fatalf("Chromium launch policy changed: %v", err)
	}
	if err := validateLaunchForOS(Chromium, []string{"--safari-browser"}, "darwin"); err == nil {
		t.Fatal("Chromium must not accept Safari argv")
	}
	manifest := filepath.Join(t.TempDir(), HostName+".json")
	if !filepath.IsAbs(manifest) {
		t.Fatalf("test manifest path must be absolute on this host: %s", manifest)
	}
	if err := validateLaunchForOS(Firefox, []string{manifest, FirefoxID}, "darwin"); err != nil {
		t.Fatalf("Firefox launch policy changed: %v", err)
	}
	if err := validateLaunchForOS(Firefox, []string{"--safari-browser"}, "darwin"); err == nil {
		t.Fatal("Firefox must not accept Safari argv")
	}
	// Mode selection can only come from the compiled argument, never from argv.
	if ValidateLaunch(Safari, []string{SafariID}) == nil {
		t.Fatal("Safari mode must not be selectable by a bundle identifier")
	}
}

func TestSafariBrokerHelloPolicy(t *testing.T) {
	safari := BrokerHello{V: 1, Browser: Safari, Origin: SafariID}
	if !validHelloForOS(safari, "darwin") {
		t.Fatal("pinned Safari hello must be valid on darwin")
	}
	for _, goos := range []string{"linux", "windows", "freebsd", ""} {
		if validHelloForOS(safari, goos) {
			t.Fatalf("Safari hello must be refused on %q", goos)
		}
	}
	for _, hello := range []BrokerHello{
		{V: 1, Browser: Safari},
		{V: 1, Browser: Safari, Origin: "chrome-extension://" + ChromiumID + "/"},
		{V: 1, Browser: Safari, Origin: FirefoxID},
		{V: 1, Browser: Safari, Origin: "org.locklark.browser.safari.extension"},
		{V: 1, Browser: Safari, Origin: "org.locklark.browser"},
		{V: 1, Browser: Safari, Origin: SafariID + "/"},
		{V: 2, Browser: Safari, Origin: SafariID},
	} {
		if validHelloForOS(hello, "darwin") {
			t.Fatalf("Safari hello must be refused: %+v", hello)
		}
	}
	// Existing identities keep their exact pinned origins on every host.
	for _, goos := range []string{"darwin", "linux", "windows"} {
		if !validHelloForOS(BrokerHello{V: 1, Browser: Chromium, Origin: "chrome-extension://" + ChromiumID + "/"}, goos) {
			t.Fatalf("Chromium hello regressed on %q", goos)
		}
		if !validHelloForOS(BrokerHello{V: 1, Browser: Firefox, Origin: FirefoxID}, goos) {
			t.Fatalf("Firefox hello regressed on %q", goos)
		}
		if validHelloForOS(BrokerHello{V: 1, Browser: Chromium, Origin: SafariID}, goos) {
			t.Fatalf("Safari origin must not authorize Chromium on %q", goos)
		}
	}
}

func TestSafariFixedIdentity(t *testing.T) {
	if Safari != "safari" {
		t.Fatalf("unexpected Safari browser value %q", Safari)
	}
	if SafariID != "org.locklark.browser.safari.Extension" {
		t.Fatalf("unexpected Safari extension identity %q", SafariID)
	}
	if SafariID == HostName || SafariID == FirefoxID || SafariID == ChromiumID {
		t.Fatal("Safari identity must stay distinct from the other native hosts")
	}
}
