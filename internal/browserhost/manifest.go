package browserhost

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func DefaultManifestPath(browser string) (string, error) {
	home, e := os.UserHomeDir()
	if e != nil {
		return "", e
	}
	var dir string
	switch runtime.GOOS {
	case "linux":
		switch browser {
		case "chrome":
			dir = filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts")
		case "edge":
			dir = filepath.Join(home, ".config", "microsoft-edge", "NativeMessagingHosts")
		case "firefox":
			dir = filepath.Join(home, ".mozilla", "native-messaging-hosts")
		}
	case "darwin":
		switch browser {
		case "chrome":
			dir = filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts")
		case "edge":
			dir = filepath.Join(home, "Library", "Application Support", "Microsoft Edge", "NativeMessagingHosts")
		case "firefox":
			dir = filepath.Join(home, "Library", "Application Support", "Mozilla", "NativeMessagingHosts")
		}
	case "windows":
		config, e := os.UserConfigDir()
		if e != nil {
			return "", e
		}
		if browser == "chrome" || browser == "edge" || browser == "firefox" {
			dir = filepath.Join(config, "Locklark", "NativeMessagingHosts", browser)
		}
	}
	if dir == "" {
		return "", ErrProtocol
	}
	return filepath.Join(dir, HostName+".json"), nil
}

// Manifest creates registration metadata only. Host binaries are separate so
// their browser mode is compiled in rather than inferred from untrusted argv.
func Manifest(browser, host string) ([]byte, error) {
	if !filepath.IsAbs(host) || filepath.Clean(host) != host || strings.ContainsAny(host, "\x00\r\n") {
		return nil, ErrProtocol
	}
	if trustedRegistrationFile(host, true) != nil {
		return nil, ErrProtocol
	}
	m := map[string]any{"name": HostName, "description": "Locklark native browser pairing and login fill", "path": host, "type": "stdio"}
	switch browser {
	case "chrome", "edge":
		m["allowed_origins"] = []string{"chrome-extension://" + ChromiumID + "/"}
	case "firefox":
		m["allowed_extensions"] = []string{FirefoxID}
	default:
		return nil, ErrProtocol
	}
	return json.MarshalIndent(m, "", "  ")
}

// Register refuses overwrite by default. The explicit output supports isolated
// browser profiles without writing a user's global browser settings.
func Register(browser, host, output string, replace bool) error {
	raw, e := Manifest(browser, host)
	if e != nil {
		return e
	}
	defer clear(raw)
	if !filepath.IsAbs(output) || filepath.Base(output) != HostName+".json" || filepath.Clean(output) != output || strings.ContainsAny(output, "\x00\r\n") {
		return ErrProtocol
	}
	if e = makeRegistrationParents(filepath.Dir(output)); e != nil {
		return e
	}
	if _, e = os.Lstat(output); e == nil {
		if !replace || trustedRegistrationFile(output, false) != nil {
			return ErrProtocol
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := privateRegistrationTemp(filepath.Dir(output))
	if e != nil {
		return e
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, e = f.Write(append(raw, '\n')); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if trustedRegistrationParent(filepath.Dir(output)) != nil || trustedRegistrationFile(temp, false) != nil {
		return ErrProtocol
	}
	if _, e = os.Lstat(output); e == nil {
		if !replace || trustedRegistrationFile(output, false) != nil {
			return ErrProtocol
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	return publishRegistrationTemp(temp, output, replace)
}

func makeRegistrationParents(dir string) error {
	var missing []string
	for current := dir; ; current = filepath.Dir(current) {
		_, e := os.Lstat(current)
		if e == nil {
			if trustedRegistrationParent(current) != nil {
				return ErrProtocol
			}
			break
		}
		if !os.IsNotExist(e) || filepath.Dir(current) == current {
			return ErrProtocol
		}
		missing = append(missing, current)
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if e := createRegistrationDirectory(missing[i]); e != nil && !os.IsExist(e) {
			return e
		}
		if trustedRegistrationParent(missing[i]) != nil {
			return ErrProtocol
		}
	}
	return trustedRegistrationParent(dir)
}
