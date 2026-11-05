//go:build windows

package browserhost

import (
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"strings"
)

func trustedRegistryKey(key registry.Key) error {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return ErrProtocol
	}
	sd, e := windows.GetSecurityInfo(windows.Handle(key), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return ErrProtocol
	}
	owner, _, e := sd.Owner()
	if e != nil || !registrationTrustedSID(owner, user.User.Sid) {
		return ErrProtocol
	}
	return registrationACL(sd, user.User.Sid, uint32(windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER|windows.GENERIC_ALL|windows.GENERIC_WRITE|registry.SET_VALUE|registry.CREATE_SUB_KEY))
}
func trustedRegistryParents(path string) error {
	for {
		key, e := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE|windows.READ_CONTROL)
		if e == nil {
			e = trustedRegistryKey(key)
			key.Close()
			if e != nil {
				return e
			}
		} else if !errors.Is(e, registry.ErrNotExist) {
			return e
		}
		if path == "" {
			return nil
		}
		i := strings.LastIndex(path, `\`)
		if i < 0 {
			path = ""
		} else {
			path = path[:i]
		}
	}
}

func RegisterUser(browser, manifest string, replace bool) error {
	paths := map[string]string{"chrome": `Software\Google\Chrome\NativeMessagingHosts\`, "edge": `Software\Microsoft\Edge\NativeMessagingHosts\`, "firefox": `Software\Mozilla\NativeMessagingHosts\`}
	prefix, ok := paths[browser]
	if !ok || trustedRegistrationFile(manifest, false) != nil || trustedRegistryParents(strings.TrimSuffix(prefix, `\`)) != nil {
		return ErrProtocol
	}
	access := uint32(registry.QUERY_VALUE | registry.SET_VALUE | windows.READ_CONTROL)
	key, e := registry.OpenKey(registry.CURRENT_USER, prefix+HostName, access)
	if e == nil {
		defer key.Close()
		if !replace {
			return ErrProtocol
		}
		if trustedRegistryKey(key) != nil {
			return ErrProtocol
		}
		return key.SetStringValue("", manifest)
	}
	if !errors.Is(e, registry.ErrNotExist) {
		return e
	}
	key, existed, e := registry.CreateKey(registry.CURRENT_USER, prefix+HostName, access)
	if e != nil {
		return e
	}
	defer key.Close()
	if existed && !replace {
		return ErrProtocol
	}
	if trustedRegistryKey(key) != nil {
		return ErrProtocol
	}
	return key.SetStringValue("", manifest)
}
