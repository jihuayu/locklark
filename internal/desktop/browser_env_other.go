//go:build !linux

package desktop

import "github.com/jihuayu/passme/internal/browserhost"

func restoreBrowserAccessibility(browserhost.Browser) error { return nil }
