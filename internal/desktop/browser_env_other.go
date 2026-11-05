//go:build !linux

package desktop

import "github.com/jihuayu/locklark/internal/browserhost"

func restoreBrowserAccessibility(browserhost.Browser) error { return nil }
