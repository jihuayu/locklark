//go:build windows

package desktop

// desktopBrokerTrusted reports the localpath.TrustedTemporaryParent verdict
// for endpoint. LOCKLARK_BROWSER_SOCKET is not a filesystem socket path on
// Windows: it is a safe token that broker_windows.go appends to the per-user
// named-pipe name (see browserhost.DefaultBrokerEndpoint). The Unix temporary
// root guard never applies to that token, so the endpoint is always trusted
// and the test always drives the real named pipe.
func desktopBrokerTrusted(string) error { return nil }
