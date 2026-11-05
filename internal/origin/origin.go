// Package origin defines a deliberately narrow HTTPS DNS profile shared by
// future browser/mobile adapters. It performs no DNS or network requests.
package origin

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

var ErrOrigin = errors.New("unsupported HTTPS website or origin")

func parse(raw string) (*url.URL, string, error) {
	if len(raw) == 0 || len(raw) > 2048 || !strings.HasPrefix(raw, "https://") || strings.ContainsAny(raw, "\\?#") {
		return nil, "", ErrOrigin
	}
	for _, r := range raw {
		if r < 33 || r > 126 {
			return nil, "", ErrOrigin
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, "", ErrOrigin
	}
	host := strings.ToLower(u.Hostname())
	labels := strings.Split(host, ".")
	if len(labels) < 2 || len(host) > 253 {
		return nil, "", ErrOrigin
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || strings.HasPrefix(label, "xn--") {
			return nil, "", ErrOrigin
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return nil, "", ErrOrigin
			}
		}
	}
	// Numeric terminal labels include browser-specific IPv4 spellings. This
	// profile accepts only alphabetic TLDs, never IP or IDN interpretations.
	last := labels[len(labels)-1]
	if len(last) < 2 {
		return nil, "", ErrOrigin
	}
	for _, c := range last {
		if c < 'a' || c > 'z' {
			return nil, "", ErrOrigin
		}
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home.arpa"} {
		if strings.HasSuffix(host, suffix) {
			return nil, "", ErrOrigin
		}
	}
	port := u.Port()
	if strings.Contains(u.Host, ":") {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return nil, "", ErrOrigin
		}
		if port != "443" {
			host += ":" + port
		}
	}
	return u, "https://" + host, nil
}

// Website permits a path; paths never affect origin matching. Query strings,
// fragments, credentials, IP/IDN literals and ambiguous authority forms fail.
func Website(raw string) (string, error) { _, origin, err := parse(raw); return origin, err }

// Parse accepts an origin only: no path except an optional literal slash.
func Parse(raw string) (string, error) {
	u, origin, err := parse(raw)
	if err != nil {
		return "", err
	}
	if u.Path != "" && u.Path != "/" || u.RawPath != "" {
		return "", ErrOrigin
	}
	return origin, nil
}
