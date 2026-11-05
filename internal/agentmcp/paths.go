package agentmcp

import (
	"path/filepath"
	"strings"
)

func canonical(p string) (string, error) {
	s, e := filepath.Abs(p)
	if e != nil {
		return "", e
	}
	return filepath.EvalSymlinks(s)
}
func within(dir, path string) bool {
	rel, e := filepath.Rel(dir, path)
	return e == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func isolated(c Config) bool {
	a, e := canonical(c.Inbox)
	if e != nil {
		return false
	}
	b, e := canonical(c.Poll.Exchange)
	if e != nil || within(a, b) || within(b, a) {
		return false
	}
	priv, e := canonical(c.Poll.Private)
	if e != nil {
		return false
	}
	for _, dir := range []string{a, b} {
		if within(dir, priv) || within(priv, dir) {
			return false
		}
	}
	paths := []string{c.Poll.Key, c.Poll.Host, c.Poll.Recipient}
	if c.Bun != "" {
		paths = append(paths, c.Bun)
	}
	for _, p := range paths {
		x, e := canonical(p)
		if e != nil || within(a, x) || within(b, x) {
			return false
		}
	}
	return true
}
