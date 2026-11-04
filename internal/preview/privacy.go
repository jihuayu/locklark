package preview

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// This screens common accidental pastes, not arbitrary opaque passwords.
// Match syntax and recognizable token prefixes, not the word "password" alone.
var credentialSyntax = regexp.MustCompile(`(?i)(?:\b(?:proxy-authorization|authorization|set-cookie|cookie)\s*:|\bbearer\s+\S|\b(?:password|passwd|secret|token|api[-_ ]?key|access[-_ ]?token|client[-_ ]?secret)\s*[:=]\s*\S|otpauth://|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|[a-z][a-z0-9+.-]*://[^/\s@]+:[^/\s@]+@|(?:gh[pousr]_|github_pat_|sk-(?:proj-)?|xox[baprs]-)[a-z0-9_-]{12,}|AGE-SECRET-KEY-1|\bA3-[A-Z0-9]{6}-[A-Z0-9]{6}-|\bAKIA[A-Z0-9]{16}\b)`)

func looksSensitive(s string) bool { return credentialSyntax.MatchString(norm.NFKC.String(s)) }
func validSession(s string) bool   { return sessionID.MatchString(s) && !looksSensitive(s) }
func validReason(s string) bool {
	return len(s) <= 960 && utf8.ValidString(s) && strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= 240 && strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) < 0 && !looksSensitive(s)
}
func displayedEvent(e Event) Event {
	if !validReason(e.Reason) {
		e.Reason = "[redacted]"
	}
	return e
}
