package vaultfilebackend

import (
	"strings"
	"unicode/utf8"
)

// ValidName reports whether name is acceptable to every driver. Names are:
//
//   - non-empty, at most MaxNameSize bytes, valid UTF-8 without NUL;
//   - free of '/', '\\' and path separators, so they cannot escape the root;
//   - not "." or ".." and free of leading/trailing spaces or dots, so they map
//     unambiguously to one entry on case-insensitive or normalization-applying
//     local filesystems.
func ValidName(name string) bool {
	if len(name) == 0 || len(name) > MaxNameSize || !validUTF8NoNUL(name) {
		return false
	}
	if name == "." || name == ".." {
		return false
	}
	if name[0] == '.' || name[0] == ' ' || name[len(name)-1] == '.' || name[len(name)-1] == ' ' {
		return false
	}
	for _, r := range name {
		switch r {
		case '/', '\\':
			return false
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validUTF8NoNUL(s string) bool {
	return strings.IndexByte(s, 0) < 0 && utf8.ValidString(s)
}

func validValue(value []byte) bool {
	return len(value) > 0 && len(value) <= MaxValueSize
}

// validExpectedRevision reports whether expected is a well-formed revision for
// ReplaceIfVersion: non-zero and within MaxRevisionSize bytes. Drivers store and
// compare it verbatim; no other interpretation is allowed.
func validExpectedRevision(expected Revision) bool {
	return expected != "" && len(expected) <= MaxRevisionSize
}
