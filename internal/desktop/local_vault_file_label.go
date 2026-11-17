package desktop

import (
	"fmt"
	"strings"

	"github.com/jihuayu/locklark/internal/vaultfileclient"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

const (
	localVaultFileReviewLabel     = "待核查文件"
	localVaultFileDuplicateSuffix = " · 重复待核查"
	localVaultFileLabelMinPrefix  = 8
	localVaultFileLabelMaxPrefix  = 32
)

// localVaultFileDisplayLabel is a display-only snapshot. The ref remains the
// exact navigation input; label is never an identity, route, or authority key.
type localVaultFileDisplayLabel struct {
	ref   localVaultFileRef
	label string
}

// localVaultFileDisplayLabels preserves every input ref and its order. Every
// distinct format-valid VaultID, including one on an invalid-name row, takes
// part in whole-list prefix extension. Valid display rows get "Name · prefix".
// Bidi controls are replaced in the display copy only. Any repeated valid full
// ID makes its normal-label rows duplicate/review, regardless of name. Multiple
// invalid shapes use deterministic display indexes in a fixed review fallback;
// they are not stable identities.
func localVaultFileDisplayLabels(refs []localVaultFileRef) []localVaultFileDisplayLabel {
	out := make([]localVaultFileDisplayLabel, len(refs))
	idCounts := make(map[string]int)
	displayNames := make([]string, len(refs))
	invalid := make([]bool, len(refs))
	reviewCount := 0

	for i, ref := range refs {
		out[i].ref = ref
		validID := vaultfileclient.ValidID(ref.vaultID)
		if validID {
			idCounts[ref.vaultID]++
		}
		if !validID || !vaultfilebackend.ValidName(ref.name) {
			invalid[i] = true
			reviewCount++
			continue
		}
		displayNames[i] = localVaultFileDisplayName(ref.name)
	}

	for i, ref := range refs {
		if invalid[i] {
			out[i].label = localVaultFileReviewLabel
			if reviewCount > 1 {
				out[i].label = fmt.Sprintf("%s #%d", localVaultFileReviewLabel, i+1)
			}
			continue
		}
		displayName := displayNames[i]
		prefixLen := localVaultFileLabelMinPrefix
		for otherID := range idCounts {
			if otherID == ref.vaultID {
				continue
			}
			needed := localVaultFileCommonPrefix(ref.vaultID, otherID) + 1
			if needed > localVaultFileLabelMaxPrefix {
				needed = localVaultFileLabelMaxPrefix
			}
			if needed > prefixLen {
				prefixLen = needed
			}
		}
		label := displayName + " · " + ref.vaultID[:prefixLen]
		if idCounts[ref.vaultID] > 1 {
			label += localVaultFileDuplicateSuffix
		}
		out[i].label = label
	}
	return out
}

// localVaultFileDisplayName creates a visible display copy without active bidi
// controls. The escape marker is a backslash, which ValidName rejects, and
// backslashes are escaped too so literal escape text cannot alias a control.
func localVaultFileDisplayName(name string) string {
	var display strings.Builder
	display.Grow(len(name))
	for _, r := range name {
		switch {
		case localVaultFileBidiControl(r):
			fmt.Fprintf(&display, `\u%04X`, r)
		case r == '\\':
			display.WriteString(`\\`)
		default:
			display.WriteRune(r)
		}
	}
	return display.String()
}

func localVaultFileBidiControl(r rune) bool {
	switch r {
	case '\u061c', '\u200e', '\u200f',
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069':
		return true
	}
	return false
}

func localVaultFileCommonPrefix(a, b string) int {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	i := 0
	for i < limit && a[i] == b[i] {
		i++
	}
	return i
}
