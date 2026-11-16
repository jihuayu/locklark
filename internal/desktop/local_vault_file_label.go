package desktop

import (
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

// localVaultFileDisplayLabels preserves every input ref and its order. Valid
// refs get "Name · prefix", where same-name groups extend each distinct ID's
// prefix only as far as needed to distinguish it from the other full IDs.
// Duplicate same-name/full-ID refs share one marked label rather than gaining
// a fabricated unique suffix. Invalid shapes use a fixed review fallback.
func localVaultFileDisplayLabels(refs []localVaultFileRef) []localVaultFileDisplayLabel {
	out := make([]localVaultFileDisplayLabel, len(refs))
	idCounts := make(map[string]map[string]int)
	valid := make([]bool, len(refs))

	for i, ref := range refs {
		out[i].ref = ref
		if !vaultfileclient.ValidID(ref.vaultID) || !vaultfilebackend.ValidName(ref.name) {
			out[i].label = localVaultFileReviewLabel
			continue
		}
		valid[i] = true
		counts := idCounts[ref.name]
		if counts == nil {
			counts = make(map[string]int)
			idCounts[ref.name] = counts
		}
		counts[ref.vaultID]++
	}

	for i, ref := range refs {
		if !valid[i] {
			continue
		}
		prefixLen := localVaultFileLabelMinPrefix
		for otherID := range idCounts[ref.name] {
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
		label := ref.name + " · " + ref.vaultID[:prefixLen]
		if idCounts[ref.name][ref.vaultID] > 1 {
			label += localVaultFileDuplicateSuffix
		}
		out[i].label = label
	}
	return out
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
