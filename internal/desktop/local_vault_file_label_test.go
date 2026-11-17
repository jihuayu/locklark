package desktop

import (
	"strings"
	"testing"
)

func TestLocalVaultFileDisplayLabelsExtendSharedNamePrefix(t *testing.T) {
	first := localVaultFileRef{
		path:    "/synthetic/same-name-first",
		name:    "Same",
		vaultID: "01234567000000000000000000000000",
	}
	second := localVaultFileRef{
		path:    "/synthetic/same-name-second",
		name:    "Same",
		vaultID: "01234567111111111111111111111111",
	}
	out := localVaultFileDisplayLabels([]localVaultFileRef{first, second})
	if len(out) != 2 {
		t.Fatal("LOCAL_VAULT_LABEL_COUNT_FAILED")
	}
	if out[0].ref != first || out[1].ref != second {
		t.Fatal("LOCAL_VAULT_LABEL_INPUT_REF_CHANGED")
	}
	if out[0].label != "Same · 012345670" || out[1].label != "Same · 012345671" {
		t.Fatal("LOCAL_VAULT_LABEL_SHARED_PREFIX_NOT_EXTENDED")
	}
}

func TestLocalVaultFileDisplayLabelsEscapeBidiControls(t *testing.T) {
	ref := localVaultFileRef{
		path:    "/synthetic/bidi",
		name:    "库\u202e名\u2066🙂\u2069",
		vaultID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	out := localVaultFileDisplayLabels([]localVaultFileRef{ref})
	if len(out) != 1 || out[0].ref != ref {
		t.Fatal("LOCAL_VAULT_LABEL_BIDI_REF_CHANGED")
	}
	if localVaultFileTestBidiControl(out[0].label) {
		t.Fatal("LOCAL_VAULT_LABEL_BIDI_CONTROL_SURVIVED")
	}
	if !strings.HasPrefix(out[0].label, "库\\u202E名\\u2066🙂\\u2069 · ") {
		t.Fatal("LOCAL_VAULT_LABEL_BIDI_NOT_VISIBLY_ESCAPED")
	}
	if !strings.ContainsRune(ref.name, '\u202e') {
		t.Fatal("LOCAL_VAULT_LABEL_BIDI_RAW_NAME_MUTATED")
	}
}

func TestLocalVaultFileDisplayLabelsBidiEscapeDoesNotCollide(t *testing.T) {
	controlName := "A\u202eB"
	literalName := `A\u202EB`
	const prefix = "aaaaaaaa"
	controlDisplay := localVaultFileDisplayName(controlName)
	literalDisplay := localVaultFileDisplayName(literalName)
	if controlDisplay == literalDisplay {
		t.Fatal("LOCAL_VAULT_LABEL_BIDI_ESCAPE_ALIASED")
	}
	if controlDisplay+" · "+prefix == literalDisplay+" · "+prefix {
		t.Fatal("LOCAL_VAULT_LABEL_BIDI_NORMAL_LABEL_ALIASED")
	}
	control := localVaultFileRef{path: "/synthetic/bidi-control", name: controlName, vaultID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	literal := localVaultFileRef{path: "/synthetic/bidi-literal", name: literalName, vaultID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	out := localVaultFileDisplayLabels([]localVaultFileRef{control, literal})
	if len(out) != 2 || out[0].ref != control || out[1].ref != literal {
		t.Fatal("LOCAL_VAULT_LABEL_BIDI_ESCAPE_REF_CHANGED")
	}
	if out[0].label == out[1].label {
		t.Fatal("LOCAL_VAULT_LABEL_BIDI_ESCAPE_LABEL_COLLISION")
	}
	if out[1].label != localVaultFileReviewLabel {
		t.Fatal("LOCAL_VAULT_LABEL_BIDI_ESCAPE_LITERAL_NOT_REVIEW")
	}
}

func localVaultFileTestBidiControl(s string) bool {
	for _, r := range s {
		switch r {
		case '\u061c', '\u200e', '\u200f',
			'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
			'\u2066', '\u2067', '\u2068', '\u2069':
			return true
		}
	}
	return false
}

func TestLocalVaultFileDisplayLabelsGlobalPrefixAcrossDifferentNames(t *testing.T) {
	first := localVaultFileRef{
		path:    "/synthetic/global-prefix-first",
		name:    "Alpha",
		vaultID: "01234567000000000000000000000000",
	}
	second := localVaultFileRef{
		path:    "/synthetic/global-prefix-second",
		name:    "Beta",
		vaultID: "01234567111111111111111111111111",
	}
	out := localVaultFileDisplayLabels([]localVaultFileRef{first, second})
	if len(out) != 2 {
		t.Fatal("LOCAL_VAULT_LABEL_GLOBAL_PREFIX_COUNT_FAILED")
	}
	if out[0].label != "Alpha · 012345670" || out[1].label != "Beta · 012345671" {
		t.Fatal("LOCAL_VAULT_LABEL_GLOBAL_PREFIX_NOT_EXTENDED")
	}
}

func TestLocalVaultFileDisplayLabelsGlobalDuplicateAcrossNames(t *testing.T) {
	duplicateID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	refs := []localVaultFileRef{
		{path: "/synthetic/global-duplicate-vault", name: "Vault", vaultID: duplicateID},
		{path: "/synthetic/global-duplicate-zwsp", name: "Va\u200blt", vaultID: duplicateID},
		{path: "/synthetic/global-duplicate-other", name: "库🙂\u200d名", vaultID: duplicateID},
	}
	before := append([]localVaultFileRef(nil), refs...)
	out := localVaultFileDisplayLabels(refs)
	if len(out) != len(refs) {
		t.Fatal("LOCAL_VAULT_LABEL_GLOBAL_DUPLICATE_COUNT_FAILED")
	}
	wants := []string{"Vault · ", "Va\u200blt · ", "库🙂\u200d名 · "}
	for i := range refs {
		if refs[i] != before[i] || out[i].ref != before[i] {
			t.Fatal("LOCAL_VAULT_LABEL_GLOBAL_DUPLICATE_REF_CHANGED")
		}
		if !strings.HasPrefix(out[i].label, wants[i]) {
			t.Fatal("LOCAL_VAULT_LABEL_GLOBAL_DUPLICATE_NAME_CHANGED")
		}
		if !strings.HasSuffix(out[i].label, localVaultFileDuplicateSuffix) {
			t.Fatal("LOCAL_VAULT_LABEL_GLOBAL_DUPLICATE_NOT_MARKED")
		}
	}
}

func TestLocalVaultFileDisplayLabelsGlobalPrefixCountsInvalidNameID(t *testing.T) {
	normal := localVaultFileRef{
		path:    "/synthetic/global-count-normal",
		name:    "Alpha",
		vaultID: "01234567000000000000000000000000",
	}
	other := localVaultFileRef{
		path:    "/synthetic/global-count-other",
		name:    "Beta",
		vaultID: "ffffffffffffffffffffffffffffffff",
	}
	badName := localVaultFileRef{
		path:    "/synthetic/global-count-bad-name",
		name:    "bad/name",
		vaultID: "01234567111111111111111111111111",
	}
	refs := []localVaultFileRef{normal, other, badName}
	out := localVaultFileDisplayLabels(refs)
	if len(out) != len(refs) {
		t.Fatal("LOCAL_VAULT_LABEL_GLOBAL_COUNT_FAILED")
	}
	if out[0].label != "Alpha · 012345670" {
		t.Fatal("LOCAL_VAULT_LABEL_GLOBAL_COUNT_OMITTED_INVALID_NAME_ID")
	}
	if out[1].label != "Beta · ffffffff" {
		t.Fatal("LOCAL_VAULT_LABEL_GLOBAL_COUNT_OVEREXTENDED_UNIQUE_ID")
	}
	if out[2].label != localVaultFileReviewLabel || out[2].ref != badName {
		t.Fatal("LOCAL_VAULT_LABEL_GLOBAL_COUNT_FALLBACK_CHANGED")
	}
}

func TestLocalVaultFileDisplayLabelsDuplicateAndInvalidRefsDegrade(t *testing.T) {
	duplicateID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	first := localVaultFileRef{path: "/synthetic/duplicate-first", name: "Same", vaultID: duplicateID}
	missing := localVaultFileRef{path: "/synthetic/review-missing"}
	second := localVaultFileRef{path: "/synthetic/duplicate-second", name: "Same", vaultID: duplicateID}
	badName := localVaultFileRef{path: "/synthetic/review-name", name: "bad/name", vaultID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	refs := []localVaultFileRef{first, missing, second, badName}
	out := localVaultFileDisplayLabels(refs)
	if len(out) != len(refs) {
		t.Fatal("LOCAL_VAULT_LABEL_DEGRADE_COUNT_FAILED")
	}
	for i := range refs {
		if out[i].ref != refs[i] {
			t.Fatal("LOCAL_VAULT_LABEL_DEGRADE_REF_CHANGED")
		}
	}
	if out[0].label != out[2].label {
		t.Fatal("LOCAL_VAULT_LABEL_DUPLICATE_FABRICATED_UNIQUE")
	}
	if !strings.HasSuffix(out[0].label, localVaultFileDuplicateSuffix) {
		t.Fatal("LOCAL_VAULT_LABEL_DUPLICATE_NOT_MARKED")
	}
	if out[1].label != localVaultFileReviewLabel+" #2" || out[3].label != localVaultFileReviewLabel+" #4" {
		t.Fatal("LOCAL_VAULT_LABEL_REVIEW_ROWS_NOT_DISTINGUISHED")
	}
}

func TestLocalVaultFileDisplayLabelsStableAcrossReorder(t *testing.T) {
	refs := []localVaultFileRef{
		{path: "/synthetic/reorder-a", name: "Same", vaultID: "01234567000000000000000000000000"},
		{path: "/synthetic/reorder-b", name: "Same", vaultID: "01234567111111111111111111111111"},
		{path: "/synthetic/reorder-c", name: "Other", vaultID: "ffffffffffffffffffffffffffffffff"},
		{path: "/synthetic/reorder-review", name: "bad/name", vaultID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}
	forward := localVaultFileDisplayLabels(refs)
	if forward[3].label != localVaultFileReviewLabel {
		t.Fatal("LOCAL_VAULT_LABEL_SINGLE_REVIEW_CHANGED")
	}
	reversedRefs := make([]localVaultFileRef, len(refs))
	for i := range refs {
		reversedRefs[i] = refs[len(refs)-1-i]
	}
	reversed := localVaultFileDisplayLabels(reversedRefs)
	labels := make(map[localVaultFileRef]string, len(refs))
	for _, entry := range forward {
		labels[entry.ref] = entry.label
	}
	if len(labels) != len(refs) {
		t.Fatal("LOCAL_VAULT_LABEL_REORDER_TEST_REFS_NOT_UNIQUE")
	}
	for i, entry := range reversed {
		if entry.ref != reversedRefs[i] {
			t.Fatal("LOCAL_VAULT_LABEL_REORDER_REF_CHANGED")
		}
		if labels[entry.ref] != entry.label {
			t.Fatal("LOCAL_VAULT_LABEL_REORDER_UNSTABLE")
		}
	}
}

func TestLocalVaultFileDisplayLabelsPreserveInputAndHidePath(t *testing.T) {
	const pathCanary = "DISPLAY_LABEL_PATH_CANARY"
	refs := []localVaultFileRef{
		{path: pathCanary + "/one", name: "Visible", vaultID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{path: pathCanary + "/two", name: "bad/name", vaultID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{path: pathCanary + "/three", name: "Visible", vaultID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	before := append([]localVaultFileRef(nil), refs...)
	out := localVaultFileDisplayLabels(refs)
	if len(out) != len(refs) {
		t.Fatal("LOCAL_VAULT_LABEL_PRESERVE_COUNT_FAILED")
	}
	for i := range refs {
		if refs[i] != before[i] {
			t.Fatal("LOCAL_VAULT_LABEL_MUTATED_INPUT")
		}
		if out[i].ref != before[i] {
			t.Fatal("LOCAL_VAULT_LABEL_ORIGINAL_REF_LOST")
		}
		if strings.Contains(out[i].label, pathCanary) {
			t.Fatal("LOCAL_VAULT_LABEL_PATH_EXPOSED")
		}
	}
}
