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
	if out[1].label != localVaultFileReviewLabel || out[3].label != localVaultFileReviewLabel {
		t.Fatal("LOCAL_VAULT_LABEL_INVALID_SHAPE_NOT_REVIEW")
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
