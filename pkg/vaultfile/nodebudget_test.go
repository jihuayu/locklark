package vaultfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests here drive decodeCanonical with a tiny decodeLimits so that
// member and node exhaustion are exercised on fixtures of a few bytes. Each
// failure is asserted on the exact code and path.

// testLimits builds tiny limits; the array limit stays generous unless a
// case sets it, so the case isolates the budget it names.
func testLimits(depth, members, nodes int) decodeLimits {
	return decodeLimits{maxDepth: depth, maxMembers: members, maxNodes: nodes, maxArray: 1 << 20}
}

func TestDecodeObjectMemberBudget(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		lim     decodeLimits
		code    string
		path    string
		wantErr bool
	}{
		// The object has exactly maxMembers members: both are read and only
		// the next key request is refused.
		{"two members at budget", `{"a":1,"b":2}`, testLimits(8, 2, 100), "", "", false},
		{"third member", `{"a":1,"b":2,"c":3}`, testLimits(8, 2, 100), CodeTooManyMembers, "", true},
		// The nested object closes first, so the path is the nested object.
		{"nested object", `{"a":{"b":1,"c":2,"d":3}}`, testLimits(8, 2, 100), CodeTooManyMembers, "a", true},
		{"deep nested object", `{"a":[{"b":1,"c":2,"d":3,"e":4}]}`, testLimits(8, 2, 100), CodeTooManyMembers, "a[]", true},
		// Member exhaustion is charged before the next key is read: the
		// duplicated and unknown keys behind it are never considered.
		{"duplicate behind budget", `{"a":1,"b":2,"a":3}`, testLimits(8, 2, 100), CodeTooManyMembers, "", true},
		// Duplicate detection still runs within the budget.
		{"duplicate within budget", `{"a":1,"a":2}`, testLimits(8, 2, 100), CodeDuplicateField, "a", true},
		// Array precheck stays ahead of the next child.
		{"array precheck", `{"a":[1,2,3,4]}`, decodeLimits{maxDepth: 8, maxMembers: 16, maxNodes: 100, maxArray: 3}, CodeTooManyItems, "a", true},
		{"array at budget", `{"a":[1,2,3]}`, decodeLimits{maxDepth: 8, maxMembers: 16, maxNodes: 100, maxArray: 3}, "", "", false},
		// Depth is checked before the node is charged.
		{"depth", `[[[1]]]`, testLimits(1, 2, 100), CodeTooDeep, "[][]", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := decodeCanonical([]byte(c.in), nil, c.lim)
			if !c.wantErr {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				if v == nil {
					t.Fatal("expected a value")
				}
				return
			}
			wantCodeAt(t, err, c.code, c.path)
		})
	}
}

func TestDecodeNodeBudget(t *testing.T) {
	cases := []struct {
		name string
		in   string
		lim  decodeLimits
		code string
		path string
		ok   bool
	}{
		// {"a":[1,true]} holds four nodes: object, array, 1, true.
		{"at budget", `{"a":[1,true]}`, testLimits(8, 16, 4), "", "", true},
		{"one over", `{"a":[1,true]}`, testLimits(8, 16, 3), CodeTooManyNodes, "a[]", false},
		// Object member names are not nodes: keys never consume budget.
		{"keys are free", `{"a":1,"b":2}`, testLimits(8, 16, 3), "", "", true},
		// A trailing value is never decoded, so it never takes a node.
		{"trailing beyond budget", `{"a":1} 2`, testLimits(8, 16, 2), CodeTrailingData, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := decodeCanonical([]byte(c.in), nil, c.lim)
			if c.ok {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			wantCodeAt(t, err, c.code, c.path)
			if c.code == CodeTooManyNodes && v != nil {
				t.Fatal("over-budget decode returned a value")
			}
		})
	}
}

// TestDefaultLimitsAdmitV1Schema pins the chosen constants: every object of
// v1 has at most 12 members (the policy document), both v1 fixtures fit well
// inside the node cap, and nesting is admitted as before.
func TestDefaultLimitsAdmitV1Schema(t *testing.T) {
	if MaxObjectMembers != 16 || MaxJSONNodes != 524288 {
		t.Fatalf("budgets changed: members=%d nodes=%d", MaxObjectMembers, MaxJSONNodes)
	}
	policyDoc := mustEncodeDoc(t)
	file := mustEncode(t)
	for _, in := range [][]byte{policyDoc, file} {
		if _, err := decodeCanonical(in, nil, defaultDecodeLimits()); err != nil {
			t.Fatalf("v1 fixture rejected by default limits: %v", err)
		}
	}
	// MaxObjectMembers+1 members is refused at the object itself, before the
	// next key is read; one member less is decoded.
	keys := make([]string, MaxObjectMembers+1)
	for i := range keys {
		keys[i] = `"k` + string(rune('a'+i)) + `":1`
	}
	_, err := decodeCanonical([]byte("{"+strings.Join(keys, ",")+"}"), nil, defaultDecodeLimits())
	wantCodeAt(t, err, CodeTooManyMembers, "")
	if _, err := decodeCanonical([]byte("{"+strings.Join(keys[:MaxObjectMembers], ",")+"}"), nil, defaultDecodeLimits()); err != nil {
		t.Fatalf("MaxObjectMembers members rejected: %v", err)
	}
	// The full 12-member policy object is at most 12 of the 16 admitted.
	// An unknown member is still reached and rejected as unknown_field
	// before the member budget can fire, because 13 <= MaxObjectMembers.
	extra := strings.Replace(string(policyDoc), `"policy_seq":`, `"extra":1,"policy_seq":`, 1)
	_, err = ParsePolicyDocument([]byte(extra))
	wantCodeAt(t, err, CodeUnknownField, "extra")
}

// TestNodeCapAdmitsV1ArrayBounds is the schema-wide part of the choice of
// MaxJSONNodes: a file at every per-array budget of v1 (128 proofs, each with
// a maximal policy: 5 arrays of 64 members, 64 delegations, 128 devices)
// decodes under the real node cap.
func TestNodeCapAdmitsV1ArrayBounds(t *testing.T) {
	member := `{"principal_id":"p","label":"L"}`
	arrOf := func(item string, n int) string {
		items := make([]string, n)
		for i := range items {
			items[i] = item
		}
		return "[" + strings.Join(items, ",") + "]"
	}
	delegation := `{"delegation_id":"d","delegate_device_id":"dev","granted_by":"k","scope":{` +
		`"invite_readers":true,"invite_writers":true,"remove_members":true,"remove_devices":true,` +
		`"promote_admin":true,"promote_owner":true,"replace_root":true},"scope_note":"n","expires_policy_seq":1}`
	device := `{"device_id":"dev","principal_id":"p","label":"L",` +
		`"content_signing_key":{"alg":"ed25519","public_key":"AA"},` +
		`"policy_signing_key":{"alg":"ed25519","public_key":"AA"},"age_encryption_key":"age1x"}`
	policy := `{"format":"locklark.vault-file","version":1,"vault_id":"v","policy_seq":1,` +
		`"prev_policy_digest":null,"owner_root":{"key_id":"k","alg":"ed25519","public_key":"AA","owners":` +
		arrOf(member, MaxPolicyArrayItems) + `},` +
		`"readers":` + arrOf(member, MaxPolicyArrayItems) +
		`,"writers":` + arrOf(member, MaxPolicyArrayItems) +
		`,"admins":` + arrOf(member, MaxPolicyArrayItems) +
		`,"owners":` + arrOf(member, MaxPolicyArrayItems) +
		`,"admin_delegations":` + arrOf(delegation, MaxDelegations) +
		`,"devices":` + arrOf(device, MaxArrayItems) + `}`
	proof := `{"document":"AA","policy":` + policy + `,"signer_id":"s","alg":"ed25519","sig":"AA"}`
	// The top-level array bound is compared in the decoder before its node
	// is charged: 128 proofs fit exactly.
	in := `{"signed_policy_proofs":` + arrOf(proof, MaxArrayItems) + `}`
	v, err := decodeCanonical([]byte(in), nil, defaultDecodeLimits())
	if err != nil {
		t.Fatalf("maximal v1 file rejected: %v", err)
	}
	// The whole file is 2 container nodes (the file object and the proofs
	// array) plus 128 copies of one proof subtree of 3,286 nodes: 420,610.
	// Nodes are values and containers; object keys are free. A proof is its
	// object (1) plus five members: `document`, `signer_id` and `alg`
	// (3), `sig` (1) and the policy (3,281) = 3,286. The policy is its
	// object (1) plus twelve members: six literals (1 each), owner_root
	// object with four literals (5), five member arrays (1 + 64 * 3 = 193
	// each), admin_delegations (1 + 64 * 14 = 897) and devices
	// (1 + 128 * 11 = 1,409): 1 + 6 + 5 + 5*193 + 897 + 1,409 = 3,281.
	want := 2 + 128*3286 // 420,610
	if n := nodeCount(v); n != want {
		t.Fatalf("maximal v1 file uses %d nodes, want %d", n, want)
	} else if n*8 > MaxJSONNodes*7 {
		t.Fatalf("maximal v1 file uses %d nodes of %d; margin below 1/8", n, MaxJSONNodes)
	}
}

// nodeCount counts the nodes of a decoded tree, object keys excluded, the
// same way the decoder charges them.
func nodeCount(v *value) int {
	n := 1
	for _, c := range v.arr {
		n += nodeCount(c)
	}
	for _, c := range v.obj {
		n += nodeCount(c)
	}
	return n
}

// TestNodeCountsResetPerInput proves the counters are per ParseFile /
// ParsePolicyDocument call: repeated parses of the same input all succeed.
func TestNodeCountsResetPerInput(t *testing.T) {
	enc := mustEncode(t)
	doc := mustEncodeDoc(t)
	for i := 0; i < 3; i++ {
		if _, err := ParseFile(enc); err != nil {
			t.Fatalf("ParseFile call %d: %v", i, err)
		}
		if _, err := ParsePolicyDocument(doc); err != nil {
			t.Fatalf("ParsePolicyDocument call %d: %v", i, err)
		}
	}
	// A rejected input does not poison the counter for the next one.
	_, err := ParseFile([]byte(`{"format":` + strings.Repeat(`[`, MaxJSONDepth+1) + strings.Repeat(`]`, MaxJSONDepth+1) + `}`))
	wantCode(t, err, CodeTooDeep)
	if _, err := ParseFile(enc); err != nil {
		t.Fatalf("ParseFile after rejection: %v", err)
	}
}

// TestNodeBudgetPublicPath pins that the public entry points apply the
// schema-wide budgets: an input that exceeds them is refused with the stable
// code and path, before its typed value is built.
func TestNodeBudgetPublicPath(t *testing.T) {
	enc := string(mustEncode(t))
	tooMany := `{"k1":1,"k2":1,"k3":1,"k4":1,"k5":1,"k6":1,"k7":1,"k8":1,"k9":1,"k10":1,"k11":1,"k12":1,"k13":1,"k14":1,"k15":1,"k16":1,"k17":1}`
	_, err := ParseFile([]byte(strings.Replace(enc, `"signed_policy_proofs":[`, `"signed_policy_proofs":[`+tooMany+`,`, 1)))
	wantCodeAt(t, err, CodeTooManyMembers, "signed_policy_proofs[]")
	doc := string(mustEncodeDoc(t))
	_, err = ParsePolicyDocument([]byte(strings.Replace(doc, `"readers":[`, `"readers":[`+tooMany+`,`, 1)))
	wantCodeAt(t, err, CodeTooManyMembers, "readers[]")
}

// TestV1FixturePublicPath is the public-path regression for this budget: the
// checked-in v1 vector and the freshly built fixture still parse through
// ParseFile and ParsePolicyDocument unchanged.
func TestV1FixturePublicPath(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "vaultfile-v1-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			File           string `json:"file"`
			PolicyDocument string `json:"policy_document"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, vec := range doc.Vectors {
		if _, err := ParseFile([]byte(vec.File)); err != nil {
			t.Fatalf("vector ParseFile: %v", err)
		}
		if _, err := ParsePolicyDocument([]byte(vec.PolicyDocument)); err != nil {
			t.Fatalf("vector ParsePolicyDocument: %v", err)
		}
	}
	if _, err := ParseFile(mustEncode(t)); err != nil {
		t.Fatalf("built ParseFile: %v", err)
	}
	if _, err := ParsePolicyDocument(mustEncodeDoc(t)); err != nil {
		t.Fatalf("built ParsePolicyDocument: %v", err)
	}
}
