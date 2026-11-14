package vaultfile

import (
	"bytes"
	"testing"
)

// The tests here pin the frozen wire order of every semantically-set array:
// strictly ascending by raw ASCII identifier bytes (policy_seq for proofs),
// compared bytewise and case-sensitively, with a duplicate rejected by the
// same rule. An unsorted value is reported as CodeUnsortedCollection at the
// first offending element, never sorted by an encoder.

// sortedPolicy returns the vector policy reordered into the frozen wire order.
// Before this checkpoint the vector kept its role and device arrays in
// historical order; the vector pins the sorted encoding.
func sortedPolicy() *Policy {
	p := buildPolicy()
	p.Readers = []Member{
		{PrincipalID: "carol", Label: "Carol"},
		{PrincipalID: "erin", Label: "Erin"},
	}
	p.Writers = []Member{
		{PrincipalID: "bob", Label: "Bob"},
		{PrincipalID: "frank", Label: "Frank"},
	}
	p.Admins = []Member{{PrincipalID: "alice", Label: "Alice"}}
	p.Devices = []Device{
		{
			DeviceID:          "device-1",
			PrincipalID:       "alice",
			Label:             "Alice laptop",
			ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x21, 32)},
			PolicySigningKey:  &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: pf(0x22, 32)},
			AgeEncryptionKey:  ageRecipient(clientKey("device-1")),
		},
		{
			DeviceID:          "device-10",
			PrincipalID:       "frank",
			Label:             "Frank desktop",
			ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x63, 32)},
			PolicySigningKey:  &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: pf(0x64, 32)},
			AgeEncryptionKey:  ageRecipient(clientKey("device-10")),
		},
		{
			DeviceID:          "device-2",
			PrincipalID:       "bob",
			Label:             "Bob phone",
			ContentSigningKey: PublicKey{Alg: SigAlgEd25519, PublicKey: pf(0x31, 32)},
			PolicySigningKey:  &PublicKey{Alg: PolicySigAlgEd25519, PublicKey: pf(0x32, 32)},
			AgeEncryptionKey:  ageRecipient(clientKey("device-2")),
		},
	}
	return p
}

// sortedFile is the vector file with every set array in its frozen order:
// members erin/frank added so each role array has two entries, device-10 as a
// second device of frank, a second owner, and two delegations. Every entry is
// in strictly ascending id order, and device ids sort bytewise ("device-10"
// precedes "device-2").
func sortedFile(t *testing.T) *File {
	t.Helper()
	f := buildFile(t)
	p := sortedPolicy()
	p.OwnerRoot.Owners = append(p.OwnerRoot.Owners, Principal{PrincipalID: "frank", Label: "Frank"})
	p.Owners = append(p.Owners, Member{PrincipalID: "frank", Label: "Frank"})
	p.AdminDelegations[0].DelegationID = "deleg-01"
	p.AdminDelegations = append(p.AdminDelegations, AdminDelegation{
		DelegationID:     "deleg-02",
		DelegateDevice:   "device-10",
		GrantedBy:        "owner-root-01",
		Scope:            DelegationScope{InviteReaders: true, RemoveMembers: true},
		ScopeNote:        "restricted: readers only",
		ExpiresPolicySeq: 14,
	})
	setPolicy(f, p)
	slot := func(id string) DeviceSlot {
		d := deviceByID(t, &f.SignedPolicyProofs[0].Policy, id)
		return DeviceSlot{DeviceID: d.DeviceID, Recipient: d.AgeEncryptionKey, WrappedVUK: []byte("synthetic-age-wrapped-" + id)}
	}
	f.VUKDeviceSlots = []DeviceSlot{slot("device-1"), slot("device-10"), slot("device-2")}
	reseal(t, f)
	return f
}

// isolatedSortedFile is sortedFile with the current proof rebuilt from a
// private copy of its policy. setPolicy installs a shallow copy of p, so the
// sealed proof still shares p's Principal and Device structs (and those of a
// fresh buildPolicy) with sortedPolicy; a test that mutates the fixture in
// place must not reach through them. The copy is p's own encoding, so it is
// the document the sealed proof already carries.
func isolatedSortedFile(t *testing.T) *File {
	t.Helper()
	f := sortedFile(t)
	cur := *clonePolicy(&f.SignedPolicyProofs[0].Policy)
	f.SignedPolicyProofs[0].Document = docFor(&cur)
	f.SignedPolicyProofs[0].Policy = cur
	f.Header.PolicyDigest = DomainSeparated(UsagePolicyDocument, f.SignedPolicyProofs[0].Document)
	sealNegativeFixture(t, f)
	return f
}

// mutatePolicy returns a sorted sealed file whose current policy has been
// updated by mut. It never reseals: SealFile validates and would reject the
// very order rule under test.
//
// The current proof is rebuilt from p alone, so its carried document is p's
// own (possibly unsorted) encoding and never a stale one: the pair is the one
// value ValidatePolicy rejects. The header PolicyDigest binds the raw carried
// document with DomainSeparated; PolicyDigest and EncodePolicyDocument reject
// an unsorted p on purpose and cannot produce it. The header digest is bound
// before the revision id is derived, so the fixture's only defect is the
// order rule.
func mutatePolicy(t *testing.T, mut func(p *Policy)) *File {
	t.Helper()
	f := sortedFile(t)
	p := installPolicyForTest(t, f)
	mut(p)
	setPolicy(f, p)
	f.Header.PolicyDigest = DomainSeparated(UsagePolicyDocument, f.SignedPolicyProofs[0].Document)
	sealNegativeFixture(t, f)
	return f
}

// installPolicyForTest returns the mutation target: the fixture's current
// policy, decoded rather than copied so nested arrays are private, validated
// first so a broken fixture is visible before any mutation is applied.
func installPolicyForTest(t *testing.T, f *File) *Policy {
	t.Helper()
	p, err := ParsePolicyDocument(f.SignedPolicyProofs[0].Document)
	if err != nil {
		t.Fatalf("fixture current policy is not valid before mutation: %v", err)
	}
	return p
}

// checkRejectedEncodeAndParse requires every entry point that sees f to
// report the exact code and path under test: nothing sorts f into the frozen
// order on the way in, and nothing aliases or drops its document.
func checkRejectedEncodeAndParse(t *testing.T, f *File, code, path string) {
	t.Helper()
	// The proof document is carried verbatim, so the policy-only entry point
	// necessarily reports the same violation.
	wantCodeAt(t, ValidatePolicy(&f.SignedPolicyProofs[0].Policy), code, path)
	// The policy encoder refuses to emit an unsorted document ...
	_, err := EncodePolicyDocument(&f.SignedPolicyProofs[0].Policy)
	wantCodeAt(t, err, code, path)
	// ... the typed wire encoder rejects the whole file ...
	_, err = EncodeFile(f)
	wantCodeAt(t, err, code, path)
	// ... and so does the decoder over the same (possibly shape-only)
	// content on the wire.
	_, err = ParseFile([]byte(mustEncodeWith(t, f)))
	wantCodeAt(t, err, code, path)
}

func TestUnsortedCollectionCode(t *testing.T) {
	if CodeUnsortedCollection != "unsorted_collection" {
		t.Fatalf("CodeUnsortedCollection = %q", CodeUnsortedCollection)
	}
}

// TestSortedCollectionsAccepted is the positive counterpart of every
// rejection below: the same content in frozen order is a valid file, on both
// the typed and the wire path, and round-trips byte for byte.
func TestSortedCollectionsAccepted(t *testing.T) {
	f := sortedFile(t)
	enc, err := EncodeFile(f)
	if err != nil {
		t.Fatalf("sorted file rejected: %v", err)
	}
	got, err := ParseFile(enc)
	if err != nil {
		t.Fatalf("sorted wire file rejected: %v", err)
	}
	again, err := EncodeFile(got)
	if err != nil || !bytes.Equal(enc, again) {
		t.Fatalf("sorted file does not round-trip: %v", err)
	}
	p := &got.SignedPolicyProofs[0].Policy
	if len(p.Readers) != 2 || len(p.Writers) != 2 || len(p.OwnerRoot.Owners) != 2 ||
		len(p.Owners) != 2 || len(p.AdminDelegations) != 2 ||
		len(p.Devices) != 3 || len(got.VUKDeviceSlots) != 3 {
		t.Fatal("fixture no longer covers every collection with at least two entries")
	}
	// The fixture pins bytewise, not numeric, id order: device-10 precedes
	// device-2. Its ids are lower-case, the only spelling validID accepts.
	ids := []string{p.Devices[0].DeviceID, p.Devices[1].DeviceID, p.Devices[2].DeviceID}
	if ids[0] != "device-1" || ids[1] != "device-10" || ids[2] != "device-2" ||
		got.VUKDeviceSlots[1].DeviceID != "device-10" {
		t.Fatalf("fixture is not in bytewise id order: %q", ids)
	}
}

// TestCollectionOrderCaseSensitive pins that the frozen order is strict
// bytewise comparison of the ids: "erin" sorts before "zara" (0x65 < 0x7a),
// and accepting or rejecting a pair follows exactly that. Upper-case ids are
// not exercised: validID accepts only lower-case bytes, so
// an id such as "Zara" is invalid input and is rejected before any order rule
// can see it.
func TestCollectionOrderCaseSensitive(t *testing.T) {
	// The readers are carol then erin; an actually sorted lower-case id
	// appended after erin keeps the array in order, so it is accepted ...
	f := mutatePolicy(t, func(p *Policy) {
		p.Readers = append(p.Readers, Member{PrincipalID: "zara", Label: "Zara"})
	})
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("bytewise-ordered readers rejected: %v", err)
	}
	// ... while the same three readers with the last pair reversed (carol,
	// zara, erin) are reported at the first offending element, index 2.
	f = mutatePolicy(t, func(p *Policy) {
		p.Readers = append(p.Readers, Member{PrincipalID: "zara", Label: "Zara"})
		p.Readers[1], p.Readers[2] = p.Readers[2], p.Readers[1]
	})
	checkRejectedEncodeAndParse(t, f, CodeUnsortedCollection, "readers[2]")
}

func TestProofPolicySeqOrder(t *testing.T) {
	// The sorted two-proof fixture, old then current, is valid.
	f := twoProofFile(t)

	const wantPath = "signed_policy_proofs[1].policy.policy_seq"

	// A decrease is rejected at the second proof. It is not resealed: reseal
	// validates first and cannot produce a sealed invalid-order file, and
	// order is checked before the stale revision id.
	down := twoProofFile(t)
	tail := clonePolicy(&down.SignedPolicyProofs[1].Policy)
	tail.PolicySeq = down.SignedPolicyProofs[0].Policy.PolicySeq
	setPolicyAt(t, down, 1, tail)
	_, err := EncodeFile(down)
	wantCodeAt(t, err, CodeUnsortedCollection, wantPath)

	// ... and so is a duplicate policy_seq, by the same rule: appending a
	// second copy of the current proof breaks the order at index 2. A reseal
	// is not needed either.
	dup := twoProofFile(t)
	dup.SignedPolicyProofs = append(dup.SignedPolicyProofs,
		dup.SignedPolicyProofs[len(dup.SignedPolicyProofs)-1])
	_, err = EncodeFile(dup)
	wantCodeAt(t, err, CodeUnsortedCollection, "signed_policy_proofs[2].policy.policy_seq")

	// The current policy first is the same rejection, not a stale-revision
	// error: order is checked before the revision id.
	swapped := twoProofFile(t)
	swapped.SignedPolicyProofs[0], swapped.SignedPolicyProofs[1] = swapped.SignedPolicyProofs[1], swapped.SignedPolicyProofs[0]
	_, err = EncodeFile(swapped)
	wantCodeAt(t, err, CodeUnsortedCollection, wantPath)

	// Old-then-current stays valid.
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("old-then-current proofs rejected: %v", err)
	}
}

// setPolicyAt installs p as proof i of f and rebinds the header digest when i
// is the current proof, without validating p.
func setPolicyAt(t *testing.T, f *File, i int, p *Policy) {
	t.Helper()
	f.SignedPolicyProofs[i] = SignedPolicy{
		Document: docFor(p), Policy: *clonePolicy(p),
		SignerID: "owner-root-01", Alg: PolicySigAlgEd25519, Sig: pf(byte(0x44+i), 64),
	}
	if p.PolicySeq == f.Header.PolicySeq {
		f.Header.PolicyDigest = policyDigest(&f.SignedPolicyProofs[i])
	}
}

func TestPrincipalIDOrder(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(p *Policy)
		accept func(p *Policy)
		path   string
	}{
		{
			name: "owner_root.owners decrease",
			mut: func(p *Policy) {
				p.OwnerRoot.Owners[0], p.OwnerRoot.Owners[1] = p.OwnerRoot.Owners[1], p.OwnerRoot.Owners[0]
			},
			accept: func(p *Policy) {
				p.OwnerRoot.Owners[0].PrincipalID, p.OwnerRoot.Owners[1].PrincipalID = "alice", "frank"
			},
			path: "owner_root.owners[1]",
		},
		{
			name: "owner_root.owners duplicate",
			mut: func(p *Policy) {
				p.OwnerRoot.Owners[1].PrincipalID = "alice"
			},
			accept: func(p *Policy) {
				p.OwnerRoot.Owners[1].Label = "Alice again"
			},
			path: "owner_root.owners[1]",
		},
		{
			name: "readers decrease",
			mut: func(p *Policy) {
				p.Readers[0], p.Readers[1] = p.Readers[1], p.Readers[0]
			},
			accept: func(p *Policy) {
				p.Readers[0].PrincipalID, p.Readers[1].PrincipalID = "carol", "erin"
			},
			path: "readers[1]",
		},
		{
			name: "readers duplicate",
			mut: func(p *Policy) {
				p.Readers[1].PrincipalID = "carol"
			},
			path: "readers[1]",
		},
		{
			name: "writers decrease",
			mut: func(p *Policy) {
				p.Writers[0], p.Writers[1] = p.Writers[1], p.Writers[0]
			},
			accept: func(p *Policy) {
				p.Writers[0].PrincipalID, p.Writers[1].PrincipalID = "bob", "frank"
			},
			path: "writers[1]",
		},
		{
			name: "writers duplicate",
			mut: func(p *Policy) {
				p.Writers[1].PrincipalID = "bob"
			},
			path: "writers[1]",
		},
		{
			// "alice" before "frank" is sorted: the only violation left in
			// the admins array is the repeated principal_id.
			name: "admins duplicate",
			mut: func(p *Policy) {
				p.Admins = append(p.Admins, Member{PrincipalID: "alice", Label: "Alice"})
			},
			path: "admins[1]",
		},
		{
			name: "owners decrease",
			mut: func(p *Policy) {
				p.Owners[0], p.Owners[1] = p.Owners[1], p.Owners[0]
			},
			path: "owners[1]",
		},
		{
			name: "owners duplicate",
			mut: func(p *Policy) {
				p.Owners[1].PrincipalID = "alice"
			},
			path: "owners[1]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkRejectedEncodeAndParse(t, mutatePolicy(t, tc.mut), CodeUnsortedCollection, tc.path)
			if tc.accept == nil {
				return
			}
			// The same size and content in frozen order is accepted: the
			// rejection above is the order, not the length or a membership.
			f := mutatePolicy(t, tc.accept)
			if _, err := EncodeFile(f); err != nil {
				t.Fatalf("sorted variant rejected: %v", err)
			}
		})
	}
}

func TestAdminDelegationOrder(t *testing.T) {
	const path = "admin_delegations[1]"
	// A decrease: deleg-02 before deleg-01.
	f := mutatePolicy(t, func(p *Policy) {
		p.AdminDelegations[0].DelegationID, p.AdminDelegations[1].DelegationID = "deleg-02", "deleg-01"
	})
	checkRejectedEncodeAndParse(t, f, CodeUnsortedCollection, path)

	// A duplicate delegation id, rejected by the same rule.
	dup := mutatePolicy(t, func(p *Policy) {
		p.AdminDelegations[1].DelegationID = "deleg-01"
	})
	checkRejectedEncodeAndParse(t, dup, CodeUnsortedCollection, path)

	// Bytewise, not numeric: deleg-10 sorts before deleg-2 ('1' < '2'), so
	// that pair is the frozen order and is accepted ...
	bytewise := mutatePolicy(t, func(p *Policy) {
		p.AdminDelegations[0].DelegationID, p.AdminDelegations[1].DelegationID = "deleg-10", "deleg-2"
	})
	if _, err := EncodeFile(bytewise); err != nil {
		t.Fatalf("bytewise-ordered delegations rejected: %v", err)
	}
	// ... while the numeric-looking deleg-2 then deleg-10 is a decrease.
	numeric := mutatePolicy(t, func(p *Policy) {
		p.AdminDelegations[0].DelegationID, p.AdminDelegations[1].DelegationID = "deleg-2", "deleg-10"
	})
	checkRejectedEncodeAndParse(t, numeric, CodeUnsortedCollection, path)
}

func TestDeviceOrder(t *testing.T) {
	const path = "devices[2]"
	// device-10 sorts between device-1 and device-2 bytewise, so swapping the
	// latter two is a decrease, reported at the first element that violates
	// strict order.
	f := mutatePolicy(t, func(p *Policy) {
		p.Devices[1], p.Devices[2] = p.Devices[2], p.Devices[1]
	})
	checkRejectedEncodeAndParse(t, f, CodeUnsortedCollection, path)

	// The bytewise order device-1, device-10, device-2 is accepted ...
	sorted := mutatePolicy(t, func(p *Policy) {})
	if _, err := EncodeFile(sorted); err != nil {
		t.Fatalf("bytewise-ordered devices rejected: %v", err)
	}
	// ... and numeric order is not the rule: device-1, device-2, device-10
	// breaks at index 2.
	numeric := mutatePolicy(t, func(p *Policy) {
		p.Devices[1].DeviceID, p.Devices[2].DeviceID = "device-2", "device-10"
	})
	checkRejectedEncodeAndParse(t, numeric, CodeUnsortedCollection, path)

	// A duplicate device id is rejected by the same rule: a copy of device-10
	// at index 2 equals its predecessor, so the order first breaks at index 2.
	dup := mutatePolicy(t, func(p *Policy) {
		p.Devices[2].DeviceID = "device-10"
	})
	checkRejectedEncodeAndParse(t, dup, CodeUnsortedCollection, "devices[2]")
}

func TestVUKDeviceSlotOrder(t *testing.T) {
	const path = "vuk_device_slots[2]"

	// The slots in the frozen order are accepted ...
	f := isolatedSortedFile(t)
	if _, err := EncodeFile(f); err != nil {
		t.Fatalf("sorted slots rejected: %v", err)
	}
	// ... while device-2 before device-10 is a decrease. The proof is
	// untouched: the digest binding is exactly the one sortedFile sealed.
	f.VUKDeviceSlots[1], f.VUKDeviceSlots[2] = f.VUKDeviceSlots[2], f.VUKDeviceSlots[1]
	sealNegativeFixture(t, f)
	wantCodeAt(t, ValidateFile(f), CodeUnsortedCollection, path)
	_, err := EncodeFile(f)
	wantCodeAt(t, err, CodeUnsortedCollection, path)
	_, err = ParseFile([]byte(mustEncodeWith(t, f)))
	wantCodeAt(t, err, CodeUnsortedCollection, path)

	// A duplicate slot id is rejected by the same rule: copying slot 1 over
	// slot 2 repeats device-10 at element 2, so the order first breaks there.
	// The frozen order is the wire order, so the path names the actual
	// element.
	dup := isolatedSortedFile(t)
	dup.VUKDeviceSlots[2] = dup.VUKDeviceSlots[1]
	sealNegativeFixture(t, dup)
	const dupPath = "vuk_device_slots[2]"
	wantCodeAt(t, ValidateFile(dup), CodeUnsortedCollection, dupPath)
	_, err = EncodeFile(dup)
	wantCodeAt(t, err, CodeUnsortedCollection, dupPath)
	_, err = ParseFile([]byte(mustEncodeWith(t, dup)))
	wantCodeAt(t, err, CodeUnsortedCollection, dupPath)
}

// TestUnsortedPolicyDocumentRejected pins the proof path: a signed document
// carrying an unsorted set is rejected by ValidatePolicy, at the same path.
func TestUnsortedPolicyDocumentRejected(t *testing.T) {
	p := sortedPolicy()
	p.Readers[0], p.Readers[1] = p.Readers[1], p.Readers[0]
	_, err := EncodePolicyDocument(p)
	wantCodeAt(t, err, CodeUnsortedCollection, "readers[1]")
	_, err = ParsePolicyDocument(docFor(p))
	wantCodeAt(t, err, CodeUnsortedCollection, "readers[1]")
}

// TestEncodersNeverSort asserts that EncodeFile reports the unsorted input
// unchanged rather than emitting sorted bytes for it.
func TestEncodersNeverSort(t *testing.T) {
	f := mutatePolicy(t, func(p *Policy) {
		p.Devices[0], p.Devices[1] = p.Devices[1], p.Devices[0]
	})
	out, err := EncodeFile(f)
	if err == nil || out != nil {
		t.Fatal("encoder emitted bytes for an unsorted collection")
	}
	wantCodeAt(t, err, CodeUnsortedCollection, "devices[1]")
	out, err = EncodePolicyDocument(&f.SignedPolicyProofs[0].Policy)
	if err == nil || out != nil {
		t.Fatal("policy encoder emitted bytes for an unsorted collection")
	}
	wantCodeAt(t, err, CodeUnsortedCollection, "devices[1]")
}
