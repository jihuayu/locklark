package vaultfile

import (
	"math"
	"testing"
)

func TestVerifyContentTransitionPositive(t *testing.T) {
	fx := newRotationFixture(t)
	next := sealOrdinaryTransition(t, fx, fx.old.Header.ContentSeq+1,
		mustDigest(t, fx.old), fx.old.Header.OpID+"-next", fx.old.Header.KeyEpoch)
	if err := VerifyContentTransition(fx.oldEnc, next, fx.chain.anchor); err != nil {
		t.Fatalf("positive ordinary transition rejected: %v", err)
	}
}

func TestVerifyContentTransitionWrongParent(t *testing.T) {
	fx := newRotationFixture(t)
	next := sealOrdinaryTransition(t, fx, fx.old.Header.ContentSeq+1,
		digest("wrong-parent"), fx.old.Header.OpID+"-next", fx.old.Header.KeyEpoch)
	if err := VerifyContentTransition(fx.oldEnc, next, fx.chain.anchor); err == nil {
		t.Fatal("wrong parent digest accepted")
	}
}

func TestVerifyContentTransitionOverflow(t *testing.T) {
	fx := newRotationFixture(t)
	old := snapshotFile(fx.old)
	old.Header.ContentSeq = math.MaxUint64
	oldMax := fx.resignOld(t, old)
	next := sealOrdinaryTransition(t, fx, 1,
		digest("next-parent"), "op-next", fx.old.Header.KeyEpoch)
	if err := VerifyContentTransition(oldMax, next, fx.chain.anchor); err == nil {
		t.Fatal("content sequence overflow accepted")
	}
}

func TestVerifyContentTransitionManagedRefused(t *testing.T) {
	fx := newRotationFixture(t)
	next, err := SealAuthenticatedFile(fx.next, payloadFixtureDB(t),
		fx.chain.anchor, fx.vuk, fx.keys.dev1Priv)
	if err != nil {
		t.Fatalf("managed next setup: %v", err)
	}
	if err := VerifyContentTransition(fx.oldEnc, next, fx.chain.anchor); err == nil {
		t.Fatal("managed policy/epoch change accepted by ordinary verifier")
	}
}

func sealOrdinaryTransition(t *testing.T, fx *rotationFixture, contentSeq uint64, prev []byte, opID string, keyEpoch uint64) []byte {
	t.Helper()
	draft := builderDraft(&File{
		Format:             Format,
		Version:            Version,
		Header:             fx.old.Header,
		SignedPolicyProofs: fx.old.SignedPolicyProofs,
	})
	draft.Header.ContentSeq = contentSeq
	draft.Header.PrevDigest = append([]byte(nil), prev...)
	draft.Header.OpID = opID
	draft.Header.KeyEpoch = keyEpoch
	encoded, err := SealAuthenticatedFile(draft, payloadFixtureDB(t), fx.chain.anchor, fx.vuk, fx.keys.dev1Priv)
	if err != nil {
		t.Fatalf("seal ordinary transition: %v", err)
	}
	if _, err := ParseFile(encoded); err != nil {
		t.Fatalf("sealed ordinary transition does not parse: %v", err)
	}
	return encoded
}

func TestVerifyContentTransitionReusedOpID(t *testing.T) {
	fx := newRotationFixture(t)
	next := sealOrdinaryTransition(t, fx, fx.old.Header.ContentSeq+1,
		mustDigest(t, fx.old), fx.old.Header.OpID, fx.old.Header.KeyEpoch)
	if err := VerifyContentTransition(fx.oldEnc, next, fx.chain.anchor); err == nil {
		t.Fatal("reused op id accepted")
	}
}

func TestVerifyContentTransitionKeyEpochChangeRefused(t *testing.T) {
	fx := newRotationFixture(t)
	next := sealOrdinaryTransition(t, fx, fx.old.Header.ContentSeq+1,
		mustDigest(t, fx.old), "op-epoch-next", fx.old.Header.KeyEpoch+1)
	if err := VerifyContentTransition(fx.oldEnc, next, fx.chain.anchor); err == nil {
		t.Fatal("key epoch change accepted by ordinary verifier")
	}
}

func TestVerifyContentTransitionAuthenticatedReaderAuthorRefused(t *testing.T) {
	fx := newRotationFixture(t)
	nextEnc := sealOrdinaryTransition(t, fx, fx.old.Header.ContentSeq+1,
		mustDigest(t, fx.old), "op-reader-next", fx.old.Header.KeyEpoch)
	next, err := ParseFile(nextEnc)
	if err != nil {
		t.Fatal(err)
	}
	next.Header.AuthorDeviceID = "device-3d" // dave is a reader in the old policy
	oldFile, oldCurrent, err := verifyParsedAuthenticatedFile(fx.oldEnc, fx.chain.anchor)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyContentTransitionAuthenticated(oldFile, oldCurrent, next); err == nil {
		t.Fatal("reader author accepted by authenticated old-policy rule")
	}
}

func TestVerifyContentTransitionParentNilOrEmptyRefused(t *testing.T) {
	fx := newRotationFixture(t)
	nextEnc := sealOrdinaryTransition(t, fx, fx.old.Header.ContentSeq+1,
		mustDigest(t, fx.old), "op-parent-next", fx.old.Header.KeyEpoch)
	next, err := ParseFile(nextEnc)
	if err != nil {
		t.Fatal(err)
	}
	oldFile, oldCurrent, err := verifyParsedAuthenticatedFile(fx.oldEnc, fx.chain.anchor)
	if err != nil {
		t.Fatal(err)
	}
	for _, parent := range [][]byte{nil, {}} {
		next.Header.PrevDigest = parent
		if err := verifyContentTransitionAuthenticated(oldFile, oldCurrent, next); err == nil {
			t.Fatal("nil or empty parent digest accepted")
		}
	}
}

func TestVerifyContentTransitionReusedRevisionRefused(t *testing.T) {
	fx := newRotationFixture(t)
	nextEnc := sealOrdinaryTransition(t, fx, fx.old.Header.ContentSeq+1,
		mustDigest(t, fx.old), "op-revision-next", fx.old.Header.KeyEpoch)
	next, err := ParseFile(nextEnc)
	if err != nil {
		t.Fatal(err)
	}
	next.Header.RevisionID = fx.old.Header.RevisionID
	oldFile, oldCurrent, err := verifyParsedAuthenticatedFile(fx.oldEnc, fx.chain.anchor)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyContentTransitionAuthenticated(oldFile, oldCurrent, next); err == nil {
		t.Fatal("reused revision id accepted")
	}
}
