package vaultfile

import (
	"bytes"
	"encoding/hex"
)

// Canonical preimages.
//
// Three values are derived from one vault file. Each has its own v1 domain
// label and NUL separator:
//
//	RevisionID(f) = hex( SHA-256( DomainRevision || 0x00
//	                              || canonical_file_without(revision, sig) ) )
//	  where canonical_file_without(revision, sig) is the canonical file with
//	  the header member revision_id and the file member content_signature
//	  removed entirely.
//
//	ContentSigningBytes(f) = the canonical file with header.revision_id set to
//	  RevisionID(f) and content_signature removed entirely. The content signer
//	  signs DomainContentSignature || 0x00 || ContentSigningBytes(f).
//
//	FileDigest(f) = hex( SHA-256( DomainFileDigest || 0x00
//	                              || canonical sealed file ) )
//	  where the canonical sealed file is EncodeFile(f) unchanged, revision id
//	  and content signature included.
//
// Removal is literal: no member, placeholder object or null stands in for a
// removed value, so an independent implementation never has to agree on how a
// placeholder would be written.
//
// The three preimages are produced by the internal encoder
// (encodeFileWire) directly, never by EncodeFile or ValidateFile, so a
// preimage is not rejected for lacking the very values it omits.
//
// This package computes hashes only. Nothing returned here is a signature and
// nothing here verifies one.

// RevisionID returns the derived revision identity of f: lowercase hex
// SHA-256 of DomainRevision, a NUL, and the canonical file with
// header.revision_id and content_signature removed.
//
// It never reads f.Header.RevisionID or f.ContentSignature, so the same file
// gives the same identity before and after sealing and a stale revision id
// cannot change it. It validates first (ValidateFile) so every other field
// has its wire shape.
func RevisionID(f *File) (string, error) {
	if f == nil {
		return "", &Error{Code: CodeInvalidValue}
	}
	if err := ValidateFile(f); err != nil {
		return "", err
	}
	rev, err := revisionHash(f)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(rev), nil
}

// ContentSigningBytes returns the content-signature preimage of f: the
// canonical file with the file member content_signature removed entirely and
// header.revision_id set to RevisionID(f).
//
// The signer signs DomainContentSignature || 0x00 || these bytes. Because the
// revision id is derived from the same file with the signature absent, the
// preimage is the same for a draft and the file sealed from it.
//
// f must be a valid draft or sealed file. No signature is verified.
func ContentSigningBytes(f *File) ([]byte, error) {
	return contentSigningBytes(f, true)
}

// contentSigningBytes is ContentSigningBytes. With validate unset it skips
// validation and trusts the wire shape; SealFile needs that because it builds
// the preimage of the signature it is about to set.
func contentSigningBytes(f *File, validate bool) ([]byte, error) {
	if f == nil {
		return nil, &Error{Code: CodeInvalidValue}
	}
	if validate {
		if err := ValidateFile(f); err != nil {
			return nil, err
		}
	}
	rev, err := revisionHash(f)
	if err != nil {
		return nil, err
	}
	revID := hex.EncodeToString(rev)
	return encodeFileWire(f, fileEncoding{revisionID: &revID, omitSignature: true})
}

// FileDigest returns the digest of the complete canonical sealed file f as
// lowercase hex SHA-256 of DomainFileDigest, a NUL, and EncodeFile(f).
//
// Nothing is omitted or replaced: the input includes header.revision_id and
// content_signature. f must be a valid file; a sealed file must already carry
// its derived revision id. No signature is verified.
func FileDigest(f *File) (string, error) {
	if f == nil {
		return "", &Error{Code: CodeInvalidValue}
	}
	if err := ValidateFile(f); err != nil {
		return "", err
	}
	enc, err := EncodeFile(f)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(DomainSeparated(DomainFileDigest, enc)), nil
}

// SealFile performs the writer's sealing step and returns the canonical bytes
// of f with content_signature set to sig and header.revision_id set to the
// RevisionID of exactly those bytes.
//
// The result is always one of the two ValidateFile states:
//
//   - sig nil: the unsigned draft, content_signature
//     {"signer_id":"","alg":"","sig":null} and header.revision_id "".
//   - sig non-nil: the sealed file, header.revision_id exactly its derived
//     RevisionID and content_signature exactly sig.
//
// Any revision id or content signature f already carries is replaced, so a
// stale value never blocks sealing. The result may still fail ValidateFile for
// any other reason, and then SealFile returns that error and no bytes.
//
// A non-nil sig must be the writer's signature over
// DomainContentSignature || 0x00 || ContentSigningBytes(draft); sig.SignerID
// must name the header's author device. This function does not compute,
// verify or otherwise check that signature beyond what ValidateFile checks.
func SealFile(f *File, sig *Signature) ([]byte, error) {
	if f == nil {
		return nil, &Error{Code: CodeInvalidValue}
	}
	sealed := deepCopyFile(f)
	sealed.Header.RevisionID = ""
	sealed.ContentSignature = Signature{}
	if sig != nil {
		sealed.ContentSignature = *sig
		sealed.ContentSignature.Sig = bytes.Clone(sig.Sig)
		// The revision identity never reads the incoming revision id or
		// signature: its preimage omits both members. The draft's null
		// signature and the sealed sig cover the same revision input.
		rev, err := revisionHash(sealed)
		if err != nil {
			return nil, err
		}
		sealed.Header.RevisionID = hex.EncodeToString(rev)
	}
	return EncodeFile(sealed)
}

// revisionHash returns the decoded RevisionID of f. It does not validate: it
// only requires the wire shape, so callers that need a valid file call
// ValidateFile first.
func revisionHash(f *File) ([]byte, error) {
	if f == nil {
		return nil, &Error{Code: CodeInvalidValue}
	}
	input, err := revisionDomainInput(f)
	if err != nil {
		return nil, err
	}
	return DomainSeparated(DomainRevision, input), nil
}

// deepCopyFile copies f so derived forms never alias caller memory.
func deepCopyFile(f *File) *File {
	g := *f
	g.Header.PrevDigest = bytes.Clone(f.Header.PrevDigest)
	g.Header.PolicyDigest = bytes.Clone(f.Header.PolicyDigest)
	g.KDBXCiphertext = bytes.Clone(f.KDBXCiphertext)
	g.ContentSignature.Sig = bytes.Clone(f.ContentSignature.Sig)
	g.CEKSlot.WrappedCEK = bytes.Clone(f.CEKSlot.WrappedCEK)
	g.SignedPolicyProofs = append([]SignedPolicy(nil), f.SignedPolicyProofs...)
	g.VUKDeviceSlots = append([]DeviceSlot(nil), f.VUKDeviceSlots...)
	return &g
}

// revisionDomainInput returns the exact RevisionID input of f: the canonical
// file with header.revision_id and content_signature removed. It is the
// unhashed preimage, exposed so fixed vectors can pin it byte for byte.
//
// Both members are absent, not empty: an independent encoder that writes
// "revision_id":"" here would derive a different id.
func revisionDomainInput(f *File) ([]byte, error) {
	if f == nil {
		return nil, &Error{Code: CodeInvalidValue}
	}
	return encodeFileWire(f, fileEncoding{omitRevision: true, omitSignature: true})
}
