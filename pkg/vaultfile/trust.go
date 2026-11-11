package vaultfile

import (
	"bytes"
	"crypto/ed25519"
)

// CodeSignatureVerifyFailed is reported by VerifyContentSignature when the
// pinned key bytes are malformed or name the wrong signer, or when the
// content signature does not verify. Each case is a trust decision by the
// caller, not a structural defect of the file.
const CodeSignatureVerifyFailed = "signature_verify_failed"

// VerifyContentSignature validates the sealed file f (ValidateFile) and then
// verifies its content signature with signerDeviceID and publicKey, which the
// caller pins out of band.
//
// The verified message is exactly DomainContentSignature || 0x00 ||
// ContentSigningBytes(f), the frozen v1 content-signature preimage, and the
// check is crypto/ed25519. The public key carried in the current policy proof
// is never used as a trust anchor: the proofs are not verified here, so the
// key they name is untrusted input. publicKey must nevertheless equal the
// content signing key recorded for signerDeviceID in that carried policy; a
// pinned key that does not match is rejected, because a caller that pins one
// key for a device should not silently accept a file that names another.
//
// f must be sealed and name signerDeviceID as its author device
// (header.author_device_id and content_signature.signer_id); a mismatch is
// rejected.
//
// Errors:
//   - structural or shape failures are returned from ValidateFile unchanged,
//     and a nil f is an invalid_value;
//   - a mismatched signer, a public key that is not ed25519.PublicKeySize
//     bytes or that differs from the carried policy key, and a signature that
//     does not verify are all *Error with Code
//     CodeSignatureVerifyFailed and an empty path. A malformed key is rejected
//     by length before ed25519.Verify is called, so it never panics.
//
// A nil return means only that f is a structurally valid file whose content
// signature verifies under the pinned key. It does not establish that the
// vault is trusted, that the policy proofs are authentic, that the signer is
// authorized by a verified policy, or anything about the content, keys or
// wrapping. Those need signature-chain and authorization verification this
// package does not implement.
func VerifyContentSignature(f *File, signerDeviceID string, publicKey ed25519.PublicKey) error {
	if f == nil {
		return Err("", CodeInvalidValue)
	}
	current, err := validateStructure(f)
	if err != nil {
		return err
	}
	if err := validateSealed(f, current); err != nil {
		return err
	}
	if signerDeviceID == "" || f.Header.AuthorDeviceID != signerDeviceID ||
		f.ContentSignature.SignerID != signerDeviceID {
		return Err("", CodeSignatureVerifyFailed)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return Err("", CodeSignatureVerifyFailed)
	}
	dev := findDevice(current, signerDeviceID)
	if dev == nil || dev.ContentSigningKey.Alg != SigAlgEd25519 ||
		!bytes.Equal(dev.ContentSigningKey.PublicKey, publicKey) {
		return Err("", CodeSignatureVerifyFailed)
	}
	input, err := contentSigningBytes(f, false)
	if err != nil {
		return err
	}
	msg := make([]byte, 0, len(DomainContentSignature)+1+len(input))
	msg = append(msg, DomainContentSignature...)
	msg = append(msg, 0)
	msg = append(msg, input...)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), msg, f.ContentSignature.Sig) {
		return Err("", CodeSignatureVerifyFailed)
	}
	return nil
}
