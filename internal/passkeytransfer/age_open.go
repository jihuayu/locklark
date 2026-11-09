package passkeytransfer

import (
	"bytes"
	"io"

	"filippo.io/age"
)

// RecipientIdentity is the caller's existing native age identity. It must also
// expose its public recipient so OpenSelection can require an exact match with
// the invitation recipient before decrypting.
type RecipientIdentity interface {
	age.Identity
	Recipient() *age.X25519Recipient
}

// decryptFrom uses DecryptReaderAt so the ciphertext size is fixed up front,
// the final chunk is authenticated before returning, and appended trailing
// bytes fail authentication. Plaintext stays within the 1 MiB bound.
func decryptFrom(own RecipientIdentity, ciphertext []byte) ([]byte, error) {
	if own == nil || len(ciphertext) == 0 || len(ciphertext) > maxPacket {
		return nil, ErrRefused
	}
	reader, size, err := age.DecryptReaderAt(bytes.NewReader(ciphertext), int64(len(ciphertext)), own)
	if err != nil || size <= 0 || size > maxPlaintext {
		return nil, ErrRefused
	}
	plaintext := make([]byte, int(size))
	if _, err := io.ReadFull(io.NewSectionReader(reader, 0, size), plaintext); err != nil {
		clear(plaintext)
		return nil, ErrRefused
	}
	return plaintext, nil
}
