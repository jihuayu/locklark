package passkeytransfer

import (
	"bytes"

	"filippo.io/age"
)

// encryptTo seals plaintext to exactly the invitation's canonical age X25519
// recipient. No password, note, attachment or other vault data is accepted.
func encryptTo(recipient string, plaintext []byte) ([]byte, error) {
	r, ok := parseRecipient(recipient)
	if !ok || len(plaintext) == 0 || len(plaintext) > maxPlaintext {
		return nil, ErrRefused
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return nil, ErrRefused
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, ErrRefused
	}
	if err := w.Close(); err != nil || out.Len() == 0 || out.Len() > maxPacket {
		return nil, ErrRefused
	}
	return out.Bytes(), nil
}
