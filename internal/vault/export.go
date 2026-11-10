package vault

import (
	"bytes"
	"errors"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"strings"
	"unicode/utf8"
)

var ErrExportPassword = errors.New("export password must contain at least 12 characters and at most 1024 bytes")

func ValidateExportPassword(password string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 || len(password) > 1024 || strings.TrimSpace(password) == "" {
		return ErrExportPassword
	}
	return nil
}

// ExportKDBX creates a portable, password-encrypted KDBX 4.1 database. It
// contains native items and their retained import provenance, not account keys,
// source audit or grants. Provenance may contain values preceding later edits.
func ExportKDBX(items []Item, password string) ([]byte, error) {
	if err := ValidateExportPassword(password); err != nil {
		return nil, err
	}
	if err := ValidateItems(nil, items); err != nil {
		return nil, err
	}
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	db.Header.FileHeaders.KdfParameters.UUID = kdbx.KdfArgon2id
	db.Header.FileHeaders.KdfParameters.Memory = 64 << 20
	db.Header.FileHeaders.KdfParameters.Iterations = 3
	db.Credentials = kdbx.NewPasswordCredentials(password)
	if err := writeItems(db, nil, items); err != nil {
		return nil, err
	}
	// The portable export has no Locklark internal metadata record.
	db.Content.Root.Groups[0].Entries = db.Content.Root.Groups[0].Entries[1:]
	if err := db.LockProtectedEntries(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := kdbx.NewEncoder(&out).Encode(db); err != nil {
		return nil, err
	}
	if out.Len() > maxStoredSnapshot {
		clear(out.Bytes())
		return nil, ErrSnapshotCapacity
	}
	return out.Bytes(), nil
}
