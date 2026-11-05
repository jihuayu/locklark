// Package pullreader identifies the first-party proposal module shipped with
// this binary. Its digest is an expected code identity, not proof that an
// untrusted agent ran it.
package pullreader

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

//go:embed index.ts
var module []byte

func Digest() string { h := sha256.Sum256(module); return hex.EncodeToString(h[:]) }
