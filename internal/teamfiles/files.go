// Package teamfiles handles bounded local bootstrap transfers, never role keys.
package teamfiles

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

var ErrFile = errors.New("team bootstrap file refused")
var ErrPublicationUnknown = errors.New("team bootstrap file publication unconfirmed")

func ValidPath(path string) bool {
	return len(path) > 0 && len(path) <= 4096 && !strings.ContainsRune(path, 0) && utf8.ValidString(path) && filepath.IsAbs(path) && filepath.Clean(path) == path && validPlatformPath(path)
}

func CheckNew(path string) error {
	if !ValidPath(path) || trustedParent(filepath.Dir(path)) != nil {
		return ErrFile
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return ErrFile
	}
	return nil
}

func Distinct(paths ...string) bool {
	seen := []string{}
	for _, path := range paths {
		if !ValidPath(path) {
			return false
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return false
		}
		path = filepath.Join(parent, filepath.Base(path))
		for _, other := range seen {
			if equalPath(path, other) {
				return false
			}
			a, ae := os.Lstat(path)
			b, be := os.Lstat(other)
			if ae == nil && be == nil && os.SameFile(a, b) {
				return false
			}
		}
		seen = append(seen, path)
	}
	return true
}

func Read(path string, limit int64, private bool) ([]byte, error) {
	if !ValidPath(path) || limit <= 0 || limit > 32<<20 || trustedFile(path, private) != nil {
		return nil, ErrFile
	}
	f, err := openLocalFile(path, private)
	if err != nil {
		return nil, ErrFile
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	closed := f.Close()
	if err != nil || closed != nil || int64(len(raw)) > limit {
		clear(raw)
		return nil, ErrFile
	}
	return raw, nil
}

// JSON rejects duplicate/unknown fields and trailing values, while permitting
// ordinary whitespace in independently supplied public records.
func JSON(raw []byte, value any) error {
	if !utf8.Valid(raw) {
		return ErrFile
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if nodes > 4096 || depth > 16 {
			return ErrFile
		}
		token, err := d.Token()
		if err != nil {
			return ErrFile
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				name = strings.ToLower(name)
				if err != nil || !ok || seen[name] || len(seen) >= 128 {
					return ErrFile
				}
				seen[name] = true
				if walk(depth+1) != nil {
					return ErrFile
				}
			}
			token, err = d.Token()
			if err != nil || token != json.Delim('}') {
				return ErrFile
			}
		case json.Delim('['):
			n := 0
			for d.More() {
				n++
				if n > 128 || walk(depth+1) != nil {
					return ErrFile
				}
			}
			token, err = d.Token()
			if err != nil || token != json.Delim(']') {
				return ErrFile
			}
		}
		return nil
	}
	if walk(0) != nil {
		return ErrFile
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrFile
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return ErrFile
	}
	return nil
}

func WriteNew(path string, raw []byte) error {
	return writeNew(path, raw, publishLocalFile)
}
func writeNew(path string, raw []byte, publish func(string, string) error) error {
	if len(raw) == 0 || len(raw) > 16<<20 || CheckNew(path) != nil {
		return ErrFile
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return ErrFile
	}
	tmp := filepath.Join(filepath.Dir(path), ".locklark-team-transfer-"+hex.EncodeToString(token[:]))
	f, err := createLocalFile(tmp)
	if err != nil {
		return ErrFile
	}
	owned, err := f.Stat()
	if err != nil || !owned.Mode().IsRegular() {
		f.Close()
		return ErrFile
	}
	defer removeOwned(tmp, owned)
	n, written := f.Write(raw)
	synced := f.Sync()
	closed := f.Close()
	if written != nil || n != len(raw) || synced != nil || closed != nil || CheckNew(path) != nil {
		return ErrFile
	}
	current, err := os.Lstat(tmp)
	if err != nil || !os.SameFile(owned, current) || trustedFile(tmp, true) != nil {
		return ErrFile
	}
	if publish(tmp, path) != nil {
		if final, err := os.Lstat(path); err == nil && os.SameFile(owned, final) {
			return ErrPublicationUnknown
		}
		return ErrFile
	}
	if removeOwned(tmp, owned) != nil {
		return ErrPublicationUnknown
	}
	return nil
}

func removeOwned(path string, owned os.FileInfo) error {
	current, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(owned, current) {
		return ErrFile
	}
	return os.Remove(path)
}
