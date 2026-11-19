// Package teamfiles handles bounded local bootstrap transfers, never role keys.
package teamfiles

import (
	"bytes"
	"context"
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

// maxBoundedFileBytes is the largest explicit limit accepted by the bounded
// private-file helper below. WriteNew and Read keep their existing, narrower
// limits; only a caller that states its own reviewed bound can use this helper.
const maxBoundedFileBytes = 128 << 20

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

// localWriteHooks is a private per-invocation seam. Production callers pass
// the zero value; tests may observe or inject failures at named boundaries.
// It is never a package-global hook and cannot inject a success.
type localWriteHooks struct {
	beforeLink      func() error
	beforeCommit    func() error
	afterLink       func() error
	afterPublish    func() error
	afterUnlink     func() error
	beforeFinalSync func() error
	afterFinalSync  func() error
	// failedRenameFinalProbe injects only the Windows final-name probe made
	// after a genuine no-replace rename rejection. A non-nil error replaces
	// that probe result and is classified by the ordinary post-probe rules; it
	// cannot inject a successful probe or a final name.
	failedRenameFinalProbe func() error
}

// localReadHooks is a private per-invocation read seam. Production callers pass
// the zero value. afterCapture runs after the accepted parent identity is
// captured but before the parent handle is opened; afterOpen runs after the
// bounded read but before the final path and parent binding are re-verified.
type localReadHooks struct {
	afterCapture func() error
	afterOpen    func() error
}

func Read(path string, limit int64, private bool) ([]byte, error) {
	return readLimited(context.Background(), path, limit, private, 32<<20, localReadHooks{})
}

// ReadLimited reads one existing private regular file with the same canonical
// path, ownership, link-count and mode rules as Read, but under an explicit
// caller-reviewed bound up to maxBoundedFileBytes. The accepted parent identity
// is pinned for the whole read; a substituted parent, a replaced final name or
// a final name that no longer resolves to the opened inode is refused before
// bytes are returned. It reports cancellation before returning bytes and never
// returns a partial or oversized read.
func ReadLimited(ctx context.Context, path string, limit int64, private bool) ([]byte, error) {
	return readLimited(ctx, path, limit, private, maxBoundedFileBytes, localReadHooks{})
}

func readLimited(ctx context.Context, path string, limit int64, private bool, max int64,
	hooks localReadHooks) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !ValidPath(path) || limit <= 0 || limit > max {
		return nil, ErrFile
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return readBoundedAtPath(ctx, path, limit, private, hooks)
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
	return writeNewLimited(context.Background(), path, raw, 16<<20, localWriteHooks{})
}

// WriteNewLimited publishes one new private regular file with the same secure
// path, same-directory owned staging, no-replace publication and platform
// durability rules as WriteNew, but under an explicit caller-reviewed bound up to
// maxBoundedFileBytes. The exact accepted parent is captured and held for
// staging, publication and cleanup. A binding change before publication is
// refused and only the owned staged name is removed. Once the final link is
// installed the helper never removes or replaces the final name. Success means
// the staged file data was synced before publication, the final name was
// installed without replacement, and the platform's publication durability
// barrier completed (one parent-directory sync on Unix; a post-rename file
// flush on Windows). Any uncertain publication, binding, cleanup or final sync
// returns ErrPublicationUnknown; when the owned stage could be removed safely
// the final file is left with exactly one link and an explicit fresh reopen can
// verify it. The returned error never asserts reopenability or durability for
// an unknown result: those are only established by an actual subsequent read
// or by a fully verified success.
func WriteNewLimited(ctx context.Context, path string, raw []byte, limit int64) error {
	return writeNewLimited(ctx, path, raw, limit, localWriteHooks{})
}

func writeNew(path string, raw []byte, hooks localWriteHooks) error {
	return writeNewLimited(context.Background(), path, raw, 16<<20, hooks)
}

func writeNewLimited(ctx context.Context, path string, raw []byte, limit int64,
	hooks localWriteHooks) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 || limit > maxBoundedFileBytes || len(raw) == 0 ||
		int64(len(raw)) > limit || !ValidPath(path) {
		return ErrFile
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return ErrFile
	}
	staging := ".locklark-team-transfer-" + hex.EncodeToString(token[:])
	return writeNewAtPath(ctx, path, raw, staging, hooks)
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
