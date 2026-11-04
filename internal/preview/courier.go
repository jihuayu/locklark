package preview

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func renewProfile(device, session, path string) error {
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return ExportBridgeProfile(device, session, path)
	}
	if e != nil || !info.Mode().IsRegular() {
		return errSession
	}
	data, e := readPath(path, 4096)
	if e != nil {
		return errSession
	}
	pub, e := read(device, "decision.pub", 32)
	if e != nil || len(pub) != 32 {
		return errSession
	}
	var p BridgeProfile
	if json.Unmarshal(data, &p) != nil || p.Session != session || !ed25519.Verify(pub, p.proof(), p.Sig) {
		return errSession
	}
	if time.Until(p.Expires) > 2*time.Minute {
		return nil
	}
	// The operator chooses this managed path. Only replace a previously signed
	// profile for the same session; rename a completed file, never truncate it.
	tmp, e := os.MkdirTemp(filepath.Dir(path), ".profile-")
	if e != nil {
		return e
	}
	defer os.Remove(tmp)
	fresh := filepath.Join(tmp, "fresh")
	defer os.Remove(fresh)
	if e = ExportBridgeProfile(device, session, fresh); e != nil {
		return e
	}
	return os.Rename(fresh, path)
}

// The courier answers signed read-only queries; it never issues decisions or
// runs an approved action. Bound work per tick; one-shot handles one full pass.
func ServeStatus(ctx context.Context, device, inbox, exchange, session, profile string, once bool) error {
	if device == "" || inbox == "" || exchange == "" || (session == "") != (profile == "") {
		return errSession
	}
	verified, e := mailIdentity(device)
	if e != nil || verified == nil {
		return errSession
	}
	var dir *os.File
	defer func() {
		if dir != nil {
			dir.Close()
		}
	}()
	last := time.Time{}
	for {
		if profile != "" && time.Since(last) >= 30*time.Second {
			if e := renewProfile(device, session, profile); e != nil {
				return e
			}
			last = time.Now()
		}
		if dir == nil {
			var e error
			dir, e = os.Open(exchange)
			if e != nil {
				return e
			}
		}
		entries, e := dir.ReadDir(16)
		for _, entry := range entries {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			name := entry.Name()
			poll, ok := strings.CutSuffix(name, ".query.age")
			if !ok || !validID(poll) || !entry.Type().IsRegular() {
				continue
			}
			if _, e := os.Lstat(filepath.Join(exchange, poll+".status.age")); !errors.Is(e, os.ErrNotExist) {
				continue
			}
			// Invalid/stale queries do not block following entries, and must not
			// create an existence oracle by writing distinguishable error envelopes.
			_ = AnswerStatus(device, inbox, exchange, poll)
		}
		if errors.Is(e, io.EOF) {
			dir.Close()
			dir = nil
			if once {
				return nil
			}
		} else if e != nil {
			return e
		}
		if once {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
