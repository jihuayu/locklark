package preview

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/account"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The only permitted reference resolves to a synthetic fixture. Submission
// deliberately performs no resolution. The mailbox key is independent of all vault keys.
const FixtureRef = "op://synthetic-vault/login-sample/ops/otp-demo"

type Request struct {
	ID      string `json:"id"`
	Session string `json:"session"`
	Reason  string `json:"reason"`
	Ref     string `json:"ref"`
	State   string `json:"state"`
	Created string `json:"claimed_time"`
}
type InboxReport struct {
	Next       string    `json:"next,omitempty"`
	Requests   []Request `json:"requests"`
	Unreadable int       `json:"unreadable"`
}

func validRequest(session, reason, ref string) bool {
	return sessionID.MatchString(session) && session != systemSession && ref == FixtureRef && utf8.ValidString(reason) && strings.TrimSpace(reason) != "" && utf8.RuneCountInString(reason) <= 240 && strings.IndexFunc(reason, unicode.IsControl) < 0
}
func setupInbox(out string, secret, id []byte) error {
	for _, name := range []string{"agent", "inbox"} {
		if err := os.Mkdir(filepath.Join(out, name), 0700); err != nil {
			return err
		}
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	s, err := account.Wrap(fixturePassword, secret, id, []byte(identity.String()))
	if err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(out, "clients", "B"), "approval.slot", s); err != nil {
		return err
	}
	return write(filepath.Join(out, "agent"), "approval.pub", []byte(identity.Recipient().String()))
}
func Submit(inbox, recipientFile, session, reason, ref string) (string, error) {
	if !validRequest(session, reason, ref) {
		return "", errors.New("invalid synthetic request, reason, session or reference")
	}
	pub, err := read(filepath.Dir(recipientFile), filepath.Base(recipientFile), 256)
	if err != nil {
		return "", err
	}
	r, err := age.ParseX25519Recipient(strings.TrimSpace(string(pub)))
	if err != nil {
		return "", errors.New("invalid pinned approval recipient")
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return "", err
	}
	request := Request{hex.EncodeToString(id[:]), session, strings.TrimSpace(reason), ref, "pending", time.Now().UTC().Format(time.RFC3339Nano)}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return "", err
	}
	if err = json.NewEncoder(w).Encode(request); err != nil {
		return "", err
	}
	if err = w.Close(); err != nil {
		return "", err
	}
	// Publish on the local filesystem only after writing, without replacing an existing ID.
	tmp, err := os.CreateTemp(inbox, ".pending-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(out.Bytes())
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err = os.Link(tmp.Name(), filepath.Join(inbox, request.ID+".request.age")); err != nil {
		return "", err
	}
	return request.ID, nil
}
func Inbox(dir, device, session string) (InboxReport, error) {
	return InboxPage(dir, device, session, "")
}
func InboxPage(dir, device, session, cursor string) (InboxReport, error) {
	report := InboxReport{Requests: []Request{}}
	if !sessionID.MatchString(session) {
		return report, errInput
	}
	data, err := read(device, "approval.slot", 4096)
	if err != nil {
		return report, err
	}
	secret, err := read(device, "fixture.secret", 16)
	if err != nil {
		return report, err
	}
	defer clear(secret)
	var slot account.Slot
	if err = json.Unmarshal(data, &slot); err != nil {
		return report, err
	}
	key, err := account.Unwrap(fixturePassword, secret, slot)
	if err != nil {
		return report, err
	}
	defer clear(key)
	id, err := age.ParseX25519Identity(string(key))
	if err != nil {
		return report, errors.New("invalid approval identity")
	}
	d, err := os.Open(dir)
	if err != nil {
		return report, err
	}
	defer d.Close()
	entries, next, err := pageEntries(d, cursor)
	if err != nil {
		return report, err
	}
	report.Next = next
	for _, f := range entries {
		if !strings.HasSuffix(f.Name(), ".request.age") {
			continue
		}
		// Skip damaged/untrusted messages individually, reporting the count even on a filtered query.
		if !f.Type().IsRegular() {
			report.Unreadable++
			continue
		}
		q, ok := openRequest(dir, f.Name(), id)
		if !ok {
			report.Unreadable++
			continue
		}
		if q.Session == session {
			report.Requests = append(report.Requests, q)
		}
	}
	sort.Slice(report.Requests, func(i, j int) bool {
		a, b := report.Requests[i], report.Requests[j]
		if a.Created == b.Created {
			return a.ID < b.ID
		}
		return a.Created < b.Created
	})
	return report, nil
}

// Bound memory and decryption work per page. Irrelevant directory entries
// never consume message capacity. Cursor is an opaque filename position.
func pageEntries(dir *os.File, cursor string) ([]os.DirEntry, string, error) {
	const size = 128
	if len(cursor) > 1024 {
		return nil, "", errors.New("invalid inbox cursor")
	}
	after, err := hex.DecodeString(cursor)
	if err != nil {
		return nil, "", errors.New("invalid inbox cursor")
	}
	page := make([]os.DirEntry, 0, size*3+1)
	for {
		batch, err := dir.ReadDir(size * 2)
		for _, entry := range batch {
			if strings.HasSuffix(entry.Name(), ".request.age") && entry.Name() > string(after) {
				page = append(page, entry)
			}
		}
		sort.Slice(page, func(i, j int) bool { return page[i].Name() < page[j].Name() })
		if len(page) > size+1 {
			page = page[:size+1]
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", err
		}
	}
	if len(page) > size {
		return page[:size], hex.EncodeToString([]byte(page[size-1].Name())), nil
	}
	return page, "", nil
}
func openRequest(dir, name string, id *age.X25519Identity) (Request, bool) {
	var q Request
	b, err := read(dir, name, 8<<10)
	if err != nil {
		return q, false
	}
	r, err := age.Decrypt(bytes.NewReader(b), id)
	if err != nil {
		return q, false
	}
	raw, err := io.ReadAll(io.LimitReader(r, 4097))
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &q) != nil {
		return q, false
	}
	_, err = time.Parse(time.RFC3339Nano, q.Created)
	_, idErr := hex.DecodeString(q.ID)
	return q, err == nil && idErr == nil && len(q.ID) == 32 && name == q.ID+".request.age" && q.State == "pending" && validRequest(q.Session, q.Reason, q.Ref)
}
