// Disposable local-owner fixture and private-pipe oracle for real desktop tests.
// The running product receives no test interface or authorization bypass.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	bolt "go.etcd.io/bbolt"
)

type fixture struct {
	Path, Password, Secret, Username, Value, URL, OTPSeed, OTPConfig string
	ProviderValue, ProviderCanary                                    string
	IDs                                                              map[string]string
}

type item struct {
	personal.Row
	URL, Username, Password, OTP, ImportSource string
}

type observation struct {
	Snapshot  string           `json:"snapshot"`
	Items     []item           `json:"items"`
	Events    []personal.Event `json:"events"`
	AuditSafe bool             `json:"audit_safe"`
}

func setup(out string) error {
	if !filepath.IsAbs(out) || os.Mkdir(out, 0700) != nil {
		return errors.New("new absolute private fixture directory required")
	}
	key, err := personal.NewSecret()
	if err != nil {
		return err
	}
	defer clear(key)
	var entropy [68]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}
	f := fixture{
		Path: filepath.Join(out, "synthetic.ll"), Password: "Daily-master-" + hex.EncodeToString(entropy[:8]),
		Secret: personal.FormatSecret(key), Username: "Daily-user-" + hex.EncodeToString(entropy[8:16]),
		Value: "Daily-value-" + hex.EncodeToString(entropy[16:32]), URL: "https://daily.locklark.test/login",
		OTPSeed: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy[32:52]), IDs: map[string]string{},
		ProviderCanary: "Daily-provider-" + hex.EncodeToString(entropy[52:]),
	}
	f.ProviderValue = f.ProviderCanary + strings.Repeat("原生🔐", 16<<10) + f.ProviderCanary
	clear(entropy[:])
	// A real, supported 20-second period bounds the GUI expiry test. Python
	// independently computes HMAC-SHA1 with this period and eight digits.
	f.OTPConfig = "otpauth://totp/daily?secret=" + f.OTPSeed + "&digits=8&period=20"
	if err := personal.Create(f.Path, f.Password, key); err != nil {
		return err
	}
	for _, kind := range []string{"OTP", "other", "archived", "trashed"} {
		id, err := personal.AddLogin(f.Path, f.Password, key, "Daily "+kind+" login", f.Username, f.Value)
		if err != nil {
			return err
		}
		f.IDs[kind] = id
		for field, value := range map[string]string{"url": f.URL, "otp": f.OTPConfig} {
			row, err := find(f, key, id)
			if err != nil {
				return err
			}
			if _, err = personal.EditLogin(f.Path, f.Password, key, personal.Edit{ID: id, Revision: row.Revision, Field: field, Value: value}); err != nil {
				return err
			}
		}
		if kind == "archived" || kind == "trashed" {
			row, err := find(f, key, id)
			if err != nil {
				return err
			}
			if kind == "archived" {
				_, err = personal.SetArchived(f.Path, f.Password, key, id, row.Revision, true)
			} else {
				_, err = personal.SetTrashed(f.Path, f.Password, key, id, row.Revision, true)
			}
			if err != nil {
				return err
			}
		}
	}
	id, err := personal.AddLogin(f.Path, f.Password, key, "Daily provider login", f.Username, f.ProviderValue)
	if err != nil {
		return err
	}
	f.IDs["provider"] = id
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	defer clear(raw)
	return os.WriteFile(filepath.Join(out, "fixture.json"), raw, 0600)
}

func find(f fixture, key []byte, id string) (personal.Row, error) {
	rows, err := personal.ListState(f.Path, f.Password, key, "all")
	if err != nil {
		return personal.Row{}, err
	}
	for _, row := range rows {
		if row.ID == id {
			return row, nil
		}
	}
	return personal.Row{}, errors.New("missing fixture item")
}

// Authenticate only a consistent bbolt copy. List/Audit/export and their
// observer events never mutate the source vault, including during a GUI write.
func snapshot(source, destination string) (digest string, err error) {
	db, err := bolt.Open(source, 0600, &bolt.Options{ReadOnly: true, Timeout: 3 * time.Second})
	if err != nil {
		return "", err
	}
	defer db.Close()
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("locklark.personal/v1"))
		if b == nil || len(b.Get([]byte("snapshot"))) == 0 {
			return errors.New("missing snapshot")
		}
		hash := sha256.Sum256(b.Get([]byte("snapshot")))
		digest = hex.EncodeToString(hash[:])
		_, e := tx.WriteTo(f)
		return e
	})
	if err != nil {
		return "", err
	}
	if err = db.Close(); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	return digest, f.Close()
}

func observe(f fixture, key []byte) error {
	// Raw owner values are emitted only to an explicitly private controller pipe,
	// never to a terminal, ordinary log, JSON diagnostic, or artifact file.
	stat, err := os.Stdout.Stat()
	if err != nil || stat.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("private output pipe required")
	}
	dir, err := os.MkdirTemp(filepath.Dir(f.Path), ".observe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "snapshot.ll")
	digest, err := snapshot(f.Path, path)
	if err != nil {
		return err
	}
	s, err := personal.UnlockSession(path, []byte(f.Password), key, time.Minute)
	if err != nil {
		return err
	}
	defer s.Lock()
	rows, err := s.List("all")
	if err != nil {
		return err
	}
	events, err := s.Audit()
	if err != nil {
		return err
	}
	exported := filepath.Join(dir, "owner.kdbx")
	if err = s.Export(f.Password, exported); err != nil {
		return err
	}
	file, err := os.Open(exported)
	if err != nil {
		return err
	}
	defer file.Close()
	db := kdbx.NewDatabase()
	db.Credentials = kdbx.NewPasswordCredentials(f.Password)
	if err = kdbx.NewDecoder(file).Decode(db); err != nil {
		return err
	}
	if err = db.UnlockProtectedEntries(); err != nil {
		return err
	}
	index := map[string]personal.Row{}
	for _, row := range rows {
		index[row.ID] = row
	}
	out := observation{Snapshot: digest, Items: []item{}, Events: events, AuditSafe: true}
	for _, group := range db.Content.Root.Groups {
		for _, entry := range group.Entries {
			id := entry.GetContent("Locklark.ID")
			row, found := index[id]
			if !found {
				return errors.New("exported item mismatch")
			}
			out.Items = append(out.Items, item{row, entry.GetContent("URL"), entry.GetContent("UserName"), entry.GetContent("Password"), entry.GetContent("otp"), entry.GetContent("Locklark.ImportSource")})
		}
	}
	if len(out.Items) != len(rows) {
		return errors.New("incomplete exported items")
	}
	public, err := json.Marshal(events)
	if err != nil {
		return err
	}
	defer clear(public)
	canaries := []string{f.Password, f.Secret, f.Username, f.Value, f.OTPSeed, f.OTPConfig, f.ProviderCanary, f.ProviderValue}
	for _, it := range out.Items {
		canaries = append(canaries, it.Password, it.Username, it.OTP)
	}
	for _, value := range canaries {
		if value != "" && bytes.Contains(public, []byte(value)) {
			out.AuditSafe = false
		}
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func run() error {
	out := flag.String("out", "", "new synthetic fixture directory")
	input := flag.String("fixture", "", "private synthetic fixture file")
	privatePipe := flag.Bool("private-pipe", false, "observe authenticated copy through private pipe only")
	stale := flag.String("stale", "", "independent local-owner URL edit for exact-target conflict test")
	flag.Parse()
	if *out != "" {
		if *input != "" || *privatePipe || *stale != "" || flag.NArg() != 0 {
			return errors.New("one operation required")
		}
		return setup(*out)
	}
	if *input == "" || flag.NArg() != 0 || (*privatePipe == (*stale != "")) {
		return errors.New("one operation required")
	}
	raw, err := os.ReadFile(*input)
	if err != nil || len(raw) > 2<<20 {
		return errors.New("invalid fixture")
	}
	defer clear(raw)
	var f fixture
	if json.Unmarshal(raw, &f) != nil || f.Path != filepath.Join(filepath.Dir(*input), "synthetic.ll") {
		return errors.New("invalid fixture path")
	}
	key, err := personal.ParseSecret(f.Secret)
	if err != nil {
		return err
	}
	defer clear(key)
	if *privatePipe {
		return observe(f, key)
	}
	row, err := find(f, key, *stale)
	if err != nil {
		return err
	}
	_, err = personal.EditLogin(f.Path, f.Password, key, personal.Edit{ID: row.ID, Revision: row.Revision, Field: "url", Value: f.URL + "/independent-change"})
	return err
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Synthetic desktop fixture operation failed")
		os.Exit(1)
	}
}
