// Disposable local-owner fixture and private-pipe oracle for real desktop tests.
// The running product receives no test interface or authorization bypass.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
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
	URL, Username, Password, OTP, Notes, ImportSource string
}

type observation struct {
	Snapshot  string           `json:"snapshot"`
	Items     []item           `json:"items"`
	Events    []personal.Event `json:"events"`
	AuditSafe bool             `json:"audit_safe"`
}

// localProjection is deliberately limited to bounded local byte/mode facts.
// It carries no path, manifest, ciphertext, recovery kit, identity or known
// fixture factor value.
type localProjection struct {
	ManifestCount      int  `json:"manifest_count"`
	ManifestPersonal   bool `json:"manifest_personal"`
	ManifestBackend    bool `json:"manifest_backend"`
	CompanionPresent   bool `json:"companion_present"`
	ManifestDigest     bool `json:"manifest_digest"`
	JournalPresent     bool `json:"journal_present"`
	ArchivePresent     bool `json:"archive_present"`
	PrivateModes       bool `json:"private_modes"`
	BackendHashMatches bool `json:"backend_hash_matches"`
	FactorsAbsent      bool `json:"factors_absent"`
}

func setup(out string) error {
	f, err := newSyntheticFixture(out)
	if err != nil {
		return err
	}
	defer clearFixture(&f)
	return writeSyntheticFixture(out, f)
}

func writeSyntheticFixture(out string, f fixture) error {
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	defer clear(raw)
	return os.WriteFile(filepath.Join(out, "fixture.json"), raw, 0600)
}

func newSyntheticFixture(out string) (fixture, error) {
	if !filepath.IsAbs(out) || os.Mkdir(out, 0700) != nil {
		return fixture{}, errors.New("new absolute private fixture directory required")
	}
	key, err := personal.NewSecret()
	if err != nil {
		return fixture{}, err
	}
	defer clear(key)
	var entropy [68]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return fixture{}, err
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
		return fixture{}, err
	}
	for _, kind := range []string{"OTP", "other", "archived", "trashed"} {
		id, err := personal.AddLogin(f.Path, f.Password, key, "Daily "+kind+" login", f.Username, f.Value)
		if err != nil {
			return fixture{}, err
		}
		f.IDs[kind] = id
		for field, value := range map[string]string{"url": f.URL, "otp": f.OTPConfig} {
			row, err := find(f, key, id)
			if err != nil {
				return fixture{}, err
			}
			if _, err = personal.EditLogin(f.Path, f.Password, key, personal.Edit{ID: id, Revision: row.Revision, Field: field, Value: value}); err != nil {
				return fixture{}, err
			}
		}
		if kind == "archived" || kind == "trashed" {
			row, err := find(f, key, id)
			if err != nil {
				return fixture{}, err
			}
			if kind == "archived" {
				_, err = personal.SetArchived(f.Path, f.Password, key, id, row.Revision, true)
			} else {
				_, err = personal.SetTrashed(f.Path, f.Password, key, id, row.Revision, true)
			}
			if err != nil {
				return fixture{}, err
			}
		}
	}
	id, err := personal.AddLogin(f.Path, f.Password, key, "Daily provider login", f.Username, f.ProviderValue)
	if err != nil {
		return fixture{}, err
	}
	f.IDs["provider"] = id
	return f, nil
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
			out.Items = append(out.Items, item{row, entry.GetContent("URL"), entry.GetContent("UserName"), entry.GetContent("Password"), entry.GetContent("otp"), entry.GetContent("Notes"), entry.GetContent("Locklark.ImportSource")})
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
		canaries = append(canaries, it.Password, it.Username, it.OTP, it.Notes)
	}
	for _, value := range canaries {
		if value != "" && bytes.Contains(public, []byte(value)) {
			out.AuditSafe = false
		}
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

// localProfileDir mirrors localVaultFilePaths: the expected profile is derived
// only from the current fixture's personal path, never from a directory scan.
func localProfileDir(workspace, personalPath string) string {
	sum := sha256.Sum256([]byte(personalPath))
	return filepath.Join(workspace, "profiles", hex.EncodeToString(sum[:]))
}

func localBackendRoot(workspace string) string {
	return filepath.Join(workspace, "backend")
}

// localBackendLockName is the one known version-level lock file documented by
// the local directory backend. It is optional for a read-only observation.
const localBackendLockName = ".locklark-vaultfile.lock"

// realDirectory accepts only an existing real directory. A missing path is
// reported as absent so the caller can emit bounded false facts instead of
// exploring any other directory.
func realDirectory(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, errors.New("invalid local workspace directory")
	}
	return true, nil
}

func boundedRegularFile(path string, limit int64) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, errors.New("local workspace file is not a real regular file")
	}
	if info.Size() > limit {
		return nil, false, errors.New("local workspace file exceeds bound")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if int64(len(raw)) > limit {
		clear(raw)
		return nil, false, errors.New("local workspace file exceeds bound")
	}
	return raw, true, nil
}

// readBoundedDir reads at most limit entries and one sentinel, so a directory
// with unexpected extra children is rejected without an unbounded allocation.
// A missing directory is reported by the caller's prior realDirectory check.
func readBoundedDir(path string, limit int) ([]os.DirEntry, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > limit {
		return nil, errors.New("local backend directory exceeds bound")
	}
	return entries, nil
}

type localBackendRecord struct {
	raw, path, digest string
	valid             bool
}

// decodeLocalBackendRecord reads the documented directory-backend record
// shape. It proves only that the stored payload matches the record's own
// digest; it does not authenticate a signature, permission or remote head.
func decodeLocalBackendRecord(raw []byte) ([]byte, bool) {
	const magic = "LLVFREV1"
	if len(raw) < len(magic)+4 || string(raw[:len(magic)]) != magic {
		return nil, false
	}
	p := len(magic)
	readU32 := func() (uint32, bool) {
		if len(raw)-p < 4 {
			return 0, false
		}
		value := uint32(raw[p]) | uint32(raw[p+1])<<8 | uint32(raw[p+2])<<16 | uint32(raw[p+3])<<24
		p += 4
		return value, true
	}
	vlen, ok := readU32()
	if !ok || vlen == 0 || vlen > 1024 || uint64(vlen) > uint64(len(raw)-p) {
		return nil, false
	}
	p += int(vlen)
	dlen, ok := readU32()
	if !ok || dlen != sha256.Size || uint64(dlen) > uint64(len(raw)-p) {
		return nil, false
	}
	digest := raw[p : p+int(dlen)]
	p += int(dlen)
	value := raw[p:]
	if len(value) == 0 || len(value) > 32<<20 {
		return nil, false
	}
	sum := sha256.Sum256(value)
	if !bytes.Equal(sum[:], digest) {
		return nil, false
	}
	return value, true
}

func readBackendObject(backendRoot, name string) (localBackendRecord, bool, error) {
	var zero localBackendRecord
	namespace := filepath.Join(backendRoot, "vaultfile-backend")
	version := filepath.Join(namespace, "v1")
	data := filepath.Join(version, "data")
	for _, dir := range []string{backendRoot, namespace, version, data} {
		exists, err := realDirectory(dir)
		if err != nil {
			return zero, false, err
		}
		if !exists {
			return zero, false, nil
		}
	}
	entries, err := os.ReadDir(data)
	if err != nil {
		return zero, false, err
	}
	sum := sha256.Sum256([]byte(name))
	want := hex.EncodeToString(sum[:])
	if len(entries) != 1 || entries[0].Name() != want {
		return zero, false, nil
	}
	path := filepath.Join(data, want)
	raw, found, err := boundedRegularFile(path, int64(32<<20)+4096)
	if err != nil {
		return zero, false, err
	}
	if !found {
		return zero, false, nil
	}
	record := localBackendRecord{raw: string(raw), path: path}
	if value, valid := decodeLocalBackendRecord(raw); valid {
		digest := sha256.Sum256(value)
		record.digest, record.valid = hex.EncodeToString(digest[:]), true
	}
	return record, true, nil
}

// verifyPairBackendLayout enforces a closed-world backend directory shape:
// root -> vaultfile-backend -> v1 -> {data, tmp, optional known lock file}.
// Any unknown child, symlink, wrong entry type or over-count is rejected
// before records are read, so an extra item can never be silently skipped.
func verifyPairBackendLayout(backendRoot string) error {
	namespace := filepath.Join(backendRoot, "vaultfile-backend")
	version := filepath.Join(namespace, "v1")
	levels := []struct {
		path     string
		allowed  map[string]bool // true means directory, false means regular file
		required []string
	}{
		{backendRoot, map[string]bool{"vaultfile-backend": true}, []string{"vaultfile-backend"}},
		{namespace, map[string]bool{"v1": true}, []string{"v1"}},
		{version, map[string]bool{"data": true, "tmp": true, localBackendLockName: false}, []string{"data", "tmp"}},
	}
	for _, level := range levels {
		exists, err := realDirectory(level.path)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("incomplete local backend layout")
		}
		entries, err := readBoundedDir(level.path, len(level.allowed))
		if err != nil {
			return err
		}
		found := make(map[string]bool, len(entries))
		for _, entry := range entries {
			wantDir, known := level.allowed[entry.Name()]
			if !known {
				return errors.New("unknown local backend entry")
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("local backend contains a symlink")
			}
			if wantDir {
				if !info.IsDir() {
					return errors.New("invalid local backend directory")
				}
			} else if !info.Mode().IsRegular() {
				return errors.New("invalid local backend file")
			}
			found[entry.Name()] = true
		}
		for _, name := range level.required {
			if !found[name] {
				return errors.New("incomplete local backend layout")
			}
		}
	}
	return nil
}

// readLocalPairBackendRecords accepts only the exact, deduplicated set of
// hashed names for two completed vaults. It does not relax the single-object
// uniqueness rule in readBackendObject: any missing, extra or duplicate object
// is reported as absent instead of being treated as an implicit match.
func readLocalPairBackendRecords(backendRoot string, names []string) (map[string]localBackendRecord, error) {
	namespace := filepath.Join(backendRoot, "vaultfile-backend")
	version := filepath.Join(namespace, "v1")
	data := filepath.Join(version, "data")
	for _, dir := range []string{backendRoot, namespace, version, data} {
		exists, err := realDirectory(dir)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, nil
		}
	}
	wanted := make(map[string]string, len(names))
	for _, name := range names {
		sum := sha256.Sum256([]byte(name))
		hash := hex.EncodeToString(sum[:])
		if _, duplicate := wanted[hash]; duplicate {
			return nil, nil
		}
		wanted[hash] = name
	}
	entries, err := readBoundedDir(data, len(wanted))
	if err != nil {
		return nil, err
	}
	if len(entries) != len(wanted) {
		return nil, nil
	}
	records := make(map[string]localBackendRecord, len(names))
	for _, entry := range entries {
		name, known := wanted[entry.Name()]
		if !known {
			return nil, nil
		}
		path := filepath.Join(data, entry.Name())
		raw, found, err := boundedRegularFile(path, int64(32<<20)+4096)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, nil
		}
		record := localBackendRecord{raw: string(raw), path: path}
		if value, valid := decodeLocalBackendRecord(raw); valid {
			digest := sha256.Sum256(value)
			record.digest, record.valid = hex.EncodeToString(digest[:]), true
		}
		records[name] = record
	}
	return records, nil
}

// backendTmpState accepts a completed create only when the versioned tmp
// directory is present and empty. Any temporary entry is an unknown object,
// so the observer refuses instead of treating it as an implicitly safe file.
func backendTmpState(backendRoot string) (present, empty bool, err error) {
	namespace := filepath.Join(backendRoot, "vaultfile-backend")
	version := filepath.Join(namespace, "v1")
	tmp := filepath.Join(version, "tmp")
	for _, dir := range []string{backendRoot, namespace, version, tmp} {
		exists, err := realDirectory(dir)
		if err != nil {
			return false, false, err
		}
		if !exists {
			return false, false, nil
		}
	}
	if _, err := readBoundedDir(tmp, 0); err != nil {
		return true, false, err
	}
	return true, true, nil
}

func localPrivateModes(f fixture, workspace, profiles, profileDir, backendRoot, config, companion, journal, archive, objectPath string, objectFound bool, entries []os.DirEntry) bool {
	ok := true
	requireDir := func(path string) {
		if path == "" {
			return
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0700 {
			ok = false
		}
	}
	requireFile := func(path string) {
		if path == "" {
			return
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			ok = false
		}
	}
	namespace := filepath.Join(backendRoot, "vaultfile-backend")
	version := filepath.Join(namespace, "v1")
	for _, dir := range []string{workspace, profiles, profileDir, backendRoot, namespace, version,
		filepath.Join(version, "tmp"), filepath.Join(version, "data")} {
		requireDir(dir)
	}
	for _, path := range []string{f.Path, config, companion, journal, archive} {
		requireFile(path)
	}
	if objectFound {
		requireFile(objectPath)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			ok = false
		}
	}
	if info, err := os.Lstat(filepath.Join(version, localBackendLockName)); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			ok = false
		}
	}
	return ok
}

// factorsAbsent reports only that the known fixture values above do not occur
// in these observed bytes. It does not inspect dynamic recovery kits or every
// channel, and it does not establish that no other secret was persisted. A
// separate transcript barrier covers the unknown LLR2 channel.
func factorsAbsent(f fixture, raws ...[]byte) bool {
	values := []string{f.Password, f.Secret, f.Username, f.Value, f.OTPSeed, f.OTPConfig, f.ProviderCanary, f.ProviderValue}
	for _, raw := range raws {
		for _, value := range values {
			if value != "" && bytes.Contains(raw, []byte(value)) {
				return false
			}
		}
	}
	return true
}

// verifyLocalWorkspace is a bounded read-only observer for one exact existing
// local create profile. It never opens the product session, backend, journal
// or archive, never creates or publishes, and never unlocks the personal file.
// A matching hash proves byte equality only.
func verifyLocalWorkspace(f fixture, workspace string) (localProjection, error) {
	var report localProjection
	if f.Path == "" || !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path {
		return report, errors.New("invalid local fixture path")
	}
	if workspace == "" || !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		return report, errors.New("invalid local workspace")
	}
	exists, err := realDirectory(workspace)
	if err != nil || !exists {
		return report, errors.New("invalid local workspace")
	}
	profiles := filepath.Join(workspace, "profiles")
	profileDir := localProfileDir(workspace, f.Path)
	backendRoot := localBackendRoot(workspace)
	if _, err := realDirectory(profiles); err != nil {
		return report, err
	}
	profileExists, err := realDirectory(profileDir)
	if err != nil {
		return report, err
	}
	if _, err := realDirectory(backendRoot); err != nil {
		return report, err
	}
	personalInfo, personalErr := os.Lstat(f.Path)
	if personalErr != nil && !os.IsNotExist(personalErr) {
		return report, personalErr
	}
	if personalErr == nil && (personalInfo.Mode()&os.ModeSymlink != 0 || !personalInfo.Mode().IsRegular()) {
		return report, errors.New("invalid local fixture path")
	}

	var entries []os.DirEntry
	if profileExists {
		entries, err = os.ReadDir(profileDir)
		if err != nil {
			return report, err
		}
		if len(entries) > 128 {
			return report, errors.New("local profile exceeds bound")
		}
	}
	count := 0
	config := ""
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return report, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return report, errors.New("local profile contains a symlink")
		}
		if strings.HasSuffix(entry.Name(), ".json") {
			if !info.Mode().IsRegular() {
				return report, errors.New("invalid local manifest")
			}
			count++
			config = filepath.Join(profileDir, entry.Name())
		}
	}
	report.ManifestCount = count
	if count != 1 {
		report.PrivateModes = localPrivateModes(f, workspace, profiles, profileDir, backendRoot, "", "", "", "", "", false, entries)
		return report, nil
	}

	base := strings.TrimSuffix(filepath.Base(config), ".json")
	known := map[string]bool{
		base + ".json":          true,
		base + ".json.baseline": true,
		base + ".journal":       true,
		base + ".llb":           true,
	}
	for _, entry := range entries {
		if !known[entry.Name()] {
			return report, errors.New("unknown local profile entry")
		}
	}
	companionPath, err := vaultfileclient.CompanionPath(config)
	if err != nil {
		return report, errors.New("invalid local companion path")
	}
	report.PrivateModes = localPrivateModes(f, workspace, profiles, profileDir, backendRoot, config, companionPath, "", "", "", false, entries)
	manifest, manifestExists, err := vaultfileclient.ReadManifest(config)
	if err != nil || !manifestExists {
		return report, nil
	}
	if personalErr == nil && manifest.PersonalFile == f.Path {
		report.ManifestPersonal = true
	}
	report.ManifestBackend = manifest.BackendRoot == backendRoot

	expectedJournal := filepath.Join(profileDir, base+".journal")
	expectedArchive := filepath.Join(profileDir, base+".llb")
	bound := manifest.Name == base+".llv" && manifest.Journal == expectedJournal && manifest.Archive == expectedArchive

	digest, digestErr := vaultfileclient.ReadManifestDigest(config, manifest)
	companion, companionExists, companionErr := vaultfileclient.ReadCompanion(config, manifest)
	if digestErr == nil && companionErr == nil && companionExists && bound &&
		report.ManifestPersonal && report.ManifestBackend &&
		companion.ManifestSHA256 == digest && companion.Resume.PersonalFile == f.Path &&
		companion.Resume.BackendRoot == backendRoot {
		report.CompanionPresent = true
		report.ManifestDigest = true
	}

	journalRaw, journalFound, journalErr := boundedRegularFile(expectedJournal, int64(32<<20))
	if journalErr != nil {
		return report, journalErr
	}
	if bound && journalFound && len(journalRaw) > 0 {
		report.JournalPresent = true
	}
	archiveRaw, archiveFound, archiveErr := boundedRegularFile(expectedArchive, int64(32<<20))
	if archiveErr != nil {
		return report, archiveErr
	}
	if bound && archiveFound && len(archiveRaw) > 0 {
		report.ArchivePresent = true
	}

	tmpPresent, tmpEmpty, tmpErr := backendTmpState(backendRoot)
	if tmpErr != nil {
		return report, tmpErr
	}
	if tmpPresent && !tmpEmpty {
		return report, errors.New("backend temporary directory is not empty")
	}
	record, recordFound, recordErr := readBackendObject(backendRoot, manifest.Name)
	if recordErr != nil {
		return report, recordErr
	}
	if report.CompanionPresent && recordFound && record.valid && record.digest == companion.GenesisSHA256 {
		report.BackendHashMatches = true
	}
	report.PrivateModes = localPrivateModes(f, workspace, profiles, profileDir, backendRoot, config, companionPath,
		expectedJournal, expectedArchive, record.path, recordFound, entries)

	manifestRaw, manifestFound, manifestRawErr := boundedRegularFile(config, 64<<10)
	if manifestRawErr != nil {
		return report, manifestRawErr
	}
	companionRaw, companionFound, companionRawErr := boundedRegularFile(companionPath, 64<<10)
	if companionRawErr != nil {
		return report, companionRawErr
	}
	if bound && manifestFound && companionFound && journalFound && archiveFound && recordFound && record.valid {
		report.FactorsAbsent = factorsAbsent(f, manifestRaw, companionRaw, journalRaw, archiveRaw, []byte(record.raw))
	}
	return report, nil
}

// localPairVault holds one manifest's bounded read-only facts. It is never
// serialized; only the fixed localProjection leaves this file.
type pairPrepareStage string

const (
	pairStagePaths              pairPrepareStage = "paths"
	pairStageFixtureParent      pairPrepareStage = "fixture-parent"
	pairStageWorkspaceParent    pairPrepareStage = "workspace-parent"
	pairStageWorkspaceFresh     pairPrepareStage = "workspace-fresh"
	pairStageFixtureSetup       pairPrepareStage = "fixture-setup"
	pairStageFixtureWrite       pairPrepareStage = "fixture-write"
	pairStageWorkspaceCreate    pairPrepareStage = "workspace-create"
	pairStageVault1             pairPrepareStage = "vault-1-create"
	pairStageVault2             pairPrepareStage = "vault-2-create"
	pairStageObserver           pairPrepareStage = "observer"
	pairStageObserverIncomplete pairPrepareStage = "observer-incomplete"
)

type pairCreateSubstage string

const (
	pairSubSelect        pairCreateSubstage = "select"
	pairSubFactorParse   pairCreateSubstage = "factor-parse"
	pairSubOpenFirst     pairCreateSubstage = "open-creation-1"
	pairSubPrepareFirst  pairCreateSubstage = "prepare-1"
	pairSubBackupPrepare pairCreateSubstage = "backup-prepare"
	pairSubBackupPublish pairCreateSubstage = "backup-publish"
	pairSubOpenSecond    pairCreateSubstage = "open-creation-2"
	pairSubPrepareSecond pairCreateSubstage = "prepare-2"
	pairSubComplete      pairCreateSubstage = "complete"
	pairSubVerify        pairCreateSubstage = "verify"
)

type pairErrorClass string

const (
	pairErrorVerifyRejected pairErrorClass = "VERIFY_REJECTED"
	pairErrorLocalReview    pairErrorClass = "LOCAL_REVIEW"
	pairErrorUnknownReview  pairErrorClass = "UNKNOWN_REVIEW"
	pairErrorCancelled      pairErrorClass = "CANCELLED"
	pairErrorUnsupported    pairErrorClass = "UNSUPPORTED"
	pairErrorBackend        pairErrorClass = "BACKEND"
	pairErrorOther          pairErrorClass = "OTHER"
)

type pairObserverEvidence struct {
	ManifestCount      int
	ManifestPersonal   bool
	ManifestBackend    bool
	CompanionPresent   bool
	ManifestDigest     bool
	JournalPresent     bool
	ArchivePresent     bool
	PrivateModes       bool
	BackendHashMatches bool
	FactorsAbsent      bool
}

type initialPairError struct {
	stage    pairPrepareStage
	target   int
	substage pairCreateSubstage
	class    pairErrorClass
	observer pairObserverEvidence
	cause    error
}

func (e *initialPairError) Error() string {
	return "initial pair preparation failed"
}

func (e *initialPairError) Unwrap() error {
	return e.cause
}

func pairErrorClassOf(err error) pairErrorClass {
	switch {
	case errors.Is(err, vaultfileclient.ErrCreateVerification):
		return pairErrorVerifyRejected
	case errors.Is(err, vaultfileclient.ErrLocalReview):
		return pairErrorLocalReview
	case errors.Is(err, vaultfileclient.ErrCreateUnknown):
		return pairErrorUnknownReview
	case errors.Is(err, vaultfileclient.ErrCreateCancelled):
		return pairErrorCancelled
	case errors.Is(err, vaultfileclient.ErrCreateUnsupported):
		return pairErrorUnsupported
	case errors.Is(err, vaultfileclient.ErrBackend):
		return pairErrorBackend
	default:
		return pairErrorOther
	}
}

func pairObserverEvidenceOf(report localProjection) pairObserverEvidence {
	return pairObserverEvidence{
		ManifestCount:      report.ManifestCount,
		ManifestPersonal:   report.ManifestPersonal,
		ManifestBackend:    report.ManifestBackend,
		CompanionPresent:   report.CompanionPresent,
		ManifestDigest:     report.ManifestDigest,
		JournalPresent:     report.JournalPresent,
		ArchivePresent:     report.ArchivePresent,
		PrivateModes:       report.PrivateModes,
		BackendHashMatches: report.BackendHashMatches,
		FactorsAbsent:      report.FactorsAbsent,
	}
}

func pairStageError(stage pairPrepareStage, target int, substage pairCreateSubstage, cause error) error {
	return &initialPairError{stage: stage, target: target, substage: substage, class: pairErrorClassOf(cause), cause: cause}
}

type createdLocalVault struct {
	config, companion, journal, archive, profileDir, backendRoot string
	kit                                                          []byte
}

func createPublishedLocalVault(f fixture, workspace, backendRoot string) (*createdLocalVault, pairCreateSubstage, error) {
	profileDir := localProfileDir(workspace, f.Path)
	var selectorRaw [16]byte
	if _, err := rand.Read(selectorRaw[:]); err != nil {
		return nil, pairSubSelect, err
	}
	selector := hex.EncodeToString(selectorRaw[:])
	v := &createdLocalVault{
		profileDir: profileDir, backendRoot: backendRoot,
		config:    filepath.Join(profileDir, selector+".json"),
		companion: filepath.Join(profileDir, selector+".json.baseline"),
		journal:   filepath.Join(profileDir, selector+".journal"),
		archive:   filepath.Join(profileDir, selector+".llb"),
	}
	proposal := vaultfileclient.Manifest{
		Version: 1, Kind: vaultfileclient.CreateKind,
		PersonalFile: f.Path, BackendRoot: backendRoot, Name: selector + ".llv",
		Journal: v.journal, Archive: v.archive,
	}
	key, err := personal.ParseSecret(f.Secret)
	if err != nil {
		return nil, pairSubFactorParse, err
	}
	defer clear(key)
	password, secret := []byte(f.Password), []byte(f.Secret)
	defer clear(password)
	defer clear(secret)

	creation, err := vaultfileclient.OpenCreation(v.config, &proposal, password, secret)
	if err != nil {
		return nil, pairSubOpenFirst, err
	}
	backupRequired, err := creation.Prepare(context.Background())
	creation.Close()
	if err != nil {
		return nil, pairSubPrepareFirst, err
	}
	if !backupRequired {
		return nil, pairSubPrepareFirst, errors.New("fixture creation did not request a backup")
	}
	backup, err := personal.PrepareBackup(f.Path, v.archive, f.Password, key)
	if err != nil {
		return nil, pairSubBackupPrepare, err
	}
	if err := backup.Publish(); err != nil {
		backup.Close()
		return nil, pairSubBackupPublish, err
	}
	v.kit = []byte(backup.Material())
	backup.Close()
	if len(v.kit) == 0 {
		return nil, pairSubBackupPublish, errors.New("fixture creation produced no backup material")
	}

	creation, err = vaultfileclient.OpenCreation(v.config, nil, password, secret)
	if err != nil {
		clear(v.kit)
		return nil, pairSubOpenSecond, err
	}
	defer creation.Close()
	backupRequired, err = creation.Prepare(context.Background())
	if err != nil {
		clear(v.kit)
		return nil, pairSubPrepareSecond, err
	}
	if backupRequired {
		clear(v.kit)
		return nil, pairSubPrepareSecond, errors.New("fixture creation requested an unexpected backup")
	}
	if err := creation.Complete(context.Background(), password, secret, v.kit); err != nil {
		clear(v.kit)
		return nil, pairSubComplete, err
	}
	if err := creation.Verify(context.Background(), password, secret, v.kit); err != nil {
		clear(v.kit)
		return nil, pairSubVerify, err
	}
	return v, "", nil
}

func prepareLocalWorkspaceDirs(workspace, personalPath string) (string, string, error) {
	parentExists, err := realDirectory(filepath.Dir(workspace))
	if err != nil || !parentExists {
		return "", "", errors.New("fixture workspace parent is unavailable")
	}
	if err := os.Mkdir(workspace, 0700); err != nil {
		return "", "", err
	}
	profiles := filepath.Join(workspace, "profiles")
	profileDir := localProfileDir(workspace, personalPath)
	backendRoot := localBackendRoot(workspace)
	for _, dir := range []string{profiles, profileDir, backendRoot} {
		if err := os.Mkdir(dir, 0700); err != nil {
			return "", "", err
		}
	}
	return profileDir, backendRoot, nil
}

func clearFixture(f *fixture) {
	if f == nil {
		return
	}
	f.Path = ""
	f.Password = ""
	f.Secret = ""
	f.Username = ""
	f.Value = ""
	f.URL = ""
	f.OTPSeed = ""
	f.OTPConfig = ""
	f.ProviderValue = ""
	f.ProviderCanary = ""
	f.IDs = nil
}

func localPairProjectionComplete(report localProjection) bool {
	return report.ManifestCount == 2 && report.ManifestPersonal && report.ManifestBackend &&
		report.CompanionPresent && report.ManifestDigest && report.JournalPresent &&
		report.ArchivePresent && report.PrivateModes && report.BackendHashMatches && report.FactorsAbsent
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func createInitialPairFixture(fixtureDir, workspace string) (fixture, error) {
	if !filepath.IsAbs(fixtureDir) || !filepath.IsAbs(workspace) ||
		filepath.Clean(fixtureDir) != fixtureDir || filepath.Clean(workspace) != workspace ||
		fixtureDir == workspace || pathContains(fixtureDir, workspace) || pathContains(workspace, fixtureDir) {
		return fixture{}, pairStageError(pairStagePaths, 0, "", nil)
	}
	parentExists, err := realDirectory(filepath.Dir(fixtureDir))
	if err != nil || !parentExists {
		return fixture{}, pairStageError(pairStageFixtureParent, 0, "", nil)
	}
	workspaceParent, err := realDirectory(filepath.Dir(workspace))
	if err != nil || !workspaceParent {
		return fixture{}, pairStageError(pairStageWorkspaceParent, 0, "", nil)
	}
	if _, err := os.Lstat(workspace); !os.IsNotExist(err) {
		return fixture{}, pairStageError(pairStageWorkspaceFresh, 0, "", nil)
	}
	f, err := newSyntheticFixture(fixtureDir)
	if err != nil {
		return fixture{}, pairStageError(pairStageFixtureSetup, 0, "", err)
	}
	if err := prepareInitialPairForFixture(f, workspace); err != nil {
		clearFixture(&f)
		return fixture{}, err
	}
	if err := writeSyntheticFixture(fixtureDir, f); err != nil {
		clearFixture(&f)
		return fixture{}, pairStageError(pairStageFixtureWrite, 0, "", err)
	}
	return f, nil
}

func prepareInitialPairForFixture(f fixture, workspace string) error {
	if _, backendRoot, err := prepareLocalWorkspaceDirs(workspace, f.Path); err != nil {
		return pairStageError(pairStageWorkspaceCreate, 0, "", err)
	} else {
		for i := 0; i < 2; i++ {
			stage := pairStageVault1
			target := 1
			if i == 1 {
				stage = pairStageVault2
				target = 2
			}
			created, substage, err := createPublishedLocalVault(f, workspace, backendRoot)
			if err != nil {
				return pairStageError(stage, target, substage, err)
			}
			clear(created.kit)
		}
	}
	report, err := verifyLocalPairWorkspace(f, workspace)
	if err != nil {
		return &initialPairError{
			stage: pairStageObserver, class: pairErrorClassOf(err),
			observer: pairObserverEvidenceOf(report), cause: err,
		}
	}
	if !localPairProjectionComplete(report) {
		return &initialPairError{
			stage: pairStageObserverIncomplete, class: pairErrorOther,
			observer: pairObserverEvidenceOf(report),
		}
	}
	return nil
}

type localPairVault struct {
	config, base, companionPath, expectedJournal, expectedArchive string
	manifest                                                      vaultfileclient.Manifest
	digest                                                        string
	companion                                                     vaultfileclient.Companion
	companionOK                                                   bool
	bound, personal, backend                                      bool
	journalRaw, archiveRaw                                        []byte
	journalFound, archiveFound                                    bool
	record                                                        localBackendRecord
	recordFound                                                   bool
}

func (v *localPairVault) complete() bool {
	return v.bound && v.journalFound && v.archiveFound && v.recordFound && v.record.valid
}

// verifyLocalPairWorkspace is a bounded read-only observer for exactly two
// completed local create profiles that share one personal file and one
// workspace/backed root. Each manifest must be complete and bound to its own
// companion, journal, archive and backend object; the backend data set must be
// exactly those two hashed names. It never opens the product session, backend,
// journal or archive, never creates, writes or publishes, and never unlocks the
// personal file. Matching hashes prove byte equality only, not authorization.
func verifyLocalPairWorkspace(f fixture, workspace string) (localProjection, error) {
	var report localProjection
	if f.Path == "" || !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path {
		return report, errors.New("invalid local fixture path")
	}
	if workspace == "" || !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		return report, errors.New("invalid local workspace")
	}
	exists, err := realDirectory(workspace)
	if err != nil || !exists {
		return report, errors.New("invalid local workspace")
	}
	profiles := filepath.Join(workspace, "profiles")
	profileDir := localProfileDir(workspace, f.Path)
	backendRoot := localBackendRoot(workspace)
	if _, err := realDirectory(profiles); err != nil {
		return report, err
	}
	profileExists, err := realDirectory(profileDir)
	if err != nil {
		return report, err
	}
	if _, err := realDirectory(backendRoot); err != nil {
		return report, err
	}
	if err := verifyPairBackendLayout(backendRoot); err != nil {
		return report, err
	}
	personalInfo, personalErr := os.Lstat(f.Path)
	if personalErr != nil && !os.IsNotExist(personalErr) {
		return report, personalErr
	}
	if personalErr == nil && (personalInfo.Mode()&os.ModeSymlink != 0 || !personalInfo.Mode().IsRegular()) {
		return report, errors.New("invalid local fixture path")
	}

	var entries []os.DirEntry
	if profileExists {
		entries, err = os.ReadDir(profileDir)
		if err != nil {
			return report, err
		}
		if len(entries) > 128 {
			return report, errors.New("local profile exceeds bound")
		}
	}
	var configs []string
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return report, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return report, errors.New("local profile contains a symlink")
		}
		if strings.HasSuffix(entry.Name(), ".json") && !strings.HasSuffix(entry.Name(), ".json.baseline") {
			if !info.Mode().IsRegular() {
				return report, errors.New("invalid local manifest")
			}
			configs = append(configs, filepath.Join(profileDir, entry.Name()))
		}
	}
	report.ManifestCount = len(configs)
	if len(configs) != 2 {
		report.PrivateModes = localPrivateModes(f, workspace, profiles, profileDir, backendRoot, "", "", "", "", "", false, entries)
		return report, nil
	}

	vaults := make([]*localPairVault, 0, 2)
	vaultIDs := map[string]bool{}
	for _, config := range configs {
		base := strings.TrimSuffix(filepath.Base(config), ".json")
		manifest, manifestExists, manifestErr := vaultfileclient.ReadManifest(config)
		if manifestErr != nil || !manifestExists {
			report.PrivateModes = localPrivateModes(f, workspace, profiles, profileDir, backendRoot, "", "", "", "", "", false, entries)
			return report, nil
		}
		if vaultIDs[manifest.VaultID] {
			return report, errors.New("duplicate local vault id")
		}
		vaultIDs[manifest.VaultID] = true
		companionPath, companionErr := vaultfileclient.CompanionPath(config)
		if companionErr != nil {
			return report, errors.New("invalid local companion path")
		}
		vault := &localPairVault{
			config: config, base: base, companionPath: companionPath,
			manifest:        manifest,
			expectedJournal: filepath.Join(profileDir, base+".journal"),
			expectedArchive: filepath.Join(profileDir, base+".llb"),
		}
		vault.personal = personalErr == nil && manifest.PersonalFile == f.Path
		vault.backend = manifest.BackendRoot == backendRoot
		vault.bound = manifest.Name == base+".llv" &&
			manifest.Journal == vault.expectedJournal && manifest.Archive == vault.expectedArchive
		vaults = append(vaults, vault)
	}

	known := make(map[string]bool, 8)
	for _, vault := range vaults {
		for _, suffix := range []string{".json", ".json.baseline", ".journal", ".llb"} {
			known[vault.base+suffix] = true
		}
	}
	if len(entries) != len(known) {
		return report, errors.New("unknown local profile entry")
	}
	for _, entry := range entries {
		if !known[entry.Name()] {
			return report, errors.New("unknown local profile entry")
		}
		info, err := entry.Info()
		if err != nil {
			return report, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return report, errors.New("local profile contains a symlink")
		}
		if !info.Mode().IsRegular() {
			return report, errors.New("invalid local profile entry")
		}
	}

	for _, vault := range vaults {
		digest, digestErr := vaultfileclient.ReadManifestDigest(vault.config, vault.manifest)
		companion, companionExists, companionErr := vaultfileclient.ReadCompanion(vault.config, vault.manifest)
		if digestErr == nil && companionErr == nil && companionExists && vault.bound &&
			vault.personal && vault.backend && companion.ManifestSHA256 == digest &&
			companion.Resume.PersonalFile == f.Path && companion.Resume.BackendRoot == backendRoot {
			vault.digest, vault.companion, vault.companionOK = digest, companion, true
		}
		vault.journalRaw, vault.journalFound, err = boundedRegularFile(vault.expectedJournal, int64(32<<20))
		if err != nil {
			return report, err
		}
		vault.archiveRaw, vault.archiveFound, err = boundedRegularFile(vault.expectedArchive, int64(32<<20))
		if err != nil {
			return report, err
		}
	}

	records, err := readLocalPairBackendRecords(backendRoot, []string{vaults[0].manifest.Name, vaults[1].manifest.Name})
	if err != nil {
		return report, err
	}
	for _, vault := range vaults {
		if record, found := records[vault.manifest.Name]; found {
			vault.record, vault.recordFound = record, true
		}
	}

	tmpPresent, tmpEmpty, tmpErr := backendTmpState(backendRoot)
	if tmpErr != nil {
		return report, tmpErr
	}
	if !tmpPresent || !tmpEmpty {
		return report, errors.New("backend temporary directory is not empty")
	}

	report.ManifestPersonal = vaults[0].personal && vaults[1].personal
	report.ManifestBackend = vaults[0].backend && vaults[1].backend
	report.CompanionPresent = vaults[0].companionOK && vaults[1].companionOK
	report.ManifestDigest = report.CompanionPresent
	report.JournalPresent = vaults[0].bound && vaults[0].journalFound && len(vaults[0].journalRaw) > 0 &&
		vaults[1].bound && vaults[1].journalFound && len(vaults[1].journalRaw) > 0
	report.ArchivePresent = vaults[0].bound && vaults[0].archiveFound && len(vaults[0].archiveRaw) > 0 &&
		vaults[1].bound && vaults[1].archiveFound && len(vaults[1].archiveRaw) > 0
	report.BackendHashMatches = vaults[0].companionOK && vaults[0].recordFound && vaults[0].record.valid &&
		vaults[0].record.digest == vaults[0].companion.GenesisSHA256 &&
		vaults[1].companionOK && vaults[1].recordFound && vaults[1].record.valid &&
		vaults[1].record.digest == vaults[1].companion.GenesisSHA256
	report.PrivateModes = true
	for _, vault := range vaults {
		report.PrivateModes = report.PrivateModes && localPrivateModes(f, workspace, profiles, profileDir, backendRoot,
			vault.config, vault.companionPath, vault.expectedJournal, vault.expectedArchive,
			vault.record.path, vault.recordFound, entries)
	}
	allComplete := vaults[0].complete() && vaults[1].complete()
	raws := [][]byte{vaults[0].journalRaw, vaults[0].archiveRaw, []byte(vaults[0].record.raw),
		vaults[1].journalRaw, vaults[1].archiveRaw, []byte(vaults[1].record.raw)}
	for _, vault := range vaults {
		manifestRaw, manifestFound, manifestErr := boundedRegularFile(vault.config, 64<<10)
		if manifestErr != nil {
			return report, manifestErr
		}
		companionRaw, companionFound, companionErr := boundedRegularFile(vault.companionPath, 64<<10)
		if companionErr != nil {
			return report, companionErr
		}
		if !manifestFound || !companionFound {
			allComplete = false
		}
		raws = append(raws, manifestRaw, companionRaw)
	}
	if allComplete {
		report.FactorsAbsent = factorsAbsent(f, raws...)
	}
	return report, nil
}

const failureMessage = "Synthetic desktop fixture operation failed"

const usageText = `Usage: desktop_acceptance_fixture [options]
  -out
        new synthetic fixture directory
  -fixture
        private synthetic fixture file
  -private-pipe
        observe authenticated copy through private pipe only
  -stale
        independent local-owner URL edit for exact-target conflict test
  -hold-readonly
        hold a read-only original-file lock until private stdin closes
  -verify-local
        read-only bounded local create workspace verification
  -verify-local-pair
        read-only bounded two-vault local workspace verification
  -prepare-initial-pair
        create exactly two strict local generation-zero targets in a fresh fixture directory
  -prepare-workspace
        absolute fresh local vaultfile workspace for -prepare-initial-pair
  -h, -help
        show this fixed help text
`

func run(args []string) error {
	flags := flag.NewFlagSet("desktop_acceptance_fixture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	out := flags.String("out", "", "new synthetic fixture directory")
	input := flags.String("fixture", "", "private synthetic fixture file")
	privatePipe := flags.Bool("private-pipe", false, "observe authenticated copy through private pipe only")
	stale := flags.String("stale", "", "independent local-owner URL edit for exact-target conflict test")
	hold := flags.Bool("hold-readonly", false, "hold a read-only original-file lock until private stdin closes")
	verifyLocalDir := flags.String("verify-local", "", "read-only bounded local create workspace verification")
	verifyLocalPairDir := flags.String("verify-local-pair", "", "read-only bounded two-vault local workspace verification")
	prepareInitialPairDir := flags.String("prepare-initial-pair", "", "fresh initial-pair fixture directory")
	prepareWorkspaceDir := flags.String("prepare-workspace", "", "fresh initial-pair local workspace")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(os.Stdout, usageText)
			return nil
		}
		return err
	}
	if *out != "" {
		if *input != "" || *privatePipe || *stale != "" || *hold ||
			*verifyLocalDir != "" || *verifyLocalPairDir != "" ||
			*prepareInitialPairDir != "" || *prepareWorkspaceDir != "" || flags.NArg() != 0 {
			return errors.New("invalid fixture arguments")
		}
		return setup(*out)
	}
	if *prepareInitialPairDir != "" {
		if *input != "" || *privatePipe || *stale != "" || *hold ||
			*verifyLocalDir != "" || *verifyLocalPairDir != "" ||
			*prepareWorkspaceDir == "" || flags.NArg() != 0 {
			return errors.New("invalid fixture arguments")
		}
		f, err := createInitialPairFixture(*prepareInitialPairDir, *prepareWorkspaceDir)
		clearFixture(&f)
		return err
	}
	if *prepareWorkspaceDir != "" {
		return errors.New("invalid fixture arguments")
	}

	operations := 0
	for _, enabled := range []bool{*privatePipe, *stale != "", *hold, *verifyLocalDir != "", *verifyLocalPairDir != ""} {
		if enabled {
			operations++
		}
	}
	if *input == "" || flags.NArg() != 0 || operations != 1 {
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
	if *verifyLocalDir != "" {
		report, err := verifyLocalWorkspace(f, *verifyLocalDir)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	if *verifyLocalPairDir != "" {
		report, err := verifyLocalPairWorkspace(f, *verifyLocalPairDir)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	if *hold {
		stat, err := os.Stdout.Stat()
		if err != nil || stat.Mode()&os.ModeNamedPipe == 0 {
			return errors.New("private control pipe required")
		}
		db, err := bolt.Open(f.Path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
		if err != nil {
			return err
		}
		defer db.Close()
		if _, err = fmt.Fprintln(os.Stdout, `{"ready":true}`); err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, os.Stdin)
		return err
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
	if run(os.Args[1:]) != nil {
		fmt.Fprintln(os.Stderr, failureMessage)
		os.Exit(1)
	}
}
