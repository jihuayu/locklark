// This executable is a private acceptance fixture, never a product entry point.
// All keys and plaintext stay in a caller-owned 0700 directory. Its stdout is a
// deliberately small classification channel; errors never include input data.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/vault"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
)

type privateDevice struct {
	Device  directory.Device
	Age     string
	Signing ed25519.PrivateKey
}
type privateFixture struct {
	Pins                        directory.Pins
	Owner, Publisher, Sequencer ed25519.PrivateKey
	Devices                     []privateDevice
	Members                     []directory.Member
	Items                       map[string][]vault.Item
}
type publication struct {
	Proposal directory.Proposal `json:"proposal"`
	Snapshot vault.Snapshot     `json:"snapshot"`
}
type serverPublic struct {
	Pins                                  directory.Pins `json:"pins"`
	Database, Certificate, TLSKey, Anchor string
}

func must(err error) {
	if err != nil {
		panic("fixture operation failed")
	}
}
func jsonRead(path string, v any) {
	raw, err := os.ReadFile(path)
	must(err)
	must(json.Unmarshal(raw, v))
}
func jsonWrite(path string, v any) {
	raw, err := json.Marshal(v)
	must(err)
	must(os.WriteFile(path, raw, 0600))
}
func randomHex(n int) string {
	b := make([]byte, n)
	_, e := rand.Read(b)
	must(e)
	return hex.EncodeToString(b)
}
func generateSigner() ed25519.PrivateKey {
	_, k, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	return k
}
func publicKey(k ed25519.PrivateKey) string {
	return hex.EncodeToString(k.Public().(ed25519.PublicKey))
}
func loadFixture(root string) privateFixture {
	var f privateFixture
	jsonRead(filepath.Join(root, "private.json"), &f)
	return f
}
func configuration(pins directory.Pins) *directory.Config {
	c, e := directory.NewConfigWithWriterACL(pins)
	must(e)
	return c
}
func itemsFor(f privateFixture, variant string) []vault.Item {
	items, ok := f.Items[variant]
	if !ok {
		panic("unknown variant")
	}
	return items
}
func checkPrivateDir(root string) {
	st, e := os.Stat(root)
	must(e)
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		panic("private directory required")
	}
}

func makeCertificate(root string) {
	caKey, serverKey := generateSigner(), generateSigner()
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Locklark acceptance root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	must(e)
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certDER, e := x509.CreateCertificate(rand.Reader, cert, ca, serverKey.Public(), caKey)
	must(e)
	keyDER, e := x509.MarshalPKCS8PrivateKey(serverKey)
	must(e)
	for name, b := range map[string][]byte{"ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), "server.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), "tls-key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		must(os.WriteFile(filepath.Join(root, name), b, 0600))
	}
}

func admission(f privateFixture, c *directory.Config, parent directory.Checkpoint, index int) directory.Admission {
	d := f.Devices[index]
	member := f.Members[0].ID
	if index == 2 {
		member = f.Members[1].ID
	}
	enrollment := directory.Enrollment{Parent: parent, Member: member, Device: d.Device}
	challenge, e := directory.IssueChallenge(c, f.Owner, enrollment)
	must(e)
	identity, e := age.ParseX25519Identity(d.Age)
	must(e)
	answer, e := directory.AnswerChallenge(c, enrollment, challenge, identity, d.Signing)
	must(e)
	must(directory.VerifyAdmission(c, enrollment, answer))
	return answer
}

func fixtureInit(root string) {
	checkPrivateDir(root)
	f := privateFixture{Owner: generateSigner(), Publisher: generateSigner(), Sequencer: generateSigner(), Items: map[string][]vault.Item{}}
	f.Pins = directory.Pins{Team: randomHex(16), Vault: randomHex(16), Owners: []string{publicKey(f.Owner)}, Publisher: publicKey(f.Publisher), Sequencer: publicKey(f.Sequencer)}
	for i := 0; i < 3; i++ {
		id, e := age.GenerateX25519Identity()
		must(e)
		key := generateSigner()
		f.Devices = append(f.Devices, privateDevice{Device: directory.Device{ID: fmt.Sprintf("%032x", 20+i), Encryption: id.Recipient().String(), Signing: publicKey(key)}, Age: id.String(), Signing: key})
	}
	f.Members = []directory.Member{{ID: fmt.Sprintf("%032x", 10), Role: "writer", Devices: []directory.Device{f.Devices[0].Device, f.Devices[1].Device}}, {ID: fmt.Sprintf("%032x", 11), Role: "reader", Devices: []directory.Device{f.Devices[2].Device}}}
	for _, variant := range []string{"initial", "a", "b", "c", "d", "e"} {
		f.Items[variant] = []vault.Item{{ID: "acceptance-login", Kind: "login", Title: "Acceptance team login", Username: "user-" + randomHex(16), Password: "password-" + randomHex(24), Notes: "notes-" + randomHex(16)}}
	}
	c := configuration(f.Pins)
	initial := []directory.Member{{ID: f.Members[0].ID, Role: "writer", Devices: []directory.Device{f.Devices[0].Device}}}
	p, s, e := directory.Build(c, f.Owner, f.Publisher, c.Genesis(), initial, f.Items["initial"], admission(f, c, c.Genesis(), 0))
	must(e)
	r, e := directory.Create(filepath.Join(root, "team.db"), c, f.Sequencer, p, s)
	must(e)
	v, e := directory.Read(filepath.Join(root, "team.db"), c, r.Checkpoint())
	must(e)
	jsonWrite(filepath.Join(root, "initial-view.json"), v)
	jsonWrite(filepath.Join(root, "private.json"), f)
	jsonWrite(filepath.Join(root, "pins.json"), f.Pins)
	jsonWrite(filepath.Join(root, "owner.json"), map[string]any{"signing": f.Owner})
	jsonWrite(filepath.Join(root, "sequencer.json"), map[string]any{"signing": f.Sequencer})
	for i, d := range f.Devices {
		jsonWrite(filepath.Join(root, fmt.Sprintf("device-%d.json", i)), map[string]any{"device": d.Device, "signing": d.Signing, "age": d.Age})
	}
	makeCertificate(root)
	jsonWrite(filepath.Join(root, "server.json"), serverPublic{Pins: f.Pins, Database: filepath.Join(root, "team.db"), Certificate: filepath.Join(root, "server.pem"), TLSKey: filepath.Join(root, "tls-key.pem"), Anchor: filepath.Join(root, "server.anchor")})
	jsonWrite(filepath.Join(root, "genesis.json"), c.Genesis())
	emit(map[string]any{"initialized": true, "independent_devices": true, "writer_acl": true})
}

func snapshotHash(s vault.Snapshot) string {
	h := sha256.New()
	h.Write([]byte("locklark/team-directory/snapshot/v1\x00"))
	h.Write(binary.BigEndian.AppendUint64(nil, s.Epoch))
	for _, part := range [][]byte{s.Database, s.Envelope, s.Signature} {
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(part))))
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func fixturePrepare(root, viewPath, kind, variant, out string) {
	f := loadFixture(root)
	c := configuration(f.Pins)
	var view directory.View
	jsonRead(viewPath, &view)
	parent := view.Receipt.Checkpoint()
	members := view.Receipt.Proposal.Members
	var p directory.Proposal
	var s vault.Snapshot
	var e error
	switch kind {
	case "admit":
		p, s, e = directory.Build(c, f.Owner, f.Publisher, parent, f.Members, itemsFor(f, variant), admission(f, c, parent, 1), admission(f, c, parent, 2))
	case "revoke-device":
		members = []directory.Member{{ID: f.Members[0].ID, Role: "writer", Devices: []directory.Device{f.Devices[1].Device}}, f.Members[1]}
		p, s, e = directory.Build(c, f.Owner, f.Publisher, parent, members, itemsFor(f, variant))
	case "revoke-member":
		p, s, e = directory.Build(c, f.Owner, f.Publisher, parent, f.Members[1:], itemsFor(f, variant))
	case "freeze":
		p, e = directory.Freeze(c, f.Owner, parent)
	case "writer-0", "writer-1":
		index := int(kind[len(kind)-1] - '0')
		p, s, e = directory.BuildUpdate(c, f.Devices[index].Signing, view.Receipt, itemsFor(f, variant))
	case "reader-forged":
		// Construct a self-consistent hostile publication independently of the
		// writer UI guard. The network must enforce the preceding reader role.
		recipients := []*age.X25519Recipient{}
		for _, m := range members {
			for _, d := range m.Devices {
				r, err := age.ParseX25519Recipient(d.Encryption)
				must(err)
				recipients = append(recipients, r)
			}
		}
		s, e = vault.SealItems([]byte("locklark/team/items/v1/"+parent.Scope), itemsFor(f, variant), parent.Version+1, recipients, f.Devices[2].Signing)
		must(e)
		p = directory.Proposal{Scope: parent.Scope, Parent: parent, Epoch: parent.Version + 1, Mode: "active", Members: members, SnapshotDigest: snapshotHash(s), AuthorDevice: f.Devices[2].Device.ID}
		raw, err := json.Marshal(p)
		must(err)
		p.Signature = ed25519.Sign(f.Devices[2].Signing, append([]byte("locklark/team-directory/proposal/v1\x00"), raw...))
	default:
		panic("unknown fixture kind")
	}
	must(e)
	jsonWrite(out, publication{p, s})
	emit(map[string]any{"prepared": true})
}

func fixtureOracle(root, viewPath, variant string, index int, shouldDecrypt bool) {
	f := loadFixture(root)
	var view directory.View
	jsonRead(viewPath, &view)
	s := view.Snapshot
	p := view.Receipt.Proposal
	var signer, author ed25519.PublicKey
	if p.AuthorDevice == "" {
		if p.Owner != publicKey(f.Owner) {
			panic("unexpected publication owner")
		}
		signer = f.Publisher.Public().(ed25519.PublicKey)
		author = f.Owner.Public().(ed25519.PublicKey)
	} else {
		for _, device := range f.Devices {
			if device.Device.ID == p.AuthorDevice {
				signer = device.Signing.Public().(ed25519.PublicKey)
				author = signer
			}
		}
	}
	if len(signer) != ed25519.PublicKeySize || !bytes.Equal(signer, view.SnapshotSigner) || s.Epoch != p.Epoch || p.Parent.Version+1 != p.Epoch || p.SnapshotDigest != snapshotHash(s) {
		panic("independent author or snapshot binding failed")
	}
	proposalSignature := p.Signature
	p.Signature = nil
	raw, e := json.Marshal(p)
	must(e)
	if !ed25519.Verify(author, append([]byte("locklark/team-directory/proposal/v1\x00"), raw...), proposalSignature) {
		panic("independent proposal signature failed")
	}
	receipt := view.Receipt
	receiptSignature := receipt.Signature
	receipt.Signature = nil
	raw, e = json.Marshal(receipt)
	must(e)
	if !ed25519.Verify(f.Sequencer.Public().(ed25519.PublicKey), append([]byte("locklark/team-directory/receipt/v1\x00"), raw...), receiptSignature) {
		panic("independent receipt signature failed")
	}
	// Independently verify the snapshot signature framing, unwrap age, and
	// decode KDBX without calling vault.OpenItems or the network client's API.
	proof := binary.BigEndian.AppendUint64([]byte("locklark/m0/vault-snapshot/v1\x00"), s.Epoch)
	for _, part := range [][]byte{s.Database, s.Envelope} {
		h := sha256.Sum256(part)
		proof = append(proof, h[:]...)
	}
	if !ed25519.Verify(signer, proof, s.Signature) {
		panic("oracle snapshot signature failed")
	}
	id, e := age.ParseX25519Identity(f.Devices[index].Age)
	must(e)
	r, e := age.Decrypt(bytes.NewReader(s.Envelope), id)
	if e != nil {
		if shouldDecrypt {
			panic("oracle decryption failed")
		}
		emit(map[string]any{"decrypted": false})
		return
	}
	if !shouldDecrypt {
		panic("retired identity decrypted new ciphertext")
	}
	key, e := io.ReadAll(io.LimitReader(r, 33))
	must(e)
	defer clear(key)
	if len(key) != 32 {
		panic("unexpected key size")
	}
	var sig kdbx.Signature
	must(binary.Read(bytes.NewReader(s.Database), binary.LittleEndian, &sig))
	if sig != kdbx.DefaultKDBX41Sig {
		panic("unexpected database format")
	}
	db := kdbx.NewDatabase()
	db.Credentials, e = kdbx.NewKeyDataCredentials(key)
	must(e)
	must(kdbx.NewDecoder(bytes.NewReader(s.Database)).Decode(db))
	must(db.UnlockProtectedEntries())
	want := itemsFor(f, variant)[0]
	found := false
	for _, g := range db.Content.Root.Groups {
		for _, entry := range g.Entries {
			if entry.GetContent("Locklark.ID") == want.ID {
				if found || entry.GetContent("Password") != want.Password || entry.GetContent("UserName") != want.Username || entry.GetContent("Notes") != want.Notes {
					panic("oracle plaintext mismatch")
				}
				found = true
			}
		}
	}
	if !found {
		panic("oracle missing login")
	}
	emit(map[string]any{"decrypted": true, "content_matches": true, "kdbx41": true})
}

func emit(v any) { must(json.NewEncoder(os.Stdout).Encode(v)) }

// The transport entry point lives in transport.go once the product API is
// agreed. Keeping this switch explicit prevents fixture setup from masquerading
// as an implementation of the network protocol.
var transportCommand func(string, []string) bool

func main() {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "fixture: operation failed")
			os.Exit(1)
		}
	}()
	if len(os.Args) < 2 {
		panic("command required")
	}
	command := os.Args[1]
	if transportCommand != nil && transportCommand(command, os.Args[2:]) {
		return
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "private fixture directory")
	view := flags.String("view", "", "verified view file")
	kind := flags.String("kind", "", "candidate type")
	variant := flags.String("variant", "initial", "expected synthetic variant")
	out := flags.String("out", "", "private publication file")
	index := flags.Int("device", 0, "device index")
	decrypt := flags.Bool("decrypt", true, "expected age decryption outcome")
	must(flags.Parse(os.Args[2:]))
	if flags.NArg() != 0 || *root == "" {
		panic("arguments required")
	}
	switch command {
	case "init":
		fixtureInit(*root)
	case "prepare":
		fixturePrepare(*root, *view, *kind, *variant, *out)
	case "oracle":
		fixtureOracle(*root, *view, *variant, *index, *decrypt)
	default:
		must(errors.New("unknown fixture command"))
	}
}
