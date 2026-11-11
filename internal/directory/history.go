package directory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"

	"github.com/jihuayu/locklark/internal/vault"
)

// History is signed public transition evidence and the encrypted head snapshot.
// It is not a freshness statement and never contains plaintext items.
type History struct {
	Receipts []Receipt      `json:"receipts"`
	Snapshot vault.Snapshot `json:"snapshot"`
}

const MaxHistoryBytes = 32 << 20

type historyVerifier struct {
	config          *Config
	anchor, current Checkpoint
	matched         bool
	state           *evolution
	head            Receipt
}

func newHistoryVerifier(c *Config, anchor Checkpoint) (*historyVerifier, error) {
	if !c.validCheckpoint(anchor) {
		return nil, ErrInvalid
	}
	genesis := c.Genesis()
	return &historyVerifier{config: c, anchor: anchor, current: genesis, matched: anchor == genesis, state: newEvolution()}, nil
}

// This reducer is shared by trusted local reload and untrusted remote history.
// A valid individual signature never substitutes for transition authorization.
func (v *historyVerifier) advance(r Receipt) error {
	if chainAdvanceObserver != nil {
		chainAdvanceObserver()
	}
	if v.current.Version >= maxVersions || v.config.verifyReceipt(r) != nil || r.Proposal.Parent != v.current || v.config.verifyTransition(v.state, r.Proposal) != nil || v.state.advance(r.Proposal) != nil {
		return ErrInvalid
	}
	v.current = r.Checkpoint()
	v.matched = v.matched || v.current == v.anchor
	v.head = r
	return nil
}
func (v *historyVerifier) finish(snapshot vault.Snapshot) (View, error) {
	if v.current.Version == 0 || !v.matched || v.config.verifySnapshot(v.head.Proposal, snapshot) != nil {
		return View{}, ErrInvalid
	}
	signer, e := v.config.snapshotSigner(v.head.Proposal)
	if e != nil {
		return View{}, ErrInvalid
	}
	return View{Receipt: v.head, Snapshot: snapshot, SnapshotSigner: signer}, nil
}

func (h History) valid() bool { return len(h.Receipts) > 0 && len(h.Receipts) <= maxVersions }

// storageSize counts the stored JSON bytes a verified history would occupy.
// Protocol fields are plain ASCII, so their encoding never grows past these
// bounds; a forged value that could still verify is always within limits.
func (h History) storageSize() (int, error) {
	size := historyBudgetBase
	for n, r := range h.Receipts {
		raw := encoded(r)
		if len(raw) > maxRecord {
			return 0, ErrInvalid
		}
		size += len(raw)
		if n > 0 {
			size++
		}
		if size > MaxHistoryBytes {
			return 0, ErrCapacity
		}
	}
	if size+len(encoded(h.Snapshot)) > MaxHistoryBytes {
		return 0, ErrCapacity
	}
	return size, nil
}

// historyBudgetBase is every byte of the stored History JSON except the
// receipts and the one head snapshot.
const historyBudgetBase = len(`{"receipts":[`) + len(`],"snapshot":`) + 1

// retainedHistorySize projects the stored serialized History a commit against
// budget would leave behind: every stored receipt, the new receipt and the one
// current head snapshot, framed exactly like History.storageSize (canonical
// receipt bytes, end-of-receipt separators, canonical snapshot bytes and JSON
// framing). The database keeps no historic snapshot, so none is counted.
// Production passes MaxHistoryBytes; only package tests pass a smaller budget.
func retainedHistorySize(retained []Receipt, receipt Receipt, snapshot vault.Snapshot, budget int) (int, error) {
	size := historyBudgetBase
	for n, r := range append(retained, receipt) {
		raw := encoded(r)
		if len(raw) > maxRecord {
			return 0, ErrInvalid
		}
		size += len(raw)
		if n > 0 {
			size++
		}
		if size > budget {
			return 0, ErrCapacity
		}
	}
	raw := encoded(snapshot)
	if len(raw) > 12<<20 {
		return 0, ErrInvalid
	}
	if size+len(raw) > budget {
		return 0, ErrCapacity
	}
	return size + len(raw), nil
}

func VerifyHistory(c *Config, anchor Checkpoint, h History) (View, error) {
	view, _, e := verifyHistory(c, anchor, h)
	return view, e
}

// AssembleHistory verifies an untrusted history and requires it to be exactly
// the history retained by a database read that produced the expected head, so
// a tampered receipt cannot be mistaken for the trusted checkpoint.
func AssembleHistory(c *Config, anchor, expected Checkpoint, h History) (View, error) {
	if expected == (Checkpoint{}) {
		return View{}, ErrInvalid
	}
	view, _, e := verifyHistory(c, anchor, h)
	if e != nil {
		return View{}, e
	}
	if view.Receipt.Checkpoint() != expected {
		return View{}, ErrInvalid
	}
	return view, nil
}

func verifyHistory(c *Config, anchor Checkpoint, h History) (View, int, error) {
	v, e := newHistoryVerifier(c, anchor)
	if e != nil || !h.valid() {
		return View{}, 0, ErrInvalid
	}
	for _, r := range h.Receipts {
		if v.advance(r) != nil {
			return View{}, 0, ErrInvalid
		}
	}
	size, e := h.storageSize()
	if e != nil {
		return View{}, 0, e
	}
	out, e := v.finish(h.Snapshot)
	if e != nil {
		return View{}, 0, e
	}
	// Do not lend caller-owned mutable proof or ciphertext buffers to consumers.
	var owned View
	if json.Unmarshal(encoded(out), &owned) != nil {
		return View{}, 0, ErrInvalid
	}
	return owned, size, nil
}

// ReadHistory returns the trusted local view together with the exact signed
// transition history behind it. It opens the database once and verifies the
// chain once; the returned history satisfies VerifyHistory(anchor).
func ReadHistory(path string, c *Config, anchor Checkpoint) (View, History, error) {
	res, e := readStore(path, c, anchor, &readRequest{proof: anchor})
	if e != nil {
		return View{}, History{}, e
	}
	h, e := res.trusted.History()
	if e != nil {
		return View{}, History{}, e
	}
	return res.view, h, nil
}

// TrustedRead is the evidence one completed database read produced for the
// team sync handler: the trusted head, every canonical receipt advanced
// exactly once from the persistent anchor this read was authorized against,
// and the head snapshot. It is sealed instead of public: every field is
// private, only ReadTrusted fills it, and the zero value is refused. It is not
// an untrusted history: VerifyHistory and AssembleHistory continue to verify
// externally supplied evidence in full.
type TrustedRead struct {
	valid    bool
	head     Receipt
	receipts []Receipt
	snapshot vault.Snapshot
	signer   ed25519.PublicKey
	proof    Checkpoint // The one anchor this pass proved, genesis included.
}

// ReadTrusted opens the trusted local directory once and verifies the whole
// chain once, requiring the persistent rollback anchor persisted and the
// request's detached proof anchor q.Proof.Anchor to both lie on that chain.
func ReadTrusted(path string, c *Config, persisted, requested Checkpoint) (TrustedRead, error) {
	if c == nil {
		return TrustedRead{}, ErrInvalid
	}
	res, e := readStore(path, c, persisted, &readRequest{proof: requested})
	if e != nil {
		return TrustedRead{}, e
	}
	return res.trusted, nil
}

// trusted reports whether a finished single pass produced this evidence:
// versioned receipts advance without a gap and the head is their last receipt.
func (t TrustedRead) trusted() bool {
	if !t.valid || len(t.receipts) == 0 || len(t.receipts) > maxVersions || t.head.Checkpoint() != t.receipts[len(t.receipts)-1].Checkpoint() {
		return false
	}
	for n, r := range t.receipts {
		if r.Proposal.Epoch != uint64(n)+1 || r.Proposal.Scope == "" || len(r.Signature) != ed25519.SignatureSize {
			return false
		}
	}
	return true
}

// Checkpoint is the verified head: the direct successor of the persisted
// anchor this read was authorized against.
func (t TrustedRead) Checkpoint() Checkpoint { return t.head.Checkpoint() }

// History returns an independent copy of every already-verified receipt and
// the verified head snapshot. It does not re-run the chain; the recomputed
// bytes must still fit the budget an export applies.
func (t TrustedRead) History() (History, error) {
	if !t.trusted() {
		return History{}, ErrInvalid
	}
	h := History{Receipts: cloneReceipts(t.receipts), Snapshot: cloneSnapshot(t.snapshot)}
	if _, e := h.storageSize(); e != nil {
		return History{}, e
	}
	return h, nil
}

// ProjectHistory returns the History a read of a directory whose head is the
// trusted head succeeded by receipt, carrying snapshot, would return: every
// receipt this pass already verified, receipt, and that one head snapshot.
// It runs no verification and this pass proved no such successor: it checks
// only what a commit of receipt would store (record size, version capacity and
// the retained History budget), so a caller can size the post-commit read
// before the commit exists. The copy is independent of the sealed evidence.
func (t TrustedRead) ProjectHistory(receipt Receipt, snapshot vault.Snapshot) (History, error) {
	if !t.trusted() || len(t.receipts)+1 > maxVersions {
		return History{}, ErrInvalid
	}
	if _, e := retainedHistorySize(t.receipts, receipt, snapshot, MaxHistoryBytes); e != nil {
		return History{}, e
	}
	h := History{Receipts: append(cloneReceipts(t.receipts), cloneReceipts([]Receipt{receipt})...), Snapshot: cloneSnapshot(snapshot)}
	if _, e := h.storageSize(); e != nil {
		return History{}, e
	}
	return h, nil
}

// chainAdvanceObserver is set only by package tests to count stored-chain
// advance steps; nil in production.
var chainAdvanceObserver func()

// HeadView is the view authorized at the trusted head. Every mutable field is
// an independent copy, so a caller can neither read nor alter sealed evidence.
func (t TrustedRead) HeadView() (View, error) {
	if !t.trusted() {
		return View{}, ErrInvalid
	}
	receipts := cloneReceipts([]Receipt{t.head})
	return View{Receipt: receipts[0], Snapshot: cloneSnapshot(t.snapshot), SnapshotSigner: bytes.Clone(t.signer)}, nil
}

// ProvenAnchorView is the view authorized at the request's proof anchor, which
// the same pass proved lies on the chain up to the trusted head. Unlike
// AssembleHistory it is not an ancestor-history membership check: the receipt
// is the head, and the permission it carries is the head's. It only selects
// the one proof anchor this read already verified; it never repeats a
// signature or transition check, and it returns an independent copy.
func (t TrustedRead) ProvenAnchorView(anchor Checkpoint) (View, error) {
	if anchor != t.proof {
		return View{}, ErrInvalid
	}
	return t.HeadView()
}

func (c *Config) WriterACLPolicy() bool              { return c.valid() && c.writerACL && c.requirePossession }
func (c *Config) ValidCheckpoint(cp Checkpoint) bool { return c.validCheckpoint(cp) }
func (c *Config) SequencerSigningKey() ed25519.PublicKey {
	if !c.valid() {
		return nil
	}
	return bytes.Clone(c.sequencer)
}
func (c *Config) OwnerSigningKey(id string) ed25519.PublicKey {
	if !c.valid() || !hexSize(id, 32) {
		return nil
	}
	return bytes.Clone(c.owners[id])
}
