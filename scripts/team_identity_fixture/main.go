// The fixture calls real native OS protection and the frozen teamclient API.
// Synthetic inputs arrive only over a private pipe; no private key is exported.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/jihuayu/locklark/internal/directory"
	"github.com/jihuayu/locklark/internal/osunlock"
	"github.com/jihuayu/locklark/internal/teamclient"
)

var refused = errors.New("fixture validation refused")

type input struct {
	ID            string                      `json:"id"`
	Value         []byte                      `json:"value"`
	Pins          directory.Pins              `json:"pins"`
	Descriptor    teamclient.DeviceDescriptor `json:"descriptor"`
	OwnerSeed     []byte                      `json:"owner_seed"`
	PublisherSeed []byte                      `json:"publisher_seed"`
	SequencerSeed []byte                      `json:"sequencer_seed"`
	Member        string                      `json:"member"`
	Output        string                      `json:"output"`
}

func randomID() (string, error) {
	raw := make([]byte, 16)
	if _, e := rand.Read(raw); e != nil {
		return "", e
	}
	return hex.EncodeToString(raw), nil
}

func writePublic(path string, value any) error {
	parent, e := os.Stat(filepath.Dir(path))
	if !filepath.IsAbs(path) || e != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return refused
	}
	raw, e := json.Marshal(value)
	if e != nil {
		return refused
	}
	file, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return refused
	}
	_, written := file.Write(raw)
	synced := file.Sync()
	closed := file.Close()
	if written != nil || synced != nil || closed != nil {
		return refused
	}
	return nil
}

func key(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, refused
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func run(mode string, in input) error {
	defer clear(in.Value)
	defer clear(in.OwnerSeed)
	defer clear(in.PublisherSeed)
	defer clear(in.SequencerSeed)
	store := osunlock.New()
	if mode == "pins" {
		owner, e := key(in.OwnerSeed)
		if e != nil {
			return e
		}
		defer clear(owner)
		publisher, e := key(in.PublisherSeed)
		if e != nil {
			return e
		}
		defer clear(publisher)
		sequencer, e := key(in.SequencerSeed)
		if e != nil {
			return e
		}
		defer clear(sequencer)
		team, e := randomID()
		if e != nil {
			return e
		}
		vault, e := randomID()
		if e != nil {
			return e
		}
		pins := directory.Pins{Team: team, Vault: vault, Owners: []string{hex.EncodeToString(owner.Public().(ed25519.PublicKey))}, Publisher: hex.EncodeToString(publisher.Public().(ed25519.PublicKey)), Sequencer: hex.EncodeToString(sequencer.Public().(ed25519.PublicKey))}
		if _, e := directory.NewConfigWithWriterACL(pins); e != nil {
			return refused
		}
		return writePublic(in.Output, pins)
	}
	if mode == "store" || mode == "load" || mode == "delete" || mode == "unavailable" {
		raw, e := hex.DecodeString(in.ID)
		if e != nil || len(raw) != 32 || hex.EncodeToString(raw) != in.ID || len(in.Value) == 0 || len(in.Value) > 2560 {
			return refused
		}
		switch mode {
		case "store":
			return store.Store(in.ID, in.Value)
		case "load":
			got, e := store.Load(in.ID)
			defer clear(got)
			if e != nil || subtle.ConstantTimeCompare(got, in.Value) != 1 {
				return refused
			}
			return nil
		case "delete":
			if e := store.Delete(in.ID); e != nil {
				return refused
			}
			got, e := store.Load(in.ID)
			defer clear(got)
			if !errors.Is(e, osunlock.ErrUnavailable) || len(got) != 0 {
				return refused
			}
			return nil
		case "unavailable":
			if !errors.Is(store.Store(in.ID, in.Value), osunlock.ErrUnavailable) {
				return refused
			}
			got, e := store.Load(in.ID)
			defer clear(got)
			if !errors.Is(e, osunlock.ErrUnavailable) || len(got) != 0 || !errors.Is(store.Delete(in.ID), osunlock.ErrUnavailable) {
				return refused
			}
			return nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if mode == "protect" || mode == "protect-unavailable" {
		plan, e := teamclient.PrepareDevice(in.Pins)
		if e != nil {
			return refused
		}
		defer plan.Close()
		before := plan.Descriptor()
		if before.State != teamclient.DevicePreparing || before.Role != "device" {
			return refused
		}
		d, e := plan.Protect(ctx, store)
		if mode == "protect-unavailable" {
			if !errors.Is(e, teamclient.ErrProtection) || d.State != teamclient.DeviceUnknown {
				return refused
			}
		} else if e != nil || d.State != teamclient.DevicePending {
			return refused
		}
		compare := d
		compare.State = teamclient.DevicePreparing
		if !reflect.DeepEqual(before, compare) {
			return refused
		}
		if _, e := plan.Protect(ctx, store); e == nil {
			return refused
		}
		return writePublic(in.Output, d)
	}
	if mode == "proof" || mode == "load-unavailable" || mode == "wrong-target" {
		op, e := teamclient.NewDeviceOperation(in.Pins, in.Descriptor)
		if e != nil {
			return refused
		}
		defer op.Close()
		e = op.Load(ctx, store)
		if mode == "load-unavailable" {
			if !errors.Is(e, teamclient.ErrProtection) {
				return refused
			}
			return nil
		}
		if e != nil {
			return refused
		}
		cfg, e := directory.NewConfigWithWriterACL(in.Pins)
		if e != nil {
			return refused
		}
		owner, e := key(in.OwnerSeed)
		if e != nil {
			return e
		}
		defer clear(owner)
		// This is a genuinely new synthetic scope, not a current-head lease or
		// an enrollment grant. The expected device/member comes from the test
		// controller, independently of the owner-generated challenge.
		expected := directory.Enrollment{Parent: cfg.Genesis(), Member: in.Member, Device: in.Descriptor.Device}
		challenge, e := directory.IssueChallenge(cfg, owner, expected)
		if e != nil {
			return refused
		}
		defer clear(challenge.Ciphertext)
		defer clear(challenge.Signature)
		if mode == "wrong-target" {
			changed := expected
			changed.Member, e = randomID()
			if e != nil {
				return e
			}
			if _, e = op.AnswerChallenge(changed, challenge); e == nil {
				return refused
			}
			if _, e = op.AnswerChallenge(expected, challenge); e == nil {
				return refused
			}
			return nil
		}
		proof, e := op.AnswerChallenge(expected, challenge)
		defer clear(proof.Nonce)
		defer clear(proof.Signature)
		if e != nil || directory.VerifyAdmission(cfg, expected, proof) != nil {
			return refused
		}
		if _, e = op.AnswerChallenge(expected, challenge); e == nil {
			return refused
		}
		return nil
	}
	return refused
}

func main() {
	good := false
	if len(os.Args) == 2 {
		raw, e := io.ReadAll(io.LimitReader(os.Stdin, (16<<10)+1))
		if e == nil && len(raw) <= 16<<10 {
			var in input
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&in) == nil {
				var extra any
				if decoder.Decode(&extra) == io.EOF {
					good = run(os.Args[1], in) == nil
				}
			}
		}
		clear(raw)
	}
	if !good {
		fmt.Println("FAIL: team identity fixture")
		os.Exit(1)
	}
	fmt.Println("PASS: team identity fixture")
}
