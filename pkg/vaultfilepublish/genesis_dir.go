package vaultfilepublish

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

var (
	// ErrGenesisUnknown means a local claim, remote read or local Ack did not
	// establish a final outcome. The original intent must be reopened and
	// reconciled; a claim or Ack error may hide a committed transaction.
	ErrGenesisUnknown = errors.New("vault file publish: genesis outcome unknown")
	// ErrGenesisReview means an authoritative read returned bytes or a revision
	// that cannot be accepted as this independently pinned, exact genesis.
	// The original intent remains for review; the remote is never removed.
	ErrGenesisReview = errors.New("vault file publish: genesis readback needs review")
)

// PublishGenesisDir publishes exactly the G already stored in a strict local
// IntentJournal through the configured Dir backend. The caller supplies the
// owner-root pin independently of G and the intent. This function does not
// create an intent, generate or export keys, or decide whether the caller has
// published a recoverable personal backup; those are producer prerequisites.
//
// The journal atomically claims at most one Create attempt for this intent,
// including across process restarts. A claimed intent only reads and resolves;
// even if the process died between claim and Create, it cannot try Create
// again. This can leave an unpublished G Unknown until separate review.
// A Create response alone never causes Ack: an authoritative Dir read must
// return the exact G, a bounded nonempty revision, and a G that verifies
// under the independent pin. A conflicting name containing this exact G may
// be acknowledged after that
// read. A foreign name is left untouched. An unavailable read or any Ack
// error is unknown, never evidence that a write or Ack did not commit.
func PublishGenesisDir(ctx context.Context, dir *vaultfilebackend.Dir, journal *vaultfilejournal.IntentJournal, pin *vaultfile.GenesisRootPin) error {
	return publishGenesisDirWith(ctx, dir, journal, pin, nil)
}

// afterCreate is a private test seam after the real Dir call. It cannot skip
// Create, change G, or authorize a readback; the exported path always passes nil.
func publishGenesisDirWith(ctx context.Context, dir *vaultfilebackend.Dir, journal *vaultfilejournal.IntentJournal, pin *vaultfile.GenesisRootPin, afterCreate func(error)) error {
	if ctx == nil || dir == nil || journal == nil || pin == nil {
		return ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	intent, err := journal.Load()
	if err != nil {
		return err
	}
	// Copy the public pin before using it for the original G and later remote
	// readback. Neither the journal's metadata nor G may supply root authority.
	rootPin := *pin
	rootPin.OwnerRootPublicKey = bytes.Clone(pin.OwnerRootPublicKey)
	if err := verifyGenesisIntentBytes(intent, intent.SealedBytes, &rootPin); err != nil {
		return fmt.Errorf("%w: %w", ErrVerification, err)
	}

	claim, err := journal.ClaimGenesisAttempt(intent)
	if err != nil {
		// A Bolt error can hide a committed marker. No Create is safe in this
		// invocation; reopening may only inspect and resolve its durable state.
		return fmt.Errorf("%w: local claim: %w", ErrGenesisUnknown, err)
	}
	switch claim {
	case vaultfilejournal.GenesisAttemptNewlyClaimed:
		writeErr := dir.CreateIfAbsent(ctx, intent.Name, intent.SealedBytes)
		if afterCreate != nil {
			afterCreate(writeErr)
		}
	case vaultfilejournal.GenesisAttemptPreviouslyClaimed:
		// Never retry Create, even when the name is now missing.
	default:
		return ErrGenesisUnknown
	}
	// ReadPulled validates the backend's exact version pair before returning
	// copies. The verifier reauthenticates the actual readback and compares it
	// with the durable proposal; it never accepts a callback-supplied pin.
	pulled, err := ReadPulled(ctx, dir, intent.Name, func(_ context.Context, data []byte, _ vaultfilebackend.Revision) error {
		if err := verifyGenesisIntentBytes(intent, data, &rootPin); err != nil {
			return err
		}
		if !bytes.Equal(data, intent.SealedBytes) {
			return vaultfilejournal.ErrGenesisMismatch
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrVerification) {
			return fmt.Errorf("%w: %w", ErrGenesisReview, err)
		}
		return fmt.Errorf("%w: %w", ErrGenesisUnknown, err)
	}
	if err := journal.AckGenesis(intent, pulled.Bytes(), pulled.Revision()); err != nil {
		return fmt.Errorf("%w: local ack: %w", ErrGenesisUnknown, err)
	}
	return nil
}

func verifyGenesisIntentBytes(intent vaultfilejournal.GenesisIntent, encoded []byte, pin *vaultfile.GenesisRootPin) error {
	checkpoint, err := vaultfile.VerifyGenesis(encoded, pin)
	if err != nil {
		return err
	}
	if checkpoint.VaultID != intent.VaultID || checkpoint.OwnerRootKeyID != intent.OwnerRootKeyID ||
		!bytes.Equal(checkpoint.OwnerRootPublicKey, intent.OwnerRootPublicKey) ||
		checkpoint.PolicySeq != intent.PolicySeq ||
		!bytes.Equal(checkpoint.PolicyDigest, intent.PolicyDigest) {
		return vaultfilejournal.ErrGenesisMismatch
	}
	f, err := vaultfile.ParseFile(encoded)
	if err != nil {
		return err
	}
	if f.Header.OpID != intent.OperationID {
		return vaultfilejournal.ErrGenesisMismatch
	}
	return nil
}
