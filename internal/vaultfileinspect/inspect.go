// Command locklark-vaultfile-inspect performs a read-only, caller-pinned
// policy and content-signature inspection of one sealed vault file. It never
// decrypts or authenticates the KDBX payload.
package vaultfileinspect

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

const (
	schemaVersion = "vaultfile-inspect/v1"
	maxCheckpoint = 16 << 10
)

type checkpointWire struct {
	V                  int    `json:"v"`
	VaultID            string `json:"vault_id"`
	OwnerRootKeyID     string `json:"owner_root_key_id"`
	OwnerRootPublicKey string `json:"owner_root_public_key"`
	PolicySeq          uint64 `json:"policy_seq"`
	PolicyDigest       string `json:"policy_digest"`
}

type resultWire struct {
	Schema       string `json:"schema"`
	Result       string `json:"result"`
	Policy       string `json:"policy,omitempty"`
	Payload      string `json:"payload,omitempty"`
	Format       string `json:"format,omitempty"`
	Version      int    `json:"version,omitempty"`
	PolicySeq    uint64 `json:"policy_seq,omitempty"`
	ContentSeq   uint64 `json:"content_seq,omitempty"`
	RevisionID   string `json:"revision_id,omitempty"`
	FileDigest   string `json:"file_digest,omitempty"`
	PolicyProofs int    `json:"policy_proofs,omitempty"`
	DeviceSlots  int    `json:"device_slots,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Run executes the read-only vaultfile inspection command.
func Run(args []string, out io.Writer) error {
	return run(args, out)
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("locklark-vaultfile-inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("file", "", "sealed vault file")
	checkpointPath := fs.String("checkpoint", "", "caller-pinned checkpoint JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *filePath == "" || *checkpointPath == "" {
		return emitRefused(out, "usage")
	}

	checkpointRaw, err := readRegular(*checkpointPath, maxCheckpoint)
	if err != nil {
		return emitRefused(out, "checkpoint")
	}
	checkpoint, err := decodeCheckpoint(checkpointRaw)
	clear(checkpointRaw)
	if err != nil {
		return emitRefused(out, "checkpoint")
	}
	fileRaw, err := readRegular(*filePath, vaultfilebackend.MaxValueSize)
	if err != nil {
		return emitRefused(out, "input")
	}
	defer clear(fileRaw)

	f, err := vaultfile.ParseFile(fileRaw)
	if err != nil {
		return emitRefused(out, classifyVaultError(err))
	}
	if err := vaultfile.VerifyPolicyCheckpoint(f, checkpoint); err != nil {
		return emitRefused(out, classifyVaultError(err))
	}
	digest, err := vaultfile.FileDigest(f)
	if err != nil {
		return emitRefused(out, "invalid_file")
	}
	result := resultWire{
		Schema:       schemaVersion,
		Result:       "verified",
		Policy:       "verified",
		Payload:      "not_decrypted",
		Format:       f.Format,
		Version:      f.Version,
		PolicySeq:    f.Header.PolicySeq,
		ContentSeq:   f.Header.ContentSeq,
		RevisionID:   f.Header.RevisionID,
		FileDigest:   digest,
		PolicyProofs: len(f.SignedPolicyProofs),
		DeviceSlots:  len(f.VUKDeviceSlots),
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return err
	}
	return nil
}

func emitRefused(out io.Writer, code string) error {
	_ = json.NewEncoder(out).Encode(resultWire{Schema: schemaVersion, Result: "refused", Error: code})
	return errors.New("vaultfile inspection refused")
}

func classifyVaultError(err error) string {
	if e, ok := vaultfile.AsError(err); ok {
		switch e.Code {
		case vaultfile.CodePolicyCheckpointFailed:
			return "policy_checkpoint_failed"
		case vaultfile.CodeSignatureVerifyFailed:
			return "signature_verify_failed"
		}
	}
	return "invalid_file"
}

func decodeCheckpoint(raw []byte) (*vaultfile.PolicyCheckpoint, error) {
	wire, err := parseCheckpointWire(raw)
	if err != nil {
		return nil, err
	}
	publicKey, err := decode32(wire.OwnerRootPublicKey)
	if err != nil {
		return nil, err
	}
	digest, err := decode32(wire.PolicyDigest)
	if err != nil {
		clear(publicKey)
		return nil, err
	}
	return &vaultfile.PolicyCheckpoint{
		VaultID: wire.VaultID, OwnerRootKeyID: wire.OwnerRootKeyID,
		OwnerRootPublicKey: ed25519.PublicKey(publicKey),
		PolicySeq:          wire.PolicySeq, PolicyDigest: digest,
	}, nil
}

func parseCheckpointWire(raw []byte) (checkpointWire, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return checkpointWire{}, errors.New("checkpoint")
	}
	seen := map[string]bool{}
	var wire checkpointWire
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return checkpointWire{}, errors.New("checkpoint")
		}
		key, ok := tok.(string)
		if !ok || seen[key] {
			return checkpointWire{}, errors.New("checkpoint")
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return checkpointWire{}, errors.New("checkpoint")
		}
		switch key {
		case "v":
			if err := json.Unmarshal(value, &wire.V); err != nil || wire.V != 1 {
				return checkpointWire{}, errors.New("checkpoint")
			}
		case "vault_id":
			if err := json.Unmarshal(value, &wire.VaultID); err != nil || wire.VaultID == "" {
				return checkpointWire{}, errors.New("checkpoint")
			}
		case "owner_root_key_id":
			if err := json.Unmarshal(value, &wire.OwnerRootKeyID); err != nil || wire.OwnerRootKeyID == "" {
				return checkpointWire{}, errors.New("checkpoint")
			}
		case "owner_root_public_key":
			if err := json.Unmarshal(value, &wire.OwnerRootPublicKey); err != nil || wire.OwnerRootPublicKey == "" {
				return checkpointWire{}, errors.New("checkpoint")
			}
		case "policy_seq":
			if err := json.Unmarshal(value, &wire.PolicySeq); err != nil {
				return checkpointWire{}, errors.New("checkpoint")
			}
		case "policy_digest":
			if err := json.Unmarshal(value, &wire.PolicyDigest); err != nil || wire.PolicyDigest == "" {
				return checkpointWire{}, errors.New("checkpoint")
			}
		default:
			return checkpointWire{}, errors.New("checkpoint")
		}
	}
	tok, err = dec.Token()
	if err != nil || tok != json.Delim('}') || len(seen) != 6 {
		return checkpointWire{}, errors.New("checkpoint")
	}
	if _, err := dec.Token(); err != io.EOF {
		return checkpointWire{}, errors.New("checkpoint")
	}
	return wire, nil
}
func decode32(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != value {
		clear(raw)
		return nil, errors.New("checkpoint")
	}
	return raw, nil
}
