// Command locklark-vaultfile-inspect performs a read-only, caller-pinned
// policy and content-signature inspection of one sealed vault file. It never
// decrypts or authenticates the KDBX payload.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

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

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		os.Exit(1)
	}
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
	var wire checkpointWire
	if err := strictDecode(raw, &wire); err != nil {
		return nil, err
	}
	if wire.V != 1 || wire.VaultID == "" || wire.OwnerRootKeyID == "" {
		return nil, errors.New("checkpoint")
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

func decode32(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != value {
		clear(raw)
		return nil, errors.New("checkpoint")
	}
	return raw, nil
}

func strictDecode(raw []byte, dst *checkpointWire) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing")
	}
	return nil
}
