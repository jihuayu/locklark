// Command passkey_transfer_fixture is an explicitly selected acceptance
// executable for the passkey transfer CLI. It creates two synthetic local
// vaults and one real passkey credential through public personal Session APIs,
// then verifies an imported assertion against the source creation public key.
//
// It never prints a password, Secret Key, seed, private key, signature, raw
// invitation, raw packet or raw credential record. Factors are read from a
// private stdin pipe supplied by the acceptance harness; they are never accepted
// from argv or the environment and are never written to a file.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
)

const (
	maxFixtureRequestBytes = 64 << 10
	createChallenge        = "Y2hhbGxlbmdlLTAxMjM0NTY3ODk"
	createOptions          = `{"challenge":"` + createChallenge + `","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"passkey-fixture-user","displayName":"Fixture"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`
	transferInviteAction   = "vault.passkey.transfer.invite"
	transferExportAction   = "vault.passkey.transfer.export"
	transferConsumeAction  = "vault.passkey.transfer.consume"
)

var errFixtureRefused = errors.New("fixture refused")

func main() {
	if err := run(); err != nil {
		// Fixed output only. No path, factor, record, packet or signature is
		// ever included in a fixture error.
		fmt.Fprintln(os.Stderr, "passkey transfer fixture failed")
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		return errFixtureRefused
	}
	switch os.Args[1] {
	case "setup":
		if len(os.Args) != 3 {
			return errFixtureRefused
		}
		return setup(os.Args[2])
	case "verify":
		if len(os.Args) != 2 {
			return errFixtureRefused
		}
		return verify()
	case "state":
		if len(os.Args) != 2 {
			return errFixtureRefused
		}
		return state()
	default:
		return errFixtureRefused
	}
}

// readRequest strictly decodes one bounded JSON object from the private stdin
// pipe. The raw bytes are cleared before returning.
func readRequest[T any]() (value T, err error) {
	raw, readErr := io.ReadAll(io.LimitReader(os.Stdin, maxFixtureRequestBytes+1))
	if readErr != nil || len(raw) == 0 || len(raw) > maxFixtureRequestBytes {
		clear(raw)
		return value, errFixtureRefused
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		var zero T
		return zero, errFixtureRefused
	}
	if decoder.Decode(new(any)) != io.EOF {
		var zero T
		return zero, errFixtureRefused
	}
	return value, nil
}

type factors struct {
	SourcePassword   string `json:"source_password"`
	SourceKey        string `json:"source_key"`
	ReceiverPassword string `json:"receiver_password"`
	ReceiverKey      string `json:"receiver_key"`
}

func parseSecret(text string) ([]byte, error) {
	key, err := personal.ParseSecret(text)
	if err != nil {
		return nil, errFixtureRefused
	}
	return key, nil
}

func newRequestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", errFixtureRefused
	}
	return hex.EncodeToString(raw), nil
}

func rowRevision(rows []personal.Row, id string) string {
	for _, row := range rows {
		if row.ID == id {
			return row.Revision
		}
	}
	return ""
}

func rowTitle(rows []personal.Row, id string) string {
	for _, row := range rows {
		if row.ID == id {
			return row.Title
		}
	}
	return ""
}

func credentialRevision(metadata map[string][]personal.ManagedPasskeyMetadata, itemID, credentialID string) string {
	for _, credential := range metadata[itemID] {
		if credential.CredentialID == credentialID {
			return credential.Revision
		}
	}
	return ""
}

func hasCredential(metadata map[string][]personal.ManagedPasskeyMetadata, itemID, credentialID string) bool {
	for _, credential := range metadata[itemID] {
		if credential.CredentialID == credentialID {
			return true
		}
	}
	return false
}

type setupRecord struct {
	SourcePath        string `json:"source_path"`
	ReceiverPath      string `json:"receiver_path"`
	ItemID            string `json:"item_id"`
	ParentRevision    string `json:"parent_revision"`
	CredentialID      string `json:"credential_id"`
	ChildRevision     string `json:"child_revision"`
	CreationPublicKey string `json:"creation_public_key"`
}

func setup(root string) error {
	if privateRoot(root) != nil {
		return errFixtureRefused
	}
	input, err := readRequest[factors]()
	if err != nil {
		return err
	}
	sourceKey, err := parseSecret(input.SourceKey)
	if err != nil {
		return err
	}
	defer clear(sourceKey)
	receiverKey, err := parseSecret(input.ReceiverKey)
	if err != nil {
		return err
	}
	defer clear(receiverKey)

	sourcePath := filepath.Join(root, "source.ll")
	receiverPath := filepath.Join(root, "receiver.ll")
	for _, path := range []string{sourcePath, receiverPath} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			return errFixtureRefused
		}
	}
	if personal.Create(receiverPath, input.ReceiverPassword, receiverKey) != nil {
		return errFixtureRefused
	}
	if personal.Create(sourcePath, input.SourcePassword, sourceKey) != nil {
		return errFixtureRefused
	}

	session, err := personal.UnlockSession(sourcePath, []byte(input.SourcePassword), sourceKey, time.Minute)
	if err != nil {
		return errFixtureRefused
	}
	itemID, addErr := session.AddLogin("Source Login", "source-user", "source-password")
	if addErr != nil {
		session.Lock()
		return errFixtureRefused
	}
	rows, listErr := session.List("active")
	if listErr != nil {
		session.Lock()
		return errFixtureRefused
	}
	revision := rowRevision(rows, itemID)
	revision, editErr := session.Edit(personal.Edit{ID: itemID, Revision: revision, Field: "url", Value: "https://example.test/login"})
	if editErr != nil {
		session.Lock()
		return errFixtureRefused
	}
	requestID, idErr := newRequestID()
	if idErr != nil {
		session.Lock()
		return idErr
	}
	target := personal.PasskeyTarget{
		Context:  personal.BrowserContext{RequestID: requestID, Origin: "https://example.test", TabID: 1, DocumentID: "document-source"},
		Create:   true,
		ID:       itemID,
		Revision: revision,
		Options:  []byte(createOptions),
	}
	gate := personal.NewMutationGate(time.Now().Add(30 * time.Second))
	if session.RegisterMutation(gate) != nil {
		session.Lock()
		return errFixtureRefused
	}
	response, passkeyErr := session.PerformPasskey(target, false, gate)
	if passkeyErr != nil {
		session.Lock()
		return errFixtureRefused
	}
	credentialID := response.ID
	creationPublicKey := response.Response.PublicKey
	if credentialID == "" || creationPublicKey == "" {
		session.Lock()
		return errFixtureRefused
	}
	rows, listErr = session.List("active")
	if listErr != nil {
		session.Lock()
		return errFixtureRefused
	}
	parentRevision := rowRevision(rows, itemID)
	metadata, metadataErr := session.ReadManagedPasskeysMetadata(false)
	if metadataErr != nil {
		session.Lock()
		return errFixtureRefused
	}
	childRevision := credentialRevision(metadata, itemID, credentialID)
	session.Lock()
	if parentRevision == "" || childRevision == "" {
		return errFixtureRefused
	}

	record := setupRecord{
		SourcePath:        sourcePath,
		ReceiverPath:      receiverPath,
		ItemID:            itemID,
		ParentRevision:    parentRevision,
		CredentialID:      credentialID,
		ChildRevision:     childRevision,
		CreationPublicKey: creationPublicKey,
	}
	return json.NewEncoder(os.Stdout).Encode(record)
}

type verifyRequest struct {
	SourcePath            string `json:"source_path"`
	ReceiverPath          string `json:"receiver_path"`
	SourcePassword        string `json:"source_password"`
	SourceKey             string `json:"source_key"`
	ReceiverPassword      string `json:"receiver_password"`
	ReceiverKey           string `json:"receiver_key"`
	ItemID                string `json:"item_id"`
	ParentRevision        string `json:"parent_revision"`
	CredentialID          string `json:"credential_id"`
	ChildRevision         string `json:"child_revision"`
	CreationPublicKey     string `json:"creation_public_key"`
	ImportedID            string `json:"imported_id"`
	ImportedRevision      string `json:"imported_revision"`
	ExpectedImportedTitle string `json:"expected_imported_title"`
}

type verifyResult struct {
	SourceAvailable   bool `json:"source_available"`
	SourceFrozen      bool `json:"source_frozen"`
	CredentialPresent bool `json:"credential_present"`
	TitleMatches      bool `json:"title_matches"`
	IdentityMatches   bool `json:"identity_matches"`
	AssertionVerified bool `json:"assertion_verified"`
}

func verify() error {
	request, err := readRequest[verifyRequest]()
	if err != nil {
		return err
	}
	sourceKey, err := parseSecret(request.SourceKey)
	if err != nil {
		return err
	}
	defer clear(sourceKey)
	receiverKey, err := parseSecret(request.ReceiverKey)
	if err != nil {
		return err
	}
	defer clear(receiverKey)

	result := verifyResult{}
	source, sourceErr := personal.UnlockSession(request.SourcePath, []byte(request.SourcePassword), sourceKey, time.Minute)
	if sourceErr != nil {
		return errFixtureRefused
	}
	sourceRows, listErr := source.List("active")
	if listErr != nil {
		source.Lock()
		return errFixtureRefused
	}
	sourceRevision := rowRevision(sourceRows, request.ItemID)
	sourceMetadata, metadataErr := source.ReadManagedPasskeysMetadata(false)
	if metadataErr != nil {
		source.Lock()
		return errFixtureRefused
	}
	result.SourceAvailable = sourceRevision != ""
	result.SourceFrozen = sourceRevision == request.ParentRevision && credentialRevision(sourceMetadata, request.ItemID, request.CredentialID) == request.ChildRevision
	source.Lock()

	receiver, receiverErr := personal.UnlockSession(request.ReceiverPath, []byte(request.ReceiverPassword), receiverKey, time.Minute)
	if receiverErr != nil {
		return errFixtureRefused
	}
	receiverRows, listErr := receiver.List("active")
	if listErr != nil {
		receiver.Lock()
		return errFixtureRefused
	}
	receiverMetadata, metadataErr := receiver.ReadManagedPasskeysMetadata(false)
	if metadataErr != nil {
		receiver.Lock()
		return errFixtureRefused
	}
	result.CredentialPresent = hasCredential(receiverMetadata, request.ImportedID, request.CredentialID)
	result.TitleMatches = rowTitle(receiverRows, request.ImportedID) == request.ExpectedImportedTitle

	challengeRaw := make([]byte, 32)
	if _, randomErr := rand.Read(challengeRaw); randomErr != nil {
		receiver.Lock()
		return errFixtureRefused
	}
	options := []byte(`{"rpId":"example.test","challenge":"` + base64.RawURLEncoding.EncodeToString(challengeRaw) + `","allowCredentials":[{"type":"public-key","id":"` + request.CredentialID + `"}]}`)
	requestID, idErr := newRequestID()
	if idErr != nil {
		receiver.Lock()
		return idErr
	}
	target := personal.PasskeyTarget{
		Context:      personal.BrowserContext{RequestID: requestID, Origin: "https://example.test", TabID: 7, DocumentID: "document-receiver"},
		ID:           request.ImportedID,
		Revision:     request.ImportedRevision,
		CredentialID: request.CredentialID,
		Options:      options,
	}
	gate := personal.NewMutationGate(time.Now().Add(30 * time.Second))
	if receiver.RegisterMutation(gate) != nil {
		receiver.Lock()
		return errFixtureRefused
	}
	response, passkeyErr := receiver.PerformPasskey(target, false, gate)
	receiver.Lock()
	if passkeyErr != nil {
		return errFixtureRefused
	}
	result.IdentityMatches = response.ID == request.CredentialID
	result.AssertionVerified = verifyAssertion(request.CreationPublicKey, response)

	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		return errFixtureRefused
	}
	if !result.SourceAvailable || !result.SourceFrozen || !result.CredentialPresent || !result.TitleMatches || !result.IdentityMatches || !result.AssertionVerified {
		return errFixtureRefused
	}
	return nil
}

// verifyAssertion checks the imported credential's real ECDSA assertion against
// the public key returned by the source creation. No signature byte is printed.
func verifyAssertion(creationPublicKey string, response passkey.Response) bool {
	publicRaw, err := base64.RawURLEncoding.Strict().DecodeString(creationPublicKey)
	if err != nil {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(publicRaw)
	if err != nil {
		return false
	}
	public, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	authData, err := base64.RawURLEncoding.Strict().DecodeString(response.Response.AuthenticatorData)
	if err != nil {
		return false
	}
	clientData, err := base64.RawURLEncoding.Strict().DecodeString(response.Response.ClientDataJSON)
	if err != nil {
		return false
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(response.Response.Signature)
	if err != nil {
		return false
	}
	clientHash := sha256.Sum256(clientData)
	signed := make([]byte, 0, len(authData)+len(clientHash))
	signed = append(signed, authData...)
	signed = append(signed, clientHash[:]...)
	digest := sha256.Sum256(signed)
	return ecdsa.VerifyASN1(public, digest[:], signature)
}

type stateRequest struct {
	SourcePath       string `json:"source_path"`
	ReceiverPath     string `json:"receiver_path"`
	SourcePassword   string `json:"source_password"`
	SourceKey        string `json:"source_key"`
	ReceiverPassword string `json:"receiver_password"`
	ReceiverKey      string `json:"receiver_key"`
}

type stateResult struct {
	SourceItems         int `json:"source_items"`
	SourceCredentials   int `json:"source_credentials"`
	ReceiverItems       int `json:"receiver_items"`
	ReceiverCredentials int `json:"receiver_credentials"`
	InviteEvents        int `json:"invite_events"`
	ExportEvents        int `json:"export_events"`
	ConsumeEvents       int `json:"consume_events"`
}

func actionCount(events []personal.Event, action string) int {
	count := 0
	for _, event := range events {
		if event.Action == action {
			count++
		}
	}
	return count
}

func state() error {
	request, err := readRequest[stateRequest]()
	if err != nil {
		return err
	}
	sourceKey, err := parseSecret(request.SourceKey)
	if err != nil {
		return err
	}
	defer clear(sourceKey)
	receiverKey, err := parseSecret(request.ReceiverKey)
	if err != nil {
		return err
	}
	defer clear(receiverKey)

	result := stateResult{}
	source, sourceErr := personal.UnlockSession(request.SourcePath, []byte(request.SourcePassword), sourceKey, time.Minute)
	if sourceErr != nil {
		return errFixtureRefused
	}
	sourceRows, listErr := source.List("active")
	if listErr != nil {
		source.Lock()
		return errFixtureRefused
	}
	sourceMetadata, metadataErr := source.ReadManagedPasskeysMetadata(false)
	if metadataErr != nil {
		source.Lock()
		return errFixtureRefused
	}
	sourceEvents, auditErr := source.Audit()
	if auditErr != nil {
		source.Lock()
		return errFixtureRefused
	}
	result.SourceItems = len(sourceRows)
	for _, credentials := range sourceMetadata {
		result.SourceCredentials += len(credentials)
	}
	result.ExportEvents = actionCount(sourceEvents, transferExportAction)
	source.Lock()

	receiver, receiverErr := personal.UnlockSession(request.ReceiverPath, []byte(request.ReceiverPassword), receiverKey, time.Minute)
	if receiverErr != nil {
		return errFixtureRefused
	}
	receiverRows, listErr := receiver.List("active")
	if listErr != nil {
		receiver.Lock()
		return errFixtureRefused
	}
	receiverMetadata, metadataErr := receiver.ReadManagedPasskeysMetadata(false)
	if metadataErr != nil {
		receiver.Lock()
		return errFixtureRefused
	}
	receiverEvents, auditErr := receiver.Audit()
	if auditErr != nil {
		receiver.Lock()
		return errFixtureRefused
	}
	result.ReceiverItems = len(receiverRows)
	for _, credentials := range receiverMetadata {
		result.ReceiverCredentials += len(credentials)
	}
	result.InviteEvents = actionCount(receiverEvents, transferInviteAction)
	result.ConsumeEvents = actionCount(receiverEvents, transferConsumeAction)
	receiver.Lock()

	return json.NewEncoder(os.Stdout).Encode(result)
}
