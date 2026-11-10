package main

// Passkey transfer CLI: owner-authorised invitation, listing, export, plan and
// import actions.
//
// Implemented here:
//
//	personal passkey-invite --file PATH --out NEW --ttl SECONDS
//	personal passkey-revoke --file PATH --invitation FILE
//	personal passkey-list   --file PATH
//	personal passkey-export --file PATH --invitation FILE --target-pin HEX64 --selection PRIVATE_JSON --out NEW_PACKET
//	personal passkey-plan   --file PATH --invitation FILE --packet FILE --source-pin HEX64
//	personal passkey-import --file PATH --invitation FILE --packet FILE --source-pin HEX64 --digest HEX64 --mapping PRIVATE_JSON
//
// The flow reuses the existing authenticated native session APIs; it never
// opens the vault database directly, never reads a raw credential record and
// never accepts a secret, key, pin or private selector from argv or the
// environment. Pins and the plan digest are public canonical lower-case hex64.
//
// The invitation and sealed packet are public transport material, but they are
// still read from and written to explicit owner-only files. They are never
// encoded to stdout. Every refusal returns a fixed message; no path, errno,
// factor, raw invitation, packet or audit value is echoed.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
)

const (
	// maxPasskeyTransferInvitationBytes mirrors the native codec bound for one
	// signed invitation. The CLI reads an invitation file only within it.
	maxPasskeyTransferInvitationBytes = 16 << 10

	// maxPasskeyTransferPacketBytes mirrors the native codec bound for one
	// signed encrypted packet.
	maxPasskeyTransferPacketBytes = 2 << 20

	// maxPasskeyTransferSelectionBytes bounds one private selector or mapping
	// document and matches the native plan budget.
	maxPasskeyTransferSelectionBytes = 192 << 10

	// maxPasskeyTransferExportTargets is the native per-packet credential and
	// per-plan group limit.
	maxPasskeyTransferExportTargets = 16

	// passkeyTransferInvitationTTLSeconds is the native upper bound (15 min).
	passkeyTransferInvitationTTLSeconds = 900
)

var (
	// errPasskeyTransferPublicationUnknown is the fixed public result when the
	// authenticated database mutation succeeded (or may have committed) but its
	// result could not be confirmed (file publication or receipt delivery). It
	// never carries raw bytes or a path and it never triggers an automatic
	// retry or deletion of an unrelated output.
	errPasskeyTransferPublicationUnknown = errors.New("passkey transfer result unknown; outcome was not confirmed; do not retry and reconcile the same operation")

	// errPasskeyTransferCancelled is the fixed refusal for a missing or
	// different hidden consent phrase.
	errPasskeyTransferCancelled = errors.New("passkey transfer action cancelled")

	// errPasskeyTransferSelectionRefused is the single fixed refusal for any
	// malformed selector document. It never echoes a key or value.
	errPasskeyTransferSelectionRefused = errors.New("passkey selection refused")

	// errPasskeyTransferMappingRefused is the single fixed refusal for any
	// malformed owner mapping document. It never echoes a key or value.
	errPasskeyTransferMappingRefused = errors.New("passkey mapping refused")
)

// passkeyTransferInviteReceipt is the public allowlist for `passkey-invite`.
type passkeyTransferInviteReceipt struct {
	Status       string    `json:"status"`
	InvitationID string    `json:"invitation_id"`
	Fingerprint  string    `json:"fingerprint"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// passkeyTransferRevokeReceipt is the public allowlist for `passkey-revoke`.
type passkeyTransferRevokeReceipt struct {
	Status string `json:"status"`
}

// passkeyTransferExportReceipt is the public allowlist for `passkey-export`.
type passkeyTransferExportReceipt struct {
	Status            string `json:"status"`
	PacketID          string `json:"packet_id"`
	SourceFingerprint string `json:"source_fingerprint"`
	TargetFingerprint string `json:"target_fingerprint"`
}

// passkeyTransferImportItem is one changed parent revision.
type passkeyTransferImportItem struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

// passkeyTransferImportReceipt is the public allowlist for `passkey-import`.
// It contains only the changed parent selectors and a status.
type passkeyTransferImportReceipt struct {
	Status string                      `json:"status"`
	Items  []passkeyTransferImportItem `json:"items"`
}

// passkeyTransferListCredential is one public managed-credential projection.
// It deliberately has no user handle, private key, record bytes or seed.
type passkeyTransferListCredential struct {
	CredentialID       string `json:"credential_id"`
	CredentialRevision string `json:"credential_revision"`
	RPID               string `json:"rp_id"`
	Name               string `json:"name"`
}

// passkeyTransferListItem is one active parent with its exact live revision.
type passkeyTransferListItem struct {
	ItemID      string                          `json:"item_id"`
	Revision    string                          `json:"revision"`
	Credentials []passkeyTransferListCredential `json:"credentials"`
}

// passkeyTransferInput holds every private input frozen before any factor or
// consent prompt. Selectors and mappings are parsed from the frozen bytes, not
// re-read from the filesystem.
type passkeyTransferInput struct {
	invitation []byte
	packet     []byte
	selection  []byte
	mapping    []byte
	targets    []personal.PasskeyTransferTarget
	mappings   []personal.PasskeyTransferMapping
}

func (in *passkeyTransferInput) clear() {
	if in == nil {
		return
	}
	clear(in.invitation)
	clear(in.packet)
	clear(in.selection)
	clear(in.mapping)
	in.invitation = nil
	in.packet = nil
	in.selection = nil
	in.mapping = nil
}

// isPasskeyTransferAction is the exact-action dispatch test used by runPersonal
// before its normal argument parser. It deliberately does not prefix-match.
func isPasskeyTransferAction(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "passkey-invite", "passkey-revoke", "passkey-list", "passkey-export", "passkey-plan", "passkey-import":
		return true
	}
	return false
}

// validPasskeyTransferHex64 accepts only a canonical lower-case 64-hex value.
func validPasskeyTransferHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}

// parsePasskeyTransferArgs strictly parses the accepted command shapes:
//
//	passkey-invite --file PATH --out NEW --ttl SECONDS
//	passkey-revoke --file PATH --invitation FILE
//	passkey-list   --file PATH
//	passkey-export --file PATH --invitation FILE --target-pin HEX64 --selection PRIVATE_JSON --out NEW_PACKET
//	passkey-plan   --file PATH --invitation FILE --packet FILE --source-pin HEX64
//	passkey-import --file PATH --invitation FILE --packet FILE --source-pin HEX64 --digest HEX64 --mapping PRIVATE_JSON
//
// Flags are exact (no foreign flag is accepted), empty values and duplicates
// are refused, and --ttl must be the canonical decimal spelling in [1, 900].
func parsePasskeyTransferArgs(args []string) (string, map[string]string, bool) {
	if len(args) < 3 || len(args)%2 != 1 {
		return "", nil, false
	}
	action := args[0]
	var allowed map[string]bool
	var expected int
	switch action {
	case "passkey-invite":
		allowed = map[string]bool{"--file": true, "--out": true, "--ttl": true}
		expected = 3
	case "passkey-revoke":
		allowed = map[string]bool{"--file": true, "--invitation": true}
		expected = 2
	case "passkey-list":
		allowed = map[string]bool{"--file": true}
		expected = 1
	case "passkey-export":
		allowed = map[string]bool{"--file": true, "--invitation": true, "--target-pin": true, "--selection": true, "--out": true}
		expected = 5
	case "passkey-plan":
		allowed = map[string]bool{"--file": true, "--invitation": true, "--packet": true, "--source-pin": true}
		expected = 4
	case "passkey-import":
		allowed = map[string]bool{"--file": true, "--invitation": true, "--packet": true, "--source-pin": true, "--digest": true, "--mapping": true}
		expected = 6
	default:
		return "", nil, false
	}
	opts := make(map[string]string, expected)
	for i := 1; i < len(args); i += 2 {
		key, value := args[i], args[i+1]
		if !allowed[key] || value == "" || opts[key] != "" {
			return "", nil, false
		}
		opts[key] = value
	}
	if len(opts) != expected || opts["--file"] == "" {
		return "", nil, false
	}
	switch action {
	case "passkey-invite":
		if opts["--out"] == "" || opts["--ttl"] == "" {
			return "", nil, false
		}
		seconds, err := strconv.Atoi(opts["--ttl"])
		if err != nil || seconds < 1 || seconds > passkeyTransferInvitationTTLSeconds || strconv.Itoa(seconds) != opts["--ttl"] {
			return "", nil, false
		}
	case "passkey-revoke":
		if opts["--invitation"] == "" {
			return "", nil, false
		}
	case "passkey-export":
		if opts["--invitation"] == "" || opts["--selection"] == "" || opts["--out"] == "" || !validPasskeyTransferHex64(opts["--target-pin"]) {
			return "", nil, false
		}
	case "passkey-plan":
		if opts["--invitation"] == "" || opts["--packet"] == "" || !validPasskeyTransferHex64(opts["--source-pin"]) {
			return "", nil, false
		}
	case "passkey-import":
		if opts["--invitation"] == "" || opts["--packet"] == "" || opts["--mapping"] == "" || !validPasskeyTransferHex64(opts["--source-pin"]) || !validPasskeyTransferHex64(opts["--digest"]) {
			return "", nil, false
		}
	}
	return action, opts, true
}

// validPasskeyTransferToken bounds an opaque item selector to printable ASCII.
func validPasskeyTransferToken(value string) bool {
	if len(value) == 0 || len(value) > 1024 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// validPasskeyTransferCredentialID requires canonical unpadded base64url, the
// same encoding the native passkey record uses.
func validPasskeyTransferCredentialID(value string) bool {
	if len(value) == 0 || len(value) > 1024 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) > 0 && base64.RawURLEncoding.EncodeToString(raw) == value
}

// validPasskeyTransferText bounds one plain-text mapping value.
func validPasskeyTransferText(value string, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > 1024 || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsAny(value, "\x00\r\n")
}

func passkeyTransferStringField(object map[string]json.RawMessage, key string) (string, bool) {
	raw, found := object[key]
	if !found {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || !utf8.ValidString(value) {
		return "", false
	}
	return value, true
}

// parsePasskeyTransferSelection strictly decodes the private selector document.
// It reuses the typed JSON shape scan (duplicate/ASCII-key/trailing/UTF-8/
// depth/node bounds) and additionally requires every object key to be the exact
// canonical tag, so case aliases are never bound by Go's case-folding decoder.
func parsePasskeyTransferSelection(raw []byte) ([]personal.PasskeyTransferTarget, error) {
	if len(raw) == 0 || len(raw) > maxPasskeyTransferSelectionBytes || !utf8.Valid(raw) || !strictTypedJSON(raw) {
		return nil, errPasskeyTransferSelectionRefused
	}
	var objects []map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&objects) != nil {
		return nil, errPasskeyTransferSelectionRefused
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return nil, errPasskeyTransferSelectionRefused
	}
	if len(objects) == 0 || len(objects) > maxPasskeyTransferExportTargets {
		return nil, errPasskeyTransferSelectionRefused
	}
	targets := make([]personal.PasskeyTransferTarget, 0, len(objects))
	for _, object := range objects {
		if len(object) != 4 {
			return nil, errPasskeyTransferSelectionRefused
		}
		values := make(map[string]string, 4)
		for key := range object {
			switch key {
			case "item_id", "revision", "credential_id", "credential_revision":
			default:
				return nil, errPasskeyTransferSelectionRefused
			}
			value, ok := passkeyTransferStringField(object, key)
			if !ok {
				return nil, errPasskeyTransferSelectionRefused
			}
			values[key] = value
		}
		if len(values) != 4 ||
			!validPasskeyTransferToken(values["item_id"]) ||
			!validPasskeyTransferHex64(values["revision"]) ||
			!validPasskeyTransferCredentialID(values["credential_id"]) ||
			!validPasskeyTransferHex64(values["credential_revision"]) {
			return nil, errPasskeyTransferSelectionRefused
		}
		targets = append(targets, personal.PasskeyTransferTarget{
			ItemID:             values["item_id"],
			Revision:           values["revision"],
			CredentialID:       values["credential_id"],
			CredentialRevision: values["credential_revision"],
		})
	}
	return targets, nil
}

// parsePasskeyTransferMappings strictly decodes the owner mapping document.
// Each array element must be exactly one of the two explicit shapes:
//
//	{"group_id":HEX64,"existing_target_id":TOKEN,"existing_revision":HEX64}
//	{"group_id":HEX64,"new_title":TEXT,"new_username":TEXT}
//
// Unknown, duplicate, case-aliased, mixed, nested, raw-credential or trailing
// members are refused. The native Apply transaction revalidates the same
// mapping against the freshly rebuilt plan and current revisions.
func parsePasskeyTransferMappings(raw []byte) ([]personal.PasskeyTransferMapping, error) {
	if len(raw) == 0 || len(raw) > maxPasskeyTransferSelectionBytes || !utf8.Valid(raw) || !strictTypedJSON(raw) {
		return nil, errPasskeyTransferMappingRefused
	}
	var objects []map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&objects) != nil {
		return nil, errPasskeyTransferMappingRefused
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return nil, errPasskeyTransferMappingRefused
	}
	if len(objects) == 0 || len(objects) > maxPasskeyTransferExportTargets {
		return nil, errPasskeyTransferMappingRefused
	}
	mappings := make([]personal.PasskeyTransferMapping, 0, len(objects))
	seenGroup := make(map[string]bool, len(objects))
	for _, object := range objects {
		groupID, ok := passkeyTransferStringField(object, "group_id")
		if !ok || !validPasskeyTransferHex64(groupID) || seenGroup[groupID] {
			return nil, errPasskeyTransferMappingRefused
		}
		seenGroup[groupID] = true
		_, hasExistingID := object["existing_target_id"]
		_, hasExistingRevision := object["existing_revision"]
		_, hasNewTitle := object["new_title"]
		_, hasNewUsername := object["new_username"]
		switch {
		case hasExistingID || hasExistingRevision:
			if len(object) != 3 || !hasExistingID || !hasExistingRevision || hasNewTitle || hasNewUsername {
				return nil, errPasskeyTransferMappingRefused
			}
			targetID, ok := passkeyTransferStringField(object, "existing_target_id")
			if !ok || !validPasskeyTransferToken(targetID) {
				return nil, errPasskeyTransferMappingRefused
			}
			revision, ok := passkeyTransferStringField(object, "existing_revision")
			if !ok || !validPasskeyTransferHex64(revision) {
				return nil, errPasskeyTransferMappingRefused
			}
			mappings = append(mappings, personal.PasskeyTransferMapping{GroupID: groupID, ExistingTargetID: targetID, ExistingRevision: revision})
		case hasNewTitle || hasNewUsername:
			if len(object) != 3 || !hasNewTitle || !hasNewUsername {
				return nil, errPasskeyTransferMappingRefused
			}
			title, ok := passkeyTransferStringField(object, "new_title")
			if !ok || !validPasskeyTransferText(title, false) {
				return nil, errPasskeyTransferMappingRefused
			}
			username, ok := passkeyTransferStringField(object, "new_username")
			if !ok || !validPasskeyTransferText(username, true) {
				return nil, errPasskeyTransferMappingRefused
			}
			mappings = append(mappings, personal.PasskeyTransferMapping{GroupID: groupID, NewTitle: title, NewUsername: username})
		default:
			return nil, errPasskeyTransferMappingRefused
		}
	}
	return mappings, nil
}

// preparePasskeyTransfer performs every path check and freezes every supplied
// private input before a terminal factor prompt or consent is shown. It never
// opens the vault database, so a refusal cannot have mutated anything.
func preparePasskeyTransfer(action string, opts map[string]string) (*passkeyTransferInput, error) {
	input := &passkeyTransferInput{}
	switch action {
	case "passkey-invite":
		// CheckNew is deliberately before consent and mutation. Distinct also
		// enforces absolute, clean paths and prevents the output from aliasing
		// the vault.
		if teamfiles.CheckNew(opts["--out"]) != nil || !teamfiles.Distinct(opts["--file"], opts["--out"]) {
			return nil, personalUsage
		}
	case "passkey-revoke":
		if !teamfiles.Distinct(opts["--file"], opts["--invitation"]) {
			return nil, personalUsage
		}
		raw, err := teamfiles.Read(opts["--invitation"], maxPasskeyTransferInvitationBytes, true)
		if err != nil {
			return nil, err
		}
		input.invitation = raw
	case "passkey-list":
		// Read-only listing has no output or input file to alias.
	case "passkey-export":
		if !teamfiles.Distinct(opts["--file"], opts["--invitation"], opts["--selection"], opts["--out"]) {
			return nil, personalUsage
		}
		if teamfiles.CheckNew(opts["--out"]) != nil {
			return nil, personalUsage
		}
		if err := input.readInvitationAndSelection(opts); err != nil {
			return nil, err
		}
	case "passkey-plan":
		if !teamfiles.Distinct(opts["--file"], opts["--invitation"], opts["--packet"]) {
			return nil, personalUsage
		}
		if err := input.readInvitationAndPacket(opts); err != nil {
			return nil, err
		}
	case "passkey-import":
		if !teamfiles.Distinct(opts["--file"], opts["--invitation"], opts["--packet"], opts["--mapping"]) {
			return nil, personalUsage
		}
		if err := input.readInvitationAndPacket(opts); err != nil {
			return nil, err
		}
		mapping, err := teamfiles.Read(opts["--mapping"], maxPasskeyTransferSelectionBytes, true)
		if err != nil {
			input.clear()
			return nil, err
		}
		input.mapping = mapping
		mappings, err := parsePasskeyTransferMappings(mapping)
		if err != nil {
			input.clear()
			return nil, err
		}
		input.mappings = mappings
	default:
		return nil, personalUsage
	}
	return input, nil
}

func (in *passkeyTransferInput) readInvitationAndPacket(opts map[string]string) error {
	invitation, err := teamfiles.Read(opts["--invitation"], maxPasskeyTransferInvitationBytes, true)
	if err != nil {
		return err
	}
	in.invitation = invitation
	packet, err := teamfiles.Read(opts["--packet"], maxPasskeyTransferPacketBytes, true)
	if err != nil {
		in.clear()
		return err
	}
	in.packet = packet
	return nil
}

func (in *passkeyTransferInput) readInvitationAndSelection(opts map[string]string) error {
	invitation, err := teamfiles.Read(opts["--invitation"], maxPasskeyTransferInvitationBytes, true)
	if err != nil {
		return err
	}
	in.invitation = invitation
	selection, err := teamfiles.Read(opts["--selection"], maxPasskeyTransferSelectionBytes, true)
	if err != nil {
		in.clear()
		return err
	}
	in.selection = selection
	targets, err := parsePasskeyTransferSelection(selection)
	if err != nil {
		in.clear()
		return err
	}
	in.targets = targets
	return nil
}

// executePasskeyTransferAction is the UI-free execution core shared by the real
// terminal wrapper and the native session tests. ask must read the hidden
// consent phrase without echoing it; prompt receives only the fixed public
// summary. No factor, raw invitation, packet, record or raw audit value is
// written to out.
func executePasskeyTransferAction(action string, opts map[string]string, input *passkeyTransferInput, out io.Writer, pw, key []byte, ask func(string) ([]byte, error), prompt io.Writer) error {
	session, err := personal.UnlockSession(opts["--file"], pw, key, time.Minute)
	if err != nil {
		return err
	}
	defer session.Lock()
	if input == nil {
		input = &passkeyTransferInput{}
	}

	switch action {
	case "passkey-invite":
		seconds, _ := strconv.Atoi(opts["--ttl"])
		if _, err = fmt.Fprintf(prompt, "Passkey transfer — create one-time invitation\r\n  Output file: %s\r\n  Validity:    %d seconds (max %d)\r\nVerify the public fingerprint out of band on both devices.\r\nCreation appends one signed audit event; if file publication fails, the outcome is unknown and is never retried automatically.\r\n", strconv.QuoteToASCII(opts["--out"]), seconds, passkeyTransferInvitationTTLSeconds); err != nil {
			return err
		}
		consent, err := ask("Enter INVITE to confirm invitation creation")
		defer clear(consent)
		if err != nil {
			return err
		}
		if string(consent) != "INVITE" {
			return errPasskeyTransferCancelled
		}
		gate := personal.NewMutationGate(time.Now().Add(30 * time.Second))
		if err = session.RegisterMutation(gate); err != nil {
			return err
		}
		invite, err := session.NewPasskeyTransferInvitation(time.Duration(seconds)*time.Second, gate)
		if err != nil {
			return err
		}
		defer clear(invite.Raw)
		if err = teamfiles.WriteNew(opts["--out"], invite.Raw); err != nil {
			// The database creation may already be committed. Never return raw
			// bytes, never retry, and never delete a foreign output.
			return errPasskeyTransferPublicationUnknown
		}
		return json.NewEncoder(out).Encode(passkeyTransferInviteReceipt{
			Status:       "invited",
			InvitationID: invite.ID,
			Fingerprint:  invite.Public.Fingerprint,
			ExpiresAt:    invite.ExpiresAt.UTC(),
		})
	case "passkey-revoke":
		if _, err = fmt.Fprintf(prompt, "Passkey transfer — revoke unused invitation\r\n  Invitation file: %s\r\nRevocation appends a signed audit event in this device's audit chain; no vault item or credential is deleted.\r\n", strconv.QuoteToASCII(opts["--invitation"])); err != nil {
			return err
		}
		consent, err := ask("Enter REVOKE to confirm revocation")
		defer clear(consent)
		if err != nil {
			return err
		}
		if string(consent) != "REVOKE" {
			return errPasskeyTransferCancelled
		}
		gate := personal.NewMutationGate(time.Now().Add(30 * time.Second))
		if err = session.RegisterMutation(gate); err != nil {
			return err
		}
		if err = session.RevokePasskeyTransferInvitation(input.invitation, gate); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(passkeyTransferRevokeReceipt{Status: "revoked"})
	case "passkey-list":
		rows, err := session.List("active")
		if err != nil {
			return err
		}
		metadata, err := session.ReadManagedPasskeysMetadata(false)
		if err != nil {
			return err
		}
		list := make([]passkeyTransferListItem, 0, len(rows))
		for _, row := range rows {
			credentials := metadata[row.ID]
			if len(credentials) == 0 {
				continue
			}
			item := passkeyTransferListItem{ItemID: row.ID, Revision: row.Revision, Credentials: make([]passkeyTransferListCredential, 0, len(credentials))}
			for _, credential := range credentials {
				item.Credentials = append(item.Credentials, passkeyTransferListCredential{
					CredentialID:       credential.CredentialID,
					CredentialRevision: credential.Revision,
					RPID:               credential.RPID,
					Name:               credential.UserName,
				})
			}
			list = append(list, item)
		}
		return json.NewEncoder(out).Encode(list)
	case "passkey-export":
		targetPin := opts["--target-pin"]
		if _, err = fmt.Fprintf(prompt, "Passkey transfer — export sealed credential packet\r\n  Selected records: %d\r\n  Target pin:       %s\r\n  Invitation file:  %s\r\n  Selection file:   %s\r\n  Packet output:    %s\r\nExporting records one signed audit intent; it never deletes source credentials or proves receiver persistence.\r\n", len(input.targets), strconv.QuoteToASCII(targetPin), strconv.QuoteToASCII(opts["--invitation"]), strconv.QuoteToASCII(opts["--selection"]), strconv.QuoteToASCII(opts["--out"])); err != nil {
			return err
		}
		consent, err := ask("Enter EXPORT to confirm sealed credential export")
		defer clear(consent)
		if err != nil {
			return err
		}
		if string(consent) != "EXPORT" {
			return errPasskeyTransferCancelled
		}
		gate := personal.NewMutationGate(time.Now().Add(30 * time.Second))
		if err = session.RegisterMutation(gate); err != nil {
			return err
		}
		export, err := session.ExportPasskeyTransfer(input.invitation, targetPin, input.targets, gate)
		if err != nil {
			return err
		}
		defer clear(export.Raw)
		if err = teamfiles.WriteNew(opts["--out"], export.Raw); err != nil {
			// The database export intent may already be committed. Never return
			// raw packet bytes, never retry, and never delete a foreign output.
			return errPasskeyTransferPublicationUnknown
		}
		return json.NewEncoder(out).Encode(passkeyTransferExportReceipt{
			Status:            "exported",
			PacketID:          export.PacketID,
			SourceFingerprint: export.SourceFingerprint,
			TargetFingerprint: export.TargetFingerprint,
		})
	case "passkey-plan":
		if _, err = fmt.Fprintf(prompt, "Passkey transfer — read-only receiver preview\r\n  Source pin:      %s\r\n  Invitation file: %s\r\n  Packet file:     %s\r\nRead-only check: appends no audit event, modifies no items, and leaves the invitation unconsumed.\r\nPreview output contains public selectors only; raw credential records, user handles, and keys are never printed.\r\n", strconv.QuoteToASCII(opts["--source-pin"]), strconv.QuoteToASCII(opts["--invitation"]), strconv.QuoteToASCII(opts["--packet"])); err != nil {
			return err
		}
		consent, err := ask("Enter PLAN to confirm receiver preview")
		defer clear(consent)
		if err != nil {
			return err
		}
		if string(consent) != "PLAN" {
			return errPasskeyTransferCancelled
		}
		plan, err := session.PlanPasskeyTransfer(input.invitation, input.packet, opts["--source-pin"])
		if err != nil {
			return err
		}
		if err := json.NewEncoder(out).Encode(plan); err != nil {
			// Read-only failure: no mutation result is at risk.
			return err
		}
		return nil
	case "passkey-import":
		digest := opts["--digest"]
		if _, err = fmt.Fprintf(prompt, "Passkey transfer — import mapped credentials\r\n  Source pin:      %s\r\n  Plan digest:     %s\r\n  Mapped groups:   %d\r\n  Invitation file: %s\r\n  Packet file:     %s\r\n  Mapping file:    %s\r\nRevalidates invitation chain, pins, expiry, and live revisions before consuming the invitation once.\r\nImport never deletes source credentials, never claims remote backup, and is never retried automatically.\r\n", strconv.QuoteToASCII(opts["--source-pin"]), strconv.QuoteToASCII(digest), len(input.mappings), strconv.QuoteToASCII(opts["--invitation"]), strconv.QuoteToASCII(opts["--packet"]), strconv.QuoteToASCII(opts["--mapping"])); err != nil {
			return err
		}
		consent, err := ask("Enter IMPORT to confirm passkey import")
		defer clear(consent)
		if err != nil {
			return err
		}
		if string(consent) != "IMPORT" {
			return errPasskeyTransferCancelled
		}
		gate := personal.NewMutationGate(time.Now().Add(30 * time.Second))
		if err = session.RegisterMutation(gate); err != nil {
			return err
		}
		receipt, err := session.ApplyPasskeyTransfer(input.invitation, input.packet, opts["--source-pin"], digest, input.mappings, gate)
		if err != nil {
			return err
		}
		items := make([]passkeyTransferImportItem, 0, len(receipt.Items))
		for _, item := range receipt.Items {
			items = append(items, passkeyTransferImportItem{ID: item.ID, Revision: item.Revision})
		}
		if err := json.NewEncoder(out).Encode(passkeyTransferImportReceipt{Status: "imported", Items: items}); err != nil {
			// The database mutation already committed. A receipt delivery
			// failure must not look like a confirmed failure or raw writer error.
			return errPasskeyTransferPublicationUnknown
		}
		return nil
	}
	return personalUsage
}

// runPersonalPasskeyTransfer owns the isolated terminal/session flow for the
// passkey transfer actions. Dispatch happens before the generic personal parser
// so no passkey path can fall through to a different command's validation.
func runPersonalPasskeyTransfer(args []string, out io.Writer) (retErr error) {
	action, opts, ok := parsePasskeyTransferArgs(args)
	if !ok {
		return personalUsage
	}
	input, err := preparePasskeyTransfer(action, opts)
	if err != nil {
		return err
	}
	defer input.clear()

	// Both factors are entered on the existing controlling terminal. Neither is
	// accepted from argv or the environment, and the terminal stays raw while
	// the hidden phrase is read so no prompt input is echoed.
	controlInput, controlOutput, err := openRunCLIConsole()
	if err != nil {
		return errors.New("passkey transfer commands require a controlling terminal for input and prompts")
	}
	defer controlInput.Close()
	if controlOutput != controlInput {
		defer controlOutput.Close()
	}

	fd := int(controlInput.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return errors.New("cannot disable terminal echo")
	}
	var once sync.Once
	var resetErr error
	restore := func() { once.Do(func() { resetErr = term.Restore(fd, state) }) }
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer func() {
		close(done)
		restore()
		if retErr == nil && resetErr != nil {
			retErr = resetErr
		}
	}()
	go func() {
		select {
		case <-signals:
			restore()
			os.Exit(130)
		case <-done:
		}
	}()

	c := console{reader: consoleByteReader{controlInput}, writer: controlOutput}

	password, err := c.field("主密码")
	if err != nil {
		return err
	}
	defer clear(password)
	secretInput, err := c.field("Secret Key")
	if err != nil {
		return err
	}
	key, err := personal.ParseSecret(string(secretInput))
	clear(secretInput)
	if err != nil {
		return errors.New("invalid Secret Key")
	}
	defer clear(key)

	return executePasskeyTransferAction(action, opts, input, out, password, key, c.field, c.output())
}
