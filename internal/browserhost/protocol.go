// Package browserhost implements the bounded native messaging channel. An
// extension's API assertions are trusted only after explicit native pairing.
package browserhost

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/watchtower"
)

const HostName = "org.locklark.browser"
const ChromiumID = "geldnhjapnackobgknocomedmjgphnpe"
const FirefoxID = "browser@locklark.local"
const MaxInput = 256 << 10
const MaxOutput = 256 << 10

type Browser string

const (
	Chromium Browser = "chromium"
	Firefox  Browser = "firefox"
)

var ErrProtocol = errors.New("native messaging refused")
var ErrBrokerUnavailable = errors.New("desktop browser broker is unavailable")
var errDuplicateRequest = errors.New("native duplicate request ignored")
var token = regexp.MustCompile(`^[a-f0-9]{32}$`)
var revision = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Request struct {
	Options        string `json:"options,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Title          string `json:"title,omitempty"`
	StageID        string `json:"stage_id,omitempty"`
	NeverForOrigin bool   `json:"never_for_origin,omitempty"`
	Category       string `json:"category,omitempty"`
	IncludeHIBP    bool   `json:"include_hibp,omitempty"`
	payload        *savePayload
	WindowID       int64  `json:"window_id,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	V              int    `json:"v"`
	ID             string `json:"id"`
	Type           string `json:"type"`
	Capability     string `json:"capability,omitempty"`
	Origin         string `json:"origin,omitempty"`
	TabID          int64  `json:"tab_id,omitempty"`
	DocumentID     string `json:"document_id,omitempty"`
	ItemID         string `json:"item_id,omitempty"`
	Revision       string `json:"revision,omitempty"`
	// Attachment transport (capability attachments-v1). Size is a pointer so a
	// zero-length file is distinguishable from an omitted field.
	FileName     string `json:"file_name,omitempty"`
	Size         *int64 `json:"size,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	MimeType     string `json:"mime_type,omitempty"`
	TransferID   string `json:"transfer_id,omitempty"`
	Offset       int64  `json:"offset,omitempty"`
	Data         string `json:"data,omitempty"`
	AttachmentID string `json:"attachment_id,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`

	Length      int   `json:"length,omitempty"`
	Digits      *bool `json:"digits,omitempty"`
	Symbols     *bool `json:"symbols,omitempty"`
	SaveHistory *bool `json:"save_history,omitempty"`

	Query         string `json:"query,omitempty"`
	VaultID       string `json:"vault_id,omitempty"`
	Tag           string `json:"tag,omitempty"`
	StateFilter   string `json:"state,omitempty"`
	FavoritesOnly *bool  `json:"favorites_only,omitempty"`
	PasskeysOnly  *bool  `json:"passkeys_only,omitempty"`
	Field         string `json:"field,omitempty"`
	FieldAction   string `json:"action,omitempty"`
	StateAction   string `json:"state_action,omitempty"`
	ItemJSON      string `json:"item_json,omitempty"`
	ProfileKind   string `json:"profile_kind,omitempty"`

	// includeHIBPSet records whether include_hibp was present. ReadRequest is
	// the only production constructor.
	includeHIBPSet bool
}

func (r Request) Context() personal.BrowserContext {
	return personal.BrowserContext{RequestID: r.ID, Origin: r.Origin, TabID: r.TabID, DocumentID: r.DocumentID}
}
func validTitle(value string) bool {
	if len(value) > 1024 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}
func (r Request) valid() bool {
	if r.V != 1 || !token.MatchString(r.ID) {
		return false
	}
	switch r.Type {
	case "save-new", "save-update", "commit-ready", "cancel-save", "otp", "otp-ack", "cancel-otp", "stage-save", "pending-save", "commit-staged-save", "dismiss-save", "generate":
	default:
		if r.payload != nil || r.WindowID != 0 || r.RequestID != "" || r.Nonce != "" || r.StageID != "" || r.Mode != "" || r.Title != "" || r.NeverForOrigin || r.Length != 0 && !attachmentReadType(r.Type) || r.Digits != nil || r.Symbols != nil || r.SaveHistory != nil {
			return false
		}
	}
	if r.Type != "passkey-create" && r.Type != "passkey-get" && r.Options != "" && r.Type != "generate" {
		return false
	}
	if r.Type != "stage-save" && r.Type != "commit-staged-save" && r.Type != "dismiss-save" && r.Type != "generate" && (r.StageID != "" || r.Mode != "" || r.Title != "" || r.NeverForOrigin) {
		return false
	}
	if r.Category != "" && r.Type != "match" && r.Type != "fill" && r.Type != "search" && r.Type != "list" && r.Type != "vault-search" && r.Type != "vault-list" {
		return false
	}
	if r.PasskeysOnly != nil && r.Type != "search" && r.Type != "list" && r.Type != "vault-search" && r.Type != "vault-list" {
		return false
	}
	if r.Type != "passkey-remove" && r.CredentialID != "" {
		return false
	}
	if (r.Type == "match" || r.Type == "fill") && r.Category != "" && r.Category != "login" && r.Category != "identity" && r.Category != "credit_card" {
		return false
	}
	if r.Type != "generate" && !attachmentReadType(r.Type) && (r.Length != 0 || r.Digits != nil || r.Symbols != nil || r.SaveHistory != nil) {
		return false
	}
	switch r.Type {
	case "passkey-create", "passkey-get":
		return token.MatchString(r.Capability) && r.Context().Valid() && r.ItemID == "" && r.Revision == "" && len(r.Options) > 0 && len(r.Options) <= 32768 && strictUnicode([]byte(r.Options))
	case "otp":
		return token.MatchString(r.Capability) && r.OTPContext().Valid() && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "otp-ack", "cancel-otp":
		return token.MatchString(r.Capability) && token.MatchString(r.RequestID) && r.payload == nil && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.WindowID == 0 && r.ItemID == "" && r.Revision == "" && (r.Type == "cancel-otp" && r.Nonce == "" || r.Type == "otp-ack" && revision.MatchString(r.Nonce))
	case "save-new", "save-update":
		if !token.MatchString(r.Capability) || !r.SaveContext().Valid() || r.RequestID != "" || r.Nonce != "" || r.payload == nil || !validPayload(r.payload) {
			return false
		}
		return r.Type == "save-new" && r.ItemID == "" && r.Revision == "" || r.Type == "save-update" && token.MatchString(r.ItemID) && revision.MatchString(r.Revision)
	case "commit-ready", "cancel-save":
		return token.MatchString(r.Capability) && token.MatchString(r.RequestID) && r.payload == nil && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.WindowID == 0 && r.ItemID == "" && r.Revision == "" && r.StageID == "" && r.Mode == "" && r.Title == "" && (r.Type == "cancel-save" && r.Nonce == "" || r.Type == "commit-ready" && revision.MatchString(r.Nonce))
	case "generate":
		if !token.MatchString(r.Capability) || r.payload != nil || r.RequestID != "" || r.Nonce != "" || r.Origin != "" || r.TabID != 0 || r.DocumentID != "" || r.WindowID != 0 || r.ItemID != "" || r.Revision != "" || r.StageID != "" || r.Title != "" || r.NeverForOrigin {
			return false
		}
		if r.Options != "" {
			return len(r.Options) <= 4096 && strictUnicode([]byte(r.Options))
		}
		return r.Mode != "" && r.Length > 0
	case "stage-save":
		if !token.MatchString(r.Capability) || !r.SaveContext().Valid() || r.payload == nil || !validPayload(r.payload) || !validTitle(r.Title) || r.RequestID != "" || r.Nonce != "" || r.StageID != "" {
			return false
		}
		if r.NeverForOrigin {
			return false
		}
		if r.Mode != "" && r.Mode != "new" && r.Mode != "update" {
			return false
		}
		if r.Mode == "update" || r.ItemID != "" || r.Revision != "" {
			return token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && (r.Mode == "" || r.Mode == "update")
		}
		return r.ItemID == "" && r.Revision == ""
	case "pending-save":
		if !token.MatchString(r.Capability) || r.payload != nil || r.RequestID != "" || r.Nonce != "" || r.WindowID < 0 || r.ItemID != "" || r.Revision != "" || r.StageID != "" || r.Mode != "" || r.Title != "" || r.NeverForOrigin {
			return false
		}
		if r.TabID < 1 || r.TabID > 9007199254740991 {
			return false
		}
		_, e := origin.Parse(r.Origin)
		return e == nil
	case "commit-staged-save":
		if !token.MatchString(r.Capability) || !token.MatchString(r.StageID) || !r.SaveContext().Valid() || !validTitle(r.Title) || r.payload != nil || r.RequestID != "" || r.Nonce != "" || r.NeverForOrigin {
			return false
		}
		if r.Mode == "update" || r.ItemID != "" || r.Revision != "" {
			return token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && (r.Mode == "" || r.Mode == "update")
		}
		return r.ItemID == "" && r.Revision == "" && (r.Mode == "" || r.Mode == "new")
	case "dismiss-save":
		if !token.MatchString(r.Capability) || r.payload != nil || r.RequestID != "" || r.Nonce != "" || r.Mode != "" || r.Title != "" {
			return false
		}
		if r.StageID != "" {
			return token.MatchString(r.StageID) && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.WindowID == 0 && r.ItemID == "" && r.Revision == ""
		}
		if r.Origin == "" || !r.NeverForOrigin || r.TabID != 0 || r.DocumentID != "" || r.WindowID != 0 || r.ItemID != "" || r.Revision != "" {
			return false
		}
		_, e := origin.Parse(r.Origin)
		return e == nil
	case "attachment-begin":
		return token.MatchString(r.Capability) && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) &&
			validAttachmentFileName(r.FileName) && r.Size != nil && *r.Size >= 0 && *r.Size <= MaxAttachmentBytes &&
			revision.MatchString(r.SHA256) && validAttachmentMime(r.MimeType) && r.AttachmentID == "" &&
			r.Length == 0 && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" &&
			r.TransferID == "" && r.Offset == 0 && r.Data == ""
	case "attachment-chunk":
		return token.MatchString(r.Capability) && token.MatchString(r.TransferID) && r.Offset >= 0 && r.Data != "" &&
			len(r.Data) <= maxAttachmentChunkEncoded && attachmentFrameIdle(r)
	case "attachment-commit", "attachment-cancel":
		return token.MatchString(r.Capability) && token.MatchString(r.TransferID) && attachmentFrameIdle(r) &&
			r.Offset == 0 && r.Data == ""
	case "attachment-read":
		return token.MatchString(r.Capability) && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) &&
			attachmentSelector(r.AttachmentID) && r.Offset >= 0 && r.Length >= 1 && r.Length <= maxAttachmentChunk &&
			r.TransferID == "" && r.Data == "" && r.FileName == "" && r.Size == nil && r.SHA256 == "" &&
			r.MimeType == "" && r.Origin == "" && r.TabID == 0 && r.DocumentID == ""
	case "attachment-remove":
		return token.MatchString(r.Capability) && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) &&
			attachmentSelector(r.AttachmentID) && r.TransferID == "" && r.Data == "" && r.Offset == 0 && r.Length == 0 &&
			r.FileName == "" && r.Size == nil && r.SHA256 == "" && r.MimeType == "" && r.Origin == "" &&
			r.TabID == 0 && r.DocumentID == ""
	case "hello":
		return r.Capability == "" && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.ItemID == "" && r.Revision == ""
	case "cancel":
		return token.MatchString(r.Capability) && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" && r.ItemID == "" && r.Revision == ""
	case "match":
		return token.MatchString(r.Capability) && r.Context().Valid() && r.ItemID == "" && r.Revision == ""
	case "watchtower", "watchtower-summary":
		if !token.MatchString(r.Capability) || r.ItemID != "" || r.Revision != "" || r.payload != nil {
			return false
		}
		if r.Origin != "" {
			if _, e := origin.Parse(r.Origin); e != nil {
				return false
			}
		}
		if r.TabID != 0 && (r.TabID < 1 || r.TabID > 9007199254740991 || r.DocumentID == "") {
			return false
		}
		return true
	case "fill":
		return token.MatchString(r.Capability) && r.Context().Valid() && token.MatchString(r.ItemID) && revision.MatchString(r.Revision)
	case "status", "session-status", "lock", "vault-lock", "unlock-request":
		return (r.Capability == "" || token.MatchString(r.Capability)) && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "search", "list", "vault-search", "vault-list":
		return token.MatchString(r.Capability) && r.payload == nil && r.RequestID == "" && r.Nonce == "" && r.ItemID == "" && r.Revision == ""
	case "item-get":
		return token.MatchString(r.Capability) && token.MatchString(r.ItemID) && (r.Revision == "" || revision.MatchString(r.Revision)) && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "item-copy-field", "item-reveal-field":
		return token.MatchString(r.Capability) && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && r.Field != "" && (r.FieldAction == "" || r.FieldAction == "copy" || r.FieldAction == "reveal") && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "item-create", "item-edit", "item-save":
		if !token.MatchString(r.Capability) || r.ItemJSON == "" || len(r.ItemJSON) > 64<<10 || !strictUnicode([]byte(r.ItemJSON)) || r.payload != nil || r.RequestID != "" || r.Nonce != "" {
			return false
		}
		if r.Type == "item-edit" {
			return token.MatchString(r.ItemID) && revision.MatchString(r.Revision)
		}
		if r.Type == "item-save" {
			return r.ItemID == "" && r.Revision == "" || token.MatchString(r.ItemID) && revision.MatchString(r.Revision)
		}
		return r.ItemID == "" && r.Revision == ""
	case "item-state":
		return token.MatchString(r.Capability) && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && r.StateAction != "" && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "passkey-remove":
		return token.MatchString(r.Capability) && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && passkey.ValidCredentialID(r.CredentialID) &&
			r.payload == nil && r.RequestID == "" && r.Nonce == "" && r.Origin == "" && r.TabID == 0 && r.DocumentID == "" &&
			r.WindowID == 0 && r.Options == "" && r.ItemJSON == ""
	case "match-profiles":
		return token.MatchString(r.Capability) && r.Context().Valid() && (r.ProfileKind == "" || r.ProfileKind == "all" || r.ProfileKind == "identity" || r.ProfileKind == "credit_card") && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	case "fill-profile":
		return token.MatchString(r.Capability) && r.Context().Valid() && token.MatchString(r.ItemID) && revision.MatchString(r.Revision) && r.payload == nil && r.RequestID == "" && r.Nonce == ""
	}
	return false
}

func isV2ValueType(t string) bool {
	switch t {
	case "stage-save", "pending-save", "commit-staged-save", "dismiss-save":
		return true
	}
	return false
}

// GeneratedProfile publishes only policy counts, never the generated secret.
type GeneratedProfile struct {
	Mode             string `json:"mode"`
	Length           int    `json:"length"`
	AlphabetSize     int    `json:"alphabet_size"`
	EntropyBitsFloor int    `json:"entropy_bits_floor"`
}

// StagedSave is metadata only. The staged password never leaves private memory.
type StagedSave struct {
	StageID          string `json:"stage_id"`
	Origin           string `json:"origin"`
	Username         string `json:"username"`
	Title            string `json:"title"`
	Mode             string `json:"mode"`
	ExistingItemID   string `json:"existing_item_id"`
	ExistingRevision string `json:"existing_revision"`
	ExpiresAt        int64  `json:"expires_at"`
}

type Response struct {
	Credential        string             `json:"credential,omitempty"`
	CredentialID      string             `json:"credential_id,omitempty"`
	QuickFill         bool               `json:"quick_fill,omitempty"`
	Code              string             `json:"code,omitempty"`
	Nonce             string             `json:"nonce,omitempty"`
	ItemID            string             `json:"item_id,omitempty"`
	Revision          string             `json:"revision,omitempty"`
	V                 int                `json:"v"`
	ID                string             `json:"id,omitempty"`
	Type              string             `json:"type"`
	Capability        string             `json:"capability,omitempty"`
	GeneratedPassword string             `json:"generated_password,omitempty"`
	HistoryID         string             `json:"history_id,omitempty"`
	Candidates        []personal.Row     `json:"candidates,omitempty"`
	Capabilities      []string           `json:"capabilities,omitempty"`
	NeverOrigins      []string           `json:"never_origins,omitempty"`
	Identity          map[string]string  `json:"identity,omitempty"`
	Card              map[string]string  `json:"card,omitempty"`
	Category          string             `json:"category,omitempty"`
	Profile           *GeneratedProfile  `json:"profile,omitempty"`
	Staged            *StagedSave        `json:"staged_save,omitempty"`
	Watchtower        *watchtower.Report `json:"watchtower,omitempty"`
	Username          string             `json:"username,omitempty"`
	Password          string             `json:"password,omitempty"`
	Error             string             `json:"error,omitempty"`

	DesktopConnected bool   `json:"desktop_connected,omitempty"`
	Unlocked         bool   `json:"unlocked,omitempty"`
	VaultLocked      bool   `json:"vault_locked,omitempty"`
	Paired           bool   `json:"paired,omitempty"`
	SessionEpoch     uint64 `json:"session_epoch,omitempty"`

	PasswordProfile *BrowserPasswordProfile `json:"-"`
	StagedSave      *BrowserStagedSave      `json:"-"`

	Items            []BrowserItemSummary  `json:"items,omitempty"`
	Vaults           []BrowserVaultSummary `json:"vaults,omitempty"`
	Item             *BrowserItemDetail    `json:"item,omitempty"`
	ItemSummary      *BrowserItemSummary   `json:"item_summary,omitempty"`
	Field            string                `json:"field,omitempty"`
	FieldValue       string                `json:"value,omitempty"`
	Copied           bool                  `json:"copied,omitempty"`
	ExpiresInSeconds int                   `json:"expires_in_seconds,omitempty"`
	State            string                `json:"state,omitempty"`
	Favorite         bool                  `json:"favorite,omitempty"`

	Profiles    []BrowserProfileSummary `json:"profiles,omitempty"`
	ProfileFill *BrowserProfileFill     `json:"profile_fill,omitempty"`

	// Attachment transport. Attachment metadata never carries the file body;
	// Data holds at most one 64KiB decoded read chunk in base64.
	Attachment   *BrowserAttachment `json:"attachment,omitempty"`
	AttachmentID string             `json:"attachment_id,omitempty"`
	TransferID   string             `json:"transfer_id,omitempty"`
	Offset       int64              `json:"offset,omitempty"`
	NextOffset   int64              `json:"next_offset,omitempty"`
	Size         int64              `json:"size,omitempty"`
	Done         bool               `json:"done,omitempty"`
	Data         string             `json:"data,omitempty"`
}

// A legitimate login may have an empty username. Fill responses always carry
// both fixed fields; identity/card responses carry only their structured map.
// Candidate rows keep the original four keys for logins and add optional
// category/subtitle metadata for other vault item kinds.
func (r *Response) UnmarshalJSON(data []byte) error {
	type plain Response
	var value plain
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*r = Response(value)
	// Compatibility views used by the v2 broker tests and callers.
	r.StagedSave = r.Staged
	r.PasswordProfile = r.Profile
	return nil
}

// A legitimate login may have an empty username. Fill responses always carry
// both fixed fields; identity/card responses carry only their structured map.
// Candidate rows keep the original four keys for logins and add optional
// category/subtitle metadata for other vault item kinds.
func (r Response) MarshalJSON() ([]byte, error) {
	type plain Response
	type candidate struct {
		ID               string   `json:"id"`
		Revision         string   `json:"revision"`
		Title            string   `json:"title"`
		State            string   `json:"state"`
		Category         string   `json:"category,omitempty"`
		Subtitle         string   `json:"subtitle,omitempty"`
		WatchtowerFlags  []string `json:"watchtower_flags,omitempty"`
		StrengthScore    *int     `json:"strength_score,omitempty"`
		StrengthCategory string   `json:"strength_category,omitempty"`
		ReuseCount       int      `json:"reuse_count,omitempty"`
		BreachCount      int      `json:"breach_count,omitempty"`
	}
	type wire struct {
		plain
		Candidates []candidate `json:"candidates,omitempty"`
	}
	if r.Type == "otp-fill" {
		return nil, ErrProtocol
	}
	// Map values are shared with the caller. Wipe them after this serialization
	// whether it succeeds or fails, then drop the references.
	defer r.Clear()
	// Attachment frames are fixed shapes. Metadata never serializes a file body
	// and size/offset values are emitted even when they are zero.
	switch r.Type {
	case "attachment-transfer":
		return json.Marshal(struct {
			V                int    `json:"v"`
			ID               string `json:"id,omitempty"`
			Type             string `json:"type"`
			TransferID       string `json:"transfer_id"`
			Offset           int64  `json:"offset"`
			Size             int64  `json:"size"`
			ExpiresInSeconds int    `json:"expires_in_seconds"`
		}{r.V, r.ID, r.Type, r.TransferID, r.Offset, r.Size, r.ExpiresInSeconds})
	case "attachment-cancelled":
		return json.Marshal(struct {
			V          int    `json:"v"`
			ID         string `json:"id,omitempty"`
			Type       string `json:"type"`
			TransferID string `json:"transfer_id"`
		}{r.V, r.ID, r.Type, r.TransferID})
	case "attachment-saved":
		return json.Marshal(struct {
			V          int                `json:"v"`
			ID         string             `json:"id,omitempty"`
			Type       string             `json:"type"`
			ItemID     string             `json:"item_id"`
			Revision   string             `json:"revision"`
			Attachment *BrowserAttachment `json:"attachment"`
		}{r.V, r.ID, r.Type, r.ItemID, r.Revision, r.Attachment})
	case "attachment-data":
		return json.Marshal(struct {
			V          int                `json:"v"`
			ID         string             `json:"id,omitempty"`
			Type       string             `json:"type"`
			ItemID     string             `json:"item_id"`
			Revision   string             `json:"revision"`
			Attachment *BrowserAttachment `json:"attachment"`
			Offset     int64              `json:"offset"`
			NextOffset int64              `json:"next_offset"`
			Done       bool               `json:"done"`
			Data       string             `json:"data"`
		}{r.V, r.ID, r.Type, r.ItemID, r.Revision, r.Attachment, r.Offset, r.NextOffset, r.Done, r.Data})
	case "attachment-removed":
		return json.Marshal(struct {
			V            int    `json:"v"`
			ID           string `json:"id,omitempty"`
			Type         string `json:"type"`
			ItemID       string `json:"item_id"`
			Revision     string `json:"revision"`
			AttachmentID string `json:"attachment_id"`
		}{r.V, r.ID, r.Type, r.ItemID, r.Revision, r.AttachmentID})
	case "passkey-removed":
		return json.Marshal(struct {
			V            int    `json:"v"`
			ID           string `json:"id,omitempty"`
			Type         string `json:"type"`
			ItemID       string `json:"item_id"`
			Revision     string `json:"revision"`
			CredentialID string `json:"credential_id"`
		}{r.V, r.ID, r.Type, r.ItemID, r.Revision, r.CredentialID})
	}
	r.Code = ""
	if r.Type != "passkey-result" {
		r.Credential = ""
	}
	if r.Type != "paired" && r.Type != "unlocked" && r.Type != "status" && r.Type != "session-status" {
		r.QuickFill = false
		r.Capabilities = nil
	}
	if r.Type == "otp-ready" {
		return json.Marshal(struct {
			V     int    `json:"v"`
			ID    string `json:"id"`
			Type  string `json:"type"`
			Nonce string `json:"nonce"`
		}{r.V, r.ID, r.Type, r.Nonce})
	}
	if r.Type == "paired" {
		out := struct {
			V            int      `json:"v"`
			ID           string   `json:"id,omitempty"`
			Type         string   `json:"type"`
			Capability   string   `json:"capability,omitempty"`
			QuickFill    bool     `json:"quick_fill,omitempty"`
			Capabilities []string `json:"capabilities,omitempty"`
		}{r.V, r.ID, r.Type, r.Capability, r.QuickFill, r.Capabilities}
		return json.Marshal(out)
	}
	if r.Type == "items" {
		items := r.Items
		if items == nil {
			items = []BrowserItemSummary{}
		}
		vaults := r.Vaults
		if vaults == nil {
			vaults = []BrowserVaultSummary{}
		}
		return json.Marshal(struct {
			V      int                   `json:"v"`
			ID     string                `json:"id,omitempty"`
			Type   string                `json:"type"`
			Items  []BrowserItemSummary  `json:"items"`
			Vaults []BrowserVaultSummary `json:"vaults"`
		}{r.V, r.ID, r.Type, items, vaults})
	}
	if r.Type == "profiles" {
		profiles := r.Profiles
		if profiles == nil {
			profiles = []BrowserProfileSummary{}
		}
		return json.Marshal(struct {
			V        int                     `json:"v"`
			ID       string                  `json:"id,omitempty"`
			Type     string                  `json:"type"`
			Profiles []BrowserProfileSummary `json:"profiles"`
		}{r.V, r.ID, r.Type, profiles})
	}
	if r.Type == "save-dismissed" {
		never := r.NeverOrigins
		if never == nil {
			never = []string{}
		}
		return json.Marshal(struct {
			V            int      `json:"v"`
			ID           string   `json:"id,omitempty"`
			Type         string   `json:"type"`
			NeverOrigins []string `json:"never_origins"`
		}{r.V, r.ID, r.Type, never})
	}
	if r.Type == "field-value" {
		out := struct {
			V                int    `json:"v"`
			ID               string `json:"id,omitempty"`
			Type             string `json:"type"`
			ItemID           string `json:"item_id,omitempty"`
			Revision         string `json:"revision,omitempty"`
			Field            string `json:"field,omitempty"`
			Value            string `json:"value"`
			Copied           bool   `json:"copied"`
			ExpiresInSeconds int    `json:"expires_in_seconds"`
		}{r.V, r.ID, r.Type, r.ItemID, r.Revision, r.Field, r.FieldValue, r.Copied, r.ExpiresInSeconds}
		return json.Marshal(out)
	}
	if r.Type == "status" || r.Type == "session-status" {
		out := struct {
			V                int      `json:"v"`
			ID               string   `json:"id,omitempty"`
			Type             string   `json:"type"`
			DesktopConnected bool     `json:"desktop_connected"`
			Unlocked         bool     `json:"unlocked"`
			VaultLocked      bool     `json:"vault_locked"`
			Paired           bool     `json:"paired,omitempty"`
			Capability       string   `json:"capability,omitempty"`
			QuickFill        bool     `json:"quick_fill,omitempty"`
			SessionEpoch     uint64   `json:"session_epoch,omitempty"`
			Capabilities     []string `json:"capabilities,omitempty"`
			NeverOrigins     []string `json:"never_origins,omitempty"`
		}{r.V, r.ID, r.Type, r.DesktopConnected, r.Unlocked, r.VaultLocked, r.Paired, r.Capability, r.QuickFill, r.SessionEpoch, r.Capabilities, r.NeverOrigins}
		return json.Marshal(out)
	}
	if r.Type == "locked" {
		out := struct {
			V    int    `json:"v"`
			ID   string `json:"id,omitempty"`
			Type string `json:"type"`
		}{r.V, r.ID, r.Type}
		return json.Marshal(out)
	}
	filled := r.Type == "filled" || r.Type == "filled-identity" || r.Type == "filled-card"
	structuredFill := r.Type == "fill" && (r.Category == "identity" || r.Category == "credit_card")
	if r.Type != "candidates" && r.Type != "fill" && !filled {
		r.Category = ""
	}
	if r.Category != "" && r.Category != "login" && r.Category != "identity" && r.Category != "credit_card" {
		return nil, ErrProtocol
	}
	if !filled && !structuredFill {
		r.Identity = nil
		r.Card = nil
	}
	if filled || structuredFill {
		switch {
		case r.Category == "identity" || r.Type == "filled-identity":
			if r.Card != nil || !validResponseFieldMap(r.Identity, identityResponseFields) {
				return nil, ErrProtocol
			}
		case r.Category == "credit_card" || r.Type == "filled-card":
			if r.Identity != nil || !validResponseFieldMap(r.Card, cardResponseFields) {
				return nil, ErrProtocol
			}
		default:
			// "filled" without an explicit category infers it from the map.
			if (r.Identity == nil) == (r.Card == nil) {
				return nil, ErrProtocol
			}
			if r.Identity != nil {
				if !validResponseFieldMap(r.Identity, identityResponseFields) {
					return nil, ErrProtocol
				}
				r.Category = "identity"
			} else {
				if !validResponseFieldMap(r.Card, cardResponseFields) {
					return nil, ErrProtocol
				}
				r.Category = "credit_card"
			}
		}
	}
	if r.Type != "fill" || structuredFill {
		r.Username = ""
		r.Password = ""
	}
	if r.Type != "generated" {
		r.GeneratedPassword = ""
		r.HistoryID = ""
		r.Profile = nil
		r.PasswordProfile = nil
	}
	if r.Type != "save-staged" && r.Type != "save-pending" {
		r.Staged = nil
		r.StagedSave = nil
	}
	if r.Type != "save-dismissed" {
		r.NeverOrigins = nil
	}
	if r.Type != "watchtower" && r.Type != "watchtower-summary" {
		r.Watchtower = nil
	}
	if r.Type != "field-value" {
		r.FieldValue = ""
		r.Field = ""
		r.Copied = false
		r.ExpiresInSeconds = 0
	}
	if r.Type != "profile-fill" {
		r.ProfileFill = nil
	}
	if r.Type != "item-detail" {
		r.Item = nil
	}
	if r.Type != "item-saved" {
		r.ItemSummary = nil
		r.State = ""
		r.Favorite = false
	}
	if r.Type != "items" {
		r.Items = nil
		r.Vaults = nil
	}
	if r.Type != "profiles" {
		r.Profiles = nil
	}
	if r.Attachment != nil || r.AttachmentID != "" || r.TransferID != "" || r.Size != 0 || r.Done || r.Data != "" || r.NextOffset != 0 {
		r.Attachment, r.AttachmentID, r.TransferID = nil, "", ""
		r.Offset, r.NextOffset, r.Size, r.Done, r.Data = 0, 0, 0, false, ""
	}
	var candidates []candidate
	if len(r.Candidates) > 0 {
		candidates = make([]candidate, len(r.Candidates))
	}
	for n, row := range r.Candidates {
		if row.Kind != "" && row.Kind != "login" && row.Kind != "identity" && row.Kind != "credit_card" {
			return nil, ErrProtocol
		}
		category := row.Category
		if category == "" && row.Kind != "" && row.Kind != "login" {
			category = row.Kind
		}
		if category != "" && category != "login" && category != "identity" && category != "credit_card" {
			return nil, ErrProtocol
		}
		if category != "" && row.Kind != "" && row.Kind != "login" && row.Kind != category {
			return nil, ErrProtocol
		}
		if len(row.Subtitle) > 1024 {
			return nil, ErrProtocol
		}
		candidates[n] = candidate{
			ID:               row.ID,
			Revision:         row.Revision,
			Title:            row.Title,
			State:            row.State,
			Category:         category,
			Subtitle:         row.Subtitle,
			WatchtowerFlags:  row.WatchtowerFlags,
			StrengthScore:    row.StrengthScore,
			StrengthCategory: row.StrengthCategory,
			ReuseCount:       row.ReuseCount,
			BreachCount:      row.BreachCount,
		}
	}
	base := wire{plain(r), candidates}
	if r.Type == "fill" && !structuredFill {
		return json.Marshal(struct {
			wire
			Username string `json:"username"`
			Password string `json:"password"`
		}{wire: base, Username: r.Username, Password: r.Password})
	}
	return json.Marshal(base)
}

var identityResponseFields = map[string]bool{
	"full_name": true, "first_name": true, "middle_name": true, "last_name": true,
	"title": true, "suffix": true, "company": true, "job_title": true,
	"street_address": true, "address_line1": true, "address_line2": true,
	"address_line3": true, "city": true, "state": true, "district": true,
	"postal_code": true, "country_code": true, "country_name": true,
	"phone": true, "phone_country_code": true, "email": true,
	"birth_date": true, "birth_year": true, "birth_month": true, "birth_day": true,
}

var cardResponseFields = map[string]bool{
	"cardholder_name": true, "given_name": true, "additional_name": true,
	"family_name": true, "number": true, "exp": true, "exp_month": true,
	"exp_year": true, "cvv": true, "type": true,
}

func validResponseFieldMap(value map[string]string, allowed map[string]bool) bool {
	if len(value) > 32 {
		return false
	}
	for key, item := range value {
		if !allowed[key] || len(item) > 16384 || !utf8.ValidString(item) {
			return false
		}
	}
	return true
}

// Clear wipes structured identity/card values and credential fields. The Writer
// calls it after serialization so the caller's map backing arrays do not retain
// secrets after a response is written.
func (r *Response) Clear() {
	if r == nil {
		return
	}
	for key := range r.Identity {
		r.Identity[key] = ""
	}
	for key := range r.Card {
		r.Card[key] = ""
	}
	r.Identity = nil
	r.Card = nil
	r.Username = ""
	r.Password = ""
	r.Code = ""
	r.Credential = ""
	r.CredentialID = ""
}

func (Response) String() string   { return "[native browser response]" }
func (Response) GoString() string { return "[native browser response]" }
func (r Request) OTPContext() personal.BrowserOTPContext {
	return personal.BrowserOTPContext{BrowserContext: r.Context(), WindowID: r.WindowID}
}

type savePayload struct{ username, password []byte }

func (p *savePayload) clear() {
	if p != nil {
		clear(p.username)
		clear(p.password)
		p.username = nil
		p.password = nil
	}
}
func (p *savePayload) take() *savePayload {
	v := &savePayload{p.username, p.password}
	p.username = nil
	p.password = nil
	return v
}
func validPayload(p *savePayload) bool {
	if !(p != nil && len(p.username) <= 16384 && len(p.password) > 0 && len(p.password) <= 16384 && utf8.Valid(p.username) && utf8.Valid(p.password)) {
		return false
	}
	for _, value := range [][]byte{p.username, p.password} {
		for _, r := range string(value) {
			if r < 32 && r != '\t' && r != '\n' && r != '\r' || r == 0xfffe || r == 0xffff {
				return false
			}
		}
	}
	return true
}
func (r Request) SaveContext() personal.BrowserSaveContext {
	return personal.BrowserSaveContext{BrowserContext: r.Context(), WindowID: r.WindowID}
}
func (r *Request) Clear() {
	if r != nil {
		r.payload.clear()
		r.payload = nil
		r.ItemJSON = ""
		r.Data = ""
	}
}

func (Request) String() string                   { return "[native browser request]" }
func (Request) GoString() string                 { return "[native browser request]" }
func (Request) MarshalJSON() ([]byte, error)     { return nil, ErrProtocol }
func (savePayload) String() string               { return "[private save payload]" }
func (savePayload) GoString() string             { return "[private save payload]" }
func (savePayload) MarshalJSON() ([]byte, error) { return nil, ErrProtocol }

// encoding/json replaces malformed UTF-8/surrogates. Reject them before any
// credential decoding, so the saved value is never silently normalized.
func strictUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for n := 0; n < len(raw); n++ {
		if raw[n] != '"' {
			continue
		}
		n++
		for ; n < len(raw) && raw[n] != '"'; n++ {
			if raw[n] != '\\' {
				continue
			}
			n++
			if n >= len(raw) {
				return false
			}
			if raw[n] != 'u' {
				continue
			}
			if n+4 >= len(raw) {
				return false
			}
			v, e := strconv.ParseUint(string(raw[n+1:n+5]), 16, 16)
			if e != nil {
				return false
			}
			n += 4
			if v >= 0xdc00 && v <= 0xdfff {
				return false
			}
			if v >= 0xd800 && v <= 0xdbff {
				if n+6 >= len(raw) || raw[n+1] != '\\' || raw[n+2] != 'u' {
					return false
				}
				w, e := strconv.ParseUint(string(raw[n+3:n+7]), 16, 16)
				if e != nil || w < 0xdc00 || w > 0xdfff {
					return false
				}
				n += 6
			}
		}
	}
	return true
}
func ReadRequest(reader io.Reader) (Request, error) {
	var h [4]byte
	if _, e := io.ReadFull(reader, h[:]); e != nil {
		return Request{}, e
	}
	n := binary.NativeEndian.Uint32(h[:])
	if n == 0 || n > MaxInput {
		return Request{}, ErrProtocol
	}
	raw := make([]byte, int(n))
	defer clear(raw)
	if _, e := io.ReadFull(reader, raw); e != nil || !strictUnicode(raw) {
		return Request{}, ErrProtocol
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	first, e := dec.Token()
	if e != nil || first != json.Delim('{') {
		return Request{}, ErrProtocol
	}
	seen := map[string]bool{}
	for dec.More() {
		key, e := dec.Token()
		name, ok := key.(string)
		if e != nil || !ok || seen[name] || len(seen) >= 32 {
			return Request{}, ErrProtocol
		}
		seen[name] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil || len(value) == 0 {
			clear(value)
			return Request{}, ErrProtocol
		}
		scalar := value[0] == '"' || value[0] == '-' || value[0] >= '0' && value[0] <= '9' || string(value) == "true" || string(value) == "false"
		if !scalar {
			clear(value)
			return Request{}, ErrProtocol
		}
		clear(value)
	}
	last, e := dec.Token()
	if e != nil || last != json.Delim('}') {
		return Request{}, ErrProtocol
	}
	if _, e = dec.Token(); e != io.EOF {
		return Request{}, ErrProtocol
	}
	var wire struct {
		Options        string  `json:"options"`
		Mode           string  `json:"mode"`
		Length         int     `json:"length"`
		Digits         *bool   `json:"digits"`
		Symbols        *bool   `json:"symbols"`
		SaveHistory    *bool   `json:"save_history"`
		StageID        string  `json:"stage_id"`
		Title          string  `json:"title"`
		NeverForOrigin *bool   `json:"never_for_origin"`
		Category       string  `json:"category"`
		IncludeHIBP    *bool   `json:"include_hibp"`
		V              int     `json:"v"`
		ID             string  `json:"id"`
		Type           string  `json:"type"`
		Capability     string  `json:"capability"`
		Origin         string  `json:"origin"`
		TabID          int64   `json:"tab_id"`
		DocumentID     string  `json:"document_id"`
		WindowID       int64   `json:"window_id"`
		ItemID         string  `json:"item_id"`
		Revision       string  `json:"revision"`
		RequestID      string  `json:"request_id"`
		Nonce          string  `json:"nonce"`
		Username       *string `json:"username"`
		Password       *string `json:"password"`
		Query          string  `json:"query"`
		VaultID        string  `json:"vault_id"`
		Tag            string  `json:"tag"`
		StateFilter    string  `json:"state"`
		FavoritesOnly  *bool   `json:"favorites_only"`
		PasskeysOnly   *bool   `json:"passkeys_only"`
		Field          string  `json:"field"`
		FieldAction    string  `json:"action"`
		StateAction    string  `json:"state_action"`
		ItemJSON       string  `json:"item_json"`
		ProfileKind    string  `json:"profile_kind"`
		FileName       string  `json:"file_name"`
		Size           *int64  `json:"size"`
		SHA256         string  `json:"sha256"`
		MimeType       string  `json:"mime_type"`
		TransferID     string  `json:"transfer_id"`
		Offset         int64   `json:"offset"`
		Data           string  `json:"data"`
		AttachmentID   string  `json:"attachment_id"`
		CredentialID   string  `json:"credential_id"`
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&wire) != nil {
		return Request{}, ErrProtocol
	}
	r := Request{
		Options: wire.Options, Mode: wire.Mode, Length: wire.Length, Digits: wire.Digits,
		Symbols: wire.Symbols, SaveHistory: wire.SaveHistory, StageID: wire.StageID,
		Title: wire.Title, Category: wire.Category, V: wire.V, ID: wire.ID, Type: wire.Type,
		Capability: wire.Capability, Origin: wire.Origin, TabID: wire.TabID,
		DocumentID: wire.DocumentID, WindowID: wire.WindowID, ItemID: wire.ItemID,
		Revision: wire.Revision, RequestID: wire.RequestID, Nonce: wire.Nonce,
		Query: wire.Query, VaultID: wire.VaultID, Tag: wire.Tag, StateFilter: wire.StateFilter,
		FavoritesOnly: wire.FavoritesOnly, PasskeysOnly: wire.PasskeysOnly, Field: wire.Field, FieldAction: wire.FieldAction,
		StateAction: wire.StateAction, ItemJSON: wire.ItemJSON, ProfileKind: wire.ProfileKind,
		FileName: wire.FileName, Size: wire.Size, SHA256: wire.SHA256, MimeType: wire.MimeType,
		TransferID: wire.TransferID, Offset: wire.Offset, Data: wire.Data, AttachmentID: wire.AttachmentID,
		CredentialID: wire.CredentialID,
	}
	r.NeverForOrigin = wire.NeverForOrigin != nil && *wire.NeverForOrigin
	if wire.IncludeHIBP != nil {
		r.IncludeHIBP = *wire.IncludeHIBP
		r.includeHIBPSet = true
	}
	if wire.Username != nil && wire.Password != nil {
		r.payload = &savePayload{[]byte(*wire.Username), []byte(*wire.Password)}
	}
	expected, optional, ok := requestKeys(r.Type)
	if !ok {
		r.Clear()
		return Request{}, ErrProtocol
	}
	for _, name := range expected {
		if !seen[name] {
			r.Clear()
			return Request{}, ErrProtocol
		}
	}
	for name := range seen {
		allowed := false
		for _, want := range expected {
			if name == want {
				allowed = true
				break
			}
		}
		if allowed {
			continue
		}
		for _, want := range optional {
			if name == want {
				allowed = true
				break
			}
		}
		if !allowed {
			r.Clear()
			return Request{}, ErrProtocol
		}
	}
	if r.Type == "dismiss-save" {
		if !seen["origin"] && !seen["stage_id"] {
			r.Clear()
			return Request{}, ErrProtocol
		}
	}
	if r.Origin != "" {
		if _, e := origin.Parse(r.Origin); e != nil {
			r.Clear()
			return Request{}, ErrProtocol
		}
	}
	if r.Type == "generate" {
		if r.Options == "" && (r.Mode == "" || r.Length == 0) || r.Options != "" && len(r.Options) > 4096 || r.Options != "" && !strictUnicode([]byte(r.Options)) {
			r.Clear()
			return Request{}, ErrProtocol
		}
	}
	if !r.valid() {
		r.Clear()
		return Request{}, ErrProtocol
	}
	return r, nil
}

func requestKeys(kind string) (required, optional []string, ok bool) {
	base := []string{"v", "id", "type"}
	switch kind {
	case "hello":
		return base, nil, true
	case "attachment-begin":
		return append(base, "capability", "item_id", "revision", "file_name", "size", "sha256"), []string{"mime_type"}, true
	case "attachment-chunk":
		return append(base, "capability", "transfer_id", "offset", "data"), nil, true
	case "attachment-commit", "attachment-cancel":
		return append(base, "capability", "transfer_id"), nil, true
	case "attachment-read":
		return append(base, "capability", "item_id", "revision", "attachment_id", "offset", "length"), nil, true
	case "attachment-remove":
		return append(base, "capability", "item_id", "revision", "attachment_id"), nil, true
	case "cancel":
		return append(base, "capability"), nil, true
	case "passkey-create", "passkey-get":
		return append(base, "capability", "origin", "tab_id", "document_id", "options"), nil, true
	case "match", "fill", "save-new", "save-update", "otp":
		required = append(base, "capability", "origin", "tab_id", "document_id")
		if kind == "fill" || kind == "save-update" || kind == "otp" {
			required = append(required, "item_id", "revision")
		}
		if kind == "otp" {
			required = append(required, "window_id")
		}
		if kind == "save-new" || kind == "save-update" {
			required = append(required, "window_id", "username", "password")
		}
		if kind == "match" || kind == "fill" {
			optional = append(optional, "category")
		}
		return required, optional, true
	case "commit-ready", "cancel-save", "otp-ack", "cancel-otp":
		required = append(base, "capability", "request_id")
		if kind == "commit-ready" || kind == "otp-ack" {
			required = append(required, "nonce")
		}
		return required, nil, true
	case "status", "session-status":
		return base, []string{"capability"}, true
	case "lock", "vault-lock", "unlock-request":
		return base, []string{"capability"}, true
	case "generate":
		return append(base, "capability"), []string{"options", "mode", "length", "digits", "symbols", "save_history", "origin"}, true
	case "stage-save":
		return append(base, "capability", "origin", "tab_id", "window_id", "document_id", "username", "password"), []string{"title", "mode", "item_id", "revision"}, true
	case "pending-save":
		return append(base, "capability", "origin", "tab_id"), []string{"window_id", "document_id"}, true
	case "commit-staged-save":
		return append(base, "capability", "stage_id", "origin", "tab_id", "window_id", "document_id"), []string{"title", "mode", "item_id", "revision"}, true
	case "dismiss-save":
		return append(base, "capability"), []string{"origin", "stage_id", "never_for_origin", "tab_id", "window_id", "document_id"}, true
	case "search", "list", "vault-search", "vault-list":
		return append(base, "capability"), []string{"query", "category", "vault_id", "state", "favorites_only", "passkeys_only", "origin", "tag"}, true
	case "item-get":
		return append(base, "capability", "item_id"), []string{"revision"}, true
	case "passkey-remove":
		return append(base, "capability", "item_id", "revision", "credential_id"), nil, true
	case "item-copy-field", "item-reveal-field":
		return append(base, "capability", "item_id", "revision", "field"), []string{"action"}, true
	case "item-create":
		return append(base, "capability", "item_json"), nil, true
	case "item-edit":
		return append(base, "capability", "item_id", "revision", "item_json"), nil, true
	case "item-save":
		return append(base, "capability", "item_json"), []string{"item_id", "revision"}, true
	case "item-state":
		return append(base, "capability", "item_id", "revision", "state_action"), nil, true
	case "match-profiles":
		return append(base, "capability", "origin", "tab_id", "document_id"), []string{"profile_kind"}, true
	case "fill-profile":
		return append(base, "capability", "origin", "tab_id", "document_id", "item_id", "revision"), nil, true
	case "watchtower", "watchtower-summary":
		return append(base, "capability"), []string{"origin", "tab_id", "document_id", "include_hibp"}, true
	}
	return nil, nil, false
}

// These checks constrain normal browser launch; a same-user native process can
// forge argv and is outside this authentication boundary.
func ValidateLaunch(browser Browser, args []string) error {
	if browser == Chromium {
		if len(args) < 1 || len(args) > 2 || args[0] != "chrome-extension://"+ChromiumID+"/" {
			return ErrProtocol
		}
		if len(args) == 2 {
			if runtime.GOOS != "windows" || !strings.HasPrefix(args[1], "--parent-window=") {
				return ErrProtocol
			}
			p := strings.TrimPrefix(args[1], "--parent-window=")
			n, e := strconv.ParseUint(p, 10, 64)
			if e != nil || strconv.FormatUint(n, 10) != p {
				return ErrProtocol
			}
		}
		return nil
	}
	if browser == Firefox && len(args) == 2 && filepath.IsAbs(args[0]) && filepath.Clean(args[0]) == args[0] && filepath.Base(args[0]) == HostName+".json" && args[1] == FirefoxID {
		return nil
	}
	return ErrProtocol
}
