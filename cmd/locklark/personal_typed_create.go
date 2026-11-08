package main

// `personal add-item` execution path.
//
// The strict decoder in personal_typed.go owns the accepted document shape; it
// runs only on bytes returned by the private owner-only reader in
// personal_typed_file_{unix,windows}.go. This file adds the authenticated,
// gated mutation and a receipt that names the new identity without echoing any
// item value or the title. There is no direct-persistence or ungated shortcut:
// the only write is Session.AddItem under a registered MutationGate.

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// errTypedCreateCancelled is the fixed refusal for a missing SAVE confirmation.
var errTypedCreateCancelled = errors.New("typed item creation cancelled")

// createTypedPersonal reads the private typed input document, authenticates the
// vault with both factors, asks for a SAVE confirmation and performs one gated
// item creation. It returns only status, id and revision so the caller's JSON
// receipt cannot leak the document.
func createTypedPersonal(path, inputPath string, pw, key []byte, ask func(string) ([]byte, error), prompt io.Writer) (map[string]string, error) {
	if path == "" || inputPath == "" || ask == nil || prompt == nil {
		return nil, errTypedInputRefused
	}

	raw, err := readTypedPersonalFile(inputPath)
	if err != nil {
		return nil, err
	}
	defer clear(raw)

	item, requests, err := decodeTypedPersonalDocument(raw)
	if err != nil {
		return nil, err
	}
	// Strings in vault.Item are immutable Go values; this drops the decoded
	// references and clears the native byte slices best-effort. It does not
	// claim to zero string backing arrays.
	defer clearTypedItem(&item)

	// Every attachment file is read and frozen before authentication, SAVE
	// consent and the mutation, so a later path replacement cannot change what
	// is stored. A refusal here happens before any prompt and clears every
	// already-read body through the deferred item clear.
	if err := resolveTypedAttachments(&item, requests, len(raw)); err != nil {
		return nil, err
	}

	session, err := personal.UnlockSession(path, pw, key, time.Minute)
	if err != nil {
		return nil, err
	}
	defer session.Lock()

	fieldCount := 0
	for _, section := range item.Sections {
		fieldCount += len(section.Fields)
	}
	totalAttachmentBytes := 0
	for _, attachment := range item.Attachments {
		totalAttachmentBytes += len(attachment.Content)
	}
	if _, err := fmt.Fprintf(prompt, "将新增 %s 类别条目：%d 个分区，%d 个自定义字段，%d 个网址，%d 个标签，%d 个附件共 %d 字节。\r\n", item.Category, len(item.Sections), fieldCount, len(item.URLs), len(item.Tags), len(item.Attachments), totalAttachmentBytes); err != nil {
		return nil, err
	}

	consent, err := ask("输入 SAVE 确认新增条目")
	defer clear(consent)
	if err != nil {
		return nil, err
	}
	if string(consent) != "SAVE" {
		return nil, errTypedCreateCancelled
	}

	gate := personal.NewMutationGate(time.Now().Add(30 * time.Second))
	if err := session.RegisterMutation(gate); err != nil {
		return nil, err
	}
	id, revision, err := session.AddItem(item, gate)
	if err != nil {
		return nil, err
	}
	return map[string]string{"status": "created", "id": id, "revision": revision}, nil
}

// typedAttachmentMetaOverhead conservatively charges fixed per-attachment
// native metadata (generated ID, size, SHA-256 hex and envelope framing) against
// the payload budget before the native AddItem validation runs.
const typedAttachmentMetaOverhead = 128

// resolveTypedAttachments reads every explicit private attachment file into the
// decoded item and enforces the aggregate payload bound. All reads happen before
// the SAVE prompt and the single mutation, so the bytes are frozen for the
// mutation; rawJSONLen and native metadata are charged conservatively alongside
// each body. On refusal the caller's deferred item clear releases every body
// already read. The final native AddItem validation remains authoritative.
func resolveTypedAttachments(item *vault.Item, requests []typedAttachmentRequest, rawJSONLen int) error {
	if item == nil || len(requests) != len(item.Attachments) {
		return errTypedInputRefused
	}
	aggregate := rawJSONLen
	for i := range requests {
		request := requests[i]
		content, err := readTypedAttachmentFile(request.file)
		if err != nil {
			return err
		}
		item.Attachments[i].Content = content
		aggregate += len(content) + len(request.fileName) + len(request.mimeType) + typedAttachmentMetaOverhead
		if aggregate > vault.MaxPayload {
			return errTypedInputRefused
		}
	}
	return nil
}

// clearTypedItem releases the decoded item and best-effort clears native byte
// slices. Go strings cannot be zeroed in place, so only their references are
// dropped here.
func clearTypedItem(item *vault.Item) {
	if item == nil {
		return
	}
	clear(item.Attachment)
	clear(item.ImportSource)
	clear(item.SSHSeed)
	clear(item.SSHPublicKey)
	clear(item.Passkey)
	for i := range item.Attachments {
		clear(item.Attachments[i].Content)
	}
	*item = vault.Item{}
}
