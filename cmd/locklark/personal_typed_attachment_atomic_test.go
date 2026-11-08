package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
)

func typedAttachmentCreateDocument(t *testing.T, paths ...string) string {
	t.Helper()
	entries := make([]string, 0, len(paths))
	for n, path := range paths {
		entries = append(entries, typedAttachmentJSON(t, path, []string{"first.bin", "second.bin"}[n%2], "application/octet-stream"))
	}
	return typedAttachmentDocument("document", "Atomic document", entries...)
}

func TestCreateTypedPersonalDocumentAttachmentsAreAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.bin")
	secondPath := filepath.Join(dir, "second.bin")
	missingPath := filepath.Join(dir, "missing.bin")
	oversizePath := filepath.Join(dir, "oversize.bin")
	aggregateOnePath := filepath.Join(dir, "aggregate-one.bin")
	aggregateTwoPath := filepath.Join(dir, "aggregate-two.bin")
	writePrivateTypedFixture(t, firstPath, []byte("first\x00canary"))
	writePrivateTypedFixture(t, secondPath, []byte("second\x00canary"))
	writePrivateTypedFixture(t, oversizePath, make([]byte, vault.MaxAttachmentSize+1))
	writePrivateTypedFixture(t, aggregateOnePath, make([]byte, vault.MaxAttachmentSize))
	writePrivateTypedFixture(t, aggregateTwoPath, make([]byte, vault.MaxAttachmentSize))

	t.Run("wrong-save", func(t *testing.T) {
		vaultPath, inputPath, pw, key := typedCreateFixture(t, typedAttachmentCreateDocument(t, firstPath, secondPath))
		var prompt bytes.Buffer
		asked := 0
		response, err := createTypedPersonal(vaultPath, inputPath, pw, key, func(string) ([]byte, error) {
			asked++
			return []byte("NOPE"), nil
		}, &prompt)
		if !errors.Is(err, errTypedCreateCancelled) || response != nil || asked != 1 {
			t.Fatalf("wrong SAVE must cancel before mutation: response=%+v asked=%d err=%v", response, asked, err)
		}
		if count := typedCreateActiveCount(t, vaultPath, pw, key); count != 0 {
			t.Fatalf("wrong SAVE partially created attachments: %d items", count)
		}
	})

	for _, test := range []struct {
		name  string
		paths []string
	}{
		{"missing-file", []string{firstPath, missingPath}},
		{"oversize-file", []string{firstPath, oversizePath}},
		{"aggregate-oversize", []string{aggregateOnePath, aggregateTwoPath}},
	} {
		t.Run(test.name, func(t *testing.T) {
			vaultPath, inputPath, pw, key := typedCreateFixture(t, typedAttachmentCreateDocument(t, test.paths...))
			var prompt bytes.Buffer
			asked := 0
			response, err := createTypedPersonal(vaultPath, inputPath, pw, key, func(string) ([]byte, error) {
				asked++
				return []byte("SAVE"), nil
			}, &prompt)
			if !errors.Is(err, errTypedInputRefused) || response != nil || asked != 0 || prompt.Len() != 0 {
				t.Fatalf("bad attachment must refuse before consent: response=%+v asked=%d prompt=%q err=%v", response, asked, prompt.String(), err)
			}
			if text := err.Error(); strings.Contains(text, dir) || strings.Contains(text, "canary") {
				t.Fatalf("refusal echoed a path or file value: %q", text)
			}
			if count := typedCreateActiveCount(t, vaultPath, pw, key); count != 0 {
				t.Fatalf("bad attachment partially created the item: %d items", count)
			}
		})
	}
}
