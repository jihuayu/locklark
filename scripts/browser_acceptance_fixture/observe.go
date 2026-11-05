package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	bolt "go.etcd.io/bbolt"
)

type saveEvent struct {
	Action       string `json:"action"`
	Item         string `json:"item_id"`
	Revision     string `json:"revision"`
	BaseRevision string `json:"base_revision"`
	Result       string `json:"result"`
}

type observation struct {
	SnapshotDigest string         `json:"snapshot_digest"`
	Rows           []personal.Row `json:"rows"`
	SaveEvents     []saveEvent    `json:"save_events"`
	AuditSafe      bool           `json:"audit_safe"`
}

// Original-file access is strictly read-only. All authentication and observer
// audit events happen on the consistent private copy, never on the live vault.
func consistentVaultCopy(source, destination string) (string, error) {
	db, err := bolt.Open(source, 0600, &bolt.Options{ReadOnly: true, Timeout: 3 * time.Second})
	if err != nil {
		return "", err
	}
	defer db.Close()
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer file.Close()
	var digest string
	if err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("locklark.personal/v1"))
		if bucket == nil || len(bucket.Get([]byte("snapshot"))) == 0 {
			return errors.New("missing synthetic snapshot")
		}
		hash := sha256.Sum256(bucket.Get([]byte("snapshot")))
		digest = hex.EncodeToString(hash[:])
		_, err := tx.WriteTo(file)
		return err
	}); err != nil {
		return "", err
	}
	if err = db.Close(); err != nil {
		return "", err
	}
	if err = file.Sync(); err != nil {
		return "", err
	}
	if err = file.Close(); err != nil {
		return "", err
	}
	return digest, nil
}

func containsCanary(raw []byte, f fixture, includeOrigin bool) bool {
	values := []string{f.Password, f.Secret, f.Username, f.Value, f.SaveUsername, f.SaveValue, f.UpdateUsername, f.UpdateValue, f.RejectedUsername, f.RejectedValue}
	if includeOrigin {
		values = append(values, f.Origin)
	}
	for _, value := range values {
		if value != "" && bytes.Contains(raw, []byte(value)) {
			return true
		}
	}
	return false
}

func observeFixture(input string) error {
	raw, err := os.ReadFile(input)
	if err != nil || len(raw) > 64<<10 {
		return errors.New("invalid synthetic fixture")
	}
	defer clear(raw)
	var f fixture
	if json.Unmarshal(raw, &f) != nil || f.Path != filepath.Join(filepath.Dir(input), "synthetic.ll") {
		return errors.New("invalid synthetic fixture path")
	}
	key, err := personal.ParseSecret(f.Secret)
	if err != nil {
		return err
	}
	defer clear(key)
	private, err := os.MkdirTemp(filepath.Dir(input), ".observe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(private)
	copyPath := filepath.Join(private, "snapshot.ll")
	digest, err := consistentVaultCopy(f.Path, copyPath)
	if err != nil {
		return err
	}
	session, err := personal.UnlockSession(copyPath, []byte(f.Password), key, time.Minute)
	if err != nil {
		return err
	}
	defer session.Lock()
	rows, err := session.List("active")
	if err != nil {
		return err
	}
	rowJSON, err := json.Marshal(rows)
	if err != nil || containsCanary(rowJSON, f, false) {
		return errors.New("unsafe synthetic metadata")
	}
	events, err := session.Audit()
	if err != nil {
		return err
	}
	auditJSON, err := json.Marshal(events)
	if err != nil {
		return err
	}
	out := observation{SnapshotDigest: digest, Rows: rows, SaveEvents: []saveEvent{}, AuditSafe: !containsCanary(auditJSON, f, true)}
	for _, event := range events {
		if event.Action != "item.browser.save.new" && event.Action != "item.browser.save.update" {
			continue
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(encoded)
		out.SaveEvents = append(out.SaveEvents, saveEvent{event.Action, event.Item, hex.EncodeToString(hash[:]), event.BaseRevision, event.Result})
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
