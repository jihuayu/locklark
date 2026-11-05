package personal

import (
	"encoding/hex"
	"errors"
	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/totp"
	"github.com/jihuayu/locklark/internal/vault"
	"strings"
)

var ErrConflict = errors.New("login changed; list again and review before retrying")
var ErrNotFound = errors.New("no login with the supplied ID")

type Edit struct{ ID, Revision, Field, Value string }

func editAction(s string) bool {
	switch s {
	case "item.archive", "item.unarchive", "item.edit.url", "item.edit.title", "item.edit.username", "item.edit.password", "item.edit.otp", "item.regenerate.password":
		return true
	}
	return false
}
func ValidEditTarget(id, revision, field string) bool {
	if !idOK(id) || !editAction("item.edit."+field) || len(revision) != 64 {
		return false
	}
	b, e := hex.DecodeString(revision)
	return e == nil && hex.EncodeToString(b) == revision
}

// A successful item mutation's signed event digest is its opaque revision.
// A stale or missing target commits only an audit outcome, never a changed item.
func EditLogin(path, pw string, key []byte, edit Edit) (string, error) {
	if !ValidEditTarget(edit.ID, edit.Revision, edit.Field) {
		return "", errors.New("invalid login ID, revision or field")
	}
	if edit.Field == "title" && strings.TrimSpace(edit.Value) == "" || edit.Field == "password" && edit.Value == "" {
		return "", errors.New("title and password must not be empty")
	}
	if edit.Field == "url" && edit.Value != "" {
		if _, err := origin.Website(edit.Value); err != nil {
			return "", err
		}
	}
	if edit.Field == "otp" && edit.Value != "" {
		config, err := totp.Parse(edit.Value)
		if err != nil {
			return "", err
		}
		config.Clear()
	}
	r, e := command(path, pw, key, "item.edit."+edit.Field, vault.Item{}, &edit)
	return r.revision, e
}
