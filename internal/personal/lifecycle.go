package personal

import (
	"errors"
	"github.com/jihuayu/locklark/internal/vault"
)

var ErrAlreadyArchived = errors.New("login is already archived")
var ErrAlreadyActive = errors.New("login is already active")

func lifecycleAction(action string) bool {
	return action == "item.archive" || action == "item.unarchive"
}
func ValidStateFilter(state string) bool {
	return state == "active" || state == "archived" || state == "trashed" || state == "all"
}

// Archiving changes discoverability, not permission to explicitly read an item.
func SetArchived(path, pw string, key []byte, id, revision string, archived bool) (string, error) {
	if !ValidEditTarget(id, revision, "title") {
		return "", errors.New("invalid login ID or revision")
	}
	action := "item.unarchive"
	if archived {
		action = "item.archive"
	}
	r, err := command(path, pw, key, action, vault.Item{}, &Edit{ID: id, Revision: revision})
	return r.revision, err
}
func ListState(path, pw string, key []byte, state string) ([]Row, error) {
	if !ValidStateFilter(state) {
		return nil, errors.New("invalid item state filter")
	}
	action := "item.list"
	if state != "active" {
		action += "." + state
	}
	r, err := command(path, pw, key, action, vault.Item{}, nil)
	return r.rows, err
}

var ErrTrashed = errors.New("login is in trash; restore it before use")
var ErrAlreadyTrashed = errors.New("login is already in trash")
var ErrNotTrashed = errors.New("login is not in trash")

func trashAction(action string) bool { return action == "item.trash" || action == "item.untrash" }

// SetTrashed retains encrypted data and its previous active/archive state.
// It neither permanently deletes data nor promises erasure of older copies.
func SetTrashed(path, pw string, key []byte, id, revision string, trashed bool) (string, error) {
	if !ValidEditTarget(id, revision, "title") {
		return "", errors.New("invalid login ID or revision")
	}
	action := "item.untrash"
	if trashed {
		action = "item.trash"
	}
	r, err := command(path, pw, key, action, vault.Item{}, &Edit{ID: id, Revision: revision})
	return r.revision, err
}
