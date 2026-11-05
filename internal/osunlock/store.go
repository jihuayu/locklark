// Package osunlock protects native quick-unlock material with system services.
// It has no disk fallback and no web / IPC bindings.
package osunlock

import "errors"

var ErrUnavailable = errors.New("system unlock unavailable or authentication declined")

type Store interface {
	Store(string, []byte) error
	Load(string) ([]byte, error)
	Delete(string) error
}

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
