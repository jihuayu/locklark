package personal

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/jihuayu/locklark/internal/onepux"
	"github.com/jihuayu/locklark/internal/vault"
)

const importPlanAction = "migration.plan.1pux"
const importAction = "migration.import.1pux"

var ErrImportChanged = errors.New("1PUX source changed since the confirmed plan")
var ErrImportDuplicate = errors.New("1PUX source item already exists; no items imported")

type ImportReceipt struct {
	Status       string               `json:"status"`
	Session      string               `json:"session"`
	Event        string               `json:"event"`
	ReportDigest string               `json:"report_digest"`
	Report       onepux.MappingReport `json:"report"`
}
type importRequest struct {
	read     func() ([]byte, error)
	expected string
}

func migrationAction(action string) bool { return action == importPlanAction || action == importAction }

func ValidImportDigest(value string) bool { return digestOK(value) }
func (r *importRequest) mapSource(secret []byte) (onepux.MappedLogins, error) {
	raw, err := r.read()
	defer clear(raw)
	if err != nil {
		return onepux.MappedLogins{}, err
	}
	derived, err := hkdf.Key(sha256.New, secret, nil, "locklark/personal/import-plan/key/v1", 32)
	if err != nil {
		return onepux.MappedLogins{}, invalid
	}
	defer clear(derived)
	mac := hmac.New(sha256.New, derived)
	mac.Write([]byte("locklark/personal/import-plan/login-v1\x00"))
	mac.Write(raw)
	stamp := mac.Sum(nil)
	if r.expected != "" {
		expected, err := hex.DecodeString(r.expected)
		if err != nil || !hmac.Equal(stamp, expected) {
			return onepux.MappedLogins{}, ErrImportChanged
		}
	}
	mapped, err := onepux.MapLogins(raw)
	if err != nil {
		return onepux.MappedLogins{}, err
	}
	mapped.Report.SourceDigest = hex.EncodeToString(stamp)
	return mapped, nil
}
func importFailure(err error) (string, error) {
	if errors.Is(err, ErrImportChanged) {
		return "source-changed", ErrImportChanged
	}
	if errors.Is(err, ErrImportDuplicate) {
		return "duplicate", ErrImportDuplicate
	}
	return inspectionFailure(err)
}
func PlanImportOnepux(path, pw string, key []byte, source string) (ImportReceipt, error) {
	return importOnepux(path, pw, key, source, "", importPlanAction)
}
func ImportOnepux(path, pw string, key []byte, source, expected string) (ImportReceipt, error) {
	if !digestOK(expected) {
		return ImportReceipt{}, ErrImportChanged
	}
	return importOnepux(path, pw, key, source, expected, importAction)
}
func importOnepux(path, pw string, key []byte, source, expected, action string) (ImportReceipt, error) {
	if source == "" {
		return ImportReceipt{}, ErrInspectionSource
	}
	r, err := command(path, pw, key, action, vault.Item{}, nil, commandOption{migration: &importRequest{read: func() ([]byte, error) { return readInspectionSource(source) }, expected: expected}})
	if err != nil {
		return ImportReceipt{}, err
	}
	status := "planned-login-v1"
	if action == importAction {
		status = "imported-login-v1"
	}
	return ImportReceipt{Status: status, Session: r.session, Event: r.intent, ReportDigest: r.reportDigest, Report: r.migration}, nil
}
