package personal

import (
	"errors"
	"github.com/jihuayu/locklark/internal/vault"
	"os"
	"path/filepath"
	"strings"
)

const exportAction = "vault.export.kdbx"

var ErrExportOutput = errors.New("encrypted export publication failed; committed intent may remain and output may exist")

type ExportReceipt struct {
	Status  string `json:"status"`
	Session string `json:"session"`
	Intent  string `json:"intent"`
}
type exportRequest struct{ password string }

func publishExport(raw []byte, dest string) error {
	f, err := os.CreateTemp(filepath.Dir(dest), ".locklark-export-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return publish(f.Name(), dest)
}

func ExportKDBX(path, pw string, key []byte, password, dest string) (ExportReceipt, error) {
	return exportKDBX(path, pw, key, password, dest, publishExport)
}
func exportKDBX(path, pw string, key []byte, password, dest string, publishFile func([]byte, string) error) (ExportReceipt, error) {
	if err := vault.ValidateExportPassword(password); err != nil {
		return ExportReceipt{}, err
	}
	if !strings.EqualFold(filepath.Ext(dest), ".kdbx") {
		return ExportReceipt{}, errors.New("explicit .kdbx output required")
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		return ExportReceipt{}, ErrExportOutput
	}
	r, err := command(path, pw, key, exportAction, vault.Item{}, nil, commandOption{export: &exportRequest{password: password}})
	defer clear(r.archive)
	if err != nil {
		return ExportReceipt{}, err
	}
	if err = publishFile(r.archive, dest); err != nil {
		return ExportReceipt{}, ErrExportOutput
	}
	return ExportReceipt{Status: "exported-encrypted", Session: r.session, Intent: r.intent}, nil
}
