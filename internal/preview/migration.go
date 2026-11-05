package preview

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// All edits are fixed fixture operations, never an arbitrary raw-value interface.
func editedFixture(archive []byte) ([]byte, error) {
	ok, err := knownOriginal(archive)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errFixture
	}
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	file, err := z.Open("export.data")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	dec := json.NewDecoder(file)
	dec.UseNumber()
	var data map[string]any
	if err := dec.Decode(&data); err != nil {
		return nil, err
	}
	accounts, _ := data["accounts"].([]any)
	if len(accounts) != 1 {
		return nil, errFixture
	}
	acct, _ := accounts[0].(map[string]any)
	find := func(list any, key, value string) (map[string]any, error) {
		entries, _ := list.([]any)
		var found map[string]any
		for _, el := range entries {
			m, _ := el.(map[string]any)
			obj := m
			if key == "attrs.uuid" {
				obj, _ = m["attrs"].(map[string]any)
				if obj["uuid"] != value {
					continue
				}
			} else if obj[key] != value {
				continue
			}
			if found != nil {
				return nil, errFixture
			}
			found = m
		}
		if found == nil {
			return nil, errFixture
		}
		return found, nil
	}
	v, err := find(acct["vaults"], "attrs.uuid", "synthetic-vault")
	if err != nil {
		return nil, err
	}
	item, err := find(v["items"], "uuid", "login-sample")
	if err != nil {
		return nil, err
	}
	overview, _ := item["overview"].(map[string]any)
	details, _ := item["details"].(map[string]any)
	section, err := find(details["sections"], "name", "ops")
	if err != nil {
		return nil, err
	}
	field, err := find(section["fields"], "id", "otp-demo")
	if err != nil {
		return nil, err
	}
	val, _ := field["value"].(map[string]any)
	if val == nil || overview == nil {
		return nil, errFixture
	}
	overview["title"] = "轮换后的演练登录"
	val["totp"] = "otpauth://totp/Synthetic?secret=MZXW6YTBOI"
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return packFixture(encoded)
}

// ExportFixture only publishes known synthetic archive bytes. Write beside the
// destination and link once complete: an existing file (including a symlink)
// is never overwritten and a failed write cannot leave a partial final file.
func ExportFixture(bundle, device string, epoch uint64, out string) error {
	if !strings.EqualFold(filepath.Ext(out), ".1pux") {
		return errors.New("explicit .1pux output file required")
	}
	p, err := readPayload(bundle, device, epoch)
	if err != nil {
		return err
	}
	ok, err := knownOriginal(p.Archive)
	if err != nil {
		return err
	}
	if !ok {
		raw, err := fixtureArchive()
		if err != nil {
			return err
		}
		edit, err := editedFixture(raw)
		if err != nil {
			return err
		}
		if !bytes.Equal(edit, p.Archive) {
			return errFixture
		}
	}
	f, err := os.CreateTemp(filepath.Dir(out), ".locklark-fixture-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = io.Copy(f, bytes.NewReader(p.Archive))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Link(f.Name(), out)
}
