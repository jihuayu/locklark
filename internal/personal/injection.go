package personal

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/vault"
)

var ErrInjectionOutput = errors.New("sensitive JSON publication failed; intent recorded, output may exist")
var ErrInjectionTarget = errors.New("invalid JSON injection target, property or destination")

type InjectionReceipt struct {
	Status            string `json:"status"`
	Session           string `json:"session"`
	Intent            string `json:"intent"`
	DestinationDigest string `json:"destination_digest"`
}
type injectionRequest struct{ path, name string }

func injectAction(action string) bool {
	return action == "item.inject.username" || action == "item.inject.password"
}
func readValueAction(action string) bool { return revealAction(action) || boundValueAction(action) }
func ValidInjectionName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for i, b := range []byte(name) {
		if b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || i > 0 && b >= '0' && b <= '9' {
			continue
		}
		return false
	}
	return true
}
func (r *injectionRequest) valid() bool {
	return r != nil && ValidInjectionName(r.name) && filepath.IsAbs(r.path) && len(r.path) <= 4096 && utf8.ValidString(r.path) && !strings.ContainsRune(r.path, 0) && strings.EqualFold(filepath.Ext(r.path), ".json")
}
func (r *injectionRequest) binding(secret []byte) (string, error) {
	key, e := hkdf.Key(sha256.New, secret, nil, "locklark/personal/injection/key/v1", 32)
	if e != nil {
		return "", invalid
	}
	defer clear(key)
	raw, e := json.Marshal(struct{ Format, Path, Property string }{"json-single-field-v1", r.path, r.name})
	if e != nil {
		return "", invalid
	}
	defer clear(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func InjectJSON(path, pw string, key []byte, target RevealTarget, name, dest string) (InjectionReceipt, error) {
	return injectJSON(target, name, dest, func(request *injectionRequest) (result, error) {
		return command(path, pw, key, "item.inject."+target.Field, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field}, commandOption{injection: request})
	}, publishInjection)
}
func injectJSON(target RevealTarget, name, dest string, prepare func(*injectionRequest) (result, error), writeFile func([]byte, string) error) (InjectionReceipt, error) {
	if dest == "" || !ValidRevealTarget(target.ID, target.Revision, target.Field) {
		return InjectionReceipt{}, ErrInjectionTarget
	}
	absolute, err := filepath.Abs(dest)
	if err != nil {
		return InjectionReceipt{}, ErrInjectionTarget
	}
	request := &injectionRequest{path: absolute, name: name}
	if !request.valid() {
		return InjectionReceipt{}, ErrInjectionTarget
	}
	r, err := prepare(request)
	defer clear(r.value)
	if err != nil {
		return InjectionReceipt{}, err
	}
	raw, err := json.Marshal(map[string]string{name: string(r.value)})
	if err != nil {
		return InjectionReceipt{}, ErrInjectionOutput
	}
	raw = append(raw, '\n')
	defer clear(raw)
	if err = writeFile(raw, absolute); err != nil {
		return InjectionReceipt{}, ErrInjectionOutput
	}
	return InjectionReceipt{Status: "written-sensitive-json", Session: r.session, Intent: r.intent, DestinationDigest: r.destinationDigest}, nil
}

func publishInjection(raw []byte, dest string) error {
	file, err := createInjectionTemp(filepath.Dir(dest))
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err = file.Write(raw); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return publish(file.Name(), dest)
}
