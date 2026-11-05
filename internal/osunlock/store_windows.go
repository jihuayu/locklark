package osunlock

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"unsafe"

	"github.com/egoist/mygo"
	"golang.org/x/sys/windows"
)

// Only Passport KSP is accepted. No Software KSP, DPAPI-only, or prompt-only
// fallback is allowed. CNG decrypt, not a boolean biometric result, releases the
// wrapping key. NgcCacheType and gesture policy must both be supported.
type hello struct{}

func New() Store    { return hello{} }
func Label() string { return "Windows Hello" }
func Description() string {
	return "使用 Windows Hello 保护的密钥解锁；人脸、指纹或系统 PIN 由 Windows 验证。24 小时后需完整解锁。"
}

var ncrypt = windows.NewLazySystemDLL("ncrypt.dll")
var nOpen = ncrypt.NewProc("NCryptOpenStorageProvider")
var nCreate = ncrypt.NewProc("NCryptCreatePersistedKey")
var nOpenKey = ncrypt.NewProc("NCryptOpenKey")
var nSet = ncrypt.NewProc("NCryptSetProperty")
var nGet = ncrypt.NewProc("NCryptGetProperty")
var nFinalize = ncrypt.NewProc("NCryptFinalizeKey")
var nFree = ncrypt.NewProc("NCryptFreeObject")
var nDelete = ncrypt.NewProc("NCryptDeleteKey")
var nEncrypt = ncrypt.NewProc("NCryptEncrypt")
var nDecrypt = ncrypt.NewProc("NCryptDecrypt")

func wide(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }
func release(h uintptr) {
	if h != 0 {
		nFree.Call(h)
	}
}
func provider() (uintptr, error) {
	var h uintptr
	name := wide("Microsoft Passport Key Storage Provider")
	status, _, _ := nOpen.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(name)), 0)
	runtime.KeepAlive(name)
	if status != 0 {
		return 0, ErrUnavailable
	}
	return h, nil
}
func setNumber(h uintptr, name string, n uint32) error {
	prop := wide(name)
	r, _, _ := nSet.Call(h, uintptr(unsafe.Pointer(prop)), uintptr(unsafe.Pointer(&n)), 4, 0)
	runtime.KeepAlive(prop)
	if r != 0 {
		return ErrUnavailable
	}
	return nil
}
func number(h uintptr, name string) (uint32, error) {
	var v, n uint32
	prop := wide(name)
	r, _, _ := nGet.Call(h, uintptr(unsafe.Pointer(prop)), uintptr(unsafe.Pointer(&v)), 4, uintptr(unsafe.Pointer(&n)), 0)
	runtime.KeepAlive(prop)
	if r != 0 || n != 4 {
		return 0, ErrUnavailable
	}
	return v, nil
}
func verify(h uintptr) error {
	usage, e := number(h, "Key Usage")
	if e != nil || usage&1 == 0 || usage&8 != 0 {
		return ErrUnavailable
	}
	policy, e := number(h, "NgcCacheType")
	if e != nil || policy != 1 {
		return ErrUnavailable
	}
	export, e := number(h, "Export Policy")
	if e != nil || export != 0 {
		return ErrUnavailable
	}
	return nil
}
func keyName(id, token string) (string, error) {
	if !validID(id) || len(token) != 32 {
		return "", ErrUnavailable
	}
	if _, e := hex.DecodeString(token); e != nil {
		return "", ErrUnavailable
	}
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return "", ErrUnavailable
	}
	return u.User.Sid.String() + "//Locklark/" + id + "/" + token, nil
}
func openKey(id, token string) (uintptr, error) {
	name, e := keyName(id, token)
	if e != nil {
		return 0, e
	}
	p, e := provider()
	if e != nil {
		return 0, e
	}
	defer release(p)
	var h uintptr
	nativeName := wide(name)
	r, _, _ := nOpenKey.Call(p, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(nativeName)), 0, 0)
	runtime.KeepAlive(nativeName)
	if r != 0 {
		return 0, ErrUnavailable
	}
	return h, nil
}
func createKey(id, token string) (uintptr, error) {
	name, e := keyName(id, token)
	if e != nil {
		return 0, e
	}
	p, e := provider()
	if e != nil {
		return 0, e
	}
	defer release(p)
	var h uintptr
	algorithm, nativeName := wide("RSA"), wide(name)
	r, _, _ := nCreate.Call(p, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(algorithm)), uintptr(unsafe.Pointer(nativeName)), 0, 0)
	runtime.KeepAlive(algorithm)
	runtime.KeepAlive(nativeName)
	if r != 0 {
		return 0, ErrUnavailable
	}
	ok := false
	defer func() {
		if !ok {
			status, _, _ := nDelete.Call(h, 0)
			if status != 0 {
				release(h)
			}
		}
	}()
	for _, prop := range []struct {
		name  string
		value uint32
	}{{"Length", 2048}, {"Key Usage", 1}, {"Export Policy", 0}, {"NgcCacheType", 1}} {
		if setNumber(h, prop.name, prop.value) != nil {
			return 0, ErrUnavailable
		}
	}
	r, _, _ = nFinalize.Call(h, 0)
	if r != 0 || verify(h) != nil {
		return 0, ErrUnavailable
	}
	ok = true
	return h, nil
}

type oaep struct {
	algorithm *uint16
	label     *byte
	labelLen  uint32
}

func crypt(h uintptr, input []byte, decrypt bool) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrUnavailable
	}
	proc := nEncrypt
	if decrypt {
		if verify(h) != nil || setNumber(h, "PinCacheIsGestureRequired", 1) != nil {
			return nil, ErrUnavailable
		}
		proc = nDecrypt
	}
	padding := oaep{algorithm: wide("SHA256")}
	output := make([]byte, 512)
	var n uint32
	status, _, _ := proc.Call(h, uintptr(unsafe.Pointer(&input[0])), uintptr(len(input)), uintptr(unsafe.Pointer(&padding)), uintptr(unsafe.Pointer(&output[0])), uintptr(len(output)), uintptr(unsafe.Pointer(&n)), 4)
	runtime.KeepAlive(padding)
	runtime.KeepAlive(input)
	if status != 0 || n > uint32(len(output)) {
		clear(output)
		return nil, ErrUnavailable
	}
	return output[:n], nil
}

type sealed struct {
	Version              int
	Token                string
	Wrapped, Nonce, Data []byte
}

func store() mygo.SecretsModule { return mygo.Secrets.Service("app.locklark.hello.v1") }
func (hello) Store(id string, raw []byte) error {
	if !validID(id) || len(raw) > 1400 {
		return ErrUnavailable
	}
	old, _ := store().Get(id)
	defer clear(old)
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		return ErrUnavailable
	}
	token := hex.EncodeToString(nonce)
	h, e := createKey(id, token)
	if e != nil {
		return e
	}
	committed := false
	defer func() {
		if committed {
			release(h)
		} else {
			status, _, _ := nDelete.Call(h, 0)
			if status != 0 {
				release(h)
			}
		}
	}()
	key := make([]byte, 32)
	defer clear(key)
	if _, e = rand.Read(key); e != nil {
		return ErrUnavailable
	}
	wrapped, e := crypt(h, key, false)
	if e != nil {
		return e
	}
	// Enrollment must exercise actual user-authenticated decryption before storing.
	check, e := crypt(h, wrapped, true)
	defer clear(check)
	if e != nil || !bytes.Equal(key, check) {
		return ErrUnavailable
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	iv := make([]byte, aead.NonceSize())
	if _, e = rand.Read(iv); e != nil {
		return ErrUnavailable
	}
	data := aead.Seal(nil, iv, raw, []byte("locklark/hello/v1/"+id+"/"+token))
	encoded, e := json.Marshal(sealed{1, token, wrapped, iv, data})
	if e != nil || len(encoded) > mygo.MaxSecretSize {
		return ErrUnavailable
	}
	defer clear(encoded)
	if store().Set(id, encoded) != nil {
		return ErrUnavailable
	}
	committed = true
	var previous sealed
	if json.Unmarshal(old, &previous) == nil {
		deleteKey(id, previous.Token)
	}
	return nil
}
func (hello) Load(id string) ([]byte, error) {
	if !validID(id) {
		return nil, ErrUnavailable
	}
	raw, e := store().Get(id)
	defer clear(raw)
	if e != nil || len(raw) > mygo.MaxSecretSize {
		return nil, ErrUnavailable
	}
	var blob sealed
	if json.Unmarshal(raw, &blob) != nil || blob.Version != 1 || len(blob.Wrapped) != 256 || len(blob.Nonce) != 12 || len(blob.Data) > 1600 {
		return nil, ErrUnavailable
	}
	h, e := openKey(id, blob.Token)
	if e != nil {
		return nil, e
	}
	defer release(h)
	key, e := crypt(h, blob.Wrapped, true)
	defer clear(key)
	if e != nil || len(key) != 32 {
		return nil, ErrUnavailable
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	value, e := aead.Open(nil, blob.Nonce, blob.Data, []byte("locklark/hello/v1/"+id+"/"+blob.Token))
	if e != nil {
		return nil, ErrUnavailable
	}
	return value, nil
}
func deleteKey(id, token string) error {
	h, e := openKey(id, token)
	if e != nil {
		return e
	}
	r, _, _ := nDelete.Call(h, 0)
	if r != 0 {
		release(h)
		return ErrUnavailable
	}
	return nil
}
func (hello) Delete(id string) error {
	if !validID(id) {
		return ErrUnavailable
	}
	raw, e := store().Get(id)
	defer clear(raw)
	if e != nil {
		return ErrUnavailable
	}
	var blob sealed
	if json.Unmarshal(raw, &blob) != nil || blob.Version != 1 {
		return ErrUnavailable
	}
	if deleteKey(id, blob.Token) != nil {
		return ErrUnavailable
	}
	if store().Delete(id) != nil {
		return ErrUnavailable
	}
	return nil
}
