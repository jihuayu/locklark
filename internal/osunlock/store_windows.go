package osunlock

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"runtime"
	"sync"
	"syscall"
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
func Biometry() string {
	return "Windows Hello"
}
func Description() string {
	return "使用 Windows Hello 保护的密钥解锁；人脸、指纹或系统 PIN 由 Windows 验证。到期后需使用主密码完整解锁。"
}
func Requirement() string {
	return "需要 Windows Hello 与 Passport KSP；系统未配置 Hello 时只能使用完整解锁。"
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

var user32 = windows.NewLazySystemDLL("user32.dll")
var uGetForegroundWindow = user32.NewProc("GetForegroundWindow")
var uGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
var uIsWindowVisible = user32.NewProc("IsWindowVisible")
var uEnumWindows = user32.NewProc("EnumWindows")

var (
	enumWindowMu   sync.Mutex
	enumWindowOnce sync.Once
	enumWindowCB   uintptr
	enumWindowPID  uint32
	enumWindowHWND uintptr
)

func processWindowHandle() uintptr {
	currentPID := windows.GetCurrentProcessId()
	fg, _, _ := uGetForegroundWindow.Call()
	if fg != 0 {
		if vis, _, _ := uIsWindowVisible.Call(fg); vis != 0 {
			var pid uint32
			_, _, _ = uGetWindowThreadProcessId.Call(fg, uintptr(unsafe.Pointer(&pid)))
			if pid == currentPID {
				return fg
			}
		}
	}
	enumWindowMu.Lock()
	defer enumWindowMu.Unlock()
	enumWindowOnce.Do(func() {
		enumWindowCB = syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
			if vis, _, _ := uIsWindowVisible.Call(hwnd); vis == 0 {
				return 1
			}
			var pid uint32
			_, _, _ = uGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
			if pid == enumWindowPID {
				enumWindowHWND = hwnd
				return 0
			}
			return 1
		})
	})
	enumWindowPID = currentPID
	enumWindowHWND = 0
	_, _, _ = uEnumWindows.Call(enumWindowCB, 0)
	return enumWindowHWND
}

func attachUIContext(h uintptr, message string) {
	if hwnd := processWindowHandle(); hwnd != 0 {
		prop := wide("HWND Handle")
		_, _, _ = nSet.Call(h, uintptr(unsafe.Pointer(prop)), uintptr(unsafe.Pointer(&hwnd)), unsafe.Sizeof(hwnd), 0)
		runtime.KeepAlive(prop)
		runtime.KeepAlive(&hwnd)
	}
	if message != "" {
		if utf16, err := windows.UTF16FromString(message); err == nil && len(utf16) > 0 {
			ctxProp := wide("Use Context")
			_, _, _ = nSet.Call(h, uintptr(unsafe.Pointer(ctxProp)), uintptr(unsafe.Pointer(&utf16[0])), uintptr(len(utf16)*2), 0)
			runtime.KeepAlive(ctxProp)
			runtime.KeepAlive(utf16)
		}
	}
}

func classifyHelloStatus(status uintptr) error {
	if status == 0 {
		return nil
	}
	switch uint32(status) {
	case 0x80090036, // NTE_USER_CANCELLED
		0x800704C7, // HRESULT_FROM_WIN32(ERROR_CANCELLED)
		0x8010006E, // SCARD_W_CANCELLED_BY_USER
		0x000004C7: // ERROR_CANCELLED
		return ErrCancelled
	case 0x80090022: // NTE_SILENT_CONTEXT
		return ErrInteractionNotAllowed
	case 0x8010006B, // SCARD_W_WRONG_CHV
		0x8007052E, // HRESULT_FROM_WIN32(ERROR_LOGON_FAILURE)
		0x80098046: // WINBIO_E_DATA_PROTECTION_FAILURE
		return ErrAuthFailed
	default:
		return ErrUnavailable
	}
}

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
	runtime.KeepAlive(&n)
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
	runtime.KeepAlive(&n)
	runtime.KeepAlive(&v)
	if r != 0 || n != 4 {
		return 0, ErrUnavailable
	}
	return v, nil
}

// Passport KSP policy properties enforced before every CNG decrypt.
const (
	// NCRYPT_ALLOW_DECRYPT_FLAG. Exactly this flag: decrypt+sign (3) and
	// decrypt+key-agreement (5) are refused even though they include decrypt.
	helloKeyUsageDecrypt = 1
	// NgcCacheType 1 requires the cached key to be released only after user
	// authentication.
	helloNgcCacheTypeAuthenticated = 1
	// Export Policy 0 marks the key nonexportable.
	helloExportPolicyNone = 0
)

// helloPolicy is the enforced key property tuple. It is a pure value so the
// accepted and refused combinations are table-testable without the KSP.
type helloPolicy struct {
	usage  uint32
	cache  uint32
	export uint32
}

func (p helloPolicy) valid() bool {
	return p.usage == helloKeyUsageDecrypt && p.cache == helloNgcCacheTypeAuthenticated && p.export == helloExportPolicyNone
}

func setCacheType(h uintptr, val uint32) error {
	if setNumber(h, "NgcCacheType", val) == nil {
		return nil
	}
	return setNumber(h, "NgcCacheTypeProperty", val)
}

func getCacheType(h uintptr) (uint32, error) {
	if v, e := number(h, "NgcCacheType"); e == nil {
		return v, nil
	}
	return number(h, "NgcCacheTypeProperty")
}

func verify(h uintptr) error {
	usage, e := number(h, "Key Usage")
	if e != nil {
		return ErrUnavailable
	}
	cache, e := getCacheType(h)
	if e != nil {
		return ErrUnavailable
	}
	export, e := number(h, "Export Policy")
	if e != nil {
		return ErrUnavailable
	}
	if !(helloPolicy{usage: usage, cache: cache, export: export}).valid() {
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
	return u.User.Sid.String() + "//Passme/" + id + "/" + token, nil
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
	}{{"Length", 2048}, {"Key Usage", 1}, {"Export Policy", 0}} {
		if setNumber(h, prop.name, prop.value) != nil {
			return 0, ErrUnavailable
		}
	}
	if setCacheType(h, 1) != nil {
		return 0, ErrUnavailable
	}
	attachUIContext(h, "Passme：第 1/2 步 — 创建 Windows Hello 保护密钥")
	r, _, _ = nFinalize.Call(h, 0)
	if r != 0 {
		return 0, classifyHelloStatus(r)
	}
	if verify(h) != nil {
		return 0, ErrUnavailable
	}
	ok = true
	return h, nil
}

// helloPadPKCS1 is NCRYPT_PAD_PKCS1_FLAG. Microsoft Passport KSP rejects
// NCRYPT_PAD_OAEP_FLAG (0x80090027 / NTE_INVALID_PARAMETER) and accepts PKCS#1
// v1.5 for wrapping uniform random 256-bit AES-GCM keys.
const helloPadPKCS1 = 2

func crypt(h uintptr, input []byte, decrypt bool, contextMsg string) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrUnavailable
	}
	proc := nEncrypt
	if decrypt {
		if verify(h) != nil || setNumber(h, "PinCacheIsGestureRequired", 1) != nil {
			return nil, ErrUnavailable
		}
		attachUIContext(h, contextMsg)
		proc = nDecrypt
	}
	output := make([]byte, 512)
	var n uint32
	status, _, _ := proc.Call(h, uintptr(unsafe.Pointer(&input[0])), uintptr(len(input)), 0, uintptr(unsafe.Pointer(&output[0])), uintptr(len(output)), uintptr(unsafe.Pointer(&n)), helloPadPKCS1)
	runtime.KeepAlive(input)
	if status != 0 {
		clear(output)
		return nil, classifyHelloStatus(status)
	}
	if n > uint32(len(output)) {
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

func store() mygo.SecretsModule { return mygo.Secrets.Service("app.passme.hello.v1") }

// helloSecretGet is the Credential Manager read used before deleting a Hello
// item. Tests replace it to classify Get failures without opening the real
// store; the default path is unchanged.
var helloSecretGet = func(id string) ([]byte, error) { return store().Get(id) }

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
		release(h)
		if !committed {
			_ = deleteKey(id, token)
		}
	}()
	key := make([]byte, 32)
	defer clear(key)
	if _, e = rand.Read(key); e != nil {
		return ErrUnavailable
	}
	wrapped, e := crypt(h, key, false, "")
	if e != nil {
		return e
	}
	// Close the creation handle and re-open the persisted key so enrollment
	// verifies the exact openKey + verify + gesture-decrypt path used by Load().
	release(h)
	h = 0
	verifyHandle, e := openKey(id, token)
	if e != nil {
		return e
	}
	check, e := crypt(verifyHandle, wrapped, true, "Passme：第 2/2 步 — 验证 Windows Hello 解密授权")
	release(verifyHandle)
	defer clear(check)
	if e != nil {
		return e
	}
	if !bytes.Equal(key, check) {
		return ErrUnavailable
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	iv := make([]byte, aead.NonceSize())
	if _, e = rand.Read(iv); e != nil {
		return ErrUnavailable
	}
	data := aead.Seal(nil, iv, raw, []byte("passme/hello/v1/"+id+"/"+token))
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
	raw, e := helloSecretGet(id)
	defer clear(raw)
	if e != nil {
		if errors.Is(e, mygo.ErrSecretNotFound) {
			return nil, ErrNotFound
		}
		return nil, ErrUnavailable
	}
	if len(raw) > mygo.MaxSecretSize {
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
	key, e := crypt(h, blob.Wrapped, true, "Passme：使用 Windows Hello 解锁金库")
	defer clear(key)
	if e != nil {
		return nil, e
	}
	if len(key) != 32 {
		return nil, ErrUnavailable
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	value, e := aead.Open(nil, blob.Nonce, blob.Data, []byte("passme/hello/v1/"+id+"/"+blob.Token))
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
	raw, e := helloSecretGet(id)
	defer clear(raw)
	if e != nil {
		// Missing means already absent. Any other read failure is unknown and
		// must not proceed to KSP or Credential Manager deletion.
		if errors.Is(e, mygo.ErrSecretNotFound) {
			return ErrNotFound
		}
		return ErrUnavailable
	}
	var blob sealed
	if json.Unmarshal(raw, &blob) != nil || blob.Version != 1 {
		return ErrUnavailable
	}
	return deleteBoth(func() error { return deleteKey(id, blob.Token) }, func() error { return store().Delete(id) })
}
