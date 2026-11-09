package personal

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// A profile fill discloses credit-card or identity fields, so it is a native
// approval stage of its own. The extension can only propose a target; the
// authenticated transaction commits one bounded read intent before any private
// value is handed to the native writer.
const browserProfileFillAction = "item.browser.profile.fill"

var ErrBrowserProfileFill = errors.New("browser profile fill refused or delivery unknown")

// BrowserProfileTarget pins the item revision, the public category and the full
// asserted browser context. Only the two sensitive profile categories qualify.
// A cross-origin checkout frame is an additional, optional assertion that only
// credit cards may carry.
type BrowserProfileTarget struct {
	ID       string
	Revision string
	Category string
	Context  BrowserContext
	Checkout *BrowserCheckoutContext
}

func validBrowserProfileCategory(category string) bool {
	return category == "credit_card" || category == "identity"
}

func (t BrowserProfileTarget) valid() bool {
	if !t.Context.Valid() || !idOK(t.ID) || !digestOK(t.Revision) || !validBrowserProfileCategory(t.Category) {
		return false
	}
	// Checkout is card-only and must satisfy the same policy the browser host
	// applied before it ever listed a card.
	if t.Checkout != nil {
		return t.Category == "credit_card" && t.Checkout.Valid(t.Context)
	}
	return true
}

// binding links the full context, the category and every checkout selector to
// the recorded intent without publishing any of them. The omitempty fields keep
// existing non-checkout bindings byte-identical.
func (t BrowserProfileTarget) binding(key []byte) (string, error) {
	checkout := BrowserCheckoutContext{}
	if t.Checkout != nil {
		checkout = *t.Checkout
	}
	raw, e := json.Marshal(struct {
		Category      string         `json:"category"`
		Context       BrowserContext `json:"context"`
		TopOrigin     string         `json:"top_origin,omitempty"`
		TopDocumentID string         `json:"top_document_id,omitempty"`
		FrameID       int64          `json:"frame_id,omitempty"`
	}{t.Category, t.Context, checkout.TopOrigin, checkout.TopDocumentID, checkout.FrameID})
	if e != nil {
		return "", e
	}
	defer clear(raw)
	derived, e := hkdf.Key(sha256.New, key, nil, "locklark/personal/browser-profile-fill/key/v1", 32)
	if e != nil {
		return "", ErrBrowserProfileFill
	}
	defer clear(derived)
	m := hmac.New(sha256.New, derived)
	m.Write([]byte("locklark/browser-profile-fill/v1\x00"))
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// NativeBrowserProfile is a one-use native-only grant. It never serializes and
// keeps no private value outside the native writer callback.
type NativeBrowserProfile struct {
	content *BrowserProfileContent
	until   time.Time
}

func (*NativeBrowserProfile) MarshalJSON() ([]byte, error) { return nil, ErrBrowserProfileFill }
func (*NativeBrowserProfile) String() string               { return "[native browser profile]" }
func (*NativeBrowserProfile) GoString() string             { return "[native browser profile]" }

func (p *NativeBrowserProfile) clear() {
	if p == nil {
		return
	}
	if p.content != nil {
		p.content.clear()
	}
	p.content = nil
	p.until = time.Time{}
}
