package browserhost

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/jihuayu/locklark/internal/personal"
)

// BrowserCheckout is the optional nested cross-origin checkout assertion a page
// may propose. It is never authoritative: the native policy in
// personal.BrowserCheckoutContext decides, before any profile metadata is read,
// whether the proposed context is acceptable.
type BrowserCheckout struct {
	TopOrigin     string `json:"top_origin"`
	TopDocumentID string `json:"top_document_id"`
	FrameID       int64  `json:"frame_id"`
}

func (c BrowserCheckout) personal() personal.BrowserCheckoutContext {
	return personal.BrowserCheckoutContext{TopOrigin: c.TopOrigin, TopDocumentID: c.TopDocumentID, FrameID: c.FrameID}
}

// clone gives the connection its own copy so a caller cannot mutate the public
// request after Handle returned and widen the captured review.
func (c *BrowserCheckout) clone() *BrowserCheckout {
	if c == nil {
		return nil
	}
	copied := *c
	return &copied
}

func sameCheckout(a, b *BrowserCheckout) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// parseBrowserCheckout is the whole nested-object contract: exactly the three
// documented keys, each present exactly once with the documented JSON type. It
// rejects duplicate keys, case aliases, unknown keys, null, arrays/objects,
// floats and trailing bytes. An explicit presence is a proposal, never a
// permission.
func parseBrowserCheckout(raw []byte) (*BrowserCheckout, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, ErrProtocol
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if first, e := dec.Token(); e != nil || first != json.Delim('{') {
		return nil, ErrProtocol
	}
	seen := map[string]bool{}
	var out BrowserCheckout
	for dec.More() {
		key, e := dec.Token()
		name, ok := key.(string)
		if e != nil || !ok || seen[name] || len(seen) >= 3 {
			return nil, ErrProtocol
		}
		seen[name] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil || len(value) == 0 || value[0] == '{' || value[0] == '[' || string(value) == "null" {
			return nil, ErrProtocol
		}
		switch name {
		case "top_origin":
			if value[0] != '"' || json.Unmarshal(value, &out.TopOrigin) != nil {
				return nil, ErrProtocol
			}
		case "top_document_id":
			if value[0] != '"' || json.Unmarshal(value, &out.TopDocumentID) != nil {
				return nil, ErrProtocol
			}
		case "frame_id":
			// A string, boolean or fraction is a type confusion attempt.
			if value[0] == '"' || string(value) == "true" || string(value) == "false" || json.Unmarshal(value, &out.FrameID) != nil {
				return nil, ErrProtocol
			}
			var exact float64
			if json.Unmarshal(value, &exact) != nil || exact != float64(out.FrameID) {
				return nil, ErrProtocol
			}
		default:
			return nil, ErrProtocol
		}
	}
	if last, e := dec.Token(); e != nil || last != json.Delim('}') {
		return nil, ErrProtocol
	}
	if _, e := dec.Token(); e != io.EOF {
		return nil, ErrProtocol
	}
	if !seen["top_origin"] || !seen["top_document_id"] || !seen["frame_id"] {
		return nil, ErrProtocol
	}
	return &out, nil
}

// checkoutFillOK keeps the checkout assertion card-only on the fill side without
// trusting the client to restate that fact.
//
// The allowlisted extension repeats profile_kind on the card listing, but its
// fill carries only the approved checkout selectors, so a checkout fill may
// arrive with an empty profile kind. The card-only rule is therefore decided
// natively: a checkout fill is accepted here only with credit_card or with no
// kind at all, and vault_ops.handleFillProfile additionally refuses any item
// whose pinned category is not credit_card. A non-checkout profile fill still
// never carries a kind.
func checkoutFillOK(r Request) bool {
	if r.Checkout == nil {
		return r.ProfileKind == ""
	}
	return r.ProfileKind == "" || r.ProfileKind == "credit_card"
}
