package personal

import (
	"github.com/jihuayu/locklark/internal/origin"
	"golang.org/x/net/publicsuffix"
)

// A checkout frame is often a different origin from the top document (a payment
// or card form embedded in a merchant page). The extension can only propose that
// observation; this native policy is the authority and refuses anything that is
// not the same scheme + registrable domain.
//
// maxBrowserFrameID bounds the exact frame selector to the JavaScript safe
// integer range every browser uses for frame ids.
const maxBrowserFrameID = 9007199254740991

// BrowserCheckoutContext is the native-only cross-origin checkout assertion. It
// is stored next to, never instead of, the ordinary BrowserContext so the frame
// origin/document keep their existing meaning.
type BrowserCheckoutContext struct {
	TopOrigin     string `json:"top_origin"`
	TopDocumentID string `json:"top_document_id"`
	FrameID       int64  `json:"frame_id"`
}

// checkoutSite derives the registrable domain (eTLD+1) from an already strict
// HTTPS origin. x/net/publicsuffix carries both the ICANN and the private
// section, so two tenants of a private suffix such as github.io are distinct
// sites even though their last two labels are equal.
func checkoutSite(canonical string) (string, bool) {
	host := hostnameOf(canonical)
	if host == "" {
		return "", false
	}
	site, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || site == "" {
		return "", false
	}
	return site, true
}

// documentTokenOK mirrors the document-id alphabet the wire contract already
// enforces for BrowserContext.DocumentID.
func documentTokenOK(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// Valid applies the whole checkout policy to the already validated frame
// context. The top and frame must be distinct HTTPS origins on the same
// scheme+registrable domain, the two documents must differ, and the frame id
// must be an exact bounded positive integer. IP literals, IDN, opaque origins,
// public suffixes and malformed values fail inside origin.Parse/eTLD+1.
func (c BrowserCheckoutContext) Valid(frame BrowserContext) bool {
	if !frame.Valid() {
		return false
	}
	top, err := origin.Parse(c.TopOrigin)
	if err != nil || top != c.TopOrigin {
		return false
	}
	frameOrigin, err := origin.Parse(frame.Origin)
	if err != nil || frameOrigin != frame.Origin || frameOrigin == top {
		return false
	}
	if !documentTokenOK(c.TopDocumentID) || c.TopDocumentID == frame.DocumentID {
		return false
	}
	if c.FrameID < 1 || c.FrameID > maxBrowserFrameID {
		return false
	}
	topSite, ok := checkoutSite(top)
	if !ok {
		return false
	}
	frameSite, ok := checkoutSite(frameOrigin)
	if !ok || topSite != frameSite {
		return false
	}
	return true
}
