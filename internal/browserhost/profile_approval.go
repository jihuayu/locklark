package browserhost

import (
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

// pendingProfile is one extension-proposed sensitive profile fill that has not
// yet been approved by the native owner. It stores only public selectors: the
// exact asserted browser context, the item revision/state snapshot, the
// category, the title and the review deadline. No approved field value is
// prepared, read into a response, or held here.
type pendingProfile struct {
	request     Request
	checkout    *BrowserCheckout
	title       string
	category    string
	deadline    time.Time
	epoch       uint64
	cancelEpoch uint64
}

// clearProfilePendingLocked drops exactly the captured reservation. A late
// callback carrying an older pending can never delete a newer replacement.
func (c *Connection) clearProfilePendingLocked(p *pendingProfile) bool {
	if p != nil && c.profile == p {
		c.profile = nil
		return true
	}
	return false
}

// ApproveProfile is called only by the native owner's explicit button. It
// revalidates the captured reservation (epoch, cancel epoch, pairing deadline,
// capability and session) before preparing the private profile projection. No
// browser request path can reach this function, and quick fill never calls it.
func (c *Connection) ApproveProfile(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	c.syncEpoch()
	c.expire()
	p := c.profile
	if p == nil || p.request.ID != id || p.epoch != c.epoch || p.cancelEpoch != c.cancelEpoch.Load() || !c.valid(p.request.Capability) || !c.now().Before(p.deadline) {
		return ErrProtocol
	}
	r := p.request
	// A checkout review is card-only; it never reaches the profile path with
	// any other category, even if a future caller built the pending by hand.
	if p.checkout != nil && p.category != "credit_card" {
		return ErrProtocol
	}
	c.clearProfilePendingLocked(p)
	// The checkout reservation is single use: the next fill must come from a
	// fresh native card listing.
	c.profileCheckout = nil
	s := c.session.Load()
	if s == nil {
		return c.refuse(r.ID)
	}
	epoch := c.epoch
	deadline := minTime(c.until, p.deadline)
	target := personal.BrowserProfileTarget{ID: r.ItemID, Revision: r.Revision, Category: p.category, Context: r.Context()}
	if p.checkout != nil {
		checkout := p.checkout.personal()
		target.Checkout = &checkout
	}
	// The authenticated intent and the private projection are created only
	// here, after native approval; until now the request was public metadata.
	grant, e := s.PrepareBrowserProfileFill(target)
	if e != nil {
		if writeErr := c.refuse(r.ID); writeErr != nil {
			return writeErr
		}
		return e
	}
	defer s.DiscardBrowserProfileFill(grant)
	// Own every response-owned map/slice for the whole writer lifetime, even
	// when Prepare/Consume/marshal/write fails.
	var fill *BrowserProfileFill
	defer func() { fill.clear() }()
	consumeErr := c.writer.WriteGranted(deadline, nil, func() (Response, error) {
		var response Response
		err := s.ConsumeBrowserProfileFill(grant, func(content *personal.BrowserProfileContent) error {
			// The serializer is ours now. Recheck the captured authority
			// immediately before any private field becomes a response value.
			if epoch != c.generation.Load() || c.closed.Load() || p.cancelEpoch != c.cancelEpoch.Load() || !c.now().Before(deadline) {
				return ErrProtocol
			}
			fill = browserProfileFillFromContent(content)
			fill.ItemID, fill.Revision = r.ItemID, r.Revision
			response = Response{V: 1, ID: r.ID, Type: "profile-fill", ProfileFill: fill}
			return nil
		})
		return response, err
	})
	if consumeErr != nil && !c.closed.Load() {
		_ = c.refuse(r.ID)
	}
	return consumeErr
}

// RejectProfile is the native refusal for one exact pending profile review. It
// always emits the fixed protocol refusal and never prepares private fields.
func (c *Connection) RejectProfile(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	c.syncEpoch()
	c.expire()
	p := c.profile
	if p == nil || p.request.ID != id {
		return ErrProtocol
	}
	c.clearProfilePendingLocked(p)
	c.profileCheckout = nil
	return c.refuse(p.request.ID)
}

// browserProfileFillFromContent projects the approved, whitelisted content into
// the unchanged profile-fill DTO. It runs only inside the granted writer
// callback. The private byte slices are converted to protocol strings here (an
// unavoidable protocol copy) and never read while the native UI is drawing.
func browserProfileFillFromContent(content *personal.BrowserProfileContent) *BrowserProfileFill {
	fill := &BrowserProfileFill{Category: content.Category, Fields: map[string]string{}}
	for _, v := range content.Fields {
		if v.Name == "" || len(v.Name) > 128 || !allowedProfileFieldName(v.Name) {
			continue
		}
		fill.Fields[v.Name] = string(v.Value)
	}
	switch content.Category {
	case "credit_card":
		card := &BrowserCreditCardFill{}
		for _, v := range content.Card {
			switch v.Name {
			case "cardholder_name":
				card.CardholderName = string(v.Value)
			case "type":
				card.Type = string(v.Value)
			case "number":
				card.Number = string(v.Value)
			case "verification":
				card.Verification = string(v.Value)
			case "expiry_date":
				card.ExpiryDate = string(v.Value)
			case "exp_month":
				card.ExpMonth = string(v.Value)
			case "exp_year":
				card.ExpYear = string(v.Value)
			case "exp_year_short":
				card.ExpYearShort = string(v.Value)
			}
		}
		fill.CreditCard = card
	case "identity":
		ident := &BrowserIdentitySummary{}
		for _, v := range content.Identity {
			switch v.Name {
			case "title":
				ident.Title = string(v.Value)
			case "first_name":
				ident.FirstName = string(v.Value)
			case "middle_name":
				ident.MiddleName = string(v.Value)
			case "last_name":
				ident.LastName = string(v.Value)
			case "birth_date":
				ident.BirthDate = string(v.Value)
			case "company":
				ident.Company = string(v.Value)
			case "department":
				ident.Department = string(v.Value)
			case "job_title":
				ident.JobTitle = string(v.Value)
			case "email":
				ident.Email = string(v.Value)
			case "phone":
				ident.Phone = string(v.Value)
			case "address_line1":
				ident.AddressLine1 = string(v.Value)
			case "address_line2":
				ident.AddressLine2 = string(v.Value)
			case "city":
				ident.City = string(v.Value)
			case "state":
				ident.State = string(v.Value)
			case "postal_code":
				ident.PostalCode = string(v.Value)
			case "country":
				ident.Country = string(v.Value)
			case "website":
				ident.Website = string(v.Value)
			}
		}
		fill.Identity = ident
	}
	return fill
}

// allowedProfileFieldName mirrors the personal projection's explicit
// page-field whitelist. Card PIN and identity SSN/passport/licence identifiers
// are deliberately absent, so even a compromised projection cannot widen the
// protocol surface.
var allowedProfileFieldNames = map[string]bool{
	"cc-name": true, "cc-number": true, "cc-exp": true, "cc-exp-month": true,
	"cc-exp-year": true, "cc-exp-year-short": true, "cc-csc": true, "cc-type": true,
	"honorific-prefix": true, "given-name": true, "additional-name": true,
	"family-name": true, "name": true, "organization": true,
	"organization-title": true, "email": true, "tel": true, "street-address": true,
	"address-line1": true, "address-line2": true, "address-level2": true,
	"address-level1": true, "postal-code": true, "country": true,
	"country-name": true, "bday": true,
}

func allowedProfileFieldName(name string) bool {
	if allowedProfileFieldNames[name] {
		return true
	}
	// Never accept a pin/ssn/passport/licence-shaped selector even if a future
	// projection accidentally emits one.
	switch strings.ToLower(strings.ReplaceAll(name, "_", "-")) {
	case "pin", "cc-pin", "ssn", "passport", "passport-number", "license", "license-number", "licence", "licence-number":
		return false
	}
	return false
}

// clear wipes response-owned profile values. Map entries and struct fields are
// emptied before the references are dropped by the caller.
func (f *BrowserProfileFill) clear() {
	if f == nil {
		return
	}
	for key := range f.Fields {
		f.Fields[key] = ""
	}
	f.Fields = nil
	if c := f.CreditCard; c != nil {
		*c = BrowserCreditCardFill{}
	}
	f.CreditCard = nil
	if i := f.Identity; i != nil {
		*i = BrowserIdentitySummary{}
	}
	f.Identity = nil
	f.ItemID, f.Revision, f.Category = "", "", ""
}
