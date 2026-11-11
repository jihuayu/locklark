package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// This helper creates one synthetic credit card through the ordinary
// authenticated Session mutation API (UnlockSession + a registered
// MutationGate + AddItem). It adds no product-only approval or fill path and
// never prints a value. It is only reached when the operator passes the
// explicit -checkout-card flag, so the default fixture stays byte-identical.
const (
	syntheticCardTitle  = "Browser acceptance card"
	syntheticCardHolder = "Synthetic Checkout Holder"
	syntheticCardBrand  = "visa"
	cardYearBase        = 2029
	cardYearSpan        = 7
	// The PAN read supplies its 12 random digits plus the two expiry limbs, so
	// the synthetic number is 0000 followed by 12 digits, as before. The
	// verification and PIN reads are independent and map one-to-one onto eight
	// decimal digits. No byte is ever shared between the PAN, CVV and PIN.
	panPrefix             = "0000"
	panDigits             = 12
	panExpiryBytes        = 2
	panEntropyBytes       = panDigits + panExpiryBytes
	cardVerificationBytes = 8
	cardPINBytes          = 8
)

// generateCheckoutCard reads all synthetic card material from entropy in
// non-overlapping reads: PAN digits plus the expiry limbs, card verification
// digits and PIN digits each come from their own read, so a deterministic
// reader can prove which bytes landed where. The expiry keeps its year and
// month range by reusing the original limb formulas on its dedicated bytes.
func generateCheckoutCard(entropy io.Reader) (number, verification, pin, expiry string, err error) {
	if entropy == nil {
		return "", "", "", "", errors.New("missing synthetic checkout entropy")
	}
	defer func() {
		if err != nil {
			number, verification, pin, expiry = "", "", "", ""
		}
	}()
	var pan [panEntropyBytes]byte
	defer clear(pan[:])
	var cvv [cardVerificationBytes]byte
	defer clear(cvv[:])
	var cardPIN [cardPINBytes]byte
	defer clear(cardPIN[:])
	if _, err = io.ReadFull(entropy, pan[:]); err != nil {
		return "", "", "", "", err
	}
	year := cardYearBase + int(pan[panDigits+1]%cardYearSpan)
	month := 1 + int(pan[panDigits]%12)
	if _, err = io.ReadFull(entropy, cvv[:]); err != nil {
		return "", "", "", "", err
	}
	if _, err = io.ReadFull(entropy, cardPIN[:]); err != nil {
		return "", "", "", "", err
	}
	return panPrefix + digitString(pan[:panDigits]),
		digitString(cvv[:]),
		digitString(cardPIN[:]),
		fmt.Sprintf("%04d-%02d", year, month),
		nil
}

// digitString maps already random bytes onto decimal digits. The values are
// disposable test data, never a real payment instrument.
func digitString(entropy []byte) string {
	out := make([]byte, len(entropy))
	for index, value := range entropy {
		out[index] = '0' + value%10
	}
	return string(out)
}

// checkoutCardValues fills the private synthetic card selectors on f. The PAN
// keeps an obviously non-issuer 0000 prefix so it can never be mistaken for a
// real card, while the remaining digits stay random enough to work as canaries.
func checkoutCardValues(f *fixture) error {
	number, verification, pin, expiry, err := generateCheckoutCard(rand.Reader)
	if err != nil {
		return err
	}
	f.CardTitle = syntheticCardTitle
	f.CardHolder = syntheticCardHolder
	f.CardNumber = number
	f.CardVerification = verification
	f.CardPIN = pin
	f.CardExpiry = expiry
	return nil
}

// createCheckoutCard creates the synthetic card in the same private vault as
// the login fixture, using only the ordinary add mutation under a registered
// gate. The PAN, CVV and PIN exist here to prove that a later page fill never
// receives the PIN and never writes an unapproved value.
func createCheckoutCard(f *fixture) error {
	if f == nil || f.Path == "" || f.Password == "" || f.Secret == "" {
		return errors.New("invalid synthetic checkout fixture")
	}
	if err := checkoutCardValues(f); err != nil {
		return err
	}
	key, err := personal.ParseSecret(f.Secret)
	if err != nil {
		return err
	}
	defer clear(key)
	session, err := personal.UnlockSession(f.Path, []byte(f.Password), key, time.Minute)
	if err != nil {
		return err
	}
	defer session.Lock()
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if err = session.RegisterMutation(gate); err != nil {
		return err
	}
	item := vault.Item{
		Kind:     "credit_card",
		Category: vault.CategoryCreditCard,
		Title:    f.CardTitle,
		CreditCard: &vault.CreditCardDetails{
			CardholderName: f.CardHolder,
			Type:           syntheticCardBrand,
			Number:         f.CardNumber,
			Verification:   f.CardVerification,
			ExpiryDate:     f.CardExpiry,
			PIN:            f.CardPIN,
		},
	}
	id, revision, err := session.AddItem(item, gate)
	if err != nil {
		return err
	}
	if id == "" || revision == "" {
		return errors.New("synthetic checkout card was not persisted")
	}
	f.CardID, f.CardRevision = id, revision
	return nil
}
