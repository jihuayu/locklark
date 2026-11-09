package main

import (
	"crypto/rand"
	"errors"
	"fmt"
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
)

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
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}
	defer clear(entropy[:])
	f.CardTitle = syntheticCardTitle
	f.CardHolder = syntheticCardHolder
	f.CardNumber = "0000" + digitString(entropy[0:12])
	f.CardVerification = digitString(entropy[12:15])
	f.CardPIN = digitString(entropy[3:7])
	f.CardExpiry = fmt.Sprintf("%04d-%02d", cardYearBase+int(entropy[15])%cardYearSpan, 1+int(entropy[7])%12)
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
