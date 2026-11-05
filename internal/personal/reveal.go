package personal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/vault"
)

type RevealTarget struct{ ID, Revision, Field string }

// DisclosureReceipt contains no value. An intent remains an intent even if a
// terminal write succeeds: neither that write nor a crash proves human receipt.
type DisclosureReceipt struct {
	Status  string `json:"status"`
	Session string `json:"session"`
	Intent  string `json:"intent"`
}

var ErrDisclosureOutput = errors.New("terminal disclosure incomplete; intent recorded, delivery unknown")

func revealAction(action string) bool {
	return action == "item.reveal.username" || action == "item.reveal.password"
}

func ValidRevealTarget(id, revision, field string) bool {
	return idOK(id) && digestOK(revision) && revealAction("item.reveal."+field)
}

// RevealLogin is a local-owner primitive, not an Agent capability. The CLI
// must obtain explicit consent and supply an interactive terminal writer.
// Values are JSON-quoted to prevent terminal control sequence injection.
func RevealLogin(path, pw string, key []byte, target RevealTarget, terminal io.Writer) (DisclosureReceipt, error) {
	return revealLogin(target, terminal, func() (result, error) {
		return command(path, pw, key, "item.reveal."+target.Field, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: target.Field})
	})
}

func revealLogin(target RevealTarget, terminal io.Writer, prepare func() (result, error)) (DisclosureReceipt, error) {
	if !ValidRevealTarget(target.ID, target.Revision, target.Field) || terminal == nil {
		return DisclosureReceipt{}, errors.New("invalid disclosure target or terminal")
	}
	return disclosePrepared(terminal, prepare)
}

func disclosePrepared(terminal io.Writer, prepare func() (result, error)) (DisclosureReceipt, error) {
	if terminal == nil {
		return DisclosureReceipt{}, errors.New("invalid disclosure terminal")
	}
	r, err := prepare()
	defer clear(r.value)
	if err != nil {
		return DisclosureReceipt{}, err
	}
	quoted := quoteDisclosure(r.value)
	defer clear(quoted)
	return writeDisclosure(terminal, quoted, r.session, r.intent)
}

func writeDisclosure(terminal io.Writer, quoted []byte, session, intent string) (DisclosureReceipt, error) {
	n, err := terminal.Write(quoted)
	if err != nil || n != len(quoted) {
		// A writer error may contain the secret. Never propagate its message.
		return DisclosureReceipt{}, ErrDisclosureOutput
	}
	return DisclosureReceipt{Status: "written-to-terminal", Session: session, Intent: intent}, nil
}

// JSON's mandatory escaping leaves C1 and Unicode format controls intact.
// Escape those too, including bidi overrides and supplementary-plane tags,
// while retaining printable Unicode and a lossless JSON string representation.
func quoteDisclosure(value []byte) []byte {
	quoted, _ := json.Marshal(string(value)) // A string is always JSON encodable.
	defer clear(quoted)
	out := make([]byte, 0, len(quoted)+2)
	for _, r := range string(quoted) {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			if r <= 0xffff {
				out = fmt.Appendf(out, "\\u%04x", r)
			} else {
				high, low := utf16.EncodeRune(r)
				out = fmt.Appendf(out, "\\u%04x\\u%04x", high, low)
			}
		} else {
			out = utf8.AppendRune(out, r)
		}
	}
	return append(out, '\r', '\n')
}
