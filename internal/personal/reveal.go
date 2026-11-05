package personal

import (
	"encoding/json"
	"errors"
	"io"

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
	r, err := prepare()
	defer clear(r.value)
	if err != nil {
		return DisclosureReceipt{}, err
	}
	quoted, err := json.Marshal(string(r.value))
	if err != nil {
		return DisclosureReceipt{}, ErrDisclosureOutput
	}
	quoted = append(quoted, '\r', '\n')
	defer clear(quoted)
	n, err := terminal.Write(quoted)
	if err != nil || n != len(quoted) {
		// A writer error may contain the secret. Never propagate its message.
		return DisclosureReceipt{}, ErrDisclosureOutput
	}
	return DisclosureReceipt{Status: "written-to-terminal", Session: r.session, Intent: r.intent}, nil
}
