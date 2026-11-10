// Package teamconsent obtains explicit public-key trust from the controlling
// terminal. It never accepts a private key or reads redirected process stdin.
package teamconsent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"
)

var ErrTrust = errors.New("team bootstrap trust not confirmed")

func Fingerprint(public string) (string, error) {
	raw, err := hex.DecodeString(public)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != public {
		return "", ErrTrust
	}
	digest := sha256.Sum256(raw)
	return "SHA256:" + hex.EncodeToString(digest[:]), nil
}
func ValidFingerprint(fp string) bool {
	if len(fp) != 71 || fp[:7] != "SHA256:" {
		return false
	}
	raw, err := hex.DecodeString(fp[7:])
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == fp[7:]
}
func Confirm(ctx context.Context, role, public, scope, expected string) error {
	actual, err := Fingerprint(public)
	if err != nil || !ValidFingerprint(expected) || actual != expected || role != "sequencer" && role != "owner" {
		return ErrTrust
	}
	if scope != "" {
		raw, err := hex.DecodeString(scope)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != scope {
			return ErrTrust
		}
	}
	input, output, err := openTerminal()
	if err != nil {
		return ErrTrust
	}
	defer input.Close()
	if output != input {
		defer output.Close()
	}
	return confirmTerminal(ctx, input, output, role, public, scope, expected)
}
func confirmTerminal(ctx context.Context, input *os.File, output io.Writer, role, public, scope, fp string) (ret error) {
	if ctx == nil || ctx.Err() != nil || !term.IsTerminal(int(input.Fd())) {
		return ErrTrust
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	state, err := term.MakeRaw(int(input.Fd()))
	if err != nil {
		return ErrTrust
	}
	defer func() {
		if term.Restore(int(input.Fd()), state) != nil {
			ret = ErrTrust
		}
	}()
	read, restore, err := prepareInput(input)
	if err != nil {
		return ErrTrust
	}
	defer func() {
		if restore() != nil {
			ret = ErrTrust
		}
	}()
	scopeDisplay := scope
	if scopeDisplay == "" {
		scopeDisplay = "(not bound at sequencer review)"
	}
	if _, err = fmt.Fprintf(output, "Team bootstrap trust review\r\n  Role:        %s\r\n  Public key:  %s\r\n  Fingerprint: %s\r\n  Scope:       %s\r\nVerify the fingerprint out of band before confirming.\r\nType TRUST %s to confirm: ", role, public, fp, scopeDisplay, fp); err != nil {
		return ErrTrust
	}
	defer fmt.Fprint(output, "\r\n")
	return readConfirmation(ctx, read, fp)
}
func readConfirmation(ctx context.Context, read func(context.Context) (byte, error), fp string) error {
	var line []byte
	defer func() { clear(line) }()
	for {
		ch, err := read(ctx)
		if err != nil || ctx.Err() != nil {
			return ErrTrust
		}
		switch ch {
		case '\r', '\n':
			if string(line) != "TRUST "+fp {
				return ErrTrust
			}
			return nil
		case 3, 4, 27:
			return ErrTrust
		case 8, 127:
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
		default:
			if ch < 32 || ch > 126 || len(line) >= 96 {
				return ErrTrust
			}
			line = append(line, ch)
		}
	}
}
