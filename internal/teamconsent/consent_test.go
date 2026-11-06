package teamconsent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestExplicitTrustRequiresExactIndependentFingerprint(t *testing.T) {
	public := strings.Repeat("ab", 32)
	fp, err := Fingerprint(public)
	if err != nil || !ValidFingerprint(fp) {
		t.Fatal("public fingerprint setup")
	}
	for _, wrong := range []string{"", strings.ToUpper(fp), "SHA256:" + strings.Repeat("0", 64), fp + "extra"} {
		if Confirm(context.Background(), "sequencer", public, "", wrong) == nil {
			t.Fatal("unconfirmed fingerprint trusted")
		}
	}
	for _, line := range []string{"TRUST " + fp + "\r", "TRUST " + fp + "\n"} {
		at := 0
		if readConfirmation(context.Background(), func(context.Context) (byte, error) { b := line[at]; at++; return b, nil }, fp) != nil {
			t.Fatal("exact trust confirmation refused")
		}
	}
	for _, line := range []string{"yes\r", " TRUST " + fp + "\r", "TRUST " + fp + " \r", "TRUST " + strings.Repeat("x", 100) + "\r", "\x03", "\x1b"} {
		at := 0
		read := func(context.Context) (byte, error) {
			if at >= len(line) {
				return 0, errors.New("end")
			}
			b := line[at]
			at++
			return b, nil
		}
		if readConfirmation(context.Background(), read, fp) == nil {
			t.Fatal("non-exact consent accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if readConfirmation(ctx, func(context.Context) (byte, error) { return 'T', nil }, fp) == nil {
		t.Fatal("cancelled trust accepted")
	}
}
