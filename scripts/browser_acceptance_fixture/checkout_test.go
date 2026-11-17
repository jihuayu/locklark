package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// countingReader records how many bytes were pulled per Read so the test can
// observe the exact entropy slices without inspecting generated values.
type countingReader struct {
	chunks []int
	src    []byte
}

func (r *countingReader) Read(p []byte) (int, error) {
	if len(r.src) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.src)
	r.src = r.src[n:]
	r.chunks = append(r.chunks, n)
	return n, nil
}

// failAfterReader returns the prefix bytes, then fails. The generator must not
// leave partially generated card material behind.
type failAfterReader struct {
	remaining int
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("synthetic entropy exhausted")
	}
	n := min(len(p), r.remaining)
	for i := 0; i < n; i++ {
		p[i] = 0x5a
	}
	r.remaining -= n
	return n, nil
}

var (
	eightDigits = regexp.MustCompile(`^[0-9]{8}$`)
	panShape    = regexp.MustCompile(`^0000[0-9]{12}$`)
)

func assertCheckoutShape(t *testing.T, number, verification, pin, expiry string) {
	t.Helper()
	if len(number) != 16 || !panShape.MatchString(number) || !strings.HasPrefix(number, "0000") {
		t.Fatal("PAN is not exactly 0000 followed by 12 digits")
	}
	for name, value := range map[string]string{
		"verification": verification,
		"pin":          pin,
	} {
		if len(value) != 8 || strings.IndexFunc(value, func(r rune) bool {
			return r < '0' || r > '9'
		}) >= 0 {
			t.Fatalf("%s is not exactly eight ASCII digits", name)
		}
	}
	if !eightDigits.MatchString(verification) || !eightDigits.MatchString(pin) {
		t.Fatal("card verification and PIN must be eight decimal digits")
	}
	for i := 0; i < len(verification); i++ {
		if verification[i] < '0' || verification[i] > '9' {
			t.Fatal("verification byte is not an ASCII digit")
		}
	}
	for i := 0; i < len(pin); i++ {
		if pin[i] < '0' || pin[i] > '9' {
			t.Fatal("PIN byte is not an ASCII digit")
		}
	}
	yearText, monthText, ok := strings.Cut(expiry, "-")
	if !ok || len(yearText) != 4 || len(monthText) != 2 {
		t.Fatal("expiry is not YYYY-MM")
	}
	year, err := strconv.Atoi(yearText)
	if err != nil {
		t.Fatal("expiry year is not numeric")
	}
	month, err := strconv.Atoi(monthText)
	if err != nil {
		t.Fatal("expiry month is not numeric")
	}
	if year < cardYearBase || year >= cardYearBase+cardYearSpan {
		t.Fatal("expiry year is outside the synthetic window")
	}
	if month < 1 || month > 12 {
		t.Fatal("expiry month is out of range")
	}
}

func TestGenerateCheckoutCardRejectsNilEntropy(t *testing.T) {
	number, verification, pin, expiry, err := generateCheckoutCard(nil)
	if err == nil {
		t.Fatal("nil entropy reader must be rejected")
	}
	if number != "" || verification != "" || pin != "" || expiry != "" {
		t.Fatal("rejected generation must not return values")
	}
}

func TestGenerateCheckoutCardShapeWithCryptoRand(t *testing.T) {
	for i := 0; i < 128; i++ {
		number, verification, pin, expiry, err := generateCheckoutCard(rand.Reader)
		if err != nil {
			t.Fatalf("generation failed: %v", err)
		}
		assertCheckoutShape(t, number, verification, pin, expiry)
		if len(number) != 16 {
			t.Fatal("PAN length changed")
		}
	}
}

func TestGenerateCheckoutCardUsesNonOverlappingReads(t *testing.T) {
	reader := &countingReader{src: make([]byte, panEntropyBytes+cardVerificationBytes+cardPINBytes)}
	for i := range reader.src {
		reader.src[i] = byte(i*7 + 1)
	}
	number, verification, pin, expiry, err := generateCheckoutCard(reader)
	if err != nil {
		t.Fatal(err)
	}
	assertCheckoutShape(t, number, verification, pin, expiry)
	want := []int{panEntropyBytes, cardVerificationBytes, cardPINBytes}
	if fmt.Sprint(reader.chunks) != fmt.Sprint(want) {
		t.Fatalf("reads were %v, want disjoint %v", reader.chunks, want)
	}
	if len(reader.src) != 0 {
		t.Fatal("generator consumed unexpected extra entropy")
	}

	// Deterministically map the expected slices onto digits and compare. This
	// proves each field comes from its own byte range, not merely that random
	// outputs happen to differ.
	panBytes := make([]byte, panEntropyBytes)
	cvvBytes := make([]byte, cardVerificationBytes)
	pinBytes := make([]byte, cardPINBytes)
	for i := range panBytes {
		panBytes[i] = byte(i*7 + 1)
	}
	for i := range cvvBytes {
		cvvBytes[i] = byte((panEntropyBytes+i)*7 + 1)
	}
	for i := range pinBytes {
		pinBytes[i] = byte((panEntropyBytes+cardVerificationBytes+i)*7 + 1)
	}
	if number != panPrefix+digitString(panBytes[:panDigits]) {
		t.Fatal("PAN did not come from its dedicated slice")
	}
	if verification != digitString(cvvBytes) {
		t.Fatal("verification did not come from its dedicated slice")
	}
	if pin != digitString(pinBytes) {
		t.Fatal("PIN did not come from its dedicated slice")
	}
}

func TestGenerateCheckoutCardDeterministicIndependence(t *testing.T) {
	cases := []struct {
		name   string
		offset int
	}{
		{"pan", 0},
		{"verification", panEntropyBytes},
		{"pin", panEntropyBytes + cardVerificationBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := make([]byte, panEntropyBytes+cardVerificationBytes+cardPINBytes)
			before, beforeVerification, beforePIN, _, err := generateCheckoutCard(bytes.NewReader(base))
			if err != nil {
				t.Fatal(err)
			}
			mutated := append([]byte(nil), base...)
			for i := tc.offset; i < tc.offset+map[string]int{
				"pan":          panEntropyBytes,
				"verification": cardVerificationBytes,
				"pin":          cardPINBytes,
			}[tc.name]; i++ {
				mutated[i] ^= 0x11
			}
			after, afterVerification, afterPIN, _, err := generateCheckoutCard(bytes.NewReader(mutated))
			if err != nil {
				t.Fatal(err)
			}
			switch tc.name {
			case "verification":
				if beforeVerification == afterVerification {
					t.Fatal("verification ignored its own entropy slice")
				}
				if beforePIN != afterPIN {
					t.Fatal("PIN depends on verification entropy")
				}
			case "pin":
				if beforePIN == afterPIN {
					t.Fatal("PIN ignored its own entropy slice")
				}
				if beforeVerification != afterVerification {
					t.Fatal("verification depends on PIN entropy")
				}
			case "pan":
				if before == after {
					t.Fatal("PAN ignored its own entropy slice")
				}
				if beforePIN != afterPIN {
					t.Fatal("PIN depends on PAN entropy")
				}
			}
		})
	}
}

func TestGenerateCheckoutCardRejectsShortEntropy(t *testing.T) {
	total := panEntropyBytes + cardVerificationBytes + cardPINBytes
	for n := 0; n < total; n++ {
		number, verification, pin, expiry, err := generateCheckoutCard(&failAfterReader{remaining: n})
		if err == nil {
			t.Fatalf("short entropy of %d bytes was accepted", n)
		}
		if number != "" || verification != "" || pin != "" || expiry != "" {
			t.Fatalf("failed generation with %d bytes left a partial card", n)
		}
	}
}

func TestDigitStringMapsEveryByte(t *testing.T) {
	input := make([]byte, 256)
	for i := range input {
		input[i] = byte(i)
	}
	if got := digitString(input); len(got) != len(input) || !regexp.MustCompile(`^[0-9]{256}$`).MatchString(got) {
		t.Fatal("digitString did not produce one ASCII digit per byte")
	}
}
