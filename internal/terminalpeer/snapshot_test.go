package terminalpeer

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

func validObserved() observed {
	return observed{
		token:      peerToken{1, 2, 3, 4, 5, 6, 7, 8},
		path:       "/bin/echo",
		pid:        123,
		pidVersion: 456,
		euid:       501,
		startSec:   789,
		startUsec:  12,
		ttyDev:     0x10000001,
	}
}

func TestValidateObservedRejectsMalformedOnly(t *testing.T) {
	if err := validateObserved(validObserved(), 501); err != nil {
		t.Fatal("well-formed observation rejected")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*observed)
	}{
		{"zero pid", func(o *observed) { o.pid = 0 }},
		{"negative pid", func(o *observed) { o.pid = -1 }},
		{"zero pidversion", func(o *observed) { o.pidVersion = 0 }},
		{"negative pidversion", func(o *observed) { o.pidVersion = -1 }},
		{"zero start", func(o *observed) { o.startSec = 0 }},
		{"start usec bound", func(o *observed) { o.startUsec = 1_000_000 }},
		{"empty path", func(o *observed) { o.path = "" }},
		{"relative path", func(o *observed) { o.path = "bin/echo" }},
		{"unclean path", func(o *observed) { o.path = "/bin/../bin/echo" }},
		{"nul path", func(o *observed) { o.path = "/bin/ec\x00ho" }},
		{"newline path", func(o *observed) { o.path = "/bin/ec\nho" }},
		{"oversize path", func(o *observed) { o.path = "/" + strings.Repeat("a", maxTokenPath) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := validObserved()
			tc.mutate(&o)
			if err := validateObserved(o, 501); !errors.Is(err, ErrMalformed) {
				t.Fatal("malformed observation did not return ErrMalformed")
			}
		})
	}

	o := validObserved()
	if err := validateObserved(o, 502); !errors.Is(err, ErrMismatch) {
		t.Fatal("credential disagreement did not return ErrMismatch")
	}

	for _, ttyDev := range []uint32{0, math.MaxUint32} {
		o := validObserved()
		o.ttyDev = ttyDev
		if err := validateObserved(o, 501); !errors.Is(err, ErrUnavailable) {
			t.Fatal("missing controlling terminal did not return ErrUnavailable")
		}
	}
}

func TestObserveMissingArgumentIsUnavailable(t *testing.T) {
	if _, err := Observe(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil connection did not return ErrUnavailable")
	}
	if err := (Observation{}).Revalidate(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil revalidation did not return ErrUnavailable")
	}
}

func TestObservationFormattingIsFixed(t *testing.T) {
	observation := Observation{
		socket: socketID{dev: 111, ino: 222},
		observed: observed{
			token:      peerToken{333, 444, 555, 666, 777, 888, 999, 1000},
			path:       "/private/secret/path",
			pid:        12345,
			pidVersion: 67890,
			euid:       501,
			startSec:   2468,
			startUsec:  1357,
			ttyDev:     0x10000001,
		},
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		got := fmt.Sprintf(format, observation)
		if got != "terminalpeer.Observation" {
			t.Fatalf("%s formatting was not the fixed name", format)
		}
		for _, secret := range []string{"12345", "67890", "2468", "1357", "10000001", "secret", "private"} {
			if strings.Contains(got, secret) {
				t.Fatalf("%s formatting disclosed an observation field", format)
			}
		}
	}
}

func TestValidTokenPathIsShapeOnly(t *testing.T) {
	for _, path := range []string{"/bin/echo", "/Applications/Example.app/Contents/MacOS/Example", "/a b/c"} {
		if !validTokenPath(path) {
			t.Fatalf("absolute clean path rejected: %q", path)
		}
	}
	for _, path := range []string{"", "relative", "/a/../b", "/a//b", "/a/./b", "/a\x00b", "/a\rb", "/a\nb"} {
		if validTokenPath(path) {
			t.Fatalf("invalid path accepted: %q", path)
		}
	}
}
