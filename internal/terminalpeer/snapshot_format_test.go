package terminalpeer

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// syntheticObservation uses only test fixtures. It never contains a native
// token, PID, path, TTY, or actor identity.
func syntheticObservation() Observation {
	return Observation{state: &observationState{
		socket: socketID{
			dev: 0xDEADBEEFCAFEBABE,
			ino: 0x1122334455667788,
		},
		observed: observed{
			token: peerToken{
				0xDEADBEEF,
				0xCAFEBABE,
				0x0BADF00D,
				0xFEEDFACE,
				0x01234567,
				0x89ABCDEF,
				0x13579BDF,
				0x2468ACE0,
			},
			path:       "/synthetic/SENSITIVE-PATH/peer-binary",
			pid:        0x12345678,
			pidVersion: 0x0BADF00D,
			euid:       0x0BADC0DE,
			startSec:   0x1122334455667788,
			startUsec:  0x99AABBCC,
			ttyDev:     0x0A0B0C0D,
		},
	}}
}

func syntheticFragments(observation Observation) []string {
	return []string{
		observation.state.observed.path,
		strconv.FormatInt(int64(observation.state.observed.pid), 10),
		strconv.FormatInt(int64(observation.state.observed.pidVersion), 10),
		strconv.FormatUint(uint64(observation.state.observed.euid), 10),
		strconv.FormatUint(observation.state.observed.startSec, 10),
		strconv.FormatUint(observation.state.observed.startUsec, 10),
		strconv.FormatUint(uint64(observation.state.observed.ttyDev), 10),
		fmt.Sprintf("%x", observation.state.observed.token[0]),
		fmt.Sprintf("%x", observation.state.observed.token[7]),
		fmt.Sprintf("%v", observation.state.observed.token),
		fmt.Sprintf("%v", observation.state.observed),
		fmt.Sprintf("%v", observation.state.socket),
	}
}

// pointerFragments excludes short hexadecimal fields that could coincidentally
// occur inside a pointer address. The long start pair, full token slice,
// struct dump, and path cannot be an address-only rendering.
func pointerFragments(observation Observation) []string {
	return []string{
		observation.state.observed.path,
		strconv.FormatUint(observation.state.observed.startSec, 10),
		fmt.Sprintf("%x", observation.state.observed.startSec),
		fmt.Sprintf("%v", observation.state.observed.token),
		fmt.Sprintf("%v", observation.state.observed),
		fmt.Sprintf("%v", observation.state.socket),
	}
}

func assertNoFragments(t *testing.T, formatted string, fragments []string) {
	t.Helper()
	for _, fragment := range fragments {
		if fragment != "" && strings.Contains(formatted, fragment) {
			t.Fatal("formatting disclosed a synthetic observation field")
		}
	}
}

func formatName(format string) string {
	return strings.ReplaceAll(format, "%", "pct")
}

func TestObservationFormatterValueMatrixIsOpaque(t *testing.T) {
	observation := syntheticObservation()
	fragments := syntheticFragments(observation)
	verbs := []string{
		"%v", "%+v", "%#v", "%s", "%q", "%d", "%b", "%o", "%O", "%x", "%X",
		"%c", "%f", "%F", "%e", "%E", "%g", "%G", "%t", "%U", "%y", "%k", "%z",
	}
	for _, format := range verbs {
		t.Run("verb_"+formatName(format), func(t *testing.T) {
			formatted := fmt.Sprintf(format, observation)
			if formatted != observationText {
				t.Fatal("value formatting was not the fixed opaque text")
			}
			assertNoFragments(t, formatted, fragments)
		})
	}

	widthAndPrecision := []struct {
		name   string
		format string
		args   []any
	}{
		{"width", "%25d", []any{observation}},
		{"left", "%-25s", []any{observation}},
		{"zero", "%025x", []any{observation}},
		{"precision", "%.2q", []any{observation}},
		{"width_precision", "%20.5f", []any{observation}},
		{"plus", "%+v", []any{observation}},
		{"sharp", "%#v", []any{observation}},
		{"dynamic", "%[2]*.[1]*[3]d", []any{3, 8, observation}},
	}
	for _, test := range widthAndPrecision {
		t.Run("width_"+test.name, func(t *testing.T) {
			formatted := fmt.Sprintf(test.format, test.args...)
			if formatted != observationText {
				t.Fatal("width, precision, or flag formatting was not the fixed opaque text")
			}
			assertNoFragments(t, formatted, fragments)
		})
	}
}

func TestObservationFormatterPointerAndTypeBounds(t *testing.T) {
	observation := syntheticObservation()
	fragments := syntheticFragments(observation)
	pointerSafe := pointerFragments(observation)

	for _, format := range []string{
		"%v", "%+v", "%#v", "%s", "%q", "%d", "%b", "%o", "%O", "%x", "%X",
		"%c", "%f", "%e", "%g", "%t", "%U", "%y", "%10d", "%.2q", "%#08x",
	} {
		t.Run("pointer_"+formatName(format), func(t *testing.T) {
			formatted := fmt.Sprintf(format, &observation)
			if formatted != observationText {
				t.Fatal("pointer formatting was not the fixed opaque text")
			}
			assertNoFragments(t, formatted, fragments)
		})
	}

	t.Run("pointer_value_badverb", func(t *testing.T) {
		formatted := fmt.Sprintf("%p", observation)
		if !strings.Contains(formatted, observationText) {
			t.Fatal("pointer verb on a value did not reach the opaque formatter")
		}
		assertNoFragments(t, formatted, fragments)
	})

	t.Run("pointer_address", func(t *testing.T) {
		formatted := fmt.Sprintf("%p", &observation)
		if !isHexAddress(formatted) {
			t.Fatal("pointer verb on a pointer was not a single address")
		}
		assertNoFragments(t, formatted, pointerSafe)
	})

	t.Run("nil_pointer_address", func(t *testing.T) {
		var nilObservation *Observation
		formatted := fmt.Sprintf("%p", nilObservation)
		if formatted != "0x0" {
			t.Fatal("nil pointer verb was not the fixed nil address")
		}
	})

	t.Run("type_value", func(t *testing.T) {
		formatted := fmt.Sprintf("%T", observation)
		if formatted != "terminalpeer.Observation" {
			t.Fatal("type verb on a value was not the type name")
		}
		assertNoFragments(t, formatted, fragments)
	})

	t.Run("type_pointer", func(t *testing.T) {
		formatted := fmt.Sprintf("%T", &observation)
		if formatted != "*terminalpeer.Observation" {
			t.Fatal("type verb on a pointer was not the pointer type name")
		}
		assertNoFragments(t, formatted, fragments)
	})
}

// TestObservationFormatterPercentWSpecialIsBounded covers fmt's non-error %w
// path. That path bypasses Formatter and may render the opaque state handle;
// it must never reach token, socket, PID, pidversion, path, start, or TTY
// fields. This package therefore does not claim %w is a fixed byte string.
func TestObservationFormatterPercentWSpecialIsBounded(t *testing.T) {
	observation := syntheticObservation()
	pointerSafe := pointerFragments(observation)
	value := any(observation)
	pointer := any(&observation)

	tests := []struct {
		name      string
		formatted func() string
	}{
		{"sprintf_value", func() string {
			format := "%w"
			return fmt.Sprintf(format, value)
		}},
		{"sprintf_pointer", func() string {
			format := "%w"
			return fmt.Sprintf(format, pointer)
		}},
		{"errorf_value", func() string {
			format := "wrap: %w"
			return fmt.Errorf(format, value).Error()
		}},
		{"errorf_pointer", func() string {
			format := "wrap: %w"
			return fmt.Errorf(format, pointer).Error()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			formatted := test.formatted()
			if !strings.Contains(formatted, "%!w") {
				t.Fatal("non-error wrap verb did not follow fmt's special path")
			}
			assertNoFragments(t, formatted, pointerSafe)
		})
	}
}

func TestObservationFormatterErrorAndContainerBounds(t *testing.T) {
	observation := syntheticObservation()
	fragments := syntheticFragments(observation)

	for _, test := range []struct {
		name   string
		format string
	}{
		{"error_v", "wrap: %v"},
		{"error_d", "wrap: %d"},
		{"error_invalid", "wrap: %y"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := fmt.Errorf(test.format, observation)
			if err == nil {
				t.Fatal("error formatting returned nil")
			}
			formatted := err.Error()
			if !strings.Contains(formatted, observationText) {
				t.Fatal("error formatting did not reach the opaque formatter")
			}
			assertNoFragments(t, formatted, fragments)
		})
	}

	containers := []struct {
		name  string
		value any
	}{
		{"slice", []Observation{observation}},
		{"array", [1]Observation{observation}},
		{"map", map[string]Observation{"key": observation}},
		{"struct_value", struct{ Peer Observation }{observation}},
		{"struct_pointer", &struct{ Peer Observation }{observation}},
		{"pointer_field", struct{ Peer *Observation }{&observation}},
	}
	for _, test := range containers {
		for _, format := range []string{"%v", "%+v", "%#v", "%d", "%x", "%q", "%s"} {
			t.Run(test.name+"_"+formatName(format), func(t *testing.T) {
				formatted := fmt.Sprintf(format, test.value)
				if !strings.Contains(formatted, observationText) {
					t.Fatal("container formatting did not reach the opaque formatter")
				}
				assertNoFragments(t, formatted, fragments)
			})
		}
	}
}

func isHexAddress(value string) bool {
	if !strings.HasPrefix(value, "0x") || len(value) <= 2 {
		return false
	}
	for _, digit := range value[2:] {
		if digit >= '0' && digit <= '9' {
			continue
		}
		if digit >= 'a' && digit <= 'f' {
			continue
		}
		return false
	}
	return true
}
