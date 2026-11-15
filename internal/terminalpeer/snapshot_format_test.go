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

// TestObservationFormatterValueMatrixIsOpaque proves the real Formatter path:
// every data-bearing verb it receives renders exactly observationText, with no
// width, precision, flag, or invalid-verb leakage.
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

// TestObservationFormatterPointerAndTypeBounds distinguishes Formatter-backed
// pointer verbs from fmt's special paths. %T and %p never enter Formatter.
// %p on a value uses badVerb and renders the static typename plus the opaque
// state handle; it must not be mistaken for Formatter output merely because
// the typename is also "terminalpeer.Observation".
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

	for _, test := range []struct {
		name   string
		format string
	}{
		{"value_p", "%p"},
		{"value_sharp_p", "%#p"},
		{"value_width_p", "%20p"},
	} {
		t.Run(test.name, func(t *testing.T) {
			formatted := fmt.Sprintf(test.format, observation)
			if formatted == observationText {
				t.Fatal("bad-verb pointer output was mistaken for Formatter output")
			}
			assertBadVerbOpaqueHandle(t, formatted, "", "p", "terminalpeer.Observation", false)
			assertNoFragments(t, formatted, pointerSafe)
		})
	}

	for _, test := range []struct {
		name   string
		format string
	}{
		{"address_p", "%p"},
		{"address_sharp_p", "%#p"},
		{"address_width_p", "%20p"},
	} {
		t.Run(test.name, func(t *testing.T) {
			formatted := fmt.Sprintf(test.format, &observation)
			assertPointerAddress(t, formatted)
			assertNoFragments(t, formatted, pointerSafe)
		})
	}

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
// path. That path bypasses Formatter and renders the static typename plus the
// opaque state handle. It must never reach token, socket, PID, pidversion,
// path, start, or TTY fields, so this package does not claim %w is fixed bytes.
func TestObservationFormatterPercentWSpecialIsBounded(t *testing.T) {
	observation := syntheticObservation()
	pointerSafe := pointerFragments(observation)
	value := any(observation)
	pointer := any(&observation)

	tests := []struct {
		name    string
		lead    string
		pointer bool
		get     func() string
	}{
		{"sprintf_value", "", false, func() string {
			format := "%w"
			return fmt.Sprintf(format, value)
		}},
		{"sprintf_pointer", "", true, func() string {
			format := "%w"
			return fmt.Sprintf(format, pointer)
		}},
		{"errorf_value", "wrap: ", false, func() string {
			format := "wrap: %w"
			return fmt.Errorf(format, value).Error()
		}},
		{"errorf_pointer", "wrap: ", true, func() string {
			format := "wrap: %w"
			return fmt.Errorf(format, pointer).Error()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			formatted := test.get()
			if formatted == observationText {
				t.Fatal("bad-verb wrap output was mistaken for Formatter output")
			}
			typeName := "terminalpeer.Observation"
			if test.pointer {
				typeName = "*terminalpeer.Observation"
			}
			assertBadVerbOpaqueHandle(t, formatted, test.lead, "w", typeName, test.pointer)
			assertNoFragments(t, formatted, pointerSafe)
		})
	}
}

// TestObservationFormatterErrorAndContainerBounds proves ordinary error verbs
// use Formatter exactly, and that composites render their Observation members
// through Formatter rather than reflecting state fields.
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
			if formatted != "wrap: "+observationText {
				t.Fatal("error formatting was not the fixed opaque text")
			}
			assertNoFragments(t, formatted, fragments)
		})
	}

	containers := []struct {
		name                    string
		value                   any
		v, plus, sharp, decimal string
	}{
		{
			name:    "slice",
			value:   []Observation{observation},
			v:       "[terminalpeer.Observation]",
			plus:    "[terminalpeer.Observation]",
			sharp:   "[]terminalpeer.Observation{terminalpeer.Observation}",
			decimal: "[terminalpeer.Observation]",
		},
		{
			name:    "array",
			value:   [1]Observation{observation},
			v:       "[terminalpeer.Observation]",
			plus:    "[terminalpeer.Observation]",
			sharp:   "[1]terminalpeer.Observation{terminalpeer.Observation}",
			decimal: "[terminalpeer.Observation]",
		},
		{
			name:    "map",
			value:   map[string]Observation{"key": observation},
			v:       "map[key:terminalpeer.Observation]",
			plus:    "map[key:terminalpeer.Observation]",
			sharp:   `map[string]terminalpeer.Observation{"key":terminalpeer.Observation}`,
			decimal: "map[%!d(string=key):terminalpeer.Observation]",
		},
		{
			name:    "struct_value",
			value:   struct{ Peer Observation }{observation},
			v:       "{terminalpeer.Observation}",
			plus:    "{Peer:terminalpeer.Observation}",
			sharp:   "struct { Peer terminalpeer.Observation }{Peer:terminalpeer.Observation}",
			decimal: "{terminalpeer.Observation}",
		},
		{
			name:    "struct_pointer",
			value:   &struct{ Peer Observation }{observation},
			v:       "&{terminalpeer.Observation}",
			plus:    "&{Peer:terminalpeer.Observation}",
			sharp:   "&struct { Peer terminalpeer.Observation }{Peer:terminalpeer.Observation}",
			decimal: "&{terminalpeer.Observation}",
		},
		{
			name:    "pointer_field",
			value:   struct{ Peer *Observation }{&observation},
			v:       "{terminalpeer.Observation}",
			plus:    "{Peer:terminalpeer.Observation}",
			sharp:   "struct { Peer *terminalpeer.Observation }{Peer:terminalpeer.Observation}",
			decimal: "{terminalpeer.Observation}",
		},
	}
	otherContainerFormats := map[string]map[string]string{
		"slice": {
			"%x": "[terminalpeer.Observation]",
			"%q": "[terminalpeer.Observation]",
			"%s": "[terminalpeer.Observation]",
		},
		"array": {
			"%x": "[terminalpeer.Observation]",
			"%q": "[terminalpeer.Observation]",
			"%s": "[terminalpeer.Observation]",
		},
		"map": {
			"%x": "map[6b6579:terminalpeer.Observation]",
			"%q": `map["key":terminalpeer.Observation]`,
			"%s": "map[key:terminalpeer.Observation]",
		},
		"struct_value": {
			"%x": "{terminalpeer.Observation}",
			"%q": "{terminalpeer.Observation}",
			"%s": "{terminalpeer.Observation}",
		},
		"struct_pointer": {
			"%x": "&{terminalpeer.Observation}",
			"%q": "&{terminalpeer.Observation}",
			"%s": "&{terminalpeer.Observation}",
		},
		"pointer_field": {
			"%x": "{terminalpeer.Observation}",
			"%q": "{terminalpeer.Observation}",
			"%s": "{terminalpeer.Observation}",
		},
	}

	for _, test := range containers {
		for _, format := range []struct {
			name string
			verb string
			want string
		}{
			{"v", "%v", test.v},
			{"plus", "%+v", test.plus},
			{"sharp", "%#v", test.sharp},
			{"decimal", "%d", test.decimal},
		} {
			t.Run(test.name+"_"+format.name, func(t *testing.T) {
				formatted := fmt.Sprintf(format.verb, test.value)
				if formatted != format.want {
					t.Fatal("container formatting was not the expected opaque structure")
				}
				assertNoFragments(t, formatted, fragments)
			})
		}
		for _, format := range []string{"%x", "%q", "%s"} {
			t.Run(test.name+"_"+formatName(format), func(t *testing.T) {
				want := otherContainerFormats[test.name][format]
				if want == "" {
					t.Fatal("missing expected container structure")
				}
				formatted := fmt.Sprintf(format, test.value)
				if formatted != want {
					t.Fatal("container formatting was not the expected opaque structure")
				}
				assertNoFragments(t, formatted, fragments)
			})
		}
	}
}

// assertBadVerbOpaqueHandle checks fmt's exact special-path shape:
//
//	%!<verb>(<typename>={<address>})
//	%!<verb>(<typename>=&{<address>})
//
// The angle brackets are an opaque state handle, not observation fields. Width
// and # may change the address spelling; the wrapper remains the same.
func assertBadVerbOpaqueHandle(t *testing.T, formatted, lead, verb, typeName string, pointer bool) {
	t.Helper()
	prefix := lead + "%!" + verb + "(" + typeName + "={"
	if pointer {
		prefix = lead + "%!" + verb + "(" + typeName + "=&{"
	}
	const suffix = "})"
	if !strings.HasPrefix(formatted, prefix) || !strings.HasSuffix(formatted, suffix) {
		t.Fatal("special verb output had an unexpected wrapper structure")
	}
	handle := strings.TrimSpace(formatted[len(prefix) : len(formatted)-len(suffix)])
	if strings.HasPrefix(handle, "0x") {
		handle = handle[2:]
	}
	if !isHexDigits(handle) {
		t.Fatal("special verb did not contain only an opaque pointer handle")
	}
}

// assertPointerAddress accepts one address, optionally width-padded and
// optionally without the 0x prefix for %#p. It rejects any struct rendering.
func assertPointerAddress(t *testing.T, formatted string) {
	t.Helper()
	address := strings.TrimSpace(formatted)
	if strings.HasPrefix(address, "0x") {
		address = address[2:]
	}
	if !isHexDigits(address) {
		t.Fatal("pointer special path was not a single address")
	}
}

func isHexDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, digit := range value {
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
