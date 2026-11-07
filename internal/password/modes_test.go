package password

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"testing"
)

const modesTestRedacted = "[redacted generated password]"

func TestModesDefaultOptions(t *testing.T) {
	want := GeneratorOptions{
		Mode:       ModeRandom,
		Length:     24,
		Digits:     true,
		Symbols:    true,
		WordCount:  5,
		Separator:  "hyphens",
		Capitalize: false,
		FullWords:  true,
		PINLength:  6,
	}
	if got := DefaultGeneratorOptions(); got != want {
		t.Fatalf("default options changed: got %+v want %+v", got, want)
	}
}

func TestModesRandomGeneration(t *testing.T) {
	cases := []struct {
		name    string
		length  int
		digits  bool
		symbols bool
	}{
		{"letters-8", 8, false, false},
		{"digits-8", 8, true, false},
		{"symbols-8", 8, false, true},
		{"all-8", 8, true, true},
		{"all-24", 24, true, true},
		{"max-256", 256, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alphabet := modesTestAlphabet(tc.digits, tc.symbols)
			wantBits := modesTestEntropy(len(alphabet), tc.length)
			for range 40 {
				value, profile, err := GenerateRandomPassword(tc.length, tc.digits, tc.symbols)
				if err != nil {
					t.Fatalf("generation failed: %v", err)
				}
				if len(value) != tc.length {
					t.Fatalf("length = %d, want %d", len(value), tc.length)
				}
				for i := range value {
					if strings.IndexByte(alphabet, value[i]) < 0 {
						t.Fatalf("byte %q escaped the enabled alphabet %q", value[i], alphabet)
					}
				}
				for _, class := range modesTestClasses(tc.digits, tc.symbols) {
					if !strings.ContainsAny(value, class.chars) {
						t.Fatalf("%s class missing from %q", class.name, value)
					}
				}
				if !tc.digits && strings.ContainsAny(value, "0123456789") {
					t.Fatalf("digit emitted while digits are disabled: %q", value)
				}
				if !tc.symbols && strings.ContainsAny(value, "!@#$%^&*()-_=+[]{};:,.<>?") {
					t.Fatalf("symbol emitted while symbols are disabled: %q", value)
				}
				wantProfile := Profile{
					Length:       tc.length,
					AlphabetSize: len(alphabet),
					EntropyBits:  wantBits,
				}
				if profile != wantProfile {
					t.Fatalf("profile = %+v, want %+v", profile, wantProfile)
				}
				opts := GeneratorOptions{Length: tc.length, Digits: tc.digits, Symbols: tc.symbols}
				if got := EntropyBitsFor(ModeRandom, opts); got != wantBits {
					t.Fatalf("entropy = %d, want %d", got, wantBits)
				}
			}
		})
	}

	if got := EntropyBitsFor(ModeRandom, DefaultGeneratorOptions()); got != 154 {
		t.Fatalf("default random entropy = %d, want 154", got)
	}
}

func TestModesRandomInvalidLengths(t *testing.T) {
	for _, length := range []int{math.MinInt, -1, 0, 1, 7, 257, 1000, math.MaxInt} {
		value, profile, err := GenerateRandomPassword(length, true, true)
		if !errors.Is(err, ErrInvalid) || value != "" || profile != (Profile{}) {
			t.Fatalf("length %d was not rejected without output: value=%q profile=%+v err=%v", length, value, profile, err)
		}
	}
}

func TestModesMemorableGeneration(t *testing.T) {
	words := modesTestWordSet()
	separators := []string{
		"hyphens", "spaces", "periods", "commas", "underscores",
		"numbers", "numbers-and-symbols", "-", "_", "|", "+", " ", ":",
	}
	for _, separator := range separators {
		for _, count := range []int{3, 5, 15} {
			t.Run(fmt.Sprintf("%s-%d", separator, count), func(t *testing.T) {
				for range 20 {
					value, err := GenerateMemorablePassword(count, separator, false)
					if err != nil {
						t.Fatalf("generation failed: %v", err)
					}
					parts := modesTestSplit(value, separator)
					if len(parts) != count {
						t.Fatalf("word count = %d, want %d in %q", len(parts), count, value)
					}
					if got := modesTestSeparatorCount(value, separator); got != count-1 {
						t.Fatalf("separator count = %d, want %d in %q", got, count-1, value)
					}
					for _, word := range parts {
						if word != strings.ToLower(word) {
							t.Fatalf("uncapitalized word %q is not lowercase", word)
						}
						if len(word) < 3 || len(word) > 10 {
							t.Fatalf("word length outside 3..10: %q", word)
						}
						if _, ok := words[word]; !ok {
							t.Fatalf("word %q is not in the embedded list", word)
						}
					}
				}
			})
		}
	}
}

func TestModesMemorableCapitalization(t *testing.T) {
	words := modesTestWordSet()
	for range 50 {
		value, err := GenerateMemorablePassword(5, "hyphens", true)
		if err != nil {
			t.Fatalf("generation failed: %v", err)
		}
		parts := strings.Split(value, "-")
		if len(parts) != 5 {
			t.Fatalf("word count = %d, want 5 in %q", len(parts), value)
		}
		for _, word := range parts {
			if len(word) < 3 || word[0] < 'A' || word[0] > 'Z' {
				t.Fatalf("word %q was not title-cased", word)
			}
			lower := strings.ToLower(word)
			if word[1:] != lower[1:] {
				t.Fatalf("word %q has non-lowercase trailing letters", word)
			}
			if _, ok := words[lower]; !ok {
				t.Fatalf("word %q is not in the embedded list", word)
			}
		}
	}
}

func TestModesMemorableInvalid(t *testing.T) {
	for _, count := range []int{math.MinInt, -1, 0, 1, 2, 16, 1000, math.MaxInt} {
		value, err := GenerateMemorablePassword(count, "hyphens", false)
		if !errors.Is(err, ErrInvalid) || value != "" {
			t.Fatalf("word count %d was not rejected without output: value=%q err=%v", count, value, err)
		}
	}
	for _, separator := range []string{"", "hyphen", "dashes", "hyphens-and-spaces", "::", "ab", "hyphens ", "\xff", "——"} {
		value, err := GenerateMemorablePassword(5, separator, false)
		if !errors.Is(err, ErrInvalid) || value != "" {
			t.Fatalf("separator %q was not rejected without output: value=%q err=%v", separator, value, err)
		}
	}
}

func TestModesWordList(t *testing.T) {
	size := WordListSize()
	if size < 256 {
		t.Fatalf("word list has %d words, want at least 256", size)
	}
	if size != len(wordList) {
		t.Fatalf("WordListSize() = %d, len(wordList) = %d", size, len(wordList))
	}
	seen := make(map[string]struct{}, size)
	for _, word := range wordList {
		if len(word) < 3 || len(word) > 10 {
			t.Fatalf("word %q length outside 3..10", word)
		}
		for i := range word {
			if word[i] < 'a' || word[i] > 'z' {
				t.Fatalf("word %q is not lowercase ASCII", word)
			}
		}
		if _, exists := seen[word]; exists {
			t.Fatalf("duplicate word %q", word)
		}
		seen[word] = struct{}{}
	}
	if len(seen) != size {
		t.Fatalf("unique word count = %d, want %d", len(seen), size)
	}
}

func TestModesPIN(t *testing.T) {
	for _, length := range []int{3, 4, 6, 12} {
		wantBits := modesTestEntropy(10, length)
		for range 50 {
			value, err := GeneratePIN(length)
			if err != nil {
				t.Fatalf("generation failed: %v", err)
			}
			if len(value) != length {
				t.Fatalf("PIN length = %d, want %d", len(value), length)
			}
			for i := range value {
				if value[i] < '0' || value[i] > '9' {
					t.Fatalf("PIN contains non-digit byte %q", value[i])
				}
			}
		}
		opts := GeneratorOptions{Mode: ModePIN, PINLength: length}
		value, bits, err := GenerateMode(opts)
		if err != nil || len(value) != length || bits != wantBits {
			t.Fatalf("GenerateMode PIN = (%q, %d, %v), want length %d bits %d", value, bits, err, length, wantBits)
		}
		if got := EntropyBitsFor(ModePIN, opts); got != wantBits {
			t.Fatalf("PIN entropy = %d, want %d", got, wantBits)
		}
	}
	for _, length := range []int{math.MinInt, -1, 0, 1, 2, 13, 100, math.MaxInt} {
		value, err := GeneratePIN(length)
		if !errors.Is(err, ErrInvalid) || value != "" {
			t.Fatalf("PIN length %d was not rejected without output: value=%q err=%v", length, value, err)
		}
	}
}

func TestModesEntropyBitsFor(t *testing.T) {
	wordCount := WordListSize()
	cases := []struct {
		name string
		mode Mode
		opts GeneratorOptions
		want int
	}{
		{"random-default", ModeRandom, DefaultGeneratorOptions(), modesTestEntropy(87, 24)},
		{"random-letters", ModeRandom, GeneratorOptions{Length: 24}, modesTestEntropy(52, 24)},
		{"random-digits", ModeRandom, GeneratorOptions{Length: 24, Digits: true}, modesTestEntropy(62, 24)},
		{"random-symbols", ModeRandom, GeneratorOptions{Length: 24, Symbols: true}, modesTestEntropy(77, 24)},
		{"random-all-8", ModeRandom, GeneratorOptions{Length: 8, Digits: true, Symbols: true}, modesTestEntropy(87, 8)},
		{"random-all-256", ModeRandom, GeneratorOptions{Length: 256, Digits: true, Symbols: true}, modesTestEntropy(87, 256)},
		{"memorable-3", ModeMemorable, GeneratorOptions{WordCount: 3}, modesTestEntropy(wordCount, 3)},
		{"memorable-5", ModeMemorable, GeneratorOptions{WordCount: 5}, modesTestEntropy(wordCount, 5)},
		{"memorable-15", ModeMemorable, GeneratorOptions{WordCount: 15}, modesTestEntropy(wordCount, 15)},
		{"pin-3", ModePIN, GeneratorOptions{PINLength: 3}, modesTestEntropy(10, 3)},
		{"pin-6", ModePIN, GeneratorOptions{PINLength: 6}, modesTestEntropy(10, 6)},
		{"pin-12", ModePIN, GeneratorOptions{PINLength: 12}, modesTestEntropy(10, 12)},
		{"empty-mode-is-random", Mode(""), GeneratorOptions{Length: 24, Digits: true, Symbols: true}, modesTestEntropy(87, 24)},
		{"invalid-random-low", ModeRandom, GeneratorOptions{Length: 7, Digits: true, Symbols: true}, 0},
		{"invalid-random-high", ModeRandom, GeneratorOptions{Length: 257, Digits: true, Symbols: true}, 0},
		{"invalid-memorable-low", ModeMemorable, GeneratorOptions{WordCount: 2}, 0},
		{"invalid-memorable-high", ModeMemorable, GeneratorOptions{WordCount: 16}, 0},
		{"invalid-pin-low", ModePIN, GeneratorOptions{PINLength: 2}, 0},
		{"invalid-pin-high", ModePIN, GeneratorOptions{PINLength: 13}, 0},
		{"unknown-mode", Mode("bogus"), DefaultGeneratorOptions(), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EntropyBitsFor(tc.mode, tc.opts); got != tc.want {
				t.Fatalf("EntropyBitsFor(%q, %+v) = %d, want %d", tc.mode, tc.opts, got, tc.want)
			}
		})
	}

	if got := EntropyBitsFor(ModeRandom, DefaultGeneratorOptions()); got != 154 {
		t.Fatalf("default random entropy = %d, want 154", got)
	}
	if got := EntropyBitsFor(ModeMemorable, GeneratorOptions{WordCount: 5}); got != 40 {
		t.Fatalf("default memorable entropy = %d, want 40", got)
	}
	if got := EntropyBitsFor(ModePIN, GeneratorOptions{PINLength: 6}); got != 19 {
		t.Fatalf("default PIN entropy = %d, want 19", got)
	}
}

func TestModesGenerateAPIDispatch(t *testing.T) {
	cases := []struct {
		name  string
		opts  GeneratorOptions
		mode  Mode
		words int
	}{
		{"default", DefaultGeneratorOptions(), ModeRandom, 0},
		{"short-random", GeneratorOptions{Mode: ModeRandom, Length: 8, Digits: true, Symbols: true}, ModeRandom, 0},
		{"memorable", GeneratorOptions{Mode: ModeMemorable, WordCount: 5, Separator: "hyphens", Capitalize: true}, ModeMemorable, 5},
		{"pin", GeneratorOptions{Mode: ModePIN, PINLength: 6}, ModePIN, 0},
		{"empty-mode", GeneratorOptions{Length: 12, Digits: true, Symbols: true}, ModeRandom, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, bits, err := GenerateMode(tc.opts)
			if err != nil {
				t.Fatalf("GenerateMode failed: %v", err)
			}
			if value == "" {
				t.Fatal("GenerateMode returned an empty value")
			}
			if want := EntropyBitsFor(tc.mode, tc.opts); bits != want {
				t.Fatalf("GenerateMode entropy = %d, want %d", bits, want)
			}
			switch tc.mode {
			case ModeRandom:
				if len(value) != tc.opts.Length {
					t.Fatalf("random length = %d, want %d", len(value), tc.opts.Length)
				}
			case ModeMemorable:
				if got := len(strings.Split(value, "-")); got != tc.opts.WordCount {
					t.Fatalf("memorable word count = %d, want %d", got, tc.opts.WordCount)
				}
			case ModePIN:
				if len(value) != tc.opts.PINLength {
					t.Fatalf("PIN length = %d, want %d", len(value), tc.opts.PINLength)
				}
			}

			generated, err := GeneratePassword(tc.opts)
			if err != nil {
				t.Fatalf("GeneratePassword failed: %v", err)
			}
			if generated.Mode() != tc.mode {
				t.Fatalf("Generated.Mode() = %q, want %q", generated.Mode(), tc.mode)
			}
			if generated.EntropyBits() != bits {
				t.Fatalf("Generated.EntropyBits() = %d, want %d", generated.EntropyBits(), bits)
			}
			if generated.Words() != tc.words {
				t.Fatalf("Generated.Words() = %d, want %d", generated.Words(), tc.words)
			}
			if generated.Value() == "" {
				t.Fatal("Generated.Value() is empty")
			}
		})
	}
}

func TestModesGeneratedRedaction(t *testing.T) {
	cases := []GeneratorOptions{
		DefaultGeneratorOptions(),
		{Mode: ModeMemorable, WordCount: 5, Separator: "hyphens", Capitalize: true},
		{Mode: ModePIN, PINLength: 6},
	}
	for _, opts := range cases {
		generated, err := GeneratePassword(opts)
		if err != nil {
			t.Fatalf("GeneratePassword failed: %v", err)
		}
		if generated.Value() == "" {
			t.Fatal("generated value is empty")
		}
		if got := generated.String(); got != modesTestRedacted {
			t.Fatalf("String() = %q, want redaction", got)
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if got := fmt.Sprintf(verb, generated); got != modesTestRedacted {
				t.Fatalf("fmt %s leaked or changed redaction: %q", verb, got)
			}
			if got := fmt.Sprintf(verb, &generated); got != modesTestRedacted {
				t.Fatalf("fmt %s on pointer leaked or changed redaction: %q", verb, got)
			}
		}
		for _, value := range []any{generated, &generated} {
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("MarshalJSON failed: %v", err)
			}
			if string(raw) != `"[redacted generated password]"` {
				t.Fatalf("JSON = %s, want a redacted string", raw)
			}
		}

		var logs bytes.Buffer
		for _, handler := range []slog.Handler{slog.NewTextHandler(&logs, nil), slog.NewJSONHandler(&logs, nil)} {
			slog.New(handler).Info("generated", "value", generated)
		}
		if strings.Contains(logs.String(), generated.Value()) {
			t.Fatal("generated value escaped through structured logging")
		}

		before := generated
		if err := json.Unmarshal([]byte(`"replacement"`), &generated); !errors.Is(err, ErrUnsupported) || generated != before {
			t.Fatalf("JSON unmarshal became an input path: err=%v changed=%v", err, generated != before)
		}
	}

	if err := json.Unmarshal([]byte(`"replacement"`), &Generated{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("zero Generated accepted JSON input: %v", err)
	}
}

func TestModesValidationDeterministic(t *testing.T) {
	invalid := []GeneratorOptions{
		{Mode: ModeRandom, Length: 7, Digits: true, Symbols: true},
		{Mode: ModeRandom, Length: 257},
		{Mode: ModeMemorable, WordCount: 2, Separator: "hyphens"},
		{Mode: ModeMemorable, WordCount: 5, Separator: "bogus"},
		{Mode: ModePIN, PINLength: 2},
		{Mode: Mode("bogus"), Length: 24},
	}
	for _, opts := range invalid {
		for range 3 {
			value, bits, err := GenerateMode(opts)
			if !errors.Is(err, ErrInvalid) || value != "" || bits != 0 {
				t.Fatalf("invalid options %+v returned output: value=%q bits=%d err=%v", opts, value, bits, err)
			}
			generated, err := GeneratePassword(opts)
			if !errors.Is(err, ErrInvalid) || generated != (Generated{}) {
				t.Fatalf("invalid options %+v returned a Generated value: %+v err=%v", opts, generated, err)
			}
		}
	}

	valid := DefaultGeneratorOptions()
	want := EntropyBitsFor(ModeRandom, valid)
	for range 10 {
		if got := EntropyBitsFor(ModeRandom, valid); got != want {
			t.Fatalf("entropy helper is not deterministic: got %d want %d", got, want)
		}
	}
}

func TestModesGeneratorRandomFailures(t *testing.T) {
	cases := []struct {
		name string
		run  func() (string, error)
	}{
		{"random-error-reader", func() (string, error) { return generateRandom(errorReader{}, 12, true, true) }},
		{"random-empty-reader", func() (string, error) { return generateRandom(bytes.NewReader(nil), 12, true, true) }},
		{"random-nil-reader", func() (string, error) { return generateRandom(nil, 12, true, true) }},
		{"memorable-error-reader", func() (string, error) { return generateMemorable(errorReader{}, 5, "hyphens", false) }},
		{"memorable-number-separator-error", func() (string, error) { return separatorValue(errorReader{}, "numbers") }},
		{"pin-error-reader", func() (string, error) { return generatePIN(errorReader{}, 6) }},
		{"pin-empty-reader", func() (string, error) { return generatePIN(bytes.NewReader(nil), 6) }},
		{"pin-nil-reader", func() (string, error) { return generatePIN(nil, 6) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, err := tc.run()
			if !errors.Is(err, ErrRandom) || value != "" {
				t.Fatalf("failure = (%q, %v), want empty value and ErrRandom", value, err)
			}
			if strings.Contains(err.Error(), "private-random-provider-marker") {
				t.Fatal("provider error details escaped")
			}
		})
	}

	// Invalid settings must be rejected before any random read.
	if _, err := generateRandom(panicReader{}, 7, true, true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid random length reached the source: %v", err)
	}
	if _, err := generateMemorable(panicReader{}, 2, "hyphens", false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid memorable count reached the source: %v", err)
	}
	if _, err := generateMemorable(panicReader{}, 5, "bogus", false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid separator reached the source: %v", err)
	}
	if _, err := generatePIN(panicReader{}, 2); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid PIN length reached the source: %v", err)
	}
}

func TestModesValidSeparator(t *testing.T) {
	for _, separator := range []string{
		"hyphens", "spaces", "periods", "commas", "underscores",
		"numbers", "numbers-and-symbols",
		"-", "_", ".", ",", " ", "|", "+", ":", "/", "0", "中",
	} {
		if !ValidSeparator(separator) {
			t.Fatalf("separator %q should be valid", separator)
		}
	}
	for _, separator := range []string{"", "hyphen", "dashes", "hyphens-and-spaces", "::", "ab", "hyphens ", "\xff", "——"} {
		if ValidSeparator(separator) {
			t.Fatalf("separator %q should be invalid", separator)
		}
	}
}

func modesTestWordSet() map[string]struct{} {
	set := make(map[string]struct{}, WordListSize())
	for _, word := range wordList {
		set[word] = struct{}{}
	}
	return set
}

func modesTestAlphabet(digits, symbols bool) string {
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if digits {
		alphabet += "0123456789"
	}
	if symbols {
		alphabet += "!@#$%^&*()-_=+[]{};:,.<>?"
	}
	return alphabet
}

type modesTestClass struct {
	name  string
	chars string
}

func modesTestClasses(digits, symbols bool) []modesTestClass {
	classes := []modesTestClass{
		{"lowercase", "abcdefghijklmnopqrstuvwxyz"},
		{"uppercase", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
	}
	if digits {
		classes = append(classes, modesTestClass{"digits", "0123456789"})
	}
	if symbols {
		classes = append(classes, modesTestClass{"symbols", "!@#$%^&*()-_=+[]{};:,.<>?"})
	}
	return classes
}

func modesTestEntropy(base, exponent int) int {
	return int(math.Floor(float64(exponent) * math.Log2(float64(base))))
}

func modesTestSplit(value, separator string) []string {
	switch separator {
	case "numbers":
		return strings.FieldsFunc(value, func(r rune) bool { return r >= '0' && r <= '9' })
	case "numbers-and-symbols":
		return strings.FieldsFunc(value, func(r rune) bool {
			return strings.ContainsRune("0123456789!@#$%^&*", r)
		})
	case "hyphens":
		return strings.Split(value, "-")
	case "spaces":
		return strings.Split(value, " ")
	case "periods":
		return strings.Split(value, ".")
	case "commas":
		return strings.Split(value, ",")
	case "underscores":
		return strings.Split(value, "_")
	default:
		return strings.Split(value, separator)
	}
}

func modesTestSeparatorCount(value, separator string) int {
	switch separator {
	case "numbers":
		return modesTestCountRunes(value, func(r rune) bool { return r >= '0' && r <= '9' })
	case "numbers-and-symbols":
		return modesTestCountRunes(value, func(r rune) bool {
			return strings.ContainsRune("0123456789!@#$%^&*", r)
		})
	case "hyphens":
		return strings.Count(value, "-")
	case "spaces":
		return strings.Count(value, " ")
	case "periods":
		return strings.Count(value, ".")
	case "commas":
		return strings.Count(value, ",")
	case "underscores":
		return strings.Count(value, "_")
	default:
		return strings.Count(value, separator)
	}
}

func modesTestCountRunes(value string, match func(rune) bool) int {
	count := 0
	for _, r := range value {
		if match(r) {
			count++
		}
	}
	return count
}
