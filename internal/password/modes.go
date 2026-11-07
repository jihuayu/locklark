package password

import (
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"unicode/utf8"
)

const (
	minRandomLength   = 8
	maxRandomLength   = MaxLength
	minMemorableWords = 3
	maxMemorableWords = 15
	minPINLength      = 3
	maxPINLength      = 12
)

const (
	lowercaseAlphabet = "abcdefghijklmnopqrstuvwxyz"
	uppercaseAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitAlphabet     = "0123456789"
	symbolAlphabet    = "!@#$%^&*()-_=+[]{};:,.<>?"
)

const (
	redactedGeneratedPassword = "[redacted generated password]"
	redactedGeneratedJSON     = `"[redacted generated password]"`
)

// Mode selects a password generator strategy. The original Policy-based
// Generate function is unaffected by these values.
type Mode string

const (
	ModeRandom    Mode = "random"
	ModeMemorable Mode = "memorable"
	ModePIN       Mode = "pin"
)

// GeneratorOptions carries the settings for every generator mode. Fields that
// do not apply to the selected mode are ignored. FullWords is retained for
// 1Password-style UI parity; the memorable generator always emits full words.
type GeneratorOptions struct {
	Mode       Mode
	Length     int
	Digits     bool
	Symbols    bool
	WordCount  int
	Separator  string
	Capitalize bool
	FullWords  bool
	PINLength  int
}

// DefaultGeneratorOptions returns the defaults used by the desktop generator.
func DefaultGeneratorOptions() GeneratorOptions {
	return GeneratorOptions{
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
}

// Generated is a generated value with non-sensitive metadata. The value is
// deliberately unexported: callers that need to display or copy it use Value,
// while formatting, JSON encoding and structured logging emit only a marker.
type Generated struct {
	secret      string
	mode        Mode
	entropyBits int
	words       int
}

// Value returns the generated password. Treat the result as sensitive.
func (g Generated) Value() string { return g.secret }

// EntropyBits returns the combinatorial entropy estimate for the options used
// to generate the value.
func (g Generated) EntropyBits() int { return g.entropyBits }

// Mode reports the mode that produced the value.
func (g Generated) Mode() Mode { return g.mode }

// Words reports the number of words used by memorable mode, or zero for the
// random and PIN modes.
func (g Generated) Words() int { return g.words }

// String redacts the value so accidental printing is safe.
func (g Generated) String() string { return redactedGeneratedPassword }

// Format redacts the value for every fmt verb, including %v, %+v and %#v.
func (Generated) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, redactedGeneratedPassword)
}

// MarshalJSON never emits the generated value.
func (Generated) MarshalJSON() ([]byte, error) {
	return []byte(redactedGeneratedJSON), nil
}

// UnmarshalJSON prevents JSON becoming an alternate secret input path.
func (*Generated) UnmarshalJSON([]byte) error { return ErrUnsupported }

// LogValue redacts the value when the struct is passed to log/slog.
func (Generated) LogValue() slog.Value {
	return slog.StringValue(redactedGeneratedPassword)
}

// GenerateMode returns a generated value and its entropy estimate. This is the
// simple string-returning API for callers that do not need metadata.
func GenerateMode(opts GeneratorOptions) (string, int, error) {
	value, bits, _, _, err := generateMode(opts)
	if err != nil {
		return "", 0, err
	}
	return value, bits, nil
}

// GeneratePassword returns a redacting Generated value. It uses exactly the
// same validation and generation logic as GenerateMode.
func GeneratePassword(opts GeneratorOptions) (Generated, error) {
	value, bits, words, mode, err := generateMode(opts)
	if err != nil {
		return Generated{}, err
	}
	return Generated{secret: value, mode: mode, entropyBits: bits, words: words}, nil
}

func generateMode(opts GeneratorOptions) (value string, bits, words int, mode Mode, err error) {
	mode = canonicalMode(opts.Mode)
	switch mode {
	case ModeRandom:
		generated, profile, genErr := GenerateRandomPassword(opts.Length, opts.Digits, opts.Symbols)
		if genErr != nil {
			return "", 0, 0, mode, genErr
		}
		return generated, profile.EntropyBits, 0, mode, nil
	case ModeMemorable:
		generated, genErr := GenerateMemorablePassword(opts.WordCount, opts.Separator, opts.Capitalize)
		if genErr != nil {
			return "", 0, 0, mode, genErr
		}
		return generated, EntropyBitsFor(mode, opts), opts.WordCount, mode, nil
	case ModePIN:
		generated, genErr := GeneratePIN(opts.PINLength)
		if genErr != nil {
			return "", 0, 0, mode, genErr
		}
		return generated, EntropyBitsFor(mode, opts), 0, mode, nil
	default:
		return "", 0, 0, mode, ErrInvalid
	}
}

// GenerateRandomPassword generates a random password from lowercase, uppercase,
// optional digits and optional symbols. The length bounds intentionally differ
// from the strict 128-bit Policy API so short 8-12 character requests work.
// The profile follows the full enabled alphabet; the class-presence guarantee
// makes its entropy a slight upper bound on the exact combinatorial space.
func GenerateRandomPassword(length int, digits, symbols bool) (string, Profile, error) {
	if length < minRandomLength || length > maxRandomLength {
		return "", Profile{}, ErrInvalid
	}
	alphabet := randomAlphabet(digits, symbols)
	profile := Profile{
		Length:       length,
		AlphabetSize: len(alphabet),
		EntropyBits:  floorLog2Power(len(alphabet), length),
	}
	value, err := generateRandom(rand.Reader, length, digits, symbols)
	if err != nil {
		return "", Profile{}, err
	}
	return value, profile, nil
}

func generateRandom(source io.Reader, length int, digits, symbols bool) (string, error) {
	if length < minRandomLength || length > maxRandomLength {
		return "", ErrInvalid
	}
	if source == nil {
		return "", ErrRandom
	}

	alphabet := randomAlphabet(digits, symbols)
	classes := enabledClasses(digits, symbols)
	out := make([]byte, 0, length)

	// Every enabled class gets one guaranteed character. The remaining draws
	// come from the full alphabet, then the whole slice is shuffled so the
	// guaranteed positions are not observable.
	for _, class := range classes {
		index, err := randomIndex(source, len(class))
		if err != nil {
			clear(out)
			return "", err
		}
		out = append(out, class[index])
	}
	for len(out) < length {
		index, err := randomIndex(source, len(alphabet))
		if err != nil {
			clear(out)
			return "", err
		}
		out = append(out, alphabet[index])
	}
	for i := len(out) - 1; i > 0; i-- {
		j, err := randomIndex(source, i+1)
		if err != nil {
			clear(out)
			return "", err
		}
		out[i], out[j] = out[j], out[i]
	}
	defer clear(out)
	return string(out), nil
}

// GenerateMemorablePassword generates a words-based password. separator may be
// one of the named separators accepted by ValidSeparator or any single
// character literal.
func GenerateMemorablePassword(wordCount int, separator string, capitalize bool) (string, error) {
	if wordCount < minMemorableWords || wordCount > maxMemorableWords || !ValidSeparator(separator) {
		return "", ErrInvalid
	}
	return generateMemorable(rand.Reader, wordCount, separator, capitalize)
}

func generateMemorable(source io.Reader, wordCount int, separator string, capitalize bool) (string, error) {
	if wordCount < minMemorableWords || wordCount > maxMemorableWords || !ValidSeparator(separator) {
		return "", ErrInvalid
	}
	if source == nil {
		return "", ErrRandom
	}

	var out strings.Builder
	out.Grow(wordCount * 10)
	for i := range wordCount {
		index, err := randomIndex(source, WordListSize())
		if err != nil {
			return "", err
		}
		word := wordList[index]
		if capitalize {
			word = capitalizeWord(word)
		}
		if i > 0 {
			between, sepErr := separatorValue(source, separator)
			if sepErr != nil {
				return "", sepErr
			}
			out.WriteString(between)
		}
		out.WriteString(word)
	}
	return out.String(), nil
}

// GeneratePIN generates a numeric PIN. crypto/rand indices are drawn with
// rejection sampling, so every digit is equally likely.
func GeneratePIN(length int) (string, error) {
	if length < minPINLength || length > maxPINLength {
		return "", ErrInvalid
	}
	return generatePIN(rand.Reader, length)
}

func generatePIN(source io.Reader, length int) (string, error) {
	if length < minPINLength || length > maxPINLength {
		return "", ErrInvalid
	}
	if source == nil {
		return "", ErrRandom
	}

	out := make([]byte, length)
	for i := range out {
		index, err := randomIndex(source, 10)
		if err != nil {
			clear(out)
			return "", err
		}
		out[i] = byte('0' + index)
	}
	defer clear(out)
	return string(out), nil
}

// EntropyBitsFor returns the combinatorial entropy estimate for a mode without
// generating a value. It follows the specified alphabet and word-list formulas;
// class-presence guarantees and random separators are not separately modeled.
// Invalid lengths, word counts or modes return zero.
func EntropyBitsFor(mode Mode, opts GeneratorOptions) int {
	switch canonicalMode(mode) {
	case ModeRandom:
		if opts.Length < minRandomLength || opts.Length > maxRandomLength {
			return 0
		}
		return floorLog2Power(len(randomAlphabet(opts.Digits, opts.Symbols)), opts.Length)
	case ModeMemorable:
		if opts.WordCount < minMemorableWords || opts.WordCount > maxMemorableWords {
			return 0
		}
		return floorLog2Power(WordListSize(), opts.WordCount)
	case ModePIN:
		if opts.PINLength < minPINLength || opts.PINLength > maxPINLength {
			return 0
		}
		return floorLog2Power(10, opts.PINLength)
	default:
		return 0
	}
}

// ValidSeparator reports whether a memorable password separator is supported.
// The named separators are "hyphens", "spaces", "periods", "commas",
// "underscores", "numbers" and "numbers-and-symbols"; any single character is
// also accepted as a literal separator.
func ValidSeparator(name string) bool {
	switch name {
	case "hyphens", "spaces", "periods", "commas", "underscores", "numbers", "numbers-and-symbols":
		return true
	}
	return validLiteralSeparator(name)
}

func validLiteralSeparator(name string) bool {
	return name != "" && utf8.ValidString(name) && utf8.RuneCountInString(name) == 1
}

func separatorValue(source io.Reader, separator string) (string, error) {
	switch separator {
	case "hyphens":
		return "-", nil
	case "spaces":
		return " ", nil
	case "periods":
		return ".", nil
	case "commas":
		return ",", nil
	case "underscores":
		return "_", nil
	case "numbers":
		index, err := randomIndex(source, 10)
		if err != nil {
			return "", err
		}
		return string(byte('0' + index)), nil
	case "numbers-and-symbols":
		const choices = "0123456789!@#$%^&*"
		index, err := randomIndex(source, len(choices))
		if err != nil {
			return "", err
		}
		return string(choices[index]), nil
	default:
		if validLiteralSeparator(separator) {
			return separator, nil
		}
		return "", ErrInvalid
	}
}

func capitalizeWord(word string) string {
	if word == "" {
		return word
	}
	out := []byte(word)
	if out[0] >= 'a' && out[0] <= 'z' {
		out[0] -= 'a' - 'A'
	}
	return string(out)
}

func canonicalMode(mode Mode) Mode {
	if mode == "" {
		return ModeRandom
	}
	return mode
}

func randomAlphabet(digits, symbols bool) string {
	alphabet := lowercaseAlphabet + uppercaseAlphabet
	if digits {
		alphabet += digitAlphabet
	}
	if symbols {
		alphabet += symbolAlphabet
	}
	return alphabet
}

func enabledClasses(digits, symbols bool) []string {
	classes := make([]string, 0, 4)
	classes = append(classes, lowercaseAlphabet, uppercaseAlphabet)
	if digits {
		classes = append(classes, digitAlphabet)
	}
	if symbols {
		classes = append(classes, symbolAlphabet)
	}
	return classes
}

// randomIndex draws a uniform index in [0, size). crypto/rand.Int performs
// rejection sampling internally, so no modulo bias is introduced.
func randomIndex(source io.Reader, size int) (int, error) {
	if source == nil || size <= 0 {
		return 0, ErrRandom
	}
	if size == 1 {
		return 0, nil
	}
	value, err := rand.Int(source, big.NewInt(int64(size)))
	if err != nil {
		return 0, ErrRandom
	}
	return int(value.Int64()), nil
}

// floorLog2Power returns floor(exponent * log2(base)) using exact integer
// arithmetic, avoiding floating-point rounding at entropy boundaries.
func floorLog2Power(base, exponent int) int {
	if base < 2 || exponent < 1 {
		return 0
	}
	power := new(big.Int).Exp(big.NewInt(int64(base)), big.NewInt(int64(exponent)), nil)
	return power.BitLen() - 1
}
