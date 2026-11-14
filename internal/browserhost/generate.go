package browserhost

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
)

// supportedCapabilities is advertised during pairing so an extension can use
// the additive v2 operations while older clients keep the v1 handshake.
var supportedCapabilities = SupportedCapabilities()

var ErrGenerate = errors.New("password generation refused")

const (
	upperAlphabet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerAlphabet   = "abcdefghijklmnopqrstuvwxyz"
	digitAlphabet   = "0123456789"
	symbolAlphabet  = "!@#$%^&*()-_=+[]{}|;:,.<>?"
	maxGenerateOpts = 4096
)

// memorableWords is a local, clean-room English word list for memorable
// passwords. It contains exactly 256 distinct four-to-seven letter words.
var memorableWords = strings.Fields(`
able acid aged also area army away baby back ball band bank base bath bear beat
been beer bell belt best bill bird blue boat body bone book boot born both bowl
bulk burn bush busy cake call calm came camp card care case cash cast cell chat
chip city club coal coat code cold come cook cool cope copy core cost crew crop
dark data date dawn days dead deal dean dear debt deep deer desk dial diet disc
disk does done door dose down draw drew drop drug dual duke dust duty each earn
ease east easy edge else even ever face fact fail fair fall farm fast fear feed
feel feet fell felt file fill film find fine fire firm fish five flat flow food
foot ford form fort four free from fuel full fund gain game gate gave gear gene
gift girl give glad goal goes gold golf gone good gray grew grow gulf hair half
hall hand hang hard harm hate have head hear heat held hell help here hero high
hill hire hold hole holy home hope host hour huge hung hunt hurt idea inch into
iron item join jump jury just keen keep kept kick kind king knee knew know lack
lady lake land lane last late lead leaf lean left less life lift like line link
list live load loan lock long look loss lost love luck made mail main make male
many mark mass meal mean meat meet menu mere mile milk mill mind mine miss mode
`)

var memorableSeparators = map[string]bool{
	"hyphens":             true,
	"spaces":              true,
	"periods":             true,
	"commas":              true,
	"underscores":         true,
	"numbers":             true,
	"numbers-and-symbols": true,
}

type generateOptions struct {
	mode       string
	length     int
	digits     bool
	symbols    bool
	separator  string
	capitalize bool
}

type generateWire struct {
	Mode       *string `json:"mode"`
	Length     *int    `json:"length"`
	Digits     *bool   `json:"digits"`
	Symbols    *bool   `json:"symbols"`
	Separator  *string `json:"separator"`
	Capitalize *bool   `json:"capitalize"`
}

func parseGenerateOptions(raw string) (generateOptions, error) {
	if len(raw) == 0 || len(raw) > maxGenerateOpts {
		return generateOptions{}, ErrGenerate
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(raw))
	if dec.Decode(&fields) != nil {
		return generateOptions{}, ErrGenerate
	}
	if fields == nil {
		return generateOptions{}, ErrGenerate
	}
	if dec.Decode(new(any)) != io.EOF {
		return generateOptions{}, ErrGenerate
	}
	for key := range fields {
		switch key {
		case "mode", "length", "digits", "symbols", "separator", "capitalize":
		default:
			return generateOptions{}, ErrGenerate
		}
	}
	var wire generateWire
	for key, value := range fields {
		var target any
		switch key {
		case "mode":
			target = &wire.Mode
		case "length":
			target = &wire.Length
		case "digits":
			target = &wire.Digits
		case "symbols":
			target = &wire.Symbols
		case "separator":
			target = &wire.Separator
		case "capitalize":
			target = &wire.Capitalize
		}
		if json.Unmarshal(value, target) != nil {
			return generateOptions{}, ErrGenerate
		}
	}
	options := generateOptions{
		mode:       "random",
		length:     24,
		digits:     true,
		symbols:    true,
		separator:  "hyphens",
		capitalize: true,
	}
	if wire.Mode != nil {
		options.mode = *wire.Mode
	}
	switch options.mode {
	case "random":
		if wire.Length != nil {
			options.length = clampInt(*wire.Length, 8, 256, 24)
		}
		if wire.Digits != nil {
			options.digits = *wire.Digits
		}
		if wire.Symbols != nil {
			options.symbols = *wire.Symbols
		}
	case "memorable":
		options.length = 4
		options.digits = false
		if wire.Length != nil {
			options.length = clampInt(*wire.Length, 3, 10, 4)
		}
		if wire.Digits != nil {
			options.digits = *wire.Digits
		}
		if wire.Separator != nil && memorableSeparators[*wire.Separator] {
			options.separator = *wire.Separator
		}
		if wire.Capitalize != nil {
			options.capitalize = *wire.Capitalize
		}
	case "pin":
		options.length = 6
		if wire.Length != nil {
			options.length = clampInt(*wire.Length, 4, 12, 6)
		}
	default:
		return generateOptions{}, ErrGenerate
	}
	if wire.Separator != nil && options.mode != "memorable" && !memorableSeparators[*wire.Separator] {
		return generateOptions{}, ErrGenerate
	}
	return options, nil
}

func pointer[T any](value T) *T { return &value }

func clampInt(value, minimum, maximum, fallback int) int {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func randomIndex(bound int) (int, error) {
	if bound < 1 || bound > 256 {
		return 0, ErrGenerate
	}
	limit := 256 - 256%bound
	var value [1]byte
	for attempt := 0; attempt < 128; attempt++ {
		if _, err := rand.Read(value[:]); err != nil {
			return 0, ErrGenerate
		}
		if int(value[0]) < limit {
			return int(value[0]) % bound, nil
		}
	}
	return 0, ErrGenerate
}

func randomCharacter(alphabet string) (byte, error) {
	index, err := randomIndex(len(alphabet))
	if err != nil {
		return 0, err
	}
	return alphabet[index], nil
}

func entropyFloor(alphabetSize, length int) int {
	if alphabetSize < 2 || length < 1 {
		return 0
	}
	space := new(big.Int).Exp(big.NewInt(int64(alphabetSize)), big.NewInt(int64(length)), nil)
	return space.BitLen() - 1
}

func generatePassword(raw string) (string, GeneratedProfile, error) {
	options, err := parseGenerateOptions(raw)
	if err != nil {
		return "", GeneratedProfile{}, err
	}
	if options.mode == "memorable" {
		return generateMemorable(options)
	}
	if options.mode == "pin" {
		output := make([]byte, options.length)
		defer clear(output)
		for index := range output {
			value, err := randomCharacter(digitAlphabet)
			if err != nil {
				return "", GeneratedProfile{}, err
			}
			output[index] = value
		}
		return string(output), GeneratedProfile{
			Mode:             "pin",
			Length:           options.length,
			AlphabetSize:     len(digitAlphabet),
			EntropyBitsFloor: entropyFloor(len(digitAlphabet), options.length),
		}, nil
	}
	classes := []string{upperAlphabet, lowerAlphabet}
	if options.digits {
		classes = append(classes, digitAlphabet)
	}
	if options.symbols {
		classes = append(classes, symbolAlphabet)
	}
	alphabet := strings.Join(classes, "")
	output := make([]byte, 0, options.length)
	defer clear(output)
	for _, class := range classes {
		value, err := randomCharacter(class)
		if err != nil {
			return "", GeneratedProfile{}, err
		}
		output = append(output, value)
	}
	for len(output) < options.length {
		value, err := randomCharacter(alphabet)
		if err != nil {
			return "", GeneratedProfile{}, err
		}
		output = append(output, value)
	}
	for index := len(output) - 1; index > 0; index-- {
		swap, err := randomIndex(index + 1)
		if err != nil {
			return "", GeneratedProfile{}, err
		}
		output[index], output[swap] = output[swap], output[index]
	}
	return string(output), GeneratedProfile{
		Mode:             "random",
		Length:           options.length,
		AlphabetSize:     len(alphabet),
		EntropyBitsFloor: entropyFloor(len(alphabet), options.length),
	}, nil
}

func generateMemorable(options generateOptions) (string, GeneratedProfile, error) {
	words := make([]string, options.length)
	defer func() {
		for index := range words {
			words[index] = ""
		}
	}()
	for index := range words {
		choice, err := randomIndex(len(memorableWords))
		if err != nil {
			return "", GeneratedProfile{}, err
		}
		word := memorableWords[choice]
		if options.capitalize {
			word = strings.ToUpper(word[:1]) + word[1:]
		}
		words[index] = word
	}
	numericSeparator := options.separator == "numbers" || options.separator == "numbers-and-symbols"
	if options.digits && !numericSeparator {
		index, err := randomIndex(len(words))
		if err != nil {
			return "", GeneratedProfile{}, err
		}
		number, err := randomIndex(90)
		if err != nil {
			return "", GeneratedProfile{}, err
		}
		words[index] += big.NewInt(int64(10 + number)).String()
	}
	var output strings.Builder
	output.WriteString(words[0])
	for index := 1; index < len(words); index++ {
		separator, err := memorableSeparator(options.separator)
		if err != nil {
			return "", GeneratedProfile{}, err
		}
		output.WriteString(separator)
		output.WriteString(words[index])
	}
	return output.String(), GeneratedProfile{
		Mode:             "memorable",
		Length:           options.length,
		AlphabetSize:     len(memorableWords),
		EntropyBitsFloor: entropyFloor(len(memorableWords), options.length),
	}, nil
}

func memorableSeparator(name string) (string, error) {
	switch name {
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
		value, err := randomCharacter(digitAlphabet)
		return string(value), err
	case "numbers-and-symbols":
		value, err := randomCharacter(digitAlphabet + symbolAlphabet)
		return string(value), err
	}
	return "", ErrGenerate
}

// handleGenerate serves both the JSON `options` form used by the extension and
// the v2 field form used by desktop/broker clients. It always delegates policy
// and entropy accounting to generatePassword so there is a single generator.
func (c *Connection) handleGenerate(r Request) error {
	raw := r.Options
	if raw == "" {
		mode := r.Mode
		if mode == "" {
			mode = "random"
		}
		length := r.Length
		if length == 0 {
			length = 24
		}
		options := map[string]any{"mode": mode, "length": length}
		if r.Digits != nil {
			options["digits"] = *r.Digits
		}
		if r.Symbols != nil {
			options["symbols"] = *r.Symbols
		}
		encoded, err := json.Marshal(options)
		if err != nil {
			return c.refuse(r.ID)
		}
		raw = string(encoded)
	}
	password, profile, err := generatePassword(raw)
	if err != nil {
		return c.refuse(r.ID)
	}
	// The native generator has no persistent history store of its own. A
	// caller-requested save_history never becomes a fabricated history ID:
	// the browser may keep its separate bounded in-memory history, but only a
	// real persisted entry may be reported as saved.
	return c.response(Response{ID: r.ID, Type: "generated", GeneratedPassword: password, Profile: &profile, PasswordProfile: (*BrowserPasswordProfile)(&profile)})
}
