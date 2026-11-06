package browserhost

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"strings"

	"github.com/jihuayu/locklark/internal/password"
)

type generateOptions struct {
	Mode       string `json:"mode"`
	Length     int    `json:"length"`
	Digits     *bool  `json:"digits"`
	Symbols    *bool  `json:"symbols"`
	Separator  string `json:"separator"`
	Capitalize bool   `json:"capitalize"`
}

const randomLower = "abcdefghijklmnopqrstuvwxyz"
const randomUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const randomDigits = "0123456789"
const randomSymbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"

// memorableWords is a fixed lowercase wordlist. It is deliberately larger
// than 256 entries so word selection remains well above a 128-bit floor for
// the minimum word count.
var memorableWords = strings.Fields(`
acorn amber anchor apple april archer arizona artist atlas autumn avenue badges
bamboo banana beacon beetle bench berry bicycle blanket bloom blossom blue bolt
border bottle boulder breeze bridge bright bronze brook bubble bucket buffalo
bullet butter button cabin cactus candle canvas canyon carbon carpet carrot castle
cedar cello chalk cherry chess chicken circle citrus clay cliff cloud clover cobalt
coconut coffee comet copper coral cotton cougar country coyote crane crater crimson
crystal cube curtain cycle daisy dance dawn delta desert diamond diesel dolphin
donkey dragon drift drum eagle earth east echo elder ember emerald engine ethics
falcon feather fence ferry field finch fire flame flint flower flute forest forge
fossil fountain fox frost galaxy garden garlic gecko ginger glacier globe golden
granite grape grass gravity green grove guitar harbor harvest hawk hazel heart
heron hill honey horizon horse hotel hummingbird iceberg indigo iris iron island
ivory jacket jade jaguar jasmine jigsaw jungle juniper kettle kestrel kiwi knight
koala lake lantern lark laser laurel lava lemon leopard lettuce library lilac lily
linen lion lizard lobster lotus lunar lynx magnet mango maple marble meadow melon
metal meteor mint mirror mist monarch moon moss mountain mouse museum nectar needle
nickel night north nutmeg oak ocean olive onyx opal orange orchid otter owl oyster
paddle palm panda paper parrot peach pearl pebble pelican pencil pepper peony petal
piano pier pine planet plum pollen pond poppy prairie prism puffin pumpkin quartz
quill rabbit raven reef rhino ribbon river robin rocket rose ruby runner saddle
sage salmon sand sapphire satin scarlet seal shadow shell shore silver sky slate
sloth smoke snow sparrow spice spring spruce star steel stone storm stream summit
sunflower sunset swan sweet swift table talon temple thrush thunder tiger timber
topaz torch trail tulip tundra turtle twilight umber valley velvet violet vision
walnut wave whale wheat willow window winter wolf wren yarrow yellow zebra zephyr
zinnia
`)

func randIndex(bound int) (int, error) {
	n, e := rand.Int(rand.Reader, big.NewInt(int64(bound)))
	if e != nil {
		return 0, ErrProtocol
	}
	return int(n.Int64()), nil
}

func randomFromAlphabet(alphabet string, length int) (string, error) {
	out := make([]byte, length)
	for i := range out {
		n, e := randIndex(len(alphabet))
		if e != nil {
			clear(out)
			return "", e
		}
		out[i] = alphabet[n]
	}
	return string(out), nil
}

func bitsFloor(pool, length int) int {
	if pool < 2 || length < 1 {
		return 0
	}
	// floor(length * log2(pool)) using a bounded series.
	bits := 0
	l := 0.0
	v := float64(pool)
	for v >= 2 {
		v /= 2
		l++
	}
	x := v - 1
	term := x
	sum := 0.0
	for i := 1; i <= 20; i++ {
		sum += term / float64(i)
		term *= -x
	}
	bits = int(float64(length) * (l + sum/0.6931471805599453))
	if bits < 0 {
		return 0
	}
	return bits
}

func boolValue(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func (c *Connection) handleGenerate(r Request) error {
	opts := generateOptions{Mode: r.GenMode, Length: r.Length, Digits: r.Digits, Symbols: r.Symbols}
	if r.Options != "" {
		dec := json.NewDecoder(strings.NewReader(r.Options))
		dec.DisallowUnknownFields()
		if dec.Decode(&opts) != nil {
			return c.refuse(r.ID)
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			return c.refuse(r.ID)
		}
	}
	if opts.Mode == "" {
		opts.Mode = "random"
	}
	var value string
	var profile BrowserPasswordProfile
	var e error
	switch opts.Mode {
	case "random":
		if opts.Length < 16 || opts.Length > 256 {
			return c.refuse(r.ID)
		}
		alphabet := randomLower + randomUpper
		if boolValue(opts.Digits, true) {
			alphabet += randomDigits
		}
		if boolValue(opts.Symbols, false) {
			alphabet += randomSymbols
		}
		if secret, err := password.Generate(password.Policy{Length: opts.Length, Alphabet: alphabet}); err == nil {
			value = secret.Value()
		} else {
			value, e = randomFromAlphabet(alphabet, opts.Length)
			if e != nil {
				return c.refuse(r.ID)
			}
		}
		profile = BrowserPasswordProfile{Mode: "random", Length: opts.Length, AlphabetSize: len(alphabet), EntropyBitsFloor: bitsFloor(len(alphabet), opts.Length)}
	case "memorable":
		if opts.Length < 3 || opts.Length > 12 {
			return c.refuse(r.ID)
		}
		separator := opts.Separator
		if separator == "" {
			separator = "-"
		}
		if len(separator) > 1 {
			return c.refuse(r.ID)
		}
		words := make([]string, opts.Length)
		for i := range words {
			n, err := randIndex(len(memorableWords))
			if err != nil {
				return c.refuse(r.ID)
			}
			w := memorableWords[n]
			if opts.Capitalize {
				w = strings.ToUpper(w[:1]) + w[1:]
			}
			words[i] = w
		}
		value = strings.Join(words, separator)
		if opts.Digits != nil && *opts.Digits {
			n, err := randIndex(10)
			if err != nil {
				return c.refuse(r.ID)
			}
			value += string(rune('0' + n))
		}
		profile = BrowserPasswordProfile{Mode: "memorable", Length: opts.Length, AlphabetSize: len(memorableWords), EntropyBitsFloor: bitsFloor(len(memorableWords), opts.Length)}
	case "pin":
		if opts.Length < 4 || opts.Length > 12 {
			return c.refuse(r.ID)
		}
		value, e = randomFromAlphabet(randomDigits, opts.Length)
		if e != nil {
			return c.refuse(r.ID)
		}
		profile = BrowserPasswordProfile{Mode: "pin", Length: opts.Length, AlphabetSize: 10, EntropyBitsFloor: bitsFloor(10, opts.Length)}
	default:
		return c.refuse(r.ID)
	}
	history := ""
	if boolValue(r.SaveHistory, true) {
		var b [16]byte
		if _, e := rand.Read(b[:]); e == nil {
			history = hex.EncodeToString(b[:])
		}
	}
	return c.response(Response{ID: r.ID, Type: "generated", GeneratedPassword: value, PasswordProfile: &profile, HistoryID: history})
}
