package totp

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const vectorKey = "12345678901234567890"

func vectorURI(key, algorithm string, digits int, period int64) string {
	seed := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(key))
	return fmt.Sprintf("otpauth://totp/RFC:synthetic?secret=%s&issuer=RFC&algorithm=%s&digits=%d&period=%d", seed, algorithm, digits, period)
}

// RFC 6238 Appendix B: all six timestamps and all three specified hashes.
func TestRFC6238Vectors(t *testing.T) {
	for _, tc := range []struct {
		at                   int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	} {
		for _, algorithm := range []struct{ name, key, want string }{
			{"SHA1", vectorKey, tc.sha1},
			{"SHA256", "12345678901234567890123456789012", tc.sha256},
			{"SHA512", "1234567890123456789012345678901234567890123456789012345678901234", tc.sha512},
		} {
			config, err := Parse(vectorURI(algorithm.key, algorithm.name, 8, 30))
			if err != nil {
				t.Fatal("published vector configuration refused", err)
			}
			code, err := config.At(tc.at)
			if err != nil || code.Value() != algorithm.want || code.Window() != (Window{tc.at / 30 * 30, tc.at/30*30 + 30}) {
				t.Fatalf("RFC vector mismatch for %s at %d", algorithm.name, tc.at)
			}
		}
	}
}

// RFC 4226 Appendix D counters 0..9, with the TOTP counter selected by time.
func TestRFC4226CountersAndWindowEdges(t *testing.T) {
	config, err := Parse(base32.StdEncoding.EncodeToString([]byte(vectorKey)))
	if err != nil || config.Parameters() != (Parameters{"SHA1", 6, 30}) {
		t.Fatal("raw seed defaults not applied", err)
	}
	for i, want := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		for _, offset := range []int64{0, 29} {
			at := int64(i)*30 + offset
			code, e := config.At(at)
			if e != nil || code.Value() != want || code.Window() != (Window{int64(i) * 30, int64(i+1) * 30}) {
				t.Fatal("counter or half-open window mismatch", i, offset, e)
			}
		}
	}
	for _, at := range []int64{-1, math.MinInt64, math.MaxInt64} {
		if got, e := config.At(at); !errors.Is(e, ErrTime) || got != (Code{}) {
			t.Fatal("invalid time returned a partial code", e)
		}
	}
	for _, empty := range []*Config{nil, {}} {
		if got, e := empty.At(59); !errors.Is(e, ErrInvalid) || got != (Code{}) {
			t.Fatal("empty configuration generated a code", e)
		}
	}
}

func TestParseCanonicalSeedsAndStrictURI(t *testing.T) {
	key := "12345678901234567"
	padded := base32.StdEncoding.EncodeToString([]byte(key))
	plain := strings.TrimRight(padded, "=")
	inputs := []string{padded, plain, strings.ToLower(plain), "otpauth://totp/Example%3Aalice?secret=" + url.QueryEscape(padded) + "&issuer=Example", "OTPAUTH://TOTP/%E7%A4%BA%E4%BE%8B?secret=" + plain + "&algorithm=sha1&digits=6&period=30"}
	var first Code
	for _, input := range inputs {
		config, err := Parse(input)
		if err != nil {
			t.Fatal("supported canonical configuration refused", err)
		}
		code, err := config.At(59)
		if err != nil || first != (Code{}) && code != first {
			t.Fatal("equivalent encodings changed code/window", err)
		}
		first = code
		parameters := config.Parameters()
		parameters.Digits, parameters.Period = 8, 60
		if config.Parameters() != (Parameters{"SHA1", 6, 30}) {
			t.Fatal("caller mutated configuration parameters")
		}
	}
	for _, period := range []int64{1, 60, 3600} {
		config, err := Parse(vectorURI(vectorKey, "SHA1", 6, period))
		if err != nil || config.Parameters().Period != period {
			t.Fatal("supported period refused", err)
		}
		code, err := config.At(period - 1)
		if err != nil || code.Value() != "755224" || code.Window() != (Window{0, period}) {
			t.Fatal("period not used for counter/window", err)
		}
	}
}

func TestParseRejectsMalformedUnsupportedAndOversized(t *testing.T) {
	seed := base32.StdEncoding.EncodeToString([]byte(vectorKey))
	base := "otpauth://totp/PrivateLabel?secret=" + seed
	for _, tc := range []struct {
		raw  string
		want error
	}{
		{"", ErrInvalid}, {"MZXW6", ErrInvalid}, {seed + " ", ErrInvalid}, {" " + seed, ErrInvalid},
		{"MZXW6YTBOI======", ErrInvalid}, {strings.Repeat("A", 25) + "B", ErrInvalid},
		{strings.Repeat("A", 26) + "=", ErrInvalid}, {strings.Repeat("A", 25) + "ſ", ErrInvalid},
		{strings.Repeat("A", MaxInput+1), ErrLimit}, {base + "&issuer=" + strings.Repeat("X", MaxInput), ErrLimit},
		{base32.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 65)), ErrLimit},
		{base + "&secret=" + seed, ErrInvalid}, {base + "&%73ecret=" + seed, ErrInvalid},
		{base + "&SECRET=" + seed, ErrUnsupported}, {base + "&counter=1", ErrUnsupported},
		{base + "&algorithm=MD5", ErrUnsupported}, {base + "&digits=7", ErrUnsupported}, {base + "&period=3601", ErrUnsupported},
		{base + "&digits=06", ErrInvalid}, {base + "&period=0", ErrInvalid}, {base + "&period=030", ErrInvalid},
		{base + "&period=-1", ErrInvalid}, {base + "&algorithm=SHA1&algorithm=SHA256", ErrInvalid},
		{base + "#", ErrInvalid}, {base + "#ignored", ErrInvalid}, {base + "&", ErrInvalid},
		{base + "&&digits=6", ErrInvalid}, {base + "&issuer=", ErrInvalid}, {base + ";digits=8", ErrInvalid},
		{base + "&issuer=%zz", ErrInvalid}, {base + "&issuer=%0Aprivate", ErrInvalid},
		{"otpauth://totp/?secret=" + seed, ErrInvalid}, {"otpauth://totp/A%2FB?secret=" + seed, ErrInvalid},
		{"otpauth://totp/A:B?secret=" + seed + "&issuer=C", ErrInvalid},
		{"otpauth://totp/%FF?secret=" + seed, ErrInvalid}, {"otpauth://totp/A:B:C?secret=" + seed, ErrInvalid},
		{"otpauth://user@totp/A?secret=" + seed, ErrInvalid}, {"otpauth://totp:80/A?secret=" + seed, ErrInvalid},
		{"otpauth:totp/A?secret=" + seed, ErrInvalid}, {"otpauth://hotp/A?secret=" + seed, ErrUnsupported},
		{"https://totp/A?secret=" + seed, ErrInvalid}, {"otpauth://totp/A?secret=", ErrInvalid},
	} {
		config, err := Parse(tc.raw)
		if !errors.Is(err, tc.want) || config != nil {
			t.Fatal("bad configuration was not rejected with fixed classification", err)
		}
		for _, marker := range []string{seed, vectorKey, "PrivateLabel"} {
			if strings.Contains(err.Error(), marker) {
				t.Fatal("configuration error echoed private input")
			}
		}
	}
}

func TestSensitiveTypesRedactFormattingJSONAndLogs(t *testing.T) {
	input := vectorURI(vectorKey, "SHA1", 8, 30)
	config, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	code, err := config.At(59)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, value := range []any{*config, config, code, &code} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			fmt.Fprintf(&out, verb, value)
		}
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		out.Write(raw)
	}
	for _, handler := range []slog.Handler{slog.NewTextHandler(&out, nil), slog.NewJSONHandler(&out, nil)} {
		slog.New(handler).Info("synthetic event", "configuration", config, "code", code)
	}
	for _, marker := range []string{input, vectorKey, base32.StdEncoding.EncodeToString([]byte(vectorKey)), code.Value(), "synthetic?secret"} {
		if strings.Contains(out.String(), marker) {
			t.Fatal("sensitive type leaked in ordinary formatting/serialization")
		}
	}
	before := code
	if err = json.Unmarshal([]byte(`{}`), config); !errors.Is(err, ErrUnsupported) {
		t.Fatal("JSON accepted as an alternate configuration input", err)
	}
	if err = json.Unmarshal([]byte(`"123456"`), &code); !errors.Is(err, ErrUnsupported) || code != before {
		t.Fatal("JSON mutated a sensitive code", err)
	}
	after, err := config.At(59)
	if err != nil || after != before {
		t.Fatal("failed deserialization changed configuration", err)
	}
}

func TestConfigurationConcurrentUse(t *testing.T) {
	config, err := Parse(vectorURI(vectorKey, "SHA1", 8, 30))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 100 {
				code, e := config.At(59)
				if e != nil || code.Value() != "94287082" {
					t.Error("shared immutable configuration changed result", e)
					return
				}
			}
		})
	}
	wg.Wait()
}

func FuzzParseAndGenerate(f *testing.F) {
	f.Add(vectorURI(vectorKey, "SHA1", 8, 30), int64(59))
	f.Add(base32.StdEncoding.EncodeToString([]byte(vectorKey)), int64(0))
	f.Add("otpauth://hotp/A?secret=ABCD", int64(-1))
	f.Add("", int64(math.MaxInt64))
	f.Fuzz(func(t *testing.T, input string, at int64) {
		config, err := Parse(input)
		if err != nil {
			if config != nil || err != ErrInvalid && err != ErrUnsupported && err != ErrLimit {
				t.Fatal("parse returned partial state or input-bearing error")
			}
			return
		}
		params := config.Parameters()
		if params.Algorithm != "SHA1" && params.Algorithm != "SHA256" && params.Algorithm != "SHA512" || params.Digits != 6 && params.Digits != 8 || params.Period < 1 || params.Period > 3600 {
			t.Fatal("parse escaped supported profile")
		}
		code, err := config.At(at)
		if err != nil {
			if err != ErrTime || code != (Code{}) {
				t.Fatal("generation returned partial code or unexpected error")
			}
			return
		}
		value, window := code.Value(), code.Window()
		if len(value) != params.Digits || window.From > at || window.Until <= at || window.Until-window.From != params.Period {
			t.Fatal("generated code escaped its type or half-open window")
		}
		for _, digit := range value {
			if digit < '0' || digit > '9' {
				t.Fatal("generated nondecimal code")
			}
		}
		again, e := config.At(at)
		if e != nil || again != code {
			t.Fatal("generation used implicit mutable state or clock")
		}
		raw, e := json.Marshal([]any{config, code})
		if e != nil || string(raw) != `["[redacted OTP configuration]","[redacted OTP code]"]` {
			t.Fatal("sensitive JSON representation changed")
		}
	})
}
