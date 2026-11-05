package password

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strings"
	"sync"
	"testing"
)

func checkSecret(t testing.TB, secret Secret, policy Policy, profile Profile) {
	t.Helper()
	if !secretMatches(secret, policy, profile) {
		t.Fatal("generated value escaped its length, alphabet or policy profile")
	}
}

func secretMatches(secret Secret, policy Policy, profile Profile) bool {
	if len(secret.Value()) != policy.Length || secret.Profile() != profile {
		return false
	}
	for _, c := range []byte(secret.Value()) {
		if strings.IndexByte(policy.Alphabet, c) < 0 {
			return false
		}
	}
	return true
}

func TestDefaultPolicyAndSystemGeneration(t *testing.T) {
	policy := DefaultPolicy()
	profile, err := Validate(policy)
	if err != nil || profile != (Profile{24, 62, 142}) {
		t.Fatal("default policy or conservative entropy changed", err)
	}
	secret, err := Generate(policy)
	if err != nil {
		t.Fatal("OS CSPRNG generation failed", err)
	}
	checkSecret(t, secret, policy, profile)
}

func TestExactEntropyAndCapacity(t *testing.T) {
	for _, tc := range []struct {
		policy Policy
		bits   int
		want   error
	}{
		{Policy{128, "01"}, 128, nil}, {Policy{127, "01"}, 0, ErrEntropy},
		{Policy{81, "ABC"}, 128, nil}, {Policy{80, "ABC"}, 0, ErrEntropy},
		{Policy{22, DefaultAlphabet}, 130, nil}, {Policy{21, DefaultAlphabet}, 0, ErrEntropy},
		{Policy{MaxLength, "aA"}, 256, nil}, {Policy{0, "ab"}, 0, ErrInvalid},
		{Policy{-1, "ab"}, 0, ErrInvalid}, {Policy{MaxLength + 1, "ab"}, 0, ErrLimit},
		{Policy{math.MaxInt, "ab"}, 0, ErrLimit}, {Policy{128, ""}, 0, ErrInvalid},
		{Policy{128, "a"}, 0, ErrInvalid}, {Policy{128, "aa"}, 0, ErrInvalid},
		{Policy{128, "abcAabc"}, 0, ErrInvalid}, {Policy{128, "ab "}, 0, ErrInvalid},
		{Policy{128, "ab\n"}, 0, ErrInvalid}, {Policy{128, "ab\x7f"}, 0, ErrInvalid},
		{Policy{128, "ab中"}, 0, ErrInvalid}, {Policy{128, "ab\xff"}, 0, ErrInvalid},
		{Policy{128, strings.Repeat("a", 95)}, 0, ErrLimit},
	} {
		profile, err := Validate(tc.policy)
		if !errors.Is(err, tc.want) || err != nil && profile != (Profile{}) {
			t.Fatal("policy did not return a fixed rejection or zero profile", err)
		}
		if err == nil && (profile.EntropyBits != tc.bits || profile.Length != tc.policy.Length || profile.AlphabetSize != len(tc.policy.Alphabet)) {
			t.Fatal("entropy bound or policy counts were not exact")
		}
		if err != nil {
			secret, e := generate(panicReader{}, tc.policy)
			if !errors.Is(e, tc.want) || secret != (Secret{}) {
				t.Fatal("invalid policy consumed randomness or returned a value", e)
			}
		}
	}
	var all strings.Builder
	for c := byte(33); c <= 126; c++ {
		all.WriteByte(c)
	}
	profile, err := Validate(Policy{20, all.String()})
	if err != nil || profile != (Profile{20, 94, 131}) {
		t.Fatal("full printable ASCII policy not accounted for", err)
	}
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("invalid policy reached random source") }

func TestRejectionSamplingByteVectors(t *testing.T) {
	input := make([]byte, 256)
	for i := range input {
		input[i] = byte(i)
	}
	for _, tc := range []struct {
		policy Policy
		want   string
	}{
		{Policy{192, "ABC"}, strings.Repeat("ABC", 64)},
		{Policy{248, DefaultAlphabet}, strings.Repeat(DefaultAlphabet, 4)},
	} {
		secret, err := generate(bytes.NewReader(input), tc.policy)
		if err != nil || secret.Value() != tc.want {
			t.Fatal("rejected random indices were reduced modulo alphabet size", err)
		}
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("private-random-provider-marker") }

type repeatReader struct{ consumed int }

func (r *repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 255
	}
	r.consumed += len(p)
	return len(p), nil
}

func TestRandomFailuresReturnNoPartialSecret(t *testing.T) {
	policy := Policy{81, "ABC"}
	for _, source := range []io.Reader{nil, errorReader{}, bytes.NewReader(nil), bytes.NewReader(make([]byte, 10)), io.MultiReader(bytes.NewReader(make([]byte, 10)), errorReader{})} {
		secret, err := generate(source, policy)
		if !errors.Is(err, ErrRandom) || secret != (Secret{}) || strings.Contains(err.Error(), "private-random-provider-marker") {
			t.Fatal("random source failure exposed partial output or provider details", err)
		}
	}
	rejecting := &repeatReader{}
	if secret, err := generate(rejecting, policy); !errors.Is(err, ErrRandom) || secret != (Secret{}) || rejecting.consumed > policy.Length*64 {
		t.Fatal("rejection sampling did not respect its entropy byte budget", err)
	}
}

func TestSecretRedactsFormattingJSONAndLogs(t *testing.T) {
	policy := Policy{81, "ABC"}
	secret, err := generate(bytes.NewReader(make([]byte, policy.Length)), policy)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, value := range []any{secret, &secret} {
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
		slog.New(handler).Info("synthetic generation", "secret", secret, "profile", secret.Profile())
	}
	if strings.Contains(out.String(), secret.Value()) {
		t.Fatal("generated password escaped through ordinary output")
	}
	before := secret
	if err = json.Unmarshal([]byte(`"replacement"`), &secret); !errors.Is(err, ErrUnsupported) || secret != before {
		t.Fatal("JSON became an alternate secret input path", err)
	}
}

func TestConcurrentSystemGeneration(t *testing.T) {
	policy := DefaultPolicy()
	profile, err := Validate(policy)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 4 {
				secret, e := Generate(policy)
				if e != nil {
					t.Error("concurrent CSPRNG generation failed", e)
					return
				}
				if !secretMatches(secret, policy, profile) {
					t.Error("concurrent result escaped policy constraints")
					return
				}
			}
		})
	}
	wg.Wait()
}

func FuzzGeneratePolicies(f *testing.F) {
	input := make([]byte, 256)
	for i := range input {
		input[i] = byte(i)
	}
	f.Add(24, DefaultAlphabet, input)
	f.Add(81, "ABC", input)
	f.Add(128, "01", bytes.Repeat([]byte{17}, 128))
	f.Add(0, "", []byte{})
	f.Fuzz(func(t *testing.T, length int, alphabet string, data []byte) {
		policy := Policy{length, alphabet}
		profile, err := Validate(policy)
		if err != nil {
			if profile != (Profile{}) || err != ErrInvalid && err != ErrLimit && err != ErrEntropy {
				t.Fatal("invalid policy returned partial or input-bearing metadata")
			}
			secret, e := generate(panicReader{}, policy)
			if e != err || secret != (Secret{}) {
				t.Fatal("invalid policy escaped generation validation")
			}
			return
		}
		if profile.EntropyBits < MinEntropyBits {
			t.Fatal("accepted policy below entropy floor")
		}
		secret, err := generate(bytes.NewReader(data), policy)
		if err != nil {
			if err != ErrRandom || secret != (Secret{}) {
				t.Fatal("random failure returned partial output or provider error")
			}
			return
		}
		checkSecret(t, secret, policy, profile)
		again, e := generate(bytes.NewReader(data), policy)
		if e != nil || again != secret {
			t.Fatal("generation used a hidden fallback or mutable source")
		}
		raw, e := json.Marshal(secret)
		if e != nil || string(raw) != `"[redacted generated password]"` {
			t.Fatal("sensitive JSON representation changed")
		}
	})
}
