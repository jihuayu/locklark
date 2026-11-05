// Package password generates secrets for a trusted local host. It does not
// authenticate callers, persist data, record audit or expose an Agent endpoint.
package password

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const MaxLength = 256
const MinEntropyBits = 128
const DefaultAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var ErrInvalid = errors.New("invalid password policy")
var ErrLimit = errors.New("password policy capacity exceeded")
var ErrEntropy = errors.New("password policy entropy below required minimum")
var ErrRandom = errors.New("password randomness unavailable")
var ErrUnsupported = errors.New("password deserialization is not supported")

type Policy struct {
	Length   int
	Alphabet string
}

// Profile contains only public policy counts, never a value or its digest.
// EntropyBits is floor(log2(alphabet size ^ length)), assuming independent
// uniform CSPRNG draws. It is not a measurement of an individual password.
type Profile struct {
	Length       int `json:"length"`
	AlphabetSize int `json:"alphabet_size"`
	EntropyBits  int `json:"entropy_bits_floor"`
}

// Secret requires explicit Value access. Redaction limits accidental output;
// it is not an in-process security boundary or an authorization decision.
type Secret struct {
	value   string
	profile Profile
}

func (s Secret) Value() string              { return s.value }
func (s Secret) Profile() Profile           { return s.profile }
func (Secret) Format(s fmt.State, _ rune)   { io.WriteString(s, "[redacted generated password]") }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted generated password]"`), nil }
func (*Secret) UnmarshalJSON([]byte) error  { return ErrUnsupported }
func DefaultPolicy() Policy                 { return Policy{24, DefaultAlphabet} }

// Validate accepts distinct printable ASCII characters, no class quotas, and
// at least 128 bits of combinatorial entropy. Integer powers avoid rounding
// a weak boundary policy up to the required minimum.
func Validate(policy Policy) (Profile, error) {
	if policy.Length > MaxLength || len(policy.Alphabet) > 94 {
		return Profile{}, ErrLimit
	}
	if policy.Length < 1 || len(policy.Alphabet) < 2 {
		return Profile{}, ErrInvalid
	}
	var seen [127]bool
	for _, c := range []byte(policy.Alphabet) {
		if c < 33 || c > 126 || seen[c] {
			return Profile{}, ErrInvalid
		}
		seen[c] = true
	}
	space := new(big.Int).Exp(big.NewInt(int64(len(policy.Alphabet))), big.NewInt(int64(policy.Length)), nil)
	bits := space.BitLen() - 1
	if bits < MinEntropyBits {
		return Profile{}, ErrEntropy
	}
	return Profile{policy.Length, len(policy.Alphabet), bits}, nil
}

// Generate always uses the OS-backed CSPRNG. There is no public custom-reader
// option or fallback. The host owns authorization and audit before disclosure.
func Generate(policy Policy) (Secret, error) { return generate(rand.Reader, policy) }

// The reader hook is private for deterministic vectors and fault injection.
func generate(source io.Reader, policy Policy) (Secret, error) {
	profile, err := Validate(policy)
	if err != nil {
		return Secret{}, err
	}
	if source == nil {
		return Secret{}, ErrRandom
	}
	// Int uses unbiased rejection sampling. Bound total entropy consumption
	// so a broken source that repeatedly gives rejected indices fails closed.
	reader := io.LimitReader(source, int64(policy.Length)*64)
	bound := big.NewInt(int64(len(policy.Alphabet)))
	out := make([]byte, policy.Length)
	defer clear(out)
	for i := range out {
		n, err := rand.Int(reader, bound)
		if err != nil {
			return Secret{}, ErrRandom
		}
		out[i] = policy.Alphabet[n.Int64()]
	}
	return Secret{string(out), profile}, nil
}
