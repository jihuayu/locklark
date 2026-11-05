package totp

import (
	"errors"
	"testing"
)

func TestClearInvalidatesConfiguration(t *testing.T) {
	config, err := Parse("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	if err != nil {
		t.Fatal(err)
	}
	config.Clear()
	config.Clear()
	if config.key != ([64]byte{}) || config.size != 0 || config.Parameters() != (Parameters{}) {
		t.Fatal("configuration not cleared")
	}
	if _, err = config.At(59); !errors.Is(err, ErrInvalid) {
		t.Fatal("cleared configuration still usable", err)
	}
	var absent *Config
	absent.Clear()
}
