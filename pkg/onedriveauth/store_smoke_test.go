package onedriveauth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"
)

// smokeStoreEnv opts in to the real OS credential store smoke test. This
// package never sets it, and without it no test touches the real store.
const smokeStoreEnv = "LOCKLARK_TEST_OS_CREDENTIAL_STORE"

// TestCredentialStoreSmoke exercises the real system credential store through
// the adapter with a random, otherwise unused profile under a synthetic client
// ID and tenant. It never lists, reads first, or deletes any other key: every
// field is fresh randomness, its cleanup deletes only that one composite key and
// is registered before the first Set, and the only read is of the same key after
// Set.
//
// Run with: LOCKLARK_TEST_OS_CREDENTIAL_STORE=1 go test ./pkg/onedriveauth -run TestCredentialStoreSmoke -count=1 -v
func TestCredentialStoreSmoke(t *testing.T) {
	if os.Getenv(smokeStoreEnv) != "1" {
		t.Skipf("set %s=1 to exercise the real OS credential store", smokeStoreEnv)
	}
	boundary := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal("random source failed")
	}
	hexRandom := hex.EncodeToString(random)
	label := []byte("locklark smoke " + hexRandom)
	clientID := "synthetic-" + hexRandom
	tenant := "synthetic.invalid"
	token := []byte("smoke-token-" + hexRandom)
	defer clear(token)

	s := NewRefreshTokenStore()
	// The cleanup runs on every path out of this test, including a failed
	// or uncertain Set, and deletes this random composite key only. The label
	// is cleared here, after the Delete, because t.Cleanup runs after the
	// test function's own defers.
	t.Cleanup(func() {
		defer clear(label)
		if err := s.DeleteRefreshToken(clientID, tenant, label); err != nil && !errors.Is(err, ErrStoreUnsupported) {
			t.Errorf("cleanup of the random smoke item failed on %s", boundary)
		}
	})

	// A Set that fails as unsupported means nothing was written; skip with
	// the observed boundary before any read happens.
	if err := s.SaveRefreshToken(clientID, tenant, label, token); err != nil {
		if errors.Is(err, ErrStoreUnsupported) {
			t.Skipf("OS credential store unsupported on %s (observed: %v); no item was read", boundary, err)
		}
		t.Fatalf("Set of the random smoke item failed on %s (observed: %v)", boundary, err)
	}
	got, present, err := s.LoadRefreshToken(clientID, tenant, label)
	defer clear(got)
	if err != nil || !present {
		t.Fatalf("Get of the random smoke item failed on %s (present=%v, err=%v)", boundary, present, err)
	}
	if !bytes.Equal(got, token) {
		t.Fatalf("Get of the random smoke item returned a different value on %s", boundary)
	}
	clear(got)
	if err := s.DeleteRefreshToken(clientID, tenant, label); err != nil {
		t.Fatalf("Delete of the random smoke item failed on %s (observed: %v)", boundary, err)
	}
	if _, present, err := s.LoadRefreshToken(clientID, tenant, label); err != nil || present {
		t.Fatalf("after Delete the random smoke item still exists on %s (present=%v, err=%v)", boundary, present, err)
	}
}
