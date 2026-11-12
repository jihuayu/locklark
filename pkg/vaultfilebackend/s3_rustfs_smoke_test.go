package vaultfilebackend

// Opt-in smoke test for an already-running, real RustFS S3-compatible endpoint
// over verified TLS.
//
// The test is skipped unless RUSTFS_SMOKE_ENABLE=1, RUSTFS_SMOKE_ENDPOINT and
// RUSTFS_SMOKE_CA_FILE are set, and -rustfs-credential-file points at a private
// regular file (no group/other permissions) holding RUSTFS_ACCESS_KEY=... and
// RUSTFS_SECRET_KEY=.... It is not a mock: every request goes to the explicit
// endpoint with path-style addressing, a static credentials provider built only
// from that file, and a TLS root pool containing only the supplied CA. No
// environment/default credential provider is used and TLS verification is never
// disabled. The test provisions a unique bucket and removes it afterwards.
//
// Run it with a placeholder credential file (never commit real credentials):
//
//	printf 'RUSTFS_ACCESS_KEY=example-access-key\nRUSTFS_SECRET_KEY=example-secret-key\n' > /private/tmp/rustfs.env
//	chmod 600 /private/tmp/rustfs.env
//	RUSTFS_SMOKE_ENABLE=1 \
//	RUSTFS_SMOKE_ENDPOINT=https://127.0.0.1:9443 \
//	RUSTFS_SMOKE_CA_FILE=/private/tmp/rustfs-ca.pem \
//	go test ./pkg/vaultfilebackend -run '^TestS3RustFSAllocatorSafetyTLSSmoke$' -v \
//	    -args -rustfs-credential-file=/private/tmp/rustfs.env

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	rustfsSmokeEnableEnv   = "RUSTFS_SMOKE_ENABLE"
	rustfsSmokeEndpointEnv = "RUSTFS_SMOKE_ENDPOINT"
	rustfsSmokeCAFileEnv   = "RUSTFS_SMOKE_CA_FILE"
	rustfsSmokeRegion      = "us-east-1"
	rustfsSmokeTimeout     = 30 * time.Second
)

var rustfsSmokeCredentialFile = flag.String("rustfs-credential-file", "",
	"path to a private file holding RUSTFS_ACCESS_KEY and RUSTFS_SECRET_KEY (real RustFS TLS smoke only)")

// rustfsSmokeEnv is the caller-supplied environment of one smoke run.
type rustfsSmokeEnv struct {
	endpoint string
	roots    *x509.CertPool
	client   *http.Client
	creds    aws.CredentialsProvider
}

// requireRustFSsmoke returns the configured environment, or skips when the
// opt-in has not been requested.
func requireRustFSsmoke(t *testing.T) rustfsSmokeEnv {
	t.Helper()
	if os.Getenv(rustfsSmokeEnableEnv) != "1" {
		t.Skipf("real RustFS TLS smoke test is opt-in: set %s=1 plus %s, %s and -rustfs-credential-file",
			rustfsSmokeEnableEnv, rustfsSmokeEndpointEnv, rustfsSmokeCAFileEnv)
	}
	endpoint := os.Getenv(rustfsSmokeEndpointEnv)
	caFile := os.Getenv(rustfsSmokeCAFileEnv)
	var missing []string
	if endpoint == "" {
		missing = append(missing, rustfsSmokeEndpointEnv)
	}
	if caFile == "" {
		missing = append(missing, rustfsSmokeCAFileEnv)
	}
	if len(missing) > 0 {
		t.Fatalf("%s=1 but %s missing", rustfsSmokeEnableEnv, strings.Join(missing, ", "))
	}
	accessKey, secretKey := readRustFSsmokeCredentials(t, *rustfsSmokeCredentialFile)

	// Trust exactly the supplied CA; the system pool is not consulted and
	// verification is never skipped.
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("read RustFS CA file: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatalf("RustFS CA file %s carries no PEM certificate", caFile)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
		Timeout: rustfsSmokeTimeout,
	}
	return rustfsSmokeEnv{
		endpoint: endpoint,
		roots:    roots,
		client:   client,
		creds:    credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
	}
}

// readRustFSsmokeCredentials reads the static keys from the private credential
// file, rejecting symlinks/non-regular files and any group/other permission.
func readRustFSsmokeCredentials(t *testing.T, path string) (accessKey, secretKey string) {
	t.Helper()
	if path == "" {
		t.Fatalf("-rustfs-credential-file is required when %s=1", rustfsSmokeEnableEnv)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat credential file: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("credential file %s must be a regular file, got %v", path, info.Mode())
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("credential file %s must have no group or other permissions, got %v", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	accessKey, secretKey = values["RUSTFS_ACCESS_KEY"], values["RUSTFS_SECRET_KEY"]
	if accessKey == "" || secretKey == "" {
		t.Fatalf("credential file lacks RUSTFS_ACCESS_KEY or RUSTFS_SECRET_KEY")
	}
	return accessKey, secretKey
}

// sdkClient is used only to provision and tear down the temporary bucket.
func (e rustfsSmokeEnv) sdkClient() *s3.Client {
	endpoint := e.endpoint
	return s3.New(s3.Options{
		Region:                     rustfsSmokeRegion,
		BaseEndpoint:               &endpoint,
		Credentials:                aws.NewCredentialsCache(e.creds),
		UsePathStyle:               true,
		HTTPClient:                 e.client,
		Retryer:                    aws.NopRetryer{},
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
}

// newBackend builds a fresh instance through the production NewS3 constructor.
func (e rustfsSmokeEnv) newBackend(t *testing.T, bucket string) Backend {
	t.Helper()
	b, err := NewS3(S3Config{
		Endpoint:     e.endpoint,
		Region:       rustfsSmokeRegion,
		Bucket:       bucket,
		Prefix:       "rustfs-smoke",
		Credentials:  e.creds,
		UsePathStyle: true,
		HTTPClient:   e.client,
	})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// provisionRustFSsmokeBucket creates a unique bucket and registers its removal.
func provisionRustFSsmokeBucket(t *testing.T, e rustfsSmokeEnv) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), rustfsSmokeTimeout)
	defer cancel()
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("random bucket suffix: %v", err)
	}
	bucket := "locklark-rustfs-smoke-" + fmt.Sprintf("%x", suffix)
	client := e.sdkClient()
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("provision bucket: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), rustfsSmokeTimeout)
		defer cancel()
		out, err := client.ListObjectsV2(cleanupCtx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
		if err != nil {
			t.Errorf("list smoke bucket for cleanup: %v", err)
			return
		}
		for _, obj := range out.Contents {
			if _, err := client.DeleteObject(cleanupCtx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    obj.Key,
			}); err != nil {
				t.Errorf("delete %q for cleanup: %v", aws.ToString(obj.Key), err)
			}
		}
		if _, err := client.DeleteBucket(cleanupCtx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
			t.Errorf("delete smoke bucket: %v", err)
		}
	})
	return bucket
}

// TestS3RustFSAllocatorSafetyTLSSmoke checks the conditional-write outcomes the
// vault allocator depends on against a real RustFS endpoint: replace-missing
// conflicts, create/read round-trip, one winner for a same-revision race, and a
// stale revision that changes nothing.
func TestS3RustFSAllocatorSafetyTLSSmoke(t *testing.T) {
	env := requireRustFSsmoke(t)
	bucket := provisionRustFSsmokeBucket(t, env)
	ctx, cancel := context.WithTimeout(context.Background(), 2*rustfsSmokeTimeout)
	defer cancel()

	const name = "allocator.bin"
	missingETag := Revision(`"00000000000000000000000000000000"`)
	first := env.newBackend(t, bucket)
	second := env.newBackend(t, bucket)

	// (1) ReplaceIfVersion on a missing key is a conflict, and the key stays
	// absent.
	if err := first.ReplaceIfVersion(ctx, name, missingETag, []byte("missing")); !errors.Is(err, ErrConflict) {
		t.Fatalf("ReplaceIfVersion on missing key: err = %v, want ErrConflict", err)
	}
	if _, err := first.Read(ctx, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read after replace-missing: err = %v, want ErrNotFound", err)
	}

	// (2) CreateIfAbsent + Read round-trip the exact bytes and one strong
	// revision.
	original := []byte("rustfs-smoke\x00original\xff\n")
	if err := first.CreateIfAbsent(ctx, name, original); err != nil {
		t.Fatalf("CreateIfAbsent: %v", err)
	}
	read := func(b Backend, what string) ReadResult {
		t.Helper()
		res, err := b.Read(ctx, name)
		if err != nil {
			t.Fatalf("%s: Read: %v", what, err)
		}
		return res
	}
	base := read(first, "after create")
	if !bytes.Equal(base.Bytes, original) {
		t.Fatalf("after create: bytes %q, want %q", base.Bytes, original)
	}
	if base.Revision.Zero() || !validStrongETag(string(base.Revision)) {
		t.Fatalf("after create: revision %q is not one nonzero strong quoted ETag", base.Revision)
	}

	// (3) Two fresh instances race with the same revision: exactly one
	// commits, the other is ErrConflict, anything else fails the smoke.
	type outcome struct {
		label string
		val   []byte
		err   error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, w := range []struct {
		label string
		b     Backend
		val   []byte
	}{
		{"first", first, []byte("rustfs-smoke-winner-a")},
		{"second", second, []byte("rustfs-smoke-winner-b")},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- outcome{label: w.label, val: w.val, err: w.b.ReplaceIfVersion(ctx, name, base.Revision, w.val)}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var winner outcome
	committed := 0
	for res := range results {
		switch {
		case res.err == nil:
			committed++
			winner = res
		case errors.Is(res.err, ErrConflict):
		default:
			t.Fatalf("racing ReplaceIfVersion by %s: unexpected err = %v", res.label, res.err)
		}
	}
	if committed != 1 {
		t.Fatalf("racing ReplaceIfVersion: %d committed, want exactly 1", committed)
	}
	afterRace := read(first, "after race")
	if !bytes.Equal(afterRace.Bytes, winner.val) {
		t.Fatalf("after race: stored bytes %q, want winner's (%s) %q", afterRace.Bytes, winner.label, winner.val)
	}

	// (4) The stale base revision conflicts and leaves the winner in place.
	if err := second.ReplaceIfVersion(ctx, name, base.Revision, []byte("rustfs-smoke-stale")); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale ReplaceIfVersion: err = %v, want ErrConflict", err)
	}
	final := read(second, "final")
	if !bytes.Equal(final.Bytes, winner.val) || final.Revision != afterRace.Revision {
		t.Fatalf("final version: bytes %q revision %q, want %q / %q",
			final.Bytes, final.Revision, winner.val, afterRace.Revision)
	}
}
