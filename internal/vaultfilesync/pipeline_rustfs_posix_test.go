//go:build darwin || linux

package vaultfilesync

// Opt-in real-provider companion for
// TestPipelinePublishThirdWriterPreservesLocalWorking. It runs the exact same
// end-to-end third-writer scenario through the production
// vaultfilebackend.NewS3 constructor against an already-running, pinned local
// RustFS instance over verified TLS. It is not a mock and never contacts a
// cloud or external endpoint.
//
// The test is skipped unless RUSTFS_SMOKE_ENABLE=1, RUSTFS_SMOKE_ENDPOINT and
// RUSTFS_SMOKE_CA_FILE are set, and -rustfs-credential-file points at a private
// regular file with no group/other permissions holding RUSTFS_ACCESS_KEY=...
// and RUSTFS_SECRET_KEY=.... The endpoint must be an explicit https loopback
// URL. Credentials come only from that file; no environment/default provider
// chain is used. TLS is verified against exactly the supplied CA, with no
// insecure bypass. A fresh unique bucket is created for the run and removed
// afterwards, so every object is isolated from other tests and runs.
//
// Run it with a synthetic credential file (never commit real credentials):
//
//	printf 'RUSTFS_ACCESS_KEY=test-access-key\nRUSTFS_SECRET_KEY=test-secret-key\n' > /private/tmp/rustfs.env
//	chmod 600 /private/tmp/rustfs.env
//	RUSTFS_SMOKE_ENABLE=1 \
//	RUSTFS_SMOKE_ENDPOINT=https://127.0.0.1:9443 \
//	RUSTFS_SMOKE_CA_FILE=/private/tmp/rustfs-ca.pem \
//	go test ./internal/vaultfilesync -run '^TestPipelinePublishThirdWriterOnRustFS$' -v \
//	    -args -rustfs-credential-file=/private/tmp/rustfs.env

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

const (
	rustfsPipelineEnableEnv   = "RUSTFS_SMOKE_ENABLE"
	rustfsPipelineEndpointEnv = "RUSTFS_SMOKE_ENDPOINT"
	rustfsPipelineCAFileEnv   = "RUSTFS_SMOKE_CA_FILE"
	rustfsPipelineRegion      = "us-east-1"
	rustfsPipelineTimeout     = 30 * time.Second

	// rustfsPipelineCredentialLimit bounds the credential file before parsing.
	rustfsPipelineCredentialLimit = 64 << 10
)

// rustfsPipelineCredentialFile is this test binary's explicit flag. The harness
// passes it with -args, as the sibling vaultfilebackend RustFS smoke does.
var rustfsPipelineCredentialFile = flag.String("rustfs-credential-file", "",
	"path to a private file holding RUSTFS_ACCESS_KEY and RUSTFS_SECRET_KEY (real RustFS pipeline test only)")

// rustfsPipelineEnv is the caller-supplied environment of one real-provider
// run. Every field is built from explicit inputs; no provider chain is used.
type rustfsPipelineEnv struct {
	endpoint string
	client   *http.Client
	creds    aws.CredentialsProvider
}

// requireRustFSPipeline returns the configured environment, or skips when the
// opt-in has not been requested. Once opted in, every mandatory input is
// required: an incomplete configuration fails instead of silently skipping.
func requireRustFSPipeline(t *testing.T) rustfsPipelineEnv {
	t.Helper()
	if os.Getenv(rustfsPipelineEnableEnv) != "1" {
		t.Skipf("real RustFS pipeline test is opt-in: set %s=1 plus %s, %s and -rustfs-credential-file",
			rustfsPipelineEnableEnv, rustfsPipelineEndpointEnv, rustfsPipelineCAFileEnv)
	}
	endpoint := os.Getenv(rustfsPipelineEndpointEnv)
	caFile := os.Getenv(rustfsPipelineCAFileEnv)
	var missing []string
	if endpoint == "" {
		missing = append(missing, rustfsPipelineEndpointEnv)
	}
	if caFile == "" {
		missing = append(missing, rustfsPipelineCAFileEnv)
	}
	if len(missing) > 0 {
		t.Fatalf("%s=1 but mandatory configuration is missing: %s", rustfsPipelineEnableEnv, strings.Join(missing, ", "))
	}
	if *rustfsPipelineCredentialFile == "" {
		t.Fatalf("%s=1 but -rustfs-credential-file is missing", rustfsPipelineEnableEnv)
	}
	if err := validateRustFSPipelineEndpoint(endpoint); err != nil {
		t.Fatalf("RustFS endpoint rejected: %v", err)
	}
	accessKey, secretKey := readRustFSPipelineCredentials(t, *rustfsPipelineCredentialFile)

	// Trust exactly the supplied CA. The system pool is not consulted and
	// verification is never skipped; the only accepted scheme is https.
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("read RustFS CA file failed: %s", rustfsPipelineSafeError(err))
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("RustFS CA file contains no PEM certificate")
	}
	client := &http.Client{
		Transport: &http.Transport{
			// No proxy: the validated endpoint is the only permitted origin,
			// and a nil Proxy field never consults the environment.
			Proxy:             nil,
			TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
		// Never follow a provider redirect, even to another loopback address:
		// return the redirect response without issuing the redirected request.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: rustfsPipelineTimeout,
	}
	return rustfsPipelineEnv{
		endpoint: endpoint,
		client:   client,
		creds:    credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
	}
}

// validateRustFSPipelineEndpoint requires an absolute https URL whose host is
// an explicit loopback IP with a nonzero port. It rejects external names and
// addresses, plain http, user info, queries and fragments before any request.
func validateRustFSPipelineEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return errors.New("endpoint is not a valid URL")
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Opaque != "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("endpoint must be an absolute https URL without user info, query or fragment")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return errors.New("endpoint must include an explicit host and port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("endpoint host must be an explicit loopback IP address")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("endpoint port is invalid")
	}
	return nil
}

// readRustFSPipelineCredentials reads the static keys from the private
// credential file. The file is opened read-only, must be a regular file that
// stays the same opened file, must not be group/other accessible, and is
// bounded before parsing. Error messages never include file contents or keys.
func readRustFSPipelineCredentials(t *testing.T, path string) (accessKey, secretKey string) {
	t.Helper()
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("credential file is unavailable: %s", rustfsPipelineSafeError(err))
	}
	if !before.Mode().IsRegular() {
		t.Fatal("credential file must be a regular file, not a symlink or special file")
	}
	if before.Mode().Perm()&0o077 != 0 {
		t.Fatal("credential file must have no group or other permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open credential file failed: %s", rustfsPipelineSafeError(err))
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		t.Fatalf("stat opened credential file failed: %s", rustfsPipelineSafeError(err))
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Mode().Perm()&0o077 != 0 {
		t.Fatal("credential file changed or is not a private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, rustfsPipelineCredentialLimit+1))
	if err != nil {
		t.Fatalf("read credential file failed: %s", rustfsPipelineSafeError(err))
	}
	if len(data) > rustfsPipelineCredentialLimit {
		t.Fatal("credential file is larger than the bounded credential limit")
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
		t.Fatal("credential file lacks RUSTFS_ACCESS_KEY or RUSTFS_SECRET_KEY")
	}
	return accessKey, secretKey
}

// sdkClient provisions and removes only this run's unique bucket.
func (e rustfsPipelineEnv) sdkClient() *s3.Client {
	endpoint := e.endpoint
	return s3.New(s3.Options{
		Region:                     rustfsPipelineRegion,
		BaseEndpoint:               &endpoint,
		Credentials:                aws.NewCredentialsCache(e.creds),
		UsePathStyle:               true,
		HTTPClient:                 e.client,
		Retryer:                    aws.NopRetryer{},
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
}

// newBackendAt constructs one fresh production S3 backend over bucket and
// prefix. Every call gets its own NewS3 instance and HTTP stack; the caller owns
// Close through the registered cleanup.
func (e rustfsPipelineEnv) newBackendAt(t *testing.T, bucket, prefix string) vaultfilebackend.Backend {
	t.Helper()
	b, err := vaultfilebackend.NewS3(vaultfilebackend.S3Config{
		Endpoint:     e.endpoint,
		Region:       rustfsPipelineRegion,
		Bucket:       bucket,
		Prefix:       prefix,
		Credentials:  e.creds,
		UsePathStyle: true,
		HTTPClient:   e.client,
	})
	if err != nil {
		t.Fatalf("NewS3: %s", rustfsPipelineSafeError(err))
	}
	t.Cleanup(func() { _ = b.Close() })
	return rustfsPipelineRedactingBackend{Backend: b}
}

// provisionRustFSPipelineBucket creates a unique bucket for this run and
// registers its removal. Cleanup errors and assertions never print the bucket
// name, provider URL, request IDs, credentials or object bytes.
func provisionRustFSPipelineBucket(t *testing.T, e rustfsPipelineEnv) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), rustfsPipelineTimeout)
	defer cancel()
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("random bucket suffix failed: %s", rustfsPipelineSafeError(err))
	}
	bucket := "locklark-rustfs-pipeline-" + fmt.Sprintf("%x", suffix)
	client := e.sdkClient()
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("provision ephemeral RustFS bucket failed: %s", rustfsPipelineSafeError(err))
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), rustfsPipelineTimeout)
		defer cancel()
		out, err := client.ListObjectsV2(cleanupCtx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
		if err != nil {
			t.Errorf("list ephemeral RustFS bucket for cleanup failed: %s", rustfsPipelineSafeError(err))
			return
		}
		for _, obj := range out.Contents {
			if _, err := client.DeleteObject(cleanupCtx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    obj.Key,
			}); err != nil {
				t.Errorf("delete ephemeral RustFS object for cleanup failed: %s", rustfsPipelineSafeError(err))
			}
		}
		if _, err := client.DeleteBucket(cleanupCtx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
			t.Errorf("delete ephemeral RustFS bucket failed: %s", rustfsPipelineSafeError(err))
		}
	})
	return bucket
}

// TestPipelinePublishThirdWriterOnRustFS runs the exact local third-writer
// regression over the production S3 backend and a real local RustFS provider.
// Two separately constructed NewS3 handles address the same unique bucket and
// prefix. The active path reads B, adopts M, and its first real conditional
// write is entered; inside that call the second real handle reads B, commits T
// from B's exact provider revision, and then the active write is forwarded
// unmodified. The provider's stale If-Match answer must be the CAS conflict,
// the losing journal must retain M and its prepared recovery record, and after
// close/reopen the recovered edits must be exactly the local edit plus T.
func TestPipelinePublishThirdWriterOnRustFS(t *testing.T) {
	env := requireRustFSPipeline(t)
	bucket := provisionRustFSPipelineBucket(t, env)
	const prefix = "third-writer-pipeline"

	first := env.newBackendAt(t, bucket, prefix)
	second := env.newBackendAt(t, bucket, prefix)
	f := newThirdWriterFixtureAt(t, first)
	runThirdWriterScenario(t, f, second)
}

// rustfsPipelineRedactingBackend keeps the real production backend unchanged
// underneath, but replaces any provider error message at the test boundary.
// errors.Is/As still reach the original error through Unwrap, while formatted
// failures cannot expose a URL, request ID or provider diagnostic body. The
// RustFS scenario asserts outcomes by sentinel, never by message text.
type rustfsPipelineRedactingBackend struct {
	vaultfilebackend.Backend
}

func (b rustfsPipelineRedactingBackend) Read(ctx context.Context, name string) (vaultfilebackend.ReadResult, error) {
	res, err := b.Backend.Read(ctx, name)
	return res, rustfsPipelineRedact(err)
}

func (b rustfsPipelineRedactingBackend) CreateIfAbsent(ctx context.Context, name string, value []byte) error {
	return rustfsPipelineRedact(b.Backend.CreateIfAbsent(ctx, name, value))
}

func (b rustfsPipelineRedactingBackend) ReplaceIfVersion(ctx context.Context, name string, expected vaultfilebackend.Revision, value []byte) error {
	return rustfsPipelineRedact(b.Backend.ReplaceIfVersion(ctx, name, expected, value))
}

func (b rustfsPipelineRedactingBackend) List(ctx context.Context) ([]string, error) {
	names, err := b.Backend.List(ctx)
	return names, rustfsPipelineRedact(err)
}

// rustfsPipelineRedactedError hides the provider's message but preserves the
// original error for errors.Is and errors.As.
type rustfsPipelineRedactedError struct {
	err error
}

func (e rustfsPipelineRedactedError) Error() string {
	return "RustFS provider operation failed (details suppressed)"
}

func (e rustfsPipelineRedactedError) Unwrap() error { return e.err }

func rustfsPipelineRedact(err error) error {
	if err == nil {
		return nil
	}
	return rustfsPipelineRedactedError{err: err}
}

// rustfsPipelineSafeError formats only the error's category or Go type, never
// its message. It is used for harness setup, credential and cleanup failures,
// where the provider error may include a URL, request ID or response body.
func rustfsPipelineSafeError(err error) string {
	if err == nil {
		return "no error"
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "context canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "context deadline exceeded"
	case errors.Is(err, vaultfilebackend.ErrConflict):
		return "provider conflict"
	case errors.Is(err, vaultfilebackend.ErrUnknown):
		return "provider outcome unknown"
	case errors.Is(err, vaultfilebackend.ErrDenied):
		return "provider denied"
	case errors.Is(err, vaultfilebackend.ErrNotFound):
		return "provider object not found"
	case errors.Is(err, vaultfilebackend.ErrCorrupt):
		return "provider object corrupt"
	}
	return fmt.Sprintf("provider error type %T", err)
}
