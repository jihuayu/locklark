package vaultfilebackend

// Opt-in STS transport-isolation acceptance for issue #122 against an
// already-running, isolated loopback RustFS instance over verified TLS.
//
// The test reuses the sibling RustFS smoke configuration: it is skipped unless
// RUSTFS_SMOKE_ENABLE=1, RUSTFS_SMOKE_ENDPOINT and RUSTFS_SMOKE_CA_FILE are set,
// and -rustfs-credential-file points at a private regular file holding
// RUSTFS_ACCESS_KEY=... and RUSTFS_SECRET_KEY=.... The credentials and TLS root
// are synthetic/local only: no AWS account, production or shared service,
// default credential chain, provider command, cloud metadata, or redirect is
// used. The endpoint is checked to be an explicit HTTPS loopback IP before any
// provisioning or STS request is sent, and redirects are refused on every
// client used here.
//
// Two unique buckets are provisioned by the synthetic root. Two different
// temporary STS credentials are then requested with a signed POST /,
// x-www-form-urlencoded AssumeRole request (Version=2011-06-15,
// DurationSeconds=900) whose session policy allows Get/Put/List for exactly one
// of those buckets. The test checks each credential against its own bucket with
// the production S3 adapter, then checks the opposite bucket through direct SDK
// calls and through the adapter. Rejections are asserted as typed ErrDenied
// results and, only from the test's dedicated recording transports, as real
// HTTP 403 responses; adapter errors are never inspected for a raw service error
// because the production classifier deliberately keeps it out of the chain.
//
// The records contain only the request method and numeric response status, and
// are reset before every asserted phase. No access key, secret, session token,
// provider identifier, URL, header, bucket, key, body or service error body is
// recorded or printed. The two reads after the cross attempts prove the
// original bytes and revisions, and an own-bucket list proves no cross-create
// key was added.
//
// Run it with the sibling RustFS smoke harness; never commit real credentials.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	rustfsSTSAssumeRoleVersion  = "2011-06-15"
	rustfsSTSAssumeRoleDuration = 900
	rustfsSTSResponseLimit      = 256 << 10
	rustfsSTSErrorLimit         = 4 << 10
	rustfsSTSPrefix             = "sts-isolation"
	rustfsSTSOwnedName          = "owned.bin"
	rustfsSTSCrossCreateName    = "cross-create.bin"
)

// TestS3RustFSTLSScopedSTSTransportIsolation is the root acceptance test. It
// proves that two independent temporary STS identities, each scoped to one
// unique bucket, can use the production adapter only within that bucket.
func TestS3RustFSTLSScopedSTSTransportIsolation(t *testing.T) {
	env := requireRustFSsmoke(t)

	// Validate the explicit loopback HTTPS endpoint and the trusted local TLS
	// transport before any provisioning, STS, or other network request.
	stsEndpoint, err := rustfsSTSValidateLoopbackEndpoint(env.endpoint)
	if err != nil {
		t.Fatalf("RustFS endpoint rejected: %v", err)
	}
	rustfsSTSRequireTrustedTLS(t, env)
	env.client.CheckRedirect = rustfsSTSRefuseRedirect

	bucketA := provisionRustFSsmokeBucket(t, env)
	bucketB := provisionRustFSsmokeBucket(t, env)
	if bucketA == bucketB {
		t.Fatal("provisioned buckets are not unique")
	}
	if !strings.HasPrefix(bucketA, "locklark-rustfs-smoke-") ||
		!strings.HasPrefix(bucketB, "locklark-rustfs-smoke-") {
		t.Fatal("provisioned buckets do not have the expected synthetic shape")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*rustfsSmokeTimeout)
	defer cancel()

	root, err := env.creds.Retrieve(ctx)
	if err != nil || root.AccessKeyID == "" || root.SecretAccessKey == "" {
		t.Fatal("synthetic root credentials are unavailable")
	}

	credentialA := rustfsSTSAssumeRoleForBucket(t, ctx, env, stsEndpoint, root, bucketA, "a")
	credentialB := rustfsSTSAssumeRoleForBucket(t, ctx, env, stsEndpoint, root, bucketB, "b")
	if credentialA.SessionToken == "" || credentialB.SessionToken == "" {
		t.Fatal("AssumeRole returned a credential without a session token")
	}
	if credentialA.AccessKeyID == credentialB.AccessKeyID &&
		credentialA.SecretAccessKey == credentialB.SecretAccessKey &&
		credentialA.SessionToken == credentialB.SessionToken {
		t.Fatal("AssumeRole returned the same temporary credential twice")
	}

	ownAlog, crossAlog := &rustfsSTSCallLog{}, &rustfsSTSCallLog{}
	ownBlog, crossBlog := &rustfsSTSCallLog{}, &rustfsSTSCallLog{}
	ownAClient := rustfsSTSRecordingClient(t, env.client, ownAlog)
	crossAClient := rustfsSTSRecordingClient(t, env.client, crossAlog)
	ownBClient := rustfsSTSRecordingClient(t, env.client, ownBlog)
	crossBClient := rustfsSTSRecordingClient(t, env.client, crossBlog)

	ownAEnv := rustfsSTSEnvWithCredential(env, credentialA, ownAClient)
	crossAEnv := rustfsSTSEnvWithCredential(env, credentialA, crossAClient)
	ownBEnv := rustfsSTSEnvWithCredential(env, credentialB, ownBClient)
	crossBEnv := rustfsSTSEnvWithCredential(env, credentialB, crossBClient)

	ownA := ownAEnv.newBackendAt(t, bucketA, rustfsSTSPrefix)
	crossA := crossAEnv.newBackendAt(t, bucketB, rustfsSTSPrefix)
	ownB := ownBEnv.newBackendAt(t, bucketB, rustfsSTSPrefix)
	crossB := crossBEnv.newBackendAt(t, bucketA, rustfsSTSPrefix)

	// A/B own positive: create, read, and conditional replace through the
	// production adapter with each bucket-scoped identity.
	ownAlog.reset()
	originalA := []byte("sts-a-original")
	replacementA := []byte("sts-a-replaced")
	rustfsSTSRequireOK(t, "A own create", ownA.CreateIfAbsent(ctx, rustfsSTSOwnedName, originalA))
	createdA, err := ownA.Read(ctx, rustfsSTSOwnedName)
	rustfsSTSRequireOK(t, "A own read", err)
	if !bytes.Equal(createdA.Bytes, originalA) {
		t.Fatal("A own read did not return the created bytes")
	}
	rustfsSTSRequireOK(t, "A own replace", ownA.ReplaceIfVersion(ctx, rustfsSTSOwnedName, createdA.Revision, replacementA))
	beforeCrossA, err := ownA.Read(ctx, rustfsSTSOwnedName)
	rustfsSTSRequireOK(t, "A own read after replace", err)
	if !bytes.Equal(beforeCrossA.Bytes, replacementA) {
		t.Fatal("A own replace did not store the replacement bytes")
	}
	rustfsSTSRequireStrongRevision(t, "A own revision", beforeCrossA.Revision)
	ownAlog.assertExactly(t,
		rustfsSTSCall{http.MethodPut, http.StatusOK},
		rustfsSTSCall{http.MethodGet, http.StatusOK},
		rustfsSTSCall{http.MethodPut, http.StatusOK},
		rustfsSTSCall{http.MethodGet, http.StatusOK},
	)

	ownBlog.reset()
	originalB := []byte("sts-b-original")
	replacementB := []byte("sts-b-replaced")
	rustfsSTSRequireOK(t, "B own create", ownB.CreateIfAbsent(ctx, rustfsSTSOwnedName, originalB))
	createdB, err := ownB.Read(ctx, rustfsSTSOwnedName)
	rustfsSTSRequireOK(t, "B own read", err)
	if !bytes.Equal(createdB.Bytes, originalB) {
		t.Fatal("B own read did not return the created bytes")
	}
	rustfsSTSRequireOK(t, "B own replace", ownB.ReplaceIfVersion(ctx, rustfsSTSOwnedName, createdB.Revision, replacementB))
	beforeCrossB, err := ownB.Read(ctx, rustfsSTSOwnedName)
	rustfsSTSRequireOK(t, "B own read after replace", err)
	if !bytes.Equal(beforeCrossB.Bytes, replacementB) {
		t.Fatal("B own replace did not store the replacement bytes")
	}
	rustfsSTSRequireStrongRevision(t, "B own revision", beforeCrossB.Revision)
	ownBlog.assertExactly(t,
		rustfsSTSCall{http.MethodPut, http.StatusOK},
		rustfsSTSCall{http.MethodGet, http.StatusOK},
		rustfsSTSCall{http.MethodPut, http.StatusOK},
		rustfsSTSCall{http.MethodGet, http.StatusOK},
	)

	// Direct SDK cross checks: each identity is allowed its own bucket but is
	// refused an object read and a bucket list on the opposite bucket with a
	// real 403. The transport recorder captures only the GetObject call.
	crossAlog.reset()
	crossARead, err := crossA.Read(ctx, rustfsSTSOwnedName)
	rustfsSTSRequireDenied(t, "A adapter cross read", err)
	if len(crossARead.Bytes) != 0 {
		t.Fatal("A adapter cross read returned bytes despite ErrDenied")
	}
	if crossARead.Revision != "" {
		t.Fatal("A adapter cross read returned a revision despite ErrDenied")
	}
	crossAlog.assertExactly(t, rustfsSTSCall{http.MethodGet, http.StatusForbidden})

	crossAlog.reset()
	crossASDK := crossAEnv.sdkClient()
	if _, err := crossASDK.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketB),
		Key:    aws.String(rustfsSTSPrefix + "/" + rustfsSTSOwnedName),
	}); err == nil {
		t.Fatal("A direct cross GetObject unexpectedly succeeded")
	} else {
		rustfsSTSRequireDirectStatus(t, "A direct cross GetObject", err, http.StatusForbidden)
	}
	crossAlog.assertExactly(t, rustfsSTSCall{http.MethodGet, http.StatusForbidden})

	crossAlog.reset()
	if _, err := crossASDK.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucketB)}); err == nil {
		t.Fatal("A direct cross list unexpectedly succeeded")
	} else {
		rustfsSTSRequireDirectStatus(t, "A direct cross list", err, http.StatusForbidden)
	}
	crossAlog.assertExactly(t)

	crossBlog.reset()
	crossBRead, err := crossB.Read(ctx, rustfsSTSOwnedName)
	rustfsSTSRequireDenied(t, "B adapter cross read", err)
	if len(crossBRead.Bytes) != 0 {
		t.Fatal("B adapter cross read returned bytes despite ErrDenied")
	}
	if crossBRead.Revision != "" {
		t.Fatal("B adapter cross read returned a revision despite ErrDenied")
	}
	crossBlog.assertExactly(t, rustfsSTSCall{http.MethodGet, http.StatusForbidden})

	crossBlog.reset()
	crossBSDK := crossBEnv.sdkClient()
	if _, err := crossBSDK.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketA),
		Key:    aws.String(rustfsSTSPrefix + "/" + rustfsSTSOwnedName),
	}); err == nil {
		t.Fatal("B direct cross GetObject unexpectedly succeeded")
	} else {
		rustfsSTSRequireDirectStatus(t, "B direct cross GetObject", err, http.StatusForbidden)
	}
	crossBlog.assertExactly(t, rustfsSTSCall{http.MethodGet, http.StatusForbidden})

	crossBlog.reset()
	if _, err := crossBSDK.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucketA)}); err == nil {
		t.Fatal("B direct cross list unexpectedly succeeded")
	} else {
		rustfsSTSRequireDirectStatus(t, "B direct cross list", err, http.StatusForbidden)
	}
	crossBlog.assertExactly(t)

	// Adapter cross create and exact known-token CAS: both are typed ErrDenied,
	// backed by a real 403 on the dedicated transport. The cross-create name
	// must never appear in the target bucket.
	crossTokenA := []byte("sts-a-cross-token")
	crossAlog.reset()
	rustfsSTSRequireDenied(t, "A adapter cross create", crossA.CreateIfAbsent(ctx, rustfsSTSCrossCreateName, crossTokenA))
	crossAlog.assertExactly(t, rustfsSTSCall{http.MethodPut, http.StatusForbidden})

	crossAlog.reset()
	rustfsSTSRequireDenied(t, "A adapter cross replace", crossA.ReplaceIfVersion(ctx, rustfsSTSOwnedName, beforeCrossB.Revision, crossTokenA))
	crossAlog.assertExactly(t, rustfsSTSCall{http.MethodPut, http.StatusForbidden})

	crossTokenB := []byte("sts-b-cross-token")
	crossBlog.reset()
	rustfsSTSRequireDenied(t, "B adapter cross create", crossB.CreateIfAbsent(ctx, rustfsSTSCrossCreateName, crossTokenB))
	crossBlog.assertExactly(t, rustfsSTSCall{http.MethodPut, http.StatusForbidden})

	crossBlog.reset()
	rustfsSTSRequireDenied(t, "B adapter cross replace", crossB.ReplaceIfVersion(ctx, rustfsSTSOwnedName, beforeCrossA.Revision, crossTokenB))
	crossBlog.assertExactly(t, rustfsSTSCall{http.MethodPut, http.StatusForbidden})

	// Re-read the original objects with their own identities. Bytes, revisions,
	// and the exact key set are unchanged by every cross attempt.
	ownAlog.reset()
	afterCrossA, err := ownA.Read(ctx, rustfsSTSOwnedName)
	rustfsSTSRequireOK(t, "A own read after cross", err)
	rustfsSTSRequireStrongRevision(t, "A own revision after cross", afterCrossA.Revision)
	if !bytes.Equal(afterCrossA.Bytes, beforeCrossA.Bytes) || afterCrossA.Revision != beforeCrossA.Revision {
		t.Fatal("A object changed during cross attempts")
	}
	ownAlog.assertExactly(t, rustfsSTSCall{http.MethodGet, http.StatusOK})

	ownBlog.reset()
	afterCrossB, err := ownB.Read(ctx, rustfsSTSOwnedName)
	rustfsSTSRequireOK(t, "B own read after cross", err)
	rustfsSTSRequireStrongRevision(t, "B own revision after cross", afterCrossB.Revision)
	if !bytes.Equal(afterCrossB.Bytes, beforeCrossB.Bytes) || afterCrossB.Revision != beforeCrossB.Revision {
		t.Fatal("B object changed during cross attempts")
	}
	ownBlog.assertExactly(t, rustfsSTSCall{http.MethodGet, http.StatusOK})

	ownAlog.reset()
	rustfsSTSRequireOwnOnlyKey(t, "A", ownAEnv.sdkClient(), bucketA, rustfsSTSExpectedOwnKey())
	ownAlog.assertExactly(t)

	ownBlog.reset()
	rustfsSTSRequireOwnOnlyKey(t, "B", ownBEnv.sdkClient(), bucketB, rustfsSTSExpectedOwnKey())
	ownBlog.assertExactly(t)
}

func rustfsSTSExpectedOwnKey() string {
	return rustfsSTSPrefix + "/" + rustfsSTSOwnedName
}

// rustfsSTSValidateLoopbackEndpoint accepts only an absolute https URL whose
// host is an explicit loopback IP with a nonzero port and whose path is the root
// used by STS. It rejects external names, plain http, user info, queries,
// fragments and non-root paths before any request is made.
func rustfsSTSValidateLoopbackEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("endpoint is not a valid URL")
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Opaque != "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("endpoint must be an absolute https URL without user info, query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("endpoint must use the root path for STS")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, errors.New("endpoint must include an explicit loopback host and port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("endpoint host must be an explicit loopback IP address")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return nil, errors.New("endpoint port is invalid")
	}
	u.Path = "/"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u, nil
}

// rustfsSTSRequireTrustedTLS checks that the sibling harness built the real
// local transport with an explicit CA root pool and without insecure
// verification or an ambient proxy.
func rustfsSTSRequireTrustedTLS(t *testing.T, env rustfsSmokeEnv) {
	t.Helper()
	if env.client == nil {
		t.Fatal("RustFS HTTPS client is missing")
	}
	transport, ok := env.client.Transport.(*http.Transport)
	if !ok || transport == nil || transport.TLSClientConfig == nil {
		t.Fatal("RustFS client does not use the expected local TLS transport")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("RustFS client must verify the local TLS certificate")
	}
	if transport.TLSClientConfig.RootCAs == nil || transport.TLSClientConfig.RootCAs != env.roots {
		t.Fatal("RustFS client must trust exactly the supplied local CA")
	}
	if transport.Proxy != nil {
		t.Fatal("RustFS client must not consult a proxy")
	}
}

func rustfsSTSRefuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// rustfsSTSRecordingClient preserves the real local TLS transport and only
// records the method and numeric status of GetObject/PutObject calls. All other
// request metadata is deliberately ignored.
func rustfsSTSRecordingClient(t *testing.T, base *http.Client, calls *rustfsSTSCallLog) *http.Client {
	t.Helper()
	if base == nil || base.Transport == nil {
		t.Fatal("dedicated S3 client has no real transport")
	}
	return &http.Client{
		Transport:     &rustfsSTSRecordingTransport{base: base.Transport, calls: calls},
		CheckRedirect: rustfsSTSRefuseRedirect,
		Timeout:       base.Timeout,
	}
}

type rustfsSTSCall struct {
	Method string
	Status int
}

type rustfsSTSCallLog struct {
	mu    sync.Mutex
	calls []rustfsSTSCall
}

func (l *rustfsSTSCallLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = nil
}

func (l *rustfsSTSCallLog) record(method string, status int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, rustfsSTSCall{Method: method, Status: status})
}

func (l *rustfsSTSCallLog) snapshot() []rustfsSTSCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]rustfsSTSCall(nil), l.calls...)
}

// assertExactly is strict: there must be exactly the expected calls, in order,
// with no extra fixture or retry traffic, and every record must be only a real
// GET/PUT with 200/403 status.
func (l *rustfsSTSCallLog) assertExactly(t *testing.T, want ...rustfsSTSCall) {
	t.Helper()
	got := l.snapshot()
	if len(got) != len(want) {
		t.Fatalf("recorded transport calls: got %d, want %d", len(got), len(want))
	}
	for i, call := range got {
		if call.Method != http.MethodGet && call.Method != http.MethodPut {
			t.Fatalf("recorded transport call %d has unexpected method %q", i, call.Method)
		}
		if call.Status != http.StatusOK && call.Status != http.StatusForbidden {
			t.Fatalf("recorded transport call %d has unexpected status %d", i, call.Status)
		}
		if call != want[i] {
			t.Fatalf("recorded transport call %d: got %s %d, want %s %d",
				i, call.Method, call.Status, want[i].Method, want[i].Status)
		}
	}
}

type rustfsSTSRecordingTransport struct {
	base  http.RoundTripper
	calls *rustfsSTSCallLog
}

func (r *rustfsSTSRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.base.RoundTrip(req)
	operation := req.URL.Query().Get("x-id")
	if operation == "GetObject" || operation == "PutObject" {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		r.calls.record(req.Method, status)
	}
	return resp, err
}

// rustfsSTSEnvWithCredential returns a copy of the sibling smoke environment
// whose only credential source is the supplied temporary STS credential.
func rustfsSTSEnvWithCredential(base rustfsSmokeEnv, credential rustfsSTSCredential, client *http.Client) rustfsSmokeEnv {
	env := base
	env.creds = credentials.NewStaticCredentialsProvider(
		credential.AccessKeyID,
		credential.SecretAccessKey,
		credential.SessionToken,
	)
	env.client = client
	return env
}

type rustfsSTSCredential struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

type rustfsSTSAssumeRoleResponse struct {
	Result struct {
		Credentials struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleResult"`
}

type rustfsSTSErrorResponse struct {
	Error struct {
		Code string `xml:"Code"`
	} `xml:"Error"`
}

// rustfsSTSAssumeRoleForBucket requests one temporary, session-policy-scoped
// credential with a signed POST to the loopback STS root. The request body is
// the actual signed payload, and the response is parsed from a bounded XML
// document. Failure messages never include the response body, identifiers, or
// credentials.
func rustfsSTSAssumeRoleForBucket(
	t *testing.T,
	ctx context.Context,
	env rustfsSmokeEnv,
	endpoint *url.URL,
	root aws.Credentials,
	bucket string,
	label string,
) rustfsSTSCredential {
	t.Helper()

	policy := fmt.Sprintf(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:ListBucket"],"Resource":["arn:aws:s3:::%s","arn:aws:s3:::%s/*"]}]}`,
		bucket, bucket,
	)
	form := url.Values{}
	form.Set("Action", "AssumeRole")
	form.Set("Version", rustfsSTSAssumeRoleVersion)
	form.Set("DurationSeconds", strconv.Itoa(rustfsSTSAssumeRoleDuration))
	form.Set("Policy", policy)
	form.Set("RoleSessionName", "locklark-rustfs-sts-"+label)
	body := []byte(form.Encode())

	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("AssumeRole request for %s could not be built", label)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := v4.NewSigner().SignHTTP(ctx, root, req, payloadHash, "s3", rustfsSmokeRegion, time.Now()); err != nil {
		t.Fatalf("AssumeRole request for %s could not be signed", label)
	}

	client := *env.client
	client.CheckRedirect = rustfsSTSRefuseRedirect
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("AssumeRole request for %s failed in transport (%T)", label, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		code := rustfsSTSReadErrorCode(resp.Body)
		if code == "" {
			t.Fatalf("AssumeRole for %s returned HTTP %d", label, resp.StatusCode)
		}
		t.Fatalf("AssumeRole for %s returned HTTP %d (%s)", label, resp.StatusCode, code)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, rustfsSTSResponseLimit+1))
	if err != nil {
		t.Fatalf("AssumeRole response for %s could not be read", label)
	}
	if len(data) > rustfsSTSResponseLimit {
		t.Fatalf("AssumeRole response for %s exceeded the bounded XML limit", label)
	}
	var parsed rustfsSTSAssumeRoleResponse
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("AssumeRole response for %s is not bounded valid XML", label)
	}
	credential := rustfsSTSCredential{
		AccessKeyID:     parsed.Result.Credentials.AccessKeyID,
		SecretAccessKey: parsed.Result.Credentials.SecretAccessKey,
		SessionToken:    parsed.Result.Credentials.SessionToken,
	}
	if credential.AccessKeyID == "" || credential.SecretAccessKey == "" || credential.SessionToken == "" {
		t.Fatalf("AssumeRole response for %s lacks complete temporary credentials", label)
	}
	expiration, err := time.Parse(time.RFC3339, strings.TrimSpace(parsed.Result.Credentials.Expiration))
	if err != nil {
		t.Fatalf("AssumeRole response for %s lacks a parseable expiration", label)
	}
	credential.Expiration = expiration
	now := time.Now()
	if !expiration.After(now) {
		t.Fatalf("AssumeRole credentials for %s are already expired", label)
	}
	if expiration.After(now.Add(time.Duration(rustfsSTSAssumeRoleDuration+60) * time.Second)) {
		t.Fatalf("AssumeRole credentials for %s outlive the requested duration", label)
	}
	return credential
}

// rustfsSTSReadErrorCode extracts only a short, safe error code from a bounded
// error document. The body itself is never returned or printed.
func rustfsSTSReadErrorCode(r io.Reader) string {
	var parsed rustfsSTSErrorResponse
	if err := xml.NewDecoder(io.LimitReader(r, rustfsSTSErrorLimit)).Decode(&parsed); err != nil {
		return ""
	}
	code := strings.TrimSpace(parsed.Error.Code)
	if code == "" || len(code) > 64 {
		return ""
	}
	for _, r := range code {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return ""
		}
	}
	return code
}

func rustfsSTSRequireDenied(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("%s: want ErrDenied, got %s", what, rustfsSTSOutcome(err))
	}
}

func rustfsSTSRequireOK(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: got %s", what, rustfsSTSOutcome(err))
	}
}

func rustfsSTSOutcome(err error) string {
	switch {
	case err == nil:
		return "nil"
	case errors.Is(err, ErrDenied):
		return "ErrDenied"
	case errors.Is(err, ErrConflict):
		return "ErrConflict"
	case errors.Is(err, ErrNotFound):
		return "ErrNotFound"
	case errors.Is(err, ErrUnsupported):
		return "ErrUnsupported"
	case errors.Is(err, ErrCorrupt):
		return "ErrCorrupt"
	case errors.Is(err, ErrUnknown):
		return "ErrUnknown"
	default:
		return fmt.Sprintf("%T", err)
	}
}

func rustfsSTSRequireStrongRevision(t *testing.T, what string, revision Revision) {
	t.Helper()
	if revision.Zero() || !validStrongETag(string(revision)) {
		t.Fatalf("%s is not one nonzero strong quoted ETag", what)
	}
}

// rustfsSTSResponseStatus reads only the numeric HTTP status from a direct SDK
// service error. It must not be used on adapter errors: the production
// classifier intentionally keeps the raw service error out of that chain.
func rustfsSTSResponseStatus(err error) (int, bool) {
	var withStatus interface{ HTTPStatusCode() int }
	if errors.As(err, &withStatus) && withStatus.HTTPStatusCode() != 0 {
		return withStatus.HTTPStatusCode(), true
	}
	return 0, false
}

func rustfsSTSRequireDirectStatus(t *testing.T, what string, err error, want int) {
	t.Helper()
	status, ok := rustfsSTSResponseStatus(err)
	if !ok {
		t.Fatalf("%s did not carry a real HTTP status", what)
	}
	if status != want {
		t.Fatalf("%s returned HTTP %d, want %d", what, status, want)
	}
}

// rustfsSTSRequireOwnOnlyKey lists the own bucket through the direct SDK and
// requires exactly the one expected key, proving a cross create added nothing.
func rustfsSTSRequireOwnOnlyKey(t *testing.T, label string, client *s3.Client, bucket, wantKey string) {
	t.Helper()
	out, err := client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	if err != nil {
		status, _ := rustfsSTSResponseStatus(err)
		t.Fatalf("%s own list failed with HTTP status %d", label, status)
	}
	if len(out.Contents) != 1 || aws.ToString(out.Contents[0].Key) != wantKey {
		t.Fatalf("%s own list did not contain exactly the expected key (count=%d)", label, len(out.Contents))
	}
}
