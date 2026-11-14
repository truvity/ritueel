package kms_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/kms"
)

// The names of the tests are the made-up names of the vectors.
const (
	account  = "123456789012"
	keyARN   = "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"
	holder   = "arn:aws:iam::123456789012:role/example-key-holder"
	readRole = "arn:aws:iam::123456789012:role/example-certifier-read"
)

var testNow = time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)

// role is the principal of a role of the test account.
func role(name string) handoff.Principal {
	return handoff.Principal{ARN: "arn:aws:iam::" + account + ":role/" + name, Kind: handoff.PrincipalRole}
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keyDER(t testing.TB, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// jsonOf renders a Go value as JSON text.
func jsonOf(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// policyOf renders a key policy of the version 2012-10-17 with the statements.
func policyOf(t testing.TB, statements ...any) string {
	t.Helper()
	return jsonOf(t, map[string]any{"Version": "2012-10-17", "Statement": statements})
}

// stmt is an Allow statement of the actions for the principal object {"AWS": aws}.
func stmt(aws any, actions ...string) map[string]any {
	var a any = actions
	if len(actions) == 1 {
		a = actions[0]
	}
	return map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": aws}, "Action": a, "Resource": "*"}
}

// holderPolicy is the policy of a good key: one statement that allows kms:Sign to the one role, and an
// administrator statement that does not.
func holderPolicy(t testing.TB) string {
	t.Helper()
	return policyOf(t,
		stmt("arn:aws:iam::"+account+":role/example-key-admin", "kms:Describe*", "kms:Get*", "kms:List*"),
		stmt(holder, "kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"),
	)
}

// goodDescription is what DescribeKey tells for a key that the contract accepts.
func goodDescription(arn string) *kms.KeyDescription {
	return &kms.KeyDescription{
		ARN: arn, KeyID: arn[strings.LastIndex(arn, "/")+1:],
		KeySpec: "ECC_NIST_P384", KeyUsage: "SIGN_VERIFY", KeyState: "Enabled", Origin: "AWS_KMS", KeyManager: "CUSTOMER",
		SigningAlgorithms: []string{"ECDSA_SHA_384"},
	}
}

// fakeAPI is a kms.API that a test controls. It records the calls and the arguments.
type fakeAPI struct {
	mu        sync.Mutex
	desc      *kms.KeyDescription
	descErr   error
	pub       *kms.PublicKeyAnswer
	pubErr    error
	policy    string
	policyErr error
	// hook runs first in every call, with the name of the call.
	hook  func(call string)
	calls []string
	arns  []string
	names []string
}

// newFake is the API of a good key: its description, its public key and a policy for one role.
func newFake(t testing.TB) *fakeAPI {
	t.Helper()
	key := newKey(t)
	return &fakeAPI{
		desc:   goodDescription(keyARN),
		pub:    &kms.PublicKeyAnswer{KeyID: keyARN, KeySpec: "ECC_NIST_P384", PublicKey: keyDER(t, &key.PublicKey)},
		policy: holderPolicy(t),
	}
}

func (f *fakeAPI) log(call, arn string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.arns = append(f.arns, arn)
	hook := f.hook
	f.mu.Unlock()
	if hook != nil {
		hook(call)
	}
}

func (f *fakeAPI) DescribeKey(_ context.Context, arn string) (*kms.KeyDescription, error) {
	f.log("DescribeKey", arn)
	return f.desc, f.descErr
}

func (f *fakeAPI) GetPublicKey(_ context.Context, arn string) (*kms.PublicKeyAnswer, error) {
	f.log("GetPublicKey", arn)
	return f.pub, f.pubErr
}

func (f *fakeAPI) GetKeyPolicy(_ context.Context, arn, name string) (string, error) {
	f.log("GetKeyPolicy", arn)
	f.mu.Lock()
	f.names = append(f.names, name)
	f.mu.Unlock()
	return f.policy, f.policyErr
}

func (f *fakeAPI) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// fakeConnector is a kms.Connector that a test controls. It records what Open was given.
type fakeConnector struct {
	mu        sync.Mutex
	api       kms.API
	apiFor    func(role string) kms.API
	err       error
	roles     []string
	deadlines []time.Time
	hasDL     []bool
	// hook runs first in Open.
	hook func()
}

func (c *fakeConnector) Open(ctx context.Context, role string) (kms.API, error) {
	dl, ok := ctx.Deadline()
	c.mu.Lock()
	c.roles = append(c.roles, role)
	c.deadlines = append(c.deadlines, dl)
	c.hasDL = append(c.hasDL, ok)
	hook := c.hook
	api, apiFor, err := c.api, c.apiFor, c.err
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return nil, err
	}
	if apiFor != nil {
		return apiFor(role), nil
	}
	return api, nil
}

func (c *fakeConnector) opens() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.roles)
}

// newVerifier makes a Verifier over the connector and fails the test when New refuses.
func newVerifier(t testing.TB, c kms.Connector, roles map[string]string) *kms.Verifier {
	t.Helper()
	v, err := kms.New(kms.Config{Connector: c, ReadRoles: roles})
	if err != nil {
		t.Fatalf("New refused a whole configuration: %v", err)
	}
	return v
}

// proofFor is the proof of an aws-kms request whose evidence names the ARN and holds the public key.
func proofFor(t testing.TB, arn string, der []byte) *handoff.Proof {
	t.Helper()
	return &handoff.Proof{Store: handoff.StoreKMS, Evidence: []byte(jsonOf(t, map[string]string{
		"key_arn": arn, "public_key": base64.StdEncoding.EncodeToString(der),
	}))}
}

// proofRaw is a proof whose evidence is the text, whatever it is.
func proofRaw(evidence string) *handoff.Proof {
	return &handoff.Proof{Store: handoff.StoreKMS, Evidence: []byte(evidence)}
}

// someDER is a P-384 public key in one spelling, for a proof whose key does not matter.
func someDER(t testing.TB) []byte {
	t.Helper()
	return keyDER(t, &newKey(t).PublicKey)
}

// wantCode checks that err is a *handoff.CodeError with the code, and that it is no undecided error.
func wantCode(t testing.TB, err error, code handoff.Code) *handoff.CodeError {
	t.Helper()
	var ce *handoff.CodeError
	if !errors.As(err, &ce) {
		t.Fatalf("error %v, want a *handoff.CodeError with the code %q", err, code)
	}
	if ce.Code != code {
		t.Fatalf("code %q (%s), want %q", ce.Code, ce.Detail, code)
	}
	if errors.Is(err, kms.ErrUndecided) {
		t.Fatalf("an error that is a refusal and undecided at once: %v", err)
	}
	return ce
}

// wantUndecided checks that err wraps ErrUndecided and is no refusal of any kind.
func wantUndecided(t testing.TB, err error) {
	t.Helper()
	if !errors.Is(err, kms.ErrUndecided) {
		t.Fatalf("error %v, want one that wraps ErrUndecided", err)
	}
	var ce *handoff.CodeError
	if errors.As(err, &ce) {
		t.Fatalf("an undecided error that is also a refusal: %v", err)
	}
	var r *kms.Refusal
	if errors.As(err, &r) {
		t.Fatalf("an undecided error that is also a kms refusal: %v", err)
	}
}

// printable reports whether s holds only printable ASCII.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}
