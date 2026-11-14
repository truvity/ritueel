package handoff_test

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/kms"
)

// The checker with the real KMS verifier, over made-up requests: a certificate request made in memory, a
// fake API that answers for it, and nothing from the vectors.

const (
	kmsKeyARN = "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"
	kmsHolder = "arn:aws:iam::123456789012:role/example-key-holder"
)

// kmsFake is a kms.API and a kms.Connector in one: it answers for one key and records the calls.
type kmsFake struct {
	mu        sync.Mutex
	desc      kms.KeyDescription
	pubDER    []byte
	policy    string
	descErr   error
	policyErr error
	panicIn   string
	calls     []string
	roles     []string
}

func (k *kmsFake) Open(_ context.Context, role string) (kms.API, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.roles = append(k.roles, role)
	return k, nil
}

func (k *kmsFake) note(call string) {
	k.mu.Lock()
	k.calls = append(k.calls, call)
	k.mu.Unlock()
	if k.panicIn == call {
		panic("a fault in the API")
	}
}

func (k *kmsFake) DescribeKey(context.Context, string) (*kms.KeyDescription, error) {
	k.note("DescribeKey")
	if k.descErr != nil {
		return nil, k.descErr
	}
	d := k.desc
	return &d, nil
}

func (k *kmsFake) GetPublicKey(context.Context, string) (*kms.PublicKeyAnswer, error) {
	k.note("GetPublicKey")
	return &kms.PublicKeyAnswer{KeyID: kmsKeyARN, KeySpec: "ECC_NIST_P384", PublicKey: k.pubDER}, nil
}

func (k *kmsFake) GetKeyPolicy(context.Context, string, string) (string, error) {
	k.note("GetKeyPolicy")
	return k.policy, k.policyErr
}

// kmsPolicy is a key policy of the version 2012-10-17 with the statements.
func kmsPolicy(t testing.TB, statements ...any) string {
	t.Helper()
	return string(mustJSON(t, map[string]any{"Version": "2012-10-17", "Statement": statements}))
}

func allowSign(principal any, actions ...string) map[string]any {
	if len(actions) == 0 {
		actions = []string{"kms:Sign"}
	}
	return map[string]any{"Effect": "Allow", "Principal": principal, "Action": actions, "Resource": "*"}
}

func awsPrincipal(arn ...string) map[string]any { return map[string]any{"AWS": arn} }

// kmsFixture is a good KMS request, its fake service, and the checker that reads one through the other.
type kmsFixture struct {
	f    *fixture
	fake *kmsFake
}

func newKMSFixture(t testing.TB) *kmsFixture {
	t.Helper()
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	der, err := x509.MarshalPKIXPublicKey(f.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	return &kmsFixture{f: f, fake: &kmsFake{
		desc: kms.KeyDescription{
			ARN: kmsKeyARN, KeyID: "11111111-2222-3333-4444-555555555555", KeySpec: "ECC_NIST_P384", KeyUsage: "SIGN_VERIFY",
			KeyState: "Enabled", Origin: "AWS_KMS", KeyManager: "CUSTOMER", SigningAlgorithms: []string{"ECDSA_SHA_384"},
		},
		pubDER: der,
		policy: kmsPolicy(t, allowSign(awsPrincipal(kmsHolder), "kms:Sign", "kms:GetPublicKey")),
	}}
}

func (x *kmsFixture) checker(t testing.TB, roles map[string]string, extra ...func(c *handoff.Config)) *handoff.Checker {
	t.Helper()
	v, err := kms.New(kms.Config{Connector: x.fake, ReadRoles: roles})
	if err != nil {
		t.Fatal(err)
	}
	return newCheckerWith(t, func(c *handoff.Config) {
		c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StoreKMS: v}
		c.Delegation.KMSReadRoles = roles
		for _, e := range extra {
			e(c)
		}
	})
}

func (x *kmsFixture) check(t testing.TB) (handoff.Verdict, error) {
	t.Helper()
	return x.checker(t, nil).Check(t.Context(), x.f.request())
}

func TestAKMSRequestIsAcceptedEndToEnd(t *testing.T) {
	x := newKMSFixture(t)
	v, err := x.check(t)
	wantAccepted(t, v, err)
	if v.Evidence.Details[kms.DetailKeyARN] != kmsKeyARN || v.Evidence.Details[kms.DetailAccount] != "123456789012" {
		t.Fatalf("details %v", v.Evidence.Details)
	}
	if !v.Key.Equal(x.f.publicKey()) {
		t.Fatal("the key of the verdict is not the key of the request")
	}
	if len(x.fake.calls) != 3 {
		t.Fatalf("calls %v", x.fake.calls)
	}
}

func TestAKMSRequestIsRefusedForWhatTheKeyIs(t *testing.T) {
	rows := map[string]func(x *kmsFixture){
		"a disabled key":    func(x *kmsFixture) { x.fake.desc.KeyState = "Disabled" },
		"a key of P-256":    func(x *kmsFixture) { x.fake.desc.KeySpec = "ECC_NIST_P256" },
		"a key for encrypt": func(x *kmsFixture) { x.fake.desc.KeyUsage = "ENCRYPT_DECRYPT" },
		"an imported key":   func(x *kmsFixture) { x.fake.desc.Origin = "EXTERNAL" },
		"a key of AWS":      func(x *kmsFixture) { x.fake.desc.KeyManager = "AWS" },
		"another ARN":       func(x *kmsFixture) { x.fake.desc.ARN = kmsKeyARN + "0" },
		"a key that cannot be read": func(x *kmsFixture) {
			x.fake.descErr = &kms.APIError{Code: "AccessDeniedException"}
		},
		"a policy that cannot be read": func(x *kmsFixture) {
			x.fake.policyErr = &kms.APIError{Code: "AccessDeniedException"}
		},
		"a policy that is not JSON": func(x *kmsFixture) { x.fake.policy = "x" },
		"a public key that is junk": func(x *kmsFixture) { x.fake.pubDER = []byte("junk") },
	}
	for name, change := range rows {
		t.Run(name, func(t *testing.T) {
			x := newKMSFixture(t)
			change(x)
			v, err := x.check(t)
			wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)
		})
	}
	// The twin of every row.
	v, err := newKMSFixture(t).check(t)
	wantAccepted(t, v, err)
}

func TestAKMSPolicyThatNamesMoreThanOnePrincipalOrTheWrongKindIsRefused(t *testing.T) {
	const acct = "123456789012"
	one := func(principal any, actions ...string) string { return kmsPolicy(t, allowSign(principal, actions...)) }
	rows := []struct {
		name   string
		policy string
		want   handoff.Code // "" for accepted
	}{
		{"one role", one(awsPrincipal(kmsHolder)), ""},
		{"one user", one(awsPrincipal("arn:aws:iam::" + acct + ":user/example-person")), ""},
		{"one role with a path", one(awsPrincipal("arn:aws:iam::" + acct + ":role/path/example")), ""},
		{"one role by a wildcard action", one(awsPrincipal(kmsHolder), "kms:*"), ""},
		{"one role by a pattern", one(awsPrincipal(kmsHolder), "kms:S?gn"), ""},
		{"the one role in two statements", kmsPolicy(t, allowSign(awsPrincipal(kmsHolder)), allowSign(awsPrincipal(kmsHolder), "kms:*")), ""},
		{"the one role twice in one statement", one(awsPrincipal(kmsHolder, kmsHolder)), ""},
		{"the account root with kms:*", one(awsPrincipal("arn:aws:iam::"+acct+":root"), "kms:*"), handoff.CodePolicy},
		{"the account root by its number", one(awsPrincipal(acct)), handoff.CodePolicy},
		{"a wildcard principal", one("*"), handoff.CodePolicy},
		{"a wildcard in AWS", one(awsPrincipal("*")), handoff.CodePolicy},
		{"a role pattern", one(awsPrincipal("arn:aws:iam::" + acct + ":role/*")), handoff.CodePolicy},
		{"two roles", one(awsPrincipal(kmsHolder, "arn:aws:iam::"+acct+":role/example-other")), handoff.CodePolicy},
		{"two roles in two statements", kmsPolicy(t, allowSign(awsPrincipal(kmsHolder)), allowSign(awsPrincipal("arn:aws:iam::"+acct+":role/example-other"))), handoff.CodePolicy},
		{"a role and a user", one(awsPrincipal(kmsHolder, "arn:aws:iam::"+acct+":user/example-person")), handoff.CodePolicy},
		{"a role of another account", kmsPolicy(t, allowSign(awsPrincipal(kmsHolder)), allowSign(awsPrincipal("arn:aws:iam::111122223333:role/example-key-holder"))), handoff.CodePolicy},
		{"a service", one(map[string]any{"Service": "kms.amazonaws.com"}), handoff.CodePolicy},
		{"an assumed role", one(awsPrincipal("arn:aws:sts::" + acct + ":assumed-role/example/session")), handoff.CodePolicy},
		{"NotPrincipal", kmsPolicy(t, map[string]any{"Effect": "Allow", "NotPrincipal": awsPrincipal(kmsHolder), "Action": "kms:Sign", "Resource": "*"}), handoff.CodePolicy},
		{"no principal", kmsPolicy(t, map[string]any{"Effect": "Allow", "Action": "kms:Sign", "Resource": "*"}), handoff.CodePolicy},
		{"no statement that allows Sign", one(awsPrincipal(kmsHolder), "kms:Describe*", "kms:Get*"), handoff.CodePolicy},
		{"a Deny of Sign only", kmsPolicy(t, map[string]any{"Effect": "Deny", "Principal": awsPrincipal(kmsHolder), "Action": "kms:Sign", "Resource": "*"}), handoff.CodePolicy},
		{"the role that signs and an administrator that cannot", kmsPolicy(t,
			allowSign(awsPrincipal("arn:aws:iam::"+acct+":role/example-key-admin"), "kms:Describe*", "kms:Get*", "kms:ScheduleKeyDeletion"),
			allowSign(awsPrincipal(kmsHolder))), ""},
		{"two principals that Escape writes alike", one(awsPrincipal("\xc3\xa9", "\\u00e9")), handoff.CodePolicy},
		{"one principal that is not a role, written twice", one(awsPrincipal("\xc3\xa9", "\xc3\xa9")), handoff.CodePolicy},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			x := newKMSFixture(t)
			x.fake.policy = tc.policy
			v, err := x.check(t)
			if tc.want == "" {
				wantAccepted(t, v, err)
				return
			}
			wantRefusal(t, v, err, tc.want, 9)
		})
	}
}

func TestTheProofsPublicKeyOfAnotherKeyIsRefusedByCheck8(t *testing.T) {
	x := newKMSFixture(t)
	other := newP384(t)
	x.f.proof["evidence"] = kmsEvidence(&other.PublicKey)
	v, err := x.check(t)
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)

	// The key KMS returns is another key than the request's, and the proof's key is the request's.
	x = newKMSFixture(t)
	x.fake.pubDER, err = x509.MarshalPKIXPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	v, err = x.check(t)
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
}

func TestAKMSServiceThatDoesNotAnswerLeavesTheCheckUndecided(t *testing.T) {
	for name, e := range map[string]error{
		"a throttle":        &kms.APIError{Code: "ThrottlingException"},
		"an internal fault": &kms.APIError{Code: "KMSInternalException"},
		"a timeout":         &kms.APIError{Code: "DependencyTimeoutException"},
		"a plain error":     errors.New("connection reset"),
		"a deadline":        context.DeadlineExceeded,
	} {
		for _, place := range []string{"DescribeKey", "GetKeyPolicy"} {
			t.Run(name+" "+place, func(t *testing.T) {
				x := newKMSFixture(t)
				if place == "DescribeKey" {
					x.fake.descErr = e
				} else {
					x.fake.policyErr = e
				}
				v, err := x.check(t)
				if !errors.Is(err, kms.ErrUndecided) {
					t.Fatalf("error %v, want ErrUndecided", err)
				}
				if v.Accepted() || v.Refused() || v.Complete() {
					t.Fatalf("accepted %v, refused %v, complete %v", v.Accepted(), v.Refused(), v.Complete())
				}
				if got := statuses(v); got != "pppppp"+"nnn" {
					t.Fatalf("statuses %s: check 7 must be not-run", got)
				}
				if v.Key != nil || v.Evidence != nil {
					t.Fatal("a key or evidence beside an error")
				}
			})
		}
	}
}

// The verifier does not catch a panic of the API: the checker does, and the request is not accepted.
func TestAPanicInTheAPIIsAnInternalErrorAndNotAnAcceptance(t *testing.T) {
	for _, place := range []string{"DescribeKey", "GetPublicKey", "GetKeyPolicy"} {
		t.Run(place, func(t *testing.T) {
			x := newKMSFixture(t)
			x.fake.panicIn = place
			v, err := x.check(t)
			wantUndecided(t, v, err, handoff.ErrInternal, "pppppp"+"nnn")
		})
	}
}

func TestACancelledContextLeavesTheCheckUndecidedAndMakesNoCall(t *testing.T) {
	x := newKMSFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	v, err := x.checker(t, nil).Check(ctx, x.f.request())
	if err == nil {
		t.Fatalf("a cancelled context gives the verdict %+v", v)
	}
	if v.Accepted() {
		t.Fatal("accepted")
	}
	if len(x.fake.calls) != 0 || len(x.fake.roles) != 0 {
		t.Fatalf("calls %v, roles %v", x.fake.calls, x.fake.roles)
	}
}

func TestTheRoleOfAKeyInAnotherAccountComesFromTheDelegation(t *testing.T) {
	const otherARN = "arn:aws:kms:eu-west-1:111122223333:key/66666666-7777-8888-9999-000000000000"
	const readRole = "arn:aws:iam::111122223333:role/example-certifier-read"
	build := func(t *testing.T, roles map[string]string, evidenceARN string) (*kmsFixture, handoff.Verdict, error) {
		x := newKMSFixture(t)
		x.fake.desc.ARN = otherARN
		x.fake.desc.KeyID = "66666666-7777-8888-9999-000000000000"
		x.fake.pubDER, _ = x509.MarshalPKIXPublicKey(x.f.publicKey())
		der := x.fake.pubDER
		x.f.proof["evidence"] = map[string]any{"key_arn": evidenceARN, "public_key": b64(string(der))}
		fk := &arnFake{kmsFake: x.fake, arn: otherARN}
		v, err := kms.New(kms.Config{Connector: fk, ReadRoles: roles})
		if err != nil {
			t.Fatal(err)
		}
		chk := newCheckerWith(t, func(c *handoff.Config) {
			c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StoreKMS: v}
			c.Delegation.KMSReadRoles = roles
		})
		verdict, err := chk.Check(t.Context(), x.f.request())
		return x, verdict, err
	}
	t.Run("the account is listed", func(t *testing.T) {
		x, v, err := build(t, map[string]string{"111122223333": readRole}, otherARN)
		wantAccepted(t, v, err)
		if len(x.fake.roles) != 1 || x.fake.roles[0] != readRole {
			t.Fatalf("roles %v", x.fake.roles)
		}
		if v.Evidence.Details[kms.DetailReadRole] != readRole {
			t.Fatalf("details %v", v.Evidence.Details)
		}
	})
	t.Run("the account is not listed", func(t *testing.T) {
		x, v, err := build(t, map[string]string{"444455556666": "arn:aws:iam::444455556666:role/example-certifier-read"}, otherARN)
		wantAccepted(t, v, err)
		if len(x.fake.roles) != 1 || x.fake.roles[0] != "" {
			t.Fatalf("roles %v", x.fake.roles)
		}
	})
}

// arnFake answers for another key ARN than kmsKeyARN.
type arnFake struct {
	*kmsFake
	arn string
}

func (a *arnFake) Open(ctx context.Context, role string) (kms.API, error) {
	if _, err := a.kmsFake.Open(ctx, role); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *arnFake) GetPublicKey(ctx context.Context, arn string) (*kms.PublicKeyAnswer, error) {
	ans, err := a.kmsFake.GetPublicKey(ctx, arn)
	if ans != nil {
		ans.KeyID = a.arn
	}
	return ans, err
}

// A request whose evidence is not of the form of the page is refused by check 2 of the checker, before the
// verifier, and by the verifier alone when it is called directly.
func TestAKMSProofThatIsMalformedMakesNoCallThroughTheChecker(t *testing.T) {
	x := newKMSFixture(t)
	x.f.proof["evidence"] = map[string]any{"key_arn": "alias/example", "public_key": b64("x")}
	v, err := x.check(t)
	if err != nil {
		t.Fatal(err)
	}
	if v.Accepted() || !v.Refused() {
		t.Fatalf("verdict %+v", v)
	}
	if len(x.fake.calls) != 0 {
		t.Fatalf("calls %v", x.fake.calls)
	}
}

// A software key is never read from KMS, and a verifier that is given for it is not called.
func TestTheKMSVerifierIsNotCalledForAnotherStore(t *testing.T) {
	x := newKMSFixture(t)
	soft := newFixture(t, handoff.StoreSoftware, csrSpec{})
	chk := x.checker(t, nil)
	if _, err := chk.Check(t.Context(), soft.request()); err != nil {
		t.Fatal(err)
	}
	if len(x.fake.calls) != 0 {
		t.Fatalf("calls %v", x.fake.calls)
	}
}
