package handoff_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/kms"
	"ritueel.id/ritueel/internal/handoff/evidence/kms/kmsreplay"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/testrepo"
)

// The verifier of the store aws-kms is the real one, over the replay of the stub that a case names. The roles
// it may assume are the ones of the delegation of the case, so that the checker and the verifier have one
// source.
func init() {
	vectorVerifiers = append(vectorVerifiers, kmsVerifiersOfCase)
}

func kmsVerifiersOfCase(t testing.TB, _ vectorManifest, c vectorCase, cfg handoff.Config) map[handoff.Store]handoff.EvidenceVerifier {
	if c.KMSStub == "" {
		return nil
	}
	replay, err := kmsreplay.Parse(testrepo.Read(t, vectorsDir, c.KMSStub))
	if err != nil {
		t.Fatalf("case %s: %v", c.ID, err)
	}
	v, err := kms.New(kms.Config{Connector: replay, ReadRoles: cfg.Delegation.KMSReadRoles})
	if err != nil {
		t.Fatalf("case %s: %v", c.ID, err)
	}
	return map[handoff.Store]handoff.EvidenceVerifier{handoff.StoreKMS: v}
}

// kmsCases are the cases of the manifest that name a stub.
func kmsCases(t testing.TB) (vectorManifest, []vectorCase) {
	t.Helper()
	m := readManifest(t)
	var out []vectorCase
	for _, c := range m.Cases {
		if c.KMSStub != "" {
			out = append(out, c)
		}
	}
	return m, out
}

// proofOfCase is the proof of a case as the verifier is given it: the store and the evidence member.
func proofOfCase(t testing.TB, c vectorCase) *handoff.Proof {
	t.Helper()
	for _, f := range c.Files {
		if !strings.HasSuffix(f, "."+handoff.FileProof) {
			continue
		}
		var w struct {
			Store    string          `json:"store"`
			Evidence json.RawMessage `json:"evidence"`
		}
		if err := json.Unmarshal(testrepo.Read(t, vectorsDir, f), &w); err != nil {
			t.Fatal(err)
		}
		return &handoff.Proof{Store: handoff.Store(w.Store), Evidence: w.Evidence}
	}
	t.Fatalf("case %s has no proof file", c.ID)
	return nil
}

// stubOfCase is the content of the stub of a case, with its public key.
type stubOfCase struct {
	Assume *struct{ RoleArn string } `json:"assume_role"`
	Public struct {
		PublicKey []byte `json:"PublicKey"`
	} `json:"get_public_key"`
	Describe struct {
		KeyMetadata struct{ Arn string }
	} `json:"describe_key"`
}

func readStub(t testing.TB, c vectorCase) stubOfCase {
	t.Helper()
	var s stubOfCase
	if err := json.Unmarshal(testrepo.Read(t, vectorsDir, c.KMSStub), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// The principals and the calls that each stub gives, in the words of the contract's vectors.
func TestEveryStubIsReadByTheVerifier(t *testing.T) {
	m, cases := kmsCases(t)
	if len(cases) != 9 {
		t.Fatalf("%d cases name a stub, want the nine of the manifest", len(cases))
	}
	const holder = "arn:aws:iam::123456789012:role/example-key-holder"
	type want struct {
		account, role string
		principals    []string
		calls         []string
		refused       bool
	}
	direct := []string{"open:-", "DescribeKey", "GetPublicKey", "GetKeyPolicy:default"}
	oneHolder := []string{holder}
	expected := map[string]want{
		"x509-kms-valid":        {"123456789012", "", oneHolder, direct, false},
		"pgp-kms-valid":         {"123456789012", "", oneHolder, direct, false},
		"ssh-kms-valid":         {"123456789012", "", oneHolder, direct, false},
		"x509-kms-key-mismatch": {"123456789012", "", oneHolder, direct, false},
		"ssh-kms-key-mismatch":  {"123456789012", "", oneHolder, direct, false},
		"x509-kms-two-actors":   {"123456789012", "", []string{holder, "arn:aws:iam::123456789012:role/example-other"}, direct, false},
		"ssh-kms-two-actors":    {"123456789012", "", []string{holder, "arn:aws:iam::123456789012:role/example-other"}, direct, false},
		"x509-kms-cross-account": {"111122223333", "arn:aws:iam::111122223333:role/example-certifier-read", []string{"arn:aws:iam::111122223333:role/example-key-holder"},
			[]string{"open:arn:aws:iam::111122223333:role/example-certifier-read", "DescribeKey", "GetPublicKey", "GetKeyPolicy:default"}, false},
		"x509-kms-cross-account-no-role": {"444455556666", "", nil, []string{"open:-", "DescribeKey"}, true},
	}
	for _, c := range cases {
		w, ok := expected[c.ID]
		if !ok {
			t.Fatalf("no expectation for the case %s", c.ID)
		}
		t.Run(c.ID, func(t *testing.T) {
			replay, err := kmsreplay.Parse(testrepo.Read(t, vectorsDir, c.KMSStub))
			if err != nil {
				t.Fatal(err)
			}
			cfg := configOfCase(t, m, c, rootsOfManifest(t, m), testNow)
			v, err := kms.New(kms.Config{Connector: replay, ReadRoles: cfg.Delegation.KMSReadRoles})
			if err != nil {
				t.Fatal(err)
			}
			proof := proofOfCase(t, c)
			ev, err := v.Verify(t.Context(), nil, proof, testNow)
			if got := replay.Calls(); !reflect.DeepEqual(got, w.calls) {
				t.Fatalf("calls %v, want %v", got, w.calls)
			}
			if w.refused {
				var ce *handoff.CodeError
				if ev != nil || !errors.As(err, &ce) || ce.Code != handoff.CodeProofInvalid {
					t.Fatalf("evidence %v, error %v: want proof-invalid", ev, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			stub := readStub(t, c)
			wantKey, err := x509.ParsePKIXPublicKey(stub.Public.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if !ev.Key.Equal(wantKey) {
				t.Fatal("the key is not the key of the stub")
			}
			if strings.HasPrefix(c.ID, "x509-") {
				csrKey, err := pki.RequestKeyFile(loadCase(t, c).Files[handoff.FileCSR])
				if err != nil {
					t.Fatal(err)
				}
				if !ev.Key.Equal(csrKey) {
					t.Fatal("the key of the stub is not the key of the request")
				}
			}
			var got []string
			for _, p := range ev.SignPrincipals {
				if p.Kind != handoff.PrincipalRole {
					t.Fatalf("principal %+v is not a role", p)
				}
				got = append(got, p.ARN)
			}
			if !reflect.DeepEqual(got, w.principals) {
				t.Fatalf("principals %v, want %v", got, w.principals)
			}
			if ev.Details[kms.DetailAccount] != w.account || ev.Details[kms.DetailKeyARN] != stub.Describe.KeyMetadata.Arn {
				t.Fatalf("details %v", ev.Details)
			}
			if r, ok := ev.Details[kms.DetailReadRole]; w.role == "" && ok || r != w.role {
				t.Fatalf("read_role %q (present %v), want %q", r, ok, w.role)
			}
			sum := sha256.Sum256(stub.Public.PublicKey)
			if ev.Details[kms.DetailPublicKeySHA256] != hex.EncodeToString(sum[:]) {
				t.Fatalf("public_key_sha256 %s", ev.Details[kms.DetailPublicKeySHA256])
			}
			if ev.Details[kms.DetailCheckedAt] != "2026-11-15T12:00:00Z" {
				t.Fatalf("checked_at %s", ev.Details[kms.DetailCheckedAt])
			}
			// The proof's own public_key is not read by the verifier: in a case about a key that is not the
			// request's, it is another key, and the verifier still succeeds.
			var e struct {
				PublicKey string `json:"public_key"`
			}
			if err := json.Unmarshal(proof.Evidence, &e); err != nil {
				t.Fatal(err)
			}
			proofKey, _ := base64.StdEncoding.DecodeString(e.PublicKey)
			if strings.HasSuffix(c.ID, "key-mismatch") == reflect.DeepEqual(proofKey, stub.Public.PublicKey) {
				t.Fatalf("the proof's public_key and the stub's key: equal is %v for %s", reflect.DeepEqual(proofKey, stub.Public.PublicKey), c.ID)
			}
		})
	}
}

// The five X.509 cases that wait for the verifier of a KMS key are decided by the checker with the real
// verifier, each as the manifest says, and none is in the pending map.
func TestTheFiveKMSVectorsAreDecidedByTheRealVerifier(t *testing.T) {
	m := readManifest(t)
	roots := rootsOfManifest(t, m)
	ids := []string{"x509-kms-valid", "x509-kms-cross-account", "x509-kms-cross-account-no-role", "x509-kms-key-mismatch", "x509-kms-two-actors"}
	statusesWant := map[string]string{
		"x509-kms-valid": "ppppppppp", "x509-kms-cross-account": "ppppppppp", "x509-kms-cross-account-no-role": "ppppppfnn",
		"x509-kms-key-mismatch": "pppppppfn", "x509-kms-two-actors": "ppppppppf",
	}
	callsWant := map[string][]string{
		"x509-kms-valid":                 {"open:-", "DescribeKey", "GetPublicKey", "GetKeyPolicy:default"},
		"x509-kms-cross-account":         {"open:arn:aws:iam::111122223333:role/example-certifier-read", "DescribeKey", "GetPublicKey", "GetKeyPolicy:default"},
		"x509-kms-cross-account-no-role": {"open:-", "DescribeKey"},
		"x509-kms-key-mismatch":          {"open:-", "DescribeKey", "GetPublicKey", "GetKeyPolicy:default"},
		"x509-kms-two-actors":            {"open:-", "DescribeKey", "GetPublicKey", "GetKeyPolicy:default"},
	}
	for _, id := range ids {
		if _, ok := pending[id]; ok {
			t.Errorf("%s is still in the pending map", id)
		}
		var c vectorCase
		for _, k := range m.Cases {
			if k.ID == id {
				c = k
			}
		}
		if c.ID == "" {
			t.Fatalf("the manifest holds no case %s", id)
		}
		t.Run(id, func(t *testing.T) {
			replay, err := kmsreplay.Parse(testrepo.Read(t, vectorsDir, c.KMSStub))
			if err != nil {
				t.Fatal(err)
			}
			cfg := configOfCase(t, m, c, roots, testNow)
			v, err := kms.New(kms.Config{Connector: replay, ReadRoles: cfg.Delegation.KMSReadRoles})
			if err != nil {
				t.Fatal(err)
			}
			chk := checkerOfCase(t, m, c, roots, testNow, map[handoff.Store]handoff.EvidenceVerifier{handoff.StoreKMS: v})
			verdict, err := chk.Check(t.Context(), loadCase(t, c))
			if !matches(c, verdict, err) {
				t.Fatalf("the manifest says %s %s, the verdict is %q (%s), error %v", c.Expect, c.Reason, verdict.Code, verdict.Detail, err)
			}
			if got := statuses(verdict); got != statusesWant[id] {
				t.Fatalf("statuses %s, want %s", got, statusesWant[id])
			}
			if got := replay.Calls(); !reflect.DeepEqual(got, callsWant[id]) {
				t.Fatalf("calls %v, want %v", got, callsWant[id])
			}
			if c.Expect == "accept" {
				if !verdict.Accepted() || verdict.Evidence == nil || verdict.Evidence.Details[kms.DetailKeyARN] == "" {
					t.Fatalf("accepted %v, evidence %+v", verdict.Accepted(), verdict.Evidence)
				}
			}
		})
	}
	// The four stubs of the cases that wait for another part are read by the verifier too, and decided by none.
	for _, id := range []string{"pgp-kms-valid", "ssh-kms-valid", "ssh-kms-key-mismatch", "ssh-kms-two-actors"} {
		if _, ok := pending[id]; !ok {
			t.Errorf("%s is not in the pending map", id)
		}
	}
}

// Every stub that a case names is a file of the folder of requests, written beside its proof.
func TestEveryStubStandsBesideItsProof(t *testing.T) {
	_, cases := kmsCases(t)
	for _, c := range cases {
		stem := ""
		for _, f := range c.Files {
			if s, ok := strings.CutSuffix(path.Base(f), "."+handoff.FileProof); ok {
				stem = s
			}
		}
		if want := "requests/" + stem + ".kms-stub.json"; c.KMSStub != want {
			t.Errorf("case %s: the stub is %s, want %s", c.ID, c.KMSStub, want)
		}
	}
}
