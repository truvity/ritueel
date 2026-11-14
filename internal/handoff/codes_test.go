package handoff_test

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// One test for each reason code of the answer table that the checks of this package can give. The
// code declined is the person's at the ceremony, and unknown-primary needs the signed root list; the
// last two tests say that the checks never give them.

func TestTheCodeVersionUnsupportedIsGivenByCheckOne(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	f.proof["handoff"] = 2
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeVersionUnsupported, 1)
	if string(v.Code) != "version-unsupported" {
		t.Errorf("the code is written %q", v.Code)
	}
}

func TestTheCodeMalformedIsGivenByCheckTwo(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	f.proof["zzz"] = 1
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	if string(v.Code) != "malformed" {
		t.Errorf("the code is written %q", v.Code)
	}
}

func TestTheCodeRequestMismatchIsGivenByCheckThree(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	f.proof["request_sha256"] = digestHex([]byte("another request"))
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)
	if string(v.Code) != "request-mismatch" {
		t.Errorf("the code is written %q", v.Code)
	}
}

func TestTheCodeAlgorithmUnsupportedIsGivenByCheckFour(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{key: otherKeys(t)["Ed25519"]})
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeAlgorithmUnsupported, 4)
	if string(v.Code) != "algorithm-unsupported" {
		t.Errorf("the code is written %q", v.Code)
	}
}

func TestTheCodePossessionInvalidIsGivenByCheckFive(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{sigAlg: x509.ECDSAWithSHA256})
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
	if string(v.Code) != "possession-invalid" {
		t.Errorf("the code is written %q", v.Code)
	}
}

func TestTheCodeStoreNotAllowedIsGivenByCheckSix(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	c := newCheckerWith(t, func(c *handoff.Config) { c.Policy.Stores = []handoff.Store{handoff.StorePIV} })
	v, err := c.Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeStoreNotAllowed, 6)
	if string(v.Code) != "store-not-allowed" {
		t.Errorf("the code is written %q", v.Code)
	}
}

func TestTheCodeProofInvalidIsGivenByCheckSeven(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	sv := failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "the key policy could not be read"})
	v, err := checkerWith(t, handoff.StoreKMS, sv).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)
	if string(v.Code) != "proof-invalid" {
		t.Errorf("the code is written %q", v.Code)
	}
}

func TestTheCodeKeyMismatchIsGivenByCheckEight(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	ev := f.goodEvidence(handoff.StoreKMS)
	ev.Key = &newP384(t).PublicKey
	v, err := checkerWith(t, handoff.StoreKMS, returning(ev)).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
	if string(v.Code) != "key-mismatch" {
		t.Errorf("the code is written %q", v.Code)
	}
}

func TestTheCodePolicyIsGivenByCheckNine(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{exts: goodExtensions(uriName("example.net"))})
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
	if string(v.Code) != "policy" {
		t.Errorf("the code is written %q", v.Code)
	}
}

func TestTheCodesAreTheWordsOfTheAnswerTable(t *testing.T) {
	want := map[handoff.Code]string{
		handoff.CodeVersionUnsupported:   "version-unsupported",
		handoff.CodeMalformed:            "malformed",
		handoff.CodeRequestMismatch:      "request-mismatch",
		handoff.CodeUnknownPrimary:       "unknown-primary",
		handoff.CodeAlgorithmUnsupported: "algorithm-unsupported",
		handoff.CodePossessionInvalid:    "possession-invalid",
		handoff.CodeStoreNotAllowed:      "store-not-allowed",
		handoff.CodeProofInvalid:         "proof-invalid",
		handoff.CodeKeyMismatch:          "key-mismatch",
		handoff.CodePolicy:               "policy",
		handoff.CodeDeclined:             "declined",
	}
	if len(want) != 11 {
		t.Fatal("the answer table has eleven codes")
	}
	for code, text := range want {
		if string(code) != text {
			t.Errorf("the code %q is written %q on the page", code, text)
		}
	}
}

func TestTheTypesAndTheStoresAreTheWordsOfTheProofFile(t *testing.T) {
	for got, want := range map[string]string{
		string(handoff.TypeX509): "x509-intermediate", string(handoff.TypeOpenPGP): "openpgp-subkey", string(handoff.TypeSSH): "ssh-ca-key",
		string(handoff.StorePIV): "piv", string(handoff.StoreOpenPGPCard): "openpgp-card", string(handoff.StoreKMS): "aws-kms", string(handoff.StoreSoftware): "software",
		string(handoff.PINNever): "never", string(handoff.PINOnce): "once", string(handoff.PINAlways): "always",
		string(handoff.PrincipalRole): "role", string(handoff.PrincipalUser): "user", string(handoff.PrincipalRoot): "root",
		string(handoff.PrincipalWildcard): "wildcard", string(handoff.PrincipalOther): "other",
		string(handoff.StatusPassed): "passed", string(handoff.StatusFailed): "failed", string(handoff.StatusNotRun): "not-run",
		handoff.FileProof: "proof.json", handoff.FileCSR: "csr.pem", handoff.FileSubkey: "subkey.pgp",
		handoff.FileSSHKey: "sshca.pub", handoff.FileSSHSig: "sshca.sig",
	} {
		if got != want {
			t.Errorf("%q is written %q", got, want)
		}
	}
	if handoff.Version != 1 || handoff.MaxFileSize != 256*1024 {
		t.Errorf("version %d, limit %d", handoff.Version, handoff.MaxFileSize)
	}
}

func TestNoCheckOfAnotherTypeGivesTheCodeDeclinedOrUnknownPrimary(t *testing.T) {
	// The code that every request of the tests so far could give, found by running a wide set of them.
	var reqs []*handoff.Request
	for _, store := range []handoff.Store{handoff.StoreSoftware, handoff.StorePIV, handoff.StoreKMS, handoff.StoreOpenPGPCard} {
		f := newFixture(t, store, csrSpec{})
		reqs = append(reqs, f.request())
		g := newFixture(t, store, csrSpec{sigAlg: x509.ECDSAWithSHA256})
		reqs = append(reqs, g.request())
		h := newFixture(t, store, csrSpec{exts: goodExtensions(uriName("example.net"))})
		reqs = append(reqs, h.request())
	}
	reqs = append(reqs, sshRequest(nil), sshRequest(func(m map[string]any) { m["request_sha256"] = digestHex(nil) }))
	c := newChecker(t)
	for i, r := range reqs {
		v, _ := c.Check(t.Context(), r)
		if v.Code == handoff.CodeDeclined || v.Code == handoff.CodeUnknownPrimary {
			t.Errorf("request %d is given the code %q, which no check of this package gives for its type", i, v.Code)
		}
	}
	// An OpenPGP request is never declined either, and the code unknown-primary is its alone.
	for name, change := range map[string]func(f *pgpFixture){
		"good":              func(f *pgpFixture) {},
		"a wrong digest":    func(f *pgpFixture) { f.digest = digestHex(nil) },
		"a wrong primary":   func(f *pgpFixture) { f.listed = fingerprints(2) },
		"a missing sig":     func(f *pgpFixture) { f.sigs = f.sigs[:1] },
		"another algorithm": func(f *pgpFixture) { f.proof["store"] = "piv" },
	} {
		f := newPGPFixture(t, 2, handoff.StoreSoftware)
		change(f)
		v, _ := f.checker(nil).Check(t.Context(), f.request())
		if v.Code == handoff.CodeDeclined {
			t.Errorf("%s: the code %q is no check's", name, v.Code)
		}
		if v.Code == handoff.CodeUnknownPrimary && statuses(v) != "ppfnnnnnn" {
			t.Errorf("%s: unknown-primary at statuses %s, want check 3", name, statuses(v))
		}
	}
}

func TestACodeErrorSaysItsCodeAndItsDetail(t *testing.T) {
	for _, tc := range []struct {
		err  *handoff.CodeError
		want string
	}{
		{&handoff.CodeError{Code: handoff.CodeProofInvalid}, "handoff: proof-invalid"},
		{&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "the chain is broken"}, "handoff: proof-invalid: the chain is broken"},
		{nil, "handoff: no refusal"},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("the error reads %q, want %q", got, tc.want)
		}
	}
}

func TestACodeErrorDoesNotPrintTextThatIsNotPlainASCII(t *testing.T) {
	// The detail may be made of what came from outside: it is written so that it cannot hide a line or a
	// control sequence in the ceremony's output.
	e := &handoff.CodeError{Code: handoff.CodePolicy, Detail: "name \x1b[31m\nred \u202e rtl \xff"}
	got := e.Error()
	for _, r := range got {
		if r < 0x20 || r >= 0x7f {
			t.Fatalf("the error holds the character %U: %q", r, got)
		}
	}
	if !strings.Contains(got, `\u001b`) || !strings.Contains(got, `\u202e`) {
		t.Errorf("the escapes are not there: %q", got)
	}
}

func TestACodeErrorIsFoundByErrorsAs(t *testing.T) {
	var target *handoff.CodeError
	err := errors.Join(errors.New("x"), &handoff.CodeError{Code: handoff.CodeMalformed})
	if !errors.As(err, &target) || target.Code != handoff.CodeMalformed {
		t.Error("errors.As does not find the CodeError")
	}
}

func TestTheDetailOfARefusalIsPlainTextWhateverTheRequestHolds(t *testing.T) {
	// A host that the delegation does not list is named in the detail, escaped.
	hostile := "ex\x1b[2Jample.org"
	f := newFixture(t, handoff.StoreSoftware, csrSpec{exts: goodExtensions(uriName(hostile))})
	v, err := newChecker(t).Check(t.Context(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Refused() {
		t.Fatal("a host with a control character is accepted")
	}
	for _, r := range v.Detail {
		if r < 0x20 || r >= 0x7f {
			t.Fatalf("the detail holds the character %U: %q", r, v.Detail)
		}
	}
}

func TestTheDetailOfARefusalForAVerifierIsTheVerifiersOwnWords(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	sv := failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "the intermediate is missing"})
	v, _ := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), f.request())
	if v.Detail != "the intermediate is missing" {
		t.Errorf("detail %q", v.Detail)
	}
}

func TestEveryRefusalHasADetailAndAcceptanceHasNone(t *testing.T) {
	for name, mut := range map[string]func(f *fixture){
		"version": func(f *fixture) { f.proof["handoff"] = 3 },
		"form":    func(f *fixture) { f.proof["zzz"] = 1 },
		"digest":  func(f *fixture) { f.proof["request_sha256"] = digestHex(nil) },
	} {
		f := newFixture(t, handoff.StoreSoftware, csrSpec{})
		mut(f)
		v, _ := newChecker(t).Check(t.Context(), f.request())
		if !v.Refused() || v.Detail == "" {
			t.Errorf("%s: code %q, detail %q", name, v.Code, v.Detail)
		}
	}
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	c := newCheckerWith(t, func(c *handoff.Config) { c.Policy.Stores = []handoff.Store{handoff.StorePIV} })
	v, _ := c.Check(t.Context(), f.request())
	if v.Code != handoff.CodeStoreNotAllowed || !strings.Contains(v.Detail, "software") {
		t.Errorf("code %q, detail %q", v.Code, v.Detail)
	}
}
