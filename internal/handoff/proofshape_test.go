package handoff_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// withProofBytes is the fixture's request with the proof file replaced.
func withProofBytes(f *fixture, proof []byte) *handoff.Request {
	r := f.request()
	r.Files[handoff.FileProof] = proof
	return r
}

// proofWith renders the fixture's proof after a change of its members.
func proofWith(t testing.TB, f *fixture, change func(m map[string]any)) []byte {
	t.Helper()
	m := map[string]any{}
	for k, v := range f.proof {
		m[k] = v
	}
	change(m)
	return mustJSON(t, m)
}

func TestAnAcceptedRequestHasNineChecksAllPassed(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	for i, c := range v.Checks {
		if c.N != i+1 || c.Name == "" || len(c.NotRun) != 0 {
			t.Errorf("check %d reads %+v", i+1, c)
		}
	}
	if v.Key == nil || !v.Key.Equal(f.publicKey()) {
		t.Error("the verdict does not carry the key of the request")
	}
	if v.Evidence == nil || !v.Evidence.Unprotected {
		t.Errorf("a software key is recorded as unprotected: %+v", v.Evidence)
	}
	if v.Code != "" || v.Detail != "" {
		t.Errorf("an accepted verdict has the code %q and the detail %q", v.Code, v.Detail)
	}
}

func TestACheckHasTheWordsOfThePageForItsName(t *testing.T) {
	v := mustCheck(t, newChecker(t), newFixture(t, handoff.StoreSoftware, csrSpec{}).request())
	want := []string{
		"The contract version is known",
		"The files parse, with no unknown or repeated member",
		"request_sha256 is the digest of the request",
		"The key is ECDSA P-384",
		"The request's signature verifies with its own key",
		"The store is allowed by the policy",
		"The evidence is valid",
		"The key in the evidence is the key in the request",
		"The policy accepts the request",
	}
	for i, w := range want {
		if v.Checks[i].Name != w {
			t.Errorf("check %d is named %q, the page says %q", i+1, v.Checks[i].Name, w)
		}
	}
}

func TestAVersionThatIsNotOneIsRefusedAndNothingElseOfTheFileIsRead(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	// Each file below is bad in many other ways: a member the page does not know, a null, a float, a
	// member twice, the wrong digest. Only the version may be read.
	rest := `"type":"nope","store":"nope","request_sha256":"XYZ","zzz":null,"f":1.5,"zzz":1`
	for _, version := range []string{"2", "0", "-1", "3", "10", "9007199254740991", "-9007199254740991"} {
		t.Run(version, func(t *testing.T) {
			proof := []byte(fmt.Sprintf(`{"handoff":%s,%s}`, version, rest))
			v, err := newChecker(t).Check(t.Context(), withProofBytes(f, proof))
			wantRefusal(t, v, err, handoff.CodeVersionUnsupported, 1)
		})
	}
	t.Run("version 2 with no csr file", func(t *testing.T) {
		r := withProofBytes(f, []byte(`{"handoff":2}`))
		delete(r.Files, handoff.FileCSR)
		v, err := newChecker(t).Check(t.Context(), r)
		wantRefusal(t, v, err, handoff.CodeVersionUnsupported, 1)
	})
	t.Run("version 2 with a csr that is not a request", func(t *testing.T) {
		r := withProofBytes(f, []byte(`{"handoff":2}`))
		r.Files[handoff.FileCSR] = []byte("not a request")
		v, err := newChecker(t).Check(t.Context(), r)
		wantRefusal(t, v, err, handoff.CodeVersionUnsupported, 1)
	})
	t.Run("version 2 in an openpgp and an ssh proof", func(t *testing.T) {
		for _, typ := range []string{"openpgp-subkey", "ssh-ca-key"} {
			proof := []byte(fmt.Sprintf(`{"handoff":2,"type":%q}`, typ))
			v, err := newChecker(t).Check(t.Context(), &handoff.Request{Stem: testStem, Files: map[string][]byte{handoff.FileProof: proof}})
			wantRefusal(t, v, err, handoff.CodeVersionUnsupported, 1)
		}
	})
}

func TestAProofWithNoReadableVersionIsMalformedAtCheckTwoAndCheckOneIsNotRun(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	for name, proof := range map[string]string{
		"a string":               `{"handoff":"1","type":"x509-intermediate"}`,
		"a float":                `{"handoff":1.0}`,
		"an exponent":            `{"handoff":1e0}`,
		"a boolean":              `{"handoff":true}`,
		"null":                   `{"handoff":null}`,
		"a list":                 `{"handoff":[1]}`,
		"an object":              `{"handoff":{"a":1}}`,
		"missing":                `{"type":"x509-intermediate"}`,
		"twice":                  `{"handoff":1,"handoff":1}`,
		"twice with two values":  `{"handoff":1,"handoff":2}`,
		"larger than the range":  `{"handoff":9007199254740992}`,
		"not an object":          `[1]`,
		"a string document":      `"handoff"`,
		"a number document":      `1`,
		"empty":                  ``,
		"white space only":       "  \n",
		"cut off":                `{"handoff":1`,
		"a byte order mark":      "\xef\xbb\xbf" + `{"handoff":1}`,
		"not UTF-8 in a member":  "{\"handoff\":1,\"type\":\"\xff\"}",
		"an object after it":     `{"handoff":1}{"handoff":1}`,
		"an upper-case member":   `{"Handoff":1}`,
		"the number in a string": `{"handoff":"2"}`,
		"a leading plus":         `{"handoff":+1}`,
		"a leading zero":         `{"handoff":01}`,
		"hex":                    `{"handoff":0x1}`,
		"a fraction of zero":     `{"handoff":1.00}`,
	} {
		t.Run(name, func(t *testing.T) {
			v, err := newChecker(t).Check(t.Context(), withProofBytes(f, []byte(proof)))
			if err != nil {
				t.Fatalf("error %v", err)
			}
			wantUnreadableVersion(t, v, err)
		})
	}
}

func TestAMinusZeroVersionIsTheIntegerZeroAndIsNotKnown(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	v, err := newChecker(t).Check(t.Context(), withProofBytes(f, []byte(`{"handoff":-0}`)))
	wantRefusal(t, v, err, handoff.CodeVersionUnsupported, 1)
}

func TestAProofLargerThanTheLimitIsMalformedAndIsNotRead(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	pad := strings.Repeat(" ", handoff.MaxFileSize)
	proof := append(bytes.Clone(f.request().Files[handoff.FileProof]), pad...)
	v, err := newChecker(t).Check(t.Context(), withProofBytes(f, proof))
	wantUnreadableVersion(t, v, err)
	// Larger than the limit, and a version that is not known: the size is the first thing that is refused,
	// and a file that is too large has no version that can be read.
	big := []byte(`{"handoff":2,"pad":"` + strings.Repeat("a", handoff.MaxFileSize) + `"}`)
	v, err = newChecker(t).Check(t.Context(), withProofBytes(f, big))
	wantUnreadableVersion(t, v, err)
}

func TestAProofOfExactlyTheLimitIsRead(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	proof := f.request().Files[handoff.FileProof]
	padded := append(bytes.Clone(proof), bytes.Repeat([]byte(" "), handoff.MaxFileSize-len(proof))...)
	if len(padded) != handoff.MaxFileSize {
		t.Fatalf("test setup: %d bytes", len(padded))
	}
	v, err := newChecker(t).Check(t.Context(), withProofBytes(f, padded))
	wantAccepted(t, v, err)
}

func TestARequestWithNoProofFileIsMalformedAtCheckTwoAndCheckOneIsNotRun(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	r := f.request()
	delete(r.Files, handoff.FileProof)
	v, err := newChecker(t).Check(t.Context(), r)
	wantUnreadableVersion(t, v, err)
	v, err = newChecker(t).Check(t.Context(), &handoff.Request{Stem: testStem})
	wantUnreadableVersion(t, v, err)
	v, err = newChecker(t).Check(t.Context(), &handoff.Request{Stem: testStem, Files: map[string][]byte{handoff.FileProof: nil}})
	wantUnreadableVersion(t, v, err)
}

// proofRefusals are proof files whose form is not the page's, each refused with malformed at check 2.
// The change is made to the member map of the good proof of the store.
type shapeCase struct {
	name   string
	store  handoff.Store
	change func(m map[string]any)
}

func TestAProofThatIsNotOfTheFormOfThePageIsMalformed(t *testing.T) {
	set := func(k string, v any) func(m map[string]any) {
		return func(m map[string]any) { m[k] = v }
	}
	del := func(k string) func(m map[string]any) {
		return func(m map[string]any) { delete(m, k) }
	}
	ev := func(store handoff.Store, change func(e map[string]any)) func(m map[string]any) {
		return func(m map[string]any) {
			e := evidenceFor(store)
			change(e)
			m["evidence"] = e
		}
	}
	two := []string{b64("a"), b64("b")}
	sw, piv, card, kms := handoff.StoreSoftware, handoff.StorePIV, handoff.StoreOpenPGPCard, handoff.StoreKMS
	cases := []shapeCase{
		{"the type is not one of the three", sw, set("type", "x509")},
		{"the type is in upper case", sw, set("type", "X509-INTERMEDIATE")},
		{"the type is empty", sw, set("type", "")},
		{"the type is missing", sw, del("type")},
		{"the type is a number", sw, set("type", 1)},
		{"the store is not one of the four", sw, set("store", "tpm")},
		{"the store is in upper case", sw, set("store", "Software")},
		{"the store is empty", sw, set("store", "")},
		{"the store is missing", sw, del("store")},
		{"the digest is missing", sw, del("request_sha256")},
		{"the digest is in upper case", sw, func(m map[string]any) { m["request_sha256"] = strings.ToUpper(m["request_sha256"].(string)) }},
		{"the digest has one capital letter", sw, func(m map[string]any) {
			s := m["request_sha256"].(string)
			for i, c := range s {
				if c >= 'a' && c <= 'f' {
					m["request_sha256"] = s[:i] + strings.ToUpper(string(c)) + s[i+1:]
					return
				}
			}
		}},
		{"the digest is 63 digits", sw, func(m map[string]any) { m["request_sha256"] = m["request_sha256"].(string)[1:] }},
		{"the digest is 65 digits", sw, func(m map[string]any) { m["request_sha256"] = m["request_sha256"].(string) + "0" }},
		{"the digest is empty", sw, set("request_sha256", "")},
		{"the digest is not hexadecimal", sw, set("request_sha256", strings.Repeat("g", 64))},
		{"the digest has a space at its end", sw, func(m map[string]any) { m["request_sha256"] = m["request_sha256"].(string)[1:] + " " }},
		{"the digest is a number", sw, set("request_sha256", 1)},
		{"the digest is in Base64", sw, set("request_sha256", strings.Repeat("A", 44))},
		{"a member the page does not define", sw, set("zzz", 1)},
		{"a member the page does not define, a string", sw, set("comment", "hello")},
		{"a member of the openpgp type on x509: primaries", sw, set("primaries", []string{strings.Repeat("a", 40)})},
		{"primaries that is an empty list on x509", sw, set("primaries", []string{})},
		{"a member of the openpgp type on x509: capabilities", sw, set("capabilities", []string{"sign"})},
		{"capabilities that is an empty list on x509", sw, set("capabilities", []string{})},
		{"a member of the ssh type on x509: use", sw, set("use", "user")},
		{"use that is an empty string on x509", sw, set("use", "")},
		{"evidence on a software key", sw, set("evidence", evidenceFor(piv))},
		{"an empty evidence on a software key", sw, set("evidence", map[string]any{})},
		{"evidence that is a list on a software key", sw, set("evidence", []string{})},
		{"no evidence for piv", piv, del("evidence")},
		{"no evidence for openpgp-card", card, del("evidence")},
		{"no evidence for aws-kms", kms, del("evidence")},
		{"an empty evidence for piv", piv, set("evidence", map[string]any{})},
		{"an empty evidence for aws-kms", kms, set("evidence", map[string]any{})},
		{"evidence that is a list", piv, set("evidence", []string{})},
		{"evidence that is a string", piv, set("evidence", "x")},
		{"evidence that is a number", kms, set("evidence", 1)},
		{"evidence that is null", piv, set("evidence", nil)},
		{"an unknown member in the attestation of piv", piv, ev(piv, func(e map[string]any) { e["extra"] = 1 })},
		{"an unknown member in the attestation of openpgp-card", card, ev(card, func(e map[string]any) { e["extra"] = "x" })},
		{"an unknown member in the evidence of aws-kms", kms, ev(kms, func(e map[string]any) { e["extra"] = "x" })},
		{"the key_arn is missing", kms, ev(kms, func(e map[string]any) { delete(e, "key_arn") })},
		{"the key_arn is empty", kms, ev(kms, func(e map[string]any) { e["key_arn"] = "" })},
		{"the key_arn is a number", kms, ev(kms, func(e map[string]any) { e["key_arn"] = 5 })},
		{"the public_key is missing", kms, ev(kms, func(e map[string]any) { delete(e, "public_key") })},
		{"the public_key is empty", kms, ev(kms, func(e map[string]any) { e["public_key"] = "" })},
		{"the public_key is not Base64", kms, ev(kms, func(e map[string]any) { e["public_key"] = "***" })},
		{"the public_key has no padding", kms, ev(kms, func(e map[string]any) { e["public_key"] = "YQ" })},
		{"the public_key is in the URL alphabet", kms, ev(kms, func(e map[string]any) { e["public_key"] = "_-8=" })},
		{"the public_key has a line break", kms, ev(kms, func(e map[string]any) { e["public_key"] = "YWJj\nZGVm" })},
		{"the public_key has a bit left over", kms, ev(kms, func(e map[string]any) { e["public_key"] = "YR==" })},
		{"the public_key is a list", kms, ev(kms, func(e map[string]any) { e["public_key"] = two })},
		{"the attestation is missing", piv, ev(piv, func(e map[string]any) { delete(e, "attestation") })},
		{"the attestation is empty", piv, ev(piv, func(e map[string]any) { e["attestation"] = []string{} })},
		{"the attestation holds one certificate", piv, ev(piv, func(e map[string]any) { e["attestation"] = two[:1] })},
		{"the attestation holds one certificate on a card", card, ev(card, func(e map[string]any) { e["attestation"] = two[:1] })},
		{"the attestation is a string", piv, ev(piv, func(e map[string]any) { e["attestation"] = "abcd" })},
		{"the attestation holds a number", piv, ev(piv, func(e map[string]any) { e["attestation"] = []any{b64("a"), 1} })},
		{"the attestation holds null", piv, ev(piv, func(e map[string]any) { e["attestation"] = []any{b64("a"), nil} })},
		{"the attestation holds an empty string", piv, ev(piv, func(e map[string]any) { e["attestation"] = []string{b64("a"), ""} })},
		{"the attestation holds text that is not Base64", piv, ev(piv, func(e map[string]any) { e["attestation"] = []string{b64("a"), "***"} })},
		{"the first certificate is not Base64", piv, ev(piv, func(e map[string]any) { e["attestation"] = []string{"***", b64("b")} })},
		{"the attestation holds Base64 with no padding", card, ev(card, func(e map[string]any) { e["attestation"] = []string{b64("a"), "YWI"} })},
		{"the attestation holds Base64 in the URL alphabet", piv, ev(piv, func(e map[string]any) { e["attestation"] = []string{b64("a"), "_-8="} })},
		{"the attestation holds Base64 with a space", piv, ev(piv, func(e map[string]any) { e["attestation"] = []string{b64("a"), "YW Jj"} })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.store, csrSpec{})
			// The checks that follow must not be reached; a verifier that is called is a fault.
			sv := returning(f.goodEvidence(tc.store))
			chk := newCheckerWith(t, func(c *handoff.Config) {
				c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{piv: sv, card: sv, kms: sv}
			})
			v, err := chk.Check(t.Context(), withProofBytes(f, proofWith(t, f, tc.change)))
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
			if sv.calls.Load() != 0 {
				t.Error("a verifier ran for a proof that is not of the form of the page")
			}
		})
	}
}

func TestAProofFileThatBreaksTheJSONRulesIsMalformedAtCheckTwo(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	good := string(f.request().Files[handoff.FileProof])
	digest := f.proof["request_sha256"].(string)
	base := func(extra string) []byte {
		return []byte(fmt.Sprintf(`{"handoff":1,"type":"x509-intermediate","request_sha256":%q,"store":"software"%s}`, digest, extra))
	}
	if !json.Valid([]byte(good)) {
		t.Fatal("test setup")
	}
	// A file that is one object with the member handoff once, as an integer, has a version: its fault is
	// found by check 2 after check 1 passed. A file that is not one JSON object has no version that can be
	// read: check 2 fails and check 1 did not run.
	for name, tc := range map[string]struct {
		proof    []byte
		readable bool
	}{
		"a member twice":                         {base(`,"store":"software"`), true},
		"the type twice with two values":         {base(`,"type":"ssh-ca-key"`), true},
		"the digest twice":                       {base(`,"request_sha256":"` + digest + `"`), true},
		"a null member":                          {base(`,"evidence":null`), true},
		"a float":                                {base(`,"x":1.5`), true},
		"a number outside the range":             {base(`,"x":9007199254740992`), true},
		"a string with a lone surrogate":         {base(`,"x":"\ud800"`), true},
		"a member name in another case":          {base(`,"Store":"software"`), true},
		"text after the object":                  {append(base(``), []byte(" x")...), false},
		"a byte order mark":                      {append([]byte("\xef\xbb\xbf"), base(``)...), false},
		"a string with a byte that is not UTF-8": {[]byte(fmt.Sprintf("{\"handoff\":1,\"type\":\"x509-intermediate\",\"request_sha256\":%q,\"store\":\"soft\xffware\"}", digest)), false},
		"a comment":                              {[]byte(`{"handoff":1 /* c */,"type":"x509-intermediate"}`), false},
		"a trailing comma":                       {[]byte(fmt.Sprintf(`{"handoff":1,"type":"x509-intermediate","request_sha256":%q,"store":"software",}`, digest)), false},
		"single quotes":                          {[]byte(`{'handoff':1}`), false},
		"nesting past the limit":                 {base(`,"x":` + strings.Repeat("[", 10001) + strings.Repeat("]", 10001)), false},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := newChecker(t).Check(t.Context(), withProofBytes(f, tc.proof))
			if tc.readable {
				wantRefusal(t, v, err, handoff.CodeMalformed, 2)
			} else {
				wantUnreadableVersion(t, v, err)
			}
		})
	}
}

func TestEvidenceInItsExactFormIsRead(t *testing.T) {
	for _, store := range []handoff.Store{handoff.StorePIV, handoff.StoreOpenPGPCard, handoff.StoreKMS} {
		t.Run(string(store), func(t *testing.T) {
			f := newFixture(t, store, csrSpec{})
			sv := returning(f.goodEvidence(store))
			v, err := checkerWith(t, store, sv).Check(t.Context(), f.request())
			wantAccepted(t, v, err)
		})
	}
}

func TestMoreThanTwoCertificatesInAnAttestationAreRead(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	f.proof["evidence"] = map[string]any{"attestation": []string{b64("a"), b64("b"), b64("c"), b64("d")}}
	var got *handoff.Proof
	sv := &stub{fn: func(_ context.Context, _ *handoff.Request, p *handoff.Proof, _ time.Time) (*handoff.Evidence, error) {
		got = p
		return f.goodEvidence(handoff.StorePIV), nil
	}}
	v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if got == nil || !bytes.Contains(got.Evidence, []byte(b64("d"))) {
		t.Errorf("the verifier did not get the evidence as it was: %s", got.Evidence)
	}
}
