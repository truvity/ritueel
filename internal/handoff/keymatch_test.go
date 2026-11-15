package handoff_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// The page, "Key match (check 8)": the attested public key (PIV or OpenPGP card), the key KMS returns, and
// the public_key in the proof, where one is given, are all the key in the request.
func TestTheKMSPublicKeyOfTheProofMustBeTheKeyOfTheRequest(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	honest := returning(f.goodEvidence(handoff.StoreKMS))

	f.proof["evidence"] = kmsEvidence(f.publicKey())
	v, err := checkerWith(t, handoff.StoreKMS, honest).Check(t.Context(), f.request())
	wantAccepted(t, v, err)

	// The verifier read the right key from KMS, and the proof names another one.
	f.proof["evidence"] = kmsEvidence(&newP384(t).PublicKey)
	v, err = checkerWith(t, handoff.StoreKMS, honest).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
}

func TestAKMSPublicKeyThatIsNotAKeyIsNeverTakenForTheKeyOfTheRequest(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	f.proof["evidence"] = map[string]any{
		"key_arn":    "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555",
		"public_key": b64("AAAA"),
	}
	v, err := checkerWith(t, handoff.StoreKMS, returning(f.goodEvidence(handoff.StoreKMS))).Check(t.Context(), f.request())
	if err == nil && !v.Refused() {
		t.Fatalf("a public_key that is not the key of the request was accepted: statuses %s", statuses(v))
	}
}

// The public_key of a KMS proof against the key of the request. The page: the key KMS returns and the
// `public_key` in the proof, where one is given, are all the key in the request. Text that is not Base64 of a
// DER value is `malformed` at check 2; Base64 that is not the key of the request, or is no key at all, is
// `key-mismatch` at check 8, whatever the verifier returned.

// kmsProofWith is a KMS fixture whose proof names the public key as the text says.
func kmsProofWith(t testing.TB, publicKey string) *fixture {
	t.Helper()
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	f.proof["evidence"] = map[string]any{
		"key_arn":    "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555",
		"public_key": publicKey,
	}
	return f
}

func spkiOf(t testing.TB, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestAProofThatNamesTheKeyOfTheRequestPassesCheckEight(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	sv := returning(f.goodEvidence(handoff.StoreKMS))
	v, err := checkerWith(t, handoff.StoreKMS, sv).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if sv.calls.Load() != 1 {
		t.Errorf("the verifier was called %d times", sv.calls.Load())
	}
}

func TestAPublicKeyOfTheProofThatIsNotTheKeyOfTheRequestIsKeyMismatchWhateverTheVerifierReturned(t *testing.T) {
	probe := newFixture(t, handoff.StoreKMS, csrSpec{})
	other := newP384(t)
	p256 := otherKeys(t)["P-256"].Public().(*ecdsa.PublicKey)
	rsaKey := otherKeys(t)["RSA-2048"].Public()
	rsaDER, err := x509.MarshalPKIXPublicKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	point, err := probe.publicKey().Bytes()
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString
	for name, text := range map[string]string{
		"the key of another P-384 request":                enc(spkiOf(t, &other.PublicKey)),
		"a key of P-256":                                  enc(spkiOf(t, p256)),
		"a key of RSA":                                    enc(rsaDER),
		"three zero bytes":                                "AAAA",
		"one byte":                                        "AA==",
		"the text AAAA written in Base64":                 b64("AAAA"),
		"a text that is no key":                           b64("public key"),
		"the key of the request and one byte after it":    enc(append(spkiOf(t, probe.publicKey()), 0)),
		"the key of the request cut by one byte":          enc(spkiOf(t, probe.publicKey())[:len(spkiOf(t, probe.publicKey()))-1]),
		"the point of the key and not its structure":      enc(point),
		"the request itself":                              enc(probe.der),
		"the key of the request with one bit changed":     enc(flipLastBit(spkiOf(t, probe.publicKey()))),
		"the key written twice":                           enc(append(spkiOf(t, probe.publicKey()), spkiOf(t, probe.publicKey())...)),
		"the key as hexadecimal text":                     hex.EncodeToString(spkiOf(t, probe.publicKey())),
		"the structure of the key with a zero coordinate": enc(append(spkiOf(t, probe.publicKey())[:len(spkiOf(t, probe.publicKey()))-96], make([]byte, 96)...)),
	} {
		t.Run(name, func(t *testing.T) {
			f := kmsProofWith(t, text)
			f.csr, f.der, f.signer = probe.csr, probe.der, probe.signer
			f.proof["request_sha256"] = digestHex(probe.der)
			// The verifier read the right key from KMS: the proof is still refused.
			sv := returning(f.goodEvidence(handoff.StoreKMS))
			v, err := checkerWith(t, handoff.StoreKMS, sv).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
			if sv.calls.Load() != 1 {
				t.Errorf("the verifier was called %d times: check 7 comes before check 8", sv.calls.Load())
			}
		})
	}
}

func flipLastBit(b []byte) []byte {
	out := bytes.Clone(b)
	out[len(out)-1] ^= 1
	return out
}

func TestEveryKeyOfAKMSRequestMustBeTheKeyOfTheRequest(t *testing.T) {
	other := &newP384(t).PublicKey
	for name, tc := range map[string]struct {
		evidenceKey, proofKey string // "request" or "other"
		ok                    bool
		detail                string // a word that the detail of the refusal holds
	}{
		"all three are the key of the request": {"request", "request", true, ""},
		"the evidence is another key":          {"other", "request", false, "evidence"},
		"the proof names another key":          {"request", "other", false, "public_key"},
		"the evidence and the proof differ":    {"other", "other", false, "evidence"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, handoff.StoreKMS, csrSpec{})
			pick := func(which string) *ecdsa.PublicKey {
				if which == "request" {
					return f.publicKey()
				}
				return other
			}
			f.proof["evidence"] = kmsEvidence(pick(tc.proofKey))
			ev := f.goodEvidence(handoff.StoreKMS)
			ev.Key = pick(tc.evidenceKey)
			v, err := checkerWith(t, handoff.StoreKMS, returning(ev)).Check(t.Context(), f.request())
			if tc.ok {
				wantAccepted(t, v, err)
				return
			}
			wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
			// The key that the verifier read is compared first: when it is wrong the detail says so, and the
			// public_key of the proof is told only when the evidence is right.
			if !strings.Contains(v.Detail, tc.detail) {
				t.Errorf("the detail %q does not name %s", v.Detail, tc.detail)
			}
			if tc.detail == "evidence" && strings.Contains(v.Detail, "public_key") {
				t.Errorf("the detail %q names the public_key, which is compared after the evidence", v.Detail)
			}
		})
	}
}

func TestACheckThatComesBeforeCheckEightIsNotHiddenByAWrongPublicKey(t *testing.T) {
	other := &newP384(t).PublicKey
	// Check 7 first: a verifier that refuses gives proof-invalid, whatever the proof names.
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	f.proof["evidence"] = kmsEvidence(other)
	sv := failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "no role"})
	v, err := checkerWith(t, handoff.StoreKMS, sv).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)

	// A verifier that could not decide is not a refusal either.
	cause := errors.New("down")
	v, err = checkerWith(t, handoff.StoreKMS, failing(cause)).Check(t.Context(), f.request())
	wantUndecided(t, v, err, cause, "ppppppnnn")

	// Check 8 before check 9: a key that is not the request's and a fault of content give the first.
	g := newFixture(t, handoff.StoreKMS, csrSpec{exts: goodExtensions(uriName("example.net"))})
	g.proof["evidence"] = kmsEvidence(other)
	v, err = checkerWith(t, handoff.StoreKMS, returning(g.goodEvidence(handoff.StoreKMS))).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)

	// And a public_key that is right with the same fault of content is check 9's.
	g.proof["evidence"] = kmsEvidence(g.publicKey())
	v, err = checkerWith(t, handoff.StoreKMS, returning(g.goodEvidence(handoff.StoreKMS))).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
}

func TestAPublicKeyThatIsNotBase64IsMalformedAtCheckTwoAndNoVerifierIsCalled(t *testing.T) {
	good := spkiOf(t, newFixture(t, handoff.StoreKMS, csrSpec{}).publicKey())
	std := base64.StdEncoding.EncodeToString(good)
	for name, text := range map[string]string{
		"an empty text":                    "",
		"characters that are not Base64":   "***",
		"the URL alphabet":                 strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb, 0xff}, 60))),
		"no padding":                       std[:len(std)-2],
		"padding that is not at the end":   std[:len(std)-4] + "AA==" + "AAAA",
		"a line break in the middle":       std[:20] + "\n" + std[20:],
		"a space at its end":               std + " ",
		"a space at its start":             " " + std,
		"Base64 with a bit left over":      "YR==",
		"the key as PEM":                   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: good})),
		"padding in the middle":            std[:8] + "====" + std[8:],
		"a character that is not ASCII":    std[:8] + "ä" + std[9:],
		"a text with a control character":  std[:8] + "\x00" + std[9:],
		"a very long text of one letter A": strings.Repeat("A", 4*1000),
	} {
		t.Run(name, func(t *testing.T) {
			f := kmsProofWith(t, text)
			sv := returning(f.goodEvidence(handoff.StoreKMS))
			v, err := checkerWith(t, handoff.StoreKMS, sv).Check(t.Context(), f.request())
			if name == "a very long text of one letter A" {
				// Base64 of a long run of zero bytes is Base64: it is no key, and it is check 8's to refuse.
				wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
				return
			}
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
			if sv.calls.Load() != 0 {
				t.Error("a verifier ran for a proof that is not of the form of the page")
			}
		})
	}
}

func TestTheOtherStoresHaveNoPublicKeyToCompare(t *testing.T) {
	// A PIV or OpenPGP card proof carries only the attestation. The key in it is the one the verifier reads,
	// compared with the key of the request; nothing else is compared.
	for _, store := range []handoff.Store{handoff.StorePIV, handoff.StoreOpenPGPCard} {
		t.Run(string(store), func(t *testing.T) {
			f := newStoreCase(t, store)
			v, err := f.checker(returning(f.good()), nil).Check(t.Context(), f.request())
			wantAccepted(t, v, err)
			// A proof of these stores that holds a public_key is not of the form of the page.
			f.proof["evidence"] = map[string]any{"attestation": []string{b64("a"), b64("b")}, "public_key": b64("x")}
			v, err = f.checker(returning(f.good()), nil).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
		})
	}
}
