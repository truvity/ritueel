package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/testrepo"
)

// The Check of a refusal (check.go): the reason code of the hand-off contract for a request that is refused, found with CheckOf. The
// table of every refusal of the source against the contract's checks is zz_refusals_test.go; this file tests the type, the order of
// the checks, and RequestKey, which gives the key of a request that passes checks 2, 4 and 5 (a request comes with no error).

func TestTheChecksAndTheirReasonCodes(t *testing.T) {
	for _, c := range []struct {
		check pki.Check
		code  string
	}{
		{pki.CheckNone, ""},
		{pki.CheckMalformed, "malformed"},
		{pki.CheckAlgorithm, "algorithm-unsupported"},
		{pki.CheckPossession, "possession-invalid"},
		{pki.CheckPolicy, "policy"},
		{pki.Check(99), ""},
		{pki.Check(-1), ""},
	} {
		if got := c.check.Code(); got != c.code {
			t.Errorf("Check(%d).Code() = %q, want %q", int(c.check), got, c.code)
		}
		if got := c.check.String(); got != c.code {
			t.Errorf("Check(%d).String() = %q, want %q", int(c.check), got, c.code)
		}
		if got := fmt.Sprint(c.check); got != c.code {
			t.Errorf("fmt of Check(%d) = %q, want %q", int(c.check), got, c.code)
		}
	}
	var zero pki.Check
	if zero != pki.CheckNone {
		t.Error("the zero value of Check is not CheckNone")
	}
	seen := map[string]bool{}
	for _, c := range []pki.Check{pki.CheckMalformed, pki.CheckAlgorithm, pki.CheckPossession, pki.CheckPolicy} {
		if c.Code() == "" || seen[c.Code()] {
			t.Errorf("the check %d has the code %q, which is empty or the code of another check", int(c), c.Code())
		}
		seen[c.Code()] = true
	}
}

// The codes of the four checks are the codes of the contract, read from the page and not typed here.
func TestTheReasonCodesAreThoseOfTheContractsTable(t *testing.T) {
	page := string(testrepo.Read(t, "docs", "reference", "hand-off-contract.md"))
	for _, c := range []pki.Check{pki.CheckMalformed, pki.CheckAlgorithm, pki.CheckPossession, pki.CheckPolicy} {
		if !strings.Contains(page, "| `"+c.Code()+"` |") {
			t.Errorf("the contract's table of checks has no row with the code %q", c.Code())
		}
	}
}

func TestCheckOfIsNoneForWhatIsNotARefusalOfARequest(t *testing.T) {
	root := buildRoot(t, nil)
	good := goodRequest(t)
	// A caller's mistake and a signer's failure are not refusals of a request.
	p := root.interParams(good)
	p.Serial = nil
	_, errParams := pki.IntermediateTBS(p)
	refused(t, errParams, pki.ErrParams)
	failing := &opaqueSigner{key: root.key, tweak: func([]byte, *ecdsa.PrivateKey, []byte) ([]byte, error) { return nil, errors.New("the card is gone") }}
	_, errSigner := pki.SignIntermediate(nil, failing, root.interParams(good), root.issue(t, good, nil).tbs)
	refused(t, errSigner, pki.ErrSignature)
	for name, err := range map[string]error{
		"nil":                             nil,
		"a plain error":                   errors.New("pki: certificate request refused: not made by this package"),
		"a parameter of the caller":       errParams,
		"a failure of the signer":         errSigner,
		"a wrapped plain error":           fmt.Errorf("context: %w", errors.New("x")),
		"an error of a root's parameters": rootParamsError(t),
	} {
		if got := pki.CheckOf(err); got != pki.CheckNone || got.Code() != "" {
			t.Errorf("%s: CheckOf = %q, want none", name, got)
		}
	}
	// A request that is accepted has no error to ask.
	if _, err := pki.ParseRequest(good.DER()); pki.CheckOf(err) != pki.CheckNone {
		t.Error("CheckOf(nil) is not none")
	}
}

func rootParamsError(t *testing.T) error {
	t.Helper()
	p := rootParams(&newKey(t).PublicKey)
	p.Name = ""
	_, err := pki.RootTBS(p)
	refused(t, err, pki.ErrParams)
	return err
}

// An error of a request says its check through wrapping too, and is an ErrRequest and nothing else.
func TestCheckOfSurvivesWrappingAndTheKindStaysOne(t *testing.T) {
	_, err := pki.ParseRequest([]byte{0x30, 0x00})
	refused(t, err, pki.ErrRequest)
	if got := pki.CheckOf(err); got != pki.CheckMalformed {
		t.Fatalf("CheckOf = %q", got)
	}
	for name, wrapped := range map[string]error{
		"fmt.Errorf":   fmt.Errorf("while reading: %w", err),
		"twice":        fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", err)),
		"errors.Join":  errors.Join(errors.New("other"), err),
		"two refusals": errors.Join(err, fmt.Errorf("second: %w", err)),
	} {
		if got := pki.CheckOf(wrapped); got != pki.CheckMalformed {
			t.Errorf("%s: CheckOf = %q, want malformed", name, got)
		}
	}
}

// The order of the checks: the first check of the contract's order that fails gives the code, whatever the order of the faults in the
// request. The contract's order is the form (2), the key (4), the signature (5), the policy (9); the later code makes 6 to 8.
func TestTheOrderOfTheChecksForSeveralFaults(t *testing.T) {
	root := buildRoot(t, nil)
	badSubject := cnName(tUTF8, "café")
	noEKU := goodExtensions()[:3:3]
	// a request that has a fault for each check, then one fewer at a time.
	allFaults := func(c *testCSR) {
		c.Version = []byte{0x02, 0x01, 0x01}                                   // 2: the form
		c.RawSubject = badSubject                                              // 9: the text of the subject
		c.Extensions = noEKU                                                   // 9: no extended key usage
		c.SignatureEdit = func(s []byte) []byte { s[len(s)-1] ^= 1; return s } // 5: the signature
	}
	rows := []struct {
		name  string
		build func(t *testing.T) *testCSR
		want  pki.Check
		words string
	}{
		{"form, key, signature and content", func(t *testing.T) *testCSR {
			c := makeCSR(t, csrOptions{key: p256Key(t), rawSubject: badSubject, exts: noEKU})
			// A request made by the standard library has no field to edit: its attribute is made twice by hand below.
			return c
		}, pki.CheckAlgorithm, "P-384"},
		{"form and the three after it", func(t *testing.T) *testCSR {
			c := makeCSR(t, csrOptions{rawSubject: badSubject, exts: noEKU})
			allFaults(c)
			c.Attributes = [][]byte{extensionRequestAttribute(extensionsValue(noEKU)), extensionRequestAttribute(extensionsValue(noEKU))}
			return c
		}, pki.CheckMalformed, "version of the request"},
		{"the version, the signature, the algorithm and the content", func(t *testing.T) *testCSR {
			c := makeCSR(t, csrOptions{rawSubject: badSubject, exts: noEKU})
			allFaults(c)
			c.Algorithm, c.Digest = algDER(0x02), 0
			return c
		}, pki.CheckMalformed, "version"},
		{"the key, the signature and the content: a P-256 key", func(t *testing.T) *testCSR {
			return makeCSR(t, csrOptions{key: p256Key(t), rawSubject: badSubject, exts: noEKU})
		}, pki.CheckAlgorithm, "P-384"},
		{"a form fault of the subject, a P-256 key and the content", func(t *testing.T) *testCSR {
			// A value that is a constructed element is a form fault of the subject (check 2), told before the key (4) and the signature (5).
			bad := nameOf(rdn(atv(oidAttrCN, tlv(0x30))))
			return makeCSR(t, csrOptions{key: p256Key(t), rawSubject: bad, exts: noEKU})
		}, pki.CheckMalformed, "whose value is not a string"},
		{"a form fault of the subject, a bad signature and the content", func(t *testing.T) *testCSR {
			c := makeCSR(t, csrOptions{rawSubject: nameOf(rdn(atv(oidAttrCN, tlv(0x30)))), exts: noEKU})
			c.SignatureEdit = func(s []byte) []byte { s[len(s)-1] ^= 1; return s }
			return c
		}, pki.CheckMalformed, "whose value is not a string"},
		{"the key (a well-formed key that is no key of P-384), the signature and the content", func(t *testing.T) *testCSR {
			c := makeCSR(t, csrOptions{rawSubject: badSubject, exts: noEKU})
			c.SignatureEdit = func(s []byte) []byte { s[len(s)-1] ^= 1; return s }
			c.RawSubjectPublicKeyInfo = tlv(0x30, tlv(0x30, mustOIDOf(oidECPublicKey)), tlv(0x03, []byte{0, 1}))
			return c
		}, pki.CheckAlgorithm, "P-384"},
		{"the key (an algorithm that is no AlgorithmIdentifier: a fault of form), the signature and the content", func(t *testing.T) *testCSR {
			c := makeCSR(t, csrOptions{rawSubject: badSubject, exts: noEKU})
			c.SignatureEdit = func(s []byte) []byte { s[len(s)-1] ^= 1; return s }
			c.RawSubjectPublicKeyInfo = tlv(0x30, tlv(0x30), tlv(0x03, []byte{0, 1}))
			return c
		}, pki.CheckMalformed, "not a SubjectPublicKeyInfo"},
		{"the key (an algorithm that is no AlgorithmIdentifier), a P-256 signature algorithm and the content", func(t *testing.T) *testCSR {
			c := makeCSR(t, csrOptions{rawSubject: badSubject, exts: noEKU})
			c.Algorithm, c.Digest = algDER(0x02), 0
			c.RawSubjectPublicKeyInfo = tlv(0x30, tlv(0x30, tlv(0x05)), tlv(0x03, []byte{0, 1}))
			return c
		}, pki.CheckMalformed, "not a SubjectPublicKeyInfo"},
		{"the algorithm, the signature and the content", func(t *testing.T) *testCSR {
			c := makeCSR(t, csrOptions{rawSubject: badSubject, exts: noEKU})
			c.Algorithm, c.Digest = algDER(0x04), 0
			c.SignatureEdit = func(s []byte) []byte { s[len(s)-1] ^= 1; return s }
			return c
		}, pki.CheckPossession, "ecdsa-with-SHA384"},
		{"the signature and the content", func(t *testing.T) *testCSR {
			c := makeCSR(t, csrOptions{rawSubject: badSubject, exts: noEKU})
			c.SignatureEdit = func(s []byte) []byte { s[len(s)-1] ^= 1; return s }
			return c
		}, pki.CheckPossession, "does not verify"},
		{"the content only, the text of the subject and the extended key usage", func(t *testing.T) *testCSR {
			return makeCSR(t, csrOptions{rawSubject: badSubject, exts: noEKU})
		}, pki.CheckPolicy, "the subject of the request has a value"},
		{"two faults of the extensions: both policy, the first of the code's order is told", func(t *testing.T) *testCSR {
			// A critical key usage that is not critical and no name constraints: the flags are read before the missing parts.
			return withExtensions(t, extBasicConstraints(), pkix.Extension{Id: oidKeyUsage, Critical: false, Value: bitString(kuKeyCertSign)})
		}, pki.CheckPolicy, "key usage is not critical"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			c := r.build(t)
			der := c.DER()
			req, err := pki.ParseRequest(der)
			refusedSaying(t, err, pki.ErrRequest, r.words)
			if got := pki.CheckOf(err); got != r.want {
				t.Errorf("ParseRequest: check %q, want %q: %v", got, r.want, err)
			}
			if req != nil {
				t.Errorf("a request came with the check %q", pki.CheckOf(err))
			}
			// IntermediateTBS reads the same bytes in the same order.
			p := root.interParams(c)
			p.CSR = der
			_, err = pki.IntermediateTBS(p)
			refusedSaying(t, err, pki.ErrRequest, r.words)
			if got := pki.CheckOf(err); got != r.want {
				t.Errorf("IntermediateTBS: check %q, want %q", got, r.want)
			}
		})
	}
	t.Run("a parameter of the caller is judged before the request", func(t *testing.T) {
		c := makeCSR(t, csrOptions{rawSubject: badSubject, exts: noEKU})
		c.Version = []byte{0x02, 0x01, 0x01}
		p := root.interParams(c)
		p.Serial = nil
		_, err := pki.IntermediateTBS(p)
		refused(t, err, pki.ErrParams)
		if pki.CheckOf(err) != pki.CheckNone {
			t.Errorf("check %q for a parameter", pki.CheckOf(err))
		}
		p = root.interParams(c)
		p.IssuerSubject = []byte{0x30, 0x00}
		_, err = pki.IntermediateTBS(p)
		refused(t, err, pki.ErrParams)
	})
	t.Run("a request that is read and is the issuer's own is policy", func(t *testing.T) {
		c := goodRequest(t)
		c.Key = root.key
		c.RawSubjectPublicKeyInfo = nil
		_, err := pki.IntermediateTBS(root.interParams(c))
		refused(t, err, pki.ErrRequest)
		if got := pki.CheckOf(err); got != pki.CheckPolicy {
			t.Errorf("check %q, want policy", got)
		}
		// Malformed beats the issuer's own key: the form is read first.
		c.Version = []byte{0x02, 0x01, 0x01}
		_, err = pki.IntermediateTBS(root.interParams(c))
		if got := pki.CheckOf(err); got != pki.CheckMalformed {
			t.Errorf("check %q, want malformed", got)
		}
	})
}

// --- no request with an error, and RequestKey -----------------------------------------------------------------

// ParseRequest and ParseRequestFile return a nil request with every error, a refusal for content (policy) included, so a guard on the
// pointer and a guard on the error say the same thing. RequestKey and RequestKeyFile read a request as far as checks 2, 4 and 5 and
// return its key: the key of a request that passes those three, also when its content would be refused; and for a request that fails
// one of them the error that ParseRequest gives, with the same check and the same words, and no key. Never a key together with an error.
func TestRequestKeyIsTheKeyOfARequestThatPassesChecks2To5(t *testing.T) {
	good := goodRequest(t)
	big := bytes.Repeat([]byte{0x30}, pki.MaxRequestSize+1)
	cases := []struct {
		name  string
		build func() *testCSR
		want  pki.Check
	}{
		{"a good request", func() *testCSR { return good }, pki.CheckNone},
		{"no extended key usage", func() *testCSR { return withExactExtensions(t, goodExtensions()[:3]...) }, pki.CheckPolicy},
		{"a subject outside ASCII", func() *testCSR { c := copyCSR(good); c.RawSubject = cnName(tUTF8, "é"); return c }, pki.CheckPolicy},
		{"name constraints that are not critical", func() *testCSR {
			return withExtensions(t, extBasicConstraints(), extKeyUsage(kuKeyCertSign), pkix.Extension{Id: oidNameConstraints, Value: nameConstraintsValue(2, "example.org")})
		}, pki.CheckPolicy},
		{"no extensions that the profile knows", func() *testCSR { return withExactExtensions(t, extBasicConstraints()) }, pki.CheckPolicy},
		{"a version of 1", func() *testCSR { c := copyCSR(good); c.Version = []byte{0x02, 0x01, 0x01}; return c }, pki.CheckMalformed},
		{"a version of 7", func() *testCSR { c := copyCSR(good); c.Version = []byte{0x02, 0x01, 0x07}; return c }, pki.CheckMalformed},
		{"a byte after the request", func() *testCSR { c := copyCSR(good); c.AfterRequest = []byte{0}; return c }, pki.CheckMalformed},
		{"junk", func() *testCSR { return &testCSR{Fixed: []byte("not a request")} }, pki.CheckMalformed},
		{"nothing", func() *testCSR { return &testCSR{Fixed: []byte{}} }, pki.CheckMalformed},
		{"more than the limit", func() *testCSR { return &testCSR{Fixed: big} }, pki.CheckMalformed},
		{"an algorithm element that is not an AlgorithmIdentifier", func() *testCSR { c := copyCSR(good); c.Algorithm = []byte{0x04, 0x01, 0x00}; return c }, pki.CheckMalformed},
		{"a P-256 key", func() *testCSR { return makeCSR(t, csrOptions{key: p256Key(t), exts: goodExtensions()}) }, pki.CheckAlgorithm},
		{"a P-256 key and a content fault", func() *testCSR {
			return makeCSR(t, csrOptions{key: p256Key(t), rawSubject: cnName(tUTF8, "é"), exts: goodExtensions()[:3]})
		}, pki.CheckAlgorithm},
		{"a signature that does not verify", func() *testCSR {
			c := copyCSR(good)
			c.SignatureEdit = func(s []byte) []byte { s[len(s)-1] ^= 1; return s }
			return c
		}, pki.CheckPossession},
		{"SHA-256", func() *testCSR { c := copyCSR(good); c.Algorithm, c.Digest = algDER(0x02), 0; return c }, pki.CheckPossession},
		{"SHA-256 and a content fault", func() *testCSR {
			c := withExactExtensions(t, goodExtensions()[:3]...)
			c.Algorithm, c.Digest = algDER(0x02), 0
			return c
		}, pki.CheckPossession},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			csr := c.build()
			der := csr.DER()
			file := pemBlockOf("CERTIFICATE REQUEST", der)
			req, err := pki.ParseRequest(der)
			reqFile, errFile := pki.ParseRequestFile(file)
			key, keyErr := pki.RequestKey(der)
			fileKey, fileKeyErr := pki.RequestKeyFile(file)
			if c.want != pki.CheckNone {
				refused(t, err, pki.ErrRequest)
			}
			if got := pki.CheckOf(err); got != c.want {
				t.Fatalf("ParseRequest: check %q, want %q (%v)", got, c.want, err)
			}
			// A request comes with no error and with no other.
			if (req != nil) != (err == nil) || (reqFile != nil) != (errFile == nil) {
				t.Errorf("a request: %v with the error %v; a file's request: %v with the error %v", req != nil, err, reqFile != nil, errFile)
			}
			// Never a key with an error, never an error with a key.
			if (key != nil) == (keyErr != nil) || (fileKey != nil) == (fileKeyErr != nil) {
				t.Fatalf("RequestKey: %v and %v; RequestKeyFile: %v and %v", key, keyErr, fileKey, fileKeyErr)
			}
			switch c.want {
			case pki.CheckNone, pki.CheckPolicy:
				// The key of a request that passes checks 2, 4 and 5: also one that the content refuses.
				if keyErr != nil || fileKeyErr != nil {
					t.Fatalf("RequestKey refuses a request that passes checks 2, 4 and 5: %v, %v", keyErr, fileKeyErr)
				}
				want := &csr.Key.PublicKey
				if !key.Equal(want) || !fileKey.Equal(want) {
					t.Error("the key that RequestKey returns is not the key of the request")
				}
				if c.want == pki.CheckNone && !req.PublicKey().Equal(key) {
					t.Error("RequestKey and the key of the request that ParseRequest reads are two keys")
				}
			default:
				// The same error as ParseRequest gives: the check and the words.
				if pki.CheckOf(keyErr) != c.want || pki.CheckOf(fileKeyErr) != c.want {
					t.Errorf("RequestKey: check %q and %q, want %q", pki.CheckOf(keyErr), pki.CheckOf(fileKeyErr), c.want)
				}
				if keyErr.Error() != err.Error() {
					t.Errorf("RequestKey says %q and ParseRequest %q", keyErr, err)
				}
				refused(t, keyErr, pki.ErrRequest)
				refused(t, fileKeyErr, pki.ErrRequest)
			}
		})
	}
	// A request file that is not one block: the PEM rules are those of ParseRequestFile.
	der := good.DER()
	block := pemBlockOf("CERTIFICATE REQUEST", der)
	for name, file := range map[string][]byte{
		"two blocks":              append(append([]byte(nil), block...), block...),
		"text after the block":    append(append([]byte(nil), block...), []byte("text\n")...),
		"another label":           pemBlockOf("NEW CERTIFICATE REQUEST", der),
		"no block":                []byte("hello"),
		"text before the block":   append([]byte("x\n"), block...),
		"more than the limit":     make([]byte, pki.MaxRequestSize+1),
		"a block of another type": pemBlockOf("CERTIFICATE", der),
	} {
		t.Run("a file with "+name, func(t *testing.T) {
			key, err := pki.RequestKeyFile(file)
			_, errParse := pki.ParseRequestFile(file)
			if key != nil || err == nil {
				t.Fatalf("a key %v with the error %v", key, err)
			}
			refused(t, err, pki.ErrRequest)
			if pki.CheckOf(err) != pki.CheckMalformed || err.Error() != errParse.Error() {
				t.Errorf("RequestKeyFile says %q (%q), ParseRequestFile %q", err, pki.CheckOf(err), errParse)
			}
		})
	}
}

// RequestKey gives a copy of the key, and copies what it reads: a caller that changes the key it was given, or the bytes it passed,
// changes nothing for a second call.
func TestRequestKeyReturnsACopyAndCopiesItsInput(t *testing.T) {
	csr := withExactExtensions(t, goodExtensions()[:3]...) // refused for content: only the key is asked for
	der := csr.DER()
	input := append([]byte(nil), der...)
	key, err := pki.RequestKey(input)
	if err != nil || key == nil {
		t.Fatalf("%v, %v", key, err)
	}
	for i := range input {
		input[i] ^= 0xff // the caller reuses its buffer
	}
	key.X = nil //nolint:staticcheck // the exported field is the only way a caller can change the key that it was given
	again, err := pki.RequestKey(der)
	if err != nil || !again.Equal(&csr.Key.PublicKey) {
		t.Errorf("a second call gives %v, %v after the first key was changed", again, err)
	}
	other, _ := pki.RequestKey(der)
	if again == other {
		t.Error("two calls give the same key object")
	}
	var none *pki.Request
	if none.DER() != nil || none.PublicKey() != nil || none.Subject() != nil || none.SubjectName() != nil || none.Extensions() != nil || none.NameConstraints().ExcludesAllIP {
		t.Error("the methods of a nil request answer")
	}
}

// What the caller of ParseRequest can do wrong with a refusal for content: nothing is left. The request is nil with every error, so a guard
// on the pointer and a guard on the error agree for every refusal, and the bytes of a refused request are refused again, with the same check,
// by IntermediateTBS. The key of a request that is refused for content is for the later checks only, and is not an issuer.
func TestNoRequestCameWithAnErrorSoNoGuardIsWrong(t *testing.T) {
	root := buildRoot(t, nil)
	csr := withExactExtensions(t, goodExtensions()[:3]...)
	der := csr.DER()
	req, err := pki.ParseRequest(der)
	if pki.CheckOf(err) != pki.CheckPolicy || req != nil {
		t.Fatalf("a request %v with the error %v", req != nil, err)
	}
	if (req == nil) != (err != nil) {
		t.Error("the guard on the pointer and the guard on the error disagree")
	}
	p := root.interParams(csr)
	p.CSR = der
	tbs, err2 := pki.IntermediateTBS(p)
	refused(t, err2, pki.ErrRequest)
	if tbs != nil || pki.CheckOf(err2) != pki.CheckPolicy || err2.Error() != err.Error() {
		t.Errorf("IntermediateTBS of the same bytes: body %v, %v", tbs != nil, err2)
	}
	// Its key given as the issuer's: still the policy refusal of the request, which is read first.
	key, kerr := pki.RequestKey(der)
	if kerr != nil {
		t.Fatal(kerr)
	}
	p.IssuerKey, p.Roots = key, []pki.RootRef{{Subject: p.IssuerSubject, Key: key}}
	_, err2 = pki.IntermediateTBS(p)
	if pki.CheckOf(err2) != pki.CheckPolicy {
		t.Errorf("check %q", pki.CheckOf(err2))
	}
}

// --- CheckOf: a signer's error, and a caller's own wrapper -------------------------------------------------------

// requestErrorsOfEveryCheck are four errors of ParseRequest, one for each check.
func requestErrorsOfEveryCheck(t *testing.T) map[pki.Check]error {
	t.Helper()
	good := goodRequest(t)
	out := map[pki.Check]error{}
	for check, csr := range map[pki.Check]*testCSR{
		pki.CheckMalformed:  func() *testCSR { c := copyCSR(good); c.Version = []byte{0x02, 0x01, 0x01}; return c }(),
		pki.CheckAlgorithm:  makeCSR(t, csrOptions{key: p256Key(t), exts: goodExtensions()}),
		pki.CheckPossession: func() *testCSR { c := copyCSR(good); c.Algorithm, c.Digest = algDER(0x02), 0; return c }(),
		pki.CheckPolicy:     withExactExtensions(t, goodExtensions()[:3]...),
	} {
		_, err := pki.ParseRequest(csr.DER())
		if pki.CheckOf(err) != check {
			t.Fatalf("a request for the check %q says %q", check, pki.CheckOf(err))
		}
		out[check] = err
	}
	return out
}

// A signer that returns an error that a request reader made: the signing function wraps the signer's error as an ErrSignature, the signer's
// error stays reachable (errors.Is), and CheckOf says no check, because the check of a request is the package's word on a request and the
// signer's error is not that. Before the fix CheckOf found the check inside the signer's error and answered for an ErrSignature.
func TestCheckOfIsNoneForTheErrorOfASigner(t *testing.T) {
	root := buildRoot(t, nil)
	good := goodRequest(t)
	p := root.interParams(good)
	tbs, err := pki.IntermediateTBS(p)
	if err != nil {
		t.Fatal(err)
	}
	rp := rootParams(&root.key.PublicKey)
	rtbs, err := pki.RootTBS(rp)
	if err != nil {
		t.Fatal(err)
	}
	for check, rerr := range requestErrorsOfEveryCheck(t) {
		t.Run(check.Code(), func(t *testing.T) {
			s := &opaqueSigner{key: root.key, tweak: func([]byte, *ecdsa.PrivateKey, []byte) ([]byte, error) { return nil, rerr }}
			for name, call := range map[string]func() ([]byte, error){
				"SignIntermediate": func() ([]byte, error) { return pki.SignIntermediate(nil, s, p, tbs) },
				"SignRoot":         func() ([]byte, error) { return pki.SignRoot(nil, s, rp, rtbs) },
			} {
				sig, err := call()
				// The error is an ErrSignature, and the signer's own error stays reachable (so, for a signer whose error is an ErrRequest, it
				// wraps that kind too: the one case where an error of the package wraps two kinds, by design, because the cause is kept).
				if err == nil || !wraps(err, pki.ErrSignature) || !wraps(err, rerr) {
					t.Fatalf("%s: %v", name, err)
				}
				if sig != nil {
					t.Errorf("%s: a signature came with the error", name)
				}
				if got := pki.CheckOf(err); got != pki.CheckNone || got.Code() != "" {
					t.Errorf("%s: CheckOf says %q for the error of a signer that was a %q request error", name, got, check)
				}
				if !errors.Is(err, rerr) {
					t.Errorf("%s: the error of the signer is not reachable", name)
				}
				// A caller's own wrapper around the signing error does not bring the check back.
				if got := pki.CheckOf(fmt.Errorf("while signing: %w", err)); got != pki.CheckNone {
					t.Errorf("%s: a wrapper says %q", name, got)
				}
				if got := pki.CheckOf(errors.Join(errors.New("x"), err)); got != pki.CheckNone {
					t.Errorf("%s: a join says %q", name, got)
				}
			}
		})
	}
	// An error of a parameter (no roots), of the signer's key and of the second check have no check either.
	p2 := root.interParams(good)
	p2.Roots = nil
	_, err = pki.IntermediateTBS(p2)
	if got := pki.CheckOf(err); got != pki.CheckNone {
		t.Errorf("no roots: check %q", got)
	}
}

// A request error that a caller wraps itself (fmt.Errorf with %w, errors.Join, and two types of its own with Unwrap in the two forms) still
// says its check: the check is found through the wrappers of the caller and not through the cause of an error of the package.
func TestCheckOfIsFoundThroughACallersOwnWrapper(t *testing.T) {
	for check, rerr := range requestErrorsOfEveryCheck(t) {
		wrappers := map[string]error{
			"fmt.Errorf":                fmt.Errorf("context: %w", rerr),
			"fmt.Errorf twice":          fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", rerr)),
			"errors.Join, first":        errors.Join(rerr, errors.New("other")),
			"errors.Join, last":         errors.Join(errors.New("other"), rerr),
			"a join of joins":           errors.Join(errors.New("a"), errors.Join(errors.New("b"), fmt.Errorf("c: %w", rerr))),
			"fmt.Errorf with two %w":    fmt.Errorf("%w and %w", errors.New("other"), rerr),
			"a wrapper type":            wrapOne{rerr},
			"a wrapper type of several": wrapMany{[]error{errors.New("x"), wrapOne{rerr}}},
		}
		for name, w := range wrappers {
			if got := pki.CheckOf(w); got != check {
				t.Errorf("%s of a %q error: CheckOf says %q", name, check, got)
			}
			if !wraps(w, pki.ErrRequest) || wraps(w, pki.ErrParams) || wraps(w, pki.ErrSignature) {
				t.Errorf("%s: the kind is not ErrRequest alone", name)
			}
		}
		// Two request errors of different checks in one join: the first in the order of the join.
		for other, oerr := range requestErrorsOfEveryCheck(t) {
			if other == check {
				continue
			}
			if got := pki.CheckOf(errors.Join(rerr, oerr)); got != check {
				t.Errorf("a join of %q then %q says %q", check, other, got)
			}
		}
	}
	for name, err := range map[string]error{
		"nil": nil, "a plain error": errors.New("x"), "the bare kind": pki.ErrRequest, "a wrapped kind": fmt.Errorf("w: %w", pki.ErrRequest),
		"a wrapped parameter kind": fmt.Errorf("w: %w", pki.ErrParams), "a join of plain errors": errors.Join(errors.New("a"), errors.New("b")),
	} {
		if got := pki.CheckOf(err); got != pki.CheckNone {
			t.Errorf("%s: CheckOf says %q", name, got)
		}
	}
}

type wrapOne struct{ err error }

func (w wrapOne) Error() string { return "wrapped: " + w.err.Error() }
func (w wrapOne) Unwrap() error { return w.err }

type wrapMany struct{ errs []error }

func (w wrapMany) Error() string   { return "wrapped many" }
func (w wrapMany) Unwrap() []error { return w.errs }

// --- RequestKey and ParseRequest never disagree about checks 2, 4 and 5 -------------------------------------------

// A large set of requests: the faults of the subject (of content and of form) with every fault of the key, the algorithm, the version, the
// signature and the extensions beside them, and 30,000 mutations of the bytes of requests (a byte changed, deleted, inserted, a cut, a
// block moved). For each, RequestKey and ParseRequest say the same about checks 2, 4 and 5: the same check and the same words for a refusal of one
// of the three, a key and no error when only the content is at fault, and the same key when the request is accepted; RequestKeyFile and
// ParseRequestFile say the same of the file of the same request. Never a key with an error, never an error without a key.
func TestRequestKeyAndParseRequestNeverDisagreeAboutChecks2To5(t *testing.T) {
	good := goodRequest(t)
	var inputs [][]byte
	// The structured set.
	subjects := [][]byte{good.RawSubject}
	for _, f := range append(allContentFaults(), formFaults()...) {
		subjects = append(subjects, subjectOf(f.rdns))
	}
	algs := [][]byte{nil, algDER(0x02), {0x04, 0x01, 0x00}, tlv(0x30, algECDSAWithSHA384DER[2:], tlv(0x05), tlv(0x05))}
	for _, subject := range subjects {
		for _, alg := range algs {
			for _, flags := range []int{0, 1, 2, 4, 8, 3, 5, 6, 7, 9, 14, 15} {
				c := copyCSR(good)
				c.RawSubject = subject
				if alg != nil {
					c.Algorithm, c.Digest = alg, 0
				}
				if flags&1 != 0 {
					c.SignatureEdit = func(b []byte) []byte { b[len(b)-1] ^= 1; return b }
				}
				if flags&2 != 0 {
					c.RawSubjectPublicKeyInfo = p256Fuzz()
				}
				if flags&4 != 0 {
					c.Version = []byte{0x02, 0x01, 0x01}
				}
				if flags&8 != 0 {
					c.Extensions = goodExtensions()[:3]
				}
				inputs = append(inputs, c.DER())
			}
		}
	}
	// Requests that are accepted, each with a key and a signature of its own: the mutated set below accepts a request only when a change
	// leaves it as it was, which is a matter of chance, so the accepted ones are put in here and not left to it.
	for i := 0; i < 12; i++ {
		inputs = append(inputs, goodRequest(t).DER())
	}
	structured := len(inputs)
	// The mutated set, from a few requests of different shapes.
	bases := [][]byte{good.DER(), withExactExtensions(t, goodExtensions()[:3]...).DER(), makeCSR(t, csrOptions{key: p256Key(t), exts: goodExtensions()}).DER()}
	rnd := mathrand.New(mathrand.NewPCG(7, 11))
	for i := 0; i < 30000; i++ {
		b := append([]byte(nil), bases[rnd.IntN(len(bases))]...)
		for n := 1 + rnd.IntN(3); n > 0 && len(b) > 4; n-- {
			at := rnd.IntN(len(b))
			switch rnd.IntN(6) {
			case 0:
				b[at] ^= byte(1 << rnd.IntN(8))
			case 1:
				b[at] = byte(rnd.IntN(256))
			case 2:
				b = append(b[:at], b[at+1:]...)
			case 3:
				b = append(b[:at], append([]byte{byte(rnd.IntN(256))}, b[at:]...)...)
			case 4:
				b = b[:at]
			default:
				j := rnd.IntN(len(b))
				b[at], b[j] = b[j], b[at]
			}
		}
		inputs = append(inputs, b)
	}
	seen := map[string]int{}
	for _, der := range inputs {
		req, err := pki.ParseRequest(der)
		key, kerr := pki.RequestKey(der)
		file := pemBlockOf("CERTIFICATE REQUEST", der)
		freq, ferr := pki.ParseRequestFile(file)
		fkey, fkerr := pki.RequestKeyFile(file)
		c := pki.CheckOf(err)
		seen[c.Code()+"/"+pki.CheckOf(kerr).Code()]++
		if (req != nil) != (err == nil) || (freq != nil) != (ferr == nil) || (key != nil) == (kerr != nil) || (fkey != nil) == (fkerr != nil) {
			t.Fatalf("a request, a key and an error that do not go together for %x", der)
		}
		if len(file) <= pki.MaxRequestSize && (pki.CheckOf(ferr) != c || pki.CheckOf(fkerr) != pki.CheckOf(kerr) || (key != nil && !key.Equal(fkey))) {
			t.Fatalf("the file says %q, %q and the bytes %q, %q for %x", pki.CheckOf(ferr), pki.CheckOf(fkerr), c, pki.CheckOf(kerr), der)
		}
		switch c {
		case pki.CheckNone:
			if kerr != nil || !key.Equal(req.PublicKey()) {
				t.Fatalf("an accepted request, and RequestKey says %v, %v for %x", key, kerr, der)
			}
		case pki.CheckPolicy:
			if kerr != nil || key == nil {
				t.Fatalf("a request that is refused for its content, and RequestKey says %v, %v for %x", key, kerr, der)
			}
		default:
			if key != nil || pki.CheckOf(kerr) != c || kerr.Error() != err.Error() {
				t.Fatalf("ParseRequest says %v (%q) and RequestKey %v (%q) for %x", err, c, kerr, pki.CheckOf(kerr), der)
			}
		}
	}
	t.Logf("%d requests (%d structured): %v", len(inputs), structured, seen)
	for _, want := range []string{"malformed/malformed", "algorithm-unsupported/algorithm-unsupported", "possession-invalid/possession-invalid", "policy/", "/"} {
		if seen[want] < 5 {
			t.Errorf("the walk saw only %d pairs of %q", seen[want], want)
		}
	}
}
