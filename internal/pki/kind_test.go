package pki_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// Every error of the package wraps exactly one of the three kinds (errors.go). Sign and Assemble read the
// extensions of a body with the rules of a request, and those rules wrap ErrRequest: the error that comes
// out of a body whose extensions are not those of the profile wraps ErrRequest as well as the kind of
// the call (ErrParams for Sign, ErrSignature for Assemble). A caller that tests errors.Is(err, ErrRequest)
// to tell "the request was refused" from "the key's parameters were wrong" is told both.
func TestRefusalsOfABodyWrapExactlyOneKind(t *testing.T) {
	f := newGuardFixture(t)
	notCritical := append([]byte(nil), f.inter.tbs...)
	i := bytes.Index(notCritical, []byte{0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff})
	notCritical[i+7] = 0x00
	pathLen1 := append([]byte(nil), f.inter.tbs...)
	j := bytes.Index(pathLen1, []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00})
	pathLen1[j+7] = 0x01
	for name, c := range map[string]struct {
		body  []byte
		words string
	}{"a key usage that is not critical": {notCritical, "key usage is not critical"}, "a path length of 1": {pathLen1, "basic constraints"}} {
		body, words := c.body, c.words
		t.Run("Sign: "+name, func(t *testing.T) {
			s := &opaqueSigner{key: f.root.key}
			_, err := pki.SignIntermediate(nil, s, f.inter.params, body)
			refused(t, err, pki.ErrParams)
			onePrefix(t, err)
			if s.calls != 0 {
				t.Error("the signer was called")
			}
		})
		t.Run("Assemble: "+name, func(t *testing.T) {
			_, err := pki.Assemble(body, rawSign(t, f.root.key, body), &f.root.key.PublicKey)
			refused(t, err, pki.ErrSignature)
			onePrefix(t, err)
			if err != nil && !strings.Contains(err.Error(), words) {
				t.Errorf("the text does not keep the reason, %q: %q", words, err.Error())
			}
		})
	}
}

// An issuer is the caller's parameter, and the request is held to 256 KiB before anything is written, so a body that
// is too long to write because of the issuer is a fault of the parameters: ErrParams, and never ErrRequest, which would
// tell the caller that the request is at fault. The smallest input: an issuer of one relative name of one attribute
// of a type that RFC 5280 gives no bound, a UTF8String of 16,776,690 characters (the body would be 16,777,097 octets, one over the limit of 16,777,096).
func TestAnIssuerThatIsTooLongToWriteIsAParameterNotARequest(t *testing.T) {
	root := buildRoot(t, nil)
	p := root.interParams(withExtensions(t, goodExtensions()...))
	p.IssuerSubject = issuerOfSize(16_776_690)
	tbs, err := intermediateTBS(t, p)
	refused(t, err, pki.ErrParams)
	if tbs != nil {
		t.Error("a body came with the error")
	}
}

// Every refusal that a test checks goes through refused (or wrapsParams, which calls it), and refused holds the error
// to exactly one kind of the package. A test that asks errors.Is(err, pki.ErrX) by hand would let an error that wraps
// two kinds pass, so the test files are held to not do it outside the helpers.
func TestNoTestChecksAKindByHandOutsideTheHelpers(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil || len(files) < 20 {
		t.Fatalf("test files: %v, %d", err, len(files))
	}
	for _, f := range files {
		if f == "helpers_test.go" || f == "kind_test.go" || strings.HasSuffix(f, "_internal_test.go") { // the internal tests are of package pki and have no refused()
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "errors.Is(err, pki.Err") || strings.Contains(line, "errors.Is(err, ErrParams") {
				t.Errorf("%s:%d checks a kind by hand: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// The issuer is the caller's parameter. A name whose text is not UTF-8 is read for its structure only by the issuer rules, and
// then the body is not a certificate that the standard library reads: the fault is the issuer's, so it is ErrParams and
// never ErrRequest, which would tell the caller that the request is at fault. The smallest input: an issuer of one common name
// whose UTF8String is the one octet 0xff.
func TestAnIssuerThatIsNotUTF8IsAParameterNotARequest(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	p := root.interParams(good)
	p.IssuerSubject = nameOf(rdn(atv(oidAttrCN, tlv(tUTF8, []byte{0xff}))))
	tbs, err := pki.IntermediateTBS(p)
	refused(t, err, pki.ErrParams)
	if tbs != nil {
		t.Error("a body came with the error")
	}
}
