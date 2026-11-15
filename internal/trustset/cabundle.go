package trustset

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strconv"
	"strings"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
)

// testMark ends the common name of a test root (bundle page, "The root certificate").
const testMark = " (TEST ONLY)"

// MarshalCABundle returns the bytes of ca-bundle.pem for a list: the first line
// "# trust-sequence: <sequence>\n", then the certificate of each root of the list in the order of
// the list, each as pem.EncodeToMemory writes a CERTIFICATE block (lines of 64 characters, LF), and
// nothing else. certs[i] is the DER certificate of roots[i]. The roots are given in the order in
// which MarshalList writes them, label order, and a bundle of roots in another order is refused,
// so that a bundle never has an order that its list does not have.
//
// It refuses a count of certificates that differs from the count of roots, a certificate that does
// not parse (trailing bytes after the DER included), whose key is not the key of the root's pin
// or is not ECDSA on P-384, that is not a CA certificate, that does not name itself as its issuer
// (a byte comparison of RawIssuer and RawSubject) or does not verify with its own key, a mix of
// test roots and real roots (the common name of a test root ends in " (TEST ONLY)"), and an output
// over MaxBytes. It does not read the dates, the names other than that mark, or the serial. The
// bytes are judged with rootlist.VerifyCABundle before they are returned. Every error wraps
// ErrParams, and no bytes come with an error.
func MarshalCABundle(sequence int64, roots []Root, certs [][]byte) ([]byte, error) {
	out, _, err := marshalCABundle(sequence, roots, certs)
	return out, err
}

// marshalCABundle is MarshalCABundle that also says whether the roots are test roots (all are, or
// none is: a mix is refused). The answer is false with an error.
func marshalCABundle(sequence int64, roots []Root, certs [][]byte) ([]byte, bool, error) {
	if err := checkSequence(sequence); err != nil {
		return nil, false, err
	}
	if err := checkRoots(roots); err != nil {
		return nil, false, err
	}
	if !slices.IsSortedFunc(roots, func(a, b Root) int { return strings.Compare(a.Label, b.Label) }) {
		return nil, false, fail(ErrParams, "the roots are not in label order, the order of the list")
	}
	if len(certs) != len(roots) {
		return nil, false, fail(ErrParams, "there are %d certificates for %d roots", len(certs), len(roots))
	}
	out := []byte("# trust-sequence: " + strconv.FormatInt(sequence, 10) + "\n")
	tests := 0
	for i, root := range roots {
		test, err := checkCertificate(root, certs[i])
		if err != nil {
			return nil, false, err
		}
		if test {
			tests++
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[i]})...)
		if len(out) > MaxBytes {
			return nil, false, fail(ErrParams, "ca-bundle.pem is longer than %d bytes", MaxBytes)
		}
	}
	if tests != 0 && tests != len(roots) {
		return nil, false, fail(ErrParams, "the certificates mix test roots and real roots")
	}
	if err := judgeBundle(out, sequence, roots); err != nil {
		return nil, false, err
	}
	return out, tests != 0, nil
}

// checkCertificate asks of one certificate what rootlist.VerifyCABundle asks, before a byte is
// written, and says whether its common name carries the mark of a test root. The size is checked
// before the parse.
func checkCertificate(root Root, der []byte) (test bool, err error) {
	if len(der) == 0 || len(der) > MaxBytes {
		return false, fail(ErrParams, "the certificate of root %s is empty or longer than %d bytes", root.Label, MaxBytes)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return false, fail(ErrParams, "the certificate of root %s is not one DER certificate", root.Label)
	}
	if err := checkKey(cert); err != nil {
		return false, fail(ErrParams, "the certificate of root %s: %v", root.Label, err)
	}
	if jws.Pin(cert) != root.X509SPKISHA256 {
		return false, fail(ErrParams, "the certificate of root %s does not hold the key of its pin", root.Label)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return false, fail(ErrParams, "the certificate of root %s is not a CA certificate", root.Label)
	}
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false, fail(ErrParams, "the certificate of root %s does not name itself as its issuer", root.Label)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return false, fail(ErrParams, "the certificate of root %s does not verify with its own key", root.Label)
	}
	return strings.HasSuffix(cert.Subject.CommonName, testMark), nil
}

// checkKey takes a certificate whose key is ECDSA on P-384 and is a point of the curve.
func checkKey(cert *x509.Certificate) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub == nil || pub.Curve != elliptic.P384() {
		return errNotP384
	}
	if _, err := pub.Bytes(); err != nil {
		return errNotP384
	}
	return nil
}

type textError string

func (e textError) Error() string { return string(e) }

const errNotP384 = textError("the key is not an ECDSA key on P-384")

// judgeBundle asks the reader of the page about the bundle that was written.
func judgeBundle(bundle []byte, sequence int64, roots []Root) error {
	list := &rootlist.List{Version: rootlist.Version, Sequence: sequence, Roots: make([]rootlist.Root, len(roots))}
	for i, r := range roots {
		list.Roots[i] = rootlist.Root(r)
	}
	if v := rootlist.VerifyCABundle(bundle, list); !v.Accepted {
		return fail(ErrParams, "the reader of the page refuses the bundle that was written: %s", v.Detail)
	}
	return nil
}
