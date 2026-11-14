package pki_test

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// encoding/asn1 reads a SEQUENCE into a Go struct and ignores an element after the last field. Every structure of a request or a body
// that the package reads is tried here with one element after its last field, and the refusal must be the check that the contract gives
// the structure, whatever way the structure is read (a struct, a list of elements, a slice): an element after the last field is never a
// way past a check. The rows are the structures that the package reads with encoding/asn1, one by one.

// withElementAfter is the DER of a constructed element with one more element (a null) after its content.
func withElementAfter(t *testing.T, der []byte) []byte {
	t.Helper()
	var v asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &v); err != nil || len(rest) != 0 {
		t.Fatalf("not one element: %v", err)
	}
	return tlv(der[0], v.Bytes, tlv(0x05))
}

func TestAnElementAfterTheLastFieldOfEveryStructureIsRefusedWithItsCheck(t *testing.T) {
	good := goodRequest(t)
	spki := good.SPKI()
	goodExts := extensionsValue(goodExtensions())
	goodNC := goodExtensions()[2].Value
	oneName := ncSub(dns("example.org"))
	rows := []struct {
		name  string
		edit  func(c *testCSR)
		check pki.Check
	}{
		// check 2: the form
		{"the request: an element after the signature", func(c *testCSR) { c.OuterTrailer = tlv(0x05) }, pki.CheckMalformed},
		{"the request info: an element after the attributes", func(c *testCSR) { c.InfoTrailer = tlv(0x05) }, pki.CheckMalformed},
		{"the signature algorithm: parameters and one more element", func(c *testCSR) {
			c.Algorithm = tlv(0x30, algECDSAWithSHA384DER[2:], tlv(0x05), tlv(0x05))
		}, pki.CheckMalformed},
		{"the key: an element after the bit string", func(c *testCSR) { c.RawSubjectPublicKeyInfo = withElementAfter(t, spki) }, pki.CheckMalformed},
		{"the key: an element after the algorithm", func(c *testCSR) { c.RawSubjectPublicKeyInfo = withElementAfterTheAlgorithm(t, spki) }, pki.CheckMalformed},
		{"the key: an algorithm of three elements", func(c *testCSR) {
			c.RawSubjectPublicKeyInfo = withAlgorithmOf(t, spki, func(a asn1.RawValue) []byte { return tlv(0x30, a.Bytes, tlv(0x05)) })
		}, pki.CheckMalformed},
		{"the attribute: an element after its set of values", func(c *testCSR) {
			c.Attributes = [][]byte{tlv(0x30, oidExtensionRequest, tlv(0x31, goodExts), tlv(0x05))}
		}, pki.CheckMalformed},
		{"the attribute: a second value in its set", func(c *testCSR) {
			c.Attributes = [][]byte{tlv(0x30, oidExtensionRequest, tlv(0x31, goodExts, goodExts))}
		}, pki.CheckMalformed},
		{"an extension: an element after its value", func(c *testCSR) {
			c.ExtensionsDER = tlv(0x30, tlv(0x30, mustOIDOf(oidBasicConstraints), []byte{0x01, 0x01, 0xff}, tlv(0x04, []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00}), tlv(0x05)))
		}, pki.CheckMalformed},
		{"the subject: an element after the value of an attribute", func(c *testCSR) {
			c.RawSubject = nameOf(rdn(tlv(0x30, oidAttrCN, str(tUTF8, "ca"), tlv(0x05))))
		}, pki.CheckMalformed},
		{"the subject: an element after the attribute in its set", func(c *testCSR) {
			c.RawSubject = nameOf(tlv(0x31, atv(oidAttrCN, str(tUTF8, "ca")), tlv(0x05)))
		}, pki.CheckMalformed},
		// check 5: the signature
		{"the signature value: a third integer", func(c *testCSR) {
			c.SignatureEdit = func(sig []byte) []byte { return withElementAfter(t, sig) }
		}, pki.CheckPossession},
		// check 9: the content
		{"the name constraints: an element after the fields", func(c *testCSR) {
			c.Extensions = []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign, kuCRLSign), {Id: oidNameConstraints, Critical: true, Value: withElementAfter(t, goodNC)}, extExtKeyUsage(false, oidServerAuth)}
		}, pki.CheckPolicy},
		{"the name constraints: an element after a subtree's base", func(c *testCSR) {
			c.Extensions = []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign, kuCRLSign), {Id: oidNameConstraints, Critical: true, Value: ncValue([][]byte{withElementAfter(t, oneName)}, nil)}, extExtKeyUsage(false, oidServerAuth)}
		}, pki.CheckPolicy},
		{"the key usage: an element after the bit string", func(c *testCSR) {
			c.Extensions = []pkix.Extension{extBasicConstraints(), {Id: oidKeyUsage, Critical: true, Value: append(bitString(kuKeyCertSign, kuCRLSign), 0x05, 0x00)}, extNameConstraints("example.org"), extExtKeyUsage(false, oidServerAuth)}
		}, pki.CheckPolicy},
		{"the extended key usage: an element after the identifiers", func(c *testCSR) {
			c.Extensions = []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign, kuCRLSign), extNameConstraints("example.org"), {Id: oidExtKeyUsage, Value: withElementAfter(t, extExtKeyUsage(false, oidServerAuth).Value)}}
		}, pki.CheckPolicy},
		{"the basic constraints: an element after the path length", func(c *testCSR) {
			c.Extensions = []pkix.Extension{{Id: oidBasicConstraints, Critical: true, Value: withElementAfter(t, extBasicConstraints().Value)}, extKeyUsage(kuKeyCertSign, kuCRLSign), extNameConstraints("example.org"), extExtKeyUsage(false, oidServerAuth)}
		}, pki.CheckPolicy},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			csr := copyCSR(good)
			r.edit(csr)
			der := csr.DER()
			req, err := pki.ParseRequest(der)
			refused(t, err, pki.ErrRequest)
			if got := pki.CheckOf(err); got != r.check || req != nil {
				t.Fatalf("check %q, want %q: %v", got, r.check, err)
			}
			// RequestKey stops at checks 2, 4 and 5.
			key, kerr := pki.RequestKey(der)
			if r.check == pki.CheckPolicy {
				if kerr != nil || key == nil {
					t.Errorf("RequestKey: %v, %v", key, kerr)
				}
			} else if key != nil || pki.CheckOf(kerr) != r.check || kerr.Error() != err.Error() {
				t.Errorf("RequestKey: %v, %v", key, kerr)
			}
		})
	}
	// The same for a body: a body with an element after its last field is refused by the signing and by the assembly.
	t.Run("a body with an element after the extensions", func(t *testing.T) {
		f := newGuardFixture(t)
		body := tlv(0x30, append(parts(t, f.inter.tbs), tlv(0x05))...)
		f.refused(t, f.signer, body)
		der, err := pki.Assemble(body, rawSign(t, f.root.key, body), &f.root.key.PublicKey)
		refused(t, err, pki.ErrSignature)
		if der != nil {
			t.Error("a certificate came with the error")
		}
	})
}
