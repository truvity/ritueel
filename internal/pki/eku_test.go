package pki_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// The extended key usage of a request (hand-off contract, the request table): required, not critical, serverAuth,
// clientAuth or both, each once, and nothing else. What is issued is the same purposes in the same order, not critical.

var (
	oidAnyExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidCodeSigning         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidEmailProtection     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidTimeStamping        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidOCSPSigning         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

// ekuRequest is a request with the three other extensions of a good request and the given extended key usage in place of the good
// one; at is where the extended key usage stands in the list (0 first, 3 last).
func ekuRequest(t testing.TB, eku []pkix.Extension, at int) *testCSR {
	t.Helper()
	exts := slicesInsert(goodExtensions()[:3:3], at, eku...)
	return withExactExtensions(t, exts...)
}

func slicesInsert(list []pkix.Extension, at int, more ...pkix.Extension) []pkix.Extension {
	out := append([]pkix.Extension(nil), list[:at]...)
	out = append(out, more...)
	return append(out, list[at:]...)
}

// The four accepted forms, in every place of the list, are read, issued, verified by both verifiers, and read back in the order of
// the request, not critical, by the standard library and by OpenSSL.
func TestTheExtendedKeyUsageFormsThatAreIssuedAreReadBackInTheirOrder(t *testing.T) {
	root := buildRoot(t, nil)
	forms := []struct {
		name    string
		oids    []asn1.ObjectIdentifier
		stdlib  []x509.ExtKeyUsage
		openssl string
	}{
		{"serverAuth", []asn1.ObjectIdentifier{oidServerAuth}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, "TLS Web Server Authentication"},
		{"clientAuth", []asn1.ObjectIdentifier{oidClientAuth}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "TLS Web Client Authentication"},
		{"serverAuth, clientAuth", []asn1.ObjectIdentifier{oidServerAuth, oidClientAuth}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, "TLS Web Server Authentication, TLS Web Client Authentication"},
		{"clientAuth, serverAuth", []asn1.ObjectIdentifier{oidClientAuth, oidServerAuth}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, "TLS Web Client Authentication, TLS Web Server Authentication"},
	}
	for _, f := range forms {
		for at := 0; at <= 3; at++ {
			t.Run(f.name+" at place "+string(rune('0'+at)), func(t *testing.T) {
				eku := extExtKeyUsage(false, f.oids...)
				csr := ekuRequest(t, []pkix.Extension{eku}, at)
				der := csr.DER()
				req, err := pki.ParseRequest(der)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				// The view has the extension as the request has it, in the request's place.
				if got := req.Extensions(); len(got) != 4 || !got[at].Id.Equal(oidExtKeyUsage) || got[at].Critical || !bytes.Equal(got[at].Value, eku.Value) {
					t.Errorf("the view of the extensions = %+v", got)
				}
				got := root.issue(t, &testCSR{Fixed: der}, nil)
				verifyEverywhere(t, root, got, true)
				// The standard library.
				if len(got.parsed.ExtKeyUsage) != len(f.stdlib) || len(got.parsed.UnknownExtKeyUsage) != 0 {
					t.Fatalf("purposes read by the standard library: %v and unknown %v", got.parsed.ExtKeyUsage, got.parsed.UnknownExtKeyUsage)
				}
				for i := range f.stdlib {
					if got.parsed.ExtKeyUsage[i] != f.stdlib[i] {
						t.Errorf("purpose %d = %v, want %v", i, got.parsed.ExtKeyUsage[i], f.stdlib[i])
					}
				}
				e := extensionOf(got.parsed, oidExtKeyUsage)
				if e == nil || e.Critical || !bytes.Equal(e.Value, eku.Value) {
					t.Errorf("the extension of the certificate = %+v, want the request's value, not critical", e)
				}
				// The place in the certificate is the profile's, whatever the place in the request.
				wantIDs := []string{"2.5.29.19", "2.5.29.15", "2.5.29.30", "2.5.29.37", "2.5.29.14", "2.5.29.35"}
				if ids := extensionIDs(got.parsed); strings.Join(ids, ",") != strings.Join(wantIDs, ",") {
					t.Errorf("extensions = %v, want %v", ids, wantIDs)
				}
				// OpenSSL, in its own words, and the strict verification of the chain.
				text := verifier.OpenSSLText(t, got.cert)
				if want := "X509v3 Extended Key Usage: \n                " + f.openssl + "\n"; !strings.Contains(text, want) {
					t.Errorf("OpenSSL does not print %q:\n%s", want, text)
				}
				if strings.Contains(text, "Extended Key Usage: critical") {
					t.Error("OpenSSL prints the extended key usage as critical")
				}
				if err := strictVerify(t, root.cert, got.cert, got.parsed.NotBefore.Add(24*time.Hour)); err != nil {
					t.Errorf("strict: %v", err)
				}
			})
		}
	}
}

// The forms that are refused are refused by the policy check, with the partial request, by ParseRequest and by IntermediateTBS, and
// no body comes.
func TestExtendedKeyUsageFormsAreRefused(t *testing.T) {
	root := buildRoot(t, nil)
	ekuValue := func(oids ...asn1.ObjectIdentifier) []byte { return extExtKeyUsage(false, oids...).Value }
	derList := func(parts ...[]byte) []byte { return tlv(0x30, parts...) }
	oidDER := mustOIDOf
	raw := func(critical bool, value []byte) []pkix.Extension {
		return []pkix.Extension{{Id: oidExtKeyUsage, Critical: critical, Value: value}}
	}
	rows := []struct {
		name  string
		exts  []pkix.Extension
		words string
	}{
		// Absent.
		{"absent", nil, "has no extended key usage"},
		// Critical: each accepted form, with the flag set.
		{"serverAuth, critical", raw(true, ekuValue(oidServerAuth)), "is critical"},
		{"clientAuth, critical", raw(true, ekuValue(oidClientAuth)), "is critical"},
		{"both, critical", raw(true, ekuValue(oidServerAuth, oidClientAuth)), "is critical"},
		{"both reversed, critical", raw(true, ekuValue(oidClientAuth, oidServerAuth)), "is critical"},
		{"critical and with another purpose: the flag is told first", raw(true, ekuValue(oidCodeSigning)), "is critical"},
		// anyExtendedKeyUsage.
		{"anyExtendedKeyUsage alone", raw(false, ekuValue(oidAnyExtendedKeyUsage)), "other than serverAuth and clientAuth"},
		{"serverAuth and anyExtendedKeyUsage", raw(false, ekuValue(oidServerAuth, oidAnyExtendedKeyUsage)), "other than serverAuth and clientAuth"},
		{"anyExtendedKeyUsage and clientAuth", raw(false, ekuValue(oidAnyExtendedKeyUsage, oidClientAuth)), "other than serverAuth and clientAuth"},
		{"anyExtendedKeyUsage, critical", raw(true, ekuValue(oidAnyExtendedKeyUsage)), "is critical"},
		// Other purposes.
		{"code signing", raw(false, ekuValue(oidCodeSigning)), "other than serverAuth and clientAuth"},
		{"e-mail protection", raw(false, ekuValue(oidEmailProtection)), "other than serverAuth and clientAuth"},
		{"time stamping", raw(false, ekuValue(oidTimeStamping)), "other than serverAuth and clientAuth"},
		{"OCSP signing", raw(false, ekuValue(oidOCSPSigning)), "other than serverAuth and clientAuth"},
		{"a purpose of a private arc", raw(false, ekuValue(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7, 1})), "other than serverAuth and clientAuth"},
		{"an identifier of one arc and a half", raw(false, ekuValue(asn1.ObjectIdentifier{2, 999, 1})), "other than serverAuth and clientAuth"},
		{"serverAuth and code signing", raw(false, ekuValue(oidServerAuth, oidCodeSigning)), "other than serverAuth and clientAuth"},
		{"code signing and clientAuth", raw(false, ekuValue(oidCodeSigning, oidClientAuth)), "other than serverAuth and clientAuth"},
		{"both and code signing", raw(false, ekuValue(oidServerAuth, oidClientAuth, oidCodeSigning)), "other than serverAuth and clientAuth"},
		{"the identifier of the extension itself", raw(false, ekuValue(oidExtKeyUsage)), "other than serverAuth and clientAuth"},
		{"an identifier that begins like serverAuth", raw(false, ekuValue(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1, 1})), "other than serverAuth and clientAuth"},
		{"an identifier that is serverAuth cut short", raw(false, ekuValue(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3})), "other than serverAuth and clientAuth"},
		// A purpose twice.
		{"serverAuth twice", raw(false, ekuValue(oidServerAuth, oidServerAuth)), "names a purpose twice"},
		{"clientAuth twice", raw(false, ekuValue(oidClientAuth, oidClientAuth)), "names a purpose twice"},
		{"serverAuth, clientAuth, serverAuth", raw(false, ekuValue(oidServerAuth, oidClientAuth, oidServerAuth)), "names a purpose twice"},
		{"clientAuth, serverAuth, clientAuth", raw(false, ekuValue(oidClientAuth, oidServerAuth, oidClientAuth)), "names a purpose twice"},
		{"serverAuth, clientAuth, serverAuth, clientAuth", raw(false, ekuValue(oidServerAuth, oidClientAuth, oidServerAuth, oidClientAuth)), "names a purpose twice"},
		{"a purpose twice and another purpose: the other is told first", raw(false, ekuValue(oidServerAuth, oidServerAuth, oidCodeSigning)), "names a purpose twice"},
		// An empty list and a list that is not a list of identifiers.
		{"an empty list", raw(false, derList()), "not a non-empty list of object identifiers"},
		{"empty bytes", raw(false, nil), "not a non-empty list of object identifiers"},
		{"a set of identifiers", raw(false, tlv(0x31, oidDER(oidServerAuth))), "not a non-empty list of object identifiers"},
		{"an octet string", raw(false, tlv(0x04, oidDER(oidServerAuth))), "not a non-empty list of object identifiers"},
		{"one identifier, not in a list", raw(false, oidDER(oidServerAuth)), "not a non-empty list of object identifiers"},
		{"a list of an integer", raw(false, derList(tlv(0x02, []byte{1}))), "not a non-empty list of object identifiers"},
		{"a list of an identifier and an integer", raw(false, derList(oidDER(oidServerAuth), tlv(0x02, []byte{1}))), "not a non-empty list of object identifiers"},
		{"a list of a string", raw(false, derList(tlv(0x0c, []byte("serverAuth")))), "not a non-empty list of object identifiers"},
		{"a list of a null", raw(false, derList(tlv(0x05))), "not a non-empty list of object identifiers"},
		{"a list that has a byte after it", raw(false, append(ekuValue(oidServerAuth), 0)), "not a non-empty list of object identifiers"},
		{"a list that has a second list after it", raw(false, append(ekuValue(oidServerAuth), ekuValue(oidClientAuth)...)), "not a non-empty list of object identifiers"},
		{"a list cut short", raw(false, ekuValue(oidServerAuth, oidClientAuth)[:10]), "not a non-empty list of object identifiers"},
		{"a list of indefinite length", raw(false, append([]byte{0x30, 0x80}, append(oidDER(oidServerAuth), 0, 0)...)), "not a non-empty list of object identifiers"},
		{"a list of a long-form length that a short form holds", raw(false, append([]byte{0x30, 0x81, byte(len(oidDER(oidServerAuth)))}, oidDER(oidServerAuth)...)), "not a non-empty list of object identifiers"},
		{"a list with a length of two octets that one holds", raw(false, append([]byte{0x30, 0x82, 0x00, byte(len(oidDER(oidServerAuth)))}, oidDER(oidServerAuth)...)), "not a non-empty list of object identifiers"},
		{"an identifier with a leading zero arc octet", raw(false, derList([]byte{0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x80, 0x01})), "not a non-empty list of object identifiers"},
		{"an identifier of no octet", raw(false, derList([]byte{0x06, 0x00})), "not a non-empty list of object identifiers"},
		{"an identifier that is a constructed object identifier", raw(false, derList(append([]byte{0x26, byte(len(oidDER(oidServerAuth)) - 2)}, oidDER(oidServerAuth)[2:]...))), "not a non-empty list of object identifiers"},
		{"a list that is context-specific", raw(false, append([]byte{0xb0}, ekuValue(oidServerAuth)[1:]...)), "not a non-empty list of object identifiers"},
		{"a primitive list", raw(false, append([]byte{0x10}, ekuValue(oidServerAuth)[1:]...)), "not a non-empty list of object identifiers"},
		// The extension twice.
		{"two extended key usages, both good", []pkix.Extension{extExtKeyUsage(false, oidServerAuth), extExtKeyUsage(false, oidClientAuth)}, "2.5.29.37 twice"},
		{"two equal extended key usages", []pkix.Extension{extExtKeyUsage(false, oidServerAuth), extExtKeyUsage(false, oidServerAuth)}, "2.5.29.37 twice"},
		{"a good one and a critical one", []pkix.Extension{extExtKeyUsage(false, oidServerAuth), extExtKeyUsage(true, oidServerAuth)}, "2.5.29.37 twice"},
	}
	for _, r := range rows {
		for _, at := range []int{0, 3} {
			t.Run(r.name+" at place "+string(rune('0'+at)), func(t *testing.T) {
				csr := ekuRequest(t, r.exts, at)
				der := csr.DER()
				req, err := pki.ParseRequest(der)
				refusedSaying(t, err, pki.ErrRequest, r.words)
				if got := pki.CheckOf(err); got != pki.CheckPolicy {
					t.Errorf("check %q, want policy", got)
				}
				assertRefusedForContent(t, req, der)
				// IntermediateTBS reads the same bytes: the same refusal, and no body.
				p := root.interParams(csr)
				p.CSR = der
				tbs, err := pki.IntermediateTBS(p)
				refusedSaying(t, err, pki.ErrRequest, r.words)
				if got := pki.CheckOf(err); got != pki.CheckPolicy {
					t.Errorf("IntermediateTBS: check %q, want policy", got)
				}
				if tbs != nil {
					t.Error("a body came with the error")
				}
			})
		}
	}
}
