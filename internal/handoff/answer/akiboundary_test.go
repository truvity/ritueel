package answer_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"testing"

	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/pki"
)

// rawKeyIDAKI is an authority key identifier whose key identifier is written WITHOUT its own field header:
// the twenty bytes stand straight in the sequence, in front of the issuer name and a serial. A reader that
// takes the first byte as a context tag [0] reads the second byte as a length, and what that length does
// decides whether the whole certificate can be read. The bytes of a real key identifier are random, so the
// cases below fix them.
func rawKeyIDAKI(k *memKit, raw []byte) pkix.Extension {
	return pkix.Extension{Id: oidAKI, Value: tlv(0x30, raw, tlv(0xa1, tlv(0xa4, k.a.cert.RawSubject)), tlv(0x82, []byte{1}))}
}

// akiWithIssuerName is the value of an authority key identifier that has the key identifier of the page in
// its own field (80 14 <20 bytes>), then the issuer name and a serial. The field is written whole, never cut
// out of another value, so that no byte of the key identifier can be read as the start of a field.
func akiWithIssuerName(t testing.TB, k *memKit) []byte {
	t.Helper()
	id, err := pki.KeyIdentifier(&k.a.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return tlv(0x30, tlv(0x80, id), tlv(0xa1, tlv(0xa4, k.a.cert.RawSubject)), tlv(0x82, []byte{1}))
}

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// An extension that the standard reader cannot read makes the certificate file one that holds no certificate
// (a malformed answer), and one that it can read but that is not the form of the page is a refusal of the
// form. Which of the two comes out depends on the bytes alone, never on luck: these cases fix the bytes.
func TestAnAuthorityKeyIdentifierThatIsNotTheFormOfThePageIsRefusedWhateverItsBytes(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	csr := newCSR(t, nil, nil)
	check := func(t *testing.T, ext pkix.Extension) (answer.Verdict, error) {
		t.Helper()
		x := k.newX509(csr)
		x.spec = certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
			e[5] = ext
			return e
		})}
		return x.check(chk)
	}

	// The four key identifiers that made the certificate unreadable in a run of the test of the form of the
	// page: the first byte is 0x80 and the second is a length that does not fit in the rest of the extension.
	for _, c := range []struct{ name, id string }{
		{"80 74", "8074" + "13e118926fd55fb12095f4653da6a94eb87e"},
		{"80 9b", "809b" + "81b2e1af0dbd42dc69b97dd7d2396848a8af"},
		{"80 85", "8085" + "4715f06999ff820deae04a0d246be82d44ef"},
		{"80 c2", "80c2" + "e560bda2a31d7a5bba3d4f6ef8f89883e652"},
	} {
		t.Run("the key identifier that begins "+c.name+" cannot be read as a certificate", func(t *testing.T) {
			v, err := check(t, rawKeyIDAKI(k, fromHex(t, c.id)))
			want(t, v, err, answer.CodeMalformed, malformedAt2)
		})
	}

	// The second byte of a field that begins 0x80 is a length: a length that fits is read and the form is
	// refused; a length that does not fit is a certificate that cannot be read. The boundary is the length of
	// what is left in the extension.
	fill := func(first, second byte) []byte {
		b := make([]byte, 20)
		for i := range b {
			b[i] = 0x11
		}
		b[0], b[1] = first, second
		return b
	}
	for _, c := range []struct {
		second byte
		code   answer.Code
		status string
	}{
		{0x00, answer.CodeProfile, st8},
		{0x14, answer.CodeProfile, st8},
		{0x7f, answer.CodeMalformed, malformedAt2}, // a length of 127 and a rest of fewer bytes
		{0x80, answer.CodeMalformed, malformedAt2}, // a long form with no length bytes that fit
		{0x81, answer.CodeMalformed, malformedAt2},
		{0xff, answer.CodeMalformed, malformedAt2},
	} {
		t.Run(fmt.Sprintf("80 %02x as the first two bytes", c.second), func(t *testing.T) {
			v, err := check(t, rawKeyIDAKI(k, fill(0x80, c.second)))
			want(t, v, err, c.code, c.status)
		})
	}

	// Any other first byte is not the tag that the reader looks for: it reads no key identifier, and the form
	// of the page is refused. The sweep covers every value of the first byte, with the second byte large.
	t.Run("every first byte except 0x80 is refused by the form", func(t *testing.T) {
		for first := 0; first < 256; first++ {
			if first == 0x80 {
				continue
			}
			v, err := check(t, rawKeyIDAKI(k, fill(byte(first), 0xff)))
			want(t, v, err, answer.CodeProfile, st8)
		}
	})

	// The key identifier of the page, with its own field header, followed by the issuer name and a serial,
	// whatever the first bytes of the key identifier are: the form is refused and the file is readable.
	t.Run("the field written whole is readable whatever the key identifier", func(t *testing.T) {
		for first := 0; first < 256; first++ {
			id := fill(byte(first), 0xff)
			ext := pkix.Extension{Id: oidAKI, Value: tlv(0x30, tlv(0x80, id), tlv(0xa1, tlv(0xa4, k.a.cert.RawSubject)), tlv(0x82, []byte{1}))}
			v, err := check(t, ext)
			want(t, v, err, answer.CodeProfile, st8)
		}
	})
}

// The certificate of the case "an authority key identifier that adds the issuer name" in the test of the form
// is what its name says: it is readable, its key identifier is the one of the issuing root, and the extension
// holds the issuer name and the serial after it. The refusal of the form cannot show this (its words are one
// fixed text), so it is held here, on the bytes.
func TestTheCertificateOfTheFormTestThatAddsTheIssuerNameIsReadable(t *testing.T) {
	k := newKit(t)
	csr := newCSR(t, nil, nil)
	id, err := pki.KeyIdentifier(&k.a.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	value := akiWithIssuerName(t, k)
	x := k.newX509(csr)
	x.spec = certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
		e[5] = pkix.Extension{Id: oidAKI, Value: value}
		return e
	})}
	cert, err := x509.ParseCertificate(x.certDER())
	if err != nil {
		t.Fatalf("the certificate cannot be read: %v", err)
	}
	if !bytes.Equal(cert.AuthorityKeyId, id) {
		t.Fatalf("the key identifier is %x, want %x", cert.AuthorityKeyId, id)
	}
	if len(id) != 20 {
		t.Fatalf("the key identifier is %d bytes, the page says 160 bits", len(id))
	}
	var found bool
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidAKI) {
			found = true
			if !bytes.Equal(e.Value, value) {
				t.Fatalf("the extension is %x, want %x", e.Value, value)
			}
			if !bytes.HasSuffix(e.Value, []byte{0x82, 0x01, 0x01}) {
				t.Fatal("the extension does not end with the serial 1")
			}
			if !bytes.Contains(e.Value, k.a.cert.RawSubject) {
				t.Fatal("the extension does not hold the issuer name")
			}
		}
	}
	if !found {
		t.Fatal("no authority key identifier")
	}
}
