package pki_test

import (
	"testing"
	"time"

	"crypto/x509/pkix"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// The invariant of the builders is that the standard library reads what they return. A relying party
// need not be Go: OpenSSL reads the name constraints differently, and refuses three forms that Go
// reads ("invalid certificate" while OpenSSL caches the extensions). A body that OpenSSL cannot read
// is no better than one that Go cannot, so a builder should either refuse these or OpenSSL should
// accept what is returned. The rows below fail while a builder returns a body for them; the rows
// that OpenSSL accepts are the controls.
func TestAnIntermediateBodyIsReadByOpenSSLToo(t *testing.T) {
	root := buildRoot(t, nil)
	at := ceremony.Add(24 * time.Hour)
	cases := []struct {
		name  string
		value []byte
		ok    bool // OpenSSL reads it
	}{
		{"a DNS name", ncValue([][]byte{ncSub(dns("example.org"))}, nil), true},
		{"an IP range", ncValue([][]byte{ncSub(tlv(0x87, make([]byte, 8)))}, nil), true},
		{"a registered ID", ncValue([][]byte{ncSub(tlv(0x88, []byte{0x2a}))}, nil), true},
		{"a general name of the tag 9", ncValue([][]byte{ncSub(tlv(0x89, []byte("x")))}, nil), false},
		{"a minimum of the wrong tag", ncValue([][]byte{ncSub(dns("example.org"), tlv(0x02, []byte{1}))}, nil), false},
		{"two general names in one subtree", ncValue([][]byte{ncSub(dns("example.org"), dns("example.com"))}, nil), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			csr := withExtensions(t, extBasicConstraints(), extKeyUsage(kuKeyCertSign), pkix.Extension{Id: oidNameConstraints, Critical: true, Value: c.value})
			tbs, err := intermediateTBS(t, root.interParams(csr))
			if err != nil {
				refused(t, err, pki.ErrRequest) // refusing it is right
				return
			}
			der, err := pki.Assemble(tbs, signatureOf(t, root.key, tbs), &root.key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifier.OpenSSLVerify(t, root.cert, der, at); err != nil {
				if c.ok {
					t.Errorf("the control is refused: %v", err)
				} else {
					t.Errorf("a body was returned that OpenSSL cannot read: %v", err)
				}
			}
		})
	}
}
