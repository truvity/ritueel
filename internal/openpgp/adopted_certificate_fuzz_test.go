package openpgp_test

import (
	"bytes"
	"errors"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"

	"ritueel.id/ritueel/internal/openpgp"
)

// FuzzReadForeignCertificate: whatever the input, the reader does not panic (it recovers one and says so in
// the text, which is a failure here), does not change its input, gives a refusal or a key and never both,
// and a certificate that it accepts is the input, byte for byte, is read by go-crypto as one entity of the
// same fingerprint, passes the property of a certificate (every signature verifies, whole packets in
// order) and gives the same snapshot when it is read again. The seeds are made at run time: the
// certificates of the kit and the certificates that the refusal table changes.
func FuzzReadForeignCertificate(f *testing.F) {
	seen := map[string]bool{}
	add := func(b []byte) {
		if !seen[string(b)] {
			seen[string(b)] = true
			f.Add(b)
		}
	}
	for _, b := range fkBases(f) {
		cert := fkRead(f, b.plain).Certificate()
		add(cert)
		add(fkRead(f, fkRichOf(f, b, false, true).file).Certificate())
		if b.name != "rsa4096" {
			add(fkRead(f, fkRichOf(f, b, false, false).file).Certificate())
		}
		for _, c := range qaCases(f, b, fkSplit(f, cert), 61) {
			add(c.cert)
		}
	}
	for _, e := range qaExports(f) {
		if k, err := openpgp.ReadForeignKey(e.file); err == nil {
			add(k.Certificate())
		}
	}
	add(nil)
	add([]byte{0xC6, 0x00})
	f.Fuzz(func(t *testing.T, in []byte) {
		before := bytes.Clone(in)
		k, err := qaReadCert(in)
		if !bytes.Equal(in, before) {
			t.Fatal("ReadForeignCertificate changed its input")
		}
		if err != nil {
			if k != nil {
				t.Fatalf("a key is returned with the error %v", err)
			}
			if !errors.Is(err, openpgp.ErrForeignKey) {
				t.Fatalf("an error that is not an ErrForeignKey: %v", err)
			}
			fkPlainText(t, err)
			return
		}
		if k == nil {
			t.Fatal("no key and no error")
		}
		if !bytes.Equal(k.Certificate(), in) {
			t.Fatal("an accepted certificate is not the input")
		}
		ents, err := pgp.ReadKeyRing(bytes.NewReader(in))
		if err != nil || len(ents) != 1 || hexOf(ents[0].PrimaryKey.Fingerprint) != k.Primary.Fingerprint {
			t.Fatalf("go-crypto does not read an accepted certificate as one entity of the key: %v", err)
		}
		_ = fkCertProperty(t, "the accepted certificate", k)
		k2, err := qaReadCert(k.Certificate())
		if err != nil || !qaSnapshotEqual(k, k2) {
			t.Fatalf("an accepted certificate is not read again as itself: %v", err)
		}
		if s, err := k.OpenSecret(nil); s != nil || !errors.Is(err, openpgp.ErrParams) {
			t.Fatalf("OpenSecret of a certificate: %v", err)
		}
		if k.Primary.Secret != 0 || k.Primary.Cipher != "" || k.OtherKeySignatures != 0 || k.DuplicatesDropped != 0 {
			t.Fatalf("a certificate has the counts of an export: %+v", k.Primary)
		}
	})
}
