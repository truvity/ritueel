package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"slices"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/verifier"
)

// The measurement of the foundation of the signing by an adopted key: gpgv and sqv, which did not build
// the packets, are asked whether they accept a signature with SHA-384 by an RSA key of 4096 bits, by a
// version 4 Ed25519 key (EdDSA legacy, algorithm 22) and by a P-384 key, which is the control. The
// signature is made by the one signing step of the package, through an AdoptedIssuer over the kit's
// keys. The result of each tool is logged for each key; the tests fail when a tool that is present
// refuses, and skip when it is missing (RITUEEL_REQUIRE_TOOLS=1 makes a missing tool fail).

// fkAdopted opens the secret of a template and makes the issuer of it, wiped when the test ends.
func fkAdopted(t testing.TB, b *fkBase) (*openpgp.ForeignKey, *openpgp.AdoptedIssuer) {
	t.Helper()
	k := fkRead(t, b.plain)
	sec, err := k.OpenSecret(nil)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	t.Cleanup(sec.Wipe)
	a, err := openpgp.NewAdoptedIssuer(k, sec.Signer())
	if err != nil {
		t.Fatalf("NewAdoptedIssuer: %v", err)
	}
	return k, a
}

// fkWithKeySig puts a signature packet after the primary packet of a certificate, where a signature of the
// key itself stands.
func fkWithKeySig(t testing.TB, cert, sig []byte) []byte {
	t.Helper()
	ps := fkSplit(t, cert)
	return slices.Concat(fkJoin(ps[0]), sig, fkJoin(ps[1:]...))
}

func TestMeasureSHA384ByGpgvAndSqvForEveryAlgorithmOfTheKit(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k, a := fkAdopted(t, b)
		dksAt, msgAt := fkEpoch.Add(24*time.Hour), fkEpoch.Add(48*time.Hour)
		dks, err := openpgp.DirectKeySignatureFor(rand.Reader, a, dksAt)
		if err != nil {
			t.Fatalf("direct-key signature: %v", err)
		}
		msg := []byte("the release of example.org version 1.2.3\n")
		sig, err := openpgp.DetachedSignatureFor(rand.Reader, a, msgAt, msg)
		if err != nil {
			t.Fatalf("detached signature: %v", err)
		}
		ring := fkWithKeySig(t, k.Certificate(), dks)
		fp := k.Primary.Fingerprint

		// go-crypto, the second reader: the direct-key signature and the detached signature verify, and
		// both are SHA-384 with the algorithm of the key.
		ents, err := pgp.ReadKeyRing(bytes.NewReader(ring))
		if err != nil || len(ents) != 1 {
			t.Fatalf("go-crypto does not read the certificate with the signature: %v", err)
		}
		for _, c := range []struct {
			what string
			pkt  []byte
			typ  gpacket.SignatureType
		}{{"direct-key", dks, gpacket.SigTypeDirectSignature}, {"detached", sig, gpacket.SigTypeBinary}} {
			p, err := gpacket.Read(bytes.NewReader(c.pkt))
			if err != nil {
				t.Fatalf("go-crypto does not read the %s signature: %v", c.what, err)
			}
			s, ok := p.(*gpacket.Signature)
			if !ok || s.SigType != c.typ || s.Hash != crypto.SHA384 || s.PubKeyAlgo != ents[0].PrimaryKey.PubKeyAlgo || s.Version != 4 {
				t.Fatalf("the %s signature is not a version 4 SHA-384 signature of the type asked: %+v", c.what, s)
			}
		}
		p, _ := gpacket.Read(bytes.NewReader(dks))
		if err := ents[0].PrimaryKey.VerifyDirectKeySignature(p.(*gpacket.Signature)); err != nil {
			t.Errorf("go-crypto does not verify the direct-key signature: %v", err)
		}
		if _, err := pgp.CheckDetachedSignature(ents, bytes.NewReader(msg), bytes.NewReader(sig), nil); err != nil {
			t.Errorf("go-crypto does not verify the detached signature: %v", err)
		}
		// the reader reads what the step signed: the certificate with the direct-key signature is a
		// certificate that it writes again as it stands, and the signature is the newest of the key
		kr, err := openpgp.ReadForeignCertificate(ring)
		if err != nil {
			t.Fatalf("ReadForeignCertificate of the certificate with the direct-key signature: %v", err)
		}
		if got := openpgp.SnapshotNewest(kr); !got.Equal(dksAt) {
			t.Errorf("the newest signature of the snapshot is %v, want the direct-key signature at %v", got, dksAt)
		}

		// the tools
		gpgvErr := verifier.GPGVVerify(t, ring, sig, msg, fp)
		t.Logf("MEASURE gpgv %s SHA-384: accepted=%v err=%v", b.name, gpgvErr == nil, gpgvErr)
		if gpgvErr != nil {
			t.Errorf("gpgv refuses SHA-384 with %s: %v", b.name, gpgvErr)
		}
		sqvErr := verifier.SQVVerify(t, ring, sig, msg, fp, msgAt.Add(time.Hour))
		t.Logf("MEASURE sqv %s SHA-384: accepted=%v err=%v", b.name, sqvErr == nil, sqvErr)
		if sqvErr != nil {
			t.Errorf("sqv refuses SHA-384 with %s: %v", b.name, sqvErr)
		}

		// the control: a signature with one bit of its value changed is refused by both, so the
		// acceptances above are not the setup accepting anything
		bad := bytes.Clone(sig)
		bad[len(bad)-1] ^= 1
		if err := verifier.GPGVVerify(t, ring, bad, msg, fp); err == nil {
			t.Errorf("gpgv accepts a signature of %s with a changed value", b.name)
		}
		if err := verifier.SQVVerify(t, ring, bad, msg, fp, msgAt.Add(time.Hour)); err == nil {
			t.Errorf("sqv accepts a signature of %s with a changed value", b.name)
		}
	})
}

// fkValueLengths reads the lengths in bytes of the numbers that a signature packet ends with, after its
// two areas and its hash tag.
func fkValueLengths(t testing.TB, pkt []byte) []int {
	t.Helper()
	body := fkSplit(t, pkt)[0].Body
	hl := int(body[4])<<8 | int(body[5])
	ul := int(body[6+hl])<<8 | int(body[7+hl])
	rest := body[8+hl+ul+2:]
	var out []int
	for len(rest) > 0 {
		n := (int(rest[0])<<8 | int(rest[1]) + 7) / 8
		out = append(out, n)
		rest = rest[2+n:]
	}
	return out
}

// An Ed25519 signature has two numbers of 32 bytes, and one of them has a leading zero byte about once in
// 128 signatures: the standard writes it without the zero byte, and a reader pads it. The tools are asked
// for a signature of each kind (R short, S short), so that this is not left to chance.
func TestEd25519SignatureWithAShortValueIsAcceptedByEveryReader(t *testing.T) {
	b := fkNamed(t, "ed25519")
	k, a := fkAdopted(t, b)
	fp := k.Primary.Fingerprint
	msg := []byte("the release of example.org version 1.2.3\n")
	found := map[int][]byte{} // 0: R short, 1: S short
	foundAt := map[int]time.Time{}
	for i := 0; i < 20000 && len(found) < 2; i++ {
		at := fkEpoch.Add(time.Hour + time.Duration(i)*time.Second)
		sig, err := openpgp.DetachedSignatureFor(rand.Reader, a, at, msg)
		if err != nil {
			t.Fatal(err)
		}
		for j, n := range fkValueLengths(t, sig) {
			if n < 32 && found[j] == nil {
				found[j], foundAt[j] = sig, at
			}
		}
	}
	if len(found) < 2 {
		t.Fatalf("no signature with a short R and none with a short S in 20000 tries: %v", found)
	}
	ents, err := pgp.ReadKeyRing(bytes.NewReader(k.Certificate()))
	if err != nil {
		t.Fatal(err)
	}
	for j, name := range []string{"R", "S"} {
		sig, at := found[j], foundAt[j]
		t.Run("short "+name, func(t *testing.T) {
			if _, err := pgp.CheckDetachedSignature(ents, bytes.NewReader(msg), bytes.NewReader(sig), nil); err != nil {
				t.Errorf("go-crypto: %v", err)
			}
			gpgvErr := verifier.GPGVVerify(t, k.Certificate(), sig, msg, fp)
			t.Logf("MEASURE gpgv ed25519 short %s: accepted=%v err=%v", name, gpgvErr == nil, gpgvErr)
			if gpgvErr != nil {
				t.Errorf("gpgv: %v", gpgvErr)
			}
			sqvErr := verifier.SQVVerify(t, k.Certificate(), sig, msg, fp, at.Add(time.Hour))
			t.Logf("MEASURE sqv ed25519 short %s: accepted=%v err=%v", name, sqvErr == nil, sqvErr)
			if sqvErr != nil {
				t.Errorf("sqv: %v", sqvErr)
			}
		})
	}
}
