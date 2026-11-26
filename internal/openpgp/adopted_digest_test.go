package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// A kept certificate is read only against the SHA-256 that the caller holds. The digest, and not the
// fixpoint, is what says that nothing is missing: the tests below DOCUMENT that limit.

// qaDigestRefusal checks that a read with a digest that is not the certificate's is an ErrAdoptedCertificate
// that names the digest and not the packets.
func qaDigestRefusal(t testing.TB, what string, cert []byte, digest [32]byte) {
	t.Helper()
	k, err := openpgp.ReadForeignCertificate(cert, digest)
	if k != nil || !errors.Is(err, openpgp.ErrAdoptedCertificate) || !errors.Is(err, openpgp.ErrForeignKey) {
		t.Errorf("%s: %v (key %v)", what, err, k != nil)
		return
	}
	if !strings.Contains(err.Error(), "SHA-256") || strings.Contains(err.Error(), "would write another") {
		t.Errorf("%s: the refusal is not the one of the digest: %v", what, err)
	}
}

// A wrong digest is refused before anything is parsed: a body that the parser would refuse for another reason,
// or that would cost it a long time, is refused for the digest, at the price of one hash.
func TestQAWrongDigestIsRefusedBeforeAnyParsing(t *testing.T) {
	b := fkNamed(t, "ed25519")
	ps := fkSplit(t, fkRead(t, b.plain).Certificate())
	var wrong [32]byte
	wrong[0] = 1

	// a body that the parser refuses by name, for each name that only the parser can give
	many := append(fkJoin(ps[:2]...), bytes.Repeat(fkJoin(ps[2]), openpgp.MaxForeignPackets)...)
	for name, body := range map[string][]byte{
		"more packets than the limit":       many,
		"a secret key packet":               b.plain,
		"garbage":                           bytes.Repeat([]byte{0xAA}, 4096),
		"a packet that runs past the end":   {0xC6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		"a trust packet before the primary": fkJoin(append([]fkPacket{{12, []byte{1}}}, ps...)...),
		"one byte":                          {1},
	} {
		qaDigestRefusal(t, name+" against a wrong digest", body, wrong)
		// with its own digest the same body is refused by the parser: not the digest
		_, err := openpgp.ReadForeignCertificate(body, sha256.Sum256(body))
		if err == nil || strings.Contains(err.Error(), "SHA-256 of the certificate") {
			t.Errorf("%s against its own digest: %v", name, err)
		}
	}
	// a certificate that costs the parser a quarter of a second (a photograph of the largest size with 255
	// distinct signatures, which hashes 510 MiB) costs a wrong digest one hash of 1 MiB
	if !testing.Short() {
		photo := qaPhoto(t, 3)
		head := fkTemplateHead(t, b.file(t, fkProt{}))
		sigs := []fkPacket{head[0], head[1], head[2], photo}
		for i := 0; i < 255; i++ {
			sigs = append(sigs, fkPacket{2, fkAttrSig(t, b, photo.Body, 1000+i)})
		}
		cert := fkRead(t, fkJoin(sigs...)).Certificate()
		start := time.Now()
		qaDigestRefusal(t, "a costly certificate against a wrong digest", cert, wrong)
		refused := time.Since(start)
		start = time.Now()
		if _, err := qaReadCert(cert); err != nil {
			t.Fatal(err)
		}
		read := time.Since(start)
		t.Logf("a certificate of %d bytes: refused for its digest in %v, read in %v", len(cert), refused.Round(time.Microsecond), read.Round(time.Millisecond))
		if refused > read/4 || refused > 100*time.Millisecond {
			t.Errorf("the wrong digest was refused after %v, the read takes %v: the parser ran", refused, read)
		}
	}
	// the two checks of length that come first need no parsing, and are not the digest's
	if _, err := openpgp.ReadForeignCertificate(nil, wrong); !errors.Is(err, openpgp.ErrForeignForm) {
		t.Errorf("an empty certificate against a wrong digest: %v", err)
	}
	if _, err := openpgp.ReadForeignCertificate(make([]byte, openpgp.MaxForeignKeyBytes+1), wrong); !errors.Is(err, openpgp.ErrForeignLimit) {
		t.Errorf("a certificate over the limit against a wrong digest: %v", err)
	}
	// the right digest of another certificate, of the same size, and the digest of the certificate with one bit changed
	cert := fkJoin(ps...)
	other := bytes.Clone(cert)
	other[len(other)-1] ^= 1
	qaDigestRefusal(t, "the digest of a certificate with a bit changed", cert, sha256.Sum256(other))
	qaDigestRefusal(t, "the digest of a prefix", cert, sha256.Sum256(cert[:len(cert)-1]))
	if k, err := openpgp.ReadForeignCertificate(cert, sha256.Sum256(cert)); err != nil || k == nil {
		t.Errorf("the certificate against its digest: %v", err)
	}
}

// The right digest is not enough: a certificate that the reader would not write is refused when its own
// digest is given, and by the parser.
func TestQARightDigestStillNeedsTheFixpoint(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		ps := fkSplit(t, fkRead(t, b.plain).Certificate())
		for name, bad := range map[string][]byte{
			"a trust packet":   fkJoin(qaIns(ps, 1, fkPacket{12, []byte{1}})...),
			"a duplicated one": fkJoin(qaIns(ps, 3, ps[2])...),
			"a cut one":        fkJoin(ps...)[:len(fkJoin(ps...))-1],
			"a bit changed":    append(fkJoin(ps...)[:len(fkJoin(ps...))-1], fkJoin(ps...)[len(fkJoin(ps...))-1]^1),
		} {
			k, err := openpgp.ReadForeignCertificate(bad, sha256.Sum256(bad))
			if k != nil || !errors.Is(err, openpgp.ErrForeignKey) {
				t.Errorf("%s with its own digest: %v", name, err)
			}
			if err != nil && strings.Contains(err.Error(), "SHA-256 of the certificate") {
				t.Errorf("%s: the refusal is the digest's: %v", name, err)
			}
		}
	})
}

// qaStripped makes the file of a key, reads its certificate, takes the packets that cut selects out of it and
// returns the whole certificate, the stripped one, and both as read against their own digests.
type qaStripCase struct {
	whole, short []byte
	k, ks        *openpgp.ForeignKey
}

func qaStrip(t testing.TB, b *fkBase, file []byte, cut func(i int, p fkPacket) bool) qaStripCase {
	t.Helper()
	k := fkRead(t, file)
	whole := k.Certificate()
	var kept []fkPacket
	taken := 0
	for i, p := range fkSplit(t, whole) {
		if cut(i, p) {
			taken++
			continue
		}
		kept = append(kept, p)
	}
	if taken != 1 {
		t.Fatalf("%d packets were taken out, want one", taken)
	}
	short := fkJoin(kept...)
	ks, err := qaReadCert(short)
	if err != nil {
		t.Fatalf("the certificate with a packet taken out is not read against its own digest: %v", err)
	}
	if !bytes.Equal(ks.Certificate(), short) {
		t.Fatal("the stripped certificate is not read as it stands")
	}
	// against the digest of the whole one it is refused: the digest, not the fixpoint, carries it
	qaDigestRefusal(t, "the stripped certificate against the digest of the whole one", short, sha256.Sum256(whole))
	if _, err := openpgp.ReadForeignCertificate(whole, sha256.Sum256(whole)); err != nil {
		t.Fatalf("the whole certificate: %v", err)
	}
	return qaStripCase{whole, short, k, ks}
}

// THE FIXPOINT DOES NOT CARRY FRESHNESS. A certificate with its newest self-signature taken out is a
// certificate that the reader would write: it is accepted when its own digest is given, with the older flags
// and the older end of the key. Only the digest of the whole certificate refuses it.
func TestQADocumentsThatOnlyTheDigestNotesAMissingNewestSelfSignature(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		me := b.primaryPair()
		cert := func(s fkSigSpec) []fkPacket { return fkSplit(t, b.certSig(t, me, me.pub, fkUser, s)) }
		head := fkTemplateHead(t, b.file(t, fkProt{}))
		ps := append([]fkPacket{head[0], head[1]}, cert(fkSigSpec{Typ: gpacket.SigTypePositiveCert, At: fkSigAt(1000), Flags: 1, KeyLife: 365 * 86400})...)
		ps = append(ps, cert(fkSigSpec{Typ: gpacket.SigTypePositiveCert, At: fkSigAt(2000), Flags: 3, KeyLife: 30 * 86400})...)
		// the certificate is the primary, the user ID and the two self-signatures in the order of the file
		c := qaStrip(t, b, fkJoin(ps...), func(i int, p fkPacket) bool { return i == 3 })
		whole, short := openpgp.SnapshotUsers(c.k)[0], openpgp.SnapshotUsers(c.ks)[0]
		if whole.Flags != 3 || !whole.Signed.Equal(fkAt(2000)) || !whole.Expires.Equal(fkEpoch.Add(30*86400*time.Second)) {
			t.Fatalf("the whole certificate: %+v", whole)
		}
		// the stripped one has the older choice, the older flags and a later end of the key: the key lives longer
		if short.Flags != 1 || !short.Signed.Equal(fkAt(1000)) || !short.Expires.Equal(fkEpoch.Add(365*86400*time.Second)) {
			t.Errorf("the certificate without its newest self-signature says %+v", short)
		}
		if !openpgp.SnapshotKey(c.ks).Expiry.Earliest.After(openpgp.SnapshotKey(c.k).Expiry.Earliest) {
			t.Error("the end of the key did not move later")
		}
		t.Logf("DOCUMENTED LIMIT: a certificate without its newest self-signature is a fixpoint (flags %d -> %d, end 30 days -> 365 days)", whole.Flags, short.Flags)
	})
}

// THE FIXPOINT DOES NOT CARRY A REVOCATION. A certificate with its key revocation taken out is accepted when
// its own digest is given, and an issuer is made of it, which signs. Only the digest of the whole certificate
// refuses it.
func TestQADocumentsThatOnlyTheDigestNotesAMissingKeyRevocation(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		me := b.primaryPair()
		head := fkTemplateHead(t, b.file(t, fkProt{}))
		rc := gpacket.KeyCompromised
		rev := fkSplit(t, b.keySig(t, me, me.pub, fkSigSpec{Typ: gpacket.SigTypeKeyRevocation, At: fkSigAt(1500), Reason: &rc}))
		file := fkJoin(append(append([]fkPacket{head[0]}, rev...), head[1:]...)...)
		c := qaStrip(t, b, file, func(i int, p fkPacket) bool { return i == 1 })
		if !c.k.Primary.Revoked || c.ks.Primary.Revoked {
			t.Fatalf("revoked: whole %v, stripped %v", c.k.Primary.Revoked, c.ks.Primary.Revoked)
		}
		std := fkStdSigner(t, b)
		if a, err := openpgp.NewAdoptedIssuer(c.k, std); a != nil || !errors.Is(err, openpgp.ErrParams) {
			t.Errorf("an issuer of the revoked key: %v", err)
		}
		a, err := openpgp.NewAdoptedIssuer(c.ks, std)
		if err != nil {
			t.Fatalf("an issuer of the key whose revocation was taken out: %v", err)
		}
		if _, err := openpgp.DirectKeySignatureFor(rand.Reader, a, fkEpoch.Add(time.Hour)); err != nil {
			t.Errorf("the key whose revocation was taken out does not sign: %v", err)
		}
		t.Log("DOCUMENTED LIMIT: a certificate without its key revocation is a fixpoint, and the key signs")
	})
}

// THE FIXPOINT DOES NOT CARRY A RETIREMENT. A certificate with the revocation of a user ID taken out has a
// live user ID again, and is accepted when its own digest is given.
func TestQADocumentsThatOnlyTheDigestNotesAMissingRetirement(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		me := b.primaryPair()
		head := fkTemplateHead(t, b.file(t, fkProt{}))
		other := "Second Person <second@example.org>"
		unvalid := gpacket.UserIDNotValid
		sig := func(uid string, s fkSigSpec) []fkPacket { return fkSplit(t, b.certSig(t, me, me.pub, uid, s)) }
		ps := []fkPacket{head[0], head[1], head[2], {13, []byte(other)}}
		ps = append(ps, sig(other, fkSigSpec{Typ: gpacket.SigTypePositiveCert, At: fkSigAt(1000)})...)
		retire := sig(other, fkSigSpec{Typ: gpacket.SigTypeCertificationRevocation, At: fkSigAt(1500), Reason: &unvalid})
		ps = append(ps, retire...)
		c := qaStrip(t, b, fkJoin(ps...), func(i int, p fkPacket) bool { return i == 5 })
		users := func(k *openpgp.ForeignKey) map[string]bool {
			out := map[string]bool{}
			for _, u := range openpgp.SnapshotUsers(k) {
				out[u.Text] = u.Revoked
			}
			return out
		}
		if got := users(c.k); !got[other] || got[fkUser] {
			t.Fatalf("the whole certificate: %v", got)
		}
		if got := users(c.ks); got[other] || len(got) != 2 {
			t.Errorf("the certificate without the retirement: %v", got)
		}
		t.Log("DOCUMENTED LIMIT: a certificate without the retirement of a user ID is a fixpoint, and the user ID is live")
	})
}

// A signer that keeps the slice that it answered and changes it from another goroutine as soon as it has
// answered. What is emitted is what was verified: every signature that comes back verifies, and the rest are
// refusals with no bytes. (The race detector would report the change itself: the test is for the build with
// no detector.)
func TestQASignerThatChangesItsAnswerAfterReturningIsNeverBelieved(t *testing.T) {
	if qaRaceEnabled {
		t.Skip("the signer changes the slice that it returned while the step copies it: a race by construction")
	}
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		m := qaNew(t, b)
		std := fkStdSigner(t, b)
		k := fkRead(t, b.plain)
		stop := make(chan struct{})
		done := make(chan struct{})
		kept := make(chan []byte, 1)
		go func() {
			defer close(done)
			var cur []byte
			for {
				select {
				case <-stop:
					return
				case s := <-kept:
					cur = s
				default:
				}
				// flip a bit of the last byte, back and forth, as fast as it goes
				if n := len(cur); n > 0 {
					cur[n-1] ^= 1
					cur[n/2] ^= 1
				}
			}
		}()
		a, err := openpgp.NewAdoptedIssuer(k, fkSigner{pub: std.Public, sign: func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
			s, err := std.Sign(r, d, o)
			select {
			case kept <- s:
			default:
			}
			return s, err
		}})
		if err != nil {
			t.Fatal(err)
		}
		made, refused := 0, 0
		rounds := 4000
		if b.name == "rsa4096" {
			rounds = 300
		}
		for i := 0; i < rounds; i++ {
			at := fkEpoch.Add(time.Hour + time.Duration(i)*time.Second)
			sig, err := openpgp.DetachedSignatureFor(rand.Reader, a, at, []byte("m"))
			if err != nil {
				if len(sig) != 0 || !errors.Is(err, openpgp.ErrSignature) {
					t.Fatalf("a refusal with %d bytes: %v", len(sig), err)
				}
				refused++
				continue
			}
			made++
			m.check(t, sig, 0x00, at, []byte("m"))
			if t.Failed() {
				break
			}
		}
		close(stop)
		<-done
		t.Logf("%s: %d signatures, all verified; %d refused while the signer scribbled", b.name, made, refused)
	})
}
