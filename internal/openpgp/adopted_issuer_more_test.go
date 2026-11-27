package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The refusals of NewAdoptedIssuer that the first tests leave: a signer whose public key is the key of the
// primary in all but one number, the zero values of the standard library's keys, a key whose primary is
// revoked, read from a certificate as well as from an export, and a wiped signer; and what it accepts.

func TestQANewAdoptedIssuerRefusesAKeyThatIsNearlyTheKey(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, b.plain)
		cert, err := qaReadCert(k.Certificate())
		if err != nil {
			t.Fatal(err)
		}
		std := fkStdSigner(t, b)
		refused := func(what string, s crypto.Signer) {
			t.Helper()
			for door, key := range map[string]*openpgp.ForeignKey{"export": k, "certificate": cert} {
				a, err := openpgp.NewAdoptedIssuer(key, s)
				if a != nil || err == nil || !errors.Is(err, openpgp.ErrParams) {
					t.Errorf("%s (%s): an issuer (%v) or the wrong error: %v", what, door, a != nil, err)
					continue
				}
				fkCheckText(t, what, err, b)
			}
		}
		withPublic := func(p crypto.PublicKey) crypto.Signer {
			return fkSigner{pub: func() crypto.PublicKey { return p }, sign: std.Sign}
		}
		switch pub := std.Public().(type) {
		case *rsa.PublicKey:
			refused("the same modulus with the exponent 3", withPublic(&rsa.PublicKey{N: new(big.Int).Set(pub.N), E: 3}))
			refused("the same modulus with the exponent 17", withPublic(&rsa.PublicKey{N: new(big.Int).Set(pub.N), E: 17}))
			refused("the same modulus with the exponent 65539", withPublic(&rsa.PublicKey{N: new(big.Int).Set(pub.N), E: pub.E + 2}))
			refused("the modulus plus two", withPublic(&rsa.PublicKey{N: new(big.Int).Add(pub.N, big.NewInt(2)), E: pub.E}))
			refused("the modulus with its last bit changed", withPublic(&rsa.PublicKey{N: new(big.Int).Xor(pub.N, big.NewInt(2)), E: pub.E}))
			refused("the key as a value, not a pointer", withPublic(*pub))
			refused("a modulus that is nil", withPublic(&rsa.PublicKey{E: pub.E}))
			refused("the zero key of the standard library", &rsa.PrivateKey{})
		case ed25519.PublicKey:
			flipped := bytes.Clone(pub)
			flipped[31] ^= 1
			refused("the key with one bit changed", withPublic(ed25519.PublicKey(flipped)))
			refused("the key with a byte less", withPublic(pub[:31]))
			refused("the key as a pointer", withPublic(&pub))
			refused("a key with nothing in it", ed25519.PrivateKey(nil))
			refused("a key too short to have a public part", ed25519.PrivateKey{1, 2, 3})
		case *ecdsa.PublicKey:
			other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			refused("another point of the curve", withPublic(&other.PublicKey))
			refused("the point with Y changed", withPublic(&ecdsa.PublicKey{Curve: pub.Curve, X: pub.X, Y: new(big.Int).Add(pub.Y, big.NewInt(1))})) //nolint:staticcheck // the test makes a point that is not on the curve: the raw coordinates are the only way
			refused("the point with Y swapped for X", withPublic(&ecdsa.PublicKey{Curve: pub.Curve, X: pub.X, Y: pub.X}))                            //nolint:staticcheck // the test makes a point that is not on the curve: the raw coordinates are the only way
			refused("the point of the other curve", withPublic(func() crypto.PublicKey {
				k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &k.PublicKey
			}()))
			refused("the point with no Y", withPublic(&ecdsa.PublicKey{Curve: pub.Curve, X: pub.X})) //nolint:staticcheck // the test makes a point that is not on the curve: the raw coordinates are the only way
			refused("the zero key of the standard library", &ecdsa.PrivateKey{})
			refused("a key of ECDH", withPublic(func() crypto.PublicKey {
				k, _ := ecdh.P384().GenerateKey(rand.Reader)
				return k.PublicKey()
			}()))
		}
		// a ForeignSigner of another key of the same algorithm
		if b.name != "rsa4096" {
			other := fkOtherForeignSigner(t, b)
			defer other.Wipe()
			refused("the signer of the reader for another key", other.Signer())
		}
	})
}

var (
	qaSecondMu    sync.Mutex
	qaSecondBases = map[string]*fkBase{}
)

// fkOtherForeignSigner is the secret of a second key of the same algorithm as the template, made once for the
// test binary.
func fkOtherForeignSigner(t testing.TB, b *fkBase) *openpgp.ForeignSecret {
	t.Helper()
	qaSecondMu.Lock()
	nb := qaSecondBases[b.name]
	if nb == nil {
		var err error
		switch b.name {
		case "ed25519":
			nb, err = fkNewBase("ed25519", b.want, b.str, gpacket.PubKeyAlgoEdDSA, gpacket.Curve25519, 0)
		case "p384":
			nb, err = fkNewBase("p384", b.want, b.str, gpacket.PubKeyAlgoECDSA, gpacket.CurveNistP384, 0)
		default:
			err = errors.New("no second key of this algorithm")
		}
		if err != nil {
			qaSecondMu.Unlock()
			t.Fatal(err)
		}
		qaSecondBases[b.name] = nb
	}
	qaSecondMu.Unlock()
	sec, err := fkRead(t, nb.plain).OpenSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	return sec
}

// A revoked primary is refused, whichever way the key was read, and the revocation that the view shows is
// not what decides: a soft one (retired) or a hard one makes the same refusal, and a revocation by another
// key does not.
func TestQANewAdoptedIssuerRefusesARevokedPrimaryFromAnExportAndFromACertificate(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	std := fkStdSigner(t, b)
	for _, reason := range []byte{0, 1, 2, 3} {
		file := qaFile(t, b, [][]byte{qaKeySig(t, w, 0x20, 8, 1500, fkReasonSub(reason))}, qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 1000)}})
		for door, key := range map[string]func() *openpgp.ForeignKey{
			"export": func() *openpgp.ForeignKey { return fkRead(t, file) },
			"certificate": func() *openpgp.ForeignKey {
				c, err := qaReadCert(fkRead(t, file).Certificate())
				if err != nil {
					t.Fatal(err)
				}
				return c
			},
		} {
			k := key()
			if !k.Primary.Revoked || !openpgp.SnapshotKey(k).Revoked {
				t.Fatalf("reason %d, %s: the key is not revoked", reason, door)
			}
			a, err := openpgp.NewAdoptedIssuer(k, std)
			if a != nil || !errors.Is(err, openpgp.ErrParams) {
				t.Errorf("reason %d, %s: an issuer of a revoked key: %v", reason, door, err)
			}
			fkCheckText(t, "revoked", err, b)
		}
	}
	// a SHA-1 revocation that verifies revokes; one by another key does not
	_, _, other := fkDonors(t)
	rev := b.keySig(t, other, b.ent.PrimaryKey, fkSigSpec{Typ: 0x20})
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	file := fkJoin(append(append([]fkPacket{head[0]}, fkSplit(t, rev)...), head[1:]...)...)
	k := fkRead(t, file)
	if k.Primary.Revoked {
		t.Fatal("a revocation by another key revokes")
	}
	if _, err := openpgp.NewAdoptedIssuer(k, std); err != nil {
		t.Errorf("a key that another key says is revoked: %v", err)
	}
}

// The signer of the reader is refused once it is wiped, whatever was made from it before, and a wipe of the
// key (not of the secret) leaves the snapshot, and so the issuer, as it was.
func TestQANewAdoptedIssuerAfterAWipe(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, b.plain)
		sec, err := k.OpenSecret(nil)
		if err != nil {
			t.Fatal(err)
		}
		signer := sec.Signer()
		a, err := openpgp.NewAdoptedIssuer(k, signer)
		if err != nil {
			t.Fatal(err)
		}
		k.Wipe()
		if _, err := openpgp.DirectKeySignatureFor(rand.Reader, a, fkEpoch.Add(time.Hour)); err != nil {
			t.Errorf("a wipe of the key stops the issuer, whose signer still has the secret: %v", err)
		}
		if _, err := openpgp.NewAdoptedIssuer(k, signer); err != nil {
			t.Errorf("an issuer of a key that was wiped: %v", err)
		}
		sec.Wipe()
		if sig, err := openpgp.DirectKeySignatureFor(rand.Reader, a, fkEpoch.Add(2*time.Hour)); sig != nil || !errors.Is(err, openpgp.ErrSecretWiped) {
			t.Errorf("a signature after the wipe of the secret: %d bytes, %v", len(sig), err)
		}
		if a2, err := openpgp.NewAdoptedIssuer(k, signer); a2 != nil || !errors.Is(err, openpgp.ErrParams) || !errors.Is(err, openpgp.ErrSecretWiped) {
			t.Errorf("an issuer with a wiped signer: %v", err)
		}
		// the handle that Signer returns after the wipe is nil: no signer
		if a2, err := openpgp.NewAdoptedIssuer(k, sec.Signer()); a2 != nil || !errors.Is(err, openpgp.ErrParams) {
			t.Errorf("an issuer with the signer that a wiped secret gives: %v", err)
		}
	})
}

// One issuer signs from many goroutines at once (the race detector watches), and every signature is the
// signature that the standard has.
func TestQAAdoptedIssuerIsSafeToShare(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		m := qaNew(t, b)
		var wg sync.WaitGroup
		type made struct {
			sig []byte
			at  time.Time
			msg []byte
		}
		out := make([]made, 8)
		errs := make([]error, 8)
		for i := range out {
			wg.Add(1)
			go func() {
				defer wg.Done()
				at := fkEpoch.Add(time.Duration(i+1) * time.Hour)
				msg := []byte{byte(i), 1, 2}
				sig, err := openpgp.DetachedSignatureFor(rand.Reader, m.a, at, msg)
				out[i], errs[i] = made{sig, at, msg}, err
			}()
		}
		wg.Wait()
		for i, o := range out {
			if errs[i] != nil {
				t.Errorf("goroutine %d: %v", i, errs[i])
				continue
			}
			m.check(t, o.sig, 0x00, o.at, o.msg)
		}
	})
}
