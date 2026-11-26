package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The issuer of an adopted key and the one signing step behind it. The signature that the tests ask for is
// the one that the foundation can make with no builder of its own: a direct-key signature of the primary,
// and a detached signature over a message (adopted_export_test.go).

// fkStdSigner is the secret of a template as a standard-library signer, made from the numbers of the plain
// file, so that it is not the signer that OpenSecret returns.
func fkStdSigner(t testing.TB, b *fkBase) crypto.Signer {
	t.Helper()
	scalar := func(size int) []byte {
		n := bytes.TrimLeft(b.secrets(t).Primary[0], "\x00")
		padded := make([]byte, size)
		copy(padded[size-len(n):], n)
		return padded
	}
	switch b.name {
	case "rsa4096":
		s, ok := b.ent.PrivateKey.PrivateKey.(crypto.Signer)
		if !ok {
			t.Fatalf("the %s template has no crypto.Signer", b.name)
		}
		return s
	case "p384":
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), scalar(48))
		if err != nil {
			t.Fatal(err)
		}
		return k
	case "ed25519":
		return ed25519.NewKeyFromSeed(scalar(ed25519.SeedSize))
	}
	t.Fatalf("no template named %s", b.name)
	return nil
}

// fkOtherSigner is a signer of the same algorithm as the template, of another key.
func fkOtherSigner(t testing.TB, b *fkBase) crypto.Signer {
	t.Helper()
	switch b.name {
	case "rsa4096":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return k
	case "p384":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fkOtherKind is a signer of a key of another algorithm than the template's.
func fkOtherKind(t testing.TB, b *fkBase) crypto.Signer {
	t.Helper()
	if b.name == "p384" {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fkSigner is a signer with the public key given and the signing function given.
type fkSigner struct {
	pub  func() crypto.PublicKey
	sign func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

func (s fkSigner) Public() crypto.PublicKey { return s.pub() }
func (s fkSigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	return s.sign(r, d, o)
}

func TestNewAdoptedIssuerRefuses(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, b.plain)
		sec, err := k.OpenSecret(nil)
		if err != nil {
			t.Fatal(err)
		}
		defer sec.Wipe()
		good := sec.Signer()
		pub := good.Public()

		refused := func(what string, k *openpgp.ForeignKey, s crypto.Signer, also ...error) {
			t.Helper()
			a, err := openpgp.NewAdoptedIssuer(k, s)
			if err == nil || a != nil {
				t.Errorf("%s: an issuer is made (%v)", what, err)
				return
			}
			if !errors.Is(err, openpgp.ErrParams) {
				t.Errorf("%s: %v is not an ErrParams", what, err)
			}
			for _, kind := range also {
				if !errors.Is(err, kind) {
					t.Errorf("%s: %v is not the kind %v", what, err, kind)
				}
			}
			fkCheckText(t, what, err, b)
		}
		refused("no key", nil, good)
		refused("a key that nothing read", &openpgp.ForeignKey{}, good)
		refused("no signer", k, nil)
		refused("a nil signer of a type", k, (*openpgp.ForeignSigner)(nil))
		refused("a nil key of the standard library", k, (*rsa.PrivateKey)(nil))
		refused("the signer of another key", k, fkOtherSigner(t, b))
		refused("the signer of another algorithm", k, fkOtherKind(t, b))
		refused("a signer that has no public key", k, fkSigner{pub: func() crypto.PublicKey { return nil }, sign: nil})
		refused("a signer whose public key is a typed nil", k, fkSigner{pub: func() crypto.PublicKey { return (*ecdsa.PublicKey)(nil) }})
		refused("a signer whose public key call panics", k, fkSigner{pub: func() crypto.PublicKey { panic("no public key") }})
		refused("the public key as a value of another type", k, fkSigner{pub: func() crypto.PublicKey { return fmt.Sprint(pub) }})

		// a signer that was wiped is refused, and the wipe is the cause that errors.Is finds
		sec2, err := k.OpenSecret(nil)
		if err != nil {
			t.Fatal(err)
		}
		wiped := sec2.Signer()
		sec2.Wipe()
		refused("a wiped signer", k, wiped, openpgp.ErrSecretWiped)

		// a key whose primary is revoked is refused: here the revocation is what the file holds, and the
		// view that a caller edits does not change that
		r := fkRead(t, fkRichOf(t, b, false, false).file)
		rs, err := r.OpenSecret(nil)
		if err != nil {
			t.Fatal(err)
		}
		defer rs.Wipe()
		if !r.Primary.Revoked {
			t.Fatal("the rich key is not revoked")
		}
		refused("a revoked primary", r, rs.Signer())
		r.Primary.Revoked = false
		refused("a revoked primary whose view was edited", r, rs.Signer())
	})
}

func TestNewAdoptedIssuerAcceptsAnySignerOfTheKey(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		export := fkRead(t, b.plain)
		sec, err := export.OpenSecret(nil)
		if err != nil {
			t.Fatal(err)
		}
		defer sec.Wipe()
		cert, err := openpgp.ReadForeignCertificate(export.Certificate())
		if err != nil {
			t.Fatal(err)
		}
		signers := map[string]crypto.Signer{
			"the signer of the reader":         sec.Signer(),
			"a signer of the standard library": fkStdSigner(t, b),
			// the same key behind a signer that answers a copy of its public key: the keys are compared,
			// not the pointers
			"a signer that gives a copy": func() crypto.Signer {
				std := fkStdSigner(t, b)
				return fkSigner{
					pub:  func() crypto.PublicKey { return copyPublic(std.Public()) },
					sign: std.Sign,
				}
			}(),
		}
		for name, s := range signers {
			for what, k := range map[string]*openpgp.ForeignKey{"the export": export, "the certificate": cert} {
				t.Run(name+" with "+what, func(t *testing.T) {
					a, err := openpgp.NewAdoptedIssuer(k, s)
					if err != nil {
						t.Fatalf("NewAdoptedIssuer: %v", err)
					}
					at := fkEpoch.Add(time.Hour)
					dks, err := openpgp.DirectKeySignatureFor(rand.Reader, a, at)
					if err != nil {
						t.Fatalf("direct-key signature: %v", err)
					}
					msg := []byte("a short message")
					sig, err := openpgp.DetachedSignatureFor(nil, a, at.Add(time.Hour), msg)
					if err != nil {
						t.Fatalf("detached signature: %v", err)
					}
					// verified by go-crypto, which did not make them
					ring, err := pgp.ReadKeyRing(bytes.NewReader(fkWithKeySig(t, k.Certificate(), dks)))
					if err != nil || len(ring) != 1 {
						t.Fatalf("go-crypto does not read the certificate with the signature: %v", err)
					}
					p, err := gpacket.Read(bytes.NewReader(dks))
					if err != nil {
						t.Fatal(err)
					}
					if err := ring[0].PrimaryKey.VerifyDirectKeySignature(p.(*gpacket.Signature)); err != nil {
						t.Errorf("go-crypto does not verify the direct-key signature: %v", err)
					}
					if _, err := pgp.CheckDetachedSignature(ring, bytes.NewReader(msg), bytes.NewReader(sig), nil); err != nil {
						t.Errorf("go-crypto does not verify the detached signature: %v", err)
					}
					// the hashed area ends with the issuer fingerprint, and the unhashed area is the key ID alone
					typ, hashed, unhashed, ok := fkSigAreasOf(fkSplit(t, dks)[0].Body)
					if !ok || typ != 0x1F {
						t.Fatalf("the signature is not a direct-key signature")
					}
					hs, _ := fkReadSubpackets(hashed)
					us, _ := fkReadSubpackets(unhashed)
					if len(hs) != 2 || hs[0].typ != 2 || hs[1].typ != 33 || len(us) != 1 || us[0].typ != 16 {
						t.Errorf("the subpackets are %+v and %+v", hs, us)
					}
				})
			}
		}
	})
}

// copyPublic is a copy of a public key, with no pointer in common with it.
func copyPublic(p crypto.PublicKey) crypto.PublicKey {
	switch k := p.(type) {
	case *rsa.PublicKey:
		return &rsa.PublicKey{N: new(big.Int).Set(k.N), E: k.E}
	case *ecdsa.PublicKey:
		point, err := k.Bytes()
		if err != nil {
			return p
		}
		c, err := ecdsa.ParseUncompressedPublicKey(k.Curve, point)
		if err != nil {
			return p
		}
		return c
	case ed25519.PublicKey:
		return ed25519.PublicKey(bytes.Clone(k))
	}
	return p
}

// What the signer is asked is the SHA-384 digest and nothing else, with the options of its key.
func TestTheSignerIsAskedForTheSHA384DigestOnly(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		std := fkStdSigner(t, b)
		var calls int
		rec := fkSigner{
			pub: std.Public,
			sign: func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
				calls++
				if len(d) != 48 {
					t.Errorf("the signer is given %d bytes, want the 48 of a SHA-384 digest", len(d))
				}
				want := crypto.SHA384
				if b.name == "ed25519" {
					want = crypto.Hash(0)
				}
				if o.HashFunc() != want {
					t.Errorf("the signer is told the hash %v, want %v", o.HashFunc(), want)
				}
				return std.Sign(r, d, o)
			},
		}
		a, err := openpgp.NewAdoptedIssuer(fkRead(t, b.plain), rec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := openpgp.DetachedSignatureFor(rand.Reader, a, fkEpoch.Add(time.Hour), []byte("m")); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Errorf("the signer was asked %d times, want once", calls)
		}
	})
}

var errSentinel = errors.New("the signer says no")

// The answer of the signer is checked with the public key of the packet before it is used, and the cause
// that the signer gives stays in the error.
func TestTheAnswerOfTheSignerIsCheckedAndItsCauseKept(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, b.plain)
		std := fkStdSigner(t, b)
		other := fkOtherSigner(t, b)
		make := func(sign func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)) *openpgp.AdoptedIssuer {
			a, err := openpgp.NewAdoptedIssuer(k, fkSigner{pub: std.Public, sign: sign})
			if err != nil {
				t.Fatal(err)
			}
			return a
		}
		at := fkEpoch.Add(time.Hour)
		cases := map[string]func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error){
			"an answer of another key": func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
				return other.Sign(r, d, o)
			},
			"an answer for another digest": func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
				return std.Sign(r, append(bytes.Clone(d[:47]), d[47]^1), o)
			},
			"no answer": func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil },
			"garbage":   func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return bytes.Repeat([]byte{7}, 70), nil },
			"an answer with a byte more": func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
				s, err := std.Sign(r, d, o)
				return append(s, 0), err
			},
			"an answer with its last bit changed": func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
				s, err := std.Sign(r, d, o)
				s[len(s)-1] ^= 1
				return s, err
			},
		}
		for name, sign := range cases {
			sig, err := openpgp.DirectKeySignatureFor(rand.Reader, make(sign), at)
			if err == nil || sig != nil || !errors.Is(err, openpgp.ErrSignature) {
				t.Errorf("%s: %v (%d bytes returned)", name, err, len(sig))
			}
			fkCheckText(t, name, err, b)
		}
		// a signer that fails: its cause is in the error, and so is ErrSignature
		_, err := openpgp.DirectKeySignatureFor(rand.Reader, make(func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
			return nil, errSentinel
		}), at)
		if !errors.Is(err, errSentinel) || !errors.Is(err, openpgp.ErrSignature) {
			t.Errorf("a signer that fails: %v", err)
		}
		// a wipe after the issuer was made: the signature is refused with the cause of the wipe
		sec, err := k.OpenSecret(nil)
		if err != nil {
			t.Fatal(err)
		}
		a, err := openpgp.NewAdoptedIssuer(k, sec.Signer())
		if err != nil {
			t.Fatal(err)
		}
		sec.Wipe()
		sig, err := openpgp.DirectKeySignatureFor(rand.Reader, a, at)
		if sig != nil || !errors.Is(err, openpgp.ErrSecretWiped) || !errors.Is(err, openpgp.ErrSignature) {
			t.Errorf("a signature after the wipe: %v", err)
		}
	})
}

// What a caller does to the view of a key after the issuer was made changes nothing that the issuer signs.
func TestTheIssuerReadsTheSnapshotAndNotTheView(t *testing.T) {
	b := fkNamed(t, "p384")
	k := fkRead(t, b.plain)
	sec, err := k.OpenSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sec.Wipe()
	before := openpgp.SnapshotOf(k)
	a, err := openpgp.NewAdoptedIssuer(k, sec.Signer())
	if err != nil {
		t.Fatal(err)
	}
	k.UserIDs[0].Text, k.UserIDs[0].Revoked, k.Primary.Fingerprint, k.Primary.Revoked = "evil", true, "00", true
	k.Subkeys = nil
	k.KeySignatures = append(k.KeySignatures, openpgp.ForeignSignature{Type: 0x20, Status: openpgp.SignatureValid})
	if !reflect.DeepEqual(before, openpgp.SnapshotOf(k)) {
		t.Error("an edit of the view changed the snapshot")
	}
	if _, err := openpgp.DirectKeySignatureFor(rand.Reader, a, fkEpoch.Add(time.Hour)); err != nil {
		t.Errorf("the issuer made before the edit does not sign after it: %v", err)
	}
	// a new issuer of the same key is made from the snapshot too
	if _, err := openpgp.NewAdoptedIssuer(k, sec.Signer()); err != nil {
		t.Errorf("an edited view makes the key an unusable one: %v", err)
	}
}
