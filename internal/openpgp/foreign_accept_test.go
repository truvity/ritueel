package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// A. The keys that the reader accepts, and what it says of them without a passphrase.
// B. The passphrase.
//
// Every key here is made by go-crypto at run time. The numbers that OpenSecret returns are compared
// with the numbers that go-crypto's own decryption of the same file gives, and a signature of the
// returned key is verified with the public key that go-crypto reads from the certificate.

// fkVariant is one way that go-crypto can protect a primary, as the reader takes it.
type fkVariant struct {
	name   string
	prot   fkProt
	state  openpgp.SecretState
	cipher string
	// hand makes the file from packets, for a form that go-crypto does not write.
	hand func(t testing.TB, b *fkBase) []byte
}

// fkHandProtected is a file whose primary is protected by fkProtectRegion.
func fkHandProtected(cipherID byte, h crypto.Hash, hashID, count byte) func(testing.TB, *fkBase) []byte {
	return func(t testing.TB, b *fkBase) []byte {
		t.Helper()
		ps := fkSplit(t, b.plain)
		region := fkProtectRegion(t, b.plainNumbers(t), fkPass, cipherID, h, hashID, count)
		ps[0].Body = append(bytes.Clone(b.pubBody(t)), region...)
		return fkJoin(ps...)
	}
}

func fkVariants() []fkVariant {
	p := func(c gpacket.CipherFunction, h crypto.Hash, count int) fkProt {
		return fkProt{Pass: fkPass, Cipher: c, Hash: h, Count: count}
	}
	return []fkVariant{
		{"unprotected", fkProt{}, openpgp.SecretUnprotected, "", nil},
		{"aes128-sha256", p(gpacket.CipherAES128, crypto.SHA256, 0), openpgp.SecretProtected, "AES-128", nil},
		{"aes192-sha256", p(gpacket.CipherAES192, crypto.SHA256, 0), openpgp.SecretProtected, "AES-192", nil},
		{"aes256-sha256", p(gpacket.CipherAES256, crypto.SHA256, 0), openpgp.SecretProtected, "AES-256", nil},
		{"aes256-sha1", fkProt{Pass: fkPass}, openpgp.SecretProtected, "AES-256", fkHandProtected(9, crypto.SHA1, 2, 0x60)},
		{"aes128-sha1-hand", fkProt{Pass: fkPass}, openpgp.SecretProtected, "AES-128", fkHandProtected(7, crypto.SHA1, 2, 0x20)},
		{"aes192-sha224", p(gpacket.CipherAES192, crypto.SHA224, 0), openpgp.SecretProtected, "AES-192", nil},
		{"aes128-sha384", p(gpacket.CipherAES128, crypto.SHA384, 0), openpgp.SecretProtected, "AES-128", nil},
		{"aes256-sha512-low-count", p(gpacket.CipherAES256, crypto.SHA512, 1024), openpgp.SecretProtected, "AES-256", nil},
	}
}

// fkReadGoCrypto reads a file with go-crypto, binary or armoured, and decrypts its primary.
func fkReadGoCrypto(t testing.TB, file []byte, pass string) *pgp.Entity {
	t.Helper()
	var ents pgp.EntityList
	var err error
	if bytes.HasPrefix(file, []byte("-----")) {
		ents, err = pgp.ReadArmoredKeyRing(bytes.NewReader(file))
	} else {
		ents, err = pgp.ReadKeyRing(bytes.NewReader(file))
	}
	if err != nil || len(ents) != 1 {
		t.Fatalf("go-crypto does not read the file: %v (%d keys)", err, len(ents))
	}
	e := ents[0]
	if e.PrivateKey.Encrypted {
		if err := e.PrivateKey.Decrypt([]byte(pass)); err != nil {
			t.Fatalf("go-crypto does not decrypt the primary: %v", err)
		}
	}
	return e
}

// fkCertPublic reads the first packet of a certificate as go-crypto reads a public key.
func fkCertPublic(t testing.TB, cert []byte) *gpacket.PublicKey {
	t.Helper()
	ps := fkSplit(t, cert)
	if len(ps) == 0 || ps[0].Tag != 6 {
		t.Fatalf("the certificate does not start with a public key packet")
	}
	p, err := gpacket.Read(bytes.NewReader(wrap(6, ps[0].Body)))
	if err != nil {
		t.Fatalf("go-crypto does not read the primary of the certificate: %v", err)
	}
	pk, ok := p.(*gpacket.PublicKey)
	if !ok {
		t.Fatalf("the first packet of the certificate is a %T", p)
	}
	return pk
}

// fkSignAndVerify signs a message with the key that OpenSecret returned and verifies the signature
// with the public numbers that go-crypto reads from the certificate, not with the key itself.
func fkSignAndVerify(t testing.TB, signer crypto.Signer, pk *gpacket.PublicKey) {
	t.Helper()
	msg := []byte("a message that the test signs")
	switch pub := pk.PublicKey.(type) {
	case *rsa.PublicKey:
		d := sha256.Sum256(msg)
		sig, err := signer.Sign(rand.Reader, d[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("the RSA key does not sign: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig); err != nil {
			t.Errorf("the signature of the RSA key does not verify with the public key of go-crypto: %v", err)
		}
	case *eddsa.PublicKey:
		sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil {
			t.Fatalf("the Ed25519 key does not sign: %v", err)
		}
		if !ed25519.Verify(ed25519.PublicKey(pub.X), msg, sig) {
			t.Errorf("the signature of the Ed25519 key does not verify with the public key of go-crypto")
		}
	case *gecdsa.PublicKey:
		d := sha512.Sum384(msg)
		sig, err := signer.Sign(rand.Reader, d[:], crypto.SHA384)
		if err != nil {
			t.Fatalf("the P-384 key does not sign: %v", err)
		}
		raw := append([]byte{4}, pub.X.FillBytes(make([]byte, 48))...)
		raw = append(raw, pub.Y.FillBytes(make([]byte, 48))...)
		std, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), raw)
		if err != nil {
			t.Fatalf("the public point of go-crypto is not a point of P-384: %v", err)
		}
		if !ecdsa.VerifyASN1(std, d[:], sig) {
			t.Errorf("the signature of the P-384 key does not verify with the public key of go-crypto")
		}
	default:
		t.Fatalf("a public key of the type %T", pub)
	}
}

// fkCheckSignerType holds what Signer returns: the handle of this package, which is not the
// standard-library key and cannot be turned into it, with the public key of the algorithm.
func fkCheckSignerType(t testing.TB, b *fkBase, s crypto.Signer) {
	t.Helper()
	if _, ok := s.(*openpgp.ForeignSigner); !ok {
		t.Fatalf("the signer is a %T, want a *ForeignSigner", s)
	}
	switch s.(type) {
	case *rsa.PrivateKey, ed25519.PrivateKey, *ecdsa.PrivateKey:
		t.Fatalf("the signer is a standard-library private key")
	}
	switch b.name {
	case "rsa4096":
		k, ok := s.Public().(*rsa.PublicKey)
		if !ok || k.N.BitLen() != 4096 {
			t.Fatalf("the public key is %T, want an *rsa.PublicKey of 4096 bits", s.Public())
		}
	case "ed25519":
		if _, ok := s.Public().(ed25519.PublicKey); !ok {
			t.Fatalf("the public key is %T, want an ed25519.PublicKey", s.Public())
		}
	case "p384":
		k, ok := s.Public().(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P384() {
			t.Fatalf("the public key is %T, want an *ecdsa.PublicKey on P-384", s.Public())
		}
	}
}

// fkAgrees is the differential test: the key behind the signer is the key that go-crypto gets from its
// own decryption of the same file. The public keys are equal; a signature of the signer verifies with
// the key of go-crypto; and where the scheme is deterministic (RSA PKCS#1 v1.5 and Ed25519) the
// signature of the key of go-crypto is the very bytes that the signer writes.
func fkAgrees(t testing.TB, s crypto.Signer, e *pgp.Entity) {
	t.Helper()
	msg := []byte("a message for the differential test")
	switch want := e.PrivateKey.PrivateKey.(type) {
	case *rsa.PrivateKey:
		d := sha256.Sum256(msg)
		got, err := s.Sign(rand.Reader, d[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if pub, ok := s.Public().(*rsa.PublicKey); !ok || !pub.Equal(&want.PublicKey) {
			t.Errorf("the RSA public key differs from that of go-crypto")
		}
		if err := rsa.VerifyPKCS1v15(&want.PublicKey, crypto.SHA256, d[:], got); err != nil {
			t.Errorf("a signature of the signer does not verify with the key of go-crypto: %v", err)
		}
		theirs, err := want.Sign(rand.Reader, d[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, theirs) {
			t.Errorf("the two RSA keys do not write the same PKCS#1 v1.5 signature")
		}
	case *eddsa.PrivateKey:
		seed := make([]byte, ed25519.SeedSize)
		copy(seed[ed25519.SeedSize-len(want.D):], want.D)
		std := ed25519.NewKeyFromSeed(seed)
		got, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		if pub, ok := s.Public().(ed25519.PublicKey); !ok || !bytes.Equal(pub, want.X) || !bytes.Equal(pub, std.Public().(ed25519.PublicKey)) {
			t.Errorf("the Ed25519 public key differs from that of go-crypto")
		}
		if !ed25519.Verify(ed25519.PublicKey(want.X), msg, got) {
			t.Errorf("a signature of the signer does not verify with the key of go-crypto")
		}
		if !bytes.Equal(got, ed25519.Sign(std, msg)) {
			t.Errorf("the two Ed25519 keys do not write the same signature")
		}
	case *gecdsa.PrivateKey:
		std, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), want.D.FillBytes(make([]byte, 48)))
		if err != nil {
			t.Fatal(err)
		}
		d := sha512.Sum384(msg)
		got, err := s.Sign(rand.Reader, d[:], crypto.SHA384)
		if err != nil {
			t.Fatal(err)
		}
		if pub, ok := s.Public().(*ecdsa.PublicKey); !ok || !pub.Equal(&std.PublicKey) {
			t.Errorf("the P-384 public key differs from that of go-crypto")
		}
		if !ecdsa.VerifyASN1(&std.PublicKey, d[:], got) {
			t.Errorf("a signature of the signer does not verify with the key of go-crypto")
		}
		theirs, err := std.Sign(rand.Reader, d[:], crypto.SHA384)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), d[:], theirs) {
			t.Errorf("a signature of go-crypto's key does not verify with the signer's public key")
		}
	default:
		t.Fatalf("go-crypto holds a %T", e.PrivateKey.PrivateKey)
	}
}

func TestForeignReadsAcceptedKeys(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, v := range fkVariants() {
			for _, form := range []string{"binary", "armoured"} {
				t.Run(v.name+"/"+form, func(t *testing.T) {
					file := b.file(t, v.prot)
					if v.hand != nil {
						file = v.hand(t, b)
					}
					if form == "armoured" {
						file = fkArmourKey(t, file)
					}
					before := bytes.Clone(file)
					k := fkRead(t, file)
					if !bytes.Equal(file, before) {
						t.Fatal("ReadForeignKey changed the file")
					}

					// What the key says about itself, with no passphrase.
					p := k.Primary
					if want := hex.EncodeToString(b.ent.PrimaryKey.Fingerprint); p.Fingerprint != want {
						t.Errorf("fingerprint %s, want %s", p.Fingerprint, want)
					}
					if len(p.Fingerprint) != 40 || p.KeyID != p.Fingerprint[24:] {
						t.Errorf("key ID %s is not the last 16 digits of %s", p.KeyID, p.Fingerprint)
					}
					if p.Algorithm != b.want || p.Algorithm.String() != b.str {
						t.Errorf("algorithm %+v (%s), want %+v (%s)", p.Algorithm, p.Algorithm, b.want, b.str)
					}
					if !p.Created.Equal(fkEpoch) || p.Created.Location().String() != "UTC" {
						t.Errorf("created %v, want %v in UTC", p.Created, fkEpoch)
					}
					if p.Secret != v.state || p.Secret.String() != v.state.String() || p.Cipher != v.cipher {
						t.Errorf("secret %v with cipher %q, want %v with %q", p.Secret, p.Cipher, v.state, v.cipher)
					}
					if p.Revoked {
						t.Error("the primary is reported revoked")
					}
					if len(k.UserIDs) != 1 || k.UserIDs[0].Text != fkUser || !k.UserIDs[0].Valid || !k.UserIDs[0].Primary || k.UserIDs[0].Revoked {
						t.Errorf("user IDs %+v", k.UserIDs)
					}
					if len(k.Subkeys) != 2 {
						t.Fatalf("%d subkeys, want 2", len(k.Subkeys))
					}
					for i, s := range k.Subkeys {
						want := hex.EncodeToString(b.ent.Subkeys[i].PublicKey.Fingerprint)
						if s.Fingerprint != want || s.Form != openpgp.SubkeyWithSecret || !s.Bound || s.Revoked || !s.Created.Equal(fkEpoch) {
							t.Errorf("subkey %d: %+v, want fingerprint %s with a secret, bound", i, s, want)
						}
					}

					// The key that OpenSecret returns is the key.
					cert := k.Certificate()
					pk := fkCertPublic(t, cert)
					secret, err := k.OpenSecret([]byte(v.prot.Pass))
					if err != nil {
						t.Fatalf("OpenSecret: %v", err)
					}
					if secret == nil || secret.Signer() == nil {
						t.Fatal("OpenSecret returned no key")
					}
					fkCheckSignerType(t, b, secret.Signer())
					fkSignAndVerify(t, secret.Signer(), pk)
					fkAgrees(t, secret.Signer(), fkReadGoCrypto(t, file, v.prot.Pass))
					secret.Wipe()
				})
			}
		}
	})
}

// A count at the top of the code of RFC 9580 section 3.7.1.3 (65,011,712 octets hashed) is read as go-crypto
// writes it.
func TestForeignReadsTopS2KCount(t *testing.T) {
	b := fkNamed(t, "ed25519")
	file := b.file(t, fkProt{Pass: fkPass, Count: 65011712})
	k := fkRead(t, file)
	s, err := k.OpenSecret([]byte(fkPass))
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	fkAgrees(t, s.Signer(), fkReadGoCrypto(t, file, fkPass))
}

// A passphrase of the longest length opens a key that go-crypto protected with it, with a count that
// is smaller than one unit of salt and passphrase: the count is then one unit (RFC 9580 section 3.7.1.3).
func TestForeignLongPassphraseUnderSmallCount(t *testing.T) {
	long := string(bytes.Repeat([]byte("p"), openpgp.MaxForeignPassphraseBytes))
	b := fkNamed(t, "ed25519")
	file := b.file(t, fkProt{Pass: long, Count: 1024})
	k := fkRead(t, file)
	s, err := k.OpenSecret([]byte(long))
	if err != nil {
		t.Fatalf("a passphrase of MaxForeignPassphraseBytes: %v", err)
	}
	fkAgrees(t, s.Signer(), fkReadGoCrypto(t, file, long))
	if _, err := k.OpenSecret([]byte(long + "x")); !errors.Is(err, openpgp.ErrParams) {
		t.Errorf("a passphrase one byte over the limit: %v, want ErrParams", err)
	}
}

// The passphrase is bytes: it need not be text, and a trailing newline or another spelling is another
// passphrase.
func TestForeignPassphraseIsBytes(t *testing.T) {
	b := fkNamed(t, "ed25519")
	for _, pass := range []string{"pässwörd of text", "\x00\x01\x02\xff binary", "a", " leading and trailing  "} {
		k := fkRead(t, b.file(t, fkProt{Pass: pass}))
		if _, err := k.OpenSecret([]byte(pass)); err != nil {
			t.Errorf("%q: %v", pass, err)
		}
		for _, other := range []string{pass + "\n", pass + " ", "x" + pass, pass[:len(pass)-1]} {
			if _, err := k.OpenSecret([]byte(other)); !errors.Is(err, openpgp.ErrWrongPassphrase) {
				t.Errorf("%q opened or failed otherwise with %q: %v", pass, other, err)
			}
		}
	}
}

// B. The passphrase.

func TestForeignWrongPassphrase(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		file := b.file(t, fkProt{Pass: fkPass})
		k := fkRead(t, file)
		for _, c := range []struct {
			name string
			pass []byte
		}{
			{"wrong", []byte("not the passphrase")},
			{"empty", []byte{}},
			{"nil", nil},
			{"one byte short", []byte(fkPass[:len(fkPass)-1])},
			{"one byte more", []byte(fkPass + "!")},
			{"upper case", []byte("CORRECT HORSE BATTERY STAPLE")},
		} {
			t.Run(c.name, func(t *testing.T) {
				before := bytes.Clone(c.pass)
				s, err := k.OpenSecret(c.pass)
				if !errors.Is(err, openpgp.ErrWrongPassphrase) {
					t.Fatalf("got %v, want ErrWrongPassphrase", err)
				}
				if err != openpgp.ErrWrongPassphrase { //nolint:errorlint // the sentinel itself is the promise: the text holds nothing
					t.Errorf("the error is not the sentinel: %v", err)
				}
				if s != nil {
					t.Error("a key is returned with a wrong passphrase")
				}
				if errors.Is(err, openpgp.ErrForeignKey) || errors.Is(err, openpgp.ErrParams) {
					t.Errorf("a wrong passphrase is an ErrForeignKey or an ErrParams: %v", err)
				}
				if !bytes.Equal(c.pass, before) {
					t.Error("the passphrase slice was changed")
				}
				fkCheckText(t, c.name, err, b)
			})
		}

		// No state is spoiled: the right one opens after the wrong ones, as often as asked, and the
		// keys are separate.
		pass := []byte(fkPass)
		before := bytes.Clone(pass)
		var first, second *openpgp.ForeignSecret
		for i := 0; i < 3; i++ {
			s, err := k.OpenSecret(pass)
			if err != nil {
				t.Fatalf("open %d after the wrong ones: %v", i, err)
			}
			if i == 0 {
				first = s
			}
			if i == 1 {
				second = s
			}
		}
		if !bytes.Equal(pass, before) {
			t.Error("the right passphrase slice was changed")
		}
		fkAgrees(t, first.Signer(), fkReadGoCrypto(t, file, fkPass))
		first.Wipe()
		fkAgrees(t, second.Signer(), fkReadGoCrypto(t, file, fkPass))
		if _, err := k.OpenSecret([]byte("wrong again")); !errors.Is(err, openpgp.ErrWrongPassphrase) {
			t.Errorf("a wrong passphrase after the right one: %v", err)
		}
	})
}

func TestForeignPassphraseOverLimit(t *testing.T) {
	over := bytes.Repeat([]byte("p"), openpgp.MaxForeignPassphraseBytes+1)
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, prot := range []fkProt{{}, {Pass: fkPass}} {
			k := fkRead(t, b.file(t, prot))
			before := bytes.Clone(over)
			s, err := k.OpenSecret(over)
			if !errors.Is(err, openpgp.ErrParams) {
				t.Fatalf("protected=%v: got %v, want ErrParams", prot.Pass != "", err)
			}
			if errors.Is(err, openpgp.ErrWrongPassphrase) || errors.Is(err, openpgp.ErrForeignKey) {
				t.Errorf("an over-long passphrase is a wrong passphrase or a refusal of the file: %v", err)
			}
			if s != nil {
				t.Error("a key is returned with the error")
			}
			if !bytes.Equal(over, before) {
				t.Error("the passphrase slice was changed")
			}
			if !bytes.Contains([]byte(err.Error()), []byte("MaxForeignPassphraseBytes")) {
				t.Errorf("the text does not name the limit: %v", err)
			}
			fkCheckText(t, "over limit", err, b)
			// the same key still opens
			if _, err := k.OpenSecret([]byte(prot.Pass)); err != nil {
				t.Errorf("the key does not open after the refusal: %v", err)
			}
		}
	})
}

// An unprotected secret takes any passphrase and nil, and does not use it.
func TestForeignUnprotectedIgnoresPassphrase(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		file := b.file(t, fkProt{})
		k := fkRead(t, file)
		for _, pass := range [][]byte{nil, {}, []byte("anything at all"), bytes.Repeat([]byte("x"), openpgp.MaxForeignPassphraseBytes)} {
			before := bytes.Clone(pass)
			s, err := k.OpenSecret(pass)
			if err != nil {
				t.Fatalf("passphrase of %d bytes: %v", len(pass), err)
			}
			fkAgrees(t, s.Signer(), fkReadGoCrypto(t, file, ""))
			if !bytes.Equal(pass, before) {
				t.Error("the passphrase slice was changed")
			}
		}
	})
}

// A key that go-crypto protected with an empty passphrase opens with nil and with an empty slice, as
// the standard hashes the salt alone.
func TestForeignEmptyPassphraseKey(t *testing.T) {
	b := fkNamed(t, "ed25519")
	e := b.entity(t)
	if err := e.PrivateKey.EncryptWithConfig([]byte{}, b.cfg); err != nil {
		t.Skipf("go-crypto does not protect a key with an empty passphrase: %v", err)
	}
	var buf bytes.Buffer
	if err := e.SerializePrivateWithoutSigning(&buf, b.cfg); err != nil {
		t.Fatal(err)
	}
	k := fkRead(t, buf.Bytes())
	if k.Primary.Secret != openpgp.SecretProtected {
		t.Skipf("go-crypto wrote the key as %v", k.Primary.Secret)
	}
	for _, pass := range [][]byte{nil, {}} {
		if _, err := k.OpenSecret(pass); err != nil {
			t.Errorf("empty passphrase %#v: %v", pass, err)
		}
	}
	if _, err := k.OpenSecret([]byte("x")); !errors.Is(err, openpgp.ErrWrongPassphrase) {
		t.Errorf("a passphrase on a key with an empty one: %v", err)
	}
}
