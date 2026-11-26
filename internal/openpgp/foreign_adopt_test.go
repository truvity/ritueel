package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The lone secret key packet of an adopted key: ForeignKey.SecretPacket writes it and
// OpenSecretPacket reads it. The keys come from the kit of the reader of a foreign key.

// fkLone writes the lone packet of a template with the passphrase given.
func fkLone(t testing.TB, b *fkBase, pass string) (*openpgp.ForeignKey, []byte) {
	t.Helper()
	k := fkRead(t, b.file(t, fkProt{Pass: pass}))
	var p []byte
	if pass != "" {
		p = []byte(pass)
	}
	pkt, err := k.SecretPacket(p)
	if err != nil {
		t.Fatalf("SecretPacket: %v", err)
	}
	return k, pkt
}

func TestSecretPacketIsOnePacketWithThePublicPartOfTheCertificate(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, pass := range []string{"", fkPass} {
			k, pkt := fkLone(t, b, pass)
			ps := fkSplit(t, pkt)
			if len(ps) != 1 || ps[0].Tag != 5 {
				t.Fatalf("the packet is %d packets, the first of tag %d, want one of tag 5", len(ps), ps[0].Tag)
			}
			if !bytes.Equal(pkt, fkJoin(ps...)) {
				t.Errorf("the header is not the shortest one of the new format")
			}
			certPub, err := openpgp.PrimaryPublicBody(k.Certificate())
			if err != nil {
				t.Fatal(err)
			}
			body := ps[0].Body
			if !bytes.HasPrefix(body, certPub) || body[len(certPub)] != 0 {
				t.Errorf("the packet does not start with the public part of the certificate and the usage 0")
			}
			numbers := body[len(certPub)+1:]
			if !bytes.Equal(numbers[:len(numbers)-2], bytes.Join(fkMPIs(b.secrets(t).Primary), nil)) {
				t.Errorf("the numbers of the packet are not the numbers of the key")
			}
			// go-crypto, the second reader: the same key, not protected
			p, err := gpacket.Read(bytes.NewReader(pkt))
			if err != nil {
				t.Fatalf("go-crypto does not read the packet: %v", err)
			}
			sk, ok := p.(*gpacket.PrivateKey)
			if !ok || sk.Encrypted || sk.IsSubkey || sk.Version != 4 || sk.KeyIdString() == "" {
				t.Errorf("go-crypto reads the packet as %T encrypted=%v", p, ok && sk.Encrypted)
			}
			if got := fkHex(sk.Fingerprint); got != k.Primary.Fingerprint {
				t.Errorf("the fingerprint is %s, want %s", got, k.Primary.Fingerprint)
			}
		}
	})
}

func fkMPIs(parts [][]byte) [][]byte {
	out := make([][]byte, len(parts))
	for i, p := range parts {
		out[i] = fkMPI(p)
	}
	return out
}

func fkHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func TestOpenSecretPacketGivesTheKeyAndWhatItSaysInPublic(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k, pkt := fkLone(t, b, fkPass)
		secret, pub, err := openpgp.OpenSecretPacket(pkt)
		if err != nil {
			t.Fatalf("OpenSecretPacket: %v", err)
		}
		if pub.Fingerprint != k.Primary.Fingerprint || !pub.Created.Equal(k.Primary.Created) || pub.Algorithm != k.Primary.Algorithm {
			t.Errorf("the public facts are %+v, want those of the export: %s %v %v", pub.Fingerprint, k.Primary.Fingerprint, k.Primary.Created, k.Primary.Algorithm)
		}
		certPub, _ := openpgp.PrimaryPublicBody(k.Certificate())
		if !bytes.Equal(pub.PublicBody, certPub) {
			t.Errorf("the public body is not the one of the certificate")
		}
		pub.PublicBody[0] ^= 1
		if again, _ := openpgp.PrimaryPublicBody(k.Certificate()); !bytes.Equal(again, certPub) {
			t.Errorf("a change of the returned body changed the key")
		}
		// it signs, and the signature verifies with the public key
		digest := sha256.Sum256([]byte("a message"))
		opts := crypto.SignerOpts(crypto.SHA256)
		in := digest[:]
		if b.name == "ed25519" {
			opts, in = crypto.Hash(0), []byte("a message")
		}
		sig, err := secret.Signer().Sign(rand.Reader, in, opts)
		if err != nil || len(sig) == 0 {
			t.Fatalf("Sign: %v", err)
		}
		signer := secret.Signer()
		secret.Wipe()
		if _, err := signer.Sign(rand.Reader, in, opts); !errors.Is(err, openpgp.ErrSecretWiped) {
			t.Errorf("a signature after the wipe: %v, want ErrSecretWiped", err)
		}
		secret.Wipe()
	})
}

func TestSecretPacketOpensTheExportLikeOpenSecret(t *testing.T) {
	b := fkNamed(t, "p384")
	k := fkRead(t, b.file(t, fkProt{Pass: fkPass}))
	if _, err := k.SecretPacket([]byte("not the passphrase")); !errors.Is(err, openpgp.ErrWrongPassphrase) {
		t.Errorf("a wrong passphrase: %v, want ErrWrongPassphrase", err)
	}
	if _, err := k.SecretPacket(nil); !errors.Is(err, openpgp.ErrWrongPassphrase) {
		t.Errorf("no passphrase for a protected export: %v, want ErrWrongPassphrase", err)
	}
	if _, err := k.SecretPacket(make([]byte, openpgp.MaxForeignPassphraseBytes+1)); !errors.Is(err, openpgp.ErrParams) {
		t.Errorf("a passphrase over the limit: %v, want ErrParams", err)
	}
	// an unprotected export ignores the passphrase
	plain := fkRead(t, b.plain)
	one, err := plain.SecretPacket(nil)
	if err != nil {
		t.Fatal(err)
	}
	two, err := plain.SecretPacket([]byte("ignored"))
	if err != nil || !bytes.Equal(one, two) {
		t.Errorf("an unprotected export gives another packet for another passphrase: %v", err)
	}
	var none *openpgp.ForeignKey
	if _, err := none.SecretPacket(nil); !errors.Is(err, openpgp.ErrParams) {
		t.Errorf("a nil key: %v, want ErrParams", err)
	}
	plain.Wipe()
	if pkt, err := plain.SecretPacket(nil); !errors.Is(err, openpgp.ErrParams) || pkt != nil {
		t.Errorf("a wiped key: %v, want ErrParams and no packet", err)
	}
	if _, err := (&openpgp.ForeignKey{}).SecretPacket(nil); !errors.Is(err, openpgp.ErrParams) {
		t.Errorf("a key that ReadForeignKey did not make: %v, want ErrParams", err)
	}
}

func TestOpenSecretPacketRefusesEverythingElse(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k, pkt := fkLone(t, b, "")
		certPub, _ := openpgp.PrimaryPublicBody(k.Certificate())
		body := fkSplit(t, pkt)[0].Body
		hdr := len(pkt) - len(body)
		usageAt := hdr + len(certPub)
		with := func(f func(p []byte) []byte) []byte { return f(bytes.Clone(pkt)) }
		primaryPub := fkJoin(fkPacket{6, certPub})
		oldHeader := func() []byte {
			if len(body) < 256 {
				return append([]byte{0x80 | 5<<2, byte(len(body))}, body...)
			}
			return append([]byte{0x80 | 5<<2 | 1, byte(len(body) >> 8), byte(len(body))}, body...)
		}()
		cases := []struct {
			name string
			in   []byte
			want []error
		}{
			{"empty", nil, []error{openpgp.ErrForeignForm}},
			{"one byte", []byte{0xC5}, []error{openpgp.ErrForeignForm}},
			{"cut short", pkt[:len(pkt)-1], []error{openpgp.ErrForeignForm}},
			{"a trailing byte", append(bytes.Clone(pkt), 0), []error{openpgp.ErrForeignForm}},
			{"a marker packet after it", append(bytes.Clone(pkt), fkJoin(fkPacket{10, []byte("PGP")})...), []error{openpgp.ErrForeignForm}},
			{"the packet and a user ID", append(bytes.Clone(pkt), fkJoin(fkPacket{13, []byte("x")})...), []error{openpgp.ErrForeignForm}},
			{"over the limit", append(bytes.Clone(pkt), make([]byte, openpgp.MaxAdoptedPacketBytes)...), []error{openpgp.ErrForeignLimit}},
			{"a public key packet", primaryPub, []error{openpgp.ErrForeignNoSecret}},
			{"a subkey packet", fkJoin(fkPacket{7, body}), []error{openpgp.ErrForeignForm}},
			{"a user ID packet", fkJoin(fkPacket{13, body}), []error{openpgp.ErrForeignPacket}},
			{"the old header form", oldHeader, []error{openpgp.ErrForeignForm}},
			{"a longer header than the shortest", fkJoin(fkPacket{5, body})[:0:0], []error{openpgp.ErrForeignForm}},
			{"version 3", with(func(p []byte) []byte { p[hdr] = 3; return p }), []error{openpgp.ErrForeignVersion}},
			{"version 6", with(func(p []byte) []byte { p[hdr] = 6; return p }), []error{openpgp.ErrForeignVersion}},
			{"usage 254", with(func(p []byte) []byte { p[usageAt] = 254; return p }), []error{openpgp.ErrForeignProtection}},
			{"usage 255", with(func(p []byte) []byte { p[usageAt] = 255; return p }), []error{openpgp.ErrForeignProtection}},
			{"usage 7 (a cipher number)", with(func(p []byte) []byte { p[usageAt] = 7; return p }), []error{openpgp.ErrForeignProtection}},
			{"no secret part", fkJoin(fkPacket{5, certPub}), []error{openpgp.ErrForeignNoSecret}},
			{"a wrong checksum", with(func(p []byte) []byte { p[len(p)-1] ^= 1; return p }), []error{openpgp.ErrForeignSecret}},
			{"a number changed and the checksum made again", fkLoneFlipped(t, b, certPub), []error{openpgp.ErrForeignSecret}},
			{"an algorithm that is not read", with(func(p []byte) []byte { p[hdr+5] = 16; return p }), []error{openpgp.ErrForeignKey}},
		}
		for _, c := range cases {
			if c.name == "a longer header than the shortest" {
				// the same body with a header of the five-octet length, which is not the shortest
				c.in = append([]byte{0xC5, 0xFF, 0, 0, byte(len(body) >> 8), byte(len(body))}, body...)
			}
			s, pub, err := openpgp.OpenSecretPacket(c.in)
			if err == nil {
				t.Errorf("%s: the packet was read, want a refusal", c.name)
				continue
			}
			if s != nil || pub.Fingerprint != "" || pub.PublicBody != nil {
				t.Errorf("%s: something is returned with the error %v", c.name, err)
			}
			if !errors.Is(err, openpgp.ErrForeignKey) {
				t.Errorf("%s: %v is not an ErrForeignKey", c.name, err)
			}
			for _, w := range c.want {
				if !errors.Is(err, w) {
					t.Errorf("%s: %v is not the kind %v", c.name, err, w)
				}
			}
			fkCheckText(t, c.name, err, b)
		}
	})
}

// fkLoneFlipped writes the lone packet of a template with one bit of its first secret number
// changed and the checksum made again, so that only the match with the public part can refuse it.
func fkLoneFlipped(t testing.TB, b *fkBase, certPub []byte) []byte {
	t.Helper()
	own := b.secrets(t).Primary
	flipped := make([][]byte, len(own))
	for i := range own {
		flipped[i] = bytes.Clone(own[i])
	}
	flipped[0][len(flipped[0])-1] ^= 1
	numbers := fkEncode(flipped...)
	var sum uint16
	for _, c := range numbers {
		sum += uint16(c)
	}
	region := append([]byte{0}, numbers...)
	region = append(region, byte(sum>>8), byte(sum))
	return fkJoin(fkPacket{5, append(bytes.Clone(certPub), region...)})
}

func TestTheLonePacketOfRSA4096FitsItsLimit(t *testing.T) {
	_, pkt := fkLone(t, fkNamed(t, "rsa4096"), fkPass)
	t.Logf("the lone packet of an RSA-4096 key is %d bytes, the limit is %d", len(pkt), openpgp.MaxAdoptedPacketBytes)
	if len(pkt) > openpgp.MaxAdoptedPacketBytes || len(pkt) < 1400 {
		t.Errorf("the packet is %d bytes, want 1400 to %d", len(pkt), openpgp.MaxAdoptedPacketBytes)
	}
}

func TestPrimaryPublicBody(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, b.plain)
		body, err := openpgp.PrimaryPublicBody(k.Certificate())
		if err != nil || !bytes.Equal(body, b.pubBody(t)) {
			t.Fatalf("PrimaryPublicBody: %v, want the public body of the primary", err)
		}
		bad := map[string][]byte{
			"empty":              nil,
			"a signature first":  fkJoin(fkPacket{2, body}),
			"a trailing byte":    fkJoin(fkPacket{6, append(bytes.Clone(body), 0)}),
			"cut":                fkJoin(fkPacket{6, body[:len(body)-1]}),
			"a secret key first": fkJoin(fkPacket{5, body}),
		}
		for name, in := range bad {
			if got, err := openpgp.PrimaryPublicBody(in); !errors.Is(err, openpgp.ErrForeignKey) || got != nil {
				t.Errorf("%s: %v, %v, want an ErrForeignKey and nothing", name, got, err)
			}
		}
	})
}

// fkRSACanon makes a secret of the RSA template whose numbers still satisfy every relation of the key
// and are not the canonical ones: u + q, and d plus the smallest multiple of the exponent of the group
// that takes it to the modulus or over.
func fkRSACanon(t testing.TB, b *fkBase) (d, p, q, u, uBig, dBig []byte) {
	t.Helper()
	own := b.secrets(t).Primary
	d, p, q, u = own[0], own[1], own[2], own[3]
	bq, bp, bd := new(big.Int).SetBytes(q), new(big.Int).SetBytes(p), new(big.Int).SetBytes(d)
	uBig = new(big.Int).Add(new(big.Int).SetBytes(u), bq).Bytes()
	n := new(big.Int).Mul(bp, bq)
	p1, q1 := new(big.Int).Sub(bp, big.NewInt(1)), new(big.Int).Sub(bq, big.NewInt(1))
	lambda := new(big.Int).Div(new(big.Int).Mul(p1, q1), new(big.Int).GCD(nil, nil, p1, q1))
	k := new(big.Int).Div(new(big.Int).Sub(n, bd), lambda)
	k.Add(k, big.NewInt(1))
	dBigInt := new(big.Int).Add(bd, new(big.Int).Mul(k, lambda))
	if dBigInt.Cmp(n) < 0 {
		t.Fatal("d plus a multiple of lambda is below the modulus")
	}
	return d, p, q, u, uBig, dBigInt.Bytes()
}

func TestRSANumbersThatAreNotCanonicalAreRefused(t *testing.T) {
	b := fkNamed(t, "rsa4096")
	d, p, q, u, uBig, dBig := fkRSACanon(t, b)
	cases := map[string][][]byte{
		"u plus q":                 {d, p, q, uBig},
		"d plus a multiple of lam": {dBig, p, q, u},
	}
	for name, nums := range cases {
		file := fkSecretFile(t, b, false, fkEncode(nums...))
		k := fkRead(t, file)
		if s, err := k.OpenSecret(nil); !errors.Is(err, openpgp.ErrForeignSecret) || s != nil {
			t.Errorf("%s: OpenSecret: %v, want ErrForeignSecret", name, err)
		}
		certPub, _ := openpgp.PrimaryPublicBody(k.Certificate())
		sum := uint16(0)
		numbers := fkEncode(nums...)
		for _, c := range numbers {
			sum += uint16(c)
		}
		region := append(append([]byte{0}, numbers...), byte(sum>>8), byte(sum))
		pkt := fkJoin(fkPacket{5, append(bytes.Clone(certPub), region...)})
		s, _, err := openpgp.OpenSecretPacket(pkt)
		if !errors.Is(err, openpgp.ErrForeignSecret) || s != nil {
			t.Errorf("%s: OpenSecretPacket: %v, want ErrForeignSecret", name, err)
		}
		fkCheckText(t, name, err, b)
	}
	// the canonical numbers still open
	if _, err := fkRead(t, b.plain).OpenSecret(nil); err != nil {
		t.Errorf("the canonical secret: %v", err)
	}
}

func TestAWipedKeyIsKnownToBeWiped(t *testing.T) {
	var none *openpgp.ForeignKey
	if !none.Wiped() {
		t.Errorf("a nil key is not wiped")
	}
	k := fkRead(t, fkNamed(t, "p384").plain)
	if k.Wiped() {
		t.Errorf("a key that was read is wiped")
	}
	k.Wipe()
	if !k.Wiped() {
		t.Errorf("a key that was wiped is not")
	}
}

// fkSwappedPrimes is the secret numbers of the RSA template with the primes in the other order and u
// made again for that order, which is a good secret for a tolerant reader.
func fkSwappedPrimes(t testing.TB, b *fkBase) (swapped, canonical []byte) {
	t.Helper()
	own := b.secrets(t).Primary
	d, p, q := own[0], own[1], own[2]
	bp, bq := new(big.Int).SetBytes(p), new(big.Int).SetBytes(q)
	if bp.Cmp(bq) >= 0 {
		t.Fatal("the template has its primes in the other order already")
	}
	u := new(big.Int).ModInverse(bq, bp)
	return fkEncode(d, q, p, u.Bytes()), fkEncode(own...)
}

func TestRSAPrimesAreWrittenInTheOrderOfTheStandardOnly(t *testing.T) {
	b := fkNamed(t, "rsa4096")
	swapped, canonical := fkSwappedPrimes(t, b)
	digest := sha256.Sum256([]byte("a message"))
	for _, protected := range []bool{false, true} {
		pass := []byte(nil)
		if protected {
			pass = []byte(fkPass)
		}
		k := fkRead(t, fkSecretFile(t, b, protected, swapped))
		// the export is read tolerantly, as it stands, and signs
		secret, err := k.OpenSecret(pass)
		if err != nil {
			t.Fatalf("protected=%v: OpenSecret of an export with p above q: %v", protected, err)
		}
		sig, err := secret.Signer().Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil || rsa.VerifyPKCS1v15(secret.Signer().Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig) != nil {
			t.Fatalf("protected=%v: the key of an export with p above q does not sign: %v", protected, err)
		}
		secret.Wipe()
		// the packet that is written has p below q, and is the packet of the canonical export
		pkt, err := k.SecretPacket(pass)
		if err != nil {
			t.Fatalf("protected=%v: SecretPacket: %v", protected, err)
		}
		want, err := fkRead(t, fkSecretFile(t, b, false, canonical)).SecretPacket(nil)
		if err != nil || !bytes.Equal(pkt, want) {
			t.Errorf("protected=%v: the packet of an export with p above q is not the canonical packet: %v", protected, err)
		}
		s2, _, err := openpgp.OpenSecretPacket(pkt)
		if err != nil {
			t.Fatalf("protected=%v: OpenSecretPacket of the written packet: %v", protected, err)
		}
		sig, err = s2.Signer().Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil || rsa.VerifyPKCS1v15(s2.Signer().Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig) != nil {
			t.Errorf("protected=%v: the key of the written packet does not sign: %v", protected, err)
		}
		s2.Wipe()
	}
	// a hand-made packet with p above q is refused, with no number in the text
	k := fkRead(t, b.plain)
	certPub, _ := openpgp.PrimaryPublicBody(k.Certificate())
	for name, nums := range map[string][]byte{"p above q": swapped, "p equal to q": fkSamePrimes(t, b)} {
		var sum uint16
		for _, c := range nums {
			sum += uint16(c)
		}
		region := append(append([]byte{0}, nums...), byte(sum>>8), byte(sum))
		s, _, err := openpgp.OpenSecretPacket(fkJoin(fkPacket{5, append(bytes.Clone(certPub), region...)}))
		if !errors.Is(err, openpgp.ErrForeignSecret) || s != nil {
			t.Errorf("%s: OpenSecretPacket: %v, want ErrForeignSecret", name, err)
		}
		fkCheckText(t, name, err, b)
	}
	// p = q is refused by the reader of an export too, and SecretPacket writes nothing for it
	pq := fkRead(t, fkSecretFile(t, b, false, fkSamePrimes(t, b)))
	if s, err := pq.OpenSecret(nil); !errors.Is(err, openpgp.ErrForeignSecret) || s != nil {
		t.Errorf("OpenSecret with p = q: %v, want ErrForeignSecret", err)
	}
	if pkt, err := pq.SecretPacket(nil); !errors.Is(err, openpgp.ErrForeignSecret) || pkt != nil {
		t.Errorf("SecretPacket with p = q: %v, want ErrForeignSecret and no packet", err)
	}
}

// fkSamePrimes is the secret numbers with the first prime twice.
func fkSamePrimes(t testing.TB, b *fkBase) []byte {
	t.Helper()
	own := b.secrets(t).Primary
	return fkEncode(own[0], own[1], own[1], own[3])
}
