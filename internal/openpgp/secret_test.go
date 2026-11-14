package openpgp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gopacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The layout of the first packet of a secret key, as the page says it (docs/reference/bundle.md,
// "The software root's key files"; RFC 9580, sections 5.5.3 and 10.2): a header of two bytes for a
// body under 192 bytes, then the version 4 public part (111 bytes for P-384), the S2K usage, the
// scalar as a multiprecision integer and the two-octet checksum of that integer.
const (
	secretPubLen   = 111
	secretUsageAt  = secretPubLen // index in the body
	secretScalarAt = secretPubLen + 1
)

// secretFixture is a certificate made by NewPrimary, the key behind it and the secret key built
// from them.
type secretFixture struct {
	signer *privateSigner
	cert   []byte
	secret []byte
}

func newSecretFixture(t testing.TB) secretFixture {
	t.Helper()
	s, _, cert, _ := newPrimary(t)
	secret, err := openpgp.SecretKey(cert, s.key)
	if err != nil {
		t.Fatalf("SecretKey: %v", err)
	}
	return secretFixture{signer: s, cert: cert, secret: secret}
}

// secretRebuild takes the first packet of secret apart, lets fn change its body and puts the
// packet together again with the shortest header, followed by the unchanged rest.
func secretRebuild(t testing.TB, secret []byte, fn func(body []byte) []byte) []byte {
	t.Helper()
	ps := splitPackets(t, secret)
	rest := secret[len(ps[0].Raw):]
	body := fn(bytes.Clone(ps[0].Body))
	return append(wrap(5, body), rest...)
}

// secretChecksumOf is the checksum of the standard, written again here: the sum of the octets of
// the multiprecision integer, modulo 65536.
func secretChecksumOf(mpiBytes []byte) []byte {
	var sum uint16
	for _, b := range mpiBytes {
		sum += uint16(b)
	}
	return []byte{byte(sum >> 8), byte(sum)}
}

// secretWithScalar writes body with another scalar and a matching checksum.
func secretWithScalar(body []byte, scalar *big.Int) []byte {
	out := bytes.Clone(body[:secretScalarAt])
	m := mpi(scalar)
	out = append(out, m...)
	return append(out, secretChecksumOf(m)...)
}

func requireSecretRefused(t *testing.T, what string, data []byte) {
	t.Helper()
	priv, at, cert, err := openpgp.ParseSecretKey(data)
	if err == nil {
		t.Errorf("%s: accepted", what)
		return
	}
	if !errors.Is(err, openpgp.ErrSecretKey) {
		t.Errorf("%s: the error does not wrap ErrSecretKey: %v", what, err)
	}
	if priv != nil || !at.IsZero() || cert != nil {
		t.Errorf("%s: a refusal returned a value", what)
	}
}

func TestSecretKeyThenParseSecretKeyGivesTheSameKeyTimeAndCertificate(t *testing.T) {
	f := newSecretFixture(t)
	priv, at, cert, err := openpgp.ParseSecretKey(f.secret)
	if err != nil {
		t.Fatalf("ParseSecretKey: %v", err)
	}
	if !priv.Equal(f.signer.key) {
		t.Error("the key that was read is not the key that was written")
	}
	if !at.Equal(created) {
		t.Errorf("creation time %v, want %v", at, created)
	}
	if !bytes.Equal(cert, f.cert) {
		t.Error("the certificate that was read is not the certificate that was given")
	}
	again, err := openpgp.SecretKey(f.cert, f.signer.key)
	if err != nil || !bytes.Equal(again, f.secret) {
		t.Errorf("SecretKey twice gives other bytes (err %v): it holds no randomness, so the file is the same", err)
	}
}

func TestTheSecretKeyIsTheKeyPacketMadeSecretThenTheUserIDThenTheSelfSignature(t *testing.T) {
	f := newSecretFixture(t)
	ps := splitPackets(t, f.secret)
	if got := tags(ps); !bytes.Equal(got, []byte{5, tagUserID, tagSignature}) {
		t.Fatalf("packet tags % d, want 5 13 2", got)
	}
	body := ps[0].Body
	if ps[0].HeaderLen != 2 || f.secret[0] != 0xC5 {
		t.Errorf("the header of the secret key packet is % x, want the new format, tag 5, one length byte", f.secret[:2])
	}
	if want := keyBody(&f.signer.key.PublicKey, created); !bytes.Equal(body[:secretPubLen], want) {
		t.Error("the public part of the secret key packet is not the body of the public key packet")
	}
	if body[secretUsageAt] != 0 {
		t.Errorf("S2K usage %d, want 0", body[secretUsageAt])
	}
	d := new(big.Int).SetBytes(mustBytes(t, f.signer.key))
	m := mpi(d)
	if got := body[secretScalarAt : len(body)-2]; !bytes.Equal(got, m) {
		t.Error("the secret material is not the multiprecision integer of the scalar")
	}
	if got := body[len(body)-2:]; !bytes.Equal(got, secretChecksumOf(m)) {
		t.Errorf("checksum % x, want % x", got, secretChecksumOf(m))
	}
	pub := splitPackets(t, f.cert)
	if !bytes.Equal(ps[1].Raw, pub[1].Raw) || !bytes.Equal(ps[2].Raw, pub[2].Raw) {
		t.Error("the user ID and the self-signature are not the ones of the certificate, unchanged")
	}
}

// crypto/ecdsa hands out the slice of its own cache from Bytes, which it shares with every user of
// the key. A function that clears a slice that it did not make clears the scalar that a signing
// goroutine of the same key is reading. SecretKey must work on a copy.
func TestSecretKeyDoesNotClearTheSliceThatTheKeyHandedOutBefore(t *testing.T) {
	f := newSecretFixture(t)
	held, err := f.signer.key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(held)
	if _, err := openpgp.SecretKey(f.cert, f.signer.key); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(held, want) {
		t.Error("SecretKey cleared a slice that crypto/ecdsa owns and shares: the scalar of a key in use is zeroed under its other users")
	}
	// The refusals clear the same way.
	held, _ = f.signer.key.Bytes()
	want = bytes.Clone(held)
	other := genKey(t)
	if _, err := openpgp.SecretKey(mustCert(t, other), f.signer.key); err == nil {
		t.Fatal("accepted a key that is not the key of the certificate")
	}
	if !bytes.Equal(held, want) {
		t.Error("a refusal of SecretKey cleared a slice that crypto/ecdsa owns and shares")
	}
}

func mustBytes(t testing.TB, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// go-crypto is the second reader of the secret key.
func TestGoCryptoReadsTheFirstPacketAsAnUnprotectedECDSAKeyWithTheFingerprintOfTheCertificate(t *testing.T) {
	f := newSecretFixture(t)
	p, err := gopacket.Read(bytes.NewReader(f.secret))
	if err != nil {
		t.Fatalf("packet.Read: %v", err)
	}
	sk, ok := p.(*gopacket.PrivateKey)
	if !ok {
		t.Fatalf("the first packet is a %T", p)
	}
	if sk.Encrypted || sk.IsSubkey || sk.Version != 4 || sk.PubKeyAlgo != gopacket.PubKeyAlgoECDSA {
		t.Errorf("encrypted %v subkey %v version %d algorithm %d", sk.Encrypted, sk.IsSubkey, sk.Version, sk.PubKeyAlgo)
	}
	certPkt, err := gopacket.Read(bytes.NewReader(f.cert))
	if err != nil {
		t.Fatal(err)
	}
	pk, ok := certPkt.(*gopacket.PublicKey)
	if !ok {
		t.Fatalf("the first packet of the certificate is a %T", certPkt)
	}
	if !bytes.Equal(sk.Fingerprint, pk.Fingerprint) {
		t.Errorf("fingerprint of the secret key % x, of the certificate % x: the change of tag changes it", sk.Fingerprint, pk.Fingerprint)
	}
	want := fingerprintOf(t, &f.signer.key.PublicKey, created)
	if got := hexLower(sk.Fingerprint); got != want {
		t.Errorf("fingerprint %s, want %s", got, want)
	}
	if !sk.CreationTime.Equal(created) {
		t.Errorf("creation time %v, want %v", sk.CreationTime, created)
	}
}

func TestGoCryptoReadsTheWholeSecretKeyAsAKeyRingEntityWithItsPrivateKey(t *testing.T) {
	f := newSecretFixture(t)
	ring, err := pgp.ReadKeyRing(bytes.NewReader(f.secret))
	if err != nil {
		t.Fatalf("ReadKeyRing: %v", err)
	}
	if len(ring) != 1 || ring[0].PrivateKey == nil || ring[0].PrivateKey.Encrypted || len(ring[0].Subkeys) != 0 {
		t.Fatalf("the ring is not one entity with an unprotected primary and no subkey")
	}
	if got := hexLower(ring[0].PrimaryKey.Fingerprint); got != fingerprintOf(t, &f.signer.key.PublicKey, created) {
		t.Errorf("fingerprint %s", got)
	}
}

func TestTheCertificateAndTheKeyGoInUnchanged(t *testing.T) {
	f := newSecretFixture(t)
	certBefore := bytes.Clone(f.cert)
	dBefore := bytes.Clone(mustBytes(t, f.signer.key))
	if _, err := openpgp.SecretKey(f.cert, f.signer.key); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(certBefore, f.cert) || !bytes.Equal(dBefore, mustBytes(t, f.signer.key)) {
		t.Error("SecretKey changed what it was given")
	}
	digest := bytes.Repeat([]byte{7}, 48)
	sig, err := ecdsa.SignASN1(rand.Reader, f.signer.key, digest)
	if err != nil || !ecdsa.VerifyASN1(&f.signer.key.PublicKey, digest, sig) {
		t.Errorf("the key does not sign after SecretKey: %v", err)
	}
	secretBefore := bytes.Clone(f.secret)
	_, _, cert, err := openpgp.ParseSecretKey(f.secret)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cert {
		cert[i] ^= 0xFF
	}
	if !bytes.Equal(secretBefore, f.secret) {
		t.Error("ParseSecretKey returns a certificate that shares memory with its input")
	}
}

func TestAScalarWithLeadingZeroBitsAndAFullScalarBothRoundTrip(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 4000 && len(seen) < 3; i++ {
		s := newSigner(t)
		d := mustBytes(t, s.key)
		kind := 0
		switch {
		case d[0] == 0:
			kind = 1 // a whole leading zero byte: the integer has 47 bytes
		case d[0] < 0x80:
			kind = 2 // fewer than 8 leading bits: the bit length is not a multiple of 8
		default:
			kind = 3
		}
		if seen[kind] {
			continue
		}
		seen[kind] = true
		p := s.params()
		cert, err := openpgp.NewPrimary(rand.Reader, p)
		if err != nil {
			t.Fatal(err)
		}
		secret, err := openpgp.SecretKey(cert, s.key)
		if err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
		priv, _, _, err := openpgp.ParseSecretKey(secret)
		if err != nil || !priv.Equal(s.key) {
			t.Errorf("kind %d: round trip failed: %v", kind, err)
		}
	}
	if len(seen) < 3 {
		t.Skipf("only %d of 3 kinds of scalar came up in 4000 keys", len(seen))
	}
}

func TestACreationTimeOfAnyYearRoundTrips(t *testing.T) {
	for _, at := range []time.Time{time.Unix(1, 0).UTC(), created, time.Unix(1<<31-1, 0).UTC()} {
		s := newSigner(t)
		p := s.params()
		p.CreationTime = at
		p.CeremonyTime = at.Add(time.Hour)
		p.ExpiresAt = at.Add(24 * time.Hour)
		cert, err := openpgp.NewPrimary(rand.Reader, p)
		if err != nil {
			t.Logf("NewPrimary with creation time %v: %v", at, err)
			continue
		}
		secret, err := openpgp.SecretKey(cert, s.key)
		if err != nil {
			t.Fatalf("%v: %v", at, err)
		}
		_, got, _, err := openpgp.ParseSecretKey(secret)
		if err != nil || !got.Equal(at) {
			t.Errorf("creation time %v read back as %v (%v)", at, got, err)
		}
	}
}

func TestSecretKeyRefusesWhatIsNotTheKeyOfTheCertificateAndReturnsNothing(t *testing.T) {
	f := newSecretFixture(t)
	other := genKey(t)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	order := elliptic.P384().Params().N
	mixed := privateWith(f.signer.key.PublicKey, scalarOf(t, other))
	noCurve := privateWith(ecdsa.PublicKey{}, scalarOf(t, f.signer.key))
	noD := privateWith(f.signer.key.PublicKey, nil)
	zeroD := privateWith(f.signer.key.PublicKey, new(big.Int))
	bigD := privateWith(f.signer.key.PublicKey, new(big.Int).Set(order))
	negD := privateWith(f.signer.key.PublicKey, new(big.Int).Neg(scalarOf(t, f.signer.key)))

	cases := []struct {
		name string
		cert []byte
		priv *ecdsa.PrivateKey
	}{
		{"a nil key", f.cert, nil},
		{"a key with nothing in it", f.cert, &ecdsa.PrivateKey{}},
		{"a key with no curve", f.cert, noCurve},
		{"a key with no scalar", f.cert, noD},
		{"a scalar of zero", f.cert, zeroD},
		{"a scalar equal to the order of the group", f.cert, bigD},
		{"a negative scalar", f.cert, negD},
		{"a key on P-256", f.cert, p256},
		{"the private key of another key", f.cert, other},
		{"the point of this key and the scalar of another", f.cert, mixed},
		{"a nil certificate", nil, f.signer.key},
		{"an empty certificate", []byte{}, f.signer.key},
		{"a certificate of 100 bytes of junk", bytes.Repeat([]byte{0xA5}, 100), f.signer.key},
		{"a certificate with a trailing byte", append(bytes.Clone(f.cert), 0), f.signer.key},
		{"the secret key where a certificate is meant", f.secret, f.signer.key},
		{"a certificate of the other key", mustCert(t, other), f.signer.key},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := openpgp.SecretKey(c.cert, c.priv)
			if err == nil {
				t.Fatal("accepted")
			}
			if out != nil {
				t.Error("a refusal returned bytes")
			}
			if !errors.Is(err, openpgp.ErrParams) {
				t.Errorf("the error does not wrap ErrParams: %v", err)
			}
		})
	}
}

// privateWith builds a key object from its parts: the only way to make a key that crypto/ecdsa
// itself would not make (no scalar, a scalar of zero, no curve).
func privateWith(pub ecdsa.PublicKey, d *big.Int) *ecdsa.PrivateKey {
	//nolint:staticcheck // a hostile key object is built from its fields on purpose
	return &ecdsa.PrivateKey{PublicKey: pub, D: d}
}

// scalarOf is the scalar of a key as a number.
func scalarOf(t testing.TB, k *ecdsa.PrivateKey) *big.Int {
	t.Helper()
	return new(big.Int).SetBytes(mustBytes(t, k))
}

func mustCert(t testing.TB, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	s := &privateSigner{key: k}
	cert, err := openpgp.NewPrimary(rand.Reader, s.params())
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestSecretKeyRefusesACertificateThatIsNotExactlyKeyUserIDAndOneSelfSignature(t *testing.T) {
	f := newSecretFixture(t)
	ps := splitPackets(t, f.cert)
	extra, err := openpgp.ExtendPrimary(rand.Reader, f.signer.params())
	if err != nil {
		t.Fatal(err)
	}
	other := genKey(t)
	forgedSig := sigSpec{
		Type:     0x13,
		Hashed:   []sub{{Type: 2, Data: u32(uint32(ceremony.Unix()))}, {Type: 27, Data: []byte{1}}},
		Data:     selfSigData(&f.signer.key.PublicKey, created, string(ps[1].Body)),
		Key:      other, // not the key of the certificate
		Unhashed: nil,
	}.build(t)
	certification := sigSpec{
		Type:   0x10, // a generic certification, not the positive one of the profile
		Hashed: []sub{{Type: 2, Data: u32(uint32(ceremony.Unix()))}, {Type: 27, Data: []byte{1}}},
		Data:   selfSigData(&f.signer.key.PublicKey, created, string(ps[1].Body)),
		Key:    f.signer.key,
	}.build(t)
	subkey := newSubkey(t, &f.signer.key.PublicKey, created, subAt)
	cases := []struct {
		name string
		cert []byte
	}{
		{"the key and the user ID, no self-signature", append(bytes.Clone(ps[0].Raw), ps[1].Raw...)},
		{"the key alone", ps[0].Raw},
		{"two self-signatures", append(bytes.Clone(f.cert), extra...)},
		{"two user IDs", append(append(bytes.Clone(ps[0].Raw), ps[1].Raw...), append(bytes.Clone(ps[1].Raw), ps[2].Raw...)...)},
		{"a subkey after the signature", append(bytes.Clone(f.cert), subkey.Packet...)},
		{"a trust packet after the signature", append(bytes.Clone(f.cert), wrap(12, []byte{0})...)},
		{"a self-signature made by another key", append(append(bytes.Clone(ps[0].Raw), ps[1].Raw...), forgedSig...)},
		{"a generic certification in place of a positive one", append(append(bytes.Clone(ps[0].Raw), ps[1].Raw...), certification...)},
		{"the signature before the user ID", slicesConcat(ps[0].Raw, ps[2].Raw, ps[1].Raw)},
		{"a user ID that the signature does not cover", slicesConcat(ps[0].Raw, wrap(tagUserID, []byte("Example Test other <a@example.org>")), ps[2].Raw)},
		{"a public key packet with a five-byte length", slicesConcat(wrapLong(tagPublicKey, ps[0].Body), ps[1].Raw, ps[2].Raw)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := openpgp.SecretKey(c.cert, f.signer.key)
			if err == nil || out != nil {
				t.Fatalf("accepted: %v", err)
			}
			if !errors.Is(err, openpgp.ErrParams) {
				t.Errorf("the error does not wrap ErrParams: %v", err)
			}
		})
	}
}

func slicesConcat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestSecretKeyRefusesEveryCutOfTheCertificate(t *testing.T) {
	f := newSecretFixture(t)
	for n := 0; n < len(f.cert); n++ {
		if out, err := openpgp.SecretKey(f.cert[:n], f.signer.key); err == nil || out != nil {
			t.Fatalf("a certificate cut to %d of %d bytes is accepted", n, len(f.cert))
		}
	}
}

func TestParseSecretKeyRefusesEveryCutAndEveryTrailingByte(t *testing.T) {
	f := newSecretFixture(t)
	for n := 0; n < len(f.secret); n++ {
		requireSecretRefused(t, "cut to "+itoa(n), f.secret[:n])
	}
	for _, b := range []byte{0, 1, 0xC5, 0xFF} {
		requireSecretRefused(t, "one trailing byte", append(bytes.Clone(f.secret), b))
	}
	requireSecretRefused(t, "nil", nil)
	requireSecretRefused(t, "empty", []byte{})
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

// A bit that is flipped in the secret key packet changes what the packet says, so no single-bit
// change of it is read as a key.
func TestNoSingleBitChangeOfTheSecretKeyPacketIsAccepted(t *testing.T) {
	f := newSecretFixture(t)
	n := len(splitPackets(t, f.secret)[0].Raw)
	for i := 0; i < n; i++ {
		for bit := 0; bit < 8; bit++ {
			b := bytes.Clone(f.secret)
			b[i] ^= 1 << bit
			if _, _, _, err := openpgp.ParseSecretKey(b); err == nil {
				t.Errorf("byte %d bit %d of the secret key packet changed: accepted", i, bit)
			}
		}
	}
}

// A bit that is flipped in the user ID or in the hashed part of the self-signature changes what
// the signature covers. The unhashed area is not covered by it and may change without the
// signature failing, which is how every OpenPGP reader treats it.
func TestNoSingleBitChangeOfTheUserIDOrTheHashedPartOfTheSignatureIsAccepted(t *testing.T) {
	f := newSecretFixture(t)
	ps := splitPackets(t, f.secret)
	start := len(ps[0].Raw)
	sig := ps[2]
	sigStart := start + len(ps[1].Raw)
	hashedEnd := sigStart + sig.HeaderLen + 6 + int(sig.Body[4])<<8 + int(sig.Body[5])
	for i := start; i < hashedEnd; i++ {
		for bit := 0; bit < 8; bit++ {
			b := bytes.Clone(f.secret)
			b[i] ^= 1 << bit
			if _, _, _, err := openpgp.ParseSecretKey(b); err == nil {
				t.Errorf("byte %d bit %d (user ID or hashed part) changed: accepted", i, bit)
			}
		}
	}
}

func TestParseSecretKeyRefusesWhatTheProfileDoesNot(t *testing.T) {
	f := newSecretFixture(t)
	ps := splitPackets(t, f.secret)
	body := ps[0].Body
	rest := f.secret[len(ps[0].Raw):]
	p256OID := []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	other := genKey(t)

	with := func(fn func(b []byte) []byte) []byte { return secretRebuild(t, f.secret, fn) }
	cases := []struct {
		name string
		data []byte
	}{
		// S2K usage
		{"S2K usage 254", with(func(b []byte) []byte { b[secretUsageAt] = 254; return b })},
		{"S2K usage 255", with(func(b []byte) []byte { b[secretUsageAt] = 255; return b })},
		{"S2K usage 1", with(func(b []byte) []byte { b[secretUsageAt] = 1; return b })},
		{"S2K usage 253", with(func(b []byte) []byte { b[secretUsageAt] = 253; return b })},
		// the checksum
		{"a wrong checksum (last byte)", with(func(b []byte) []byte { b[len(b)-1] ^= 1; return b })},
		{"a wrong checksum (first byte)", with(func(b []byte) []byte { b[len(b)-2] ^= 1; return b })},
		{"no checksum", with(func(b []byte) []byte { return b[:len(b)-2] })},
		{"a one-byte checksum", with(func(b []byte) []byte { return b[:len(b)-1] })},
		{"a checksum and a byte", with(func(b []byte) []byte { return append(b, 0) })},
		// the public part
		{"a version 5 key", with(func(b []byte) []byte { b[0] = 5; return b })},
		{"a version 3 key", with(func(b []byte) []byte { b[0] = 3; return b })},
		{"an RSA key", with(func(b []byte) []byte { b[5] = 1; return b })},
		{"an EdDSA key", with(func(b []byte) []byte { b[5] = 22; return b })},
		{"an ECDH key", with(func(b []byte) []byte { b[5] = 18; return b })},
		{"a DSA key", with(func(b []byte) []byte { b[5] = 17; return b })},
		{"the OID of P-256", with(func(b []byte) []byte {
			out := append(bytes.Clone(b[:6]), byte(len(p256OID)))
			out = append(out, p256OID...)
			return append(out, b[6+1+5:]...)
		})},
		{"the OID of P-384 with a changed byte", with(func(b []byte) []byte { b[10] ^= 1; return b })},
		{"a point of 96 bytes", with(func(b []byte) []byte {
			return append(bytes.Clone(b[:secretPubLen-1]), b[secretPubLen:]...)
		})},
		{"a point that is not on the curve", with(func(b []byte) []byte { b[secretPubLen-1] ^= 1; return b })},
		{"a compressed point marker", with(func(b []byte) []byte { b[14] = 2; return b })},
		// the scalar
		{"the scalar of another key", with(func(b []byte) []byte {
			return secretWithScalar(b, new(big.Int).SetBytes(mustBytes(t, other)))
		})},
		{"a scalar equal to the order", with(func(b []byte) []byte {
			return secretWithScalar(b, elliptic.P384().Params().N)
		})},
		{"a scalar of 1", with(func(b []byte) []byte { return secretWithScalar(b, big.NewInt(1)) })},
		{"a scalar of 49 bytes", with(func(b []byte) []byte {
			return secretWithScalar(b, new(big.Int).Lsh(big.NewInt(1), 8*48))
		})},
		{"a multiprecision integer with a leading zero byte", with(func(b []byte) []byte {
			m := b[secretScalarAt : len(b)-2]
			out := bytes.Clone(b[:secretScalarAt])
			out = append(out, m[:2]...)
			out = append(out, 0)
			out = append(out, m[2:]...)
			return append(out, b[len(b)-2:]...) // the checksum is now wrong too: both are refused
		})},
		{"a multiprecision integer of bit length zero", with(func(b []byte) []byte {
			out := bytes.Clone(b[:secretScalarAt])
			out = append(out, 0, 0)
			return append(out, 0, 0)
		})},
		{"a bit length that is too large for the bytes", with(func(b []byte) []byte {
			b[secretScalarAt+1] += 8
			return b
		})},
		// the framing
		{"an old-format header", append(append([]byte{0x80 | 5<<2, byte(len(body))}, body...), rest...)},
		{"a five-byte length where one byte is enough", append(wrapLong(5, body), rest...)},
		{"a partial length", append(append([]byte{0xC5, 0xE0 | 7}, body[:128]...), append([]byte{byte(len(body) - 128)}, append(bytes.Clone(body[128:]), rest...)...)...)},
		{"an indeterminate length", append(append([]byte{0x80 | 5<<2 | 3}, body...), rest...)},
		{"a secret subkey packet in place of the primary", append(wrap(7, body), rest...)},
		{"a public key packet in place of the secret key packet", append(wrap(tagPublicKey, body), rest...)},
		{"the secret key packet with the high bit clear", append([]byte{0x45, byte(len(body))}, append(bytes.Clone(body), rest...)...)},
		// what follows
		{"a second secret key packet", append(bytes.Clone(f.secret), ps[0].Raw...)},
		{"a subkey after the signature", append(bytes.Clone(f.secret), wrap(14, body[:secretPubLen])...)},
		{"a secret subkey after the signature", append(bytes.Clone(f.secret), wrap(7, body)...)},
		{"a trust packet after the signature", append(bytes.Clone(f.secret), wrap(12, []byte{0})...)},
		{"a second user ID", slicesConcat(ps[0].Raw, ps[1].Raw, ps[1].Raw, ps[2].Raw)},
		{"a second signature", append(bytes.Clone(f.secret), ps[2].Raw...)},
		{"no signature", f.secret[:len(ps[0].Raw)+len(ps[1].Raw)]},
		{"no user ID and no signature", ps[0].Raw},
		{"the signature before the user ID", slicesConcat(ps[0].Raw, ps[2].Raw, ps[1].Raw)},
		{"the certificate (a public key) instead of a secret key", f.cert},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { requireSecretRefused(t, c.name, c.data) })
	}
}

// The packets of a secret key that has no user ID are not a transferable secret key of the page.
func TestParseSecretKeyNeverPanicsOnShortAndOddInput(t *testing.T) {
	f := newSecretFixture(t)
	inputs := [][]byte{nil, {}, {0}, {0xC5}, {0xC5, 0}, {0xC5, 0xFF}, {0xC5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, {0xFF, 0xFF}, {0x94, 0x05, 1, 2, 3, 4, 5}}
	inputs = append(inputs, bytes.Repeat([]byte{0xC5}, 300), bytes.Repeat([]byte{0}, 300), bytes.Repeat([]byte{0xFF}, 70000))
	for i := 1; i < len(f.secret); i += 7 {
		inputs = append(inputs, f.secret[i:])
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d (%d bytes) panics: %v", i, len(in), r)
				}
			}()
			if priv, _, _, err := openpgp.ParseSecretKey(in); err == nil || priv != nil {
				t.Errorf("input %d is accepted", i)
			}
		}()
	}
}

func TestTheTextOfARefusalHoldsNoKeyByteAndNoInputText(t *testing.T) {
	f := newSecretFixture(t)
	d := mustBytes(t, f.signer.key)
	for _, data := range [][]byte{
		secretRebuild(t, f.secret, func(b []byte) []byte { b[len(b)-1] ^= 1; return b }),
		secretRebuild(t, f.secret, func(b []byte) []byte { b[secretUsageAt] = 254; return b }),
		f.secret[:len(f.secret)-3],
	} {
		_, _, _, err := openpgp.ParseSecretKey(data)
		if err == nil {
			t.Fatal("accepted")
		}
		text := err.Error()
		for _, form := range []string{string(d), hexLower(d), strings.ToUpper(hexLower(d))} {
			if strings.Contains(text, form) {
				t.Errorf("the error text holds the scalar: %q", text)
			}
		}
	}
	for _, bad := range []*ecdsa.PrivateKey{nil, {}, privateWith(ecdsa.PublicKey{}, scalarOf(t, f.signer.key))} {
		_, err := openpgp.SecretKey(f.cert, bad)
		if err == nil {
			t.Fatal("accepted")
		}
		if strings.Contains(err.Error(), hexLower(d)) {
			t.Errorf("the error text holds the scalar: %q", err.Error())
		}
	}
}

func FuzzParseSecretKey(f *testing.F) {
	fx := newSecretFixture(f)
	f.Add(fx.secret)
	f.Add(fx.cert)
	f.Add(fx.secret[:len(fx.secret)/2])
	f.Add([]byte{})
	f.Add([]byte{0xC5, 0x00})
	f.Add(secretRebuild(f, fx.secret, func(b []byte) []byte { b[secretUsageAt] = 254; return b }))
	f.Add(secretRebuild(f, fx.secret, func(b []byte) []byte { b[len(b)-1] ^= 1; return b }))
	f.Add(append(bytes.Clone(fx.secret), fx.cert...))
	f.Fuzz(func(t *testing.T, data []byte) {
		priv, at, cert, err := openpgp.ParseSecretKey(data)
		if err != nil {
			if priv != nil || !at.IsZero() || cert != nil {
				t.Fatal("an error with a value")
			}
			if !errors.Is(err, openpgp.ErrSecretKey) {
				t.Fatalf("an error that does not wrap ErrSecretKey: %v", err)
			}
			return
		}
		// An accepted input is exactly what SecretKey writes: writing it again gives the same bytes.
		again, err := openpgp.SecretKey(cert, priv)
		if err != nil {
			t.Fatalf("an accepted input cannot be written again: %v", err)
		}
		if !bytes.Equal(again, data) {
			t.Fatalf("an accepted input is not canonical: %d bytes in, %d bytes written again", len(data), len(again))
		}
		if at.IsZero() || priv.Curve != elliptic.P384() {
			t.Fatal("an accepted input gives no time or a wrong curve")
		}
	})
}
