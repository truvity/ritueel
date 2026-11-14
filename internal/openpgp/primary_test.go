package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"slices"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"

	"ritueel.id/ritueel/internal/openpgp"
)

// selfSigData is what the self-signature of a user ID covers before its own fields.
func selfSigData(pub *ecdsa.PublicKey, at time.Time, uid string) [][]byte {
	n := len(uid)
	return [][]byte{hashPrefix(pub, at), {0xB4, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, []byte(uid)}
}

// newPrimary builds a certificate with a signer of the tests and splits it into packets.
func newPrimary(t testing.TB) (*privateSigner, openpgp.PrimaryParams, []byte, []packet) {
	t.Helper()
	s := newSigner(t)
	p := s.params()
	cert, err := openpgp.NewPrimary(rand.Reader, p)
	if err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	return s, p, cert, splitPackets(t, cert)
}

func TestTheCertificateOfAPrimaryIsTheKeyThenTheUserIDThenTheSelfSignature(t *testing.T) {
	s, p, _, ps := newPrimary(t)
	if got := tags(ps); !bytes.Equal(got, []byte{tagPublicKey, tagUserID, tagSignature}) {
		t.Fatalf("packet tags % d, want 6 13 2", got)
	}
	if got, want := ps[0].Body, keyBody(&s.key.PublicKey, created); !bytes.Equal(got, want) {
		t.Errorf("the key packet body is % x, want % x", got, want)
	}
	if string(ps[1].Body) != p.UserID {
		t.Errorf("the user ID packet holds %q, want %q", ps[1].Body, p.UserID)
	}
}

// The profile of the page row by row: type 0x13, SHA-384, ECDSA; hashed 2, 27, 9 (critical), 33;
// unhashed 16.
func TestTheSelfSignatureHasTheSubpacketsOfThePageInTheOrderOfThePage(t *testing.T) {
	s, p, _, ps := newPrimary(t)
	sig := parseSig(t, ps[2].Body)
	if sig.Version != 4 || sig.Type != 0x13 || sig.Algo != 19 || sig.Hash != 9 {
		t.Errorf("version %d type %#x algorithm %d hash %d, want 4, 0x13, 19, 9", sig.Version, sig.Type, sig.Algo, sig.Hash)
	}
	if got := types(sig.Hashed); !bytes.Equal(got, []byte{2, 27, 9, 33}) {
		t.Errorf("hashed subpacket types % d, want 2 27 9 33", got)
	}
	if got := types(sig.Unhashed); !bytes.Equal(got, []byte{16}) {
		t.Errorf("unhashed subpacket types % d, want 16", got)
	}
	if got := critical(sig.Hashed); !bytes.Equal(got, []byte{9}) {
		t.Errorf("critical hashed subpackets % d, want only 9 (the key expiration time)", got)
	}
	if got := critical(sig.Unhashed); len(got) != 0 {
		t.Errorf("critical unhashed subpackets % d, want none", got)
	}
	fp := fingerprint(&s.key.PublicKey, created)
	if got := find(t, sig.Hashed, 2).Data; !bytes.Equal(got, u32(uint32(p.CeremonyTime.Unix()))) {
		t.Errorf("signature creation time % x, want the ceremony time", got)
	}
	if got := find(t, sig.Hashed, 27).Data; !bytes.Equal(got, []byte{0x01}) {
		t.Errorf("key flags % x, want 01 (certify only)", got)
	}
	if got := find(t, sig.Hashed, 33).Data; !bytes.Equal(got, append([]byte{4}, fp...)) {
		t.Errorf("issuer fingerprint % x, want version 4 and the fingerprint of the primary", got)
	}
	if got := find(t, sig.Unhashed, 16).Data; !bytes.Equal(got, fp[12:]) {
		t.Errorf("issuer key ID % x, want the last eight bytes of the fingerprint", got)
	}
}

// The key expiration time counts from the creation of the key, not from the ceremony, so that the
// key ends at ExpiresAt (the page: "36 calendar months after the ceremony").
func TestTheKeyExpiresAtTheInstantGivenCountedFromTheCreationOfTheKey(t *testing.T) {
	_, p, _, ps := newPrimary(t)
	sig := parseSig(t, ps[2].Body)
	life := binary.BigEndian.Uint32(find(t, sig.Hashed, 9).Data)
	if got := created.Add(time.Duration(life) * time.Second); !got.Equal(p.ExpiresAt) {
		t.Errorf("created + %d s = %v, want %v", life, got, p.ExpiresAt)
	}
	if life == uint32(p.ExpiresAt.Sub(p.CeremonyTime)/time.Second) {
		t.Error("the expiry was counted from the ceremony time")
	}
}

func TestTheKeyExpiresThirtySixCalendarMonthsAfterTheCeremony(t *testing.T) {
	s := newSigner(t)
	p := s.params()
	p.ExpiresAt = time.Date(2029, 11, 15, 12, 0, 0, 0, time.UTC)
	cert, err := openpgp.NewPrimary(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	sig := parseSig(t, splitPackets(t, cert)[2].Body)
	life := binary.BigEndian.Uint32(find(t, sig.Hashed, 9).Data)
	if got := created.Add(time.Duration(life) * time.Second); !got.Equal(time.Date(2029, 11, 15, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("the key ends at %v, want 2029-11-15 12:00:00 UTC", got)
	}
}

// The signature is a signature by the standard: the tests check it with their own hash and the
// ECDSA check of the standard library.
func TestTheSelfSignatureVerifiesByTheFormulaOfTheStandard(t *testing.T) {
	s, p, _, ps := newPrimary(t)
	if !verifySig(t, &s.key.PublicKey, ps[2].Body, selfSigData(&s.key.PublicKey, created, p.UserID)...) {
		t.Error("the self-signature does not verify over the key and the user ID")
	}
	if verifySig(t, &s.key.PublicKey, ps[2].Body, selfSigData(&s.key.PublicKey, created, p.UserID+"x")...) {
		t.Error("the self-signature verifies over another user ID")
	}
	if verifySig(t, &genKey(t).PublicKey, ps[2].Body, selfSigData(&s.key.PublicKey, created, p.UserID)...) {
		t.Error("the self-signature verifies with another key")
	}
}

// A second reader: go-crypto reads the certificate as a key ring and checks the self-signature.
func TestAnotherReaderTakesTheCertificateAsAKeyWithOneUserID(t *testing.T) {
	s, p, cert, _ := newPrimary(t)
	ring, err := pgp.ReadKeyRing(bytes.NewReader(cert))
	if err != nil {
		t.Fatalf("ReadKeyRing: %v", err)
	}
	if len(ring) != 1 || len(ring[0].Identities) != 1 || len(ring[0].Subkeys) != 0 {
		t.Fatalf("%d keys, want one key with one user ID and no subkey", len(ring))
	}
	e := ring[0]
	if _, ok := e.Identities[p.UserID]; !ok {
		t.Errorf("the identities are %v, want %q", e.Identities, p.UserID)
	}
	if got, want := hexLower(e.PrimaryKey.Fingerprint), fingerprintOf(t, &s.key.PublicKey, created); got != want {
		t.Errorf("fingerprint %s, want %s", got, want)
	}
	self := e.Identities[p.UserID].SelfSignature
	if self.KeyLifetimeSecs == nil || !self.FlagCertify || self.FlagSign || self.FlagEncryptStorage {
		t.Errorf("flags or lifetime of the self-signature are not as built: %+v", self)
	}
	if !self.CreationTime.Equal(ceremony) {
		t.Errorf("the self-signature is from %v, want %v", self.CreationTime, ceremony)
	}
}

// The layout of the vector primary: the same tags, the same subpacket types in the same order, the
// same critical bits, and the hashed area byte for byte the same except the issuer fingerprint,
// which depends on the key.
func TestTheSelfSignatureIsTheSelfSignatureOfTheVectorExceptForTheFingerprint(t *testing.T) {
	_, vps := vectorPrimary(t, "a")
	vs := parseSig(t, vps[2].Body)
	// The vector: key created 2026-01-01, ceremony one second later, 1096 days of life.
	vlife := binary.BigEndian.Uint32(find(t, vs.Hashed, 9).Data)
	vcreated := time.Unix(int64(binary.BigEndian.Uint32(vps[0].Body[1:5])), 0).UTC()
	vceremony := time.Unix(int64(binary.BigEndian.Uint32(find(t, vs.Hashed, 2).Data)), 0).UTC()

	s := newSigner(t)
	p := openpgp.PrimaryParams{
		Key:          s,
		CreationTime: vcreated,
		CeremonyTime: vceremony,
		ExpiresAt:    vcreated.Add(time.Duration(vlife) * time.Second),
		UserID:       string(vps[1].Body),
	}
	cert, err := openpgp.NewPrimary(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	ps := splitPackets(t, cert)
	if !bytes.Equal(tags(ps), tags(vps)) {
		t.Fatalf("tags % d, the vector has % d", tags(ps), tags(vps))
	}
	if !bytes.Equal(ps[0].Body[:12], vps[0].Body[:12]) {
		t.Errorf("the key packet starts % x, the vector's starts % x", ps[0].Body[:12], vps[0].Body[:12])
	}
	if !bytes.Equal(ps[1].Body, vps[1].Body) {
		t.Errorf("user ID %q, the vector has %q", ps[1].Body, vps[1].Body)
	}
	sig := parseSig(t, ps[2].Body)
	if sig.Version != vs.Version || sig.Type != vs.Type || sig.Algo != vs.Algo || sig.Hash != vs.Hash {
		t.Errorf("fields %d %#x %d %d, the vector has %d %#x %d %d", sig.Version, sig.Type, sig.Algo, sig.Hash, vs.Version, vs.Type, vs.Algo, vs.Hash)
	}
	if !bytes.Equal(types(sig.Hashed), types(vs.Hashed)) || !bytes.Equal(critical(sig.Hashed), critical(vs.Hashed)) {
		t.Errorf("hashed types % d critical % d, the vector has % d and % d", types(sig.Hashed), critical(sig.Hashed), types(vs.Hashed), critical(vs.Hashed))
	}
	if !bytes.Equal(types(sig.Unhashed), types(vs.Unhashed)) || !bytes.Equal(critical(sig.Unhashed), critical(vs.Unhashed)) {
		t.Errorf("unhashed types % d, the vector has % d", types(sig.Unhashed), types(vs.Unhashed))
	}
	if len(sig.HashedRaw) != len(vs.HashedRaw) || len(sig.UnhashedRaw) != len(vs.UnhashedRaw) {
		t.Errorf("area lengths %d and %d, the vector has %d and %d", len(sig.HashedRaw), len(sig.UnhashedRaw), len(vs.HashedRaw), len(vs.UnhashedRaw))
	}
	for i, x := range sig.Hashed {
		if x.Type == 33 {
			continue
		}
		if !bytes.Equal(x.Data, vs.Hashed[i].Data) {
			t.Errorf("hashed subpacket %d (type %d) holds % x, the vector's holds % x", i, x.Type, x.Data, vs.Hashed[i].Data)
		}
	}
}

// Errors: no bytes come back, and the signer is not asked when a parameter is refused.
func TestAParameterThatIsRefusedGivesNoBytesAndNoRequestToTheSigner(t *testing.T) {
	good := func() (*privateSigner, openpgp.PrimaryParams) {
		s := newSigner(t)
		return s, s.params()
	}
	cases := []struct {
		name string
		mod  func(s *privateSigner, p *openpgp.PrimaryParams)
	}{
		{"the creation time has a fraction of a second", func(_ *privateSigner, p *openpgp.PrimaryParams) { p.CreationTime = created.Add(time.Nanosecond) }},
		{"the ceremony time has a fraction of a second", func(_ *privateSigner, p *openpgp.PrimaryParams) { p.CeremonyTime = ceremony.Add(time.Millisecond) }},
		{"the expiry has a fraction of a second", func(_ *privateSigner, p *openpgp.PrimaryParams) { p.ExpiresAt = p.ExpiresAt.Add(time.Microsecond) }},
		{"the ceremony is before the creation of the key", func(_ *privateSigner, p *openpgp.PrimaryParams) { p.CeremonyTime = created.Add(-time.Second) }},
		{"the expiry equals the ceremony", func(_ *privateSigner, p *openpgp.PrimaryParams) { p.ExpiresAt = p.CeremonyTime }},
		{"the expiry is before the ceremony", func(_ *privateSigner, p *openpgp.PrimaryParams) { p.ExpiresAt = p.CeremonyTime.Add(-time.Hour) }},
		{"the expiry is after the year 2106", func(_ *privateSigner, p *openpgp.PrimaryParams) { p.ExpiresAt = time.Unix(1<<32, 0) }},
		{"the creation time is the zero time", func(_ *privateSigner, p *openpgp.PrimaryParams) { p.CreationTime = time.Time{} }},
		{"the ceremony time is after the year 2106", func(_ *privateSigner, p *openpgp.PrimaryParams) { p.CeremonyTime = time.Unix(1<<32, 0) }},
		{"the creation time is before 1970", func(_ *privateSigner, p *openpgp.PrimaryParams) { p.CreationTime = time.Unix(-1, 0) }},
		{"there is no key", func(_ *privateSigner, p *openpgp.PrimaryParams) { p.Key = nil }},
		{"the key is a typed nil", func(_ *privateSigner, p *openpgp.PrimaryParams) { var k *ecdsa.PrivateKey; p.Key = k }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, p := good()
			c.mod(s, &p)
			assertRefused(t, "NewPrimary", func() ([]byte, error) { return openpgp.NewPrimary(nil, p) }, openpgp.ErrParams)
			assertRefused(t, "ExtendPrimary", func() ([]byte, error) { return openpgp.ExtendPrimary(nil, p) }, openpgp.ErrParams)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times", s.calls)
			}
		})
	}
}

func TestAKeyThatIsNotAnEcdsaKeyOnP384IsRefused(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A public key of the right type whose point is not on the curve.
	off := offCurve(t)
	cases := []struct {
		name string
		key  crypto.Signer
	}{
		{"ECDSA on P-256", p256},
		{"ECDSA on P-521", p521},
		{"RSA", rsaKey},
		{"Ed25519", edKey},
		{"a signer whose public key is nil", fixedPublic{nil}},
		{"a signer whose public key is not a key", fixedPublic{"not a key"}},
		{"a signer with a point that is not on the curve", fixedPublic{off}},
		{"a signer with a nil ECDSA key", fixedPublic{(*ecdsa.PublicKey)(nil)}},
		{"a signer with a key on P-384 that holds no point", fixedPublic{&ecdsa.PublicKey{Curve: elliptic.P384()}}},
		{"a signer with a key on P-384 that holds only the abscissa", fixedPublic{abscissaOnly(t)}},
		{"a signer with a key on P-384 that holds only the ordinate", fixedPublic{ordinateOnly(t)}},
		{"a signer with a key that has no curve", fixedPublic{&ecdsa.PublicKey{}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newSigner(t).params()
			p.Key = c.key
			assertRefused(t, "NewPrimary", func() ([]byte, error) { return openpgp.NewPrimary(nil, p) }, openpgp.ErrParams)
			assertRefused(t, "ExtendPrimary", func() ([]byte, error) { return openpgp.ExtendPrimary(nil, p) }, openpgp.ErrParams)
			rev := func() ([]byte, error) { return openpgp.RevocationSignature(nil, p, openpgp.Compromised) }
			assertRefused(t, "RevocationSignature", rev, openpgp.ErrParams)
		})
	}
}

// A Go key is a crypto.Signer too, and so is a type that holds the scalar privately.
func TestAGoKeyAndAPrivateSignerBuildTheSameShape(t *testing.T) {
	k := genKey(t)
	p := openpgp.PrimaryParams{Key: k, CreationTime: created, CeremonyTime: ceremony, ExpiresAt: ceremony.AddDate(3, 0, 0), UserID: "Acme Release Root A <a@example.org>"}
	a, err := openpgp.NewPrimary(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	ps := &privateSigner{key: k}
	p.Key = ps
	b, err := openpgp.NewPrimary(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	pa, pb := splitPackets(t, a), splitPackets(t, b)
	sa, sb := parseSig(t, pa[2].Body), parseSig(t, pb[2].Body)
	if !bytes.Equal(pa[0].Raw, pb[0].Raw) || !bytes.Equal(sa.HashedRaw, sb.HashedRaw) || !bytes.Equal(sa.UnhashedRaw, sb.UnhashedRaw) {
		t.Error("a Go key and a private signer with the same key give different packets")
	}
	if ps.calls != 1 {
		t.Errorf("the private signer was asked %d times, want once", ps.calls)
	}
}

// The signer is given the SHA-384 digest and the hash named crypto.SHA384; it never sees the data.
func TestTheSignerIsGivenTheSHA384DigestAndTheHashSHA384(t *testing.T) {
	s, p, _, ps := newPrimary(t)
	if s.calls != 1 {
		t.Fatalf("the signer was asked %d times, want once", s.calls)
	}
	if s.hashes[0].HashFunc() != crypto.SHA384 {
		t.Errorf("the hash named is %v, want SHA-384", s.hashes[0].HashFunc())
	}
	sig := parseSig(t, ps[2].Body)
	trailer := append([]byte{4, 0xFF}, u32(uint32(len(sig.Fields)))...)
	h := sha512.New384()
	for _, d := range selfSigData(&s.key.PublicKey, created, p.UserID) {
		h.Write(d)
	}
	h.Write(sig.Fields)
	h.Write(trailer)
	want := h.Sum(nil)
	if !bytes.Equal(s.digests[0], want) {
		t.Errorf("the signer was given % x, want the SHA-384 of the signed data % x", s.digests[0], want)
	}
	if len(s.digests[0]) != 48 {
		t.Errorf("the digest has %d bytes, want 48", len(s.digests[0]))
	}
	if !bytes.Equal(sig.Tag, want[:2]) {
		t.Errorf("the left 16 bits of the digest are % x, want % x", sig.Tag, want[:2])
	}
}

// A signer that wipes the digest it was given after it signed must not harm the result: the
// builder verifies against its own digest, not the one it lent out.
func TestASignerThatWipesTheDigestItWasGivenDoesNotSpoilTheResult(t *testing.T) {
	s := newSigner(t)
	s.sign = func(d []byte) ([]byte, error) {
		sig, err := ecdsa.SignASN1(rand.Reader, s.key, d)
		clear(d)
		return sig, err
	}
	cert, err := openpgp.NewPrimary(nil, s.params())
	if err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	ps := splitPackets(t, cert)
	if !verifySig(t, &s.key.PublicKey, ps[2].Body, selfSigData(&s.key.PublicKey, created, s.params().UserID)...) {
		t.Error("the self-signature does not verify")
	}
}

// Same parameters, same hashed data and same digest. The signature bytes may differ, because
// ECDSA draws a random number.
func TestTheSameParametersGiveTheSameHashedDataAndTheSameDigest(t *testing.T) {
	s := newSigner(t)
	p := s.params()
	a, err := openpgp.NewPrimary(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := openpgp.NewPrimary(rand.Reader, p)
	if err != nil {
		t.Fatal(err)
	}
	pa, pb := splitPackets(t, a), splitPackets(t, b)
	sa, sb := parseSig(t, pa[2].Body), parseSig(t, pb[2].Body)
	if !bytes.Equal(pa[0].Raw, pb[0].Raw) || !bytes.Equal(pa[1].Raw, pb[1].Raw) {
		t.Error("the key or the user ID packet differs between two runs")
	}
	if !bytes.Equal(sa.Fields, sb.Fields) || !bytes.Equal(sa.UnhashedRaw, sb.UnhashedRaw) {
		t.Error("the hashed data differs between two runs")
	}
	if !bytes.Equal(s.digests[0], s.digests[1]) {
		t.Error("the digest differs between two runs")
	}
}

func TestTheHashedDataChangesWithEachParameter(t *testing.T) {
	base := newSigner(t)
	build := func(mod func(p *openpgp.PrimaryParams)) []byte {
		p := base.params()
		mod(&p)
		cert, err := openpgp.NewPrimary(nil, p)
		if err != nil {
			t.Fatal(err)
		}
		return parseSig(t, splitPackets(t, cert)[2].Body).Fields
	}
	ref := build(func(*openpgp.PrimaryParams) {})
	cases := map[string]func(p *openpgp.PrimaryParams){
		"the ceremony time": func(p *openpgp.PrimaryParams) { p.CeremonyTime = p.CeremonyTime.Add(time.Second) },
		"the expiry":        func(p *openpgp.PrimaryParams) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
		"the creation time": func(p *openpgp.PrimaryParams) { p.CreationTime = p.CreationTime.Add(time.Second) },
	}
	for name, mod := range cases {
		if bytes.Equal(ref, build(mod)) {
			t.Errorf("the hashed data does not change with %s", name)
		}
	}
}

// ExtendPrimary: "each use extends it, with a new self-signature of the same shape at the
// ceremony time".
func TestExtendingGivesOneSelfSignatureOfTheSameShapeAtTheNewCeremonyTime(t *testing.T) {
	s, p, _, ps := newPrimary(t)
	first := parseSig(t, ps[2].Body)

	later := p
	later.CeremonyTime = ceremony.Add(24 * time.Hour)
	later.ExpiresAt = later.CeremonyTime.AddDate(3, 0, 0)
	ext, err := openpgp.ExtendPrimary(rand.Reader, later)
	if err != nil {
		t.Fatal(err)
	}
	eps := splitPackets(t, ext)
	if len(eps) != 1 || eps[0].Tag != tagSignature {
		t.Fatalf("ExtendPrimary returned packets with tags % d, want one signature", tags(eps))
	}
	got := parseSig(t, eps[0].Body)
	if got.Type != 0x13 || got.Algo != 19 || got.Hash != 9 {
		t.Errorf("type %#x algorithm %d hash %d", got.Type, got.Algo, got.Hash)
	}
	if !bytes.Equal(types(got.Hashed), types(first.Hashed)) || !bytes.Equal(critical(got.Hashed), critical(first.Hashed)) ||
		!bytes.Equal(types(got.Unhashed), types(first.Unhashed)) {
		t.Errorf("shape differs: hashed % d critical % d unhashed % d", types(got.Hashed), critical(got.Hashed), types(got.Unhashed))
	}
	if d := find(t, got.Hashed, 2).Data; !bytes.Equal(d, u32(uint32(later.CeremonyTime.Unix()))) {
		t.Errorf("creation time % x, want the new ceremony time", d)
	}
	life := binary.BigEndian.Uint32(find(t, got.Hashed, 9).Data)
	if end := created.Add(time.Duration(life) * time.Second); !end.Equal(later.ExpiresAt) {
		t.Errorf("the key ends at %v, want %v", end, later.ExpiresAt)
	}
	if !verifySig(t, &s.key.PublicKey, eps[0].Body, selfSigData(&s.key.PublicKey, created, p.UserID)...) {
		t.Error("the new self-signature does not verify")
	}
	if !bytes.Equal(find(t, got.Hashed, 33).Data, find(t, first.Hashed, 33).Data) || !bytes.Equal(find(t, got.Unhashed, 16).Data, find(t, first.Unhashed, 16).Data) {
		t.Error("the issuer subpackets differ from those of the first self-signature")
	}
}

// A certificate with the extension after the self-signature reads as one key whose newest
// self-signature gives the expiry.
func TestAnotherReaderTakesTheNewestSelfSignatureForTheExpiry(t *testing.T) {
	_, p, cert, _ := newPrimary(t)
	later := p
	later.CeremonyTime = ceremony.Add(48 * time.Hour)
	later.ExpiresAt = later.CeremonyTime.AddDate(3, 0, 0)
	ext, err := openpgp.ExtendPrimary(nil, later)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := pgp.ReadKeyRing(bytes.NewReader(slices.Concat(cert, ext)))
	if err != nil {
		t.Fatal(err)
	}
	self := ring[0].Identities[p.UserID].SelfSignature
	if !self.CreationTime.Equal(later.CeremonyTime) {
		t.Errorf("the self-signature taken is from %v, want the one from %v", self.CreationTime, later.CeremonyTime)
	}
	if end := created.Add(time.Duration(*self.KeyLifetimeSecs) * time.Second); !end.Equal(later.ExpiresAt) {
		t.Errorf("the key ends at %v, want %v", end, later.ExpiresAt)
	}
}

func TestNilRandomnessMeansTheSystemSource(t *testing.T) {
	s := newSigner(t)
	if _, err := openpgp.NewPrimary(nil, s.params()); err != nil {
		t.Errorf("NewPrimary with a nil reader: %v", err)
	}
}
