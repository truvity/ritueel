package openpgp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// The helpers of the tests of the readers of a revocation signature
// (docs/reference/revocation-material.md, "What is made"). They write signatures by hand, with the
// tests' own signer and packet writer, so that the code under test never made or read its own input.

// revKit is a primary and what a revocation signature of it is made of. spec gives the signature that
// RevocationSignature writes, as a spec the test may change; the signature is made over the true
// digest, so a changed spec still verifies and only the change is what a reader refuses.
type revKit struct {
	key     *ecdsa.PrivateKey
	primary *openpgp.PrimaryKey
	fp      []byte // the 20 bytes of the fingerprint
}

// newRevKit makes a kit from a key made out of a label, so that a fuzz target has the same primary in every
// process.
func newRevKit(t testing.TB, label string) revKit {
	t.Helper()
	return revKitOf(t, fixedKey(t, "revocation "+label))
}

func revKitOf(t testing.TB, key *ecdsa.PrivateKey) revKit {
	t.Helper()
	pk, err := openpgp.NewPrimaryKey(&key.PublicKey, created)
	if err != nil {
		t.Fatalf("NewPrimaryKey: %v", err)
	}
	return revKit{key: key, primary: pk, fp: fingerprint(&key.PublicKey, created)}
}

// params are the parameters that RevocationSignature takes for the kit.
func (k revKit) params() openpgp.PrimaryParams {
	return openpgp.PrimaryParams{
		Key: k.key, CreationTime: created, CeremonyTime: ceremony, ExpiresAt: ceremony.AddDate(3, 0, 0),
		UserID: exampleUserID(true),
	}
}

// made is the signature that RevocationSignature writes for a reason.
func (k revKit) made(t testing.TB, r openpgp.Reason) []byte {
	t.Helper()
	sig, err := openpgp.RevocationSignature(rand.Reader, k.params(), r)
	if err != nil {
		t.Fatalf("RevocationSignature: %v", err)
	}
	return sig
}

// spec is the signature of the page for a reason, as RevocationSignature writes it, ready to change.
func (k revKit) spec(r openpgp.Reason) sigSpec {
	return sigSpec{
		Type: 0x20,
		Hashed: []sub{
			{Type: 2, Data: u32(uint32(ceremony.Unix()))},
			{Type: 29, Data: append([]byte{r.Code}, r.Text...)},
			{Type: 33, Data: append([]byte{4}, k.fp...)},
		},
		Unhashed: []sub{{Type: 16, Data: bytes.Clone(k.fp[12:])}},
		Data:     [][]byte{hashPrefix(&k.key.PublicKey, created)},
		Key:      k.key,
	}
}

// build writes the signature of the spec for a reason after tweak has changed it.
func (k revKit) build(t testing.TB, r openpgp.Reason, tweak func(*sigSpec)) []byte {
	t.Helper()
	sp := k.spec(r)
	if tweak != nil {
		tweak(&sp)
	}
	return sp.build(t)
}

// read is ReadRevocation with the primary of the kit, and a panic is a failure of the test.
func (k revKit) read(t testing.TB, what string, pkt []byte) (rev *openpgp.Revocation, err error) {
	t.Helper()
	return readRevocationSafely(t, what, pkt, k.primary)
}

func readRevocationSafely(t testing.TB, what string, pkt []byte, p *openpgp.PrimaryKey) (rev *openpgp.Revocation, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: ReadRevocation panicked: %v", what, r)
			rev, err = nil, errors.New("panic")
		}
	}()
	return openpgp.ReadRevocation(pkt, p)
}

// assertRevoked fails the test unless the kit reads pkt as a revocation for reason, and returns what
// it read. The digest is computed here, with crypto/sha256.
func (k revKit) assertRevoked(t testing.TB, what string, pkt []byte, r openpgp.Reason) *openpgp.Revocation {
	t.Helper()
	before := bytes.Clone(pkt)
	rev, err := k.read(t, what, pkt)
	if err != nil || rev == nil {
		t.Errorf("%s: ReadRevocation = %v, %v; want a revocation", what, rev, err)
		return nil
	}
	if !bytes.Equal(pkt, before) {
		t.Errorf("%s: ReadRevocation changed its input", what)
	}
	if rev.Reason != r {
		t.Errorf("%s: the reason is %+v, want %+v", what, rev.Reason, r)
	}
	if !rev.Created.Equal(ceremony) || rev.Created.Location().String() != "UTC" {
		t.Errorf("%s: the creation time is %v, want %v in UTC", what, rev.Created, ceremony)
	}
	if want := hex.EncodeToString(k.fp); rev.Issuer != want {
		t.Errorf("%s: the issuer is %q, want %q", what, rev.Issuer, want)
	}
	sum := sha256.Sum256(pkt)
	if want := hex.EncodeToString(sum[:]); rev.SHA256 != want {
		t.Errorf("%s: the digest is %q, want %q", what, rev.SHA256, want)
	}
	return rev
}

// assertNotRevoked fails the test unless the kit refuses pkt with ErrRevocation and returns no
// Revocation; withReason says whether the fault is also an ErrRevocationReason. The text of the error
// is one short line that holds no byte of the packet, no digest and no fingerprint.
func (k revKit) assertNotRevoked(t testing.TB, what string, pkt []byte, withReason bool) {
	t.Helper()
	assertRevocationRefused(t, what, pkt, k.primary, withReason, hex.EncodeToString(k.fp))
}

func assertRevocationRefused(t testing.TB, what string, pkt []byte, p *openpgp.PrimaryKey, withReason bool, fingerprint string) {
	t.Helper()
	before := bytes.Clone(pkt)
	rev, err := readRevocationSafely(t, what, pkt, p)
	if rev != nil {
		t.Errorf("%s: a Revocation was returned with the error %v", what, err)
	}
	if err == nil {
		t.Errorf("%s: no error, want an ErrRevocation", what)
		return
	}
	if !errors.Is(err, openpgp.ErrRevocation) {
		t.Errorf("%s: error = %v, want an ErrRevocation", what, err)
	}
	if errors.Is(err, openpgp.ErrRevocationReason) != withReason {
		t.Errorf("%s: error %v is an ErrRevocationReason: %v, want %v", what, err, !withReason, withReason)
	}
	for _, other := range []error{openpgp.ErrParams, openpgp.ErrAnswer, openpgp.ErrBinding, openpgp.ErrRequest,
		openpgp.ErrSignatureFile, openpgp.ErrCertificateForm, openpgp.ErrKeyring} {
		if errors.Is(err, other) {
			t.Errorf("%s: error %v is also %v", what, err, other)
		}
	}
	if !bytes.Equal(pkt, before) {
		t.Errorf("%s: ReadRevocation changed its input", what)
	}
	checkErrorText(t, what, err)
	checkRevocationText(t, what, err, pkt, fingerprint)
}

// checkRevocationText holds the text of a refusal to what holds no part of the packet: not its digest, not
// its fingerprint, not 8 of its bytes in hexadecimal.
func checkRevocationText(t testing.TB, what string, err error, pkt []byte, fingerprint string) {
	t.Helper()
	text := err.Error()
	sum := sha256.Sum256(pkt)
	shown := []string{hex.EncodeToString(sum[:8])}
	if len(fingerprint) == 40 {
		shown = append(shown, fingerprint, fingerprint[24:])
	}
	for _, s := range shown {
		if s != "" && bytes.Contains([]byte(text), []byte(s)) {
			t.Errorf("%s: the text %q holds %q", what, text, s)
		}
	}
	for i := 0; i+8 <= len(pkt) && i < 64; i++ {
		if bytes.Contains([]byte(text), []byte(hex.EncodeToString(pkt[i:i+8]))) {
			t.Errorf("%s: the text %q holds 8 bytes of the packet", what, text)
			return
		}
	}
}

// allReasons is the four reasons of the page with their names.
var allReasons = reasons

// resigned patches the fixed fields of a good signature (the type, the algorithm and the hash
// identifier stand in the bytes 1, 2 and 3 of the body) and signs the patched fields again with
// SHA-384 over the key packet, so that the signature verifies over the bytes it holds and only the
// claim in the fields is wrong.
func (k revKit) resigned(t testing.TB, r openpgp.Reason, patch func(body []byte)) []byte {
	t.Helper()
	body := bodyOf(t, k.made(t, r))
	patch(body)
	l := layoutOf(body)
	fields := body[:l.hashedAt+l.hashedLen]
	h := sha512.New384()
	h.Write(hashPrefix(&k.key.PublicKey, created))
	h.Write(fields)
	h.Write(append([]byte{4, 0xFF}, u32(uint32(len(fields)))...))
	digest := h.Sum(nil)
	der, err := ecdsa.SignASN1(rand.Reader, k.key, digest)
	if err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		t.Fatal(err)
	}
	out := append(bytes.Clone(body[:l.tagAt]), digest[0], digest[1])
	out = append(out, mpi(rs.R)...)
	out = append(out, mpi(rs.S)...)
	return withBody(out)
}
