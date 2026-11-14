package openpgp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/verifier"
)

// These tests hand the packets of the builders to two programs that did not build them: gpgv and
// sqv (record 0010, rule 20). Each acceptance is paired with a control in the same world, so that a
// refusal cannot come from a mistake of the setup.

// world is a primary, a subkey bound by it, and what a tool needs to read them.
type world struct {
	signer  *privateSigner
	pp      openpgp.PrimaryParams
	cert    []byte
	sub     subkeyMaterial
	bound   []byte
	keyring []byte
	subEnd  time.Time
}

type worldTimes struct {
	created, ceremony, expires, subAt, subEnd time.Time
	capability                                string
	key                                       *privateSigner
}

// nowWorld is a world that a tool that reads the clock accepts: everything happened in the past
// and nothing has ended.
func nowWorldTimes() worldTimes {
	now := nowSec()
	ceremony := now.Add(-24 * time.Hour)
	return worldTimes{
		created:    now.Add(-72 * time.Hour),
		ceremony:   ceremony,
		expires:    ceremony.AddDate(3, 0, 0),
		subAt:      now.Add(-36 * time.Hour),
		subEnd:     ceremony.AddDate(1, 1, 0),
		capability: "sign",
	}
}

func buildWorld(t testing.TB, w worldTimes) world {
	t.Helper()
	s := w.key
	if s == nil {
		s = newSigner(t)
	}
	pp := openpgp.PrimaryParams{
		Key: s, CreationTime: w.created, CeremonyTime: w.ceremony, ExpiresAt: w.expires,
		UserID: exampleUserID(true),
	}
	cert, err := openpgp.NewPrimary(rand.Reader, pp)
	if err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	m := newSubkey(t, &s.key.PublicKey, w.created, w.subAt)
	bound, err := openpgp.BindSubkey(rand.Reader, openpgp.BindParams{
		Primary: pp, Subkey: m.Packet, BackSig: m.BackSig, Capability: w.capability, ExpiresAt: w.subEnd,
	})
	if err != nil {
		t.Fatalf("BindSubkey: %v", err)
	}
	return world{signer: s, pp: pp, cert: cert, sub: m, bound: bound, keyring: slices.Concat(cert, bound), subEnd: w.subEnd}
}

// signMessage is a detached binary signature (type 0x00) by the subkey, made with the tests' own code.
// fp is the fingerprint of the primary of the world: the certificate that the tools are to name.
func (w world) fp(t testing.TB) string {
	t.Helper()
	return fingerprintOf(t, &w.signer.key.PublicKey, w.pp.CreationTime)
}

func (w world) signMessage(t testing.TB, at time.Time, msg []byte) []byte {
	t.Helper()
	fp := fingerprint(&w.sub.Key.PublicKey, w.sub.Created)
	return sigSpec{
		Type: 0x00,
		Hashed: []sub{
			{Type: 2, Data: u32(uint32(at.Unix()))},
			{Type: 33, Data: append([]byte{4}, fp...)},
		},
		Unhashed: []sub{{Type: 16, Data: fp[12:]}},
		Data:     [][]byte{msg},
		Key:      w.sub.Key,
	}.build(t)
}

var message = []byte("the release of example.org version 1.2.3\n")

// refusedByBoth asserts that gpgv and sqv both refuse, and returns nothing: the controls.
func gpgvAccepts(t testing.TB, keyring, sig, msg []byte, fp string) bool {
	t.Helper()
	err := verifier.GPGVVerify(t, keyring, sig, msg, fp)
	if err != nil {
		t.Logf("gpgv refuses: %v", err)
	}
	return err == nil
}

func sqvAccepts(t testing.TB, keyring, sig, msg []byte, fp string, at time.Time) bool {
	t.Helper()
	err := verifier.SQVVerify(t, keyring, sig, msg, fp, at)
	if err != nil {
		t.Logf("sqv refuses: %v", err)
	}
	return err == nil
}

func TestGpgvAndSqvAcceptAMessageSignedByASubkeyThatABuiltPrimaryBound(t *testing.T) {
	w := buildWorld(t, nowWorldTimes())
	now := nowSec()
	sig := w.signMessage(t, now.Add(-time.Hour), message)
	if err := verifier.GPGVVerify(t, w.keyring, sig, message, w.fp(t)); err != nil {
		t.Errorf("gpgv: %v", err)
	}
	if err := verifier.SQVVerify(t, w.keyring, sig, message, w.fp(t), now); err != nil {
		t.Errorf("sqv: %v", err)
	}
}

// The same with a key that is an ordinary Go key as the signer.
func TestGpgvAndSqvAcceptTheSameWorldBuiltWithAGoKeyAsTheSigner(t *testing.T) {
	times := nowWorldTimes()
	k := genKey(t)
	pp := openpgp.PrimaryParams{Key: k, CreationTime: times.created, CeremonyTime: times.ceremony, ExpiresAt: times.expires, UserID: "Example Test Release Root A (TEST ONLY) <release@example.org>"}
	cert, err := openpgp.NewPrimary(nil, pp)
	if err != nil {
		t.Fatal(err)
	}
	m := newSubkey(t, &k.PublicKey, times.created, times.subAt)
	bound, err := openpgp.BindSubkey(nil, openpgp.BindParams{Primary: pp, Subkey: m.Packet, BackSig: m.BackSig, Capability: "sign", ExpiresAt: times.subEnd})
	if err != nil {
		t.Fatal(err)
	}
	w := world{sub: m}
	now := nowSec()
	sig := w.signMessage(t, now.Add(-time.Hour), message)
	ring := slices.Concat(cert, bound)
	fpGo := fingerprintOf(t, &k.PublicKey, times.created)
	if err := verifier.GPGVVerify(t, ring, sig, message, fpGo); err != nil {
		t.Errorf("gpgv: %v", err)
	}
	if err := verifier.SQVVerify(t, ring, sig, message, fpGo, now); err != nil {
		t.Errorf("sqv: %v", err)
	}
}

func TestGpgvAndSqvRefuseAChangedMessage(t *testing.T) {
	w := buildWorld(t, nowWorldTimes())
	now := nowSec()
	sig := w.signMessage(t, now.Add(-time.Hour), message)
	if !gpgvAccepts(t, w.keyring, sig, message, w.fp(t)) || !sqvAccepts(t, w.keyring, sig, message, w.fp(t), now) {
		t.Fatal("the control does not start from an acceptance")
	}
	changed := bytes.Replace(message, []byte("1.2.3"), []byte("1.2.4"), 1)
	status, _ := verifier.GPGVStatus(t, w.keyring, sig, changed)
	if !hasStatus(status, "BADSIG") {
		t.Errorf("gpgv status %q, want a BADSIG", status)
	}
	if err := verifier.GPGVVerify(t, w.keyring, sig, changed, w.fp(t)); err == nil {
		t.Error("gpgv accepts a changed message")
	}
	if err := verifier.SQVVerify(t, w.keyring, sig, changed, w.fp(t), now); err == nil {
		t.Error("sqv accepts a changed message")
	}
}

func TestGpgvAndSqvRefuseAnUnrelatedCertificate(t *testing.T) {
	w := buildWorld(t, nowWorldTimes())
	other := buildWorld(t, nowWorldTimes())
	now := nowSec()
	sig := w.signMessage(t, now.Add(-time.Hour), message)
	if !gpgvAccepts(t, w.keyring, sig, message, w.fp(t)) || !sqvAccepts(t, w.keyring, sig, message, w.fp(t), now) {
		t.Fatal("the control does not start from an acceptance")
	}
	if err := verifier.GPGVVerify(t, other.keyring, sig, message, w.fp(t)); err == nil {
		t.Error("gpgv accepts a signature against an unrelated certificate")
	}
	if err := verifier.SQVVerify(t, other.keyring, sig, message, w.fp(t), now); err == nil {
		t.Error("sqv accepts a signature against an unrelated certificate")
	}
}

// The key of the certificate without its binding is not a key that can sign for it.
func TestGpgvAndSqvRefuseTheSubkeyWhenTheBindingIsNotInTheKeyring(t *testing.T) {
	w := buildWorld(t, nowWorldTimes())
	now := nowSec()
	sig := w.signMessage(t, now.Add(-time.Hour), message)
	if !gpgvAccepts(t, w.keyring, sig, message, w.fp(t)) || !sqvAccepts(t, w.keyring, sig, message, w.fp(t), now) {
		t.Fatal("the control does not start from an acceptance")
	}
	if gpgvAccepts(t, w.cert, sig, message, w.fp(t)) {
		t.Error("gpgv accepts the signature with the certificate alone")
	}
	if sqvAccepts(t, w.cert, sig, message, w.fp(t), now) {
		t.Error("sqv accepts the signature with the certificate alone")
	}
}

// The tools really check what the builders wrote: a damaged copy of each packet is refused, and the
// undamaged one in the same world is accepted.
func TestGpgvAndSqvRefuseACertificateWhoseBytesWereChangedAfterSigning(t *testing.T) {
	w := buildWorld(t, nowWorldTimes())
	now := nowSec()
	sig := w.signMessage(t, now.Add(-time.Hour), message)
	if !gpgvAccepts(t, w.keyring, sig, message, w.fp(t)) || !sqvAccepts(t, w.keyring, sig, message, w.fp(t), now) {
		t.Fatal("the control does not start from an acceptance")
	}
	certPs := splitPackets(t, w.cert)
	boundPs := splitPackets(t, w.bound)
	cases := []struct {
		name string
		ring func() []byte
	}{
		{"a byte of the user ID changed", func() []byte {
			c := bytes.Clone(w.cert)
			i := bytes.Index(c, []byte("Example Test"))
			c[i] ^= 0x20
			return slices.Concat(c, w.bound)
		}},
		{"the key flags of the binding changed", func() []byte {
			b := bytes.Clone(boundPs[1].Raw)
			sig := parseSig(t, splitPackets(t, b)[0].Body)
			flags := find(t, sig.Hashed, 27)
			i := bytes.Index(b, append([]byte{0x02, 0x1b}, flags.Data...)) // length 2, type 27, data
			if i < 0 {
				i = bytes.Index(b, []byte{0x1b, flags.Data[0]})
			}
			b[i+1+1] ^= 0x20 // sign becomes sign and authenticate
			return slices.Concat(w.cert, boundPs[0].Raw, b)
		}},
		{"a byte of the key expiration time of the self-signature changed", func() []byte {
			c := bytes.Clone(certPs[2].Raw)
			sig := parseSig(t, splitPackets(t, c)[0].Body)
			life := find(t, sig.Hashed, 9).Data
			i := bytes.Index(c, life)
			c[i+3] ^= 0x01
			return slices.Concat(certPs[0].Raw, certPs[1].Raw, c, w.bound)
		}},
		{"a byte of the subkey changed", func() []byte {
			b := bytes.Clone(boundPs[0].Raw)
			b[len(b)-5] ^= 0x01
			return slices.Concat(w.cert, b, boundPs[1].Raw)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ring := c.ring()
			if gpgvAccepts(t, ring, sig, message, w.fp(t)) {
				t.Error("gpgv accepts it")
			}
			if sqvAccepts(t, ring, sig, message, w.fp(t), now) {
				t.Error("sqv accepts it")
			}
		})
	}
}

// GnuPG and Sequoia refuse a signing subkey without a good back-signature (the hand-off contract,
// "The request"). The binding of the builder carries the request's one, and without it both tools
// refuse the key: so the embedded signature of the answer is not decoration.
func TestGpgvAndSqvRefuseASigningSubkeyWhoseBindingLacksTheBackSignature(t *testing.T) {
	w := buildWorld(t, nowWorldTimes())
	now := nowSec()
	sig := w.signMessage(t, now.Add(-time.Hour), message)
	if !gpgvAccepts(t, w.keyring, sig, message, w.fp(t)) || !sqvAccepts(t, w.keyring, sig, message, w.fp(t), now) {
		t.Fatal("the control does not start from an acceptance")
	}
	boundPs := splitPackets(t, w.bound)
	stripped := withoutUnhashed(t, boundPs[1], 32)
	ring := slices.Concat(w.cert, boundPs[0].Raw, stripped)
	if gpgvAccepts(t, ring, sig, message, w.fp(t)) {
		t.Error("gpgv accepts a signing subkey with no back-signature")
	}
	if sqvAccepts(t, ring, sig, message, w.fp(t), now) {
		t.Error("sqv accepts a signing subkey with no back-signature")
	}
}

// withoutUnhashed rewrites a signature packet without the unhashed subpackets of one type. The hash
// does not cover the unhashed area, so the signature stays good.
func withoutUnhashed(t testing.TB, p packet, typ byte) []byte {
	t.Helper()
	sig := parseSig(t, p.Body)
	var kept []sub
	for _, s := range sig.Unhashed {
		if s.Type != typ {
			kept = append(kept, s)
		}
	}
	un := encodeSubs(kept)
	body := slices.Concat(sig.Fields, []byte{byte(len(un) >> 8), byte(len(un))}, un, sig.Tag, mpi(sig.R), mpi(sig.S))
	return wrap(tagSignature, body)
}

// A subkey bound for authentication only is not a signing key: the flags of the binding are kept to
// by the tools.
func TestGpgvAndSqvRefuseAMessageSignedByASubkeyBoundOnlyForAuthentication(t *testing.T) {
	times := nowWorldTimes()
	sign := buildWorld(t, times)
	times.capability = "authenticate"
	auth := buildWorld(t, times)
	now := nowSec()
	okSig := sign.signMessage(t, now.Add(-time.Hour), message)
	if !gpgvAccepts(t, sign.keyring, okSig, message, sign.fp(t)) || !sqvAccepts(t, sign.keyring, okSig, message, sign.fp(t), now) {
		t.Fatal("the control does not start from an acceptance")
	}
	sig := auth.signMessage(t, now.Add(-time.Hour), message)
	if gpgvAccepts(t, auth.keyring, sig, message, auth.fp(t)) {
		t.Error("gpgv accepts a message signed by a subkey bound for authentication only")
	}
	if sqvAccepts(t, auth.keyring, sig, message, auth.fp(t), now) {
		t.Error("sqv accepts a message signed by a subkey bound for authentication only")
	}
}

// Revocation. Record 0009, rule 20: gpgv exits 0 for a revoked key, so the verdict is read from the
// status line REVKEYSIG, and sqv is the verdict for the rest.

// revoked puts a revocation right after the primary key packet, where GnuPG reads it as a
// revocation of the primary (appended at the end it would read as one of the last subkey).
func revoked(t testing.TB, cert, bound, rev []byte) []byte {
	t.Helper()
	ps := splitPackets(t, cert)
	return slices.Concat(ps[0].Raw, rev, ps[1].Raw, ps[2].Raw, bound)
}

func TestACompromisedRevocationMakesSqvRefuseAndGpgvReportRevKeySig(t *testing.T) {
	w := buildWorld(t, nowWorldTimes())
	now := nowSec()
	rp := w.pp
	rp.CeremonyTime = now.Add(-30 * time.Minute)
	rev, err := openpgp.RevocationSignature(nil, rp, openpgp.Compromised)
	if err != nil {
		t.Fatal(err)
	}
	ring := revoked(t, w.cert, w.bound, rev)
	for _, c := range []struct {
		name string
		at   time.Time
	}{
		{"after the revocation", now.Add(-10 * time.Minute)},
		{"before the revocation", now.Add(-time.Hour)},
	} {
		t.Run("a message signed "+c.name, func(t *testing.T) {
			sig := w.signMessage(t, c.at, message)
			if !gpgvAccepts(t, w.keyring, sig, message, w.fp(t)) || !sqvAccepts(t, w.keyring, sig, message, w.fp(t), now) {
				t.Fatal("the control does not start from an acceptance")
			}
			status, _ := verifier.GPGVStatus(t, ring, sig, message)
			if !hasStatus(status, "REVKEYSIG") {
				t.Errorf("gpgv status %q, want REVKEYSIG", status)
			}
			if err := verifier.GPGVVerify(t, ring, sig, message, w.fp(t)); err == nil {
				t.Error("GPGVVerify accepts a signature by a key that is revoked")
			}
			if err := verifier.SQVVerify(t, ring, sig, message, w.fp(t), now); err == nil {
				t.Error("sqv accepts a signature by a key with a compromised revocation, whenever it was made")
			}
		})
	}
}

func TestASoftRevocationKeepsWhatWasSignedBeforeItAndRefusesWhatWasSignedAfter(t *testing.T) {
	for _, r := range []struct {
		name string
		r    openpgp.Reason
	}{{"superseded", openpgp.Superseded}, {"retired", openpgp.Retired}} {
		t.Run(r.name, func(t *testing.T) {
			w := buildWorld(t, nowWorldTimes())
			now := nowSec()
			rp := w.pp
			rp.CeremonyTime = now.Add(-30 * time.Minute)
			rev, err := openpgp.RevocationSignature(nil, rp, r.r)
			if err != nil {
				t.Fatal(err)
			}
			ring := revoked(t, w.cert, w.bound, rev)
			before := w.signMessage(t, now.Add(-time.Hour), message)
			after := w.signMessage(t, now.Add(-10*time.Minute), message)
			if !sqvAccepts(t, w.keyring, after, message, w.fp(t), now) {
				t.Fatal("the control does not start from an acceptance")
			}
			if err := verifier.SQVVerify(t, ring, before, message, w.fp(t), now); err != nil {
				t.Errorf("sqv refuses what was signed before a %s revocation: %v", r.name, err)
			}
			if sqvAccepts(t, ring, after, message, w.fp(t), now) {
				t.Errorf("sqv accepts what was signed after a %s revocation", r.name)
			}
		})
	}
}

// A revocation that is not in the keyring changes nothing; one that was made for another key does not
// revoke this one.
func TestARevocationOfAnotherKeyRevokesNothing(t *testing.T) {
	w := buildWorld(t, nowWorldTimes())
	now := nowSec()
	other := newSigner(t)
	op := w.pp
	op.Key = other
	op.CeremonyTime = now.Add(-30 * time.Minute)
	rev, err := openpgp.RevocationSignature(nil, op, openpgp.Compromised)
	if err != nil {
		t.Fatal(err)
	}
	sig := w.signMessage(t, now.Add(-10*time.Minute), message)
	ring := revoked(t, w.cert, w.bound, rev)
	if err := verifier.SQVVerify(t, ring, sig, message, w.fp(t), now); err != nil {
		t.Errorf("sqv refuses because of a revocation made by another key: %v", err)
	}
	status, _ := verifier.GPGVStatus(t, ring, sig, message)
	if hasStatus(status, "REVKEYSIG") {
		t.Errorf("gpgv reports REVKEYSIG for a revocation made by another key: %q", status)
	}
}

// Each use extends it. Time of the tests: sqv is told the time; gpgv reads the clock, so its case is
// built around now.
func TestSqvTakesTheNewestSelfSignatureForTheEndOfTheKey(t *testing.T) {
	first := worldTimes{
		created: created, ceremony: ceremony, expires: ceremony.Add(24 * time.Hour),
		subAt: ceremony.Add(-2 * time.Hour), subEnd: ceremony.AddDate(1, 0, 0), capability: "sign",
	}
	w := buildWorld(t, first)
	at := ceremony.Add(48 * time.Hour)
	sig := w.signMessage(t, at.Add(-time.Hour), message)

	if sqvAccepts(t, w.keyring, sig, message, w.fp(t), at) {
		t.Fatal("the key is not expired after one day, the control does not hold")
	}
	later := w.pp
	later.CeremonyTime = ceremony.Add(12 * time.Hour)
	later.ExpiresAt = later.CeremonyTime.AddDate(3, 0, 0)
	ext, err := openpgp.ExtendPrimary(nil, later)
	if err != nil {
		t.Fatal(err)
	}
	extended := slices.Concat(w.cert, ext, w.bound)
	if err := verifier.SQVVerify(t, extended, sig, message, w.fp(t), at); err != nil {
		t.Errorf("sqv refuses a key that was extended after its first expiry: %v", err)
	}
	// The other direction: a newer self-signature with an earlier end shortens the key.
	shorter := w.pp
	shorter.CeremonyTime = ceremony.Add(12 * time.Hour)
	shorter.ExpiresAt = ceremony.Add(24*time.Hour + 30*time.Minute)
	w2 := buildWorld(t, worldTimes{created: created, ceremony: ceremony, expires: ceremony.AddDate(3, 0, 0), subAt: first.subAt, subEnd: first.subEnd, capability: "sign", key: w.signer})
	short, err := openpgp.ExtendPrimary(nil, shorter)
	if err != nil {
		t.Fatal(err)
	}
	sig2 := w2.signMessage(t, at.Add(-time.Hour), message)
	if !sqvAccepts(t, w2.keyring, sig2, message, w2.fp(t), at) {
		t.Fatal("the control does not start from an acceptance")
	}
	if sqvAccepts(t, slices.Concat(w2.cert, short, w2.bound), sig2, message, w2.fp(t), at) {
		t.Error("sqv ignores the newest self-signature that ends the key sooner")
	}
}

func TestGpgvTakesTheExtensionOfAKeyThatHadExpired(t *testing.T) {
	now := nowSec()
	c0 := now.Add(-96 * time.Hour)
	first := worldTimes{
		created: c0, ceremony: c0.Add(time.Hour), expires: now.Add(-24 * time.Hour),
		subAt: c0.Add(30 * time.Minute), subEnd: now.AddDate(1, 0, 0), capability: "sign",
	}
	w := buildWorld(t, first)
	sig := w.signMessage(t, now.Add(-time.Hour), message)

	status, _ := verifier.GPGVStatus(t, w.keyring, sig, message)
	if hasStatus(status, "GOODSIG") && !hasStatus(status, "EXPKEYSIG") {
		t.Fatalf("a key that ended a day ago is taken as good: %q", status)
	}
	later := w.pp
	later.CeremonyTime = now.Add(-12 * time.Hour)
	later.ExpiresAt = now.AddDate(3, 0, 0)
	ext, err := openpgp.ExtendPrimary(nil, later)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.GPGVVerify(t, slices.Concat(w.cert, ext, w.bound), sig, message, w.fp(t)); err != nil {
		t.Errorf("gpgv refuses the extended key: %v", err)
	}
	if err := verifier.SQVVerify(t, slices.Concat(w.cert, ext, w.bound), sig, message, w.fp(t), now); err != nil {
		t.Errorf("sqv refuses the extended key: %v", err)
	}
}

// The key ends at ExpiresAt, counted from the creation of the key (not from the ceremony). The
// message times straddle the end by an hour on both sides.
func TestTheKeyEndsAtTheInstantThatWasAskedWhenSqvReadsIt(t *testing.T) {
	end := time.Date(2029, 11, 15, 12, 0, 0, 0, time.UTC)
	w := buildWorld(t, worldTimes{created: created, ceremony: ceremony, expires: end, subAt: ceremony.Add(-time.Hour), subEnd: end.AddDate(1, 0, 0), capability: "sign"})
	inside := w.signMessage(t, end.Add(-time.Hour), message)
	outside := w.signMessage(t, end.Add(time.Hour), message)
	if err := verifier.SQVVerify(t, w.keyring, inside, message, w.fp(t), end.Add(2*time.Hour)); err != nil {
		t.Errorf("sqv refuses a message signed an hour before the end of the key: %v", err)
	}
	if sqvAccepts(t, w.keyring, outside, message, w.fp(t), end.Add(2*time.Hour)) {
		t.Error("sqv accepts a message signed an hour after the end of the key")
	}
}

func TestTheSubkeyEndsAtTheInstantThatWasAskedWhenSqvReadsIt(t *testing.T) {
	subEnd := ceremony.AddDate(1, 1, 0)
	w := buildWorld(t, worldTimes{created: created, ceremony: ceremony, expires: ceremony.AddDate(3, 0, 0), subAt: ceremony.Add(-time.Hour), subEnd: subEnd, capability: "sign"})
	inside := w.signMessage(t, subEnd.Add(-time.Hour), message)
	outside := w.signMessage(t, subEnd.Add(time.Hour), message)
	if err := verifier.SQVVerify(t, w.keyring, inside, message, w.fp(t), subEnd.Add(2*time.Hour)); err != nil {
		t.Errorf("sqv refuses a message signed an hour before the end of the subkey: %v", err)
	}
	if sqvAccepts(t, w.keyring, outside, message, w.fp(t), subEnd.Add(2*time.Hour)) {
		t.Error("sqv accepts a message signed an hour after the end of the subkey, while the primary lives on")
	}
}

func TestSqvRefusesAMessageSignedBeforeTheBindingExisted(t *testing.T) {
	w := buildWorld(t, worldTimes{created: created, ceremony: ceremony, expires: ceremony.AddDate(3, 0, 0), subAt: ceremony.Add(-time.Hour), subEnd: ceremony.AddDate(1, 0, 0), capability: "sign"})
	if err := verifier.SQVVerify(t, w.keyring, w.signMessage(t, ceremony.Add(time.Hour), message), message, w.fp(t), ceremony.Add(2*time.Hour)); err != nil {
		t.Fatalf("the control does not start from an acceptance: %v", err)
	}
	if sqvAccepts(t, w.keyring, w.signMessage(t, ceremony.Add(-30*time.Minute), message), message, w.fp(t), ceremony.Add(2*time.Hour)) {
		t.Error("sqv accepts a message signed before the primary bound the subkey")
	}
}

func TestSqvRefusesAKeyBeforeItsCreation(t *testing.T) {
	w := buildWorld(t, worldTimes{created: created, ceremony: ceremony, expires: ceremony.AddDate(3, 0, 0), subAt: ceremony.Add(-time.Hour), subEnd: ceremony.AddDate(1, 0, 0), capability: "sign"})
	sig := w.signMessage(t, created.Add(-time.Hour), message)
	if sqvAccepts(t, w.keyring, sig, message, w.fp(t), ceremony.Add(time.Hour)) {
		t.Error("sqv accepts a message signed before the key was created")
	}
}

func hasStatus(status []string, word string) bool {
	for _, l := range status {
		if w, _, _ := strings.Cut(l, " "); w == word {
			return true
		}
	}
	return false
}

var _ = ecdsa.PublicKey{}

// nowSec is the present time in whole seconds, which is what the builders take.
func nowSec() time.Time { return time.Now().UTC().Truncate(time.Second) }

// The controls of the revocation and of the extension: a changed byte makes the signature bad, and
// the tools then ignore it. A revocation that was changed after signing revokes nothing, and an
// extension that was changed no longer extends the key.
func TestARevocationWhoseReasonWasChangedAfterSigningRevokesNothing(t *testing.T) {
	w := buildWorld(t, nowWorldTimes())
	now := nowSec()
	rp := w.pp
	rp.CeremonyTime = now.Add(-30 * time.Minute)
	rev, err := openpgp.RevocationSignature(nil, rp, openpgp.Compromised)
	if err != nil {
		t.Fatal(err)
	}
	sig := w.signMessage(t, now.Add(-10*time.Minute), message)
	if err := verifier.SQVVerify(t, revoked(t, w.cert, w.bound, rev), sig, message, w.fp(t), now); err == nil {
		t.Fatal("the control does not start from a revoked key")
	}
	bad := bytes.Clone(rev)
	i := bytes.Index(bad, []byte("compromised"))
	bad[i] ^= 0x01 // the word is hashed: the signature no longer matches
	ring := revoked(t, w.cert, w.bound, bad)
	if err := verifier.SQVVerify(t, ring, sig, message, w.fp(t), now); err != nil {
		t.Errorf("sqv takes a revocation that does not verify as a revocation: %v", err)
	}
	status, _ := verifier.GPGVStatus(t, ring, sig, message)
	if hasStatus(status, "REVKEYSIG") {
		t.Errorf("gpgv reports REVKEYSIG for a revocation that does not verify: %q", status)
	}
}

func TestAnExtensionThatWasChangedAfterSigningDoesNotExtendTheKey(t *testing.T) {
	w := buildWorld(t, worldTimes{
		created: created, ceremony: ceremony, expires: ceremony.Add(24 * time.Hour),
		subAt: ceremony.Add(-2 * time.Hour), subEnd: ceremony.AddDate(1, 0, 0), capability: "sign",
	})
	at := ceremony.Add(48 * time.Hour)
	sig := w.signMessage(t, at.Add(-time.Hour), message)
	later := w.pp
	later.CeremonyTime = ceremony.Add(12 * time.Hour)
	later.ExpiresAt = later.CeremonyTime.AddDate(3, 0, 0)
	ext, err := openpgp.ExtendPrimary(nil, later)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.SQVVerify(t, slices.Concat(w.cert, ext, w.bound), sig, message, w.fp(t), at); err != nil {
		t.Fatalf("the control does not start from an acceptance: %v", err)
	}
	bad := bytes.Clone(ext)
	life := find(t, parseSig(t, splitPackets(t, ext)[0].Body).Hashed, 9).Data
	bad[bytes.Index(bad, life)+3] ^= 0x01 // a second of the new end: hashed, so the signature breaks
	if sqvAccepts(t, slices.Concat(w.cert, bad, w.bound), sig, message, w.fp(t), at) {
		t.Error("sqv takes an extension that does not verify")
	}
}

// Two certificates in one keyring: a message signed by a subkey that one primary bound is accepted
// for the fingerprint of that primary, by both tools, and is refused for the fingerprint of the
// other one, and for the fingerprint of the subkey itself.
func TestTwoCertificatesInOneKeyringAreToldApartByTheFingerprintOfThePrimary(t *testing.T) {
	a := buildWorld(t, nowWorldTimes())
	b := buildWorld(t, nowWorldTimes())
	ring := slices.Concat(a.keyring, b.keyring)
	now := nowSec()
	sigA := a.signMessage(t, now.Add(-time.Hour), message)
	sigB := b.signMessage(t, now.Add(-time.Hour), message)
	fpA, fpB := a.fp(t), b.fp(t)
	if fpA == fpB {
		t.Fatal("two worlds with one fingerprint")
	}
	for _, c := range []struct {
		name string
		sig  []byte
		fp   string
		ok   bool
	}{
		{"the first by the first", sigA, fpA, true},
		{"the second by the second", sigB, fpB, true},
		{"the second by the first", sigB, fpA, false},
		{"the first by the second", sigA, fpB, false},
		{"the first by its own subkey", sigA, fingerprintOf(t, &a.sub.Key.PublicKey, a.sub.Created), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			g, s := verifier.GPGVVerify(t, ring, c.sig, message, c.fp), verifier.SQVVerify(t, ring, c.sig, message, c.fp, now)
			if c.ok && (g != nil || s != nil) {
				t.Errorf("gpgv: %v, sqv: %v", g, s)
			}
			if !c.ok && (g == nil || s == nil) {
				t.Errorf("gpgv refuses: %v, sqv refuses: %v; both must", g != nil, s != nil)
			}
		})
	}
}

// A revocation stands right after the primary key packet in a keyring file, and then gpgv applies it
// to the primary (REVKEYSIG). Written after the other packets it is read as a signature on the last
// subkey, and gpgv still says GOODSIG: the doc of RevocationSignature says so, and the helper that
// writes a keyring file belongs to later work.
func TestAGpgvKeyringTakesTheRevocationOnlyRightAfterThePrimaryKeyPacket(t *testing.T) {
	w := buildWorld(t, nowWorldTimes())
	now := nowSec()
	rp := w.pp
	rp.CeremonyTime = now.Add(-30 * time.Minute)
	rev, err := openpgp.RevocationSignature(nil, rp, openpgp.Compromised)
	if err != nil {
		t.Fatal(err)
	}
	sig := w.signMessage(t, now.Add(-10*time.Minute), message)
	if !gpgvAccepts(t, w.keyring, sig, message, w.fp(t)) {
		t.Fatal("the control does not start from an acceptance")
	}
	after, _ := verifier.GPGVStatus(t, revoked(t, w.cert, w.bound, rev), sig, message)
	if !hasStatus(after, "REVKEYSIG") || hasStatus(after, "GOODSIG") {
		t.Errorf("a revocation after the primary key packet: gpgv status %q, want REVKEYSIG", after)
	}
	atEnd, _ := verifier.GPGVStatus(t, slices.Concat(w.keyring, rev), sig, message)
	if hasStatus(atEnd, "REVKEYSIG") {
		t.Errorf("a revocation at the end of the keyring: gpgv status %q; the doc of RevocationSignature says gpgv does not apply it there", atEnd)
	}
}

// The reason is not a critical subpacket in the vectors, and not here.
func TestTheReasonOfARevocationIsNotCritical(t *testing.T) {
	s := newSigner(t)
	for _, r := range []openpgp.Reason{openpgp.Compromised, openpgp.Superseded, openpgp.Retired, openpgp.NoReason} {
		rev, err := openpgp.RevocationSignature(nil, s.params(), r)
		if err != nil {
			t.Fatal(err)
		}
		sig := parseSig(t, splitPackets(t, rev)[0].Body)
		if x := find(t, sig.Hashed, 29); x.Critical {
			t.Errorf("the reason %q is critical", r.Text)
		}
		if got := critical(sig.Hashed); len(got) != 0 {
			t.Errorf("the revocation has critical subpackets % d, want none", got)
		}
	}
}

// A subkey may end after its primary ends: the primary is extended at each use (record 0007, rule
// 15), so the end of the subkey is not held to the end of the primary at one ceremony.
func TestASubkeyMayEndAfterItsPrimaryEnds(t *testing.T) {
	s, b, m := bindFixture(t)
	b.Primary.ExpiresAt = ceremony.AddDate(1, 0, 0)
	b.ExpiresAt = ceremony.AddDate(5, 0, 0)
	out, err := openpgp.BindSubkey(rand.Reader, b)
	if err != nil {
		t.Fatalf("BindSubkey: %v", err)
	}
	ps := splitPackets(t, out)
	if !verifySig(t, &s.key.PublicKey, ps[1].Body, hashPrefix(&s.key.PublicKey, created), hashPrefix(&m.Key.PublicKey, subAt)) {
		t.Error("the binding does not verify")
	}
	life := binary.BigEndian.Uint32(find(t, parseSig(t, ps[1].Body).Hashed, 9).Data)
	if end := subAt.Add(time.Duration(life) * time.Second); !end.Equal(b.ExpiresAt) {
		t.Errorf("the subkey ends at %v, want %v", end, b.ExpiresAt)
	}
}
