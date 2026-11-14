package openpgp_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/verifier"
)

// The differential test: whenever BindSubkey returns a binding for a back-signature, the two
// programs that did not build it, sqv and gpgv, accept a message signed by that subkey under that
// binding. The back-signatures are built in many valid shapes; the shapes that a strict reader
// refuses are refused by the builder instead, so that no binding comes back for them.
//
// gpgv has no option for the time, so every world here is built around the real clock: the key a
// few days old, the ceremony a day ago, the message an hour ago, and every end well ahead. No date
// is written down: the tests do not start to fail when a fixed date passes.

// farFuture is the last second that a creation time can hold: it is ahead of the clock for as long
// as the format lasts, so no test here depends on a date that will pass.
var farFuture = time.Unix(1<<32-1, 0).UTC()

// buildWorldFor is buildWorld with a change to the back-signature, and with the error of the
// binding returned and not failed on. The primary is built the same way.
func buildWorldFor(t testing.TB, w worldTimes, tweak func(*sigSpec)) (world, error) {
	t.Helper()
	s := w.key
	if s == nil {
		s = newSigner(t)
	}
	m := newSubkeyWith(t, &s.key.PublicKey, w.created, w.subAt, tweak)
	return bindWorld(t, w, s, m)
}

// bindWorld builds the primary of a signer and binds the subkey material around it.
func bindWorld(t testing.TB, w worldTimes, s *privateSigner, m subkeyMaterial) (world, error) {
	t.Helper()
	pp := s.params()
	pp.CreationTime, pp.CeremonyTime, pp.ExpiresAt = w.created, w.ceremony, w.expires
	cert, err := openpgp.NewPrimary(rand.Reader, pp)
	if err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	s.calls = 0 // what is counted from here is what the binding asked of the signer
	bound, err := openpgp.BindSubkey(rand.Reader, openpgp.BindParams{
		Primary: pp, Subkey: m.Packet, BackSig: m.BackSig, Capability: w.capability, ExpiresAt: w.subEnd,
	})
	out := world{signer: s, pp: pp, cert: cert, sub: m, bound: bound, subEnd: w.subEnd}
	if err == nil {
		out.keyring = slices.Concat(cert, bound)
	}
	return out, err
}

func TestBothToolsAcceptTheBindingForEveryShapeOfBackSignatureThatBindSubkeyAccepts(t *testing.T) {
	wt := nowWorldTimes()
	shapes := backSigShapes(backTimes{subAt: wt.subAt, ceremony: wt.ceremony})
	accepted, refused := 0, 0
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			w, err := buildWorldFor(t, wt, sh.tweak)
			if err != nil {
				refused++
				if !errors.Is(err, openpgp.ErrRequest) {
					t.Fatalf("BindSubkey: %v, want a refusal of the request", err)
				}
				if sh.kind == accept {
					t.Fatalf("a back-signature of a valid shape is refused: %v", err)
				}
				if w.signer.calls != 0 {
					t.Errorf("the signer was asked %d times for a request that was refused", w.signer.calls)
				}
				if w.bound != nil {
					t.Errorf("%d bytes came back with the error", len(w.bound))
				}
				return
			}
			if sh.kind == refuse {
				t.Fatal("a binding came back for a back-signature that must be refused")
			}
			accepted++
			now := nowSec()
			sig := w.signMessage(t, now.Add(-time.Hour), message)
			if err := verifier.GPGVVerify(t, w.keyring, sig, message, w.fp(t)); err != nil {
				t.Errorf("gpgv refuses the binding: %v", err)
			}
			if err := verifier.SQVVerify(t, w.keyring, sig, message, w.fp(t), now); err != nil {
				t.Errorf("sqv refuses the binding: %v", err)
			}
		})
	}
	if accepted < 10 || refused < 150 {
		t.Errorf("%d shapes were accepted and %d refused; the differential test needs both kinds in number", accepted, refused)
	}
}

// handBinding builds the binding of a subkey by hand, as the builder would, around any
// back-signature at all: the tests' own code and the key of the signer. It is what the builder
// refuses to write, and so the tools can be shown what it would have written.
func handBinding(t testing.TB, w worldTimes, tweak func(*sigSpec)) (ring []byte, mat world) {
	t.Helper()
	s := newSigner(t)
	pp := s.params()
	pp.CreationTime, pp.CeremonyTime, pp.ExpiresAt = w.created, w.ceremony, w.expires
	cert, err := openpgp.NewPrimary(rand.Reader, pp)
	if err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	m := newSubkeyWith(t, &s.key.PublicKey, w.created, w.subAt, tweak)
	back := splitPackets(t, m.BackSig)[0].Body
	fp := fingerprint(&s.key.PublicKey, w.created)
	life := uint32(w.subEnd.Sub(w.subAt) / time.Second)
	binding := sigSpec{
		Type: 0x18,
		Hashed: []sub{
			{Type: 2, Data: u32at(w.ceremony)},
			{Type: 27, Data: []byte{0x02}},
			{Type: 9, Critical: true, Data: u32(life)},
			{Type: 33, Data: append([]byte{4}, fp...)},
		},
		Unhashed: []sub{{Type: 16, Data: fp[12:]}, {Type: 32, Data: back}},
		Data:     [][]byte{hashPrefix(&s.key.PublicKey, w.created), hashPrefix(&m.Key.PublicKey, w.subAt)},
		Key:      s.key,
	}.build(t)
	return slices.Concat(cert, m.Packet, binding), world{signer: s, pp: pp, cert: cert, sub: m}
}

// The binding that the builder refuses to make is one that a strict reader would refuse: this shows
// it, so that the refusals are not refusals of something harmless. For the three inputs of the
// refused shapes that sqv reads strictly, the hand-built binding is refused by sqv, and the plain
// shape built the same way is accepted by both tools.
func TestTheBindingsThatTheBuilderRefusesToWriteAreOnesThatSqvRefuses(t *testing.T) {
	wt := nowWorldTimes()
	now := nowSec()
	t.Run("the plain back-signature, built by hand, is accepted by both tools", func(t *testing.T) {
		ring, w := handBinding(t, wt, nil)
		sig := w.signMessage(t, now.Add(-time.Hour), message)
		fp := fingerprintOf(t, &w.signer.key.PublicKey, wt.created)
		if err := verifier.GPGVVerify(t, ring, sig, message, fp); err != nil {
			t.Errorf("gpgv: %v", err)
		}
		if err := verifier.SQVVerify(t, ring, sig, message, fp, now); err != nil {
			t.Errorf("sqv: %v", err)
		}
	})
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"three bytes after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{0xAA, 0xBB, 0xCC} }},
		{"a creation time at the end of the four-byte field (2106)", creationAt(farFuture)},
		{"an expiration of one second", addHashed(sub{Type: 3, Data: u32(1)})},
	} {
		t.Run(c.name, func(t *testing.T) {
			ring, w := handBinding(t, wt, c.tweak)
			sig := w.signMessage(t, now.Add(-time.Hour), message)
			fp := fingerprintOf(t, &w.signer.key.PublicKey, wt.created)
			err := verifier.SQVVerify(t, ring, sig, message, fp, now)
			if err == nil {
				t.Error("sqv accepts the binding around this back-signature: the refusal of the builder protects nothing")
			}
			// What the builder does with the same back-signature.
			_, berr := buildWorldFor(t, wt, c.tweak)
			if !errors.Is(berr, openpgp.ErrRequest) {
				t.Errorf("BindSubkey: %v, want a refusal of the request", berr)
			}
			if gerr := verifier.GPGVVerify(t, ring, sig, message, fp); gerr == nil {
				t.Log("gpgv accepts the binding that sqv refuses")
			}
		})
	}
}

// The refused shapes of the list again, one by one, by what the tools do with them: the builder
// refuses each, the signer is never asked, and what the tools say is only logged (some of them
// accept these back-signatures; they are refused for the strict readers and the old ones).
func TestEveryRefusedShapeOfTheListGivesNoBindingAndTheToolsAreOnlyAsked(t *testing.T) {
	wt := nowWorldTimes()
	now := nowSec()
	refusedShapes := []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"one byte after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{0x01} }},
		{"three bytes after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{0xAA, 0xBB, 0xCC} }},
		{"a creation time after the ceremony", creationAt(wt.ceremony.Add(time.Second))},
		{"a creation time a day after the ceremony", creationAt(wt.ceremony.Add(24 * time.Hour))},
		{"a creation time at the end of the four-byte field (2106)", creationAt(farFuture)},
		{"an expiration of one second", addHashed(sub{Type: 3, Data: u32(1)})},
		{"an expiration of a hundred years", addHashed(sub{Type: 3, Data: u32(100 * 365 * 86400)})},
		{"an unhashed expiration of a hundred years", addUnhashed(sub{Type: 3, Data: u32(100 * 365 * 86400)})},
		{"a wrong hash tag", func(sp *sigSpec) { sp.TagXOR = [2]byte{0x01, 0x01} }},
		{"a number with a leading zero byte and its true bit length", numbers(leadingZero(false), mpi)},
		{"a number with a leading zero byte that the bit length counts", numbers(mpi, leadingZero(true))},
	}
	for _, c := range refusedShapes {
		t.Run(c.name, func(t *testing.T) {
			w, err := buildWorldFor(t, wt, c.tweak)
			if !errors.Is(err, openpgp.ErrRequest) || w.bound != nil || w.signer.calls != 0 {
				t.Fatalf("BindSubkey: %v, %d bytes, signer asked %d times; want a refusal of the request, nothing and no call", err, len(w.bound), w.signer.calls)
			}
			ring, hw := handBinding(t, wt, c.tweak)
			sig := hw.signMessage(t, now.Add(-time.Hour), message)
			fp := fingerprintOf(t, &hw.signer.key.PublicKey, wt.created)
			t.Logf("by hand: gpgv %v, sqv %v", verifier.GPGVVerify(t, ring, sig, message, fp) == nil, verifier.SQVVerify(t, ring, sig, message, fp, now) == nil)
		})
	}
}

// gpgv reads no subpacket area of more than 10000 bytes: it says "unhashed data too long" and then
// reads no key of the keyring at all. BindSubkey refuses a binding whose unhashed area would be
// longer (maxUnhashedArea), so that the root never signs what gpgv cannot read. The back-signature
// of the page is far too short to reach that edge, so the edge is shown here with a binding that the
// test builds by hand with a padded unhashed area: gpgv reads 10000 bytes and does not read 10001,
// and sqv reads both. If gpgv ever changes this edge, the number of the guard is to change with it.
func TestTheUnhashedAreaOfTheBindingEndsWhereGpgvStopsReadingIt(t *testing.T) {
	wt := nowWorldTimes()
	now := nowSec()
	for _, c := range []struct {
		area       int
		gpgvReads  bool
		sqvReadsIt bool
	}{
		{400, true, true},
		{9999, true, true},
		{10000, true, true},
		{10001, false, true},
		{10002, false, true},
		{12000, false, true},
	} {
		t.Run(fmt.Sprintf("%d bytes", c.area), func(t *testing.T) {
			s := newSigner(t)
			pp := s.params()
			pp.CreationTime, pp.CeremonyTime, pp.ExpiresAt = wt.created, wt.ceremony, wt.expires
			cert, err := openpgp.NewPrimary(rand.Reader, pp)
			if err != nil {
				t.Fatalf("NewPrimary: %v", err)
			}
			m := newSubkey(t, &s.key.PublicKey, wt.created, wt.subAt)
			back := splitPackets(t, m.BackSig)[0].Body
			fp := fingerprint(&s.key.PublicKey, wt.created)
			unhashed := []sub{{Type: 16, Data: fp[12:]}, {Type: 32, Data: back}}
			if pad := c.area - len(encodeSubs(unhashed)); pad > 0 {
				// The two-octet form: 2 length octets, the type, and the data.
				unhashed = append(unhashed, sub{Type: 100, Data: bytes.Repeat([]byte{7}, pad-3)})
			}
			life := uint32(wt.subEnd.Sub(wt.subAt) / time.Second)
			binding := sigSpec{
				Type: 0x18,
				Hashed: []sub{
					{Type: 2, Data: u32at(wt.ceremony)},
					{Type: 27, Data: []byte{0x02}},
					{Type: 9, Critical: true, Data: u32(life)},
					{Type: 33, Data: append([]byte{4}, fp...)},
				},
				Unhashed: unhashed,
				Data:     [][]byte{hashPrefix(&s.key.PublicKey, wt.created), hashPrefix(&m.Key.PublicKey, wt.subAt)},
				Key:      s.key,
			}.build(t)
			if got := len(parseSig(t, splitPackets(t, binding)[0].Body).UnhashedRaw); got != c.area {
				t.Fatalf("the unhashed area holds %d bytes, the test meant %d", got, c.area)
			}
			ring := slices.Concat(cert, m.Packet, binding)
			w := world{signer: s, pp: pp, sub: m}
			sig := w.signMessage(t, now.Add(-time.Hour), message)
			fpr := fingerprintOf(t, &s.key.PublicKey, wt.created)
			if got := verifier.GPGVVerify(t, ring, sig, message, fpr) == nil; got != c.gpgvReads {
				t.Errorf("gpgv reads the binding: %v, want %v", got, c.gpgvReads)
			}
			if got := verifier.SQVVerify(t, ring, sig, message, fpr, now) == nil; got != c.sqvReadsIt {
				t.Errorf("sqv reads the binding: %v, want %v", got, c.sqvReadsIt)
			}
		})
	}
}

// The unhashed area of a binding that BindSubkey writes is the issuer key ID and the back-signature
// of the page, a few hundred bytes at most, so the guard on its length never bites on a back-signature
// of the page; a back-signature that would make it long is refused for its shape before that.
func TestTheUnhashedAreaOfABindingBuiltFromTheBackSignatureOfThePageIsFarBelowTheGuard(t *testing.T) {
	for _, long := range []bool{false, true} {
		_, b, m := bindFixture(t)
		b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.LongLengths = long })
		ps := splitPackets(t, bind(t, b))
		area := len(parseSig(t, ps[1].Body).UnhashedRaw)
		back := len(splitPackets(t, b.BackSig)[0].Body)
		// 10 for the issuer key ID, 2 for the length and the type of the embedding, and the body.
		if area != 10+2+back {
			t.Errorf("the unhashed area holds %d bytes for a back-signature of %d bytes", area, back)
		}
		if area > 300 {
			t.Errorf("the unhashed area holds %d bytes", area)
		}
	}
}

// What the tools do with the back-signatures that the builder let through before it held the exact
// shape of the page. A binding is built by hand around each, and at least one of the two tools
// refuses a message signed by the subkey under it: the root would have signed a binding that a
// relying party cannot use. BindSubkey refuses every one of them, and never asks the signer.
func TestEachBackSignatureThatATooLooseBuilderLetThroughMakesABindingThatAToolRefuses(t *testing.T) {
	wt := nowWorldTimes()
	now := nowSec()
	notation := append([]byte{0x80, 0, 0, 0, 0, 17, 0, 1}, []byte("probe@example.org"+"v")...)
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"a hashed critical notation", addHashed(sub{Type: 20, Critical: true, Data: notation})},
		{"an unhashed critical subpacket of type 99", addUnhashed(sub{Type: 99, Critical: true, Data: []byte{1, 2}})},
		{"an unhashed key expiration of one byte", addUnhashed(sub{Type: 9, Data: []byte{1}})},
		{"a hashed critical key server preferences", addHashed(sub{Type: 23, Critical: true, Data: []byte{0x80}})},
		{"a hashed critical signer's user ID", addHashed(sub{Type: 28, Critical: true, Data: []byte("Example Test")})},
		{"a hashed critical preferred AEAD ciphersuites", addHashed(sub{Type: 39, Critical: true, Data: []byte{9, 2}})},
	} {
		t.Run(c.name, func(t *testing.T) {
			ring, w := handBinding(t, wt, c.tweak)
			sig := w.signMessage(t, now.Add(-time.Hour), message)
			fp := fingerprintOf(t, &w.signer.key.PublicKey, wt.created)
			gpgvErr := verifier.GPGVVerify(t, ring, sig, message, fp)
			sqvErr := verifier.SQVVerify(t, ring, sig, message, fp, now)
			if gpgvErr == nil && sqvErr == nil {
				t.Error("both tools accept the binding: the refusal of the builder protects nothing")
			}
			t.Logf("by hand: gpgv refuses %v, sqv refuses %v", gpgvErr != nil, sqvErr != nil)
			bw, err := buildWorldFor(t, wt, c.tweak)
			if !errors.Is(err, openpgp.ErrRequest) || bw.bound != nil || bw.signer.calls != 0 {
				t.Errorf("BindSubkey: %v, %d bytes, signer asked %d times; want a refusal of the request, nothing and no call", err, len(bw.bound), bw.signer.calls)
			}
		})
	}
}
