package openpgp_test

import (
	"bytes"
	"fmt"
	"slices"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/verifier"
)

// The reader of an answer is held to the two programs that read the same bindings: a binding that
// VerifyBinding accepts is one that gpgv and sqv accept, so that the requester never installs a
// subkey that a verifier will refuse. Only gpgv and sqv are started, each with a keyring file of its
// own (internal/verifier); the world is built around the real clock, as in the differential test.

// toolBinding is the binding of the page for the world, as a spec the test may change.
func toolBinding(t testing.TB, w world, wt worldTimes, tweak func(*sigSpec)) []byte {
	t.Helper()
	fp := fingerprint(&w.signer.key.PublicKey, wt.created)
	sp := sigSpec{
		Type: 0x18,
		Hashed: []sub{
			{Type: 2, Data: u32at(wt.ceremony)},
			{Type: 27, Data: []byte{0x02}},
			{Type: 9, Critical: true, Data: u32(uint32(wt.subEnd.Sub(wt.subAt) / time.Second))},
			{Type: 33, Data: append([]byte{4}, fp...)},
		},
		Unhashed: []sub{{Type: 16, Data: fp[12:]}, {Type: 32, Data: splitPackets(t, w.sub.BackSig)[0].Body}},
		Data:     [][]byte{hashPrefix(&w.signer.key.PublicKey, wt.created), hashPrefix(&w.sub.Key.PublicKey, wt.subAt)},
		Key:      w.signer.key,
	}
	if tweak != nil {
		tweak(&sp)
	}
	return sp.build(t)
}

func TestWhatVerifyBindingAcceptsGpgvAndSqvAcceptToo(t *testing.T) {
	long := func(sp *sigSpec) { sp.LongLengths = true }
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"the binding of the page", nil},
		{"the subpackets in the reverse order", func(sp *sigSpec) {
			slices.Reverse(sp.Hashed)
			slices.Reverse(sp.Unhashed)
		}},
		{"five-byte lengths", long},
		{"an old-format header", func(sp *sigSpec) { sp.OldHeader = true }},
	} {
		t.Run(c.name, func(t *testing.T) {
			wt := nowWorldTimes()
			w := buildWorld(t, wt)
			binding := toolBinding(t, w, wt, c.tweak)
			primary, err := openpgp.NewPrimaryKey(&w.signer.key.PublicKey, wt.created)
			if err != nil {
				t.Fatal(err)
			}
			sk, err := openpgp.ReadSubkey(w.sub.Packet)
			if err != nil {
				t.Fatal(err)
			}
			got, verr := openpgp.VerifyBinding(binding, primary, sk)
			ring := slices.Concat(w.cert, w.sub.Packet, binding)
			now := nowSec()
			sig := w.signMessage(t, now.Add(-time.Hour), message)
			fpr := w.fp(t)
			gpgv := verifier.GPGVVerify(t, ring, sig, message, fpr) == nil
			sqv := verifier.SQVVerify(t, ring, sig, message, fpr, now) == nil
			if verr == nil && (!gpgv || !sqv) {
				t.Errorf("VerifyBinding accepts the binding; gpgv reads it: %v, sqv reads it: %v", gpgv, sqv)
			}
			if verr != nil || got == nil {
				t.Errorf("VerifyBinding refuses a binding of the page: %v", verr)
			}
			if !gpgv || !sqv {
				t.Errorf("a binding of the page is read by gpgv: %v, by sqv: %v", gpgv, sqv)
			}
		})
	}
}

// The measure of the limit in the form that VerifyBinding must hold: gpgv reads an unhashed area by
// the bytes it is written in, so an area written with five-byte lengths is read up to 10000 bytes,
// and not by the bytes of the same subpackets in their shortest form.
func TestGpgvReadsAnUnhashedAreaByTheBytesItIsWrittenIn(t *testing.T) {
	for _, c := range []struct {
		area      int
		gpgvReads bool
	}{{9999, true}, {10000, true}, {10001, false}, {10003, false}} {
		t.Run(fmt.Sprintf("%d bytes", c.area), func(t *testing.T) {
			wt := nowWorldTimes()
			w := buildWorld(t, wt)
			// The area is padded with a subpacket of an unknown type, so that the back-signature in it
			// is the real one and sqv reads the binding; the five-byte lengths make it as long as
			// it is written. VerifyBinding refuses such a binding for the extra subpacket.
			binding := toolBinding(t, w, wt, func(sp *sigSpec) {
				sp.LongLengths = true
				pad := c.area - 14 - (6 + len(sp.Unhashed[1].Data)) - 6
				sp.Unhashed = append(sp.Unhashed, sub{Type: 100, Data: bytes.Repeat([]byte{7}, pad)})
			})
			if got := layoutOf(bodyOf(t, binding)).unhashedLen; got != c.area {
				t.Fatalf("the unhashed area holds %d bytes, the test meant %d", got, c.area)
			}
			ring := slices.Concat(w.cert, w.sub.Packet, binding)
			now := nowSec()
			sig := w.signMessage(t, now.Add(-time.Hour), message)
			if got := verifier.GPGVVerify(t, ring, sig, message, w.fp(t)) == nil; got != c.gpgvReads {
				t.Errorf("gpgv reads the binding: %v, want %v", got, c.gpgvReads)
			}
			if verifier.SQVVerify(t, ring, sig, message, w.fp(t), now) != nil {
				t.Error("sqv refuses a binding that only gpgv is expected to refuse")
			}
		})
	}
}

// A binding that BindSubkey writes for the world is accepted by VerifyBinding, and the tools read the
// same bytes. The control of the tests above: the setup of the world is not what is refused.
// VerifyBinding does not read the embedded signature: that is the comparison of Embeds, which the
// requester makes with its own back-signature. The two programs do read it: a binding whose embedded
// signature is not a signature is refused by sqv. So VerifyBinding alone is not "what a verifier
// accepts", and Embeds is not optional.
func TestABindingWithAnEmbeddedSignatureThatIsNoBackSignatureIsOneThatOnlyEmbedsRefuses(t *testing.T) {
	wt := nowWorldTimes()
	w := buildWorld(t, wt)
	binding := toolBinding(t, w, wt, func(sp *sigSpec) { sp.Unhashed[1].Data = []byte{1, 2, 3, 4, 5} })
	primary, err := openpgp.NewPrimaryKey(&w.signer.key.PublicKey, wt.created)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := openpgp.ReadSubkey(w.sub.Packet)
	if err != nil {
		t.Fatal(err)
	}
	b, err := openpgp.VerifyBinding(binding, primary, sk)
	if err != nil || b == nil {
		t.Fatalf("VerifyBinding: %v", err)
	}
	if b.Embeds(w.sub.BackSig) {
		t.Error("Embeds takes a made-up embedded signature for the request's back-signature")
	}
	ring := slices.Concat(w.cert, w.sub.Packet, binding)
	now := nowSec()
	sig := w.signMessage(t, now.Add(-time.Hour), message)
	if verifier.SQVVerify(t, ring, sig, message, w.fp(t), now) == nil {
		t.Error("sqv reads a binding whose embedded signature is not a signature")
	}
}

func TestTheBindingThatBindSubkeyWritesIsReadByTheReaderAndByBothTools(t *testing.T) {
	wt := nowWorldTimes()
	w := buildWorld(t, wt)
	subPkt, binding, err := openpgp.SplitBoundFile(w.bound)
	if err != nil {
		t.Fatal(err)
	}
	primary, err := openpgp.NewPrimaryKey(&w.signer.key.PublicKey, wt.created)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := openpgp.ReadSubkey(subPkt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.VerifyBinding(binding, primary, sk); err != nil {
		t.Fatalf("VerifyBinding: %v", err)
	}
	now := nowSec()
	sig := w.signMessage(t, now.Add(-time.Hour), message)
	if err := verifier.GPGVVerify(t, w.keyring, sig, message, w.fp(t)); err != nil {
		t.Errorf("gpgv: %v", err)
	}
	if err := verifier.SQVVerify(t, w.keyring, sig, message, w.fp(t), now); err != nil {
		t.Errorf("sqv: %v", err)
	}
}

// gpgv reads the end of a subkey as a 32-bit time: an end after the last second of a time field is
// read as a wrapped time. The measure behind TestAnEndAfterTheLastSecondOfATimeFieldIsRefused.
func TestGpgvReadsAnEndThatPassesTheTimeFieldAsAWrappedTime(t *testing.T) {
	for _, c := range []struct {
		name      string
		life      func(wt worldTimes) uint32
		gpgvReads bool
	}{
		{"an end at the last second", func(wt worldTimes) uint32 { return uint32(lastSecond - wt.subAt.Unix()) }, true},
		{"a key expiration of 0xC0000000", func(worldTimes) uint32 { return 0xC0000000 }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			wt := nowWorldTimes()
			w := buildWorld(t, wt)
			binding := toolBinding(t, w, wt, func(sp *sigSpec) { sp.Hashed[2].Data = u32(c.life(wt)) })
			ring := slices.Concat(w.cert, w.sub.Packet, binding)
			now := nowSec()
			sig := w.signMessage(t, now.Add(-time.Hour), message)
			if got := verifier.GPGVVerify(t, ring, sig, message, w.fp(t)) == nil; got != c.gpgvReads {
				t.Errorf("gpgv reads the binding: %v, want %v", got, c.gpgvReads)
			}
		})
	}
}
