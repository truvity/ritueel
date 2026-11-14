//go:build !race

//nolint:staticcheck // these tests write the numbers of a key in place, which is what a hostile caller does
package pki_test

import (
	"crypto/ecdsa"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// The two reads of the signing functions: a body is built from the key that a call copied, and the signer is held to the same copy.
// The key object is switched by a second goroutine between two whole valid keys, so a copy of it can be torn (the X of one key
// and the Y of the other): the call refuses it, as a key that changed while it was copied, or as numbers that are not a point. A
// copy that falls back to the caller's live object, and is read again for the key that the signer is compared with, is the
// fault that this test is there to catch.
// A caller that switches the key object between two whole valid keys during the call must not get a signature from a card that is
// not the key of the body: the card of the second key is never touched for the body of the first.
//
// What the test holds does not depend on how the two goroutines are scheduled. Whether a call is caught inside the short window of
// one copy depends on it (with one processor the writer runs only when the caller is preempted, and the window is short), so the
// test does not ask that any call is caught there; the states that decide the outcome are put in place one
// by one, with no second goroutine, in TestAKeyObjectInEachStateItCanBeSwitchedToIsNeverSignedForByTheWrongCard. What is asked here
// holds for every interleaving, and whatever the count of the calls that were caught:
//   - no call panics;
//   - every call that does not sign is refused as a parameter (ErrParams and no other kind);
//   - the card of the second key is never touched, and no signature is returned for it;
//   - the card of the first key signs only a signature of the first key over the body, and is touched once for each signature.
//
// The count of the calls that were refused as a key that changed while it was copied is logged, and asked for nothing.
func TestACallerThatSwitchesTheKeyObjectCannotTouchTheWrongCard(t *testing.T) {
	root := buildRoot(t, nil)
	other := newKey(t)
	const calls = 3000
	for _, fn := range []string{"SignIntermediate", "SignRoot"} {
		for _, c := range []struct {
			name  string
			key   *ecdsa.PrivateKey
			wrong bool // the card is not the key that the body names
		}{
			{"the card of the second key", other, true},
			{"the card of the first key", root.key, false},
		} {
			t.Run(fn+", "+c.name, func(t *testing.T) {
				shared := ownKey(t, &root.key.PublicKey)
				tbs, call := keySwitchCall(t, root, shared, fn)
				card := &hookSigner{key: c.key}
				var stop atomic.Bool
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; !stop.Load(); i++ {
						overwrite(shared, []*ecdsa.PublicKey{&root.key.PublicKey, &other.PublicKey}[i%2], true)
					}
				}()
				signed, changed, notPoint := 0, 0, 0
				var panicked any
				var wrongKind, badSignature, wrongSignature error
				func() {
					defer func() { panicked = recover() }()
					for i := 0; i < calls; i++ {
						sig, err := call(card)
						if err != nil {
							if sig != nil {
								wrongSignature = errors.New("a signature came with an error")
							}
							if !errors.Is(kindOf(t, err), pki.ErrParams) { // one kind, and it is ErrParams
								wrongKind = err
							}
							if strings.Contains(err.Error(), "a parameter changed while the call copied it") {
								changed++
							}
							if strings.Contains(err.Error(), "not a point") {
								notPoint++
							}
							continue
						}
						signed++
						if !ecdsa.VerifyASN1(&root.key.PublicKey, pki.TBSDigest(tbs), sig) {
							badSignature = errors.New("a signature that is not the signature of the first key over the body")
						}
					}
				}()
				stop.Store(true)
				wg.Wait()
				if panicked != nil {
					t.Fatalf("a call panicked: %v", panicked)
				}
				t.Logf("%s, %s: %d calls, %d signatures, the card touched %d times, %d refused as a key that changed while it was copied, %d refused as a torn key that is not a point",
					fn, c.name, calls, signed, card.signs, changed, notPoint)
				if wrongKind != nil {
					t.Errorf("a call was refused in a kind other than ErrParams: %v", wrongKind)
				}
				if wrongSignature != nil {
					t.Error(wrongSignature)
				}
				if badSignature != nil {
					t.Error(badSignature)
				}
				if c.wrong && (signed != 0 || card.signs != 0) {
					t.Errorf("%d signatures from a card that the body does not name, the card touched %d times", signed, card.signs)
				}
				if card.signs != signed {
					t.Errorf("the card was touched %d times for %d signatures: a card was touched for a call that did not sign", card.signs, signed)
				}
			})
		}
	}
}
