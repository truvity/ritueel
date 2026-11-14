//go:build !race

//nolint:staticcheck // these tests write the numbers of a key in place, which is what a hostile caller does
package pki_test

import (
	"crypto/ecdsa"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// The two reads of the signing functions: a body is built from the key that a call copied, and the signer is held to the same copy.
// (It was red until the copy of a key stopped falling back to the caller's object.) The key object is switched by a second goroutine between two whole valid keys, so
// a copy of it can be torn (the X of one key and the Y of the other), which is not a point; keyCopy then returns the caller's live
// object, and the call reads it again for the key that the signer is compared with.
// A caller that switches the key object between two whole valid keys during the call must not get a signature from a card that is
// not the key of the body: the card of the second key is never touched for the body of the first.
func TestACallerThatSwitchesTheKeyObjectCannotTouchTheWrongCard(t *testing.T) {
	root := buildRoot(t, nil)
	other := newKey(t)
	const calls = 6000
	for _, fn := range []string{"SignIntermediate", "SignRoot"} {
		t.Run(fn, func(t *testing.T) {
			shared := ownKey(t, &root.key.PublicKey)
			var tbs []byte
			var call func(s *hookSigner) ([]byte, error)
			switch fn {
			case "SignIntermediate":
				p := root.interParams(withExtensions(t, goodExtensions()...))
				p.IssuerKey = shared
				b, err := pki.IntermediateTBS(p)
				if err != nil {
					t.Fatal(err)
				}
				tbs = b
				call = func(s *hookSigner) ([]byte, error) { return pki.SignIntermediate(nil, s, p, tbs) }
			default:
				p := rootParams(shared)
				b, err := pki.RootTBS(p)
				if err != nil {
					t.Fatal(err)
				}
				tbs = b
				call = func(s *hookSigner) ([]byte, error) { return pki.SignRoot(nil, s, p, tbs) }
			}
			card := &hookSigner{key: other} // the card of the second key: the body names the first
			var stop atomic.Bool
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; !stop.Load(); i++ {
					overwrite(shared, []*ecdsa.PublicKey{&root.key.PublicKey, &other.PublicKey}[i%2], true)
				}
			}()
			signed, changed := 0, 0
			var panicked any
			func() {
				defer func() { panicked = recover() }()
				for i := 0; i < calls; i++ {
					sig, err := call(card)
					if err == nil || sig != nil {
						signed++
					} else if strings.Contains(err.Error(), "a parameter changed while the call copied it") {
						changed++
					}
				}
			}()
			stop.Store(true)
			wg.Wait()
			if panicked != nil {
				t.Fatalf("a call panicked: %v", panicked)
			}
			t.Logf("%s: %d calls, %d signatures, the card touched %d times", fn, calls, signed, card.signs)
			// A copy of the key that is torn (the X of one key and the Y of the other) is refused as a change, which is what the second
			// look at the object finds; without it the refusal would say only that the numbers are not a point.
			if changed == 0 {
				t.Errorf("no call was refused as a key that changed while it was copied, in %d calls", calls)
			}
			if signed != 0 || card.signs != 0 {
				t.Errorf("%d signatures from a card that the body does not name, the card touched %d times", signed, card.signs)
			}
		})
	}
}
