//go:build !race

//nolint:staticcheck // these tests write the numbers of a key in place, which is what a hostile caller does
package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// This file is left out of a run with the race detector, and only for this reason: a caller that writes to a parameter while a
// call reads it has a data race of its own, and the detector reports it, as the caller's, and fails the run. That is what the test
// does on purpose, with a second goroutine, because a write between two reads inside one function cannot be reached by a hook at a
// fixed point. What the test asserts is not about the race: the call must not panic, and a body that is returned must be, part by
// part and as a whole, the body of one of the two values that the writer switches between (a refusal is allowed). The package
// copies each parameter twice and refuses a call when the two copies differ; a writer that stops half way through a value for
// both copies cannot be caught, so a returned body of a mixed value is counted and the test fails on it.

func TestACallerThatRewritesAParameterDuringACallCannotMakeTheCallPanicOrReturnAMixedBody(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	const calls = 1500

	// Two whole values of each parameter, of the same length.
	serialA, serialB := new(big.Int).Set(aSerial), new(big.Int).Xor(aSerial, big.NewInt(0x0f0f0f0f))
	serialShort := new(big.Int).SetBytes([]byte{0x80, 1, 2, 3, 4, 5, 6, 7, 8})
	issuerA, issuerB := cnName(tUTF8, "a root named alpha"), cnName(tUTF8, "a root named bravo")
	csrA, csrB := sameLengthRequests(t)
	keyA, keyB := &root.key.PublicKey, &newKey(t).PublicKey
	rootBName, rootBName2 := cnName(tUTF8, "another root beta"), cnName(tUTF8, "another root zeta")
	keyBRoot, keyBRoot2 := &newKey(t).PublicKey, &newKey(t).PublicKey

	base := func() pki.IntermediateParams {
		p := root.interParams(good)
		p.CSR, p.IssuerSubject, p.Serial = append([]byte(nil), csrA...), append([]byte(nil), issuerA...), new(big.Int).Set(serialA)
		p.IssuerKey = ownKey(t, keyA)
		// The roots of the bundle: the issuer (the same slice and the same key object as the issuer parameters, so that a writer that
		// changes the issuer in place changes the root with it), and another root of the bundle that the writer may change too.
		p.Roots = []pki.RootRef{{Subject: p.IssuerSubject, Key: p.IssuerKey}, {Subject: append([]byte(nil), rootBName...), Key: ownKey(t, keyBRoot)}}
		return p
	}
	cases := []struct {
		name  string
		write func(p *pki.IntermediateParams, i int) // writes the whole of value i of the parameter, in place
		// lengths: the two values are of different lengths. A number whose size changes under the copy can be copied torn (the words
		// of one value and of the other), and the two copies of one call can agree on the torn number; the package cannot prevent
		// that, it is the caller's race, and the test asks only that the call does not panic and that what it returns is a body of
		// the profile (a serial of 64 to 159 bits).
		lengths bool
		// invalidB: value 1 is a value that the package refuses (a serial of 160 bits, an issuer name with an octet that is not
		// UTF-8, a request with a changed signature), and differs from value 0 in one word or one octet, so that it cannot be
		// copied torn. A call that checked value 0 and then built the body from value 1 (a parameter read twice) would return a
		// body that is not the body of value 0; a call that works on one copy returns the body of value 0, or is refused.
		invalidB bool
	}{
		{"the serial", func(p *pki.IntermediateParams, i int) { p.Serial.Set([]*big.Int{serialA, serialB}[i]) }, false, false},
		// Two serials of different lengths (20 octets and 9): a number whose size changes while it is read is what made the
		// DER writer panic before the serial was copied.
		{"the serial, of two lengths", func(p *pki.IntermediateParams, i int) { p.Serial.Set([]*big.Int{serialA, serialShort}[i]) }, true, false},
		{"the issuer name", func(p *pki.IntermediateParams, i int) { copy(p.IssuerSubject, [][]byte{issuerA, issuerB}[i]) }, false, false},
		{"the request", func(p *pki.IntermediateParams, i int) { copy(p.CSR, [][]byte{csrA, csrB}[i]) }, false, false},
		{"the key of the issuer", func(p *pki.IntermediateParams, i int) {
			k, src := p.IssuerKey.(*ecdsa.PublicKey), []*ecdsa.PublicKey{keyA, keyB}[i]
			k.X.Set(src.X)
			k.Y.Set(src.Y)
		}, false, false},
		// Another root of the bundle (not the issuer): the body does not depend on it, so every body that is returned is the same
		// body, and a refusal is allowed.
		{"the name of another root of the bundle", func(p *pki.IntermediateParams, i int) { copy(p.Roots[1].Subject, [][]byte{rootBName, rootBName2}[i]) }, false, false},
		{"the key of another root of the bundle", func(p *pki.IntermediateParams, i int) {
			k, src := p.Roots[1].Key.(*ecdsa.PublicKey), []*ecdsa.PublicKey{keyBRoot, keyBRoot2}[i]
			k.X.Set(src.X)
			k.Y.Set(src.Y)
		}, false, false},
		{"the name of another root, valid and then with an octet that is not UTF-8", func(p *pki.IntermediateParams, i int) {
			p.Roots[1].Subject[bytes.Index(rootBName, []byte("beta"))] = []byte{'b', 0xff}[i%2]
		}, false, true},
		{"the serial, valid and then of 160 bits", func(p *pki.IntermediateParams, i int) { p.Serial.SetBit(p.Serial, 159, uint(i%2)) }, false, true},
		{"the issuer name, valid and then with an octet that is not UTF-8", func(p *pki.IntermediateParams, i int) {
			p.IssuerSubject[bytes.Index(issuerA, []byte("root"))] = []byte{'r', 0xff}[i%2]
		}, false, true},
		{"the request, valid and then with a changed signature", func(p *pki.IntermediateParams, i int) {
			p.CSR[len(p.CSR)-1] = []byte{csrA[len(csrA)-1], csrA[len(csrA)-1] ^ 1}[i%2]
		}, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The body of each of the two values, every other parameter fixed.
			var want [2][]byte
			for i := range want {
				p := base()
				c.write(&p, i)
				b, err := pki.IntermediateTBS(p)
				if err != nil {
					if c.invalidB && i == 1 {
						continue // refused: that is the point of the value
					}
					t.Fatalf("the body of value %d: %v", i, err)
				}
				if c.invalidB && i == 1 {
					t.Fatalf("the value 1 of %s is not refused", c.name)
				}
				want[i] = b
			}
			p := base()
			var stop atomic.Bool
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; !stop.Load(); i++ {
					c.write(&p, i%2)
				}
			}()
			returned, refusedN, mixed := 0, 0, 0
			texts := map[string]int{}
			var panicked any
			func() {
				defer func() { panicked = recover() }()
				for i := 0; i < calls; i++ {
					tbs, err := pki.IntermediateTBS(p)
					if err != nil {
						refusedN++
						texts[err.Error()[:min(len(err.Error()), 70)]]++
						// No refusal is the second reading of the finished body, which only a fault of the package reaches: a call that
						// checked one value and wrote the body from another is what would reach it.
						if strings.Contains(err.Error(), "a fault of this package") || strings.Contains(err.Error(), "standard library") {
							t.Errorf("the call was refused by the reading of the finished body: %v", err)
						}
						_ = kindOf(t, err) // a refusal is allowed, in one kind of the package
						continue
					}
					returned++
					if !bytes.Equal(tbs, want[0]) && !bytes.Equal(tbs, want[1]) {
						mixed++
						if c.lengths {
							if err := pki.CheckSerial(parseBodyOf(t, tbs).SerialNumber); err != nil {
								t.Errorf("a body with a serial that is not of the profile: %v", err)
							}
						}
					}
				}
			}()
			stop.Store(true)
			wg.Wait()
			if panicked != nil {
				t.Fatalf("a call panicked: %v", panicked)
			}
			t.Logf("refusals by text: %v", texts)
			// The refusal "a parameter changed while the call copied it" can be forced only by a writer in a second goroutine; it
			// is reached here, for the serial and the request, where the call is refused most often.
			changed := 0
			for text, n := range texts {
				if strings.Contains(text, "a parameter changed while the call copied it") {
					changed += n
				}
			}
			if (c.name == "the serial" || c.name == "the request") && changed == 0 {
				t.Errorf("no call was refused for a parameter that changed while it was copied, in %d refusals", refusedN)
			}
			t.Logf("%s: %d calls, %d returned (%d not the body of either value), %d refused", c.name, calls, returned, mixed, refusedN)
			if mixed != 0 && !c.lengths {
				t.Errorf("%d bodies of a mixed value were returned", mixed)
			}
		})
	}
}

// sameLengthRequests are two requests of the same length, of two keys and two subjects.
func sameLengthRequests(t *testing.T) ([]byte, []byte) {
	t.Helper()
	for try := 0; try < 200; try++ {
		a := withExtensions(t, goodExtensions()...)
		b := withExtensions(t, goodExtensions()...)
		a.RawSubject, b.RawSubject = cnName(tUTF8, "request alpha"), cnName(tUTF8, "request bravo")
		if da, db := a.DER(), b.DER(); len(da) == len(db) {
			return da, db
		}
	}
	t.Fatal("no two requests of the same length")
	return nil, nil
}

// Assemble reads its body, its signature and its key more than once; a caller that switches the body or the signature between a
// good value and a bad one during the call must not get a certificate whose signature does not verify.
func TestACallerThatRewritesTheBodyOrTheSignatureDuringAssembleGetsOnlyACertificateThatVerifies(t *testing.T) {
	f := newGuardFixture(t)
	const calls = 1500
	goodSig := rawSign(t, f.root.key, f.root.tbs)
	for _, what := range []string{"the body", "the signature"} {
		t.Run(what, func(t *testing.T) {
			tbs := append([]byte(nil), f.root.tbs...)
			sig := append([]byte(nil), goodSig...)
			serialAt := bytes.Index(tbs, f.root.params.Serial.Bytes()) + len(f.root.params.Serial.Bytes()) - 1
			var stop atomic.Bool
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; !stop.Load(); i++ {
					if what == "the body" { // the last octet of the serial: another body of the profile
						tbs[serialAt] = f.root.tbs[serialAt] ^ byte(i%2)
					} else {
						sig[len(sig)-1] = goodSig[len(goodSig)-1] ^ byte(i%2)
					}
				}
			}()
			certs, bad := 0, 0
			var panicked any
			func() {
				defer func() { panicked = recover() }()
				for i := 0; i < calls; i++ {
					der, err := pki.Assemble(tbs, sig, &f.root.key.PublicKey)
					if err != nil {
						_ = kindOf(t, err)
						continue
					}
					certs++
					cert, perr := x509.ParseCertificate(der)
					if perr != nil || cert.CheckSignatureFrom(cert) != nil {
						bad++
					}
				}
			}()
			stop.Store(true)
			wg.Wait()
			if panicked != nil {
				t.Fatalf("a call panicked: %v", panicked)
			}
			t.Logf("%s: %d calls, %d certificates, %d of them with a signature that does not verify", what, calls, certs, bad)
			if bad != 0 {
				t.Errorf("%d certificates whose signature does not verify", bad)
			}
		})
	}
}

// RootTBS: the serial and the key read more than once. A serial that is valid and then of 160 bits, a key that is valid and
// then another number: the body is the body of the valid value, or the call is refused, never by the reading of the finished body.
func TestACallerThatRewritesTheRootsParametersDuringACall(t *testing.T) {
	const calls = 1500
	key := newKey(t)
	for _, what := range []string{"the serial", "the key"} {
		t.Run(what, func(t *testing.T) {
			shared := ownKey(t, &key.PublicKey)
			p := rootParams(shared)
			p.Serial = new(big.Int).Set(aSerial)
			want, err := pki.RootTBS(p)
			if err != nil {
				t.Fatal(err)
			}
			var stop atomic.Bool
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; !stop.Load(); i++ {
					if what == "the serial" {
						p.Serial.SetBit(p.Serial, 159, uint(i%2))
					} else {
						shared.X.SetBit(shared.X, 0, uint(i%2)^shared.X.Bit(0))
					}
				}
			}()
			returned, refusedN, wrong := 0, 0, 0
			var panicked any
			func() {
				defer func() { panicked = recover() }()
				for i := 0; i < calls; i++ {
					tbs, err := pki.RootTBS(p)
					if err != nil {
						refusedN++
						if strings.Contains(err.Error(), "a fault of this package") || strings.Contains(err.Error(), "standard library") {
							t.Errorf("refused by the reading of the finished body: %v", err)
						}
						continue
					}
					returned++
					if !bytes.Equal(tbs, want) {
						wrong++
					}
				}
			}()
			stop.Store(true)
			wg.Wait()
			if panicked != nil {
				t.Fatalf("a call panicked: %v", panicked)
			}
			t.Logf("%s: %d calls, %d returned (%d not the body of the valid value), %d refused", what, calls, returned, wrong, refusedN)
			if what == "the serial" && wrong != 0 {
				t.Errorf("%d bodies that are not the body of the valid value", wrong)
			}
		})
	}
}
