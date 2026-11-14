//nolint:staticcheck // these tests write the numbers of a key in place, which is what a hostile caller does
package pki_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// Every exported function takes its own copy of everything that it reads more than once, at its top, and works only on the
// copies; the public key of a signer is asked for once, copied, and compared with the key that the body was built from. These
// tests show it through the public surface, with hooks that run at a fixed point of a call: a signer's Public and Sign run
// after the package has copied its parameters, so what they write to the caller's objects must not reach the call. What
// cannot be reached without a second goroutine (a write between two reads inside one function) is the racing test of
// copies_norace_test.go.

// hookSigner is a signer with a key of its own and hooks that run when it is asked for its public key and when it signs.
type hookSigner struct {
	key             *ecdsa.PrivateKey
	onPublic, onSig func()
	publics, signs  int
}

func (h *hookSigner) Public() crypto.PublicKey {
	h.publics++
	if h.onPublic != nil {
		h.onPublic()
	}
	return &h.key.PublicKey
}

func (h *hookSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	h.signs++
	if h.onSig != nil {
		h.onSig()
	}
	return ecdsa.SignASN1(rand.Reader, h.key, digest)
}

// ownKey is a public key that shares no number with k: the caller's own object, which a test may write to.
func ownKey(t testing.TB, k *ecdsa.PublicKey) *ecdsa.PublicKey {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	c, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// overwrite changes the caller's key object to hold the key of other, in the two ways that a caller can: the struct is assigned
// (the numbers of the other key are shared), or the numbers are written in place.
func overwrite(target, other *ecdsa.PublicKey, inPlace bool) {
	if inPlace {
		target.X.Set(other.X)
		target.Y.Set(other.Y)
		return
	}
	*target = *other
}

func TestASignerThatRewritesTheCallersKeyObjectIsRefusedBeforeItIsTouched(t *testing.T) {
	root := buildRoot(t, nil)
	other := newKey(t)
	for _, inPlace := range []bool{false, true} {
		mode := map[bool]string{false: "the struct assigned", true: "the numbers written in place"}[inPlace]
		t.Run("SignIntermediate, "+mode, func(t *testing.T) {
			shared := ownKey(t, &root.key.PublicKey)
			p := root.interParams(withExtensions(t, goodExtensions()...))
			p.IssuerKey = shared
			tbs, err := pki.IntermediateTBS(p) // the body names the key of the root
			if err != nil {
				t.Fatal(err)
			}
			// The card is another key whose Public rewrites the caller's key object to itself: the body does not name it.
			s := &hookSigner{key: other}
			s.onPublic = func() { overwrite(shared, &other.PublicKey, inPlace) }
			sig, err := pki.SignIntermediate(nil, s, p, tbs)
			refused(t, err, pki.ErrParams)
			if sig != nil || s.signs != 0 {
				t.Errorf("a signature came, or the card was touched %d times, for a body that does not name it", s.signs)
			}
			if s.publics != 1 {
				t.Errorf("the signer was asked for its key %d times, want once", s.publics)
			}
		})
		t.Run("SignRoot, "+mode, func(t *testing.T) {
			first := newKey(t)
			shared := ownKey(t, &first.PublicKey)
			p := rootParams(shared)
			tbs, err := pki.RootTBS(p)
			if err != nil {
				t.Fatal(err)
			}
			s := &hookSigner{key: other}
			s.onPublic = func() { overwrite(shared, &other.PublicKey, inPlace) }
			sig, err := pki.SignRoot(nil, s, p, tbs)
			refused(t, err, pki.ErrParams)
			if sig != nil || s.signs != 0 {
				t.Errorf("a signature came, or the card was touched %d times, for a body that does not name it", s.signs)
			}
			if s.publics != 1 {
				t.Errorf("the signer was asked for its key %d times, want once", s.publics)
			}
		})
		// The right card, whose Public rewrites the caller's key object to another key: the call works on its copy, so it signs, and
		// the signature is for the body that was built.
		t.Run("SignIntermediate, the right card, the caller's key rewritten, "+mode, func(t *testing.T) {
			shared := ownKey(t, &root.key.PublicKey)
			p := root.interParams(withExtensions(t, goodExtensions()...))
			p.IssuerKey = shared
			tbs, err := pki.IntermediateTBS(p)
			if err != nil {
				t.Fatal(err)
			}
			s := &hookSigner{key: root.key}
			s.onPublic = func() { overwrite(shared, &other.PublicKey, inPlace) }
			sig, err := pki.SignIntermediate(nil, s, p, tbs)
			if err != nil {
				t.Fatalf("the right card is refused because the caller wrote to its own key object: %v", err)
			}
			if s.signs != 1 {
				t.Errorf("the card was touched %d times, want once", s.signs)
			}
			if _, err := pki.Assemble(tbs, sig, &root.key.PublicKey); err != nil {
				t.Errorf("the signature is not for the body that was built: %v", err)
			}
		})
		t.Run("SignRoot, the right card, the caller's key rewritten, "+mode, func(t *testing.T) {
			key := newKey(t)
			shared := ownKey(t, &key.PublicKey)
			p := rootParams(shared)
			tbs, err := pki.RootTBS(p)
			if err != nil {
				t.Fatal(err)
			}
			s := &hookSigner{key: key}
			s.onPublic = func() { overwrite(shared, &other.PublicKey, inPlace) }
			sig, err := pki.SignRoot(nil, s, p, tbs)
			if err != nil {
				t.Fatalf("the right card is refused because the caller wrote to its own key object: %v", err)
			}
			if _, err := pki.Assemble(tbs, sig, &key.PublicKey); err != nil {
				t.Errorf("the signature is not for the body that was built: %v", err)
			}
		})
	}
}

// A signer that gives another key on each call is asked once, and the first answer is the one that counts.
func TestASignerWhoseKeyChangesIsAskedOnce(t *testing.T) {
	f := newGuardFixture(t)
	other := newKey(t)
	for _, c := range []struct {
		name          string
		first, second *ecdsa.PrivateKey
		ok            bool
	}{
		{"the right key first, another after", f.root.key, other, true},
		{"another key first, the right one after", other, f.root.key, false},
	} {
		for fn, call := range map[string]func(s crypto.Signer) ([]byte, error){
			"SignRoot": func(s crypto.Signer) ([]byte, error) { return pki.SignRoot(nil, s, f.root.params, f.root.tbs) },
			"SignIntermediate": func(s crypto.Signer) ([]byte, error) {
				return pki.SignIntermediate(nil, s, f.inter.params, f.inter.tbs)
			},
		} {
			t.Run(fn+": "+c.name, func(t *testing.T) {
				first := &flippingSigner{private: f.root.key, keys: []*ecdsa.PublicKey{&c.first.PublicKey, &c.second.PublicKey}}
				sig, err := call(first)
				if c.ok {
					if err != nil {
						t.Fatal(err)
					}
					if _, err := pki.Assemble(map[string][]byte{"SignRoot": f.root.tbs, "SignIntermediate": f.inter.tbs}[fn], sig, &f.root.key.PublicKey); err != nil {
						t.Errorf("the signature does not verify: %v", err)
					}
				} else {
					refused(t, err, pki.ErrParams)
					if sig != nil || first.signs != 0 {
						t.Errorf("a signature came, or the card was touched %d times", first.signs)
					}
				}
				if first.asked != 1 {
					t.Errorf("the signer was asked for its key %d times, want once", first.asked)
				}
			})
		}
	}
}

// flippingSigner answers each call of Public with the next of its keys, and signs with the private key it holds.
type flippingSigner struct {
	private *ecdsa.PrivateKey
	keys    []*ecdsa.PublicKey
	asked   int
	signs   int
}

func (f *flippingSigner) Public() crypto.PublicKey {
	k := f.keys[min(f.asked, len(f.keys)-1)]
	f.asked++
	return k
}

func (f *flippingSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	f.signs++
	return ecdsa.SignASN1(rand.Reader, f.private, digest)
}

// What the caller writes at the fixed points of a call, after the package has copied its parameters (in the signer's Public and
// in its Sign, which run in the middle of SignRoot and SignIntermediate), does not reach the call: the signature is for the body
// of the values that the call was given.
func TestWhatTheCallerWritesDuringTheCallDoesNotReachIt(t *testing.T) {
	root := buildRoot(t, nil)
	// A bundle of the caller's own parameters, each a value that a test can write to.
	build := func(t *testing.T) (pki.IntermediateParams, []byte, *ecdsa.PublicKey, func()) {
		shared := ownKey(t, &root.key.PublicKey)
		p := root.interParams(withExtensions(t, goodExtensions()...))
		p.IssuerKey = shared
		p.Serial = new(big.Int).Set(aSerial)
		p.IssuerSubject = append([]byte(nil), p.IssuerSubject...)
		tbs, err := pki.IntermediateTBS(p)
		if err != nil {
			t.Fatal(err)
		}
		tbs = append([]byte(nil), tbs...)
		scribble := func() { // every parameter written, to another value of the same length
			p.Serial.Add(p.Serial, big.NewInt(1))
			for i := range p.CSR {
				p.CSR[i] ^= 0xff
			}
			for i := range p.IssuerSubject {
				p.IssuerSubject[i] ^= 0x20
			}
			for i := range tbs {
				tbs[i] ^= 0xff
			}
			other := newKey(t)
			overwrite(shared, &other.PublicKey, true)
		}
		return p, tbs, shared, scribble
	}
	for _, hook := range []string{"in Public", "in Sign"} {
		t.Run("SignIntermediate, a caller that writes everything "+hook, func(t *testing.T) {
			p, tbs, _, scribble := build(t)
			original := append([]byte(nil), tbs...)
			s := &hookSigner{key: root.key}
			if hook == "in Public" {
				s.onPublic = scribble
			} else {
				s.onSig = scribble
			}
			sig, err := pki.SignIntermediate(nil, s, p, tbs)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if _, err := pki.Assemble(original, sig, &root.key.PublicKey); err != nil {
				t.Errorf("the signature is not for the body of the values that the call was given: %v", err)
			}
		})
	}
	for _, hook := range []string{"in Public", "in Sign"} {
		t.Run("SignRoot, a caller that writes everything "+hook, func(t *testing.T) {
			key := newKey(t)
			shared := ownKey(t, &key.PublicKey)
			p := rootParams(shared)
			p.Serial = new(big.Int).Set(aSerial)
			tbs, err := pki.RootTBS(p)
			if err != nil {
				t.Fatal(err)
			}
			tbs = append([]byte(nil), tbs...)
			original := append([]byte(nil), tbs...)
			scribble := func() {
				p.Serial.Add(p.Serial, big.NewInt(1))
				for i := range tbs {
					tbs[i] ^= 0xff
				}
				other := newKey(t)
				overwrite(shared, &other.PublicKey, true)
			}
			s := &hookSigner{key: key}
			if hook == "in Public" {
				s.onPublic = scribble
			} else {
				s.onSig = scribble
			}
			sig, err := pki.SignRoot(nil, s, p, tbs)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if _, err := pki.Assemble(original, sig, &key.PublicKey); err != nil {
				t.Errorf("the signature is not for the body of the values that the call was given: %v", err)
			}
		})
	}
}

// snapshot is a deep copy of the parameters of a call, to compare with them afterwards.
type snapshot struct {
	serial     *big.Int
	csr, iss   []byte
	tbs, sig   []byte
	keyX, keyY *big.Int // the numbers of the key object, as values
	keyXp      *big.Int // and the pointers, to see that the caller's object was not made to point elsewhere
	keyYp      *big.Int
}

type bundle struct {
	serial   *big.Int
	csr, iss []byte
	tbs, sig []byte
	key      *ecdsa.PublicKey
}

func (b *bundle) snap() snapshot {
	return snapshot{
		serial: new(big.Int).Set(b.serial), csr: append([]byte(nil), b.csr...), iss: append([]byte(nil), b.iss...),
		tbs: append([]byte(nil), b.tbs...), sig: append([]byte(nil), b.sig...),
		keyX: new(big.Int).Set(b.key.X), keyY: new(big.Int).Set(b.key.Y), keyXp: b.key.X, keyYp: b.key.Y,
	}
}

func (b *bundle) same(s snapshot) bool {
	return b.serial.Cmp(s.serial) == 0 && bytes.Equal(b.csr, s.csr) && bytes.Equal(b.iss, s.iss) && bytes.Equal(b.tbs, s.tbs) && bytes.Equal(b.sig, s.sig) &&
		b.key.X.Cmp(s.keyX) == 0 && b.key.Y.Cmp(s.keyY) == 0 && b.key.X == s.keyXp && b.key.Y == s.keyYp
}

// The parameters are unchanged after every call, also a refused one, for every exported function that takes them: the value of
// the serial, the bytes of the request, of the issuer name, of the body and of the signature, and the key object (its numbers and
// the pointers to them).
func TestTheParametersAreUnchangedAfterEveryCall(t *testing.T) {
	f := newGuardFixture(t)
	fresh := func(t *testing.T) *bundle {
		return &bundle{
			serial: new(big.Int).Set(aSerial), csr: append([]byte(nil), f.inter.params.CSR...), iss: append([]byte(nil), f.inter.params.IssuerSubject...),
			tbs: append([]byte(nil), f.inter.tbs...), sig: rawSign(t, f.root.key, f.inter.tbs), key: ownKey(t, &f.root.key.PublicKey),
		}
	}
	iparams := func(b *bundle) pki.IntermediateParams {
		return pki.IntermediateParams{CSR: b.csr, IssuerSubject: b.iss, IssuerKey: b.key, Roots: []pki.RootRef{{Subject: b.iss, Key: b.key}}, CeremonyTime: ceremony, Serial: b.serial}
	}
	calls := map[string]func(t *testing.T, b *bundle, bad bool){
		"RootTBS": func(t *testing.T, b *bundle, bad bool) {
			p := rootParams(b.key)
			p.Serial = b.serial
			if bad {
				p.Label = "no"
			}
			_, _ = pki.RootTBS(p)
		},
		"IntermediateTBS": func(t *testing.T, b *bundle, bad bool) {
			p := iparams(b)
			if bad {
				p.CSR = b.csr[:len(b.csr)-1]
			}
			_, _ = pki.IntermediateTBS(p)
		},
		"SignRoot": func(t *testing.T, b *bundle, bad bool) {
			p := rootParams(b.key)
			p.Serial = b.serial
			tbs, err := pki.RootTBS(p)
			if err != nil {
				t.Fatal(err)
			}
			s := &opaqueSigner{key: f.root.key}
			if !bad { // the right card: the key of the parameters is the signer's
				p.Key = &s.key.PublicKey
				tbs, _ = pki.RootTBS(p)
			}
			_, _ = pki.SignRoot(nil, s, p, tbs)
		},
		"SignIntermediate": func(t *testing.T, b *bundle, bad bool) {
			s := &opaqueSigner{key: f.root.key}
			body := b.tbs
			if bad {
				s = &opaqueSigner{key: newKey(t)}
			}
			_, _ = pki.SignIntermediate(nil, s, iparams(b), body)
		},
		"Assemble": func(t *testing.T, b *bundle, bad bool) {
			sig := b.sig
			if bad {
				sig = sig[:len(sig)-1]
			}
			_, _ = pki.Assemble(b.tbs, sig, b.key)
		},
		"ParseRequest": func(t *testing.T, b *bundle, bad bool) {
			d := b.csr
			if bad {
				d = d[:len(d)-1]
			}
			_, _ = pki.ParseRequest(d)
		},
		"ParseRequestFile": func(t *testing.T, b *bundle, bad bool) {
			file := b.csr // not a PEM file: refused; and an honest file is made from the bytes and is a copy
			if !bad {
				file = []byte(armor(b.csr, "CERTIFICATE REQUEST", "\n"))
			}
			_, _ = pki.ParseRequestFile(file)
		},
		"SameName": func(t *testing.T, b *bundle, bad bool) {
			_, _ = pki.SameName(b.iss, map[bool][]byte{false: b.iss, true: b.iss[:3]}[bad])
		},
		"CheckSerial": func(t *testing.T, b *bundle, bad bool) { _ = pki.CheckSerial(b.serial); _ = bad },
		"KeyIdentifier": func(t *testing.T, b *bundle, bad bool) {
			_, _ = pki.KeyIdentifier(b.key)
		},
		"SPKISHA256": func(t *testing.T, b *bundle, bad bool) { _, _ = pki.SPKISHA256(b.key) },
		"TBSDigest":  func(t *testing.T, b *bundle, bad bool) { _ = pki.TBSDigest(b.tbs) },
		"TBSSHA256":  func(t *testing.T, b *bundle, bad bool) { _ = pki.TBSSHA256(b.tbs) },
	}
	for name, call := range calls {
		for _, bad := range []bool{false, true} {
			t.Run(map[bool]string{false: name + ", honest", true: name + ", refused"}[bad], func(t *testing.T) {
				b := fresh(t)
				before := b.snap()
				call(t, b, bad)
				if !b.same(before) {
					t.Errorf("%s changed one of its parameters", name)
				}
			})
		}
	}
}

// A key that the package returns or keeps shares nothing with the caller's key: the caller changes its key afterwards and nothing
// that the package returned changes.
func TestWhatThePackageReturnsSharesNothingWithTheCallersKey(t *testing.T) {
	f := newGuardFixture(t)
	other := newKey(t)
	t.Run("the results of the builders, the signatures and the identifiers", func(t *testing.T) {
		shared := ownKey(t, &f.root.key.PublicKey)
		p := f.inter.params
		p.IssuerKey = shared
		tbs, err := pki.IntermediateTBS(p)
		if err != nil {
			t.Fatal(err)
		}
		id, err := pki.KeyIdentifier(shared)
		if err != nil {
			t.Fatal(err)
		}
		pin, err := pki.SPKISHA256(shared)
		if err != nil {
			t.Fatal(err)
		}
		s := &opaqueSigner{key: f.root.key}
		sig, err := pki.SignIntermediate(nil, s, p, tbs)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := pki.Assemble(tbs, sig, shared)
		if err != nil {
			t.Fatal(err)
		}
		wantTBS, wantID, wantPin, wantCert := append([]byte(nil), tbs...), append([]byte(nil), id...), pin, append([]byte(nil), cert...)
		// The caller changes its key object, in both ways.
		overwrite(shared, &other.PublicKey, true)
		if !bytes.Equal(tbs, wantTBS) || !bytes.Equal(id, wantID) || pin != wantPin || !bytes.Equal(cert, wantCert) {
			t.Error("a result changed with the caller's key")
		}
		// And the key as the package holds it (in the request) is the request's, whatever the caller does.
		req, err := pki.ParseRequest(p.CSR)
		if err != nil {
			t.Fatal(err)
		}
		k := req.PublicKey()
		x := new(big.Int).Set(k.X)
		k.X.Add(k.X, big.NewInt(1))
		k.Y.SetInt64(7)
		if got := req.PublicKey(); got.X.Cmp(x) != 0 || got.Y.Cmp(k.Y) == 0 {
			t.Error("the key of the view shares numbers with the key that it returned")
		}
	})
	t.Run("the signer's key is copied when it is asked for", func(t *testing.T) {
		signerKey := newKey(t)
		shared := ownKey(t, &signerKey.PublicKey)
		p := rootParams(shared)
		tbs, err := pki.RootTBS(p)
		if err != nil {
			t.Fatal(err)
		}
		s := &sharedKeySigner{private: signerKey, pub: shared}
		s.after = func() { overwrite(shared, &other.PublicKey, true) } // the card's key object is changed after the call began
		sig, err := pki.SignRoot(nil, s, p, tbs)
		if err != nil {
			t.Fatal(err)
		}
		pubCopy := ownKey(t, &signerKey.PublicKey)
		if _, err := pki.Assemble(tbs, sig, pubCopy); err != nil {
			t.Errorf("the signature does not verify with the signer's own key: %v", err)
		}
	})
}

// sharedKeySigner answers Public with one object that the test holds, and runs a hook when it signs.
type sharedKeySigner struct {
	private *ecdsa.PrivateKey
	pub     *ecdsa.PublicKey
	after   func()
}

func (s *sharedKeySigner) Public() crypto.PublicKey { return s.pub }
func (s *sharedKeySigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if s.after != nil {
		s.after()
	}
	return ecdsa.SignASN1(rand.Reader, s.private, digest)
}

// The order of refusals for an input with two faults: the key is copied, and so refused, at the top of a call, so a bad key wins
// over a bad serial, a bad issuer name, a bad request or a bad ceremony time. (No earlier test held the other order.)
func TestABadKeyIsRefusedBeforeAnyOtherParameter(t *testing.T) {
	root := buildRoot(t, nil)
	var none *ecdsa.PublicKey
	for name, key := range map[string]crypto.PublicKey{
		"nil": nil, "a typed nil": none, "a string": "not a key", "an empty key": &ecdsa.PublicKey{},
		"a key of another curve": &newP256(t).PublicKey, "a point that is not on the curve": offCurveKey(t),
	} {
		t.Run("IntermediateTBS, "+name, func(t *testing.T) {
			p := root.interParams(withExtensions(t, goodExtensions()...))
			p.IssuerKey, p.Serial, p.IssuerSubject, p.CSR = key, nil, []byte("not a name"), []byte("not a request")
			tbs, err := pki.IntermediateTBS(p)
			refused(t, err, pki.ErrParams)
			if tbs != nil || err == nil || !strings.Contains(err.Error(), "public key") {
				t.Errorf("not refused for the key first: %v", err)
			}
		})
		t.Run("RootTBS, "+name, func(t *testing.T) {
			p := rootParams(key)
			p.Serial, p.Name, p.Label = nil, "", "no"
			tbs, err := pki.RootTBS(p)
			refused(t, err, pki.ErrParams)
			if tbs != nil || err == nil || !strings.Contains(err.Error(), "public key") {
				t.Errorf("not refused for the key first: %v", err)
			}
		})
		t.Run("SignRoot and SignIntermediate, "+name, func(t *testing.T) {
			s := &opaqueSigner{key: root.key}
			p := rootParams(key)
			p.Serial = nil
			sig, err := pki.SignRoot(nil, s, p, nil)
			refused(t, err, pki.ErrParams)
			if sig != nil || s.calls != 0 || err == nil || !strings.Contains(err.Error(), "public key") {
				t.Errorf("SignRoot: not refused for the key first, or the card was touched: %v", err)
			}
			ip := root.interParams(withExtensions(t, goodExtensions()...))
			ip.IssuerKey, ip.Serial = key, nil
			sig, err = pki.SignIntermediate(nil, s, ip, nil)
			refused(t, err, pki.ErrParams)
			if sig != nil || s.calls != 0 || err == nil || !strings.Contains(err.Error(), "public key") {
				t.Errorf("SignIntermediate: not refused for the key first, or the card was touched: %v", err)
			}
		})
	}
}

func newP256(t *testing.T) *ecdsa.PrivateKey { return p256Key(t) }

// offCurveKey is a P-384 key object whose numbers are not a point.
func offCurveKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	k := ownKey(t, &newKey(t).PublicKey)
	k.Y.Add(k.Y, big.NewInt(1))
	return k
}
