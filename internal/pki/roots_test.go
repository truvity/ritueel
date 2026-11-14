package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// The roots of the bundle (IntermediateParams.Roots): the contract says that the key of a request is not the key of any root key of the
// bundle, and that the subject is not the name of any root key of the bundle, compared as OpenSSL compares names. The package cannot know the
// bundle, so the caller gives the list, with the issuer in it. The list is required (an empty list is not "no other root": it is a
// parameter that was not given), must hold the issuer, and is read as an issuer is read. A request for any of them is `policy`.

// rootSet is a test bundle: the issuer (root A) and two other roots, each with a key and a name that a request can take.
type rootSet struct {
	a, b, c *testRoot
}

func newBundle(t *testing.T) rootSet {
	t.Helper()
	return rootSet{
		a: buildRoot(t, func(p *pki.RootParams) { p.Name = "Alpha"; p.Label = "A" }),
		b: buildRoot(t, func(p *pki.RootParams) { p.Name = "Beta"; p.Label = "B" }),
		c: buildRoot(t, func(p *pki.RootParams) { p.Name = "Gamma"; p.Label = "C" }),
	}
}

func (b rootSet) params(t *testing.T, csr *testCSR) pki.IntermediateParams {
	p := b.a.interParams(csr)
	p.Roots = []pki.RootRef{b.a.ref(), b.b.ref(), b.c.ref()}
	return p
}

// ownParams are parameters whose subjects and keys are the caller's own objects, which a test may write to without touching the roots.
func (b rootSet) ownParams(t *testing.T, csr *testCSR) pki.IntermediateParams {
	p := b.params(t, csr)
	p.IssuerSubject = append([]byte(nil), p.IssuerSubject...)
	p.IssuerKey = ownKey(t, &b.a.key.PublicKey)
	for i, r := range p.Roots {
		p.Roots[i] = pki.RootRef{Subject: append([]byte(nil), r.Subject...), Key: ownKey(t, r.Key.(*ecdsa.PublicKey))}
	}
	return p
}

func TestTheRootsOfTheBundleAreRequiredAndHoldTheIssuer(t *testing.T) {
	b := newBundle(t)
	csr := goodRequest(t)
	other := newKey(t)
	rows := []struct {
		name  string
		roots []pki.RootRef
		words string
	}{
		{"nil", nil, "no roots of the bundle are given"},
		{"empty", []pki.RootRef{}, "no roots of the bundle are given"},
		{"roots without the issuer", []pki.RootRef{b.b.ref(), b.c.ref()}, "do not hold the issuer"},
		{"the issuer's subject with another key", []pki.RootRef{{Subject: b.a.parsed.RawSubject, Key: &other.PublicKey}, b.b.ref()}, "do not hold the issuer"},
		{"the issuer's key with another subject", []pki.RootRef{{Subject: b.b.parsed.RawSubject, Key: &b.a.key.PublicKey}}, "do not hold the issuer"},
		{"the issuer's subject in one root and its key in another", []pki.RootRef{{Subject: b.a.parsed.RawSubject, Key: &b.b.key.PublicKey}, {Subject: b.b.parsed.RawSubject, Key: &b.a.key.PublicKey}}, "do not hold the issuer"},
		{"a root with a subject that is not a name", []pki.RootRef{b.a.ref(), {Subject: []byte{0x04, 0x01, 0x00}, Key: &b.b.key.PublicKey}}, "not a name"},
		{"a root with no subject", []pki.RootRef{b.a.ref(), {Key: &b.b.key.PublicKey}}, "not a name"},
		{"a root with an empty name", []pki.RootRef{b.a.ref(), {Subject: []byte{0x30, 0x00}, Key: &b.b.key.PublicKey}}, "is empty"},
		{"a root with a name that is not UTF-8", []pki.RootRef{b.a.ref(), {Subject: cnName(tUTF8, "x\xff"), Key: &b.b.key.PublicKey}}, "not valid UTF-8"},
		{"a root with a name outside printable ASCII", []pki.RootRef{b.a.ref(), {Subject: cnName(tUTF8, "café Root"), Key: &b.b.key.PublicKey}}, "outside printable ASCII"},
		{"a root with a name with two spaces", []pki.RootRef{b.a.ref(), {Subject: cnName(tUTF8, "a  Root"), Key: &b.b.key.PublicKey}}, "two spaces"},
		{"a root with no key", []pki.RootRef{b.a.ref(), {Subject: b.b.parsed.RawSubject}}, ""},
		{"a root with a typed nil key", []pki.RootRef{b.a.ref(), {Subject: b.b.parsed.RawSubject, Key: (*ecdsa.PublicKey)(nil)}}, ""},
		{"a root with a key of P-256", []pki.RootRef{b.a.ref(), {Subject: b.b.parsed.RawSubject, Key: &mustP256(t).PublicKey}}, ""},
		{"a root with a key that is not an ECDSA key", []pki.RootRef{b.a.ref(), {Subject: b.b.parsed.RawSubject, Key: "key"}}, ""},
		{"a root with a key that is not on the curve", []pki.RootRef{b.a.ref(), {Subject: b.b.parsed.RawSubject, Key: &ecdsa.PublicKey{Curve: elliptic.P384(), X: b.b.key.X, Y: b.c.key.Y}}}, ""}, //nolint:staticcheck // the point that is not on the curve is the input
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p := b.a.interParams(csr)
			p.Roots = r.roots
			tbs, err := pki.IntermediateTBS(p)
			refused(t, err, pki.ErrParams)
			if pki.CheckOf(err) != pki.CheckNone {
				t.Errorf("check %q for a parameter", pki.CheckOf(err))
			}
			if tbs != nil {
				t.Error("a body came with the error")
			}
			if r.words != "" && !strings.Contains(err.Error(), r.words) {
				t.Errorf("the text does not say %q: %v", r.words, err)
			}
			// SignIntermediate builds the body again from the same parameters: the same refusal, and the signer is not touched.
			honest, herr := pki.IntermediateTBS(b.params(t, csr))
			if herr != nil {
				t.Fatal(herr)
			}
			s := &opaqueSigner{key: b.a.key}
			sig, err2 := pki.SignIntermediate(nil, s, p, honest)
			refused(t, err2, pki.ErrParams)
			if sig != nil || s.calls != 0 || pki.CheckOf(err2) != pki.CheckNone || err2.Error() != err.Error() {
				t.Errorf("SignIntermediate: signature %v, %d calls, check %q, %v", sig != nil, s.calls, pki.CheckOf(err2), err2)
			}
		})
	}
	// The parameters are judged before the request: a bad list and a bad request are the list's fault.
	t.Run("a bad list and a bad request: the list is judged first", func(t *testing.T) {
		bad := copyCSR(csr)
		bad.Version = []byte{0x02, 0x01, 0x07}
		p := b.a.interParams(bad)
		p.Roots = nil
		_, err := pki.IntermediateTBS(p)
		refused(t, err, pki.ErrParams)
	})
	t.Run("the list that holds the issuer is accepted, in any place", func(t *testing.T) {
		for _, roots := range [][]pki.RootRef{
			{b.a.ref()},
			{b.a.ref(), b.b.ref(), b.c.ref()},
			{b.b.ref(), b.a.ref(), b.c.ref()},
			{b.b.ref(), b.c.ref(), b.a.ref()},
			{b.a.ref(), b.a.ref(), b.a.ref()},
		} {
			p := b.a.interParams(csr)
			p.Roots = roots
			if _, err := pki.IntermediateTBS(p); err != nil {
				t.Errorf("%d roots: %v", len(roots), err)
			}
		}
	})
}

func mustP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A request for the key of any root of the bundle, or whose subject is the name of any root as OpenSSL compares names, is refused with
// `policy`, and a request for none of them is issued. The issuer's own key and name keep their own words.
func TestARequestForTheKeyOrTheNameOfAnyRootOfTheBundleIsRefused(t *testing.T) {
	b := newBundle(t)
	good := goodRequest(t)
	nameOfB := b.b.parsed.Subject.CommonName // "Beta Root B (TEST ONLY)"
	rows := []struct {
		name    string
		csr     func() *testCSR
		refused bool
		words   string
	}{
		{"a request for none of them", func() *testCSR { return copyCSR(good) }, false, ""},
		{"the key of root B", func() *testCSR { c := copyCSR(good); c.Key, c.RawSubjectPublicKeyInfo = b.b.key, nil; return c }, true, "the key of the request is the key of a root of the bundle"},
		{"the key of root C", func() *testCSR { c := copyCSR(good); c.Key, c.RawSubjectPublicKeyInfo = b.c.key, nil; return c }, true, "the key of the request is the key of a root of the bundle"},
		{"the key of the issuer", func() *testCSR { c := copyCSR(good); c.Key, c.RawSubjectPublicKeyInfo = b.a.key, nil; return c }, true, "the key of the request is the key of the issuer"},
		{"the name of root B, byte for byte", func() *testCSR { c := copyCSR(good); c.RawSubject = b.b.parsed.RawSubject; return c }, true, "the name of a root of the bundle"},
		{"the name of root B in capitals", func() *testCSR { c := copyCSR(good); c.RawSubject = cnName(tUTF8, strings.ToUpper(nameOfB)); return c }, true, "the name of a root of the bundle"},
		{"the name of root B in lower case", func() *testCSR { c := copyCSR(good); c.RawSubject = cnName(tUTF8, strings.ToLower(nameOfB)); return c }, true, "the name of a root of the bundle"},
		{"the name of root B as a PrintableString", func() *testCSR { c := copyCSR(good); c.RawSubject = cnName(tPrintable, nameOfB); return c }, true, "the name of a root of the bundle"},
		{"the name of root C", func() *testCSR { c := copyCSR(good); c.RawSubject = b.c.parsed.RawSubject; return c }, true, "the name of a root of the bundle"},
		{"the name of the issuer", func() *testCSR { c := copyCSR(good); c.RawSubject = b.a.parsed.RawSubject; return c }, true, "is the name of the issuer"},
		{"the name of the issuer in capitals", func() *testCSR {
			c := copyCSR(good)
			c.RawSubject = cnName(tUTF8, strings.ToUpper(b.a.parsed.Subject.CommonName))
			return c
		}, true, "is the name of the issuer"},
		{"a name that is the name of root B and one more relative name", func() *testCSR {
			c := copyCSR(good)
			c.RawSubject = nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme"))), rdn(atv(oidAttrCN, str(tUTF8, nameOfB))))
			return c
		}, false, ""},
		{"a name that starts like the name of root B", func() *testCSR { c := copyCSR(good); c.RawSubject = cnName(tUTF8, nameOfB+" 2"); return c }, false, ""},
		{"a name that is the name of root B with another letter", func() *testCSR { c := copyCSR(good); c.RawSubject = cnName(tUTF8, "Beta Root X (TEST ONLY)"); return c }, false, ""},
		{"a name that is the name of root B in another attribute type", func() *testCSR {
			c := copyCSR(good)
			c.RawSubject = nameOf(rdn(atv(oidAttrO, str(tUTF8, nameOfB))))
			return c
		}, false, ""},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			csr := r.csr()
			der := csr.DER()
			p := b.params(t, csr)
			p.CSR = der
			tbs, err := pki.IntermediateTBS(p)
			if !r.refused {
				if err != nil || tbs == nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			refused(t, err, pki.ErrRequest)
			if got := pki.CheckOf(err); got != pki.CheckPolicy {
				t.Errorf("check %q, want policy", got)
			}
			if !strings.Contains(err.Error(), r.words) {
				t.Errorf("the text does not say %q: %v", r.words, err)
			}
			if tbs != nil {
				t.Error("a body came with the error")
			}
			// ParseRequest reads the request on its own (it does not know the bundle): it is a rule of the issuer's side.
			if _, perr := pki.ParseRequest(der); perr != nil {
				t.Errorf("ParseRequest refuses the request: %v", perr)
			}
			// SignIntermediate builds the body again from the parameters, so the rule holds at the signing too: given the body of another
			// request (the honest one), the call is refused as the parameters' request is, with `policy`, and the signer is not touched.
			honest, herr := pki.IntermediateTBS(b.params(t, good))
			if herr != nil {
				t.Fatal(herr)
			}
			s := &opaqueSigner{key: b.a.key}
			sig, serr := pki.SignIntermediate(nil, s, p, honest)
			refused(t, serr, pki.ErrRequest)
			if sig != nil || s.calls != 0 || pki.CheckOf(serr) != pki.CheckPolicy || serr.Error() != err.Error() {
				t.Errorf("SignIntermediate: signature %v, %d calls, check %q: %v", sig != nil, s.calls, pki.CheckOf(serr), serr)
			}
		})
	}
	// The honest request is issued and signed under root A with the list of three, and chains to A.
	t.Run("the request for none of them is signed and verified under the issuer", func(t *testing.T) {
		p := b.params(t, good)
		tbs, err := pki.IntermediateTBS(p)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := pki.SignIntermediate(nil, b.a.key, p, tbs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pki.Assemble(tbs, sig, &b.a.key.PublicKey); err != nil {
			t.Fatal(err)
		}
	})
	// The list may be long: every root is read, and a request for the last one is refused.
	t.Run("a rootSet of a hundred roots", func(t *testing.T) {
		p := b.params(t, good)
		var last *testRoot
		for i := 0; i < 100; i++ {
			last = buildRoot(t, func(rp *pki.RootParams) {
				rp.Name = "Many " + strings.Repeat("x", i%7) + string(rune('a'+i%26))
				rp.Label = string(rune('A' + i%26))
			})
			p.Roots = append(p.Roots, last.ref())
		}
		if _, err := pki.IntermediateTBS(p); err != nil {
			t.Fatalf("a request for none of them: %v", err)
		}
		c := copyCSR(good)
		c.Key, c.RawSubjectPublicKeyInfo = last.key, nil
		p.CSR = c.DER()
		_, err := pki.IntermediateTBS(p)
		if pki.CheckOf(err) != pki.CheckPolicy || !strings.Contains(err.Error(), "a root of the bundle") {
			t.Errorf("a request for the key of the hundredth root: %v", err)
		}
	})
	// The request is read before the roots are compared: a request that is refused for another reason is refused for that.
	t.Run("a request that is bad in another way is refused for that", func(t *testing.T) {
		c := copyCSR(good)
		c.Key, c.RawSubjectPublicKeyInfo = b.b.key, nil
		c.Version = []byte{0x02, 0x01, 0x01}
		p := b.params(t, c)
		_, err := pki.IntermediateTBS(p)
		if pki.CheckOf(err) != pki.CheckMalformed {
			t.Errorf("check %q: %v", pki.CheckOf(err), err)
		}
	})
}

// --- copies -------------------------------------------------------------------------------------------------

func snapshotRoots(roots []pki.RootRef) []pki.RootRef {
	out := make([]pki.RootRef, len(roots))
	for i, r := range roots {
		k := r.Key.(*ecdsa.PublicKey)
		out[i] = pki.RootRef{Subject: append([]byte(nil), r.Subject...), Key: &ecdsa.PublicKey{Curve: k.Curve, X: new(big.Int).Set(k.X), Y: new(big.Int).Set(k.Y)}} //nolint:staticcheck // a snapshot of the numbers
	}
	return out
}

func sameRoots(a, b []pki.RootRef) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ka, kb := a[i].Key.(*ecdsa.PublicKey), b[i].Key.(*ecdsa.PublicKey)
		if !bytes.Equal(a[i].Subject, b[i].Subject) || ka.X.Cmp(kb.X) != 0 || ka.Y.Cmp(kb.Y) != 0 { //nolint:staticcheck // the numbers are the point
			return false
		}
	}
	return true
}

// The list of roots is copied like the other parameters: it is unchanged after a call, honest or refused; a signer's hooks that write to the
// subjects, the keys and the slice of the list while the call is signing do not reach the body that was built; and a key of the list that
// is overwritten while it is copied is refused at the copy, and the call is refused as a change.
func TestTheRootsAreCopiedAndTheCallerKeepsHisList(t *testing.T) {
	b := newBundle(t)
	good := goodRequest(t)
	other := newKey(t)

	t.Run("unchanged after a call, honest and refused", func(t *testing.T) {
		for name, csr := range map[string]*testCSR{
			"an honest request": good,
			"a request for the key of root B": func() *testCSR {
				c := copyCSR(good)
				c.Key, c.RawSubjectPublicKeyInfo = b.b.key, nil
				return c
			}(),
			"a request for the name of root C": func() *testCSR { c := copyCSR(good); c.RawSubject = b.c.parsed.RawSubject; return c }(),
		} {
			p := b.params(t, csr)
			before := snapshotRoots(p.Roots)
			slice := append([]pki.RootRef(nil), p.Roots...) // the slice as the caller gave it: the same keys in the same places
			tbs, err := pki.IntermediateTBS(p)
			if _, serr := pki.SignIntermediate(nil, b.a.key, p, tbs); err == nil && serr != nil {
				t.Errorf("%s: %v", name, serr)
			}
			if !sameRoots(before, p.Roots) {
				t.Errorf("%s: the roots of the caller changed", name)
			}
			if len(slice) != len(p.Roots) {
				t.Errorf("%s: the list of the caller has %d roots, it had %d", name, len(p.Roots), len(slice))
			}
			for i := range slice {
				if slice[i].Key != p.Roots[i].Key || &slice[i].Subject[0] != &p.Roots[i].Subject[0] {
					t.Errorf("%s: the slice of the caller changed in place %d", name, i)
				}
			}
		}
	})

	t.Run("hooks of a signer write to the list while it signs", func(t *testing.T) {
		p := b.ownParams(t, good)
		tbs, err := pki.IntermediateTBS(p)
		if err != nil {
			t.Fatal(err)
		}
		before := append([]byte(nil), tbs...)
		s := &hookSigner{key: b.a.key}
		s.onSig = func() {
			for i := range p.Roots {
				for j := range p.Roots[i].Subject {
					p.Roots[i].Subject[j] ^= 0xff
				}
				k := p.Roots[i].Key.(*ecdsa.PublicKey)
				overwrite(k, &other.PublicKey, true)
			}
			p.Roots[0], p.Roots[1] = p.Roots[1], p.Roots[0]
			p.Roots = p.Roots[:1]
		}
		sig, err := pki.SignIntermediate(nil, s, p, tbs)
		if err != nil {
			t.Fatalf("a caller that writes to its own list during the signing is refused: %v", err)
		}
		if s.signs != 1 {
			t.Errorf("the signer was touched %d times, want once", s.signs)
		}
		if _, err := pki.Assemble(before, sig, &b.a.key.PublicKey); err != nil {
			t.Errorf("the signature is not for the body that was built: %v", err)
		}
	})

	t.Run("a key of the list that a signer's Public overwrites in the caller's object is not the key of the call", func(t *testing.T) {
		for _, inPlace := range []bool{false, true} {
			p := b.ownParams(t, good)
			shared := ownKey(t, &b.b.key.PublicKey)
			p.Roots[1].Key = shared
			tbs, err := pki.IntermediateTBS(p)
			if err != nil {
				t.Fatal(err)
			}
			s := &hookSigner{key: b.a.key}
			s.onPublic = func() { overwrite(shared, &other.PublicKey, inPlace) }
			if _, err := pki.SignIntermediate(nil, s, p, tbs); err != nil {
				t.Errorf("in place %v: the right card is refused because the caller wrote to a key of its list: %v", inPlace, err)
			}
		}
	})

	t.Run("a key of the list that is not a copy of what was given is refused at the copy", func(t *testing.T) {
		p := b.params(t, good)
		p.Roots[2].Key = (*ecdsa.PublicKey)(nil)
		_, err := pki.IntermediateTBS(p)
		refused(t, err, pki.ErrParams)
		p.Roots[2].Key = &ecdsa.PublicKey{Curve: elliptic.P384()}
		_, err = pki.IntermediateTBS(p)
		refused(t, err, pki.ErrParams)
	})
}
