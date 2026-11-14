package pki_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
)

// The signing functions: a key signs only the body that the builder returns for the parameters it is given, and
// only when the signer's key is the key of those parameters. Every refusal comes before the key is used. The tests use a
// signer that counts its calls (opaqueSigner), because "before the key is used" is "the count stays 0": for a card it is
// "nobody is asked to touch it".

// guardFixture is a root and an intermediate under it, and the signer of the root (a bare crypto.Signer that counts).
type guardFixture struct {
	root   *testRoot
	inter  *issued
	signer *opaqueSigner // holds the key of the root
}

func newGuardFixture(t *testing.T) *guardFixture {
	t.Helper()
	root := buildRoot(t, nil)
	inter := root.issue(t, withExtensions(t, goodExtensions()...), nil)
	return &guardFixture{root: root, inter: inter, signer: &opaqueSigner{key: root.key}}
}

// refused checks that both signing functions refuse the body, with the parameters of the honest root and of the honest
// intermediate, in the kind ErrParams, with no signature and without a call of the signer.
func (f *guardFixture) refused(t *testing.T, s *opaqueSigner, body []byte) {
	t.Helper()
	before := s.calls
	for name, call := range map[string]func() ([]byte, error){
		"SignRoot":         func() ([]byte, error) { return pki.SignRoot(nil, s, f.root.params, body) },
		"SignIntermediate": func() ([]byte, error) { return pki.SignIntermediate(nil, s, f.inter.params, body) },
	} {
		sig, err := call()
		refused(t, err, pki.ErrParams)
		if err != nil {
			onePrefix(t, err)
		}
		if sig != nil {
			t.Errorf("%s: a signature %x came with the error", name, sig)
		}
	}
	if s.calls != before {
		t.Errorf("the signer was called %d times for a body that is refused", s.calls-before)
	}
}

// An honest call: the signer is called once with the SHA-384 of the body, the options say SHA-384, the source of random
// numbers is the one given (crypto/rand when none), the signature verifies, and the body is not changed.
func TestSignRootAndSignIntermediateSignTheirOwnBody(t *testing.T) {
	f := newGuardFixture(t)
	for name, call := range map[string]func(s crypto.Signer, rnd io.Reader) ([]byte, []byte, *ecdsa.PublicKey, error){
		"SignRoot": func(s crypto.Signer, rnd io.Reader) ([]byte, []byte, *ecdsa.PublicKey, error) {
			sig, err := pki.SignRoot(rnd, s, f.root.params, f.root.tbs)
			return sig, f.root.tbs, &f.root.key.PublicKey, err
		},
		"SignIntermediate": func(s crypto.Signer, rnd io.Reader) ([]byte, []byte, *ecdsa.PublicKey, error) {
			sig, err := pki.SignIntermediate(rnd, s, f.inter.params, f.inter.tbs)
			return sig, f.inter.tbs, &f.root.key.PublicKey, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := &opaqueSigner{key: f.root.key}
			before := append([]byte(nil), f.inter.tbs...)
			sig, tbs, pub, err := call(s, nil)
			if err != nil {
				t.Fatal(err)
			}
			if s.calls != 1 {
				t.Errorf("the signer was called %d times, want 1", s.calls)
			}
			want := sha512.Sum384(tbs)
			if !bytes.Equal(s.digest, want[:]) || len(s.digest) != 48 {
				t.Errorf("the signer got %x, want the SHA-384 of the body %x", s.digest, want)
			}
			if s.opts == nil || s.opts.HashFunc() != crypto.SHA384 {
				t.Errorf("the signer got the options %v, want crypto.SHA384", s.opts)
			}
			if s.rnd == nil {
				t.Error("the signer got no source of random numbers: want crypto/rand when none is given")
			}
			if !ecdsa.VerifyASN1(pub, want[:], sig) {
				t.Error("the signature does not verify over the SHA-384 of the body")
			}
			if der, err := pki.Assemble(tbs, sig, pub); err != nil {
				t.Errorf("Assemble: %v", err)
			} else if cert, err := x509.ParseCertificate(der); err != nil || cert.CheckSignatureFrom(f.root.parsed) != nil {
				t.Errorf("the certificate does not verify under the root: %v", err)
			}
			if !bytes.Equal(f.inter.tbs, before) {
				t.Error("the body was changed")
			}
			// A given source of random numbers is the one the signer gets.
			own := bytes.NewReader(make([]byte, 8))
			if _, _, _, err := call(s, own); err != nil {
				t.Fatal(err)
			}
			if s.rnd != io.Reader(own) {
				t.Error("the source of random numbers that was given is not the one the signer got")
			}
			// The same key as a software key, with no wrapper, signs too.
			if _, _, _, err := call(f.root.key, nil); err != nil {
				t.Errorf("the software key: %v", err)
			}
			// A high s is another form of the same signature: accepted.
			h := &opaqueSigner{key: f.root.key}
			h.tweak = func(_ []byte, _ *ecdsa.PrivateKey, sig []byte) ([]byte, error) { return highS(t, sig), nil }
			hs, _, _, err := call(h, nil)
			if err != nil {
				t.Fatalf("a signature with a high s: %v", err)
			}
			if _, err := pki.Assemble(tbs, hs, pub); err != nil {
				t.Errorf("Assemble of a high s: %v", err)
			}
		})
	}
}

// Whatever is not the body of the parameters is refused before the key is used, and the answer is one kind.
func TestSignRefusesWhatIsNotTheBodyOfTheParameters(t *testing.T) {
	f := newGuardFixture(t)
	other := newKey(t)
	otherRoot := buildRoot(t, nil)
	otherInter := otherRoot.issue(t, withExtensions(t, goodExtensions()...), nil)
	rp, ip := f.root.params, f.inter.params
	with := func(p pki.RootParams, edit func(*pki.RootParams)) pki.RootParams { edit(&p); return p }
	withI := func(p pki.IntermediateParams, edit func(*pki.IntermediateParams)) pki.IntermediateParams {
		edit(&p)
		return p
	}
	anotherCSR := withExtensions(t, goodExtensions()...)
	sameKeyAnotherName := copyCSR(f.inter.csr)
	sameKeyAnotherName.RawSubject = nameOf(rdn(atv(oidAttrCN, str(tUTF8, "another name"))))
	sameKeyMoreExtensions := withExtensions(t, append(goodExtensions()[:3:3], extExtKeyUsage(false, oidClientAuth))...)
	sameKeyMoreExtensions.Key = f.inter.csr.Key

	t.Run("a root", func(t *testing.T) {
		rows := []struct {
			name string
			p    pki.RootParams
			body []byte
		}{
			{"another serial", with(rp, func(p *pki.RootParams) { p.Serial = new(big.Int).Add(p.Serial, big.NewInt(1)) }), f.root.tbs},
			{"another ceremony time", with(rp, func(p *pki.RootParams) { p.CeremonyTime = p.CeremonyTime.Add(time.Second) }), f.root.tbs},
			{"another name", with(rp, func(p *pki.RootParams) { p.Name = "Example Other" }), f.root.tbs},
			{"another label", with(rp, func(p *pki.RootParams) { p.Label = "L" }), f.root.tbs},
			{"the other kind of root", with(rp, func(p *pki.RootParams) { p.Test = !p.Test }), f.root.tbs},
			{"another key in the parameters, the body of the first", with(rp, func(p *pki.RootParams) { p.Key = &other.PublicKey }), f.root.tbs},
			{"the body of another root", rp, otherRoot.tbs},
			{"the body of an intermediate", rp, f.inter.tbs},
			{"nothing", rp, nil},
			{"an empty body", rp, []byte{}},
			{"text", rp, []byte("not a certificate body at all")},
			{"a whole certificate", rp, f.root.cert},
			{"a whole request", rp, f.inter.params.CSR},
			{"the body and a byte", rp, append(append([]byte(nil), f.root.tbs...), 0)},
			{"the body without its last byte", rp, f.root.tbs[:len(f.root.tbs)-1]},
			{"the body twice", rp, append(append([]byte(nil), f.root.tbs...), f.root.tbs...)},
			{"the first byte of the body", rp, f.root.tbs[:1]},
		}
		for _, r := range rows {
			t.Run(r.name, func(t *testing.T) {
				s := &opaqueSigner{key: f.root.key}
				sig, err := pki.SignRoot(nil, s, r.p, r.body)
				refused(t, err, pki.ErrParams)
				if err != nil {
					onePrefix(t, err)
				}
				if sig != nil || s.calls != 0 {
					t.Errorf("a signature came, or the signer was called %d times", s.calls)
				}
			})
		}
	})
	t.Run("an intermediate", func(t *testing.T) {
		rows := []struct {
			name string
			p    pki.IntermediateParams
			body []byte
		}{
			{"another serial", withI(ip, func(p *pki.IntermediateParams) { p.Serial = new(big.Int).Add(p.Serial, big.NewInt(1)) }), f.inter.tbs},
			{"another ceremony time", withI(ip, func(p *pki.IntermediateParams) { p.CeremonyTime = p.CeremonyTime.Add(time.Second) }), f.inter.tbs},
			{"another request", withI(ip, func(p *pki.IntermediateParams) { p.CSR = anotherCSR.DER() }), f.inter.tbs},
			{"the request of the same key with another name", withI(ip, func(p *pki.IntermediateParams) { p.CSR = sameKeyAnotherName.DER() }), f.inter.tbs},
			{"the request of the same key with another extension", withI(ip, func(p *pki.IntermediateParams) { p.CSR = sameKeyMoreExtensions.DER() }), f.inter.tbs},
			{"another issuer name", withI(ip, func(p *pki.IntermediateParams) { p.IssuerSubject = cnName(tUTF8, "another root") }), f.inter.tbs},
			{"another issuer key in the parameters", withI(ip, func(p *pki.IntermediateParams) { p.IssuerKey = &other.PublicKey }), f.inter.tbs},
			{"the body of another root's intermediate", ip, otherInter.tbs},
			{"the body of a root", ip, f.root.tbs},
			{"nothing", ip, nil},
			{"an empty body", ip, []byte{}},
			{"text", ip, []byte("not a certificate body at all")},
			{"a whole certificate", ip, f.inter.cert},
			{"a whole request", ip, ip.CSR},
			{"the body and a byte", ip, append(append([]byte(nil), f.inter.tbs...), 0)},
			{"the body without its last byte", ip, f.inter.tbs[:len(f.inter.tbs)-1]},
			{"the body twice", ip, append(append([]byte(nil), f.inter.tbs...), f.inter.tbs...)},
		}
		for _, r := range rows {
			t.Run(r.name, func(t *testing.T) {
				s := &opaqueSigner{key: f.root.key}
				sig, err := pki.SignIntermediate(nil, s, r.p, r.body)
				refused(t, err, pki.ErrParams)
				if err != nil {
					onePrefix(t, err)
				}
				if sig != nil || s.calls != 0 {
					t.Errorf("a signature came, or the signer was called %d times", s.calls)
				}
			})
		}
	})
	t.Run("random bytes of every size that matters", func(t *testing.T) {
		for _, n := range []int{1, 2, 10, 100, len(f.root.tbs), len(f.inter.tbs), 4096} {
			body := make([]byte, n)
			if _, err := rand.Read(body); err != nil {
				t.Fatal(err)
			}
			f.refused(t, f.signer, body)
		}
	})
	t.Run("the wrong card, with the right body and the right parameters", func(t *testing.T) {
		for name, key := range map[string]*ecdsa.PrivateKey{"another key": other, "the key of the intermediate": f.inter.csr.Key} {
			s := &opaqueSigner{key: key}
			for fn, call := range map[string]func() ([]byte, error){
				"SignRoot":         func() ([]byte, error) { return pki.SignRoot(nil, s, f.root.params, f.root.tbs) },
				"SignIntermediate": func() ([]byte, error) { return pki.SignIntermediate(nil, s, f.inter.params, f.inter.tbs) },
			} {
				sig, err := call()
				refused(t, err, pki.ErrParams)
				if sig != nil || s.calls != 0 {
					t.Errorf("%s with %s: a signature came, or the signer was called %d times", fn, name, s.calls)
				}
			}
		}
	})
	t.Run("a request that is not issued is a request fault, before the key", func(t *testing.T) {
		s := &opaqueSigner{key: f.root.key}
		bad := withI(ip, func(p *pki.IntermediateParams) { p.CSR = anotherCSRWithoutNameConstraints(t) })
		sig, err := pki.SignIntermediate(nil, s, bad, f.inter.tbs)
		refused(t, err, pki.ErrRequest)
		if _, berr := pki.IntermediateTBS(bad); berr == nil || err == nil || berr.Error() != err.Error() {
			t.Errorf("SignIntermediate says %v, the builder says %v", err, berr)
		}
		if sig != nil || s.calls != 0 {
			t.Errorf("a signature came, or the signer was called %d times", s.calls)
		}
	})
	t.Run("parameters that are refused by the builder", func(t *testing.T) {
		s := &opaqueSigner{key: f.root.key}
		for name, p := range map[string]pki.IntermediateParams{
			"no request":      withI(ip, func(p *pki.IntermediateParams) { p.CSR = nil }),
			"no serial":       withI(ip, func(p *pki.IntermediateParams) { p.Serial = nil }),
			"no ceremony":     withI(ip, func(p *pki.IntermediateParams) { p.CeremonyTime = time.Time{} }),
			"no issuer key":   withI(ip, func(p *pki.IntermediateParams) { p.IssuerKey = nil }),
			"a typed nil key": withI(ip, func(p *pki.IntermediateParams) { p.IssuerKey = (*ecdsa.PublicKey)(nil) }),
			"no issuer":       withI(ip, func(p *pki.IntermediateParams) { p.IssuerSubject = nil }),
		} {
			sig, err := pki.SignIntermediate(nil, s, p, f.inter.tbs)
			refused(t, err, pki.ErrParams)
			if sig != nil || s.calls != 0 {
				t.Errorf("%s: a signature came, or the signer was called %d times", name, s.calls)
			}
			// The error of the builder is returned as it is: the same words, so that the caller learns which parameter is wrong.
			if _, berr := pki.IntermediateTBS(p); berr == nil || err == nil || berr.Error() != err.Error() {
				t.Errorf("%s: SignIntermediate says %v, the builder says %v", name, err, berr)
			}
		}
		for name, p := range map[string]pki.RootParams{
			"no key":      with(rp, func(p *pki.RootParams) { p.Key = nil }),
			"no serial":   with(rp, func(p *pki.RootParams) { p.Serial = nil }),
			"no ceremony": with(rp, func(p *pki.RootParams) { p.CeremonyTime = time.Time{} }),
		} {
			sig, err := pki.SignRoot(nil, s, p, f.root.tbs)
			refused(t, err, pki.ErrParams)
			if sig != nil || s.calls != 0 {
				t.Errorf("%s: a signature came, or the signer was called %d times", name, s.calls)
			}
			if _, berr := pki.RootTBS(p); berr == nil || err == nil || berr.Error() != err.Error() {
				t.Errorf("%s: SignRoot says %v, the builder says %v", name, err, berr)
			}
		}
	})
	t.Run("the honest calls are signed, once each", func(t *testing.T) {
		before := f.signer.calls
		if _, err := pki.SignRoot(nil, f.signer, rp, f.root.tbs); err != nil {
			t.Error(err)
		}
		if _, err := pki.SignIntermediate(nil, f.signer, ip, f.inter.tbs); err != nil {
			t.Error(err)
		}
		if f.signer.calls != before+2 {
			t.Errorf("the signer was called %d times for two honest bodies", f.signer.calls-before)
		}
	})
}

// A request without name constraints: the request of the property that a request that is not issued is refused as one.
func anotherCSRWithoutNameConstraints(t *testing.T) []byte {
	t.Helper()
	return withExtensions(t, extBasicConstraints(), extKeyUsage(kuKeyCertSign, kuCRLSign)).DER()
}

// Every byte of the root body and of the intermediate body is changed, in nine ways, and every other change of a
// length too (a byte inserted, a byte deleted, the body cut short at each length). With the parameters fixed, no changed
// body is signed: this is stronger than "refused or another body that a builder could return", because the parameters
// have one body.
func TestEveryChangedByteOfABodyIsRefusedWithTheParametersFixed(t *testing.T) {
	f := newGuardFixture(t)
	masks := []byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff}
	type sign func(s crypto.Signer, body []byte) ([]byte, error)
	run := func(t *testing.T, name string, body []byte, call sign) {
		t.Helper()
		s := &opaqueSigner{key: f.root.key}
		check := func(changed []byte, what string) {
			t.Helper()
			sig, err := call(s, changed)
			if err == nil || sig != nil {
				t.Fatalf("%s: signed (%v)", what, err)
			}
			if k := kindOf(t, err); !errors.Is(k, pki.ErrParams) {
				t.Fatalf("%s: the kind is %v", what, k)
			}
		}
		n := 0
		for pos := range body {
			for _, mask := range masks {
				changed := append([]byte(nil), body...)
				changed[pos] ^= mask
				check(changed, "a changed byte")
				n++
			}
			for _, b := range []byte{0x00, 0x30} {
				ins := append(append(append([]byte(nil), body[:pos]...), b), body[pos:]...)
				check(ins, "an inserted byte")
				n++
			}
			del := append(append([]byte(nil), body[:pos]...), body[pos+1:]...)
			check(del, "a deleted byte")
			check(body[:pos], "a body cut short")
			n += 2
		}
		if s.calls != 0 {
			t.Errorf("%s: the signer was called %d times", name, s.calls)
		}
		t.Logf("%s: %d changed bodies of a body of %d octets, none signed, the signer called 0 times", name, n, len(body))
		if want := len(body) * (len(masks) + 4); n != want {
			t.Errorf("%d changes, want %d", n, want)
		}
		// And the body itself is signed.
		if _, err := call(s, body); err != nil {
			t.Errorf("the honest body is refused: %v", err)
		}
	}
	t.Run("a root body", func(t *testing.T) {
		run(t, "root", f.root.tbs, func(s crypto.Signer, b []byte) ([]byte, error) { return pki.SignRoot(nil, s, f.root.params, b) })
	})
	t.Run("an intermediate body", func(t *testing.T) {
		run(t, "intermediate", f.inter.tbs, func(s crypto.Signer, b []byte) ([]byte, error) {
			return pki.SignIntermediate(nil, s, f.inter.params, b)
		})
	})
}

// A signer that lies. Nothing wrong comes out: either an error, or a signature that verifies over the body.
func TestSignAgainstASignerThatLies(t *testing.T) {
	f := newGuardFixture(t)
	key := f.root.key
	otherDigest := pki.TBSDigest(otherBodyOf(t))
	ones := bytes.Repeat([]byte{0x01}, 48)
	n := elliptic.P384().Params().N
	derSig := func(r, s []byte) []byte { return tlv(0x30, tlv(0x02, r), tlv(0x02, s)) }
	be := func(x *big.Int) []byte { return append([]byte{0}, x.Bytes()...) }
	boom := errors.New("the card is not there")
	calls := map[string]func(s crypto.Signer) ([]byte, error){
		"SignRoot": func(s crypto.Signer) ([]byte, error) { return pki.SignRoot(nil, s, f.root.params, f.root.tbs) },
		"SignIntermediate": func(s crypto.Signer) ([]byte, error) {
			return pki.SignIntermediate(nil, s, f.inter.params, f.inter.tbs)
		},
	}
	bodies := map[string][]byte{"SignRoot": f.root.tbs, "SignIntermediate": f.inter.tbs}
	cases := []struct {
		name  string
		tweak func(digest []byte, k *ecdsa.PrivateKey, sig []byte, body []byte) ([]byte, error)
		is    error
	}{
		{"it fails", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) { return nil, boom }, boom},
		{"it returns nothing and no error", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) { return nil, nil }, nil},
		{"it returns an empty signature", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) { return []byte{}, nil }, nil},
		{"it writes the digest of another body into the digest it was given, and signs that", func(d []byte, k *ecdsa.PrivateKey, _ []byte, _ []byte) ([]byte, error) {
			copy(d, otherDigest)
			return ecdsa.SignASN1(rand.Reader, k, d)
		}, nil},
		{"it signs the digest of another body", func(_ []byte, k *ecdsa.PrivateKey, _ []byte, _ []byte) ([]byte, error) {
			return ecdsa.SignASN1(rand.Reader, k, otherDigest)
		}, nil},
		{"it signs the body and not its digest", func(_ []byte, k *ecdsa.PrivateKey, _ []byte, body []byte) ([]byte, error) {
			return ecdsa.SignASN1(rand.Reader, k, body)
		}, nil},
		{"it signs a SHA-256 digest", func(_ []byte, k *ecdsa.PrivateKey, _ []byte, body []byte) ([]byte, error) {
			d := sha256.Sum256(body)
			return ecdsa.SignASN1(rand.Reader, k, d[:])
		}, nil},
		{"it returns the signature of another key over the right digest", func(d []byte, _ *ecdsa.PrivateKey, _ []byte, _ []byte) ([]byte, error) {
			return ecdsa.SignASN1(rand.Reader, newKey(t), d)
		}, nil},
		{"it returns the raw r and s", func(d []byte, k *ecdsa.PrivateKey, _ []byte, _ []byte) ([]byte, error) {
			r, s, err := ecdsa.Sign(rand.Reader, k, d) //nolint:staticcheck // the raw form is the point
			if err != nil {
				return nil, err
			}
			return append(r.FillBytes(make([]byte, 48)), s.FillBytes(make([]byte, 48))...), nil
		}, nil},
		{"it returns a good signature with a byte after it", func(_ []byte, _ *ecdsa.PrivateKey, sig []byte, _ []byte) ([]byte, error) {
			return append(append([]byte{}, sig...), 0x00), nil
		}, nil},
		{"it returns a good signature cut short", func(_ []byte, _ *ecdsa.PrivateKey, sig []byte, _ []byte) ([]byte, error) {
			return sig[:len(sig)-1], nil
		}, nil},
		{"it returns a good signature with its last byte changed", func(_ []byte, _ *ecdsa.PrivateKey, sig []byte, _ []byte) ([]byte, error) {
			out := append([]byte{}, sig...)
			out[len(out)-1] ^= 0x01
			return out, nil
		}, nil},
		{"r is zero", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) { return derSig([]byte{0}, ones), nil }, nil},
		{"s is zero", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) { return derSig(ones, []byte{0}), nil }, nil},
		{"r is the order", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) { return derSig(be(n), ones), nil }, nil},
		{"s is the order", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) { return derSig(ones, be(n)), nil }, nil},
		{"r is above the order", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) {
			return derSig(be(new(big.Int).Add(n, big.NewInt(1))), ones), nil
		}, nil},
		{"r is negative", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) {
			return derSig([]byte{0xff}, ones), nil
		}, nil},
		{"r has a useless leading zero", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) {
			return derSig(append([]byte{0, 0}, ones...), ones), nil
		}, nil},
		{"three integers", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) {
			return tlv(0x30, tlv(0x02, ones), tlv(0x02, ones), tlv(0x02, ones)), nil
		}, nil},
		{"one integer", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) {
			return tlv(0x30, tlv(0x02, ones)), nil
		}, nil},
		{"a bit string", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) {
			return tlv(0x03, []byte{0}, ones), nil
		}, nil},
		{"a set of two integers", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) {
			return tlv(0x31, tlv(0x02, ones), tlv(0x02, ones)), nil
		}, nil},
		{"an empty sequence", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) { return []byte{0x30, 0x00}, nil }, nil},
		{"a sequence of indefinite length", func([]byte, *ecdsa.PrivateKey, []byte, []byte) ([]byte, error) {
			return []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00}, nil
		}, nil},
	}
	for fn, call := range calls {
		for _, c := range cases {
			t.Run(fn+": "+c.name, func(t *testing.T) {
				body := bodies[fn]
				s := &opaqueSigner{key: key}
				s.tweak = func(d []byte, k *ecdsa.PrivateKey, sig []byte) ([]byte, error) { return c.tweak(d, k, sig, body) }
				sig, err := call(s)
				refused(t, err, pki.ErrSignature)
				onePrefix(t, err)
				if sig != nil {
					t.Errorf("a signature %x came with the error", sig)
				}
				if s.calls != 1 {
					t.Errorf("the signer was called %d times, want 1", s.calls)
				}
				if c.is != nil && !errors.Is(err, c.is) {
					t.Errorf("errors.Is(err, %v) is false: %v", c.is, err)
				}
			})
		}
		t.Run(fn+": it returns the same signature for two bodies", func(t *testing.T) {
			var kept []byte
			s := &opaqueSigner{key: key}
			s.tweak = func(_ []byte, _ *ecdsa.PrivateKey, sig []byte) ([]byte, error) {
				if kept == nil {
					kept = append([]byte(nil), sig...)
				}
				return kept, nil
			}
			if _, err := call(s); err != nil {
				t.Fatal(err)
			}
			// Another body of the same kind: another serial.
			second := pki.RootParams(f.root.params)
			second.Serial = new(big.Int).Add(second.Serial, big.NewInt(1))
			secondBody, err := pki.RootTBS(second)
			if err != nil {
				t.Fatal(err)
			}
			got, err := pki.SignRoot(nil, s, second, secondBody)
			refused(t, err, pki.ErrSignature)
			if got != nil {
				t.Error("a signature of another body came out")
			}
		})
		t.Run(fn+": it keeps the digest and the signature and changes them later", func(t *testing.T) {
			var keptD, keptS []byte
			s := &opaqueSigner{key: key}
			s.tweak = func(d []byte, _ *ecdsa.PrivateKey, sig []byte) ([]byte, error) {
				keptD, keptS = d, sig
				return sig, nil
			}
			sig, err := call(s)
			if err != nil {
				t.Fatal(err)
			}
			for i := range keptD {
				keptD[i] ^= 0xff
			}
			for i := range keptS {
				keptS[i] ^= 0xff
			}
			if _, err := pki.Assemble(bodies[fn], sig, &key.PublicKey); err != nil {
				t.Errorf("the signature changed with the signer's slices: %v", err)
			}
		})
		t.Run(fn+": its public key changes after the first look", func(t *testing.T) {
			s := &changingPublic{opaqueSigner: &opaqueSigner{key: key}, later: &newKey(t).PublicKey}
			sig, err := call(s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pki.Assemble(bodies[fn], sig, &key.PublicKey); err != nil {
				t.Errorf("the signature does not verify with the key that was looked at first: %v", err)
			}
		})
	}
}

// otherBodyOf is the body of another root.
func otherBodyOf(t *testing.T) []byte { return mustRootTBS(t, newKey(t)) }

// changingPublic is a signer whose Public returns another key after the first call.
type changingPublic struct {
	*opaqueSigner
	later *ecdsa.PublicKey
	seen  int
}

func (c *changingPublic) Public() crypto.PublicKey {
	c.seen++
	if c.seen == 1 {
		return &c.key.PublicKey
	}
	return c.later
}

// A signer whose Public method returns nothing at all.
type noPublic struct{}

func (noPublic) Public() crypto.PublicKey { return nil }
func (noPublic) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("must not be called")
}

func TestSignRefusesASignerWithNoPublicKeyOrABadOne(t *testing.T) {
	f := newGuardFixture(t)
	calls := map[string]func(s crypto.Signer) ([]byte, error){
		"SignRoot": func(s crypto.Signer) ([]byte, error) { return pki.SignRoot(nil, s, f.root.params, f.root.tbs) },
		"SignIntermediate": func(s crypto.Signer) ([]byte, error) {
			return pki.SignIntermediate(nil, s, f.inter.params, f.inter.tbs)
		},
	}
	for fn, call := range calls {
		t.Run(fn+": no signer", func(t *testing.T) {
			sig, err := call(nil)
			refused(t, err, pki.ErrParams)
			if sig != nil {
				t.Error("a signature came with the error")
			}
		})
		t.Run(fn+": a signer with no public key", func(t *testing.T) {
			_, err := call(noPublic{})
			refused(t, err, pki.ErrParams)
		})
		for name, key := range badKeys(t) {
			if key == nil {
				continue // an opaque signer treats a nil pub as "not set"; noPublic covers it above
			}
			t.Run(fn+": a signer with the public key "+name, func(t *testing.T) {
				s := &opaqueSigner{key: f.root.key, pub: key}
				sig, err := call(s)
				refused(t, err, pki.ErrParams)
				if sig != nil || s.calls != 0 {
					t.Errorf("a signature came, or the signer was called %d times", s.calls)
				}
			})
		}
	}
}
