package trustset_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// signingChain is a chain with a list of A, B and a draft for the next list that adds C.
func addDraft(t *testing.T) (*chain, *trustset.Draft) {
	t.Helper()
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	d, err := c.draft(next{labels: []string{"A", "B", "C"}})
	if err != nil {
		t.Fatal(err)
	}
	return c, d
}

// scripted makes a counting signer for a label with a hook for SignES384.
func scripted(t testing.TB, label string, sign func(input []byte) ([]byte, error)) *scriptedSigner {
	t.Helper()
	s := counting(newRoot(t, label, true).signer(t))
	s.sign = sign
	return s
}

// The signers are checked before any key is asked: every fault is ErrSigners and every counter is 0.
func TestSignersAreCheckedBeforeAnyKey(t *testing.T) {
	type tc struct {
		name    string
		prepare func(t *testing.T) (*trustset.Draft, []*scriptedSigner)
		want    string
	}
	sg := func(labels ...string) []*scriptedSigner {
		var out []*scriptedSigner
		for _, l := range labels {
			out = append(out, counting(newRoot(t, l, true).signer(t)))
		}
		return out
	}
	addD := func(t *testing.T) *trustset.Draft { _, d := addDraft(t); return d }
	renewD := func(t *testing.T) *trustset.Draft {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B"}})
		d, err := c.draft(next{labels: []string{"A", "B"}})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	firstD := func(t *testing.T) *trustset.Draft {
		d, err := newChain(t).draft(next{labels: []string{"A", "B"}})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	revokeD := func(t *testing.T, deps ...func() trustset.Departure) *trustset.Draft {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B", "C"}})
		var ds []trustset.Departure
		for _, f := range deps {
			ds = append(ds, f())
		}
		labels := []string{"A", "B", "C"}
		for _, d := range ds {
			labels = slices.DeleteFunc(labels, func(l string) bool { return newRoot(t, l, true).Pin == d.X509SPKISHA256 })
		}
		d, err := c.draft(next{labels: labels, deps: ds})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	retireD := func(t *testing.T) *trustset.Draft {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B", "C"}})
		d, err := c.draft(next{labels: []string{"A", "B"}, deps: []trustset.Departure{retire(t, "C")}})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	cases := []tc{
		{"missing signer", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return addD(t), sg("A", "B") }, "must sign this list and has no signer"},
		{"no signers at all", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return addD(t), nil }, "must sign"},
		{"extra signer of a label that is on no list", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			return addD(t), sg("A", "B", "C", "Z")
		}, "may sign this list"},
		{"two signers with one label", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			return addD(t), sg("A", "B", "C", "B")
		}, "two signers have the label B"},
		{"the same signer twice", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			s := sg("A", "B", "C")
			return addD(t), append(s, s[0])
		}, "two signers have the label A"},
		{"a certificate with another pin than the label's", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			s := sg("A", "B", "C")
			s[1].cert = func() *x509.Certificate { return newRoot(t, "D", true).Cert }
			return addD(t), s
		}, "holds another key"},
		{"a certificate that is another variant of the key", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			s := sg("A", "B", "C")
			s[0].cert = func() *x509.Certificate { return newRootVariant(t, "A", "second").Cert }
			return addD(t), s
		}, "holds another key"},
		{"a nil certificate", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			s := sg("A", "B", "C")
			s[2].cert = func() *x509.Certificate { return nil }
			return addD(t), s
		}, "there is no certificate"},
		{"a certificate with no DER", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			s := sg("A", "B", "C")
			s[2].cert = func() *x509.Certificate { return &x509.Certificate{} }
			return addD(t), s
		}, "no DER"},
		{"a label in lower case", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			s := sg("A", "B", "C")
			s[0].label = func() string { return "a" }
			return addD(t), s
		}, "label of the signer"},
		{"an empty label", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			s := sg("A", "B", "C")
			s[0].label = func() string { return "" }
			return addD(t), s
		}, "label of the signer"},
		{"27 signers", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			s := sg("A", "B", "C")
			for i := 0; i < 24; i++ {
				s = append(s, s[0])
			}
			return addD(t), s
		}, "at most 26"},
		{"first list: two signers", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return firstD(t), sg("A", "B") }, "exactly one"},
		{"first list: none", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return firstD(t), nil }, "exactly one"},
		{"first list: a signer of another label", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return firstD(t), sg("C") }, "may sign this list"},
		{"renewal: two signers", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return renewD(t), sg("A", "B") }, "exactly one"},
		{"renewal: none", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return renewD(t), nil }, "exactly one"},
		{"renewal: a key that is not on the list", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return renewD(t), sg("C") }, "may sign this list"},
		{"renewal: one of the list and one that is not", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return renewD(t), sg("A", "C") }, "may sign this list"},
		{"retire: the retired key is not asked", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return retireD(t), sg("A", "B") }, "must sign this list and has no signer"},
		{"retire: only the retired key", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return retireD(t), sg("C") }, "must sign"},
		{"revoke with an authorisation: a signer for the revoked key", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			return revokeD(t, func() trustset.Departure { return revoke(t, "A") }), sg("A", "B", "C")
		}, "stands for its signature"},
		{"revoke with an authorisation: a kept key has no signer", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			return revokeD(t, func() trustset.Departure { return revoke(t, "A") }), sg("B")
		}, "must sign this list and has no signer"},
		{"revoke without an authorisation: the key does not sign", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			return revokeD(t, func() trustset.Departure { return revokeLost(t, "A") }), sg("B", "C")
		}, "must sign this list and has no signer"},
		{"revoke-of-two-keys-one-has-neither", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) {
			// A has its authorisation, B has none and is given no signer.
			return revokeD(t, func() trustset.Departure { return revoke(t, "A") }, func() trustset.Departure { return revokeLost(t, "B") }), sg("C")
		}, "root key B must sign"},
		{"add: the new key has no signer", func(t *testing.T) (*trustset.Draft, []*scriptedSigner) { return addD(t), sg("A", "B") }, "root key C must sign"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, signers := tc.prepare(t)
			set, err := d.Sign(asSigners(signers), nil)
			if set != nil {
				t.Fatal("a set came with the error")
			}
			wantOnly(t, err, trustset.ErrSigners)
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the text does not hold %q: %v", tc.want, err)
			}
			zeroCalls(t, signers)
		})
	}
	t.Run("a nil signer in the list", func(t *testing.T) {
		_, d := addDraft(t)
		s := sg("A", "B", "C")
		in := []trustset.Signer{s[0], nil, s[1], s[2]}
		set, err := d.Sign(in, nil)
		if set != nil {
			t.Fatal("a set")
		}
		wantOnly(t, err, trustset.ErrSigners)
		zeroCalls(t, s)
	})
}

// A signer that panics when its label or certificate is read is ErrSign, with no key asked.
func TestSignerThatPanicsWhenRead(t *testing.T) {
	_, d := addDraft(t)
	for name, mk := range map[string]func(*scriptedSigner){
		"label":       func(s *scriptedSigner) { s.label = func() string { panic("label") } },
		"certificate": func(s *scriptedSigner) { s.cert = func() *x509.Certificate { panic("certificate") } },
	} {
		s := []*scriptedSigner{scripted(t, "A", nil), scripted(t, "B", nil), scripted(t, "C", nil)}
		mk(s[1])
		set, err := d.Sign(asSigners(s), nil)
		if set != nil {
			t.Errorf("%s: a set", name)
		}
		wantOnly(t, err, trustset.ErrSign)
		if strings.Contains(err.Error(), "label") && strings.Contains(err.Error(), "panic(") {
			t.Errorf("the panic value is shown: %v", err)
		}
		zeroCalls(t, s)
	}
	// A typed nil pointer in the interface panics on its first call.
	var nilSigner *scriptedSigner
	s := []*scriptedSigner{scripted(t, "A", nil), scripted(t, "B", nil), scripted(t, "C", nil)}
	set, err := d.Sign([]trustset.Signer{s[0], nilSigner, s[1], s[2]}, nil)
	if set != nil {
		t.Error("a set")
	}
	wantOnly(t, err, trustset.ErrSign)
	zeroCalls(t, s)
}

// The label and the certificate of a signer are read once: a signer that answers another label the
// second time is judged by the first answer, and the signature is made for it.
func TestLabelAndCertificateAreReadOnce(t *testing.T) {
	_, d := addDraft(t)
	var mu sync.Mutex
	reads := map[string]int{}
	signers := make([]*scriptedSigner, 0, 3)
	for _, l := range []string{"A", "B", "C"} {
		s := counting(newRoot(t, l, true).signer(t))
		first := l
		s.label = func() string {
			mu.Lock()
			defer mu.Unlock()
			reads[first+"label"]++
			if reads[first+"label"] > 1 {
				return "Q"
			}
			return first
		}
		s.cert = func() *x509.Certificate {
			mu.Lock()
			defer mu.Unlock()
			reads[first+"cert"]++
			if reads[first+"cert"] > 1 {
				return newRoot(t, "Q", true).Cert
			}
			return newRoot(t, first, true).Cert
		}
		signers = append(signers, s)
	}
	set, err := d.Sign(asSigners(signers), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	for k, n := range reads {
		if n != 1 {
			t.Errorf("%s was read %d times", k, n)
		}
	}
	for i, n := range calls(signers) {
		if n != 1 {
			t.Errorf("signer %d was asked %d times", i, n)
		}
	}
	if !slices.Equal(set.Signers(), []string{"A", "B", "C"}) {
		t.Errorf("Signers = %v", set.Signers())
	}
}

// Each signer is asked once, in the order of the labels, whatever the order they are given in.
func TestSignersAreAskedOnceInLabelOrder(t *testing.T) {
	c, d := addDraft(t)
	var mu sync.Mutex
	var order []string
	mk := func(l string) *scriptedSigner {
		s := counting(newRoot(t, l, true).signer(t))
		inner := s.inner
		s.sign = func(in []byte) ([]byte, error) {
			mu.Lock()
			order = append(order, l)
			mu.Unlock()
			return inner.SignES384(in)
		}
		return s
	}
	for _, perm := range [][]string{{"A", "B", "C"}, {"C", "B", "A"}, {"B", "C", "A"}, {"C", "A", "B"}} {
		order = nil
		var signers []*scriptedSigner
		for _, l := range perm {
			signers = append(signers, mk(l))
		}
		var seen []string
		set, err := d.Sign(asSigners(signers), func(s trustset.Signed) error {
			seen = append(seen, s.Label)
			return nil
		})
		if err != nil {
			t.Fatalf("%v: %v", perm, err)
		}
		if !slices.Equal(order, []string{"A", "B", "C"}) {
			t.Errorf("given as %v the signers were asked in the order %v", perm, order)
		}
		if !slices.Equal(seen, []string{"A", "B", "C"}) || !slices.Equal(set.Signers(), []string{"A", "B", "C"}) {
			t.Errorf("after saw %v and Signers is %v", seen, set.Signers())
		}
		for i, n := range calls(signers) {
			if n != 1 {
				t.Errorf("signer %d asked %d times", i, n)
			}
		}
		pins := []string{newRoot(t, "A", true).Pin, newRoot(t, "B", true).Pin, newRoot(t, "C", true).Pin}
		if got := kidsOf(t, set.ListJWS()); !slices.Equal(got, pins) {
			t.Errorf("the kids of the file are not in label order: %v", got)
		}
		mustAccept(t, set, c.last().ListJSON(), firstCeremony.Add(time.Hour))
	}
}

// A signer that fails at its turn (the second of three): ErrSign, the first was asked once, the
// third never, no set.
func TestSignerFailsAtItsTurn(t *testing.T) {
	cases := map[string]func(t *testing.T) func([]byte) ([]byte, error){
		"an error": func(t *testing.T) func([]byte) ([]byte, error) {
			return func([]byte) ([]byte, error) { return nil, errors.New("the card was removed") }
		},
		"an error that carries hostile text": func(t *testing.T) func([]byte) ([]byte, error) {
			return func([]byte) ([]byte, error) {
				return nil, errors.New("\x1b[31mred\x00\xff\u202e" + strings.Repeat("long ", 400))
			}
		},
		"an error of another kind of the package": func(t *testing.T) func([]byte) ([]byte, error) {
			return func([]byte) ([]byte, error) { return nil, trustset.ErrParams }
		},
		"an error that wraps the kind of the package": func(t *testing.T) func([]byte) ([]byte, error) {
			return func([]byte) ([]byte, error) { return nil, fmt.Errorf("x: %w", trustset.ErrReturns) }
		},
		"no signature and no error": func(t *testing.T) func([]byte) ([]byte, error) {
			return func([]byte) ([]byte, error) { return nil, nil }
		},
		"a signature of 95 bytes": func(t *testing.T) func([]byte) ([]byte, error) {
			return func([]byte) ([]byte, error) { return make([]byte, 95), nil }
		},
		"a signature of 97 bytes": func(t *testing.T) func([]byte) ([]byte, error) {
			return func([]byte) ([]byte, error) { return make([]byte, 97), nil }
		},
		"a signature of 96 zero bytes": func(t *testing.T) func([]byte) ([]byte, error) {
			return func([]byte) ([]byte, error) { return make([]byte, 96), nil }
		},
		"the signature of another key": func(t *testing.T) func([]byte) ([]byte, error) {
			return func(in []byte) ([]byte, error) { return newRoot(t, "D", true).signer(t).SignES384(in) }
		},
		"the signature of the right key over another input": func(t *testing.T) func([]byte) ([]byte, error) {
			return func(in []byte) ([]byte, error) {
				return newRoot(t, "B", true).signer(t).SignES384(append(slices.Clone(in), 'x'))
			}
		},
		"a signature with a flipped bit": func(t *testing.T) func([]byte) ([]byte, error) {
			return func(in []byte) ([]byte, error) {
				sig, err := newRoot(t, "B", true).signer(t).SignES384(in)
				sig[95] ^= 1
				return sig, err
			}
		},
		"a panic": func(t *testing.T) func([]byte) ([]byte, error) {
			return func([]byte) ([]byte, error) { panic("the card") }
		},
		"a panic with an error": func(t *testing.T) func([]byte) ([]byte, error) {
			return func([]byte) ([]byte, error) { panic(errors.New("the card")) }
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			_, d := addDraft(t)
			s := []*scriptedSigner{scripted(t, "A", nil), scripted(t, "B", mk(t)), scripted(t, "C", nil)}
			var seen []string
			set, err := d.Sign(asSigners(s), func(x trustset.Signed) error {
				seen = append(seen, x.Label)
				return nil
			})
			if set != nil {
				t.Fatal("a set came with the error")
			}
			wantOnly(t, err, trustset.ErrSign)
			if got := calls(s); !slices.Equal(got, []int{1, 1, 0}) {
				t.Errorf("the signers were asked %v times, want [1 1 0]", got)
			}
			if !slices.Equal(seen, []string{"A"}) {
				t.Errorf("after was called for %v, want [A]", seen)
			}
			if strings.Contains(err.Error(), "the card") && strings.Contains(name, "panic") {
				t.Errorf("the text of a panic is shown: %v", err)
			}
		})
	}
}

// The signer fails at the first turn, at the last turn.
func TestSignerFailsFirstAndLast(t *testing.T) {
	for _, bad := range []string{"A", "C"} {
		_, d := addDraft(t)
		s := []*scriptedSigner{scripted(t, "A", nil), scripted(t, "B", nil), scripted(t, "C", nil)}
		for _, x := range s {
			if x.Label() == bad {
				x.sign = func([]byte) ([]byte, error) { return nil, errors.New("no") }
			}
		}
		set, err := d.Sign(asSigners(s), nil)
		if set != nil {
			t.Fatal("a set")
		}
		wantOnly(t, err, trustset.ErrSign)
		want := []int{1, 1, 1}
		if bad == "A" {
			want = []int{1, 0, 0}
		}
		if got := calls(s); !slices.Equal(got, want) {
			t.Errorf("failing %s: asked %v, want %v", bad, got, want)
		}
	}
}

// What the signer gets is a copy: a signer that changes its input, and one that keeps and changes
// the signature it returned, change nothing in the set.
func TestSignerGetsACopyAndLeavesACopy(t *testing.T) {
	c, d := addDraft(t)
	var kept [][]byte
	mk := func(l string) *scriptedSigner {
		s := counting(newRoot(t, l, true).signer(t))
		inner := s.inner
		s.sign = func(in []byte) ([]byte, error) {
			sig, err := inner.SignES384(in)
			for i := range in {
				in[i] = 'x'
			}
			kept = append(kept, sig)
			return sig, err
		}
		return s
	}
	set, err := d.Sign([]trustset.Signer{mk("A"), mk("B"), mk("C")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range kept {
		for i := range k {
			k[i] ^= 0xff
		}
	}
	mustAccept(t, set, c.last().ListJSON(), firstCeremony.Add(time.Hour))
	// A second signing of the same draft is another set that verifies too.
	again, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	mustAccept(t, again, c.last().ListJSON(), firstCeremony.Add(time.Hour))
	if bytes.Equal(set.ListJWS(), again.ListJWS()) {
		t.Error("two signatures with a random part are equal")
	}
	if !bytes.Equal(set.ListJSON(), again.ListJSON()) || !bytes.Equal(set.CABundle(), again.CABundle()) {
		t.Error("the list and the bundle change from one signing to the next")
	}
}

// after is called once for each signature with the label, the kid, the digest of the signing input
// and the digest of the signature. When it fails Sign stops with ErrSign, asks no more signers and
// returns no set.
func TestAfterEachSignature(t *testing.T) {
	_, d := addDraft(t)
	signers := signersFor(t, d, nil, nil)
	var got []trustset.Signed
	set, err := d.Sign(asSigners(signers), func(s trustset.Signed) error {
		got = append(got, s)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("after was called %d times", len(got))
	}
	sigs := fileSignatures(t, set.ListJWS())
	for i, label := range []string{"A", "B", "C"} {
		r := newRoot(t, label, true)
		if got[i].Label != label || got[i].Kid != r.Pin {
			t.Errorf("call %d: %+v", i, got[i])
		}
		want, err := d.SigningInputSHA256(r.Cert)
		if err != nil {
			t.Fatal(err)
		}
		if got[i].TBSSHA256 != want {
			t.Errorf("call %d: TBSSHA256 %s, SigningInputSHA256 %s", i, got[i].TBSSHA256, want)
		}
		sum := sha256.Sum256(sigs[i])
		if got[i].SignatureSHA256 != hex.EncodeToString(sum[:]) || len(sigs[i]) != 96 {
			t.Errorf("call %d: SignatureSHA256 is not the digest of the 96 bytes of the file", i)
		}
		if signersInput := signers[i].inputs[0]; hexOf(string(signersInput)) != got[i].TBSSHA256 {
			t.Errorf("call %d: TBSSHA256 is not the digest of what the signer was given", i)
		}
	}
	// A nil after is allowed.
	if _, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil); err != nil {
		t.Errorf("a nil after: %v", err)
	}
}

// fileSignatures returns the 96 bytes of each signature of a root-list.jws, in file order.
func fileSignatures(t testing.TB, file []byte) [][]byte {
	t.Helper()
	g, err := jws.ParseGeneral(file, rootlist.ListTyp)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, s := range g.Signatures {
		out = append(out, s.Sig)
	}
	return out
}

func TestAfterThatFails(t *testing.T) {
	for name, fail := range map[string]func(trustset.Signed) error{
		"an error":                     func(trustset.Signed) error { return errors.New("the journal is full") },
		"an error with a hostile text": func(trustset.Signed) error { return errors.New("\x1b[2J\x00" + strings.Repeat("z", 1000)) },
		"a panic":                      func(trustset.Signed) error { panic("the journal") },
		"a panic with an error":        func(trustset.Signed) error { panic(errors.New("the journal")) },
		"an error of the package":      func(trustset.Signed) error { return trustset.ErrSigners },
	} {
		for _, at := range []string{"A", "B", "C"} {
			t.Run(name+" at "+at, func(t *testing.T) {
				_, d := addDraft(t)
				s := signersFor(t, d, nil, nil)
				var seen []string
				set, err := d.Sign(asSigners(s), func(x trustset.Signed) error {
					seen = append(seen, x.Label)
					if x.Label == at {
						return fail(x)
					}
					return nil
				})
				if set != nil {
					t.Fatal("a set came with the error")
				}
				wantOnly(t, err, trustset.ErrSign)
				want := map[string][]int{"A": {1, 0, 0}, "B": {1, 1, 0}, "C": {1, 1, 1}}[at]
				if got := calls(s); !slices.Equal(got, want) {
					t.Errorf("the signers were asked %v times, want %v", got, want)
				}
				if n := slices.Index([]string{"A", "B", "C"}, at); len(seen) != n+1 {
					t.Errorf("after was called %d times, want %d", len(seen), n+1)
				}
				if strings.Contains(err.Error(), "the journal") && strings.Contains(name, "panic") {
					t.Errorf("a panic value is shown: %v", err)
				}
			})
		}
	}
}

// An error of a signer or of after is shown through its text taken once: a cause that counts its
// calls is called once, and not again by Error, errors.Is, errors.As or the print of the error.
func TestTheCauseIsReadOnce(t *testing.T) {
	var fromSigner, fromAfter int
	_, d := addDraft(t)
	s := []*scriptedSigner{scripted(t, "A", nil), scripted(t, "B", func([]byte) ([]byte, error) {
		return nil, erroringCounted{calls: &fromSigner}
	}), scripted(t, "C", nil)}
	_, err := d.Sign(asSigners(s), nil)
	wantOnly(t, err, trustset.ErrSign)
	_ = fmt.Sprintf("%v %+v %s %q", err, err, err, err)
	_ = err.Error()
	_ = errors.Is(err, trustset.ErrParams)
	var target erroringCounted
	_ = errors.As(err, &target)
	if fromSigner != 1 {
		t.Errorf("the error of the signer was asked %d times", fromSigner)
	}
	moreSigners := signersFor(t, d, nil, nil)
	_, err = d.Sign(asSigners(moreSigners), func(trustset.Signed) error { return erroringCounted{calls: &fromAfter} })
	wantOnly(t, err, trustset.ErrSign)
	_ = fmt.Sprintf("%v %+v %s %q", err, err, err, err)
	_ = errors.Is(err, trustset.ErrSign)
	if fromAfter != 1 {
		t.Errorf("the error of after was asked %d times", fromAfter)
	}
	// A cause that cannot be shown is shown as such, from a signer and from after.
	var nilValue *erroringValue
	for _, cause := range []error{erroringPanic{}, erroringPanicNil{}, nilValue} {
		thirdSigners := []*scriptedSigner{scripted(t, "A", nil), scripted(t, "B", func([]byte) ([]byte, error) { return nil, cause }), scripted(t, "C", nil)}
		_, err := d.Sign(asSigners(thirdSigners), nil)
		wantOnly(t, err, trustset.ErrSign)
		_, err = d.Sign(asSigners(signersFor(t, d, nil, nil)), func(trustset.Signed) error { return cause })
		wantOnly(t, err, trustset.ErrSign)
		if !strings.Contains(err.Error(), "the cause could not be shown") {
			t.Errorf("an unshowable cause is not said so: %v", err)
		}
	}
}

// SigningInputSHA256 is the digest that is signed: a signer with a recording SignES384 gets an input
// whose SHA-256 equals the digest made before the signing, with no key.
func TestSigningInputSHA256IsTheDigestThatIsSigned(t *testing.T) {
	_, d := addDraft(t)
	var want []string
	for _, l := range []string{"A", "B", "C"} {
		got, err := d.SigningInputSHA256(newRoot(t, l, true).Cert)
		if err != nil {
			t.Fatal(err)
		}
		again, _ := d.SigningInputSHA256(newRoot(t, l, true).Cert)
		if got != again || len(got) != 64 {
			t.Errorf("%s: %s then %s", l, got, again)
		}
		want = append(want, got)
	}
	if want[0] == want[1] || want[1] == want[2] {
		t.Error("two certificates give one digest")
	}
	signers := signersFor(t, d, nil, nil)
	if _, err := d.Sign(asSigners(signers), nil); err != nil {
		t.Fatal(err)
	}
	for i, s := range signers {
		if got := hexOf(string(s.inputs[0])); got != want[i] {
			t.Errorf("signer %s got an input of digest %s, the plan said %s", s.Label(), got, want[i])
		}
		// The input is protected "." base64url(list), as the page says.
		parts := strings.Split(string(s.inputs[0]), ".")
		if len(parts) != 2 {
			t.Fatalf("the input is %q", s.inputs[0])
		}
		if string(s.inputs[0]) != string(jws.SigningInput(parts[0], d.ListJSON())) {
			t.Error("the input is not the signing input of the list")
		}
		hdr, err := base64Decode(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		var h struct {
			Alg string   `json:"alg"`
			Kid string   `json:"kid"`
			Typ string   `json:"typ"`
			X5C []string `json:"x5c"`
		}
		if err := json.Unmarshal(hdr, &h); err != nil {
			t.Fatal(err)
		}
		r := newRoot(t, s.Label(), true)
		if h.Alg != "ES384" || h.Kid != r.Pin || h.Typ != "root-list+json" || len(h.X5C) != 1 {
			t.Errorf("the protected header is %s", hdr)
		}
		if ok, _ := canonjson.IsCanonical(hdr); !ok {
			t.Errorf("the protected header is not canonical: %s", hdr)
		}
		// The members are written in the order alg, kid, typ, x5c.
		last := -1
		for _, name := range []string{`"alg"`, `"kid"`, `"typ"`, `"x5c"`} {
			at := strings.Index(string(hdr), name)
			if at <= last {
				t.Errorf("the members of the header are not in the order alg kid typ x5c: %s", hdr)
			}
			last = at
		}
	}
	// A certificate that is not a root key of this list gives a digest too, and needs no key.
	if got, err := d.SigningInputSHA256(newRoot(t, "D", true).Cert); err != nil || len(got) != 64 {
		t.Errorf("another certificate: %q, %v", got, err)
	}
	// And a re-issued certificate over the same key gives another digest, because x5c changes.
	re := reissue(t, newRoot(t, "A", true), 100)
	if got, err := d.SigningInputSHA256(re); err != nil || got == want[0] {
		t.Errorf("a re-issued certificate: %q, %v", got, err)
	}
}

func base64Decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// SigningInputSHA256 refuses a certificate that Sign would refuse.
func TestSigningInputSHA256RefusesWhatSignRefuses(t *testing.T) {
	_, d := addDraft(t)
	for name, cert := range map[string]*x509.Certificate{
		"nil":      nil,
		"empty":    {},
		"rsa":      makeCert(t, certOptions{rsaKey: true}).cert,
		"P-256":    makeCert(t, certOptions{curve: elliptic.P256()}).cert,
		"too long": reissue(t, newRoot(t, "A", true), trustset.MaxBytes),
	} {
		got, err := d.SigningInputSHA256(cert)
		if got != "" {
			t.Errorf("%s: a digest", name)
		}
		wantOnly(t, err, trustset.ErrParams)
	}
}

// The size of root-list.jws is known before the first key is asked: a signer whose certificate
// is large makes a file over MaxBytes while ca-bundle.pem is small, and no key is asked.
func TestFileOverTheLimitIsRefusedBeforeAnyKey(t *testing.T) {
	c := newChain(t)
	d, err := c.draft(next{labels: []string{"A", "B"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.CABundle()) > 4000 {
		t.Fatalf("the CA bundle is %d bytes", len(d.CABundle()))
	}
	ra := newRoot(t, "A", true)
	signer := func(pad int) *scriptedSigner {
		s, err := trustset.NewKeySigner("A", reissue(t, ra, pad), ra.Key)
		if err != nil {
			t.Fatal(err)
		}
		return counting(s)
	}
	big := signer(150 * 1024)
	set, err := d.Sign([]trustset.Signer{big}, nil)
	if set != nil {
		t.Fatal("a set came with the error")
	}
	wantOnly(t, err, trustset.ErrParams)
	if !strings.Contains(err.Error(), "longer than") {
		t.Errorf("the text does not name the file: %v", err)
	}
	if big.count() != 0 {
		t.Errorf("the key was asked %d times", big.count())
	}
	// The largest certificate that goes: the file is under the limit, one more step is over it, and
	// in both the key is asked or not asked accordingly.
	lo, hi := 1000, 150*1024 // lo goes, hi does not
	var fit []byte
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		s := signer(mid)
		set, err := d.Sign([]trustset.Signer{s}, nil)
		if err == nil {
			lo, fit = mid, set.ListJWS()
			continue
		}
		wantOnly(t, err, trustset.ErrParams)
		if s.count() != 0 {
			t.Fatalf("padding %d: the key was asked before the file was refused", mid)
		}
		hi = mid
	}
	if len(fit) > trustset.MaxBytes || len(fit) < trustset.MaxBytes-8 {
		t.Errorf("the largest file that goes is %d bytes, the limit is %d", len(fit), trustset.MaxBytes)
	}
}

// reissue makes another certificate over the key of a root, with an extension that makes it pad bytes
// larger: the same pin, so a signer may use it.
func reissue(t testing.TB, r *testRoot, pad int) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(77),
		Subject:               pkix.Name{CommonName: "Example Test " + r.Label + " (TEST ONLY)"},
		NotBefore:             ceremony,
		NotAfter:              ceremony.AddDate(3, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtraExtensions:       []pkix.Extension{{Id: []int{1, 3, 6, 1, 4, 1, 99999, 1}, Value: bytes.Repeat([]byte{'a'}, pad)}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, r.Key.Public(), r.Key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
