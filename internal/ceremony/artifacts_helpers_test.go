//go:build linux || darwin

package ceremony_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/trustset"
)

// mkRootKey is one root key of a hand-made set: the key, its certificate (hand-made), its label and
// pin.
type mkRootKey struct {
	Label string
	Key   *ecdsa.PrivateKey
	Cert  mkCert
	Pin   string
}

func mkRootKeys(labels ...string) []mkRootKey {
	var out []mkRootKey
	for i, l := range labels {
		k := mkKeyP384()
		c := mkCertSpec{Key: k, Label: l, Serial: mkSerial(byte(i + 1))}.build()
		out = append(out, mkRootKey{Label: l, Key: k, Cert: c, Pin: mkPin(&k.PublicKey)})
	}
	return out
}

// mkSetSpec says how to make a first trust set from hand-made keys.
type mkSetSpec struct {
	Keys     []mkRootKey
	SignedAt time.Time // the ceremony time when zero
	Signers  []string  // labels; the first key's when empty
	Sequence int64     // 1 when zero
}

// build makes the set with trustset, the way the engine does but with the keys of the test.
func (s mkSetSpec) build(t testing.TB) *trustset.Set {
	t.Helper()
	at := s.SignedAt
	if at.IsZero() {
		at = pfClock
	}
	seq := s.Sequence
	if seq == 0 {
		seq = 1
	}
	var roots []trustset.Root
	certs := map[string][]byte{}
	for _, k := range s.Keys {
		roots = append(roots, trustset.Root{Label: k.Label, X509SPKISHA256: k.Pin})
		certs[k.Label] = k.Cert.DER
	}
	d, err := trustset.NewDraft(trustset.Input{Sequence: seq, SignedAt: at, Roots: roots, Certificates: certs})
	if err != nil {
		t.Fatalf("NewDraft: %v", err)
	}
	want := s.Signers
	if len(want) == 0 {
		want = []string{s.Keys[0].Label}
	}
	var signers []trustset.Signer
	for _, l := range want {
		for _, k := range s.Keys {
			if k.Label != l {
				continue
			}
			cert, err := x509.ParseCertificate(k.Cert.DER)
			if err != nil {
				t.Fatal(err)
			}
			sg, err := trustset.NewKeySigner(k.Label, cert, k.Key)
			if err != nil {
				t.Fatal(err)
			}
			signers = append(signers, sg)
		}
	}
	set, err := d.Sign(signers, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return set
}

// wantFor is the facts of a first list for the keys, as the engine gives them.
func mkWantFor(keys []mkRootKey, signer string) ceremony.RootListWant {
	w := ceremony.RootListWant{SignedAt: pfClock, Signer: signer}
	for _, k := range keys {
		w.Labels = append(w.Labels, k.Label)
		w.Pins = append(w.Pins, k.Pin)
		w.Certificates = append(w.Certificates, k.Cert.DER)
	}
	return w
}
