package trustset_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// The certificates that NewDraft takes for the roots of the new list: one for each root and none
// for any other label, each as the page says (record 0006, rule 52; list page, "The CA bundle").
func TestCertificatesOfTheDraft(t *testing.T) {
	good := func() trustset.Input { return newChain(t).input(next{labels: []string{"A", "B"}}) }
	for _, tc := range []struct {
		name   string
		change func(*trustset.Input)
		want   string
	}{
		{"none", func(in *trustset.Input) { in.Certificates = nil }, "0 certificates for 2 roots"},
		{"one missing", func(in *trustset.Input) { delete(in.Certificates, "B") }, "1 certificates for 2 roots"},
		{"one missing and one extra", func(in *trustset.Input) {
			delete(in.Certificates, "B")
			in.Certificates["C"] = newRoot(t, "C", true).DER
		}, "no certificate for root B"},
		{"one extra", func(in *trustset.Input) { in.Certificates["C"] = newRoot(t, "C", true).DER }, "3 certificates for 2 roots"},
		{"the certificate of another key", func(in *trustset.Input) { in.Certificates["A"] = newRoot(t, "C", true).DER }, ""},
		{"the two swapped", func(in *trustset.Input) {
			in.Certificates["A"], in.Certificates["B"] = in.Certificates["B"], in.Certificates["A"]
		}, ""},
		{"not DER", func(in *trustset.Input) { in.Certificates["A"] = []byte("-----BEGIN CERTIFICATE-----") }, ""},
		{"empty", func(in *trustset.Input) { in.Certificates["A"] = nil }, ""},
		{"DER and a trailing byte", func(in *trustset.Input) { in.Certificates["A"] = append(in.Certificates["A"], 0) }, ""},
		{"a cut DER", func(in *trustset.Input) { in.Certificates["A"] = in.Certificates["A"][:len(in.Certificates["A"])-1] }, ""},
		{"over the limit", func(in *trustset.Input) {
			in.Certificates["A"] = append(slices.Clone(in.Certificates["A"]), make([]byte, trustset.MaxBytes)...)
		}, ""},
		{"a RSA certificate", func(in *trustset.Input) { in.Certificates["A"] = makeCert(t, certOptions{rsaKey: true}).der }, ""},
		{"a certificate that is not a CA", func(in *trustset.Input) { in.Certificates["A"] = makeCert(t, certOptions{noCA: true}).der }, ""},
		{"a root certificate without the test mark next to one with it", func(in *trustset.Input) {
			real := newRoot(t, "A", false)
			in.Roots[0] = real.entry(true)
			in.Certificates["A"] = real.DER
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := good()
			tc.change(&in)
			refuses(t, in, tc.want)
		})
	}
	// The certificate of the retired or revoked key is not in the bundle: giving it is refused as
	// an extra certificate.
	c := newChain(t)
	c.add(next{labels: []string{"A", "B", "C"}})
	in := c.input(next{labels: []string{"A", "B"}, deps: []trustset.Departure{retire(t, "C")}})
	in.Certificates["C"] = newRoot(t, "C", true).DER
	refuses(t, in, "certificates for 2 roots")
}

// Real roots, all of them without the mark, make a list; the draft does not ask for a test mark.
func TestRealRootsMakeAList(t *testing.T) {
	a, b := newRoot(t, "A", false), newRoot(t, "B", false)
	in := trustset.Input{
		Sequence:     1,
		SignedAt:     firstCeremony,
		Roots:        []trustset.Root{a.entry(true), b.entry(true)},
		Certificates: map[string][]byte{"A": a.DER, "B": b.DER},
		// Real primaries too: the keyring file does not ask for the test mark either, it asks only that
		// all primaries have it or none has.
		OpenPGPCertificates: map[string][]byte{"A": a.PGP, "B": b.PGP},
	}
	d, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	set, err := d.Sign([]trustset.Signer{b.signer(t)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mustAccept(t, set, nil, firstCeremony)
	if !slices.Equal(set.Signers(), []string{"B"}) {
		t.Errorf("Signers = %v", set.Signers())
	}
}

// The certificate in the bundle is the DER the caller gave, not a re-encoding of it, and the
// certificate of the signer in x5c may be another one over the same key (re-issued at each use).
func TestTheBundleHoldsTheDERGivenAndTheSignerMayCarryAnotherCertificate(t *testing.T) {
	c := newChain(t)
	a := newRoot(t, "A", true)
	re := reissue(t, a, 50)
	in := c.input(next{labels: []string{"A"}})
	in.Certificates["A"] = re.Raw
	d, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	certs := bundleCerts(t, d.CABundle())
	if len(certs) != 1 || !bytes.Equal(certs[0], re.Raw) {
		t.Error("the bundle does not hold the DER that was given")
	}
	// The list pins the key, not the certificate: the same pin for both certificates.
	l, _ := rootlist.ParseList(d.ListJSON())
	if l.Roots[0].X509SPKISHA256 != a.Pin {
		t.Error("the pin changed")
	}
	// The signer's certificate is the old one; the list was made for the new one.
	set, err := d.Sign([]trustset.Signer{a.signer(t)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mustAccept(t, set, nil, firstCeremony)
	if strings.Count(string(set.CABundle()), "BEGIN CERTIFICATE") != 1 {
		t.Error("the bundle holds a certificate too many")
	}
}
