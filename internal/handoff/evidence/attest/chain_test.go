package attest_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
)

// verify parses the evidence and verifies its chain at now against the bundle for the applet.
func verify(t testing.TB, b *attest.Bundle, a attest.Applet, evidence []byte, now time.Time) error {
	t.Helper()
	att, err := attest.ParseAttestation(evidence)
	if err != nil {
		return err
	}
	return b.Verify(a, att, now)
}

// The page: the chain from the slot certificate through the token's certificate and the maker's
// intermediates leads to a pinned root. A good chain verifies, for both applets.
func TestAGoodChainLeadsToThePinnedRoot(t *testing.T) {
	for _, tokenECDSA := range []bool{true, false} {
		m := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: tokenECDSA, Now: clock})
		b := m.Bundle(t)
		if err := verify(t, b, attest.AppletPIV, m.PIVEvidence(t, p384(t), attesttest.Slot{}), clock); err != nil {
			t.Errorf("piv (ECDSA token %v): %v", tokenECDSA, err)
		}
		if err := verify(t, b, attest.AppletOpenPGP, m.OpenPGPEvidence(t, p384(t)), clock); err != nil {
			t.Errorf("openpgp (ECDSA token %v): %v", tokenECDSA, err)
		}
	}
}

// The page: "A root in the file is never trusted. Only the roots the certifier has pinned are." A chain that
// ends in a root that is not pinned, an intermediate that is not pinned, or an intermediate pinned for the
// other applet only, is refused.
func TestOnlyThePinnedCertificatesEndAChain(t *testing.T) {
	m := newMaker(t)
	other := newMaker(t) // a second hierarchy with the same names and other keys
	good := m.Spec()

	type spec = attest.BundleSpec
	cases := []struct {
		name   string
		spec   func() spec
		unpin  bool // the token is issued by an intermediate that no spec holds
		applet attest.Applet
		ok     bool
	}{
		{"piv, the pinned set", func() spec { return good }, false, attest.AppletPIV, true},
		{"openpgp, the pinned set", func() spec { return good }, false, attest.AppletOpenPGP, true},
		{"piv, the token issued by an intermediate that is not pinned", func() spec { return good }, true, attest.AppletPIV, false},
		{"openpgp, the token issued by an intermediate that is not pinned", func() spec { return good }, true, attest.AppletOpenPGP, false},
		{"piv, no piv intermediate pinned", func() spec { s := m.Spec(); s.PIVIntermediates = nil; return s }, false, attest.AppletPIV, false},
		{"openpgp, no openpgp intermediate pinned", func() spec { s := m.Spec(); s.OpenPGPIntermediates = nil; return s }, false, attest.AppletOpenPGP, false},
		{"piv, only the openpgp intermediate pinned for piv", func() spec {
			s := m.Spec()
			s.PIVIntermediates = s.OpenPGPIntermediates
			s.OpenPGPIntermediates = nil // a bundle that holds one in both groups is refused
			return s
		}, false, attest.AppletPIV, false},
		{"openpgp, only the piv intermediate pinned for openpgp", func() spec {
			s := m.Spec()
			s.OpenPGPIntermediates = s.PIVIntermediates
			s.PIVIntermediates = nil
			return s
		}, false, attest.AppletOpenPGP, false},
		{"piv, the openpgp intermediate pinned in the openpgp group only", func() spec {
			s := m.Spec()
			s.PIVIntermediates = nil
			return s
		}, false, attest.AppletPIV, false},
		{"piv, a root of another maker pinned", func() spec {
			s := m.Spec()
			s.Roots = other.Spec().Roots
			return s
		}, false, attest.AppletPIV, false},
		{"piv, both roots pinned", func() spec {
			s := m.Spec()
			s.Roots = append(s.Roots, other.Spec().Roots...)
			return s
		}, false, attest.AppletPIV, true},
		{"piv, an intermediate in the group of the roots' maker only", func() spec {
			s := m.Spec()
			s.PIVIntermediates = other.Spec().PIVIntermediates
			return s
		}, false, attest.AppletPIV, false},
		{"piv, extra intermediates beside the right one", func() spec {
			s := m.Spec()
			s.PIVIntermediates = append(s.PIVIntermediates, other.Spec().PIVIntermediates...)
			return s
		}, false, attest.AppletPIV, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := attest.NewBundle(c.spec())
			if err != nil {
				t.Fatal(err)
			}
			slot := attesttest.Slot{UnpinnedIssuer: c.unpin}
			var ev []byte
			if c.applet == attest.AppletPIV {
				ev = m.PIVEvidence(t, p384(t), slot)
			} else {
				ev = m.OpenPGPEvidenceWith(t, p384(t), slot)
			}
			err = verify(t, b, c.applet, ev, clock)
			if c.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			wantRefusal(t, err, handoff.CodeProofInvalid)
		})
	}
}

// A chain that the evidence completes is refused: the entries from the third are not read (record 0003, rule
// 18: only the holder's own flag supplies a helper, and the requester's list does not). A self-signed root
// in the list is never trusted either.
func TestTheEntriesFromTheThirdAreNeverHelpers(t *testing.T) {
	m := newMaker(t)
	b := m.Bundle(t)
	// The pinned set holds the root and the intermediates; a bundle without the PIV intermediate cannot
	// complete a chain whose token was issued by it, unless the intermediate came with the evidence.
	spec := m.Spec()
	pivInt := spec.PIVIntermediates[0]
	rootDER := spec.Roots[0]
	spec.PIVIntermediates = nil
	noInter, err := attest.NewBundle(spec)
	if err != nil {
		t.Fatal(err)
	}
	leaf, token := m.PIVChain(t, p384(t), attesttest.Slot{})

	// The good chain, with the intermediate that would complete it as the third entry.
	if err := verify(t, noInter, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf, token, pivInt), clock); err == nil {
		t.Error("an intermediate from the evidence completed a chain")
	} else {
		wantRefusal(t, err, handoff.CodeProofInvalid)
	}
	// The same, with the intermediate and the root as the third and fourth entries.
	if err := verify(t, noInter, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf, token, pivInt, rootDER), clock); err == nil {
		t.Error("an intermediate and a root from the evidence completed a chain")
	} else {
		wantRefusal(t, err, handoff.CodeProofInvalid)
	}
	// A bundle that pins a root of another maker, with the right root in the evidence: not trusted.
	other := newMaker(t)
	otherSpec := other.Spec()
	otherSpec.PIVIntermediates = other.Spec().PIVIntermediates
	otherB, err := attest.NewBundle(otherSpec)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(t, otherB, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf, token, pivInt, rootDER), clock); err == nil {
		t.Error("a root from the evidence was trusted")
	} else {
		wantRefusal(t, err, handoff.CodeProofInvalid)
	}
	// The third entry changes nothing for a good chain, whatever it holds.
	for _, extra := range [][]byte{{0x01}, rootDER, pivInt, token, leaf, []byte("text")} {
		if err := verify(t, b, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf, token, extra), clock); err != nil {
			t.Errorf("an extra entry %d bytes long: %v", len(extra), err)
		}
	}
	// A chain whose token is issued by an intermediate that is under the root but pinned nowhere: the
	// intermediate in the evidence does not help.
	stray := m.StrayIntermediate().Raw
	leaf2, token2 := m.PIVChain(t, p384(t), attesttest.Slot{UnpinnedIssuer: true})
	if err := verify(t, b, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf2, token2, stray), clock); err == nil {
		t.Error("an unpinned intermediate from the evidence completed a chain")
	} else {
		wantRefusal(t, err, handoff.CodeProofInvalid)
	}
	// And a chain through the token only: a bundle that pins the root and nothing else, with the evidence
	// being the root's direct issue (token issued by the root) is not the shape of the page, and refused here
	// because no pinned intermediate stands between.
	if err := verify(t, noInter, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf, token), clock); err == nil {
		t.Error("a chain with a missing intermediate verified")
	}
}

// The page: "with every certificate valid at the time of the ceremony", the pinned ones included. A
// certificate is valid from its notBefore through its notAfter (RFC 5280, section 4.1.2.5); one second
// before or after is not.
func TestEveryCertificateOfTheChainMustBeValidAtTheTime(t *testing.T) {
	roles := []struct {
		name   string
		applet attest.Applet
		set    func(w window) attesttest.MakerOptions
		slot   func(w window) attesttest.Slot
	}{
		{"leaf", attest.AppletPIV, nil, func(w window) attesttest.Slot {
			return attesttest.Slot{Tweak: func(c *x509.Certificate) { c.NotBefore, c.NotAfter = w.before, w.after }}
		}},
		{"token", attest.AppletPIV, nil, func(w window) attesttest.Slot {
			return attesttest.Slot{TokenTweak: func(c *x509.Certificate) { c.NotBefore, c.NotAfter = w.before, w.after }}
		}},
		{"piv intermediate", attest.AppletPIV, hierarchy(attesttest.RolePIVIntermediate), nil},
		{"openpgp intermediate", attest.AppletOpenPGP, hierarchy(attesttest.RoleOpenPGPIntermediate), nil},
		{"root, piv", attest.AppletPIV, hierarchy(attesttest.RoleRoot), nil},
		{"root, openpgp", attest.AppletOpenPGP, hierarchy(attesttest.RoleRoot), nil},
		{"leaf, openpgp", attest.AppletOpenPGP, nil, func(w window) attesttest.Slot {
			return attesttest.Slot{Tweak: func(c *x509.Certificate) { c.NotBefore, c.NotAfter = w.before, w.after }}
		}},
		{"token, openpgp", attest.AppletOpenPGP, nil, func(w window) attesttest.Slot {
			return attesttest.Slot{TokenTweak: func(c *x509.Certificate) { c.NotBefore, c.NotAfter = w.before, w.after }}
		}},
	}
	day := 24 * time.Hour
	windows := []struct {
		name string
		w    window
		ok   bool
	}{
		{"valid", window{clock.Add(-day), clock.Add(day)}, true},
		{"notBefore is the time", window{clock, clock.Add(day)}, true},
		{"notAfter is the time", window{clock.Add(-day), clock}, true},
		{"notBefore one second after the time", window{clock.Add(time.Second), clock.Add(day)}, false},
		{"notAfter one second before the time", window{clock.Add(-day), clock.Add(-time.Second)}, false},
		{"long expired", window{clock.AddDate(-5, 0, 0), clock.AddDate(-4, 0, 0)}, false},
		{"not yet valid", window{clock.AddDate(1, 0, 0), clock.AddDate(2, 0, 0)}, false},
	}
	for _, r := range roles {
		for _, w := range windows {
			t.Run(r.name+", "+w.name, func(t *testing.T) {
				opts := attesttest.MakerOptions{TokenECDSA: true, Now: clock}
				if r.set != nil {
					opts = r.set(w.w)
				}
				m := attesttest.NewMaker(t, opts)
				var slot attesttest.Slot
				if r.slot != nil {
					slot = r.slot(w.w)
				}
				var ev []byte
				if r.applet == attest.AppletPIV {
					ev = m.PIVEvidence(t, p384(t), slot)
				} else {
					ev = m.OpenPGPEvidenceWith(t, p384(t), slot)
				}
				err := verify(t, m.Bundle(t), r.applet, ev, clock)
				if w.ok {
					if err != nil {
						t.Fatalf("refused: %v", err)
					}
					return
				}
				detail := wantRefusal(t, err, handoff.CodeProofInvalid)
				if !strings.Contains(detail, "not valid at the time") {
					t.Errorf("the detail %q does not say that a certificate is not valid at the time", detail)
				}
			})
		}
	}
}

// window is the validity that a test gives one certificate.
type window struct{ before, after time.Time }

// hierarchy returns the options of a maker in which the certificate of one role of the hierarchy has the
// window.
func hierarchy(role string) func(w window) attesttest.MakerOptions {
	return func(w window) attesttest.MakerOptions {
		return attesttest.MakerOptions{TokenECDSA: true, Now: clock, Tweak: func(r string, c *x509.Certificate) {
			if r == role {
				c.NotBefore, c.NotAfter = w.before, w.after
			}
		}}
	}
}

// The time is the argument: the same evidence is good at one time and refused at another, and the zone of
// the argument does not matter.
func TestTheTimeIsTheArgumentAndItsZoneDoesNotMatter(t *testing.T) {
	m := newMaker(t)
	b := m.Bundle(t)
	ev := m.PIVEvidence(t, p384(t), attesttest.Slot{})
	zone := time.FixedZone("far", 14*3600)
	for _, now := range []time.Time{clock, clock.In(zone), clock.In(time.FixedZone("west", -11*3600)), clock.Add(30 * 24 * time.Hour)} {
		if err := verify(t, b, attest.AppletPIV, ev, now); err != nil {
			t.Errorf("at %v: %v", now, err)
		}
	}
	// The leaf is valid one year either side of the clock; the others longer.
	for _, now := range []time.Time{clock.AddDate(1, 0, 1), clock.AddDate(-1, 0, -1), clock.AddDate(3, 0, 0), clock.AddDate(-30, 0, 0)} {
		wantRefusal(t, verify(t, b, attest.AppletPIV, ev, now), handoff.CodeProofInvalid)
	}
	// The same instant in another zone is the same answer: the leaf's notAfter, in two zones.
	edge := m.Now().AddDate(1, 0, 0)
	if err := verify(t, b, attest.AppletPIV, ev, edge); err != nil {
		t.Errorf("at the notAfter of the leaf: %v", err)
	}
	if err := verify(t, b, attest.AppletPIV, ev, edge.In(zone)); err != nil {
		t.Errorf("at the notAfter of the leaf, in another zone: %v", err)
	}
	wantRefusal(t, verify(t, b, attest.AppletPIV, ev, edge.Add(time.Second).In(zone)), handoff.CodeProofInvalid)
	// And the other edge of the leaf: a year before the clock it is valid, one second before that it is not.
	start := m.Now().AddDate(-1, 0, 0)
	if err := verify(t, b, attest.AppletPIV, ev, start); err != nil {
		t.Errorf("at the notBefore of the leaf: %v", err)
	}
	wantRefusal(t, verify(t, b, attest.AppletPIV, ev, start.Add(-time.Second)), handoff.CodeProofInvalid)
}

// The token's certificate must have signed the key's certificate: a leaf signed by another key that has the
// token's name, and a leaf whose issuer name is not the token's, are refused.
func TestTheKeysCertificateMustBeSignedByTheTokensCertificate(t *testing.T) {
	m := newMaker(t)
	b := m.Bundle(t)
	cases := map[string]attesttest.Slot{
		"signed by another key with the token's name":  {OtherSigner: true},
		"a leaf whose issuer is not the token's name":  {IssuerName: "Example Other Name"},
		"a leaf whose issuer name is empty text-like":  {IssuerName: "x"},
		"signed by the right key with the right chain": {},
	}
	for name, slot := range cases {
		t.Run(name, func(t *testing.T) {
			err := verify(t, b, attest.AppletPIV, m.PIVEvidence(t, p384(t), slot), clock)
			if name == "signed by the right key with the right chain" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantRefusal(t, err, handoff.CodeProofInvalid)
		})
	}
	// The explicit rule of the page names its fault in fixed words: the signature, not the chain.
	err := verify(t, b, attest.AppletPIV, m.PIVEvidence(t, p384(t), attesttest.Slot{OtherSigner: true}), clock)
	if d := wantRefusal(t, err, handoff.CodeProofInvalid); !strings.Contains(d, "not signed by the token") {
		t.Errorf("the detail %q does not say that the signature is not the token's", d)
	}
}

// The chain is not for a purpose: a leaf or an intermediate with a restricted extended key usage, such as one
// for code signing, does not stop an attestation chain (the rule asks for no key usage).
func TestExtendedKeyUsageDoesNotStopTheChain(t *testing.T) {
	m := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, Now: clock, Tweak: func(role string, c *x509.Certificate) {
		if role == attesttest.RolePIVIntermediate {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
	}})
	ev := m.PIVEvidence(t, p384(t), attesttest.Slot{Tweak: func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}})
	if err := verify(t, m.Bundle(t), attest.AppletPIV, ev, clock); err != nil {
		t.Errorf("a chain with extended key usages: %v", err)
	}
}

// A signature of a weak algorithm is refused: SHA-1 on the key's certificate.
func TestASHA1SignatureIsRefused(t *testing.T) {
	m := attesttest.NewMaker(t, attesttest.MakerOptions{Now: clock}) // an RSA token key can sign with SHA-1
	b := m.Bundle(t)
	ev := m.PIVEvidence(t, p384(t), attesttest.Slot{
		Tweak: func(c *x509.Certificate) { c.SignatureAlgorithm = x509.SHA1WithRSA },
		Check: attesttest.CheckNone,
	})
	wantRefusal(t, verify(t, b, attest.AppletPIV, ev, clock), handoff.CodeProofInvalid)
}

// A critical extension that the library does not know makes the chain refused, on the key's certificate and
// on a pinned intermediate (record: fail closed). The detail says so in fixed words.
func TestACriticalExtensionThatIsNotKnownIsRefused(t *testing.T) {
	unknown := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7}, Critical: true, Value: []byte{5, 0}}
	m := newMaker(t)
	b := m.Bundle(t)
	d := wantRefusal(t, verify(t, b, attest.AppletPIV, m.PIVEvidence(t, p384(t), attesttest.Slot{
		Tweak: func(c *x509.Certificate) { c.ExtraExtensions = append(c.ExtraExtensions, unknown) },
	}), clock), handoff.CodeProofInvalid)
	if d != "the key's certificate has a critical extension that is not known" {
		t.Errorf("the detail on the key's certificate: %q", d)
	}
	// On an extension that the maker's own slot has (.3.3) marked critical.
	wantRefusal(t, verify(t, b, attest.AppletPIV, m.PIVEvidence(t, p384(t), attesttest.Slot{
		Critical: map[string]bool{attesttest.ExtFirmware: true},
	}), clock), handoff.CodeProofInvalid)

	// On the intermediate that the chain passes.
	mi := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, Now: clock, Tweak: func(role string, c *x509.Certificate) {
		if role == attesttest.RolePIVIntermediate {
			c.ExtraExtensions = append(c.ExtraExtensions, unknown)
		}
	}})
	d = wantRefusal(t, verify(t, mi.Bundle(t), attest.AppletPIV, mi.PIVEvidence(t, p384(t), attesttest.Slot{}), clock), handoff.CodeProofInvalid)
	if d != "a certificate of the chain has a critical extension that is not known" {
		t.Errorf("the detail on the intermediate: %q", d)
	}
	// The openpgp chain does not pass that intermediate; and its pool holds only its own group.
	if err := verify(t, mi.Bundle(t), attest.AppletOpenPGP, mi.OpenPGPEvidence(t, p384(t)), clock); err != nil {
		t.Errorf("a critical extension on the other applet's intermediate: %v", err)
	}
	// The same extension, not critical, is read past.
	nc := unknown
	nc.Critical = false
	if err := verify(t, b, attest.AppletPIV, m.PIVEvidence(t, p384(t), attesttest.Slot{
		Tweak: func(c *x509.Certificate) { c.ExtraExtensions = append(c.ExtraExtensions, nc) },
	}), clock); err != nil {
		t.Errorf("a non-critical unknown extension: %v", err)
	}
}

// An intermediate that does not allow a certificate under the token (path length 0), one that is not allowed
// to sign certificates, and a name constraint that the leaf breaks, all refuse the chain.
func TestTheConstraintsOfTheIntermediatesAreKept(t *testing.T) {
	cases := []struct {
		name  string
		tweak func(c *x509.Certificate)
		slot  attesttest.Slot
		ok    bool
	}{
		{"path length 0 on the intermediate", func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 0, true }, attesttest.Slot{}, false},
		{"path length 1 on the intermediate", func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 1, false }, attesttest.Slot{}, true},
		{"no path length on the intermediate", func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = -1, false }, attesttest.Slot{}, true},
		{"a permitted DNS name that the leaf does not break", func(c *x509.Certificate) {
			c.PermittedDNSDomains, c.PermittedDNSDomainsCritical = []string{"example.org"}, true
		}, attesttest.Slot{}, true},
		{"a permitted DNS name that the leaf breaks", func(c *x509.Certificate) {
			c.PermittedDNSDomains, c.PermittedDNSDomainsCritical = []string{"example.org"}, true
		}, attesttest.Slot{Tweak: func(c *x509.Certificate) { c.DNSNames = []string{"host.other.test"} }}, false},
		{"an excluded DNS name that the leaf breaks", func(c *x509.Certificate) {
			c.ExcludedDNSDomains, c.PermittedDNSDomainsCritical = []string{"other.test"}, true
		}, attesttest.Slot{Tweak: func(c *x509.Certificate) { c.DNSNames = []string{"host.other.test"} }}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, Now: clock, Tweak: func(role string, tmpl *x509.Certificate) {
				if role == attesttest.RolePIVIntermediate {
					c.tweak(tmpl)
				}
			}})
			err := verify(t, m.Bundle(t), attest.AppletPIV, m.PIVEvidence(t, p384(t), c.slot), clock)
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantRefusal(t, err, handoff.CodeProofInvalid)
		})
	}
}

// A pinned intermediate that is not a CA, or a root that is a leaf, cannot be pinned: see the bundle tests.
// A token that is a CA with a key usage that cannot sign is refused: the chain is not the token's.
func TestATokenWhoseKeyUsageCannotSignIsRefused(t *testing.T) {
	m := newMaker(t)
	ev := m.PIVEvidence(t, p384(t), attesttest.Slot{
		TokenTweak: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
		Check:      attesttest.CheckNone,
	})
	wantRefusal(t, verify(t, m.Bundle(t), attest.AppletPIV, ev, clock), handoff.CodeProofInvalid)
}

// The fixed words: every kind of refusal of the chain says which kind in words of this package, and none
// copies a name from a certificate.
func TestEachFaultOfTheChainHasItsFixedWords(t *testing.T) {
	m := newMaker(t)
	b := m.Bundle(t)
	cases := []struct {
		name string
		slot attesttest.Slot
		want string
	}{
		{"unpinned issuer", attesttest.Slot{UnpinnedIssuer: true}, "pinned root"},
		{"not signed by the token", attesttest.Slot{OtherSigner: true}, "not signed by the token"},
		{"expired leaf", attesttest.Slot{Tweak: func(c *x509.Certificate) { c.NotAfter = clock.Add(-time.Hour) }}, "not valid at the time"},
		{"critical", attesttest.Slot{Critical: map[string]bool{attesttest.ExtSerial: true}}, "critical extension"},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := wantRefusal(t, verify(t, b, attest.AppletPIV, m.PIVEvidence(t, p384(t), c.slot), clock), handoff.CodeProofInvalid)
			if !strings.Contains(d, c.want) {
				t.Errorf("the detail %q does not hold %q", d, c.want)
			}
			if seen[d] {
				t.Errorf("two faults have the same words: %q", d)
			}
			seen[d] = true
		})
	}
}
