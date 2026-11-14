package attest_test

import (
	"errors"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
)

// The page gives each card type its own set of intermediates: for piv "the maker's intermediates", for
// openpgp-card "the maker's OpenPGP intermediates". NewBundle keeps the two groups apart, so that a chain
// that ends in one intermediate does not pass for both card types.

// sameKey makes two intermediates under the root that are different certificates of one key.
func sameKey(t testing.TB) (root, first, second *handCA) {
	t.Helper()
	root = handIssue(t, "Example Test Root", handKey(t), nil, true, -1, nil)
	key := handKey(t)
	first = handIssue(t, "Example Test Intermediate One", key, root, true, 1, nil)
	second = handIssue(t, "Example Test Intermediate Two", key, root, true, 1, nil)
	return root, first, second
}

func TestABundleRefusesTheSameIntermediateInBothGroups(t *testing.T) {
	s, m := goodSpec(t)
	other := newMaker(t).Spec()
	extra := m.StrayIntermediate().Raw
	shared := s.PIVIntermediates[0]

	cases := map[string]func(*attest.BundleSpec){
		"the same certificate alone in both groups": func(s *attest.BundleSpec) { s.OpenPGPIntermediates = s.PIVIntermediates },
		"the same certificate, the piv one in the openpgp group": func(s *attest.BundleSpec) {
			s.OpenPGPIntermediates = [][]byte{s.PIVIntermediates[0]}
		},
		"the same certificate, the openpgp one in the piv group": func(s *attest.BundleSpec) {
			s.PIVIntermediates = [][]byte{s.OpenPGPIntermediates[0]}
		},
		"the same certificate at the end of each group": func(s *attest.BundleSpec) {
			s.PIVIntermediates = [][]byte{other.PIVIntermediates[0], extra, shared}
			s.OpenPGPIntermediates = [][]byte{other.OpenPGPIntermediates[0], shared}
		},
		"the same certificate first in the piv group and last in the openpgp group": func(s *attest.BundleSpec) {
			s.PIVIntermediates = [][]byte{shared, extra}
			s.OpenPGPIntermediates = [][]byte{other.OpenPGPIntermediates[0], shared}
		},
		"the same certificate last in the piv group and first in the openpgp group": func(s *attest.BundleSpec) {
			s.PIVIntermediates = [][]byte{extra, shared}
			s.OpenPGPIntermediates = [][]byte{shared, other.OpenPGPIntermediates[0]}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			spec := s
			spec.PIVIntermediates = append([][]byte(nil), s.PIVIntermediates...)
			spec.OpenPGPIntermediates = append([][]byte(nil), s.OpenPGPIntermediates...)
			change(&spec)
			wantBundleError(t, spec)
		})
	}

	// The control: the same certificates in groups that do not share one are a good bundle.
	good := s
	good.PIVIntermediates = [][]byte{extra, s.PIVIntermediates[0]}
	good.OpenPGPIntermediates = [][]byte{other.OpenPGPIntermediates[0], s.OpenPGPIntermediates[0]}
	if _, err := attest.NewBundle(good); err != nil {
		t.Fatalf("groups with no certificate in common: %v", err)
	}
}

func TestABundleRefusesTwoCertificatesOfOneKeyInTheTwoGroups(t *testing.T) {
	root, first, second := sameKey(t)
	spec := func(piv, opgp [][]byte) attest.BundleSpec {
		return attest.BundleSpec{Version: "hand", Roots: [][]byte{root.der}, PIVIntermediates: piv, OpenPGPIntermediates: opgp}
	}
	if string(first.der) == string(second.der) || string(first.cert.RawSubjectPublicKeyInfo) != string(second.cert.RawSubjectPublicKeyInfo) {
		t.Fatal("test setup: two different certificates of one key were not made")
	}
	wantBundleError(t, spec([][]byte{first.der}, [][]byte{second.der}))
	wantBundleError(t, spec([][]byte{second.der}, [][]byte{first.der}))

	// The key is looked for in every certificate of the groups, not in the first ones only.
	stray := handIssue(t, "Example Test Intermediate Three", handKey(t), root, true, 1, nil)
	wantBundleError(t, spec([][]byte{stray.der, first.der}, [][]byte{handIssue(t, "Example Test Intermediate Four", handKey(t), root, true, 1, nil).der, second.der}))

	// Two certificates of one key in one group are fine, and so is each of them with a key of its own in the other.
	if _, err := attest.NewBundle(spec([][]byte{first.der, second.der}, [][]byte{stray.der})); err != nil {
		t.Errorf("two certificates of one key in the piv group: %v", err)
	}
	if _, err := attest.NewBundle(spec([][]byte{stray.der}, [][]byte{first.der, second.der})); err != nil {
		t.Errorf("two certificates of one key in the openpgp group: %v", err)
	}
	if _, err := attest.NewBundle(spec([][]byte{first.der}, [][]byte{stray.der})); err != nil {
		t.Errorf("two intermediates with two keys: %v", err)
	}
}

// The refusal does not tell a certificate apart from a key by its words, and gives no bundle.
func TestTheRefusalOfASharedIntermediateIsAnErrBundle(t *testing.T) {
	s, _ := goodSpec(t)
	s.OpenPGPIntermediates = s.PIVIntermediates
	b, err := attest.NewBundle(s)
	if b != nil || !errors.Is(err, attest.ErrBundle) {
		t.Fatalf("bundle %v, error %v", b, err)
	}
	noLeak(t, err.Error())
}

// The maker can still make a hierarchy with one intermediate for both applets, to test this refusal.
func TestTheMakerSharedIntermediateIsRefusedByNewBundle(t *testing.T) {
	m := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, Now: clock, SharedIntermediate: true})
	wantBundleError(t, m.Spec())
}

// The page: the chain goes "through the token's certificate and the maker's intermediates". A token
// certificate that a pinned root signed directly has no pinned intermediate of the applet above it, and the
// roots are shared by both applets, so the chain does not tell which applet it belongs to.
func TestATokenIssuedDirectlyByAPinnedRootIsRefused(t *testing.T) {
	root := handIssue(t, "Example Test Root", handKey(t), nil, true, -1, nil)
	inter := handIssue(t, "Example Test Intermediate", handKey(t), root, true, 1, nil)
	token := handIssue(t, "Example Test Token", handKey(t), root, true, 0, nil)
	leaf := handIssue(t, "YubiKey PIV Attestation 9c", handKey(t), token, false, 0, nil)
	ev := attesttest.EvidenceJSON(t, leaf.der, token.der)

	// A pinned intermediate of each applet is in the bundle, and the root is pinned. The chain is
	// leaf, token, root: three certificates.
	b, err := attest.NewBundle(attest.BundleSpec{
		Version: "hand", Roots: [][]byte{root.der}, PIVIntermediates: [][]byte{inter.der},
		OpenPGPIntermediates: [][]byte{handIssue(t, "Example Test OpenPGP Intermediate", handKey(t), root, true, 1, nil).der},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []attest.Applet{attest.AppletPIV, attest.AppletOpenPGP} {
		d := wantRefusal(t, verify(t, b, a, ev, clock), handoff.CodeProofInvalid)
		if d != "the chain does not pass through a pinned intermediate of the applet" {
			t.Errorf("applet %v: the detail is %q", a, d)
		}
	}

	// The same token, issued by the pinned intermediate of the applet, passes: the chain has four.
	issued := handIssue(t, "Example Test Token", handKey(t), inter, true, 0, nil)
	leaf2 := handIssue(t, "YubiKey PIV Attestation 9c", handKey(t), issued, false, 0, nil)
	if err := verify(t, b, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf2.der, issued.der), clock); err != nil {
		t.Errorf("a token under the pinned intermediate: %v", err)
	}
	// And it does not pass for the other applet, whose group does not hold that intermediate.
	d := wantRefusal(t, verify(t, b, attest.AppletOpenPGP, attesttest.EvidenceJSON(t, leaf2.der, issued.der), clock), handoff.CodeProofInvalid)
	if d == "the chain does not pass through a pinned intermediate of the applet" {
		t.Errorf("the token under another applet's intermediate has the words of a direct token: %q", d)
	}
}

// A chain with more than one pinned intermediate above the token's certificate has more than four
// certificates and passes: the rule is a floor of four, not a count of four.
func TestAChainOfFiveCertificatesPasses(t *testing.T) {
	root := handIssue(t, "Example Test Root", handKey(t), nil, true, -1, nil)
	upper := handIssue(t, "Example Test Upper", handKey(t), root, true, 2, nil)
	lower := handIssue(t, "Example Test Lower", handKey(t), upper, true, 1, nil)
	token := handIssue(t, "Example Test Token", handKey(t), lower, true, 0, nil)
	leaf := handIssue(t, "YubiKey PIV Attestation 9c", handKey(t), token, false, 0, nil)
	b, err := attest.NewBundle(attest.BundleSpec{Version: "hand", Roots: [][]byte{root.der}, PIVIntermediates: [][]byte{upper.der, lower.der}})
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(t, b, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf.der, token.der), clock); err != nil {
		t.Errorf("a chain of five: %v", err)
	}
}

// When the token's certificate has two chains, a short one that ends in a pinned root of the token's own key
// and a long one through a pinned intermediate, the long one is enough. Here the pinned root and the
// pinned intermediate are two certificates of one key and one name; the intermediate is issued by a second
// pinned root.
func TestOneLongChainThroughTheTokenIsEnoughBesideAShortOne(t *testing.T) {
	key := handKey(t)
	shortRoot := handIssue(t, "Example Test Shared Name", key, nil, true, -1, nil)
	longRoot := handIssue(t, "Example Test Long Root", handKey(t), nil, true, -1, nil)
	inter := handIssue(t, "Example Test Shared Name", key, longRoot, true, 1, nil)
	token := handIssue(t, "Example Test Token", handKey(t), &handCA{cert: shortRoot.cert, key: key}, true, 0, nil)
	leaf := handIssue(t, "YubiKey PIV Attestation 9c", handKey(t), token, false, 0, nil)
	ev := attesttest.EvidenceJSON(t, leaf.der, token.der)

	for _, order := range [][][]byte{{shortRoot.der, longRoot.der}, {longRoot.der, shortRoot.der}} {
		b, err := attest.NewBundle(attest.BundleSpec{Version: "hand", Roots: order, PIVIntermediates: [][]byte{inter.der}})
		if err != nil {
			t.Fatal(err)
		}
		if err := verify(t, b, attest.AppletPIV, ev, clock); err != nil {
			t.Errorf("a long chain beside a short one: %v", err)
		}
		// Without the intermediate only the short chain is left, and it is refused.
		short, err := attest.NewBundle(attest.BundleSpec{Version: "hand", Roots: order})
		if err != nil {
			t.Fatal(err)
		}
		wantRefusal(t, verify(t, short, attest.AppletPIV, ev, clock), handoff.CodeProofInvalid)
	}
}
