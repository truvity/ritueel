package handoff_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/trustset"
)

// The checks take as many OpenPGP primaries as a root list has entries: one for each label A to Z. Every list that
// the trust set writer and the reader of root lists accept can then be checked. The tests below hold the bound itself,
// the one more that is refused, and the tie to the bounds of the other packages that cannot move without it.

// The number is written down here: a change of it is deliberate.
const primariesBound = 26

func TestTheBoundOfPrimariesIsTheNumberOfEntriesOfARootList(t *testing.T) {
	if handoff.MaxPrimaries != primariesBound {
		t.Errorf("MaxPrimaries = %d, want %d", handoff.MaxPrimaries, primariesBound)
	}
	for name, other := range map[string]int{
		"trustset.MaxRoots":                trustset.MaxRoots,
		"history.MaxRootsPerList":          history.MaxRootsPerList,
		"openpgp.MaxKeyringCertificates":   openpgp.MaxKeyringCertificates,
		"the letters A to Z (one a label)": 'Z' - 'A' + 1,
	} {
		if handoff.MaxPrimaries != other {
			t.Errorf("MaxPrimaries = %d and %s = %d: the bound of the checks is not the size of a root list", handoff.MaxPrimaries, name, other)
		}
	}
}

// A subkey file with n packets after the subkey and a proof that lists n primaries: at the bound it is whole and
// accepted, one more is malformed at check 2, before any signature is read and whatever the digest says.
func TestASubkeyFileWithOneBackSignatureForEachOfTheMostPrimariesIsAcceptedAndOneMoreIsMalformed(t *testing.T) {
	f := newPGPFixture(t, handoff.MaxPrimaries, handoff.StoreSoftware)
	v := f.mustAccept(f.checker(nil))
	if v.Subkey == nil || len(f.sigs) != handoff.MaxPrimaries {
		t.Fatalf("setup: %d back-signatures", len(f.sigs))
	}
	for _, extra := range []int{1, 2, 10, 500} {
		for _, digest := range []string{"", digestHex([]byte("not this file"))} {
			t.Run(fmt.Sprintf("%d packets after the subkey/digest %q", handoff.MaxPrimaries+extra, digest), func(t *testing.T) {
				g := newPGPFixture(t, 2, handoff.StoreSoftware)
				g.primaries, g.sub, g.subPacket, g.sigs = f.primaries, f.sub, f.subPacket, slices.Clone(f.sigs)
				for len(g.sigs) < handoff.MaxPrimaries+extra {
					g.sigs = append(g.sigs, f.sigs[0])
				}
				g.digest = digest
				v, err := g.checker(nil).Check(t.Context(), g.request())
				wantRefusal(t, v, err, handoff.CodeMalformed, 2)
				if got := statuses(v); got != "pfnnnnnnn" {
					t.Errorf("statuses %s, want pfnnnnnnn", got)
				}
				if v.Detail == "" || !plain(v.Detail) {
					t.Errorf("detail %q", v.Detail)
				}
			})
		}
	}
}

// At the bound check 2 passes for a file that is not good in some other way: here the packets are the right number
// and the signatures are not for the primaries, so check 5 refuses, and never check 2.
func TestAFileOfTheMostPacketsPassesCheckTwoAndIsJudgedAtCheckFive(t *testing.T) {
	f := newPGPFixture(t, handoff.MaxPrimaries, handoff.StoreSoftware)
	g := newPGPFixture(t, 2, handoff.StoreSoftware)
	g.primaries, g.sub, g.subPacket = f.primaries, f.sub, f.subPacket
	g.sigs = nil
	for range handoff.MaxPrimaries {
		g.sigs = append(g.sigs, f.sigs[0])
	}
	v, err := g.checker(nil).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
}

// The proof file: the most fingerprints are read, in the order of the file, and one more is malformed with a
// sentence that names the bound. The count is judged before the fingerprints are: more than the bound of one
// fingerprint repeated is the count and not the repeat.
func TestAProofOfTheMostPrimariesIsReadAndOneMoreIsRefusedWithTheBoundInTheSentence(t *testing.T) {
	proofOf := func(list []string) []byte {
		pf := newPGPFixture(t, 2, handoff.StoreSoftware)
		pf.edit(func(m map[string]any) { m["primaries"] = list })
		return pf.request().Files[handoff.FileProof]
	}
	for _, n := range []int{1, 17, 20, handoff.MaxPrimaries} {
		list := fingerprints(n)
		p, err := handoff.ReadProof(proofOf(list))
		if err != nil || p == nil || !slices.Equal(p.Primaries, list) {
			t.Errorf("%d fingerprints: (%v, %v)", n, p, err)
		}
	}
	bound := fmt.Sprintf("primaries holds more than %d fingerprints", handoff.MaxPrimaries)
	for name, list := range map[string][]string{
		"one more":                            fingerprints(handoff.MaxPrimaries + 1),
		"two more":                            fingerprints(handoff.MaxPrimaries + 2),
		"one fingerprint repeated over bound": slices.Repeat(fingerprints(1), handoff.MaxPrimaries+1),
	} {
		p, err := handoff.ReadProof(proofOf(list))
		if p != nil || !errors.Is(err, handoff.ErrProofShape) || !strings.Contains(err.Error(), bound) {
			t.Errorf("%s: (%v, %v), want ErrProofShape that says %q", name, p, err, bound)
		}
	}
	// At the bound a repeat is the repeat.
	twice := append(fingerprints(handoff.MaxPrimaries-1), fingerprints(1)[0])
	if _, err := handoff.ReadProof(proofOf(twice)); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a repeat at the bound: %v", err)
	}
}

// A checker with the most primaries is made, with one more it is not; the count is of the configuration and no
// primary is read for it.
func TestACheckerIsMadeForTheMostPrimariesAndNotForOneMore(t *testing.T) {
	f := newPGPFixture(t, handoff.MaxPrimaries, handoff.StoreSoftware)
	if _, err := handoff.New(f.config(nil)); err != nil {
		t.Fatalf("%d primaries: %v", handoff.MaxPrimaries, err)
	}
	over := newPGPFixture(t, handoff.MaxPrimaries+1, handoff.StoreSoftware)
	_, err := handoff.New(over.config(nil))
	if !errors.Is(err, handoff.ErrConfig) || !strings.Contains(err.Error(), fmt.Sprintf("more than %d primaries", handoff.MaxPrimaries)) {
		t.Errorf("%d primaries: %v, want ErrConfig that names the bound", handoff.MaxPrimaries+1, err)
	}
	// With no delegation the primaries are still counted.
	_, err = handoff.New(over.config(func(c *handoff.Config) { c.Delegation = nil }))
	if !errors.Is(err, handoff.ErrConfig) {
		t.Errorf("%d primaries and no delegation: %v", handoff.MaxPrimaries+1, err)
	}
}

// Every size from one up to the bound is judged the same way: a request that fits is accepted, and a request
// whose primaries are not the list's is refused at check 3 with unknown-primary, whatever the count.
func TestTheVerdictDoesNotDependOnHowManyPrimariesThereAreUpToTheBound(t *testing.T) {
	for _, n := range []int{2, 16, 17, 20, handoff.MaxPrimaries} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			f := newPGPFixture(t, n, handoff.StoreSoftware)
			f.mustAccept(f.checker(nil))
			// One primary of the list is not the one the proof names: check 3.
			g := newPGPFixture(t, 2, handoff.StoreSoftware)
			g.primaries, g.sub, g.subPacket, g.sigs = f.primaries, f.sub, f.subPacket, f.sigs
			list := slices.Clone(f.fingerprints())
			list[n-1] = newPGPKey(t, pgpPrimaryCreated).fingerprint()
			g.listed = list
			v, err := g.checker(nil).Check(t.Context(), g.request())
			wantRefusal(t, v, err, handoff.CodeUnknownPrimary, 3)
			// One primary left out of the proof: check 3 as well.
			h := newPGPFixture(t, 2, handoff.StoreSoftware)
			h.primaries, h.sub, h.subPacket, h.sigs = f.primaries, f.sub, f.subPacket, f.sigs
			h.listed = f.fingerprints()[:n-1]
			v, err = h.checker(nil).Check(t.Context(), h.request())
			if err != nil || !v.Refused() {
				t.Fatalf("a primary left out: (%+v, %v)", v, err)
			}
		})
	}
}

// FuzzReadProofOfManyPrimaries gives ReadProof proofs that list from one to a hundred fingerprints, and their
// mutations. A proof that is read lists at most the bound of fingerprints, each 40 lower-case hexadecimal digits
// and none twice, and a proof that is refused is an ErrProofShape and no proof.
func FuzzReadProofOfManyPrimaries(f *testing.F) {
	for _, n := range []int{1, 2, 16, 17, 20, handoff.MaxPrimaries - 1, handoff.MaxPrimaries, handoff.MaxPrimaries + 1, 100} {
		pf := newPGPFixture(f, 2, handoff.StoreSoftware)
		pf.edit(func(m map[string]any) { m["primaries"] = fingerprints(n) })
		f.Add(pf.request().Files[handoff.FileProof])
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := handoff.ReadProof(data)
		if err != nil {
			if p != nil || !errors.Is(err, handoff.ErrProofShape) {
				t.Fatalf("a refusal that is not one: (%v, %v)", p, err)
			}
			return
		}
		if p.Type != handoff.TypeOpenPGP {
			return
		}
		if len(p.Primaries) == 0 || len(p.Primaries) > handoff.MaxPrimaries {
			t.Fatalf("%d primaries", len(p.Primaries))
		}
		seen := map[string]bool{}
		for _, fp := range p.Primaries {
			if len(fp) != 40 || strings.Trim(fp, "0123456789abcdef") != "" || seen[fp] {
				t.Fatalf("the fingerprint %q in %v", fp, p.Primaries)
			}
			seen[fp] = true
		}
	})
}

// FuzzCheckOpenPGPOfTheMostPrimaries runs the checks on the proof and the subkey file of a request for the most
// primaries, and their mutations. Whatever the bytes, the laws of every verdict hold, and a verdict that accepts a file
// accepts one that has one back-signature for each of the primaries and no more.
func FuzzCheckOpenPGPOfTheMostPrimaries(f *testing.F) {
	good := newPGPFixture(f, handoff.MaxPrimaries, handoff.StoreSoftware)
	r := good.request()
	f.Add(r.Files[handoff.FileProof], r.Files[handoff.FileSubkey])
	longer := newPGPFixture(f, 2, handoff.StoreSoftware)
	longer.primaries, longer.sub, longer.subPacket = good.primaries, good.sub, good.subPacket
	longer.sigs = append(slices.Clone(good.sigs), good.sigs[0])
	f.Add(r.Files[handoff.FileProof], longer.fileBytes())
	f.Add(r.Files[handoff.FileProof], good.fileBytes()[:len(good.fileBytes())-1])
	f.Add([]byte(`{"handoff":1}`), []byte(nil))
	chk := good.checker(nil)
	f.Fuzz(func(t *testing.T, proof, subkey []byte) {
		req := requestOf(proof, nil, subkey, nil)
		v, err := chk.Check(t.Context(), req)
		checkVerdictLaws(t, req, v, err)
		if err == nil && v.Accepted() {
			_, sigs, serr := openpgp.SplitSubkeyFile(subkey, handoff.MaxPrimaries)
			if serr != nil || len(sigs) != handoff.MaxPrimaries {
				t.Fatalf("accepted a file with %d packets after the subkey (%v)", len(sigs), serr)
			}
		}
	})
}
