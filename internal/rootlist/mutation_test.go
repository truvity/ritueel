package rootlist_test

import (
	"bytes"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

var masks = []byte{0x01, 0x20, 0x80, 0xff}

// TestEveryChangeOfASmallValidPairIsRefused takes a pair that is accepted, and changes its bytes
// one change at a time. The base case must be accepted, and no change of the signed bytes may be.
func TestEveryChangeOfASmallValidPairIsRefused(t *testing.T) {
	b := newBase(t)
	w := b.w
	trust := b.trust(t)
	pair := signed(t, b.cand, w.a)
	accepts(t, rootlist.Verify(pair, trust, now))
	pins := pinsOf(t, w.a.pin, w.b.pin)
	accepts(t, rootlist.Verify(pair, pins, now))

	run := func(cand rootlist.Signed) rootlist.Verdict { return rootlist.Verify(cand, trust, now) }
	checked := 0

	t.Run("one flipped byte of root-list.json is a signature that does not verify", func(t *testing.T) {
		for i := range pair.JSON {
			for _, m := range masks {
				mut := bytes.Clone(pair.JSON)
				mut[i] ^= m
				v := run(rootlist.Signed{JSON: mut, JWS: pair.JWS})
				if v.Accepted || v.Reason != rootlist.SignatureInvalid || v.Check != 3 {
					t.Fatalf("byte %d xor %#x: %+v", i, m, v)
				}
				checked++
			}
		}
	})
	t.Run("root-list.json cut at every length, and with a byte added", func(t *testing.T) {
		for n := range len(pair.JSON) {
			v := run(rootlist.Signed{JSON: pair.JSON[:n], JWS: pair.JWS})
			if v.Accepted || v.Reason != rootlist.SignatureInvalid || v.Check != 3 {
				t.Fatalf("cut to %d: %+v", n, v)
			}
			checked++
		}
		for _, add := range []byte{' ', '\n', 0, 'x', '}'} {
			v := run(rootlist.Signed{JSON: append(bytes.Clone(pair.JSON), add), JWS: pair.JWS})
			if v.Accepted || v.Reason != rootlist.SignatureInvalid || v.Check != 3 {
				t.Fatalf("byte %#x added: %+v", add, v)
			}
		}
		for i := 0; i <= len(pair.JSON); i++ {
			ins := append(append(bytes.Clone(pair.JSON[:i]), ' '), pair.JSON[i:]...)
			if v := run(rootlist.Signed{JSON: ins, JWS: pair.JWS}); v.Accepted {
				t.Fatalf("a space inserted at %d is accepted", i)
			}
		}
	})
	t.Run("one flipped byte of root-list.jws", func(t *testing.T) {
		for i := range pair.JWS {
			for _, m := range masks {
				mut := bytes.Clone(pair.JWS)
				mut[i] ^= m
				v := run(rootlist.Signed{JSON: pair.JSON, JWS: mut})
				if v.Accepted || (v.Reason != rootlist.Malformed && v.Reason != rootlist.SignatureInvalid) {
					t.Fatalf("byte %d xor %#x: %+v", i, m, v)
				}
				checked++
			}
		}
	})
	t.Run("root-list.jws cut at every length, and with a byte added or inserted", func(t *testing.T) {
		for n := range len(pair.JWS) {
			v := run(rootlist.Signed{JSON: pair.JSON, JWS: pair.JWS[:n]})
			refuses(t, v, rootlist.Malformed, 1)
			checked++
		}
		for _, add := range []byte{'x', '}', ',', 0} {
			if v := run(rootlist.Signed{JSON: pair.JSON, JWS: append(bytes.Clone(pair.JWS), add)}); v.Accepted {
				t.Fatalf("byte %#x added to the signature file is accepted", add)
			}
		}
		for i := 0; i <= len(pair.JWS); i++ {
			ins := append(append(bytes.Clone(pair.JWS[:i]), 'A'), pair.JWS[i:]...)
			if v := run(rootlist.Signed{JSON: pair.JSON, JWS: ins}); v.Accepted {
				t.Fatalf("a byte inserted at %d of the signature file is accepted", i)
			}
		}
	})
	t.Run("the pair swapped, and the pair of another list", func(t *testing.T) {
		other := signed(t, listOf(9, w.a, w.b), w.a)
		for name, c := range map[string]rootlist.Signed{
			"the files swapped":         {JSON: pair.JWS, JWS: pair.JSON},
			"json of one, jws of other": {JSON: pair.JSON, JWS: other.JWS},
			"jws of one, json of other": {JSON: other.JSON, JWS: pair.JWS},
			"both empty":                {},
			"the json twice":            {JSON: pair.JSON, JWS: pair.JSON},
			"the jws twice":             {JSON: pair.JWS, JWS: pair.JWS},
		} {
			if v := run(c); v.Accepted {
				t.Errorf("%s: accepted", name)
			}
		}
	})
	if checked == 0 {
		t.Fatal("nothing was checked")
	}
}

// TestEveryChangeOfAVectorPairIsRefused does the same on the pairs of the manifest. The pairs
// change when the vectors are made again; the test does not know their bytes.
func TestEveryChangeOfAVectorPairIsRefused(t *testing.T) {
	m := loadManifest(t)
	checked := 0
	seen := map[string]bool{}
	for _, c := range m.Cases {
		if c.Candidate == nil {
			continue
		}
		// Several cases name one pair of files; the changes of a pair are the same whichever case
		// names it, and are run once for each pair and each kind of outcome.
		key := *c.Candidate + "/" + c.Expect
		if seen[key] {
			continue
		}
		seen[key] = true
		t.Run(c.ID, func(t *testing.T) {
			cand := m.listFiles(t, *c.Candidate)
			trust := m.trustOfCase(t, c)
			clock := m.clockOf(t, c.Clock)
			base := rootlist.Verify(cand, trust, clock)
			// A refusal that is the bundle's has an accepted list.
			if base.Accepted != (c.Expect == "accept" || c.Bundle != "") {
				t.Fatalf("the base case is not what the manifest says: %+v", base)
			}
			// Every byte for a list that is accepted, which is what a forger starts from; every seventh
			// for a list that is refused already, to keep the run short.
			step, cut := 1, 5
			if !base.Accepted {
				step, cut = 11, 17
			}
			for i := 0; i < len(cand.JSON); i += step {
				mut := bytes.Clone(cand.JSON)
				mut[i] ^= 0x01
				v := rootlist.Verify(rootlist.Signed{JSON: mut, JWS: cand.JWS}, trust, clock)
				if v.Accepted {
					t.Fatalf("json byte %d is accepted", i)
				}
				// Whatever refuses a list before its signature is read (check 1, check 2) or at it
				// does so for the same cause as the base case; a change of the signed bytes is 3.
				if base.Check >= 3 || base.Accepted {
					if v.Reason != rootlist.SignatureInvalid || v.Check != 3 {
						t.Fatalf("json byte %d: %+v", i, v)
					}
				}
				checked++
			}
			for i := 0; i < len(cand.JWS); i += 3*step + step/2 {
				mut := bytes.Clone(cand.JWS)
				mut[i] ^= 0x01
				if v := rootlist.Verify(rootlist.Signed{JSON: cand.JSON, JWS: mut}, trust, clock); v.Accepted {
					t.Fatalf("jws byte %d is accepted", i)
				}
				checked++
			}
			for n := 0; n < len(cand.JSON); n += cut {
				if v := rootlist.Verify(rootlist.Signed{JSON: cand.JSON[:n], JWS: cand.JWS}, trust, clock); v.Accepted {
					t.Fatalf("json cut to %d is accepted", n)
				}
			}
			for n := 0; n < len(cand.JWS); n += cut {
				if v := rootlist.Verify(rootlist.Signed{JSON: cand.JSON, JWS: cand.JWS[:n]}, trust, clock); v.Accepted {
					t.Fatalf("jws cut to %d is accepted", n)
				}
			}
		})
	}
	if checked == 0 {
		t.Fatal("nothing was checked")
	}
}
