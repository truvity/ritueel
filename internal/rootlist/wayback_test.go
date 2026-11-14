package rootlist_test

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

// The way back (record 0006, rule 53). These tests make their own keys and lists, so that every
// sentence of the rule that accepts or refuses something has a test that names it. The lists of the
// vectors are run by TestManifestCases.
//
// The host holds a list of A and B at sequence 7, unless a test says another. "B without A" is the
// list that drops A, names A in removals with A's stored authorisation, and is signed by B.

const highestSequence = "9007199254740991" // 2^53 - 1, the largest sequence of the JSON rules

// atSequence returns the list with another sequence, written as text so that it can be the largest.
func atSequence(s spec, seq string) spec {
	s.sequence = seq
	return s
}

// bWithoutA is the list that removes A and names it, at sequence seq.
func bWithoutA(t testing.TB, w *world, seq int) spec {
	t.Helper()
	return listOf(seq, w.b).withRemovals(removalOf(t, w.a))
}

// heldAtMax is the host of the thief: it holds a list of A and B at the highest sequence.
func heldAtMax(t testing.TB, w *world) rootlist.Trust {
	t.Helper()
	return heldOf(t, atSequence(listOf(1, w.a, w.b), highestSequence))
}

// heldFrom is the trust of a host that took the accepted list: it holds it from then on.
func heldFrom(t testing.TB, s spec) rootlist.Trust {
	t.Helper()
	return heldOf(t, s)
}

func TestWayBackASequenceBelowTheHeldOneIsTaken(t *testing.T) {
	// Rule 53, first sentence: a list that removes a root key of the held list and names it is taken
	// without check 6, so it is not refused as a rollback.
	w := newWorld(t)
	held := heldOf(t, listOf(7, w.a, w.b))
	for _, seq := range []int{6, 5, 3, 1} {
		t.Run("sequence "+strconv.Itoa(seq), func(t *testing.T) {
			v := rootlist.Verify(signed(t, bWithoutA(t, w, seq), w.b), held, now)
			acceptsWayback(t, v)
			if v.List.Sequence != int64(seq) {
				t.Errorf("the accepted list has the sequence %d, want %d", v.List.Sequence, seq)
			}
		})
	}
	t.Run("from the highest sequence", func(t *testing.T) {
		v := rootlist.Verify(signed(t, bWithoutA(t, w, 8), w.b), heldAtMax(t, w), now)
		acceptsWayback(t, v)
	})
	t.Run("one below the held sequence", func(t *testing.T) {
		v := rootlist.Verify(signed(t, bWithoutA(t, w, 6), w.b), held, now)
		acceptsWayback(t, v)
	})
}

func TestWayBackTheSameSequenceWithOtherContentIsTaken(t *testing.T) {
	// Rule 53: a list at the held sequence with other content, with an entry for every key it
	// removes, is taken without check 7. The vector of a thief at the same sequence.
	w := newWorld(t)
	t.Run("one key removed and named", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b))
		acceptsWayback(t, rootlist.Verify(signed(t, bWithoutA(t, w, 7), w.b), held, now))
	})
	t.Run("every removed key named, a full set of entries", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b, w.c))
		cand := listOf(7, w.c).withRemovals(removalOf(t, w.a), removalOf(t, w.b))
		v := rootlist.Verify(signed(t, cand, w.c), held, now)
		acceptsWayback(t, v)
		if v.List.Sequence != 7 {
			t.Errorf("the accepted list has the sequence %d, want the held one, 7", v.List.Sequence)
		}
	})
	t.Run("at the highest sequence", func(t *testing.T) {
		cand := atSequence(bWithoutA(t, w, 1), highestSequence)
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.b), heldAtMax(t, w), now))
	})
	t.Run("the same sequence with other content and no entry is a conflict", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b))
		refuses(t, rootlist.Verify(signed(t, listOf(7, w.b), w.a, w.b), held, now), rootlist.SequenceConflict, 7)
	})
}

func TestWayBackTheSameListAgainIsNotAWayBack(t *testing.T) {
	// Rule 53 and record 0006, rule 21: the held list again is accepted and says Again; it removes
	// nothing from itself, so it never says Wayback, also when it carries entries of its own.
	w := newWorld(t)
	for name, held := range map[string]spec{
		"a list with no removals":        listOf(7, w.a, w.b),
		"a list that carries an entry":   bWithoutA(t, w, 8),
		"a list at the highest sequence": atSequence(bWithoutA(t, w, 1), highestSequence),
	} {
		t.Run(name, func(t *testing.T) {
			data := held.json()
			trust := heldOf(t, held)
			acceptsAgain(t, rootlist.Verify(rootlist.Signed{JSON: data, JWS: sign(t, data, w.b)}, trust, now))
			// With the signature of a key that left, and of one that stays.
			if len(held.roots) == 2 {
				acceptsAgain(t, rootlist.Verify(rootlist.Signed{JSON: data, JWS: sign(t, data, w.a, w.b)}, trust, now))
			}
		})
	}
	t.Run("the held list again after a way back", func(t *testing.T) {
		wb := bWithoutA(t, w, 3)
		accepted := rootlist.Verify(signed(t, wb, w.b), heldOf(t, listOf(7, w.a, w.b)), now)
		acceptsWayback(t, accepted)
		again := rootlist.Verify(signed(t, wb, w.b), heldFrom(t, wb), now)
		acceptsAgain(t, again)
	})
}

func TestWayBackAHigherSequenceWithEntriesIsNotAWayBack(t *testing.T) {
	// Rule 53 and the page: Wayback is true only when check 6 or 7 would have refused the list. A
	// list that names a removed key at a higher sequence is accepted as it always was.
	w := newWorld(t)
	held := heldOf(t, listOf(7, w.a, w.b))
	for _, seq := range []int{8, 9, 100} {
		t.Run("sequence "+strconv.Itoa(seq), func(t *testing.T) {
			v := rootlist.Verify(signed(t, bWithoutA(t, w, seq), w.b), held, now)
			accepts(t, v)
			if v.List.Sequence != int64(seq) {
				t.Errorf("the sequence is %d, want %d", v.List.Sequence, seq)
			}
		})
	}
	t.Run("two keys removed and both named", func(t *testing.T) {
		h := heldOf(t, listOf(7, w.a, w.b, w.c))
		cand := listOf(8, w.c).withRemovals(removalOf(t, w.a), removalOf(t, w.b))
		accepts(t, rootlist.Verify(signed(t, cand, w.c), h, now))
	})
	t.Run("the highest sequence over the highest below it", func(t *testing.T) {
		h := heldOf(t, atSequence(listOf(1, w.a, w.b), "9007199254740990"))
		cand := atSequence(bWithoutA(t, w, 1), highestSequence)
		accepts(t, rootlist.Verify(signed(t, cand, w.b), h, now))
	})
	t.Run("a list that removes a key with no entry and signs for it", func(t *testing.T) {
		// A retire at a higher sequence needs no entry and does not use the way back.
		accepts(t, rootlist.Verify(signed(t, listOf(8, w.b), w.a, w.b), held, now))
	})
}

func TestWayBackTwoKeysRemovedAndOneNamedIsARollback(t *testing.T) {
	// Rule 53: an entry for every root key the list removes. One unnamed key is enough to leave the
	// way back, and the list is refused by check 6, or by check 7 at the held sequence.
	w := newWorld(t)
	held := heldAtMax(t, w)
	heldABC := heldOf(t, atSequence(listOf(1, w.a, w.b, w.c), highestSequence))
	t.Run("A named, B not", func(t *testing.T) {
		cand := listOf(8, w.c).withRemovals(removalOf(t, w.a))
		refuses(t, rootlist.Verify(signed(t, cand, w.b, w.c), heldABC, now), rootlist.Rollback, 6)
	})
	t.Run("B named, A not", func(t *testing.T) {
		cand := listOf(8, w.c).withRemovals(removalOf(t, w.b))
		refuses(t, rootlist.Verify(signed(t, cand, w.a, w.c), heldABC, now), rootlist.Rollback, 6)
	})
	t.Run("signed by every key that could make it pass the later checks", func(t *testing.T) {
		cand := listOf(8, w.c).withRemovals(removalOf(t, w.a))
		refuses(t, rootlist.Verify(signed(t, cand, w.a, w.b, w.c), heldABC, now), rootlist.Rollback, 6)
	})
	t.Run("at the held sequence it is a conflict", func(t *testing.T) {
		h := heldOf(t, listOf(7, w.a, w.b, w.c))
		cand := listOf(7, w.c).withRemovals(removalOf(t, w.a))
		refuses(t, rootlist.Verify(signed(t, cand, w.b, w.c), h, now), rootlist.SequenceConflict, 7)
	})
	t.Run("at a higher sequence the ordinary checks decide", func(t *testing.T) {
		// B has signed, so the list is a change that every current key signed or has named.
		h := heldOf(t, listOf(7, w.a, w.b, w.c))
		cand := listOf(8, w.c).withRemovals(removalOf(t, w.a))
		accepts(t, rootlist.Verify(signed(t, cand, w.b, w.c), h, now))
		refuses(t, rootlist.Verify(signed(t, cand, w.c), h, now), rootlist.InsufficientSigners, 10)
	})
	t.Run("an entry for a key that is on no list does not stand in for the removed key", func(t *testing.T) {
		cand := listOf(8, w.b).withRemovals(removalOf(t, w.z))
		refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.Rollback, 6)
	})
	t.Run("a key removed and no entry at all", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, listOf(8, w.b), w.a, w.b), held, now), rootlist.Rollback, 6)
	})
}

func TestWayBackAnEntryForAKeyThatIsNotOnTheHeldListIsRemovalInvalid(t *testing.T) {
	// Rule 53: the list removes A and names it, and has one more entry, for Z, which is not on the
	// held list. The list is in the way back and check 9 judges the entry: removal-invalid.
	w := newWorld(t)
	for name, seq := range map[string]int{"below": 3, "equal": 7} {
		t.Run(name, func(t *testing.T) {
			held := heldOf(t, listOf(7, w.a, w.b))
			cand := listOf(seq, w.b).withRemovals(removalOf(t, w.a), removalOf(t, w.z))
			refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.RemovalInvalid, 9)
		})
	}
	t.Run("the entry for the key that is not held comes first", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b))
		cand := listOf(3, w.b).withRemovals(removalOf(t, w.z), removalOf(t, w.a))
		refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.RemovalInvalid, 9)
	})
	t.Run("an entry for a key that stays", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b, w.c))
		cand := listOf(3, w.b, w.c).withRemovals(removalOf(t, w.a), removalOf(t, w.b))
		refuses(t, rootlist.Verify(signed(t, cand, w.b, w.c), held, now), rootlist.RemovalInvalid, 9)
	})
	t.Run("an entry for a key the list adds", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b))
		cand := listOf(3, w.b, w.c).withRemovals(removalOf(t, w.a), removalOf(t, w.c))
		refuses(t, rootlist.Verify(signed(t, cand, w.b, w.c), held, now), rootlist.RemovalInvalid, 9)
	})
	t.Run("an entry for a key that is not held and nothing removed is a rollback", func(t *testing.T) {
		// The list removes nothing, so the way back does not apply and check 6 refuses it first.
		held := heldOf(t, listOf(7, w.a, w.b))
		cand := listOf(3, w.a, w.b).withRemovals(removalOf(t, w.z))
		refuses(t, rootlist.Verify(signed(t, cand, w.a), held, now), rootlist.Rollback, 6)
	})
}

func TestWayBackAnAuthorisationThatIsNotValidIsRemovalInvalidAndNeverRollback(t *testing.T) {
	// Rule 53: whether the authorisation in an entry is valid is judged by check 9, so a list that
	// names a key with a bad authorisation gives removal-invalid at every sequence, below the held
	// one, at it and above it.
	w := newWorld(t)
	good := authorisation(t, w.a)
	bad := map[string]string{
		"the authorisation of another root key":   authorisation(t, w.b),
		"the authorisation of a key on no list":   authorisation(t, w.z),
		"text that is no authorisation":           "not a jws",
		"the authorisation cut short":             good[:len(good)-1],
		"a line feed after the authorisation":     good + `\n`,
		"a signature of another key":              authWith(t, w.b, goodHeader(w.a, typRemoval), removalPayload(w.a.pin)),
		"a payload that names another key":        authWith(t, w.a, goodHeader(w.a, typRemoval), removalPayload(w.b.pin)),
		"the type of a list":                      authWith(t, w.a, goodHeader(w.a, typList), removalPayload(w.a.pin)),
		"the authorisation of the key that signs": authorisation(t, w.b),
	}
	for name, auth := range bad {
		for seqName, seq := range map[string]int{"below the held sequence": 3, "at the held sequence": 7, "above the held sequence": 8} {
			t.Run(name+", "+seqName, func(t *testing.T) {
				held := heldOf(t, listOf(7, w.a, w.b))
				cand := listOf(seq, w.b).withRemovals(removalSpec{label: "A", pin: w.a.pin, auth: auth})
				refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.RemovalInvalid, 9)
			})
		}
	}
	t.Run("the good authorisation is the witness", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b))
		cand := listOf(3, w.b).withRemovals(removalSpec{label: "A", pin: w.a.pin, auth: good})
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.b), held, now))
	})
	t.Run("one good entry and one bad one, whichever comes first", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b, w.c))
		goodA := removalOf(t, w.a)
		badB := removalSpec{label: "B", pin: w.b.pin, auth: authorisation(t, w.a)}
		for _, entries := range [][]removalSpec{{goodA, badB}, {badB, goodA}} {
			cand := listOf(3, w.c).withRemovals(entries...)
			refuses(t, rootlist.Verify(signed(t, cand, w.c), held, now), rootlist.RemovalInvalid, 9)
		}
	})
}

func TestWayBackRemovalsCountedByTheirPinInRootsAndNotByLabel(t *testing.T) {
	// Rule 53: a root key is removed when its pin is on the roots of the held list and not on the
	// roots of the new list. The entries of removals do not count as being on the new list, and
	// labels and fingerprints are not compared.
	w := newWorld(t)
	held := heldOf(t, listOf(7, w.a, w.b))
	t.Run("a key that is only in removals is removed", func(t *testing.T) {
		acceptsWayback(t, rootlist.Verify(signed(t, bWithoutA(t, w, 3), w.b), held, now))
	})
	t.Run("a key that is in roots and in removals is not removed", func(t *testing.T) {
		// Nothing is removed, so the way back does not apply and check 6 refuses the list.
		cand := listOf(3, w.a, w.b).withRemovals(removalOf(t, w.a))
		refuses(t, rootlist.Verify(signed(t, cand, w.a, w.b), held, now), rootlist.Rollback, 6)
	})
	t.Run("a relabelled key that stays removes nothing", func(t *testing.T) {
		relabelled := listOf(3, w.a, w.b)
		relabelled.roots[1].label = "D"
		refuses(t, rootlist.Verify(signed(t, relabelled, w.a, w.b), held, now), rootlist.Rollback, 6)
		same := relabelled
		same.sequence = "7"
		refuses(t, rootlist.Verify(signed(t, same, w.a, w.b), held, now), rootlist.SequenceConflict, 7)
	})
	t.Run("a relabelled key that stays beside a removed key", func(t *testing.T) {
		cand := bWithoutA(t, w, 3)
		cand.roots[0].label = "D"
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.b), held, now))
	})
	t.Run("an entry that carries another label than the root had", func(t *testing.T) {
		cand := bWithoutA(t, w, 3)
		cand.removals[0].label = "D"
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.b), held, now))
	})
	t.Run("the labels of the two keys swapped", func(t *testing.T) {
		// B's key under A's label, and the entry of A's key under B's label: the pins decide.
		cand := listOf(3, w.b).withRemovals(removalOf(t, w.a))
		cand.roots[0].label = "A"
		cand.removals[0].label = "B"
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.b), held, now))
	})
	t.Run("another fingerprint of a kept key", func(t *testing.T) {
		cand := bWithoutA(t, w, 3)
		cand.roots[0].fp = w.z.fp()
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.b), held, now))
	})
	t.Run("another fingerprint of a kept key removes nothing", func(t *testing.T) {
		cand := listOf(3, w.a, w.b)
		cand.roots[1].fp = w.z.fp()
		refuses(t, rootlist.Verify(signed(t, cand, w.a, w.b), held, now), rootlist.Rollback, 6)
	})
	t.Run("no fingerprint on a kept key", func(t *testing.T) {
		cand := bWithoutA(t, w, 3)
		cand.roots[0].noFP = true
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.b), held, now))
	})
	t.Run("the fingerprint of the removed key on a key that is added", func(t *testing.T) {
		// Fingerprints are not compared: C carries A's fingerprint and is a key that is added.
		cand := listOf(3, w.b, w.c).withRemovals(removalOf(t, w.a))
		cand.roots[1].fp = w.a.fp()
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.b, w.c), held, now))
	})
}

func TestWayBackPinsAreComparedAsWritten(t *testing.T) {
	// Rule 53: pins are compared as written, and a pin is 64 lower-case hexadecimal digits (check 5).
	// An entry whose pin is the held key's pin in upper case is no entry for that key: the list is
	// refused by check 5, before the way back is decided.
	w := newWorld(t)
	held := heldOf(t, listOf(7, w.a, w.b))
	t.Run("an entry with its pin in upper case", func(t *testing.T) {
		cand := listOf(3, w.b).withRemovals(removalSpec{label: "A", pin: strings.ToUpper(w.a.pin), auth: authorisation(t, w.a)})
		refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.Malformed, 5)
	})
	t.Run("a kept root with its pin in upper case", func(t *testing.T) {
		cand := bWithoutA(t, w, 3)
		cand.roots[0].pin = strings.ToUpper(w.b.pin)
		refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.Malformed, 5)
	})
	t.Run("an entry with its pin one digit short", func(t *testing.T) {
		cand := listOf(3, w.b).withRemovals(removalSpec{label: "A", pin: w.a.pin[1:], auth: authorisation(t, w.a)})
		refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.Malformed, 5)
	})
	t.Run("the same pin twice in removals", func(t *testing.T) {
		for name, seq := range map[string]int{"below": 3, "equal": 7, "above": 8} {
			t.Run(name, func(t *testing.T) {
				cand := listOf(seq, w.b).withRemovals(removalOf(t, w.a), removalOf(t, w.a))
				refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.Malformed, 5)
			})
		}
	})
	t.Run("the same pin twice in removals under two labels", func(t *testing.T) {
		second := removalOf(t, w.a)
		second.label = "D"
		cand := listOf(3, w.b).withRemovals(removalOf(t, w.a), second)
		refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.Malformed, 5)
	})
}

func TestWayBackTheOtherChecksRunAndTheFirstThatFailsGivesTheCode(t *testing.T) {
	// Rule 53: checks 1 to 5 and 8 to 11 run as for every list. Each defect below is in a list that
	// the way back would take, at a sequence below the held one.
	w := newWorld(t)
	held := heldOf(t, listOf(7, w.a, w.b))
	good := bWithoutA(t, w, 3)
	goodJSON := good.json()
	t.Run("the witness", func(t *testing.T) {
		acceptsWayback(t, rootlist.Verify(signed(t, good, w.b), held, now))
	})
	for _, c := range []struct {
		name   string
		cand   func(t *testing.T) rootlist.Signed
		reason rootlist.Reason
		check  int
	}{
		{"1: no signature file", func(t *testing.T) rootlist.Signed { return rootlist.Signed{JSON: goodJSON} }, rootlist.Malformed, 1},
		{"1: a signature file that is not a JWS", func(t *testing.T) rootlist.Signed {
			return rootlist.Signed{JSON: goodJSON, JWS: []byte("{}")}
		}, rootlist.Malformed, 1},
		{"2: signed by a key on no list", func(t *testing.T) rootlist.Signed { return signed(t, good, w.z) }, rootlist.UnknownSigner, 2},
		{"2: signed only by the key that is added", func(t *testing.T) rootlist.Signed {
			return signed(t, listOf(3, w.b, w.c).withRemovals(removalOf(t, w.a)), w.c)
		}, rootlist.UnknownSigner, 2},
		{"3: a byte changed after signing", func(t *testing.T) rootlist.Signed {
			return rootlist.Signed{JSON: append(append([]byte{}, goodJSON...), ' '), JWS: sign(t, goodJSON, w.b)}
		}, rootlist.SignatureInvalid, 3},
		{"4: version 2", func(t *testing.T) rootlist.Signed {
			return signedBytes(t, replace(t, goodJSON, `"version":1`, `"version":2`), w.b)
		}, rootlist.VersionUnsupported, 4},
		{"5: a member the page does not know", func(t *testing.T) rootlist.Signed {
			return signedBytes(t, replace(t, goodJSON, `"version":1`, `"version":1,"x":1`), w.b)
		}, rootlist.Malformed, 5},
		{"5: an expiry that is not 13 months after signing", func(t *testing.T) rootlist.Signed {
			s := good
			s.expiresAt = `"2027-11-15T12:00:00Z"`
			return signed(t, s, w.b)
		}, rootlist.Malformed, 5},
		{"5: signed after the clock", func(t *testing.T) rootlist.Signed {
			return signed(t, good.at("2026-12-02T12:00:00Z"), w.b)
		}, rootlist.Malformed, 5},
		{"8: a second signer on no list", func(t *testing.T) rootlist.Signed { return signed(t, good, w.b, w.z) }, rootlist.UnknownSigner, 8},
		{"9: another key's authorisation", func(t *testing.T) rootlist.Signed {
			return signed(t, listOf(3, w.b).withRemovals(removalSpec{label: "A", pin: w.a.pin, auth: authorisation(t, w.b)}), w.b)
		}, rootlist.RemovalInvalid, 9},
		{"10: the kept key does not sign", func(t *testing.T) rootlist.Signed {
			return signed(t, listOf(3, w.b, w.c).withRemovals(removalOf(t, w.a)), w.c, w.a)
		}, rootlist.InsufficientSigners, 10},
		{"10: the added key does not sign", func(t *testing.T) rootlist.Signed {
			return signed(t, listOf(3, w.b, w.c).withRemovals(removalOf(t, w.a)), w.b)
		}, rootlist.InsufficientSigners, 10},
		{"11: the list has expired", func(t *testing.T) rootlist.Signed { return signed(t, good.at(longAgo), w.b) }, rootlist.Expired, 11},
	} {
		t.Run(c.name, func(t *testing.T) {
			refuses(t, rootlist.Verify(c.cand(t), held, now), c.reason, c.check)
			if got := rootlist.Checks()[c.check-1]; got.N != c.check || got.Reason != c.reason {
				t.Errorf("check %d gives %q, the test expects %q", c.check, got.Reason, c.reason)
			}
		})
	}
	t.Run("the same defects at the held sequence", func(t *testing.T) {
		atHeld := bWithoutA(t, w, 7)
		refuses(t, rootlist.Verify(signed(t, atHeld, w.z), held, now), rootlist.UnknownSigner, 2)
		refuses(t, rootlist.Verify(signed(t, atHeld, w.b, w.z), held, now), rootlist.UnknownSigner, 8)
		refuses(t, rootlist.Verify(signed(t, atHeld.at(longAgo), w.b), held, now), rootlist.Expired, 11)
		refuses(t, rootlist.Verify(signed(t, listOf(7, w.b, w.c).withRemovals(removalOf(t, w.a)), w.b), held, now), rootlist.InsufficientSigners, 10)
	})
}

func TestWayBackTheFirstCheckThatFailsGivesTheCode(t *testing.T) {
	// Rule 53: when two checks would fail, the earlier one gives the code, and the order of the
	// checks is the page's: 2, 3, 4, 5, 8, 9, 10, 11.
	w := newWorld(t)
	held := heldOf(t, listOf(7, w.a, w.b, w.c))
	badAuth := removalSpec{label: "A", pin: w.a.pin, auth: authorisation(t, w.b)}
	t.Run("check 9 before check 10", func(t *testing.T) {
		// A's entry is not valid and the kept key C does not sign.
		cand := listOf(3, w.b, w.c).withRemovals(badAuth)
		refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.RemovalInvalid, 9)
	})
	t.Run("check 8 before check 9", func(t *testing.T) {
		cand := listOf(3, w.b, w.c).withRemovals(badAuth)
		refuses(t, rootlist.Verify(signed(t, cand, w.b, w.c, w.z), held, now), rootlist.UnknownSigner, 8)
	})
	t.Run("check 10 before check 11", func(t *testing.T) {
		cand := listOf(3, w.b, w.c).withRemovals(removalOf(t, w.a)).at(longAgo)
		refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.InsufficientSigners, 10)
	})
	t.Run("check 9 before check 11", func(t *testing.T) {
		cand := listOf(3, w.b, w.c).withRemovals(badAuth).at(longAgo)
		refuses(t, rootlist.Verify(signed(t, cand, w.b, w.c), held, now), rootlist.RemovalInvalid, 9)
	})
	t.Run("check 5 before check 8", func(t *testing.T) {
		cand := listOf(3, w.b, w.c).withRemovals(removalOf(t, w.a)).at("2026-12-02T12:00:00Z")
		refuses(t, rootlist.Verify(signed(t, cand, w.b, w.c, w.z), held, now), rootlist.Malformed, 5)
	})
	t.Run("check 2 before check 3", func(t *testing.T) {
		data := listOf(3, w.b, w.c).withRemovals(removalOf(t, w.a)).json()
		changed := append(append([]byte{}, data...), ' ')
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: changed, JWS: sign(t, data, w.z)}, held, now), rootlist.UnknownSigner, 2)
	})
	t.Run("check 3 before check 4", func(t *testing.T) {
		data := replace(t, listOf(3, w.b, w.c).withRemovals(removalOf(t, w.a)).json(), `"version":1`, `"version":2`)
		changed := append(append([]byte{}, data...), ' ')
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: changed, JWS: sign(t, data, w.b)}, held, now), rootlist.SignatureInvalid, 3)
	})
}

func TestWayBackTheHostKeepsNoHigherNumber(t *testing.T) {
	// Rule 53: the list replaces the held list, and the host's sequence is the list's sequence; it
	// keeps no higher number anywhere. The host that took the list holds it from then on.
	w := newWorld(t)
	first := bWithoutA(t, w, 3)
	v := rootlist.Verify(signed(t, first, w.b), heldAtMax(t, w), now)
	acceptsWayback(t, v)
	if v.List.Sequence != 3 {
		t.Fatalf("the accepted list has the sequence %d, want 3", v.List.Sequence)
	}
	after := heldFrom(t, first)
	t.Run("the next honest list is the next sequence", func(t *testing.T) {
		accepts(t, rootlist.Verify(signed(t, listOf(4, w.b), w.b), after, now))
	})
	t.Run("a sequence below the new one is a rollback", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, listOf(2, w.b), w.b), after, now), rootlist.Rollback, 6)
	})
	t.Run("the same sequence with other content is a conflict", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, listOf(3, w.b, w.c), w.b, w.c), after, now), rootlist.SequenceConflict, 7)
	})
	t.Run("a sequence between the new one and the old one is not a rollback", func(t *testing.T) {
		for _, seq := range []int{4, 100, 1000000} {
			accepts(t, rootlist.Verify(signed(t, listOf(seq, w.b), w.b), after, now))
		}
	})
	t.Run("the list that was held before is not a rollback either", func(t *testing.T) {
		// The held list had the highest sequence. A host that took the way back holds sequence 3 and
		// the keys of that list: a list of sequence 3 or higher that its keys sign is judged afresh.
		old := atSequence(listOf(1, w.a, w.b), highestSequence)
		refuses(t, rootlist.Verify(signed(t, old, w.b), after, now), rootlist.InsufficientSigners, 10)
	})
	t.Run("the host that held the list at the highest sequence is not changed by the check", func(t *testing.T) {
		trust := heldAtMax(t, w)
		cand := signed(t, first, w.b)
		for i := 0; i < 2; i++ {
			acceptsWayback(t, rootlist.Verify(cand, trust, now))
		}
		// The same trust refuses a list that is not a way back, after one that was.
		refuses(t, rootlist.Verify(signed(t, listOf(8, w.b), w.a, w.b), trust, now), rootlist.Rollback, 6)
		// A list that is not a way back, and a way back, give each its own answer in either order.
		acceptsWayback(t, rootlist.Verify(cand, trust, now))
	})
}

func TestWayBackAHostThatHoldsOnlyPinsNeverUsesIt(t *testing.T) {
	// Rule 53: a host that holds no list, only initial pins with or without a lowest sequence, does
	// not use the rule; rule 51 stays as it is for it.
	w := newWorld(t)
	cand := signed(t, bWithoutA(t, w, 8), w.b)
	pins := pinsOf(t, w.a.pin, w.b.pin)
	withMin := func(n int64) rootlist.Trust {
		tr, err := pins.WithMinSequence(n)
		if err != nil {
			t.Fatal(err)
		}
		return tr
	}
	t.Run("without a lowest sequence the list is a first list", func(t *testing.T) {
		v := rootlist.Verify(cand, pins, now)
		accepts(t, v)
	})
	t.Run("at the lowest sequence", func(t *testing.T) {
		accepts(t, rootlist.Verify(cand, withMin(8), now))
	})
	t.Run("below the lowest sequence, whatever the list names", func(t *testing.T) {
		for _, n := range []int64{9, 10, 1000, 9007199254740991} {
			refuses(t, rootlist.Verify(cand, withMin(n), now), rootlist.Rollback, 6)
		}
	})
	t.Run("below the lowest sequence for a list with every key named", func(t *testing.T) {
		cand := listOf(2, w.c).withRemovals(removalOf(t, w.a), removalOf(t, w.b))
		refuses(t, rootlist.Verify(signed(t, cand, w.c, w.a), withMin(3), now), rootlist.Rollback, 6)
		accepts(t, rootlist.Verify(signed(t, cand, w.c, w.a), withMin(2), now))
	})
	t.Run("the same list against a held list is a way back and against pins it is not", func(t *testing.T) {
		held := heldOf(t, atSequence(listOf(1, w.a, w.b), "9"))
		acceptsWayback(t, rootlist.Verify(cand, held, now))
		refuses(t, rootlist.Verify(cand, withMin(9), now), rootlist.Rollback, 6)
	})
	t.Run("the host that holds nothing trusts nothing", func(t *testing.T) {
		refuses(t, rootlist.Verify(cand, rootlist.Trust{}, now), rootlist.UnknownSigner, 2)
	})
}

func TestWayBackAListThatRemovesAKeyAndAddsAKey(t *testing.T) {
	// Rule 53: the list needs the signature of every key it adds (check 10). A list that removes A,
	// names it, and adds C, signed by B and C, is a way back.
	w := newWorld(t)
	held := heldOf(t, listOf(7, w.a, w.b))
	cand := listOf(3, w.b, w.c).withRemovals(removalOf(t, w.a))
	t.Run("signed by the kept key and the added key", func(t *testing.T) {
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.b, w.c), held, now))
	})
	t.Run("at the held sequence", func(t *testing.T) {
		acceptsWayback(t, rootlist.Verify(signed(t, atSequence(cand, "7"), w.b, w.c), held, now))
	})
	t.Run("the added key does not sign", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, cand, w.b), held, now), rootlist.InsufficientSigners, 10)
	})
	t.Run("the kept key does not sign", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, cand, w.c), held, now), rootlist.UnknownSigner, 2)
	})
	t.Run("a key that is added and not removed anywhere is no way back", func(t *testing.T) {
		// A list that only adds C, below the held sequence, removes nothing.
		refuses(t, rootlist.Verify(signed(t, listOf(3, w.a, w.b, w.c), w.a, w.b, w.c), held, now), rootlist.Rollback, 6)
	})
	t.Run("a removal and an addition at a higher sequence", func(t *testing.T) {
		accepts(t, rootlist.Verify(signed(t, atSequence(cand, "8"), w.b, w.c), held, now))
	})
}

func TestWayBackAListThatRemovesEveryKeyOfTheHeldList(t *testing.T) {
	// Rule 53: a list that removes every held key and names each is a way back; it needs the
	// signature of a held key (check 2), and the signature of every key it adds (check 10).
	w := newWorld(t)
	held := heldAtMax(t, w)
	cand := listOf(8, w.z).withRemovals(removalOf(t, w.a), removalOf(t, w.b))
	t.Run("signed by a removed key and the new key", func(t *testing.T) {
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.a, w.z), held, now))
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.b, w.z), held, now))
	})
	t.Run("at the held sequence", func(t *testing.T) {
		h := heldOf(t, listOf(8, w.a, w.b))
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.a, w.z), h, now))
	})
	t.Run("signed only by the new key", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, cand, w.z), held, now), rootlist.UnknownSigner, 2)
	})
	t.Run("signed by a removed key and not by the new key", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, cand, w.a), held, now), rootlist.InsufficientSigners, 10)
	})
	t.Run("one of the two not named", func(t *testing.T) {
		one := listOf(8, w.z).withRemovals(removalOf(t, w.a))
		refuses(t, rootlist.Verify(signed(t, one, w.a, w.z), held, now), rootlist.Rollback, 6)
	})
	t.Run("a key on no list removed", func(t *testing.T) {
		withZ := listOf(8, w.c).withRemovals(removalOf(t, w.a), removalOf(t, w.b), removalOf(t, w.z))
		refuses(t, rootlist.Verify(signed(t, withZ, w.a, w.c), held, now), rootlist.RemovalInvalid, 9)
	})
}

func TestWayBackOverAHeldListThatHasExpired(t *testing.T) {
	// Rule 53 and record 0006, rule 21: a held list that has expired is kept and raises a warning;
	// a list that is a way back is taken over it, and the candidate's own expiry (check 11) still
	// counts.
	w := newWorld(t)
	heldSpec := atSequence(listOf(1, w.a, w.b), highestSequence).at(longAgo)
	held, err := rootlist.ParseHeld(heldSpec.json())
	if err != nil {
		t.Fatal(err)
	}
	if got := rootlist.CheckHeld(held, now); len(got) != 1 || got[0] != rootlist.WarningHeldExpired {
		t.Fatalf("the held list has not expired at the clock of the test: %v", got)
	}
	trust := rootlist.HeldTrust(held)
	t.Run("a way back over it", func(t *testing.T) {
		acceptsWayback(t, rootlist.Verify(signed(t, bWithoutA(t, w, 8), w.b), trust, now))
	})
	t.Run("a way back whose own expiry has passed", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, bWithoutA(t, w, 8).at(longAgo), w.b), trust, now), rootlist.Expired, 11)
	})
	t.Run("a list that is not a way back, over it", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, listOf(8, w.a, w.b), w.a), trust, now), rootlist.Rollback, 6)
	})
}

func TestWayBackARetireWithTheAuthorisationAndARevokeThatTheKeySigns(t *testing.T) {
	// Rule 53, last sentences: a host decides by the entries only. A list that names the key it
	// removes is a way back whatever the writer meant: a retire with the authorisation, a revoke
	// that the removed key itself signs, and a revoke of a key that cannot sign.
	w := newWorld(t)
	held := heldAtMax(t, w)
	t.Run("a revoke that the removed key signs", func(t *testing.T) {
		acceptsWayback(t, rootlist.Verify(signed(t, bWithoutA(t, w, 8), w.a, w.b), held, now))
	})
	t.Run("a revoke that the removed key does not sign", func(t *testing.T) {
		acceptsWayback(t, rootlist.Verify(signed(t, bWithoutA(t, w, 8), w.b), held, now))
	})
	t.Run("a retire with the authorisation", func(t *testing.T) {
		heldABC := heldOf(t, atSequence(listOf(1, w.a, w.b, w.c), highestSequence))
		cand := listOf(8, w.a, w.c).withRemovals(removalOf(t, w.b))
		acceptsWayback(t, rootlist.Verify(signed(t, cand, w.a, w.b, w.c), heldABC, now))
	})
	t.Run("a retire with no entry is a rollback", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, listOf(8, w.b), w.a, w.b), held, now), rootlist.Rollback, 6)
	})
	t.Run("a retire of one key and a revoke of another, naming only the revoked one", func(t *testing.T) {
		heldABC := heldOf(t, atSequence(listOf(1, w.a, w.b, w.c), highestSequence))
		cand := listOf(8, w.c).withRemovals(removalOf(t, w.a))
		refuses(t, rootlist.Verify(signed(t, cand, w.a, w.b, w.c), heldABC, now), rootlist.Rollback, 6)
	})
}

func TestWayBackTheVerdictCarriesTheListThatWasRead(t *testing.T) {
	// The accepted list is the list that ParseList reads from the candidate's bytes, whether the
	// list was taken by the way back or not.
	w := newWorld(t)
	held := heldAtMax(t, w)
	cand := signed(t, bWithoutA(t, w, 8), w.b)
	v := rootlist.Verify(cand, held, now)
	acceptsWayback(t, v)
	want, err := rootlist.ParseList(cand.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if v.List.Sequence != want.Sequence || len(v.List.Roots) != 1 || v.List.Roots[0].X509SPKISHA256 != w.b.pin || len(v.List.Removals) != 1 || v.List.Removals[0].X509SPKISHA256 != w.a.pin {
		t.Errorf("the accepted list is not the one that was read: %+v", v.List)
	}
}

func TestWayBackTheInputsAreNotChanged(t *testing.T) {
	w := newWorld(t)
	cand := signed(t, bWithoutA(t, w, 3), w.b)
	json, jws := bytes.Clone(cand.JSON), bytes.Clone(cand.JWS)
	heldSpec := listOf(7, w.a, w.b)
	h, err := rootlist.ParseHeld(heldSpec.json())
	if err != nil {
		t.Fatal(err)
	}
	heldJSON := bytes.Clone(h.JSON)
	trust := rootlist.HeldTrust(h)
	for i := 0; i < 2; i++ {
		acceptsWayback(t, rootlist.Verify(cand, trust, now))
	}
	if !bytes.Equal(cand.JSON, json) || !bytes.Equal(cand.JWS, jws) || !bytes.Equal(h.JSON, heldJSON) || h.List.Sequence != 7 || len(h.List.Roots) != 2 {
		t.Errorf("Verify changed its input")
	}
}

func TestWayBackTheNamesOfChecks6And7SayTheyAreNotRunForTheWayBack(t *testing.T) {
	// The page names the way back in checks 6 and 7 and in no other: the names that Checks gives are
	// for a person, and the reasons and the order are the page's.
	for _, c := range rootlist.Checks() {
		mentions := strings.Contains(c.Name, "way back")
		if want := c.N == 6 || c.N == 7; mentions != want {
			t.Errorf("check %d (%q) mentions the way back: %v, want %v", c.N, c.Name, mentions, want)
		}
	}
}
