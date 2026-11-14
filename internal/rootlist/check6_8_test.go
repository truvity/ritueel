package rootlist_test

import (
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

func TestCheck6TheSequenceMustNotFall(t *testing.T) {
	b := newBase(t)
	w := b.w
	for _, seq := range []int{6, 5, 1} {
		t.Run("sequence "+itoa(seq), func(t *testing.T) {
			refuses(t, b.verify(t, listOf(seq, w.a, w.b), w.a), rootlist.Rollback, 6)
		})
	}
	t.Run("a rollback to a list with other root keys", func(t *testing.T) {
		refuses(t, b.verify(t, listOf(3, w.a), w.a), rootlist.Rollback, 6)
	})
	t.Run("a rollback that a root key of the held list signs and the other does too", func(t *testing.T) {
		refuses(t, b.verify(t, listOf(6, w.a, w.b), w.a, w.b), rootlist.Rollback, 6)
	})
	t.Run("a rollback by one below the largest sequence", func(t *testing.T) {
		held := listOf(1, w.a, w.b)
		held.sequence = "9007199254740991"
		cand := listOf(1, w.a, w.b)
		cand.sequence = "9007199254740990"
		refuses(t, rootlist.Verify(signed(t, cand, w.a), heldOf(t, held), now), rootlist.Rollback, 6)
	})
	for _, seq := range []int{8, 9, 100, 1000000} {
		t.Run("a higher sequence "+itoa(seq), func(t *testing.T) {
			accepts(t, b.verify(t, listOf(seq, w.a, w.b), w.a))
		})
	}
	t.Run("against initial pins there is no sequence to fall below", func(t *testing.T) {
		pins := pinsOf(t, w.a.pin, w.b.pin)
		for _, seq := range []int{1, 2, 7, 1000} {
			accepts(t, rootlist.Verify(signed(t, listOf(seq, w.a, w.b), w.a), pins, now))
		}
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}

func TestCheck7OneSequenceNamesOneList(t *testing.T) {
	b := newBase(t)
	w := b.w
	heldJSON := b.held.json()
	trust := b.trust(t)
	heldAgain := func(signers ...*key) rootlist.Verdict {
		return rootlist.Verify(rootlist.Signed{JSON: heldJSON, JWS: sign(t, heldJSON, signers...)}, trust, now)
	}
	t.Run("the same list again, whichever root key signs", func(t *testing.T) {
		acceptsAgain(t, heldAgain(w.a))
		acceptsAgain(t, heldAgain(w.b))
		acceptsAgain(t, heldAgain(w.a, w.b))
		acceptsAgain(t, heldAgain(w.b, w.a))
	})
	t.Run("the same sequence with another content", func(t *testing.T) {
		for name, s := range map[string]spec{
			"fewer root keys":                 listOf(7, w.a),
			"more root keys":                  listOf(7, w.a, w.b, w.c),
			"other root keys":                 listOf(7, w.c, w.z),
			"another fingerprint":             func() spec { s := listOf(7, w.a, w.b); s.roots[0].fp = w.z.fp(); return s }(),
			"another digest of record":        func() spec { s := listOf(7, w.a, w.b); s.last = w.z.pin; return s }(),
			"another signing time and expiry": listOf(7, w.a, w.b).at("2026-11-16T12:00:00Z"),
			"no last record":                  func() spec { s := listOf(7, w.a, w.b); s.noLast = true; return s }(),
			"the roots in another order":      listOf(7, w.b, w.a),
		} {
			t.Run(name, func(t *testing.T) {
				refuses(t, b.verify(t, s, w.a), rootlist.SequenceConflict, 7)
			})
		}
	})
	t.Run("one byte of difference is a difference", func(t *testing.T) {
		for name, data := range map[string][]byte{
			"a space after the object":     append(append([]byte{}, heldJSON...), ' '),
			"a line feed after the object": append(append([]byte{}, heldJSON...), '\n'),
			"a space before the object":    append([]byte{' '}, heldJSON...),
			"an escape for a letter":       replace(t, heldJSON, `"label":"A"`, `"label":"\u0041"`),
			"a space after a colon":        replace(t, heldJSON, `"version":1`, `"version": 1`),
		} {
			t.Run(name, func(t *testing.T) {
				v := rootlist.Verify(rootlist.Signed{JSON: data, JWS: sign(t, data, w.a)}, trust, now)
				refuses(t, v, rootlist.SequenceConflict, 7)
			})
		}
	})
	t.Run("the held list again passes checks 8 to 10 and not check 11", func(t *testing.T) {
		// Page: "Receiving the current list again is not an error: a list at the same sequence
		// passes when its root-list.json is byte-identical to the held one." The same list, signed
		// by A and by Z, which is on no list, is that list again. Check 2 still needs a signer the
		// host trusts, and that is A.
		acceptsAgain(t, heldAgain(w.a, w.z))
		// The same list after it expired: check 11 still applies.
		late := mustTime(expiresAt)
		v := rootlist.Verify(rootlist.Signed{JSON: heldJSON, JWS: sign(t, heldJSON, w.a)}, trust, late)
		refuses(t, v, rootlist.Expired, 11)
	})
	t.Run("a sequence that is not equal is never a conflict", func(t *testing.T) {
		refuses(t, b.verify(t, listOf(6, w.a), w.a), rootlist.Rollback, 6)
		accepts(t, b.verify(t, listOf(8, w.a, w.b), w.a))
	})
	t.Run("against initial pins nothing is held, so nothing conflicts", func(t *testing.T) {
		pins := pinsOf(t, w.a.pin, w.b.pin)
		accepts(t, rootlist.Verify(signedBytes(t, heldJSON, w.a), pins, now)) // a new list: Again is false
	})
}

func TestCheck8EverySignerMustBeKnown(t *testing.T) {
	b := newBase(t)
	w := b.w
	t.Run("a known signer and an unknown one", func(t *testing.T) {
		refuses(t, b.verify(t, b.cand, w.a, w.z), rootlist.UnknownSigner, 8)
		refuses(t, b.verify(t, b.cand, w.z, w.a), rootlist.UnknownSigner, 8)
		refuses(t, b.verify(t, b.cand, w.a, w.b, w.z), rootlist.UnknownSigner, 8)
	})
	t.Run("an unknown signer that is on the new list is known", func(t *testing.T) {
		accepts(t, b.verify(t, listOf(8, w.a, w.b, w.c), w.a, w.b, w.c))
	})
	t.Run("a signer that is on the held list and not on the new one is known", func(t *testing.T) {
		accepts(t, b.verify(t, listOf(8, w.b), w.a, w.b))
	})
	t.Run("a signer of the new list is not known by being on the list that is refused", func(t *testing.T) {
		// Z is on the new list and signs it, but the list adds Z and A does not sign: the signature of
		// Z alone would be unknown-signer at check 2; with A it passes 8 and is judged at 10.
		refuses(t, b.verify(t, listOf(8, w.a, w.b, w.z), w.a, w.z), rootlist.InsufficientSigners, 10)
	})
	t.Run("against initial pins", func(t *testing.T) {
		pins := pinsOf(t, w.a.pin, w.b.pin)
		refuses(t, rootlist.Verify(signed(t, listOf(1, w.a, w.b), w.a, w.z), pins, now), rootlist.UnknownSigner, 8)
		accepts(t, rootlist.Verify(signed(t, listOf(1, w.a, w.b, w.c), w.a, w.b, w.c), pins, now))
	})
}
