package rootlist_test

import (
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

// The operator who gives a host its initial pins can give it, on the
// same channel, the lowest sequence to accept. A list below it is refused with rollback at check 6.
// A host that holds a list has its sequence, so the lowest sequence is for pins only.

const maxSafe = 9007199254740991 // the largest integer of the JSON rules, 2^53 - 1

func TestTheLowestSequenceOfAHostWithPins(t *testing.T) {
	w := newWorld(t)
	pins := pinsOf(t, w.a.pin, w.b.pin)
	min := func(n int64) rootlist.Trust {
		tr, err := pins.WithMinSequence(n)
		if err != nil {
			t.Fatalf("WithMinSequence(%d): %v", n, err)
		}
		return tr
	}
	list := func(seq int) rootlist.Signed { return signed(t, listOf(seq, w.a, w.b), w.a) }
	t.Run("a list below it is refused as rollback at check 6", func(t *testing.T) {
		for _, c := range []struct {
			seq int
			min int64
		}{{1, 2}, {6, 7}, {7, 8}, {7, 1000}, {1, 9007199254740991}} {
			refuses(t, rootlist.Verify(list(c.seq), min(c.min), now), rootlist.Rollback, 6)
		}
	})
	t.Run("a list at it or above it is accepted", func(t *testing.T) {
		for _, c := range []struct {
			seq int
			min int64
		}{{1, 1}, {7, 7}, {8, 7}, {100, 7}, {7, 1}} {
			accepts(t, rootlist.Verify(list(c.seq), min(c.min), now))
		}
		big := listOf(1, w.a, w.b)
		big.sequence = "9007199254740991"
		accepts(t, rootlist.Verify(signed(t, big, w.a), min(maxSafe), now))
	})
	t.Run("without it nothing changes", func(t *testing.T) {
		accepts(t, rootlist.Verify(list(1), pins, now))
		accepts(t, rootlist.Verify(list(7), pins, now))
	})
	t.Run("the trust it comes from is not changed", func(t *testing.T) {
		_ = min(100)
		accepts(t, rootlist.Verify(list(7), pins, now))
	})
	t.Run("it can be given again, and the last one counts", func(t *testing.T) {
		twice, err := min(10).WithMinSequence(3)
		if err != nil {
			// A trust that has a lowest sequence is still a trust of pins.
			t.Fatalf("a second lowest sequence: %v", err)
		}
		accepts(t, rootlist.Verify(list(5), twice, now))
		refuses(t, rootlist.Verify(list(2), twice, now), rootlist.Rollback, 6)
	})
	t.Run("the example of the page: an old list with a root key that left since", func(t *testing.T) {
		// A host with the pins of A and B. An old list of sequence 5 with A, B and C, signed by all three,
		// not expired: it is taken without a lowest sequence, and refused with one.
		old := signed(t, listOf(5, w.a, w.b, w.c), w.a, w.b, w.c)
		accepts(t, rootlist.Verify(old, pins, now))
		refuses(t, rootlist.Verify(old, min(7), now), rootlist.Rollback, 6)
	})
}

func TestTheLowestSequenceIsRefusedWhereItMeansNothing(t *testing.T) {
	w := newWorld(t)
	pins := pinsOf(t, w.a.pin)
	for _, n := range []int64{0, -1, -9007199254740991, maxSafe + 1, 1 << 62} {
		if _, err := pins.WithMinSequence(n); err == nil {
			t.Errorf("WithMinSequence(%d) is accepted", n)
		} else {
			mustBeASCII(t, "the error text", err.Error())
		}
	}
	for _, n := range []int64{1, 2, maxSafe} {
		if _, err := pins.WithMinSequence(n); err != nil {
			t.Errorf("WithMinSequence(%d): %v", n, err)
		}
	}
	t.Run("a host that holds a list has its sequence", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a))
		if _, err := held.WithMinSequence(3); err == nil {
			t.Error("a lowest sequence is given to a trust of a held list")
		}
		// A trust of nothing has no pins to be the lowest sequence of.
		var zero rootlist.Trust
		if _, err := zero.WithMinSequence(3); err == nil {
			t.Error("a lowest sequence is given to the zero trust")
		}
		if _, err := rootlist.HeldTrust(nil).WithMinSequence(3); err == nil {
			t.Error("a lowest sequence is given to the trust of a nil held list")
		}
	})
	t.Run("a held list's trust is not changed by the refused attempt", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a))
		_, _ = held.WithMinSequence(100)
		accepts(t, rootlist.Verify(signed(t, listOf(8, w.a), w.a), held, now))
	})
}

func TestTheLowestSequenceComesAfterTheChecksBeforeIt(t *testing.T) {
	w := newWorld(t)
	tr, err := pinsOf(t, w.a.pin, w.b.pin).WithMinSequence(10)
	if err != nil {
		t.Fatal(err)
	}
	low := listOf(2, w.a, w.b)
	// Checks 1 to 5 come first.
	refuses(t, rootlist.Verify(signed(t, low, w.z), tr, now), rootlist.UnknownSigner, 2)
	refuses(t, rootlist.Verify(rootlist.Signed{JSON: low.json(), JWS: sign(t, listOf(3, w.a, w.b).json(), w.a)}, tr, now), rootlist.SignatureInvalid, 3)
	v2 := low
	v2.version = "2"
	refuses(t, rootlist.Verify(signed(t, v2, w.a), tr, now), rootlist.VersionUnsupported, 4)
	bad := low
	bad.expiresAt = `"9999-12-31T00:00:00Z"`
	refuses(t, rootlist.Verify(signed(t, bad, w.a), tr, now), rootlist.Malformed, 5)
	// Check 6 comes before 8 to 11.
	refuses(t, rootlist.Verify(signed(t, listOf(2, w.a, w.b, w.z), w.a, w.z), tr, now), rootlist.Rollback, 6)   // not unknown-signer at 8
	refuses(t, rootlist.Verify(signed(t, listOf(2, w.a), w.a), tr, now), rootlist.Rollback, 6)                  // not insufficient-signers
	refuses(t, rootlist.Verify(signed(t, listOf(2, w.a, w.b).at(longAgo), w.a), tr, now), rootlist.Rollback, 6) // not expired
	// With the sequence at the lowest, those checks speak for themselves.
	refuses(t, rootlist.Verify(signed(t, listOf(10, w.a), w.a), tr, now), rootlist.InsufficientSigners, 10)
	refuses(t, rootlist.Verify(signed(t, listOf(10, w.a, w.b).at(longAgo), w.a), tr, now), rootlist.Expired, 11)
}
