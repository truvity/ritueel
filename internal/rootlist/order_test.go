package rootlist_test

import (
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

// TestTheEarlierCheckGivesTheCode: for each pair of neighbouring checks, a list that fails both is
// refused with the code of the earlier one. Each case is built so that the later check would
// refuse it too: the defect of the later check is in it, and the test says which.
func TestTheEarlierCheckGivesTheCode(t *testing.T) {
	b := newBase(t)
	w := b.w
	trust := b.trust(t)
	good := b.cand.json()
	run := func(cand rootlist.Signed) rootlist.Verdict { return rootlist.Verify(cand, trust, now) }

	t.Run("1 before 2: a malformed file whose only signer is unknown", func(t *testing.T) {
		h := goodHeader(w.z, typList)
		h.typ = `"` + typRemoval + `"`
		p := h.text()
		cand := rootlist.Signed{JSON: good, JWS: jwsFile(entry(p, sigOver(t, w.z, p, good)))}
		refuses(t, run(cand), rootlist.Malformed, 1)
		// The same file with the right type is refused at 2: the second defect is real.
		refuses(t, run(signedBytes(t, good, w.z)), rootlist.UnknownSigner, 2)
	})
	t.Run("2 before 3: an unknown signer whose signature does not verify", func(t *testing.T) {
		tampered := append(append([]byte{}, good...), ' ')
		cand := rootlist.Signed{JSON: tampered, JWS: sign(t, good, w.z)}
		refuses(t, run(cand), rootlist.UnknownSigner, 2)
		refuses(t, run(rootlist.Signed{JSON: tampered, JWS: sign(t, good, w.a)}), rootlist.SignatureInvalid, 3)
	})
	t.Run("3 before 4: a signature that does not verify over a list of version 2", func(t *testing.T) {
		v2 := replace(t, good, `"version":1`, `"version":2`)
		cand := rootlist.Signed{JSON: append(append([]byte{}, v2...), ' '), JWS: sign(t, v2, w.a)}
		refuses(t, run(cand), rootlist.SignatureInvalid, 3)
		refuses(t, run(signedBytes(t, v2, w.a)), rootlist.VersionUnsupported, 4)
	})
	t.Run("4 before 5: a list of version 2 that is also broken in its members", func(t *testing.T) {
		v2 := replace(t, good, `"version":1`, `"version":2,"x":1.5,"y":null`)
		v2 = replace(t, v2, `"sequence":8`, `"sequence":0`)
		refuses(t, run(signedBytes(t, v2, w.a)), rootlist.VersionUnsupported, 4)
		v1 := replace(t, v2, `"version":2`, `"version":1`)
		refuses(t, run(signedBytes(t, v1, w.a)), rootlist.Malformed, 5)
	})
	t.Run("5 before 6: a list with an unknown member and a lower sequence", func(t *testing.T) {
		bad := replace(t, good, `"sequence":8`, `"sequence":3,"x":1`)
		refuses(t, run(signedBytes(t, bad, w.a)), rootlist.Malformed, 5)
		refuses(t, run(signedBytes(t, replace(t, good, `"sequence":8`, `"sequence":3`), w.a)), rootlist.Rollback, 6)
	})
	t.Run("6 and 7 exclude each other", func(t *testing.T) {
		// A lower sequence is not an equal one and the reverse, so no list fails both. Each one alone
		// gives its code, and a list that is lower and also differs from the held one is a rollback.
		refuses(t, run(signedBytes(t, listOf(6, w.a).json(), w.a)), rootlist.Rollback, 6)
		refuses(t, run(signedBytes(t, listOf(7, w.a).json(), w.a)), rootlist.SequenceConflict, 7)
	})
	t.Run("7 before 8: another list at the held sequence, signed by an unknown key as well", func(t *testing.T) {
		other := listOf(7, w.a)
		refuses(t, run(signed(t, other, w.a, w.z)), rootlist.SequenceConflict, 7)
		refuses(t, run(signed(t, listOf(8, w.a, w.b), w.a, w.z)), rootlist.UnknownSigner, 8)
	})
	t.Run("8 before 9: an unknown signer and a removal that is not valid", func(t *testing.T) {
		bad := removalSpec{label: "A", pin: w.a.pin, auth: authorisation(t, w.b)}
		cand := listOf(8, w.b).withRemovals(bad)
		refuses(t, run(signed(t, cand, w.b, w.z)), rootlist.UnknownSigner, 8)
		refuses(t, run(signed(t, cand, w.b)), rootlist.RemovalInvalid, 9)
	})
	t.Run("9 before 10: a removal that is not valid and signers that are too few", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b, w.c))
		bad := removalSpec{label: "A", pin: w.a.pin, auth: authorisation(t, w.b)}
		cand := listOf(8, w.c).withRemovals(bad)
		// B is neither a signer nor removed: check 10 would refuse this too.
		refuses(t, rootlist.Verify(signed(t, cand, w.c), held, now), rootlist.RemovalInvalid, 9)
		fixed := listOf(8, w.c).withRemovals(removalOf(t, w.a))
		refuses(t, rootlist.Verify(signed(t, fixed, w.c), held, now), rootlist.InsufficientSigners, 10)
	})
	t.Run("10 before 11: signers that are too few on a list that has expired", func(t *testing.T) {
		cand := listOf(8, w.a).at(longAgo) // its expiry, 13 months later, is before now
		refuses(t, run(signed(t, cand, w.a)), rootlist.InsufficientSigners, 10)
		cand2 := listOf(8, w.a, w.b).at(longAgo)
		refuses(t, run(signed(t, cand2, w.a)), rootlist.Expired, 11)
	})
	t.Run("a list that fails every check that can fail together is refused by the first", func(t *testing.T) {
		// Malformed signature file, unknown signer, no valid signature, and an expired time: check 1.
		h := goodHeader(w.z, typList)
		h.alg = `"none"`
		bad := replace(t, good, `"expires_at":"`+expiresAt+`"`, `"expires_at":"2026-11-20T12:00:00Z"`)
		bad = replace(t, bad, `"version":1`, `"version":2`)
		p := h.text()
		cand := rootlist.Signed{JSON: bad, JWS: jwsFile(entry(p, b64u(make([]byte, 96))))}
		refuses(t, run(cand), rootlist.Malformed, 1)
	})
}

// TestEachCheckIsReachedByItsOwnDefect says that the defect of each case above is the one that its
// check refuses alone, so that the order tests above are tests of the order.
func TestEachCheckIsReachedByItsOwnDefect(t *testing.T) {
	b := newBase(t)
	w := b.w
	trust := b.trust(t)
	good := b.cand.json()
	cases := []struct {
		check  int
		reason rootlist.Reason
		cand   func(t *testing.T) rootlist.Signed
		trust  rootlist.Trust
	}{
		{1, rootlist.Malformed, func(t *testing.T) rootlist.Signed { return rootlist.Signed{JSON: good} }, trust},
		{2, rootlist.UnknownSigner, func(t *testing.T) rootlist.Signed { return signedBytes(t, good, w.z) }, trust},
		{3, rootlist.SignatureInvalid, func(t *testing.T) rootlist.Signed {
			return rootlist.Signed{JSON: append(append([]byte{}, good...), ' '), JWS: sign(t, good, w.a)}
		}, trust},
		{4, rootlist.VersionUnsupported, func(t *testing.T) rootlist.Signed {
			return signedBytes(t, replace(t, good, `"version":1`, `"version":2`), w.a)
		}, trust},
		{5, rootlist.Malformed, func(t *testing.T) rootlist.Signed {
			return signedBytes(t, replace(t, good, `"version":1`, `"version":1,"x":1`), w.a)
		}, trust},
		{6, rootlist.Rollback, func(t *testing.T) rootlist.Signed { return signed(t, listOf(6, w.a, w.b), w.a) }, trust},
		{7, rootlist.SequenceConflict, func(t *testing.T) rootlist.Signed { return signed(t, listOf(7, w.a), w.a) }, trust},
		{8, rootlist.UnknownSigner, func(t *testing.T) rootlist.Signed { return signed(t, b.cand, w.a, w.z) }, trust},
		{9, rootlist.RemovalInvalid, func(t *testing.T) rootlist.Signed {
			return signed(t, listOf(8, w.b).withRemovals(removalSpec{label: "A", pin: w.a.pin, auth: authorisation(t, w.b)}), w.b)
		}, trust},
		{10, rootlist.InsufficientSigners, func(t *testing.T) rootlist.Signed { return signed(t, listOf(8, w.a), w.a) }, trust},
		{11, rootlist.Expired, func(t *testing.T) rootlist.Signed {
			return signed(t, b.cand.at(longAgo), w.a)
		}, trust},
	}
	if len(cases) != len(rootlist.Checks()) {
		t.Fatalf("%d cases for %d checks", len(cases), len(rootlist.Checks()))
	}
	for _, c := range cases {
		t.Run(itoa(c.check), func(t *testing.T) {
			refuses(t, rootlist.Verify(c.cand(t), c.trust, now), c.reason, c.check)
			if got := rootlist.Checks()[c.check-1]; got.N != c.check || got.Reason != c.reason {
				t.Errorf("Checks()[%d] is check %d with %q", c.check-1, got.N, got.Reason)
			}
		})
	}
}
