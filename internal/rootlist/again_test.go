package rootlist_test

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
)

// The page says: "Receiving the current list again is not an error: a list at the same sequence
// passes when its root-list.json is byte-identical to the held one, whichever active root key
// signed it, and is refused with sequence-conflict when its content differs". The tests of this
// file are about that sentence: the held list received again, Verdict.Again, and what still
// applies to it (checks 1 to 7, which include a signer the host trusts and every signature
// verifying, and check 11).

// holdable returns the ids of the lists of the manifest that a host can hold: a list that a case
// names as the held list, or that an accepting case accepts. The manifest says which; no id is
// written here.
func (m *manifest) holdable(t testing.TB) []string {
	t.Helper()
	var ids []string
	add := func(id *string) {
		if id != nil && !slices.Contains(ids, *id) {
			ids = append(ids, *id)
		}
	}
	for _, c := range m.Cases {
		add(c.Held)
		if c.Expect == "accept" {
			add(c.Candidate)
		}
	}
	if len(ids) == 0 {
		t.Fatal("the manifest has no list that a host can hold")
	}
	return ids
}

// before is the last moment before the list expires, for a clock that is read from the list.
func before(l *rootlist.List) time.Time { return l.ExpiresAt.Add(-time.Second) }

func TestTheHeldListAgainForEveryHoldableListOfTheManifest(t *testing.T) {
	m := loadManifest(t)
	for _, id := range m.holdable(t) {
		t.Run(id, func(t *testing.T) {
			pair := m.listFiles(t, id)
			h, err := rootlist.ParseHeld(pair.JSON)
			if err != nil {
				t.Fatal(err)
			}
			trust := rootlist.HeldTrust(h)
			v := rootlist.Verify(pair, trust, before(h.List))
			acceptsAgain(t, v)
			if !reflect.DeepEqual(v.List, h.List) {
				t.Errorf("the list that is accepted again is not the held list")
			}
			t.Run("after the expiry it is refused at check 11, and the host is warned", func(t *testing.T) {
				for _, at := range []time.Time{h.List.ExpiresAt, h.List.ExpiresAt.Add(time.Second), h.List.ExpiresAt.AddDate(5, 0, 0)} {
					refuses(t, rootlist.Verify(pair, trust, at), rootlist.Expired, 11)
					if got := rootlist.CheckHeld(h, at); !slices.Equal(got, []string{rootlist.WarningHeldExpired}) {
						t.Errorf("CheckHeld = %v", got)
					}
				}
			})
			t.Run("against initial pins it is never the held list again", func(t *testing.T) {
				v := rootlist.Verify(pair, m.trustOf(t, nil), before(h.List))
				if v.Again {
					t.Errorf("Again against initial pins: %+v", v)
				}
			})
		})
	}
}

func TestOneChangedByteOfTheHeldListIsNotTheHeldListAgain(t *testing.T) {
	m := loadManifest(t)
	conflicts := 0
	for _, id := range m.holdable(t) {
		t.Run(id, func(t *testing.T) {
			pair := m.listFiles(t, id)
			h, err := rootlist.ParseHeld(pair.JSON)
			if err != nil {
				t.Fatal(err)
			}
			at := before(h.List)
			// The candidate is the held list with one byte changed: its signature no longer verifies.
			for i := 0; i < len(pair.JSON); i += 3 {
				mut := bytes.Clone(pair.JSON)
				mut[i] ^= 0x01
				v := rootlist.Verify(rootlist.Signed{JSON: mut, JWS: pair.JWS}, rootlist.HeldTrust(h), at)
				if v.Accepted || v.Again || v.Reason != rootlist.SignatureInvalid || v.Check != 3 {
					t.Fatalf("candidate byte %d: %+v", i, v)
				}
			}
			// The host holds the list with one byte changed, and the good pair arrives: a list at the
			// same sequence with other bytes. Every third byte, and a space after the object.
			held := append(bytes.Clone(pair.JSON), ' ')
			variants := [][]byte{held}
			for i := 0; i < len(pair.JSON); i += 3 {
				mut := bytes.Clone(pair.JSON)
				mut[i] ^= 0x01
				variants = append(variants, mut)
			}
			for _, hb := range variants {
				hh, err := rootlist.ParseHeld(hb)
				if err != nil {
					continue // not a list that a host could hold
				}
				v := rootlist.Verify(pair, rootlist.HeldTrust(hh), at)
				if v.Again {
					t.Fatalf("a held list with other bytes is not the same list: %+v", v)
				}
				if hh.List.Sequence == h.List.Sequence {
					if !slices.Equal(hh.List.Pins(), h.List.Pins()) && v.Reason == rootlist.UnknownSigner {
						// The changed byte is in a pin, and the host no longer trusts the signers (check 2).
						refuses(t, v, rootlist.UnknownSigner, 2)
						continue
					}
					refuses(t, v, rootlist.SequenceConflict, 7)
					conflicts++
				}
			}
		})
	}
	if conflicts == 0 {
		t.Fatal("no changed byte gave a conflict: nothing was checked")
	}
}

func TestTheHeldListAgainNeedsASignerTheHostTrusts(t *testing.T) {
	m := loadManifest(t)
	checked := 0
	for _, id := range m.holdable(t) {
		pair := m.listFiles(t, id)
		h, err := rootlist.ParseHeld(pair.JSON)
		if err != nil {
			t.Fatal(err)
		}
		trusted := h.List.Pins()
		for _, other := range m.Lists {
			if other.ID == id {
				continue
			}
			g, err := jws.ParseGeneral(m.listFiles(t, other.ID).JWS, "root-list+json")
			if err != nil {
				continue
			}
			known := false
			for _, s := range g.Signatures {
				known = known || slices.Contains(trusted, s.Header.Kid)
			}
			if known {
				continue
			}
			// The held list's bytes with the signature file of a list that nobody the host trusts
			// signed: refused at check 2, before the signatures are read.
			t.Run(id+" with the signatures of "+other.ID, func(t *testing.T) {
				cand := rootlist.Signed{JSON: pair.JSON, JWS: m.listFiles(t, other.ID).JWS}
				refuses(t, rootlist.Verify(cand, rootlist.HeldTrust(h), before(h.List)), rootlist.UnknownSigner, 2)
			})
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no pair of lists with signers that the host does not trust: nothing was checked")
	}
}

func TestTheHeldListAgainNeedsEverySignatureToVerify(t *testing.T) {
	m := loadManifest(t)
	for _, id := range m.holdable(t) {
		t.Run(id, func(t *testing.T) {
			pair := m.listFiles(t, id)
			h, err := rootlist.ParseHeld(pair.JSON)
			if err != nil {
				t.Fatal(err)
			}
			text := string(pair.JWS)
			// Change one character of each signature in turn: the text after each `"signature":"`.
			n := 0
			for from := 0; ; {
				i := strings.Index(text[from:], `"signature":"`)
				if i < 0 {
					break
				}
				at := from + i + len(`"signature":"`) + 20
				from = at
				c := text[at]
				repl := byte('A')
				if c == 'A' {
					repl = 'B'
				}
				mut := []byte(text)
				mut[at] = repl
				v := rootlist.Verify(rootlist.Signed{JSON: pair.JSON, JWS: mut}, rootlist.HeldTrust(h), before(h.List))
				refuses(t, v, rootlist.SignatureInvalid, 3)
				n++
			}
			if n == 0 {
				t.Fatal("the signature file has no signature to change")
			}
			// A signature file that is no signature file.
			v := rootlist.Verify(rootlist.Signed{JSON: pair.JSON, JWS: pair.JWS[:len(pair.JWS)-1]}, rootlist.HeldTrust(h), before(h.List))
			refuses(t, v, rootlist.Malformed, 1)
		})
	}
}

// retiredHeld is the case that needs no vector: the host holds the list of sequence 8 that drops A
// and carries A's authorisation, which B signed (a revocation), or that A and B signed (a
// retirement).
func TestTheHeldListAgainWhenAKeyHasLeft(t *testing.T) {
	w := newWorld(t)
	revoke := listOf(8, w.b).withRemovals(removalOf(t, w.a))
	retire := listOf(8, w.b)
	for name, c := range map[string]struct {
		list    spec
		signers []*key
	}{
		"a revocation signed by B":           {revoke, []*key{w.b}},
		"a revocation signed by B and by A":  {revoke, []*key{w.b, w.a}},
		"a retirement signed by B":           {retire, []*key{w.b}},
		"a retirement signed by A and B":     {retire, []*key{w.a, w.b}},
		"a retirement signed by B, A and Z":  {retire, []*key{w.b, w.a, w.z}},
		"a list signed by B and by a key Z":  {listOf(8, w.b, w.c), []*key{w.b, w.z}},
		"a list signed by every root key":    {listOf(8, w.a, w.b, w.c), []*key{w.a, w.b, w.c}},
		"a list of a root key and a removal": {listOf(8, w.a).withRemovals(removalOf(t, w.b)), []*key{w.a}},
	} {
		t.Run(name, func(t *testing.T) {
			held := heldOf(t, c.list)
			acceptsAgain(t, rootlist.Verify(signed(t, c.list, c.signers...), held, now))
		})
	}
	t.Run("signed only by a key on no list", func(t *testing.T) {
		held := heldOf(t, revoke)
		refuses(t, rootlist.Verify(signed(t, revoke, w.a), held, now), rootlist.UnknownSigner, 2)
		refuses(t, rootlist.Verify(signed(t, revoke, w.z), held, now), rootlist.UnknownSigner, 2)
		refuses(t, rootlist.Verify(signed(t, revoke, w.a, w.z), held, now), rootlist.UnknownSigner, 2)
	})
	t.Run("a trusted signer and a signature that does not verify", func(t *testing.T) {
		held := heldOf(t, retire)
		good := goodEntry(t, w.b, typList, retire.json())
		p := goodHeader(w.a, typList).text()
		sig := w.a.rawSign(t, []byte(p+"."+b64u(retire.json())))
		sig[10] ^= 1
		bad := entry(p, b64u(sig))
		cand := rootlist.Signed{JSON: retire.json(), JWS: jwsFile(good, bad)}
		refuses(t, rootlist.Verify(cand, held, now), rootlist.SignatureInvalid, 3)
		cand.JWS = jwsFile(bad, good)
		refuses(t, rootlist.Verify(cand, held, now), rootlist.SignatureInvalid, 3)
	})
	t.Run("a signature file that is malformed", func(t *testing.T) {
		held := heldOf(t, revoke)
		cand := rootlist.Signed{JSON: revoke.json(), JWS: []byte(`{"signatures":[]}`)}
		refuses(t, rootlist.Verify(cand, held, now), rootlist.Malformed, 1)
	})
	t.Run("the host's own bytes are not judged again: a removal that would be refused as new", func(t *testing.T) {
		bad := listOf(8, w.b).withRemovals(removalSpec{label: "A", pin: w.a.pin, auth: authorisation(t, w.b)})
		acceptsAgain(t, rootlist.Verify(signed(t, bad, w.b), heldOf(t, bad), now))
		// The same bytes as a list that is new are refused.
		refuses(t, rootlist.Verify(signed(t, bad, w.b), heldOf(t, listOf(7, w.a, w.b)), now), rootlist.RemovalInvalid, 9)
	})
	t.Run("a removal for a key that is on neither list", func(t *testing.T) {
		z := listOf(8, w.b).withRemovals(removalOf(t, w.z))
		acceptsAgain(t, rootlist.Verify(signed(t, z, w.b), heldOf(t, z), now))
	})
	t.Run("the clock still counts", func(t *testing.T) {
		held := heldOf(t, revoke)
		cand := signed(t, revoke, w.b)
		acceptsAgain(t, rootlist.Verify(cand, held, mustTime(expiresAt).Add(-time.Second)))
		refuses(t, rootlist.Verify(cand, held, mustTime(expiresAt)), rootlist.Expired, 11)
	})
	t.Run("a new list is not the held list again, whoever signs it", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b))
		for _, signers := range [][]*key{{w.a}, {w.b}, {w.a, w.b}} {
			accepts(t, rootlist.Verify(signed(t, listOf(8, w.a, w.b), signers...), held, now))
		}
		accepts(t, rootlist.Verify(signed(t, listOf(8, w.b).withRemovals(removalOf(t, w.a)), w.b), held, now))
	})
	t.Run("the same sequence is not enough", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b))
		v := rootlist.Verify(signed(t, listOf(7, w.a, w.b, w.c), w.a, w.b, w.c), held, now)
		refuses(t, v, rootlist.SequenceConflict, 7)
	})
	t.Run("against initial pins nothing is held, so nothing is again", func(t *testing.T) {
		pins := pinsOf(t, w.a.pin, w.b.pin)
		accepts(t, rootlist.Verify(signed(t, listOf(8, w.a, w.b), w.a), pins, now))
		accepts(t, rootlist.Verify(signed(t, listOf(8, w.b).withRemovals(removalOf(t, w.a)), w.b), pins, now))
	})
}

func TestAListWithNoRootKeyHasNoPins(t *testing.T) {
	var nilList *rootlist.List
	if p := nilList.Pins(); len(p) != 0 {
		t.Errorf("Pins() of a nil list is %v", p)
	}
	if p := (&rootlist.List{}).Pins(); len(p) != 0 {
		t.Errorf("Pins() of an empty list is %v", p)
	}
}

func TestEveryRefusalAndEveryNewListSaysItIsNotAgain(t *testing.T) {
	b := newBase(t)
	w := b.w
	// Some refusals of the table, and some new lists: none says Again.
	for name, v := range map[string]rootlist.Verdict{
		"rollback":          b.verify(t, listOf(6, w.a, w.b), w.a),
		"conflict":          b.verify(t, listOf(7, w.a), w.a),
		"unknown signer":    b.verify(t, b.cand, w.z),
		"expired":           b.verify(t, b.cand.at(longAgo), w.a),
		"insufficient":      b.verify(t, listOf(8, w.a), w.a),
		"the empty verdict": rootlist.Verify(rootlist.Signed{}, rootlist.Trust{}, now),
	} {
		if v.Again || v.Accepted {
			t.Errorf("%s: %+v", name, v)
		}
	}
	accepts(t, b.verify(t, b.cand, w.a))
	accepts(t, b.verify(t, listOf(8, w.a, w.b, w.c), w.a, w.b, w.c))
}
