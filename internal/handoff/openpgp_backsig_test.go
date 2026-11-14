package handoff_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// Check 5 for an openpgp-subkey request: the packets are the ones of "The request", one back-signature for
// each listed primary, each of type 0x19 by the subkey over that primary and the subkey, with the issuer
// fingerprint and the issuer key ID of the subkey. A fault is possession-invalid, check 5 fails, and the
// checks after it are not run.

// sigParts are the byte offsets of the parts of a signature packet that this file's writer made: a
// new-format header of two bytes, the body, and in it the two subpacket areas, the hash tag and the two numbers.
type sigParts struct {
	hashed, unhashed, tag, r, s int // offsets in the packet of the first byte of each
	hashedLen, unhashedLen      int
}

func partsOf(t testing.TB, sig []byte) sigParts {
	t.Helper()
	if sig[1] >= 192 {
		t.Fatalf("test setup: the header of the signature is not two bytes: % x", sig[:3])
	}
	body := 2
	var p sigParts
	p.hashedLen = int(sig[body+4])<<8 | int(sig[body+5])
	p.hashed = body + 6
	u := p.hashed + p.hashedLen
	p.unhashedLen = int(sig[u])<<8 | int(sig[u+1])
	p.unhashed = u + 2
	p.tag = p.unhashed + p.unhashedLen
	p.r = p.tag + 2
	rbits := int(sig[p.r])<<8 | int(sig[p.r+1])
	p.s = p.r + 2 + (rbits+7)/8
	return p
}

// refusedAtFive checks that the request is refused with possession-invalid at check 5 and that the detail says
// which back-signature it is (position at is 1-based, 0 when the fault is in the count of packets).
func refusedAtFive(t *testing.T, f *pgpFixture, at int) handoff.Verdict {
	t.Helper()
	v, err := f.checker(nil).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
	if got := statuses(v); got != "ppppfnnnn" {
		t.Errorf("statuses %s, want ppppfnnnn", got)
	}
	switch {
	case at > 0 && !strings.HasPrefix(v.Detail, fmt.Sprintf("back-signature %d: ", at)):
		t.Errorf("the fault is in back-signature %d, and the detail is %q", at, v.Detail)
	case at == 0 && !strings.Contains(v.Detail, "number"):
		t.Errorf("the detail of a fault in the count is %q", v.Detail)
	}
	if v.Detail == "" || !plain(v.Detail) {
		t.Errorf("detail %q", v.Detail)
	}
	return v
}

func TestTheCountOfPacketsAfterTheSubkeyIsTheCountOfPrimaries(t *testing.T) {
	for name, change := range map[string]func(f *pgpFixture){
		"the last back-signature missing":                 func(f *pgpFixture) { f.sigs = f.sigs[:2] },
		"the first back-signature missing":                func(f *pgpFixture) { f.sigs = f.sigs[1:] },
		"no back-signature":                               func(f *pgpFixture) { f.sigs = nil },
		"one back-signature more":                         func(f *pgpFixture) { f.sigs = append(f.sigs, f.sigs[0]) },
		"the first back-signature twice, then the second": func(f *pgpFixture) { f.sigs = [][]byte{f.sigs[0], f.sigs[0], f.sigs[1], f.sigs[2]} },
		"the first twice, the last gone":                  func(f *pgpFixture) { f.sigs = [][]byte{f.sigs[0], f.sigs[0]} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 3, handoff.StoreSoftware)
			change(f)
			v := refusedAtFive(t, f, 0)
			// The detail names both counts.
			if !strings.Contains(v.Detail, fmt.Sprint(len(f.sigs))) || !strings.Contains(v.Detail, "3") {
				t.Errorf("the detail names neither count: %q", v.Detail)
			}
		})
	}
}

func TestTheBackSignaturesInTheWrongPlaceAreRefused(t *testing.T) {
	for name, change := range map[string]func(f *pgpFixture){
		"two back-signatures swapped":               func(f *pgpFixture) { f.sigs[0], f.sigs[1] = f.sigs[1], f.sigs[0] },
		"the last two swapped":                      func(f *pgpFixture) { f.sigs[1], f.sigs[2] = f.sigs[2], f.sigs[1] },
		"the order reversed":                        func(f *pgpFixture) { slices.Reverse(f.sigs) },
		"one signature for the wrong primary twice": func(f *pgpFixture) { f.sigs[2] = f.sigs[1] },
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 3, handoff.StoreSoftware)
			change(f)
			refusedAtFive(t, f, 0+firstDifference(t, f))
		})
	}
}

// firstDifference is the 1-based position of the first back-signature that is not the one of its primary, in
// the fixture as changed.
func firstDifference(t testing.TB, f *pgpFixture) int {
	t.Helper()
	// The fixture is rebuilt with the same keys; each of its signatures is made again by the writer, so two
	// signatures are equal only when they are of one primary.
	for i, sig := range f.sigs {
		if len(sig) == 0 {
			return i + 1
		}
		// a signature of primary i verifies only at place i: the detail says place i+1 for the first that
		// does not.
		want := f.primaries[i]
		if !coversPrimary(f, sig, want) {
			return i + 1
		}
	}
	return 0
}

// coversPrimary tells whether the signature is the one that this writer made for the primary: the hash tag is the
// start of the digest of the data, which depends on the primary.
func coversPrimary(f *pgpFixture, sig []byte, p *pgpKey) bool {
	s := sigSpec{primary: p, sub: f.sub, created: f.sub.created.Add(time.Minute)}
	body := s.body(f.t)
	// Signatures are randomised, but the hash tag is not: it is the first two bytes of the digest.
	got, want := partsOf(f.t, sig), partsOf(f.t, pgpPacket(pgpTagSignature, body))
	return slices.Equal(sig[got.tag:got.tag+2], pgpPacket(pgpTagSignature, body)[want.tag:want.tag+2])
}

func TestAPacketAfterTheSubkeyThatIsNotASignatureIsRefused(t *testing.T) {
	f0 := newPGPFixture(t, 2, handoff.StoreSoftware)
	for name, packet := range map[string][]byte{
		"a user id":               pgpPacket(pgpTagUserID, []byte("Example Person")),
		"a subkey packet":         f0.subPacket,
		"a primary key packet":    pgpPacket(pgpTagPrimary, f0.primaries[0].body()),
		"an empty signature":      pgpPacket(pgpTagSignature, nil),
		"a signature of one byte": pgpPacket(pgpTagSignature, []byte{4}),
		"a literal data packet":   pgpPacket(11, []byte("b\x00\x00\x00\x00\x00\x00\x00\x00")),
		"a marker packet":         pgpPacket(10, []byte("PGP")),
	} {
		for at := range 2 {
			t.Run(fmt.Sprintf("%s at %d", name, at+1), func(t *testing.T) {
				f := newPGPFixture(t, 2, handoff.StoreSoftware)
				f.sigs[at] = packet
				refusedAtFive(t, f, at+1)
			})
		}
	}
}

func TestABackSignatureThatIsNotExactlyTheOneOfThePageIsRefused(t *testing.T) {
	other := newPGPKey(t, pgpPrimaryCreated)
	otherSub := newPGPKey(t, pgpSubCreated)
	late := testNow.Add(time.Second)
	cases := map[string]func(f *pgpFixture, s *sigSpec){
		"type 0x18, the binding":            func(f *pgpFixture, s *sigSpec) { s.sigType = 0x18 },
		"type 0x13, a certification":        func(f *pgpFixture, s *sigSpec) { s.sigType = 0x13 },
		"type 0x01, a text signature":       func(f *pgpFixture, s *sigSpec) { s.sigType = 0x01 },
		"type 0x1F, a direct key signature": func(f *pgpFixture, s *sigSpec) { s.sigType = 0x1F },
		"version 3":                         func(f *pgpFixture, s *sigSpec) { s.version = 3 },
		"version 5":                         func(f *pgpFixture, s *sigSpec) { s.version = 5 },
		"version 6":                         func(f *pgpFixture, s *sigSpec) { s.version = 6 },
		"SHA-256":                           func(f *pgpFixture, s *sigSpec) { s.hashAlgo = 8 },
		"SHA-512":                           func(f *pgpFixture, s *sigSpec) { s.hashAlgo = 10 },
		"SHA-256 with a hash tag that does not tell it": func(f *pgpFixture, s *sigSpec) { s.hashAlgo, s.grindTag = 8, true },
		"SHA-512 with a hash tag that does not tell it": func(f *pgpFixture, s *sigSpec) { s.hashAlgo, s.grindTag = 10, true },
		"made by the primary and not the subkey":        func(f *pgpFixture, s *sigSpec) { s.signer = s.primary },
		"made by another key":                           func(f *pgpFixture, s *sigSpec) { s.signer = other },
		"over another primary":                          func(f *pgpFixture, s *sigSpec) { s.primary = other },
		"no issuer key ID":                              func(f *pgpFixture, s *sigSpec) { s.noUnhashed = true },
		"the issuer key ID of another key":              func(f *pgpFixture, s *sigSpec) { s.unhashed = []subpacket{spIssuerID(other)} },
		"the issuer key ID of the primary":              func(f *pgpFixture, s *sigSpec) { s.unhashed = []subpacket{spIssuerID(s.primary)} },
		"no issuer fingerprint":                         func(f *pgpFixture, s *sigSpec) { s.hashed = []subpacket{spCreated(s.sub.created.Add(time.Minute))} },
		"the issuer fingerprint of another key": func(f *pgpFixture, s *sigSpec) {
			s.hashed = []subpacket{spCreated(s.sub.created.Add(time.Minute)), spIssuerFingerprint(other)}
		},
		"the issuer fingerprint of the primary": func(f *pgpFixture, s *sigSpec) {
			s.hashed = []subpacket{spCreated(s.sub.created.Add(time.Minute)), spIssuerFingerprint(s.primary)}
		},
		"no creation time":     func(f *pgpFixture, s *sigSpec) { s.hashed = []subpacket{spIssuerFingerprint(s.sub)} },
		"no subpacket at all":  func(f *pgpFixture, s *sigSpec) { s.noHashed, s.noUnhashed = true, true },
		"an empty hashed area": func(f *pgpFixture, s *sigSpec) { s.noHashed = true },
		"a creation time twice": func(f *pgpFixture, s *sigSpec) {
			at := s.sub.created.Add(time.Minute)
			s.hashed = []subpacket{spCreated(at), spCreated(at), spIssuerFingerprint(s.sub)}
		},
		"an extra subpacket in the hashed area": func(f *pgpFixture, s *sigSpec) {
			s.hashed = []subpacket{spCreated(s.sub.created.Add(time.Minute)), spIssuerFingerprint(s.sub), {typ: 27, data: []byte{0x02}}}
		},
		"an extra subpacket in the unhashed area": func(f *pgpFixture, s *sigSpec) {
			s.unhashed = []subpacket{spIssuerID(s.sub), {typ: 20, data: []byte("note")}}
		},
		"a signature expiration in the hashed area": func(f *pgpFixture, s *sigSpec) {
			s.hashed = []subpacket{spCreated(s.sub.created.Add(time.Minute)), spIssuerFingerprint(s.sub), {typ: 3, data: []byte{0x7F, 0xFF, 0xFF, 0xFF}}}
		},
		"a signature expiration in the unhashed area": func(f *pgpFixture, s *sigSpec) {
			s.unhashed = []subpacket{spIssuerID(s.sub), {typ: 3, data: []byte{0x7F, 0xFF, 0xFF, 0xFF}}}
		},
		"the creation time marked critical": func(f *pgpFixture, s *sigSpec) {
			c := spCreated(s.sub.created.Add(time.Minute))
			c.critical = true
			s.hashed = []subpacket{c, spIssuerFingerprint(s.sub)}
		},
		"the issuer fingerprint marked critical": func(f *pgpFixture, s *sigSpec) {
			fp := spIssuerFingerprint(s.sub)
			fp.critical = true
			s.hashed = []subpacket{spCreated(s.sub.created.Add(time.Minute)), fp}
		},
		"the issuer key ID marked critical": func(f *pgpFixture, s *sigSpec) {
			id := spIssuerID(s.sub)
			id.critical = true
			s.unhashed = []subpacket{id}
		},
		"made before the subkey":           func(f *pgpFixture, s *sigSpec) { s.created = s.sub.created.Add(-time.Second) },
		"made after the time of the check": func(f *pgpFixture, s *sigSpec) { s.created = late },
		"a byte after the two numbers":     func(f *pgpFixture, s *sigSpec) { s.trailing = []byte{0} },
		"two bytes after the two numbers":  func(f *pgpFixture, s *sigSpec) { s.trailing = []byte{0, 0} },
	}
	for name, change := range cases {
		for at := range 2 {
			t.Run(fmt.Sprintf("%s at %d", name, at+1), func(t *testing.T) {
				f := newPGPFixture(t, 2, handoff.StoreSoftware)
				f.sigs[at] = f.backSig(f.primaries[at], func(s *sigSpec) { change(f, s) })
				refusedAtFive(t, f, at+1)
			})
		}
	}
	// A signature of the same subkey over a subkey packet that is another one: the file holds a subkey that
	// the back-signatures were not made over.
	t.Run("signatures over another subkey", func(t *testing.T) {
		f := newPGPFixture(t, 2, handoff.StoreSoftware)
		f.subPacket = otherSub.subkeyPacket()
		refusedAtFive(t, f, 1)
	})
	// The controls: a creation time at the edges of the allowed range is accepted.
	for name, at := range map[string]time.Time{
		"made at the creation of the subkey": pgpSubCreated,
		"made at the time of the check":      testNow,
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 2, handoff.StoreSoftware)
			f.sigs[1] = f.backSig(f.primaries[1], func(s *sigSpec) { s.created = at })
			f.mustAccept(f.checker(nil))
		})
	}
}

func TestABitChangedInAnyPartOfABackSignatureIsRefused(t *testing.T) {
	f0 := newPGPFixture(t, 2, handoff.StoreSoftware)
	p := partsOf(t, f0.sigs[0])
	// One bit in each part: the version byte, the type, the algorithms, a hashed subpacket (its type, its
	// length, its data), an unhashed one, the hash tag, and each number.
	positions := map[string]int{
		"the version":                  2 * 8,
		"the signature type":           3 * 8,
		"the public-key algorithm":     4*8 + 1,
		"the hash algorithm":           5 * 8,
		"the hashed length":            7*8 + 3,
		"the creation time":            (p.hashed + 3) * 8,
		"the issuer fingerprint":       (p.hashed + 6 + 5) * 8,
		"the unhashed length":          (p.unhashed-1)*8 + 2,
		"the issuer key ID":            (p.unhashed + 4) * 8,
		"the hash tag":                 p.tag*8 + 4,
		"the first number":             (p.r + 10) * 8,
		"the second number":            (p.s + 10) * 8,
		"the end of the second number": (len(f0.sigs[0])-1)*8 + 0,
	}
	for name, bit := range positions {
		for at := range 2 {
			t.Run(fmt.Sprintf("%s at %d", name, at+1), func(t *testing.T) {
				f := newPGPFixture(t, 2, handoff.StoreSoftware)
				pp := partsOf(t, f.sigs[at])
				bitHere := bit
				if strings.Contains(name, "number") || strings.Contains(name, "end") {
					// the offsets of the numbers differ between signatures: take them from this one
					switch name {
					case "the first number":
						bitHere = (pp.r + 10) * 8
					case "the second number":
						bitHere = (pp.s + 10) * 8
					default:
						bitHere = (len(f.sigs[at])-1)*8 + 0
					}
				}
				f.sigs[at] = flipBit(f.sigs[at], bitHere)
				refusedAtFive(t, f, at+1)
			})
		}
	}
}

func TestEveryCutOfABackSignatureAndEveryByteAfterItIsRefusedAsPossessionAndNotAsAForm(t *testing.T) {
	f0 := newPGPFixture(t, 1, handoff.StoreSoftware)
	body := f0.sigs[0][2:]
	// A packet whose body is cut at any length, and written again with the right header, is a whole packet
	// with a damaged body: check 2 passes and check 5 refuses it.
	for n := range len(body) {
		f := newPGPFixture(t, 1, handoff.StoreSoftware)
		f.primaries, f.sub, f.subPacket = f0.primaries, f0.sub, f0.subPacket
		f.sigs = [][]byte{pgpPacket(pgpTagSignature, body[:n])}
		v, err := f.checker(nil).Check(t.Context(), f.request())
		wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
	}
	f0.mustAccept(f0.checker(nil))
}

func TestABackSignatureOfTheSubkeyIsNotAcceptedForAnotherPrimaryEvenWithTheSameKey(t *testing.T) {
	// A primary with the same key and another creation time is another primary: its fingerprint differs, so a
	// back-signature made over the first does not verify over the second.
	f := newPGPFixture(t, 1, handoff.StoreSoftware)
	moved := &pgpKey{priv: f.primaries[0].priv, created: f.primaries[0].created.Add(time.Second)}
	g := newPGPFixture(t, 1, handoff.StoreSoftware)
	g.primaries, g.sub, g.subPacket, g.sigs = []*pgpKey{moved}, f.sub, f.subPacket, f.sigs
	refusedAtFive(t, g, 1)
}

func TestTheSubkeyCreatedAfterTheClockIsRefusedAtCheckFive(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	chk := f.checker(func(c *handoff.Config) { c.Now = func() time.Time { return pgpSubCreated.Add(-time.Second) } })
	v, err := chk.Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
	if !strings.Contains(v.Detail, "subkey") {
		t.Errorf("detail %q", v.Detail)
	}
	// At the creation time itself the subkey is not created after the check, and the signatures (a minute
	// later) are: the refusal is of the signatures.
	chk = f.checker(func(c *handoff.Config) { c.Now = func() time.Time { return pgpSubCreated } })
	v, err = chk.Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
	if !strings.HasPrefix(v.Detail, "back-signature 1: ") {
		t.Errorf("detail %q", v.Detail)
	}
}

// The first fault is the one told: the earlier position, whatever stands after it.

func TestTheFirstBadBackSignatureIsTheOneTold(t *testing.T) {
	f := newPGPFixture(t, 3, handoff.StoreSoftware)
	f.sigs[1] = flipBit(f.sigs[1], 8*partsOf(t, f.sigs[1]).tag+1)
	f.sigs[2] = pgpPacket(pgpTagUserID, []byte("x"))
	refusedAtFive(t, f, 2)
	g := newPGPFixture(t, 3, handoff.StoreSoftware)
	g.sigs[0] = pgpPacket(pgpTagUserID, []byte("x"))
	g.sigs[2] = pgpPacket(pgpTagUserID, []byte("x"))
	refusedAtFive(t, g, 1)
}
