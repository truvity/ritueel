package openpgp_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// ReadRevocation reads exactly what RevocationSignature writes and verifies it with the primary
// (docs/reference/revocation-material.md, "What is made"; record 0007, rules 21 and 23). The tests
// build each signature with their own signer and packet writer, so that every refusal is for the
// one thing that was changed: the signature still verifies over the bytes it has.

func TestReadRevocationAcceptsWhatRevocationSignatureWritesForEachReason(t *testing.T) {
	k := newRevKit(t, "accept")
	for _, c := range allReasons {
		t.Run(c.name, func(t *testing.T) {
			pkt := k.made(t, c.r)
			rev := k.assertRevoked(t, c.name, pkt, c.r)
			if rev == nil {
				return
			}
			// The same digest and time again on a second read: nothing is kept between calls.
			again := k.assertRevoked(t, c.name+" again", pkt, c.r)
			if again == nil || *again != *rev {
				t.Errorf("a second read gives %+v, the first gave %+v", again, rev)
			}
			// A zero Revocation holds nothing, so that one that was never read accepts nothing.
			var zero openpgp.Revocation
			if zero.Issuer != "" || zero.SHA256 != "" || !zero.Created.IsZero() || zero.Reason != (openpgp.Reason{}) {
				t.Errorf("the zero Revocation holds %+v", zero)
			}
		})
	}
}

// The tests' own writer and RevocationSignature write signatures that one reader reads, and the two
// have the same layout, so that the hand-built signatures of the refusal tests differ from a good one
// in the one thing that each changes.
func TestTheTestsOwnRevocationSignatureHasTheLayoutOfTheOneThatTheCodeWrites(t *testing.T) {
	k := newRevKit(t, "layout")
	for _, c := range allReasons {
		t.Run(c.name, func(t *testing.T) {
			mine := k.build(t, c.r, nil)
			made := k.made(t, c.r)
			if len(mine) != len(made) {
				// ECDSA numbers differ by a byte now and then: the two lengths may differ by at most 2.
				if d := len(mine) - len(made); d > 2 || d < -2 {
					t.Errorf("the hand-built signature has %d bytes, the written one %d", len(mine), len(made))
				}
			}
			a, b := parseSig(t, bodyOf(t, mine)), parseSig(t, bodyOf(t, made))
			if !bytes.Equal(a.HashedRaw, b.HashedRaw) || !bytes.Equal(a.UnhashedRaw, b.UnhashedRaw) {
				t.Error("the two signatures have other subpackets")
			}
			k.assertRevoked(t, "hand-built", mine, c.r)
		})
	}
}

func TestReadRevocationReturnsTheCreationTimeOfTheSignatureInUTC(t *testing.T) {
	k := newRevKit(t, "time")
	for name, at := range map[string]time.Time{
		"the creation time of the key": created,
		"a second after":               created.Add(time.Second),
		"the ceremony time":            ceremony,
		"the last second of the field": time.Unix(1<<32-1, 0).UTC(),
	} {
		t.Run(name, func(t *testing.T) {
			pkt := k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed[0].Data = u32(uint32(at.Unix())) })
			rev, err := k.read(t, name, pkt)
			if err != nil {
				t.Fatalf("ReadRevocation: %v", err)
			}
			if !rev.Created.Equal(at) || rev.Created.Location() != time.UTC {
				t.Errorf("the creation time is %v, want %v in UTC", rev.Created, at)
			}
		})
	}
}

// A signature dated before its key is refused, one dated at the creation time of the key is not, and
// no clock is read: a signature dated in the far future is read (docs: the reader reads no clock).
func TestReadRevocationHoldsTheCreationTimeToTheCreationOfThePrimary(t *testing.T) {
	k := newRevKit(t, "created")
	at := func(sec int64) func(*sigSpec) {
		return func(sp *sigSpec) { sp.Hashed[0].Data = u32(uint32(sec)) }
	}
	k.assertNotRevoked(t, "one second before the key", k.build(t, openpgp.Compromised, at(created.Unix()-1)), false)
	k.assertNotRevoked(t, "time zero", k.build(t, openpgp.Compromised, at(0)), false)
	k.assertNotRevoked(t, "the year 1970 and a second", k.build(t, openpgp.Compromised, at(1)), false)
	k.assertNotRevoked(t, "a day before the key", k.build(t, openpgp.Superseded, at(created.Unix()-86400)), false)
	if _, err := k.read(t, "at the creation of the key", k.build(t, openpgp.Compromised, at(created.Unix()))); err != nil {
		t.Errorf("a signature dated at the creation of its key is refused: %v", err)
	}
	if _, err := k.read(t, "far in the future", k.build(t, openpgp.Compromised, at(1<<32-1))); err != nil {
		t.Errorf("a signature dated in 2106 is refused: %v", err)
	}
}

func TestReadRevocationRefusesAPacketOfAnotherPrimary(t *testing.T) {
	k := newRevKit(t, "one")
	other := newRevKit(t, "two")
	for _, c := range allReasons {
		pkt := k.made(t, c.r)
		other.assertNotRevoked(t, c.name+" by another primary", pkt, false)
		k.assertRevoked(t, c.name+" by its own", pkt, c.r) // the control
	}
	// A signature that claims the issuer of the primary and is made with another key does not verify.
	forged := other.build(t, openpgp.Compromised, func(sp *sigSpec) {
		sp.Hashed[2].Data = append([]byte{4}, k.fp...)
		sp.Unhashed[0].Data = bytes.Clone(k.fp[12:])
	})
	k.assertNotRevoked(t, "a forged issuer", forged, false)
	// The same, with the issuer of the other key, is a signature that the other key reads.
	other.assertRevoked(t, "the control of the forged issuer", other.build(t, openpgp.Compromised, nil), openpgp.Compromised)
}

func TestReadRevocationRefusesANilAndAZeroPrimary(t *testing.T) {
	k := newRevKit(t, "nil")
	pkt := k.made(t, openpgp.Compromised)
	for name, p := range map[string]*openpgp.PrimaryKey{"a nil primary": nil, "a zero primary": {}} {
		t.Run(name, func(t *testing.T) {
			assertRevocationRefused(t, name, pkt, p, false, hex.EncodeToString(k.fp))
		})
	}
	for name, in := range map[string][]byte{"a nil packet": nil, "an empty packet": {}} {
		t.Run(name+" and a nil primary", func(t *testing.T) {
			assertRevocationRefused(t, name, in, nil, false, hex.EncodeToString(k.fp))
		})
		t.Run(name, func(t *testing.T) {
			k.assertNotRevoked(t, name, in, false)
		})
	}
}

// Each byte of a good packet changed, one at a time and in three ways, is refused. A byte that a reader
// takes no notice of would show here as an acceptance, and the test names its position.
func TestReadRevocationRefusesEveryByteOfAGoodPacketChanged(t *testing.T) {
	k := newRevKit(t, "flip")
	for _, c := range allReasons {
		t.Run(c.name, func(t *testing.T) {
			pkt := k.made(t, c.r)
			k.assertRevoked(t, "the control", pkt, c.r)
			for i := range pkt {
				for _, mask := range []byte{0x01, 0x80, 0xFF} {
					bad := bytes.Clone(pkt)
					bad[i] ^= mask
					if rev, err := k.read(t, fmt.Sprintf("byte %d ^ %#x", i, mask), bad); err == nil || rev != nil {
						t.Errorf("byte %d of %d xor %#x: the packet is accepted (%+v)", i, len(pkt), mask, rev)
					}
				}
			}
		})
	}
}

func TestReadRevocationRefusesEveryCutAndEveryExtensionOfAGoodPacket(t *testing.T) {
	k := newRevKit(t, "cut")
	pkt := k.made(t, openpgp.Superseded)
	for n := 0; n < len(pkt); n++ {
		k.assertNotRevoked(t, fmt.Sprintf("the first %d of %d bytes", n, len(pkt)), pkt[:n], false)
	}
	for _, extra := range [][]byte{{0}, {0xC2, 0x00}, {0xFF, 0xFF}, k.made(t, openpgp.Superseded), bytes.Repeat([]byte{7}, 100)} {
		k.assertNotRevoked(t, fmt.Sprintf("%d bytes after", len(extra)), cat(pkt, extra), false)
	}
	for _, extra := range [][]byte{{0}, {1, 2, 3}} {
		k.assertNotRevoked(t, fmt.Sprintf("%d bytes before", len(extra)), cat(extra, pkt), false)
	}
}

func TestReadRevocationRefusesAHeaderThatIsNotTheShortestOfTheNewFormat(t *testing.T) {
	k := newRevKit(t, "header")
	body := bodyOf(t, k.made(t, openpgp.Compromised))
	k.assertRevoked(t, "the control", wrap(tagSignature, body), openpgp.Compromised)
	for _, form := range []string{"new5", "old1", "old2", "old4"} {
		pkt, ok := packetIn(form, tagSignature, body)
		if !ok {
			t.Fatalf("the form %s does not hold the body", form)
		}
		k.assertNotRevoked(t, form, pkt, false)
	}
	k.assertNotRevoked(t, "a partial length", cat([]byte{0xC0 | tagSignature, 0xE0}, body), false)
	k.assertNotRevoked(t, "an indeterminate length", cat([]byte{0x80 | tagSignature<<2 | 3}, body), false)
	k.assertNotRevoked(t, "a length past the packet", cat([]byte{0xC0 | tagSignature, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, body), false)
	k.assertNotRevoked(t, "a tag of a key packet", wrap(tagPublicKey, body), false)
	k.assertNotRevoked(t, "a tag of a subkey packet", wrap(tagSubkey, body), false)
	k.assertNotRevoked(t, "a tag of a user ID", wrap(tagUserID, body), false)
	k.assertNotRevoked(t, "a header with no body", []byte{0xC0 | tagSignature, 0}, false)
}

// The text of a refusal of the frame says that the bytes are not one signature packet, so that a person
// who gave the wrong file is told so before any word about a reason or a key.
func TestReadRevocationSaysWhenTheBytesAreNotOneSignaturePacket(t *testing.T) {
	k := newRevKit(t, "frame text")
	good := k.made(t, openpgp.Compromised)
	for name, in := range map[string][]byte{
		"a nil packet":    nil,
		"a cut packet":    good[:len(good)-1],
		"two packets":     cat(good, good),
		"a key packet":    wrap(tagPublicKey, bodyOf(t, good)),
		"a text":          []byte("hello"),
		"a byte after":    cat(good, []byte{0}),
		"a partial first": cat([]byte{0xC2, 0xE0}, bodyOf(t, good)),
	} {
		_, err := k.read(t, name, in)
		if err == nil || !strings.Contains(err.Error(), "not one signature packet") {
			t.Errorf("%s: the refusal is %v, want a text that holds %q", name, err, "not one signature packet")
		}
	}
}

func TestReadRevocationRefusesAFieldThatIsNotTheProfile(t *testing.T) {
	k := newRevKit(t, "fields")
	patched := func(f func(body []byte)) []byte {
		body := bodyOf(t, k.made(t, openpgp.Compromised))
		f(body)
		return withBody(body)
	}
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"version 5", patched(func(b []byte) { b[0] = 5 })},
		{"version 3", patched(func(b []byte) { b[0] = 3 })},
		{"version 6", patched(func(b []byte) { b[0] = 6 })},
		{"the algorithm EdDSA", patched(func(b []byte) { b[2] = 22 })},
		{"the algorithm RSA", patched(func(b []byte) { b[2] = 1 })},
		{"the hash SHA-512 in the field", patched(func(b []byte) { b[3] = 10 })},
		{"the hash SHA-256 in the field", patched(func(b []byte) { b[3] = 8 })},
		{"the type 0x28 in the field", patched(func(b []byte) { b[1] = 0x28 })},
		{"the type 0x18 in the field", patched(func(b []byte) { b[1] = 0x18 })},
		{"the type 0x13 in the field", patched(func(b []byte) { b[1] = 0x13 })},
		{"the type 0x00 in the field", patched(func(b []byte) { b[1] = 0x00 })},
		{"the type 0x1F in the field", patched(func(b []byte) { b[1] = 0x1F })},
		{"a hashed length that runs past the body", patched(func(b []byte) { b[4], b[5] = 0xFF, 0xFF })},
		{"a hashed length of zero", patched(func(b []byte) { b[4], b[5] = 0, 0 })},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { k.assertNotRevoked(t, c.name, c.pkt, false) })
	}
}

// The signatures that the hand-built spec writes with another type, hash or other number layout, each
// made over the digest that it claims, so that the signature verifies and the shape is what is refused.
func TestReadRevocationRefusesAnotherTypeHashAndLayoutOfASignatureThatVerifies(t *testing.T) {
	k := newRevKit(t, "verifying")
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"a subkey revocation 0x28", func(sp *sigSpec) { sp.Type = 0x28 }},
		{"a subkey binding 0x18", func(sp *sigSpec) { sp.Type = 0x18 }},
		{"a positive certification 0x13", func(sp *sigSpec) { sp.Type = 0x13 }},
		{"a certification revocation 0x30", func(sp *sigSpec) { sp.Type = 0x30 }},
		{"a binary signature 0x00", func(sp *sigSpec) { sp.Type = 0x00 }},
		{"a direct key signature 0x1F", func(sp *sigSpec) { sp.Type = 0x1F }},
		{"SHA-256", func(sp *sigSpec) { sp.Hash = 8 }},
		{"SHA-512", func(sp *sigSpec) { sp.Hash = 10 }},
		{"a wrong start of the digest in the first byte", func(sp *sigSpec) { sp.TagXOR = [2]byte{1, 0} }},
		{"a wrong start of the digest in the second byte", func(sp *sigSpec) { sp.TagXOR = [2]byte{0, 0x80} }},
		{"a byte after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{0} }},
		{"two bytes after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{1, 2} }},
		{"no second number", func(sp *sigSpec) { sp.Numbers = func(r, s *big.Int) []byte { return mpi(r) } }},
		{"no numbers", func(sp *sigSpec) { sp.Numbers = func(r, s *big.Int) []byte { return nil } }},
		{"the numbers swapped", func(sp *sigSpec) { sp.Numbers = func(r, s *big.Int) []byte { return append(mpi(s), mpi(r)...) } }},
		{"a first number with a leading zero byte", func(sp *sigSpec) {
			sp.Numbers = func(r, s *big.Int) []byte {
				return append(append([]byte{byte((r.BitLen() + 8) >> 8), byte(r.BitLen() + 8), 0}, r.Bytes()...), mpi(s)...)
			}
		}},
		{"a number whose bit length is one too many", func(sp *sigSpec) {
			sp.Numbers = func(r, s *big.Int) []byte {
				m := mpi(r)
				m[1]++
				return append(m, mpi(s)...)
			}
		}},
		{"a number of zero bits", func(sp *sigSpec) {
			sp.Numbers = func(r, s *big.Int) []byte { return append([]byte{0, 0}, mpi(s)...) }
		}},
		{"a second number longer than the packet", func(sp *sigSpec) {
			sp.Numbers = func(r, s *big.Int) []byte { return append(mpi(r), 0x0F, 0xFF, 1) }
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			k.assertNotRevoked(t, c.name, k.build(t, openpgp.Compromised, c.tweak), false)
		})
	}
}

// The fixed fields, signed again over the claim that they make: the signature verifies with SHA-384 over
// the bytes it holds, and the type, the algorithm or the hash that it names is not the profile's.
func TestReadRevocationRefusesAFieldThatIsNotTheProfileWhenTheSignatureVerifiesOverIt(t *testing.T) {
	k := newRevKit(t, "resigned")
	for _, c := range allReasons {
		k.assertRevoked(t, "the control, signed again with no change", k.resigned(t, c.r, func([]byte) {}), c.r)
	}
	for name, patch := range map[string]func([]byte){
		"the type 0x28":    func(b []byte) { b[1] = 0x28 },
		"the type 0x18":    func(b []byte) { b[1] = 0x18 },
		"the type 0x13":    func(b []byte) { b[1] = 0x13 },
		"the type 0x1F":    func(b []byte) { b[1] = 0x1F },
		"the type 0x00":    func(b []byte) { b[1] = 0x00 },
		"the algorithm 22": func(b []byte) { b[2] = 22 },
		"the algorithm 18": func(b []byte) { b[2] = 18 },
		"the algorithm 1":  func(b []byte) { b[2] = 1 },
		"the hash 8":       func(b []byte) { b[3] = 8 },
		"the hash 10":      func(b []byte) { b[3] = 10 },
		"the hash 11":      func(b []byte) { b[3] = 11 },
		"the hash 2":       func(b []byte) { b[3] = 2 },
		"the version 5":    func(b []byte) { b[0] = 5 },
		"the version 3":    func(b []byte) { b[0] = 3 },
	} {
		t.Run(name, func(t *testing.T) { k.assertNotRevoked(t, name, k.resigned(t, openpgp.Compromised, patch), false) })
	}
}

// A signature that holds the right subpackets and was made over other bytes than the key packet alone
// does not verify.
func TestReadRevocationRefusesASignatureOverOtherBytes(t *testing.T) {
	k := newRevKit(t, "over")
	other := newRevKit(t, "over other")
	key := &k.key.PublicKey
	for _, c := range []struct {
		name string
		data [][]byte
		by   *revKit
	}{
		{"nothing before the fields", nil, nil},
		{"the key packet with another creation time", [][]byte{hashPrefix(key, created.Add(time.Second))}, nil},
		{"the key packet of another key", [][]byte{hashPrefix(&other.key.PublicKey, created)}, nil},
		{"the key packet twice", [][]byte{hashPrefix(key, created), hashPrefix(key, created)}, nil},
		{"the key packet and a user ID", [][]byte{hashPrefix(key, created), cat([]byte{0xB4, 0, 0, 0, 3}, []byte("abc"))}, nil},
		{"a subkey the way a binding is made", [][]byte{hashPrefix(key, created), hashPrefix(&other.key.PublicKey, created)}, nil},
		{"the key packet and the key packet of another", [][]byte{hashPrefix(&other.key.PublicKey, created), hashPrefix(key, created)}, nil},
		{"the key packet cut by one byte", [][]byte{hashPrefix(key, created)[:len(hashPrefix(key, created))-1]}, nil},
		{"the key packet and a byte", [][]byte{cat(hashPrefix(key, created), []byte{0})}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			pkt := k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Data = c.data })
			k.assertNotRevoked(t, c.name, pkt, false)
		})
	}
	t.Run("a signature by another key with the issuer of this one", func(t *testing.T) {
		pkt := k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Key = other.key })
		k.assertNotRevoked(t, "signed by another key", pkt, false)
	})
}

// The reason: a missing one, an unknown code, a word that does not go with the code, an empty one are
// an ErrRevocationReason; two of them are an ErrRevocation and no ErrRevocationReason.
func TestReadRevocationRefusesAReasonThatIsNotOneOfTheFour(t *testing.T) {
	k := newRevKit(t, "reason")
	reasonOf := func(data []byte) func(*sigSpec) {
		return func(sp *sigSpec) { sp.Hashed[1].Data = data }
	}
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"no reason subpacket", func(sp *sigSpec) { sp.Hashed = []sub{sp.Hashed[0], sp.Hashed[2]} }},
		{"no reason and a key flags subpacket in its place", func(sp *sigSpec) { sp.Hashed[1] = sub{Type: 27, Data: []byte{1}} }},
		{"a reason subpacket that is empty", reasonOf(nil)},
		{"a reason subpacket of the code only, compromised", reasonOf([]byte{2})},
		{"a reason subpacket of the code only, no reason", reasonOf([]byte{0})},
		{"the code 4 with a word", reasonOf(append([]byte{4}, "key-material"...))},
		{"the code 9", reasonOf(append([]byte{9}, "compromised"...))},
		{"the code 32 with a word", reasonOf(append([]byte{32}, "retired"...))},
		{"the code 255", reasonOf(append([]byte{255}, "compromised"...))},
		{"the code 2 and the word of 1", reasonOf(append([]byte{2}, "superseded"...))},
		{"the code 1 and the word of 2", reasonOf(append([]byte{1}, "compromised"...))},
		{"the code 3 and the word of 0", reasonOf(append([]byte{3}, "no-reason"...))},
		{"the code 0 and the word of 3", reasonOf(append([]byte{0}, "retired"...))},
		{"the word in capitals", reasonOf(append([]byte{2}, "Compromised"...))},
		{"the word with a space after it", reasonOf(append([]byte{2}, "compromised "...))},
		{"the word cut by a letter", reasonOf(append([]byte{2}, "compromise"...))},
		{"the word with a letter more", reasonOf(append([]byte{2}, "compromisedd"...))},
		{"the word with a zero byte", reasonOf(append([]byte{2}, "compromised\x00"...))},
		{"the word with a space for the hyphen", reasonOf(append([]byte{0}, "no reason"...))},
		{"no word", reasonOf([]byte{1})},
		{"a word that is not text", reasonOf([]byte{2, 0xFF, 0xFE, 0xFD})},
		{"a long word", reasonOf(append([]byte{2}, bytes.Repeat([]byte("compromised"), 20)...))},
	} {
		t.Run(c.name, func(t *testing.T) {
			k.assertNotRevoked(t, c.name, k.build(t, openpgp.Compromised, c.tweak), true)
		})
	}
	t.Run("two reason subpackets", func(t *testing.T) {
		twice := k.build(t, openpgp.Compromised, func(sp *sigSpec) {
			sp.Hashed = append(sp.Hashed, sub{Type: 29, Data: append([]byte{2}, "compromised"...)})
		})
		k.assertNotRevoked(t, "the same reason twice", twice, false)
		other := k.build(t, openpgp.Compromised, func(sp *sigSpec) {
			sp.Hashed = append(sp.Hashed, sub{Type: 29, Data: append([]byte{1}, "superseded"...)})
		})
		k.assertNotRevoked(t, "two different reasons", other, false)
		bad := k.build(t, openpgp.Compromised, func(sp *sigSpec) {
			sp.Hashed = append(sp.Hashed, sub{Type: 29, Data: []byte{9}})
		})
		k.assertNotRevoked(t, "a good reason and a bad one", bad, false)
	})
	t.Run("the reason in the unhashed area only", func(t *testing.T) {
		pkt := k.build(t, openpgp.Compromised, func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sub{Type: 29, Data: append([]byte{2}, "compromised"...)})
			sp.Hashed = []sub{sp.Hashed[0], sp.Hashed[2]}
		})
		k.assertNotRevoked(t, "the unhashed reason", pkt, true)
	})
	t.Run("no reason and no issuer is a fault of the issuer, which is read first", func(t *testing.T) {
		k.assertNotRevoked(t, "only the creation time", k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed = sp.Hashed[:1] }), false)
		k.assertNotRevoked(t, "no hashed subpacket", k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed = nil }), false)
	})
	t.Run("each of the four is read, with the word of the table", func(t *testing.T) {
		for _, c := range allReasons {
			k.assertRevoked(t, c.name, k.build(t, c.r, nil), c.r)
		}
	})
}

// The reason is judged before the count: a packet with no reason and one more subpacket is a fault of
// the reason, and a packet with a good reason and one more subpacket is a fault of the shape.
func TestReadRevocationJudgesTheReasonBeforeTheCountOfSubpackets(t *testing.T) {
	k := newRevKit(t, "order")
	noReasonAndExtra := k.build(t, openpgp.Compromised, func(sp *sigSpec) {
		sp.Hashed = []sub{sp.Hashed[0], sp.Hashed[2], {Type: 27, Data: []byte{1}}}
	})
	k.assertNotRevoked(t, "no reason and a key flags subpacket", noReasonAndExtra, true)
	goodAndExtra := k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 27, Data: []byte{1}}) })
	k.assertNotRevoked(t, "a good reason and a key flags subpacket", goodAndExtra, false)
}

func TestReadRevocationRefusesASubpacketMarkedCritical(t *testing.T) {
	k := newRevKit(t, "critical")
	for i, name := range []string{"the creation time", "the reason", "the issuer fingerprint"} {
		k.assertNotRevoked(t, "critical "+name, k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed[i].Critical = true }), false)
	}
	k.assertNotRevoked(t, "critical issuer key ID", k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Unhashed[0].Critical = true }), false)
	k.assertNotRevoked(t, "all critical", k.build(t, openpgp.Compromised, func(sp *sigSpec) {
		for i := range sp.Hashed {
			sp.Hashed[i].Critical = true
		}
		sp.Unhashed[0].Critical = true
	}), false)
}

func TestReadRevocationRefusesASubpacketThatIsNotInTheSet(t *testing.T) {
	k := newRevKit(t, "extra")
	extras := []sub{
		{Type: 27, Data: []byte{0x01}},                // key flags
		{Type: 9, Data: u32(1000)},                    // key expiration
		{Type: 3, Data: u32(1000)},                    // signature expiration
		{Type: 100, Data: []byte{1}},                  // a type of nobody's
		{Type: 100, Critical: true, Data: []byte{1}},  // the same, critical
		{Type: 16, Data: bytes.Repeat([]byte{1}, 8)},  // a key ID in the hashed area
		{Type: 33, Data: append([]byte{4}, k.fp...)},  // a second issuer fingerprint
		{Type: 2, Data: u32(uint32(ceremony.Unix()))}, // a second creation time
		{Type: 32, Data: []byte{1, 2, 3}},             // an embedded signature
		{Type: 26, Data: []byte{1}},                   // a policy URI of a kind
		{Type: 20, Data: []byte{1, 2}},                // a notation
	}
	for _, e := range extras {
		t.Run(fmt.Sprintf("hashed type %d critical %v", e.Type, e.Critical), func(t *testing.T) {
			k.assertNotRevoked(t, "in the hashed area", k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, e) }), false)
		})
		t.Run(fmt.Sprintf("unhashed type %d critical %v", e.Type, e.Critical), func(t *testing.T) {
			k.assertNotRevoked(t, "in the unhashed area", k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, e) }), false)
		})
	}
	t.Run("an empty subpacket", func(t *testing.T) {
		k.assertNotRevoked(t, "an empty hashed subpacket", k.build(t, openpgp.Compromised, func(sp *sigSpec) {
			sp.Hashed = append(sp.Hashed, sub{Type: 100})
		}), false)
	})
	t.Run("a missing creation time", func(t *testing.T) {
		k.assertNotRevoked(t, "no creation time", k.build(t, openpgp.Compromised, func(sp *sigSpec) {
			sp.Hashed = []sub{sp.Hashed[1], sp.Hashed[2], {Type: 27, Data: []byte{1}}}
		}), false)
	})
	t.Run("the unhashed area empty", func(t *testing.T) {
		k.assertNotRevoked(t, "no key ID", k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Unhashed = nil }), false)
	})
	t.Run("the unhashed area is not the key ID but the same bytes of another kind", func(t *testing.T) {
		k.assertNotRevoked(t, "a notation with the key ID", k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Unhashed[0].Type = 20 }), false)
	})
}

func TestReadRevocationHoldsTheIssuerToTheFingerprintOfThePrimary(t *testing.T) {
	k := newRevKit(t, "issuer")
	other := newRevKit(t, "issuer other")
	fpOf := func(v byte, fp []byte) []byte { return append([]byte{v}, fp...) }
	cases := []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"no issuer fingerprint", func(sp *sigSpec) { sp.Hashed = sp.Hashed[:2] }},
		{"the issuer fingerprint in the unhashed area", func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sp.Hashed[2])
			sp.Hashed = sp.Hashed[:2]
		}},
		{"the fingerprint of another key", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(4, other.fp) }},
		{"the fingerprint with its last byte changed", func(sp *sigSpec) { sp.Hashed[2].Data[20] ^= 1 }},
		{"the fingerprint with its first byte changed", func(sp *sigSpec) { sp.Hashed[2].Data[1] ^= 1 }},
		{"a version 5 fingerprint of 32 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(5, bytes.Repeat([]byte{1}, 32)) }},
		{"a version 5 byte on the 20 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(5, k.fp) }},
		{"a version 3 byte on the 20 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(3, k.fp) }},
		{"a fingerprint of 19 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(4, k.fp[:19]) }},
		{"a fingerprint of 21 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(4, append(bytes.Clone(k.fp), 0)) }},
		{"no version byte", func(sp *sigSpec) { sp.Hashed[2].Data = bytes.Clone(k.fp) }},
		{"an empty fingerprint subpacket", func(sp *sigSpec) { sp.Hashed[2].Data = nil }},
		{"the key ID of another key", func(sp *sigSpec) { sp.Unhashed[0].Data = bytes.Clone(other.fp[12:]) }},
		{"the key ID with a byte changed", func(sp *sigSpec) { sp.Unhashed[0].Data[7] ^= 1 }},
		{"the key ID of 7 bytes", func(sp *sigSpec) { sp.Unhashed[0].Data = sp.Unhashed[0].Data[1:] }},
		{"the key ID of 9 bytes", func(sp *sigSpec) { sp.Unhashed[0].Data = append([]byte{0}, sp.Unhashed[0].Data...) }},
		{"the first 8 bytes of the fingerprint as the key ID", func(sp *sigSpec) { sp.Unhashed[0].Data = bytes.Clone(k.fp[:8]) }},
		{"the key ID in the hashed area and the fingerprint in the unhashed", func(sp *sigSpec) {
			sp.Hashed[2], sp.Unhashed[0] = sp.Unhashed[0], sp.Hashed[2]
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { k.assertNotRevoked(t, c.name, k.build(t, openpgp.Compromised, c.tweak), false) })
	}
}

func TestReadRevocationHoldsTheCreationTimeSubpacketToFourBytes(t *testing.T) {
	k := newRevKit(t, "four")
	for name, data := range map[string][]byte{
		"no bytes":     nil,
		"three bytes":  u32(uint32(ceremony.Unix()))[:3],
		"five bytes":   append(u32(uint32(ceremony.Unix())), 0),
		"eight bytes":  append(u32(0), u32(uint32(ceremony.Unix()))...),
		"a single one": {1},
	} {
		t.Run(name, func(t *testing.T) {
			k.assertNotRevoked(t, name, k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed[0].Data = data }), false)
		})
	}
}

// The two bounds are checked before anything is read: a body over 512 bytes, and more than 32
// subpackets in an area. Each is also a shape that is refused, so the text of the error is what shows
// which check refused it.
func TestReadRevocationChecksTheBoundsBeforeItReadsTheSubpackets(t *testing.T) {
	k := newRevKit(t, "bounds")
	// padded makes a signature whose body has exactly n bytes, with one subpacket of an unknown type in
	// the unhashed area (or the hashed area) that holds the rest.
	padded := func(n int, hashed bool) []byte {
		pad := 300
		for range 4 {
			pkt := k.build(t, openpgp.Compromised, func(sp *sigSpec) {
				e := sub{Type: 100, Data: bytes.Repeat([]byte{1}, pad)}
				if hashed {
					sp.Hashed = append(sp.Hashed, e)
				} else {
					sp.Unhashed = append(sp.Unhashed, e)
				}
			})
			got := len(bodyOf(t, pkt))
			if got == n {
				return pkt
			}
			pad += n - got
		}
		t.Fatalf("no signature of a body of %d bytes", n)
		return nil
	}
	for _, hashed := range []bool{false, true} {
		area := map[bool]string{false: "unhashed", true: "hashed"}[hashed]
		t.Run("512 bytes of body in the "+area+" area is read as a shape", func(t *testing.T) {
			pkt := padded(512, hashed)
			k.assertNotRevoked(t, "512 bytes", pkt, false)
			if _, err := k.read(t, "512 bytes", pkt); err != nil && strings.Contains(err.Error(), "longer than") {
				t.Errorf("a body of exactly 512 bytes is refused as too long: %v", err)
			}
		})
		t.Run("513 bytes of body in the "+area+" area is refused as too long", func(t *testing.T) {
			pkt := padded(513, hashed)
			k.assertNotRevoked(t, "513 bytes", pkt, false)
			if _, err := k.read(t, "513 bytes", pkt); err == nil || !strings.Contains(err.Error(), "longer than 512") {
				t.Errorf("a body of 513 bytes is refused with %v, want the text to say that it is longer than 512 bytes", err)
			}
		})
	}
	filler := func(n int) []sub {
		var out []sub
		for i := range n {
			out = append(out, sub{Type: byte(100 + i%20), Data: []byte{1}})
		}
		return out
	}
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
		limit bool
	}{
		{"32 subpackets in the hashed area", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, filler(29)...) }, false},
		{"33 subpackets in the hashed area", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, filler(30)...) }, true},
		{"32 subpackets in the unhashed area", func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, filler(31)...) }, false},
		{"33 subpackets in the unhashed area", func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, filler(32)...) }, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			pkt := k.build(t, openpgp.Compromised, c.tweak)
			k.assertNotRevoked(t, c.name, pkt, false)
			_, err := k.read(t, c.name, pkt)
			if got := err != nil && strings.Contains(err.Error(), "more subpackets"); got != c.limit {
				t.Errorf("the refusal %v says that there are more subpackets than the limit: %v, want %v", err, got, c.limit)
			}
		})
	}
}

// A hostile length does not make the reader allocate or crash: a length field of 4 GiB, a hashed area
// that runs past the packet, and a signature that is only a header.
func TestReadRevocationRefusesHostileLengthsWithoutCrashing(t *testing.T) {
	k := newRevKit(t, "hostile")
	good := bodyOf(t, k.made(t, openpgp.Compromised))
	for name, pkt := range map[string][]byte{
		"a length of 4 GiB":             cat([]byte{0xC0 | tagSignature, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, good),
		"a length of 2 GiB":             cat([]byte{0xC0 | tagSignature, 0xFF, 0x80, 0, 0, 0}, good),
		"an old length of 4 GiB":        cat([]byte{0x80 | tagSignature<<2 | 2, 0xFF, 0xFF, 0xFF, 0xFF}, good),
		"a hashed area of 64 KiB":       withBody(append([]byte{4, 0x20, 19, 9, 0xFF, 0xFF}, good[6:]...)),
		"an unhashed area of 64 KiB":    withBody(cat(good[:6+int(good[4])<<8+int(good[5])], []byte{0xFF, 0xFF}, good[8+int(good[4])<<8+int(good[5]):])),
		"a subpacket of 4 GiB":          withBody(cat([]byte{4, 0x20, 19, 9, 0, 8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2, 0, 0}, []byte{0, 0})),
		"a subpacket length past it":    withBody(cat([]byte{4, 0x20, 19, 9, 0, 3, 50, 2, 0, 0, 0})),
		"a header and no body":          {0xC0 | tagSignature, 0},
		"a version byte and nothing":    withBody([]byte{4}),
		"nothing but the fixed fields":  withBody([]byte{4, 0x20, 19, 9, 0, 0, 0, 0}),
		"a body of zeros":               withBody(make([]byte, 100)),
		"a body of 0xFF":                withBody(bytes.Repeat([]byte{0xFF}, 100)),
		"512 bytes of 0x04":             withBody(bytes.Repeat([]byte{4}, 512)),
		"a long body of 1 MiB":          withBody(bytes.Repeat([]byte{4}, 1<<20)),
		"a long body, a five-octet one": wrapLong(tagSignature, bytes.Repeat([]byte{4}, 70000)),
	} {
		t.Run(name, func(t *testing.T) { k.assertNotRevoked(t, name, pkt, false) })
	}
}

func TestReadRevocationIsSafeFromSeveralGoroutinesOnOnePrimary(t *testing.T) {
	k := newRevKit(t, "race")
	var pkts [][]byte
	for _, c := range allReasons {
		pkts = append(pkts, k.made(t, c.r))
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 8 {
				pkt := pkts[(g+i)%len(pkts)]
				rev, err := openpgp.ReadRevocation(pkt, k.primary)
				if err != nil || rev == nil || rev.Reason != allReasons[(g+i)%len(pkts)].r {
					errs <- fmt.Errorf("goroutine %d read %d: %+v: %w", g, i, rev, err)
					return
				}
				if _, err := openpgp.RevocationIssuer(pkt); err != nil {
					errs <- err
					return
				}
				bad := bytes.Clone(pkt)
				bad[len(bad)-1] ^= 1
				if _, err := openpgp.ReadRevocation(bad, k.primary); err == nil {
					errs <- errors.New("a changed packet was accepted")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestTheKindsOfTheErrorsOfTheReadersOfAnotherKind(t *testing.T) {
	if !errors.Is(openpgp.ErrRevocationReason, openpgp.ErrRevocation) {
		t.Error("an ErrRevocationReason is not an ErrRevocation")
	}
	if errors.Is(openpgp.ErrRevocation, openpgp.ErrRevocationReason) {
		t.Error("an ErrRevocation is an ErrRevocationReason")
	}
	all := []error{openpgp.ErrCertificateForm, openpgp.ErrSignatureFile, openpgp.ErrRevocation, openpgp.ErrRevocationReason,
		openpgp.ErrKeyring, openpgp.ErrKeyringForm, openpgp.ErrKeyringPrimaries, openpgp.ErrParams, openpgp.ErrAnswer,
		openpgp.ErrBinding, openpgp.ErrBindingShape, openpgp.ErrBoundFile, openpgp.ErrRequest, openpgp.ErrSignature}
	for i, a := range all {
		for j, b := range all {
			if i == j {
				continue
			}
			//nolint:errorlint // the sentinels of the table are compared by identity
			related := (a == openpgp.ErrRevocationReason && b == openpgp.ErrRevocation) ||
				(a == openpgp.ErrKeyringForm && b == openpgp.ErrKeyring) || (a == openpgp.ErrKeyringPrimaries && b == openpgp.ErrKeyring) ||
				(a == openpgp.ErrBinding && b == openpgp.ErrAnswer) || (a == openpgp.ErrBindingShape && b == openpgp.ErrAnswer) ||
				(a == openpgp.ErrBoundFile && b == openpgp.ErrAnswer)
			if errors.Is(a, b) != related {
				t.Errorf("errors.Is(%v, %v) = %v, want %v", a, b, !related, related)
			}
		}
		if a.Error() == "" || !strings.HasPrefix(a.Error(), "openpgp: ") {
			t.Errorf("the text of %v does not start with the package name", a)
		}
	}
}
