package openpgp_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// The self-certification of a primary is one shape (bundle page, "The OpenPGP primary", row
// Self-signature; record 0009, rule 8), and one function checks it for the builder and for the reader
// of the keyring file. Each row of the shape is broken in turn below. A broken certification is
// refused by that function and by the reader; a change that the page allows is accepted by both.

// certCase is one change to a good certification. words is empty when both must accept it.
type certCase struct {
	name  string
	tweak func(*sigSpec)
	words string
}

func reverse[T any](s []T) []T {
	out := slices.Clone(s)
	slices.Reverse(out)
	return out
}

func extraSubs(n int) []sub {
	out := make([]sub, n)
	for i := range out {
		out[i] = sub{Type: 100}
	}
	return out
}

func certCases(t *testing.T) []certCase {
	other := genKey(t)
	otherFP := fingerprint(&other.PublicKey, created)
	return []certCase{
		// What the page allows.
		{"the subpackets in the reverse order", func(sp *sigSpec) { sp.Hashed = reverse(sp.Hashed) }, ""},
		{"the subpackets in another order", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed[2:], sp.Hashed[:2]...) }, ""},
		{"the five-octet length of every subpacket", func(sp *sigSpec) { sp.LongLengths = true }, ""},
		{"the old format header of the packet", func(sp *sigSpec) { sp.OldHeader = true }, ""},
		{"a key expiration of another value", func(sp *sigSpec) { sp.Hashed[2].Data = u32(5) }, ""},
		{"the largest key expiration", func(sp *sigSpec) { sp.Hashed[2].Data = u32(0xFFFFFFFF) }, ""},
		{"a creation time a year later", func(sp *sigSpec) { sp.Hashed[0].Data = u32(uint32(ceremony.AddDate(1, 0, 0).Unix())) }, ""},
		{"a creation time equal to the key's", func(sp *sigSpec) { sp.Hashed[0].Data = u32(uint32(created.Unix())) }, ""},

		// The type, the hash, the numbers.
		{"a generic certification (0x10)", func(sp *sigSpec) { sp.Type = 0x10 }, "0x13"},
		{"a persona certification (0x11)", func(sp *sigSpec) { sp.Type = 0x11 }, "0x13"},
		{"a casual certification (0x12)", func(sp *sigSpec) { sp.Type = 0x12 }, "0x13"},
		{"a subkey binding (0x18)", func(sp *sigSpec) { sp.Type = 0x18 }, "0x13"},
		{"a primary key binding (0x19)", func(sp *sigSpec) { sp.Type = 0x19 }, "0x13"},
		{"a certification revocation (0x30)", func(sp *sigSpec) { sp.Type = 0x30 }, "0x13"},
		{"a key revocation (0x20)", func(sp *sigSpec) { sp.Type = 0x20 }, "0x13"},
		{"a binary signature (0x00)", func(sp *sigSpec) { sp.Type = 0x00 }, "0x13"},
		{"SHA-256", func(sp *sigSpec) { sp.Hash = 8 }, "SHA-384"},
		{"SHA-512", func(sp *sigSpec) { sp.Hash = 10 }, "SHA-384"},
		{"SHA-1", func(sp *sigSpec) { sp.Hash = 2 }, "SHA-384"},
		{"the first byte of the hash tag changed", func(sp *sigSpec) { sp.TagXOR = [2]byte{1, 0} }, "hash tag"},
		{"the second byte of the hash tag changed", func(sp *sigSpec) { sp.TagXOR = [2]byte{0, 1} }, "hash tag"},
		{"a byte after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{0} }, "two numbers"},
		{"three bytes after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{1, 2, 3} }, "two numbers"},
		{"one number only", func(sp *sigSpec) { sp.Numbers = func(r, _ *big.Int) []byte { return mpi(r) } }, "two numbers"},
		{"a number of no bits", func(sp *sigSpec) {
			sp.Numbers = func(_, s *big.Int) []byte { return append([]byte{0, 0}, mpi(s)...) }
		}, "two numbers"},
		{"a number with a leading zero byte", func(sp *sigSpec) {
			sp.Numbers = func(r, s *big.Int) []byte {
				return cat(append([]byte{byte(r.BitLen() >> 8), byte(r.BitLen()), 0}, r.Bytes()...), mpi(s))
			}
		}, "two numbers"},
		{"a signature made by another key", func(sp *sigSpec) { sp.Key = other }, "verify"},

		// The hashed area.
		{"a creation time that is critical", func(sp *sigSpec) { sp.Hashed[0].Critical = true }, "critical"},
		{"a creation time of three bytes", func(sp *sigSpec) { sp.Hashed[0].Data = []byte{1, 2, 3} }, "creation time"},
		{"a creation time of five bytes", func(sp *sigSpec) { sp.Hashed[0].Data = []byte{1, 2, 3, 4, 5} }, "creation time"},
		{"no creation time", func(sp *sigSpec) { sp.Hashed[0] = sub{Type: 100, Data: []byte{1}} }, "creation time"},
		{"a second creation time in place of the key flags", func(sp *sigSpec) { sp.Hashed[1] = sp.Hashed[0] }, "creation time"},
		{"a creation time before the key", func(sp *sigSpec) { sp.Hashed[0].Data = u32(uint32(created.Unix() - 1)) }, "before"},
		{"key flags that certify and sign", func(sp *sigSpec) { sp.Hashed[1].Data = []byte{0x03} }, "key flags"},
		{"key flags that sign only", func(sp *sigSpec) { sp.Hashed[1].Data = []byte{0x02} }, "key flags"},
		{"key flags of none", func(sp *sigSpec) { sp.Hashed[1].Data = []byte{0x00} }, "key flags"},
		{"key flags of two bytes", func(sp *sigSpec) { sp.Hashed[1].Data = []byte{0x01, 0x00} }, "key flags"},
		{"key flags of no byte", func(sp *sigSpec) { sp.Hashed[1].Data = nil }, "key flags"},
		{"key flags that are critical", func(sp *sigSpec) { sp.Hashed[1].Critical = true }, "critical"},
		{"a key expiration that is not critical", func(sp *sigSpec) { sp.Hashed[2].Critical = false }, "critical"},
		{"a key expiration of zero", func(sp *sigSpec) { sp.Hashed[2].Data = u32(0) }, "not zero"},
		{"a key expiration of five bytes", func(sp *sigSpec) { sp.Hashed[2].Data = []byte{0, 0, 0, 1, 1} }, "key expiration"},
		{"a key expiration of three bytes", func(sp *sigSpec) { sp.Hashed[2].Data = []byte{1, 2, 3} }, "key expiration"},
		{"no key expiration", func(sp *sigSpec) { sp.Hashed[2] = sub{Type: 100, Data: []byte{1}} }, "key expiration"},
		{"an issuer fingerprint of another key", func(sp *sigSpec) { sp.Hashed[3].Data = append([]byte{4}, otherFP...) }, "issuer fingerprint"},
		{"an issuer fingerprint of version 5", func(sp *sigSpec) { sp.Hashed[3].Data[0] = 5 }, "issuer fingerprint"},
		{"an issuer fingerprint with no version byte", func(sp *sigSpec) { sp.Hashed[3].Data = sp.Hashed[3].Data[1:] }, "issuer fingerprint"},
		{"an issuer fingerprint that is critical", func(sp *sigSpec) { sp.Hashed[3].Critical = true }, "critical"},
		{"no issuer fingerprint", func(sp *sigSpec) { sp.Hashed[3] = sub{Type: 100, Data: []byte{1}} }, "issuer fingerprint"},
		{"one more hashed subpacket, of a type that is unknown", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 100, Data: []byte{1}}) }, "four"},
		{"one more hashed subpacket, a signature expiration", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 3, Data: u32(1)}) }, "four"},
		{"one more hashed subpacket, a notation", func(sp *sigSpec) {
			sp.Hashed = append(sp.Hashed, sub{Type: 20, Data: []byte{0, 0, 0, 0, 0, 1, 0, 1, 'n', 'v'}})
		}, "four"},
		{"one more hashed subpacket that is critical", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 99, Critical: true, Data: []byte{1}}) }, "four"},
		{"a hashed subpacket less", func(sp *sigSpec) { sp.Hashed = sp.Hashed[:3] }, "four"},
		{"no hashed subpacket", func(sp *sigSpec) { sp.Hashed = nil }, "four"},

		// The unhashed area.
		{"an issuer key ID of another key", func(sp *sigSpec) { sp.Unhashed[0].Data = otherFP[12:] }, "issuer key ID"},
		{"an issuer key ID of seven bytes", func(sp *sigSpec) { sp.Unhashed[0].Data = sp.Unhashed[0].Data[1:] }, "issuer key ID"},
		{"an issuer key ID that is critical", func(sp *sigSpec) { sp.Unhashed[0].Critical = true }, "critical"},
		{"no unhashed subpacket", func(sp *sigSpec) { sp.Unhashed = nil }, "unhashed"},
		{"the issuer key ID in the hashed area instead", func(sp *sigSpec) {
			sp.Hashed, sp.Unhashed = append(sp.Hashed, sp.Unhashed[0]), nil
		}, "four"},
		{"one more unhashed subpacket, of a type that is unknown", func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sub{Type: 100, Data: []byte{1}}) }, "unhashed"},
		{"one more unhashed subpacket that is critical", func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sub{Type: 99, Critical: true, Data: []byte{1}}) }, "unhashed"},
		{"the issuer key ID twice", func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sp.Unhashed[0]) }, "unhashed"},

		// The counts of the subpackets: 32 reach the shape, 33 are refused by the count.
		{"32 hashed subpackets", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, extraSubs(28)...) }, "four"},
		{"33 hashed subpackets", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, extraSubs(29)...) }, "32"},
		{"32 unhashed subpackets", func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, extraSubs(31)...) }, "unhashed"},
		{"33 unhashed subpackets", func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, extraSubs(32)...) }, "32"},
	}
}

// runCertCase builds the certification, asks the shared check and the reader about it, and checks
// that they agree and that go-crypto, which reads what the reader accepts, reads it too.
func runCertCase(t *testing.T, m keyringPrimary, c certCase, sig []byte) {
	t.Helper()
	_, _, errShared := openpgp.CheckCertificationBytes(sig, m.keyPacket(), m.uid, m.at)
	file := m.assemble(sig)
	if c.words == "" {
		if errShared != nil {
			t.Errorf("the shared check refuses it: %v", errShared)
		}
		assertRead(t, c.name, file, wantOf(m), m)
		return
	}
	if errShared == nil {
		t.Errorf("the shared check accepts a certification that has %s", c.name)
	} else if !strings.Contains(errShared.Error(), c.words) {
		t.Errorf("the shared check says %q, want the words %q", errShared, c.words)
	}
	assertKeyringRefused(t, c.name, file, wantOf(m), openpgp.ErrKeyringForm, "certification 1", c.words)
}

func TestEveryRowOfTheShapeOfASelfCertificationIsBrokenInTurnAndHeld(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	cases := certCases(t)
	refused, accepted := 0, 0
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runCertCase(t, m, c, m.sig(t, ceremony, c.tweak))
		})
		if c.words == "" {
			accepted++
		} else {
			refused++
		}
	}
	if accepted < 6 || refused < 40 {
		t.Errorf("the table holds %d accepted and %d refused changes: a check that finds nothing to check fails", accepted, refused)
	}
}

// The changes of the bytes of a packet that the spec cannot write.

func TestACertificationWhoseBytesAreNotTheBytesOfTheShapeIsRefusedByBothReaders(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	good := m.sig(t, ceremony, nil)
	body := bodyOf(t, good)
	hl := int(binary.BigEndian.Uint16(body[4:6]))
	edit := func(f func(b []byte) []byte) []byte { return withBody(f(bytes.Clone(body))) }
	cases := []struct {
		name  string
		pkt   []byte
		words string
	}{
		{"version 3", edit(func(b []byte) []byte { b[0] = 3; return b }), "version 4"},
		{"version 5", edit(func(b []byte) []byte { b[0] = 5; return b }), "version 4"},
		{"version 6", edit(func(b []byte) []byte { b[0] = 6; return b }), "version 4"},
		{"RSA", edit(func(b []byte) []byte { b[2] = 1; return b }), "ECDSA"},
		{"EdDSA", edit(func(b []byte) []byte { b[2] = 22; return b }), "ECDSA"},
		{"ECDH", edit(func(b []byte) []byte { b[2] = 18; return b }), "ECDSA"},
		{"a hash named SHA-256 over a SHA-384 digest", edit(func(b []byte) []byte { b[3] = 8; return b }), "SHA-384"},
		{"a hashed area that runs past the packet", edit(func(b []byte) []byte { b[4], b[5] = 0xFF, 0xFF; return b }), "runs past"},
		{"a hashed area one byte too long", edit(func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[4:6], uint16(hl+1))
			return b
		}), ""},
		{"a hashed area one byte too short", edit(func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[4:6], uint16(hl-1))
			return b
		}), ""},
		{"an unhashed area that runs past the packet", edit(func(b []byte) []byte { b[6+hl], b[7+hl] = 0xFF, 0xFF; return b }), "runs past"},
		{"a body with the signature cut short", edit(func(b []byte) []byte { return b[:len(b)-1] }), ""},
		{"a body of five bytes", edit(func(b []byte) []byte { return b[:5] }), "version 4"},
		{"a body that ends after the unhashed area, with no hash tag", edit(func(b []byte) []byte { return b[:layoutOf(body).tagAt] }), "hash tag"},
		{"a body with one byte of the hash tag", edit(func(b []byte) []byte { return b[:layoutOf(body).tagAt+1] }), "hash tag"},
		{"a hashed area that leaves one byte for the length of the unhashed area", edit(func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-7))
			return b
		}), "runs past"},
		{"an unhashed area one byte longer than the packet", edit(func(b []byte) []byte {
			ul := binary.BigEndian.Uint16(b[6+hl : 8+hl])
			binary.BigEndian.PutUint16(b[6+hl:8+hl], ul+uint16(len(b)-(8+hl)-int(ul))+1)
			return b
		}), "runs past"},
		{"a subpacket of length zero at the start of the hashed area", edit(func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[4:6], uint16(hl+1))
			return cat(b[:6], []byte{0x00}, b[6:])
		}), "whole subpackets"},
		{"a subpacket of length zero at the start of the unhashed area", edit(func(b []byte) []byte {
			ul := binary.BigEndian.Uint16(b[6+hl : 8+hl])
			binary.BigEndian.PutUint16(b[6+hl:8+hl], ul+1)
			return cat(b[:8+hl], []byte{0x00}, b[8+hl:])
		}), "whole subpackets"},
		{"a body that is only the version", edit(func(b []byte) []byte { return b[:1] }), "version 4"},
		{"an empty body", edit(func([]byte) []byte { return nil }), "version 4"},
		{"the packet of a user ID in place of a signature", wrap(tagUserID, body), "one signature packet"},
		{"a signature packet and a byte after it", append(bytes.Clone(good), 0x00), "one signature packet"},
		{"two signature packets", cat(good, good), "one signature packet"},
		{"a signature packet cut short", good[:len(good)-1], "one signature packet"},
		{"nothing", nil, "one signature packet"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := openpgp.CheckCertificationBytes(c.pkt, m.keyPacket(), m.uid, m.at)
			if err == nil {
				t.Fatal("the shared check accepts it")
			}
			if c.words != "" && !strings.Contains(err.Error(), c.words) {
				t.Errorf("the shared check says %q, want the words %q", err, c.words)
			}
			checkText(t, c.name, err)
		})
	}
}

func TestACertificationMustNotBeDatedBeforeTheOneBeforeIt(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	sig := m.sig(t, ceremony, nil)
	for _, c := range []struct {
		name      string
		notBefore time.Time
		ok        bool
	}{
		{"the same second", ceremony, true},
		{"a second earlier", ceremony.Add(-time.Second), true},
		{"a second later", ceremony.Add(time.Second), false},
		{"a day later", ceremony.Add(24 * time.Hour), false},
	} {
		_, _, err := openpgp.CheckCertificationBytes(sig, m.keyPacket(), m.uid, c.notBefore)
		if (err == nil) != c.ok {
			t.Errorf("%s: error = %v, accepted = %v", c.name, err, c.ok)
		}
	}
}

func TestACertificationOfAnotherUserIDDoesNotVerify(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	sig := m.sig(t, ceremony, nil)
	for _, uid := range []string{m.uid + " ", strings.Replace(m.uid, "Root A", "Root B", 1), strings.Replace(m.uid, "TEST ONLY", "TEST ONLZ", 1), ""} {
		if _, _, err := openpgp.CheckCertificationBytes(sig, m.keyPacket(), uid, m.at); err == nil {
			t.Errorf("a certification of %q is accepted for another user ID", m.uid)
		}
	}
}

func TestACertificationOfAnotherKeyDoesNotVerify(t *testing.T) {
	m, n := newKeyringPrimary(t, "A", true), newKeyringPrimary(t, "A", true)
	sig := m.sig(t, ceremony, nil)
	if _, _, err := openpgp.CheckCertificationBytes(sig, n.keyPacket(), m.uid, m.at); err == nil {
		t.Error("a certification of one key is accepted for another")
	}
	// The same certification with the issuer fields of the other key still does not verify.
	forged := m.sig(t, ceremony, func(sp *sigSpec) {
		fp := fingerprint(&n.key.PublicKey, created)
		sp.Hashed[3].Data = append([]byte{4}, fp...)
		sp.Unhashed[0].Data = fp[12:]
	})
	if _, _, err := openpgp.CheckCertificationBytes(forged, n.keyPacket(), m.uid, m.at); err == nil {
		t.Error("a certification by one key that names another as its issuer is accepted")
	}
}

// Every flip of one bit of a certification packet that the builder wrote leaves it refused.
func TestNoChangeOfOneBitOfACertificationThatTheBuilderWroteLeavesItAccepted(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	cert := m.cert(t)
	pkts := splitPackets(t, cert)
	sig := pkts[2].Raw
	for i := range sig {
		for bit := 0; bit < 8; bit++ {
			file := bytes.Clone(sig)
			file[i] ^= 1 << bit
			if _, _, err := openpgp.CheckCertificationBytes(file, pkts[0].Raw, m.uid, m.at); err == nil {
				t.Errorf("byte %d bit %d: a changed certification is accepted", i, bit)
			}
		}
	}
}

// The bounds that keep a hostile certification from being read at all.

func TestACertificationOfFiveHundredAndTwelveBytesIsReadAndOneMoreByteIsRefusedBySize(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	pad := func(n int) func(*sigSpec) {
		return func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 100, Data: make([]byte, n)}) }
	}
	sizeFor := func(n int) int { return len(bodyOf(t, m.sig(t, ceremony, pad(n)))) }
	find := func(target int) int {
		for n := 0; n < 600; n++ {
			if sizeFor(n) == target {
				return n
			}
		}
		t.Fatalf("no padding gives a body of %d bytes", target)
		return 0
	}
	at, over := find(openpgp.MaxCertificationBody), find(openpgp.MaxCertificationBody+1)
	for _, c := range []struct {
		n     int
		words string
		not   string
	}{
		{at, "four", "longer"},
		{over, "longer than 512", ""},
	} {
		sig := m.sig(t, ceremony, pad(c.n))
		_, _, err := openpgp.CheckCertificationBytes(sig, m.keyPacket(), m.uid, m.at)
		if err == nil || !strings.Contains(err.Error(), c.words) || (c.not != "" && strings.Contains(err.Error(), c.not)) {
			t.Errorf("a body of %d bytes: error = %v, want the words %q", len(bodyOf(t, sig)), err, c.words)
		}
		assertKeyringRefused(t, fmt.Sprintf("a body of %d bytes", len(bodyOf(t, sig))), m.assemble(sig), wantOf(m), openpgp.ErrKeyringForm, c.words)
	}
}

func TestASignatureWithTensOfThousandsOfSubpacketsIsRefusedBySizeBeforeAnySubpacketIsRead(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	for _, n := range []int{200, 30000} {
		area := bytes.Repeat([]byte{0x01, 100}, n)
		// The length of an area has two bytes: 32,767 empty subpackets are the most that one can hold.
		if len(area) > 65535 {
			area = area[:65534]
		}
		hashed := area
		body := []byte{4, 0x13, 19, 9, byte(len(hashed) >> 8), byte(len(hashed))}
		body = append(body, hashed...)
		body = append(body, 0, 0, 0, 0)
		body = append(body, mpi(big.NewInt(1))...)
		body = append(body, mpi(big.NewInt(1))...)
		pkt := wrap(tagSignature, body)
		_, _, err := openpgp.CheckCertificationBytes(pkt, m.keyPacket(), m.uid, m.at)
		if n > 200 && (err == nil || !strings.Contains(err.Error(), "longer than 512")) {
			t.Errorf("%d subpackets: error = %v, want the size", n, err)
		}
		if err == nil {
			t.Errorf("%d subpackets: accepted", n)
		}
		assertKeyringRefused(t, fmt.Sprintf("%d subpackets", n), m.assemble(pkt), wantOf(m), openpgp.ErrKeyringForm)
	}
	// 200,000 subpackets cannot be written in the two bytes of an area; a signature that claims them
	// by a packet of 400,000 bytes is refused by size.
	huge := wrapLong(tagSignature, append([]byte{4, 0x13, 19, 9, 0xFF, 0xFF}, bytes.Repeat([]byte{0x01, 100}, 200000)...))
	_, _, err := openpgp.CheckCertificationBytes(huge, m.keyPacket(), m.uid, m.at)
	if err == nil || !strings.Contains(err.Error(), "longer than 512") {
		t.Errorf("200,000 subpackets: error = %v, want the size", err)
	}
	assertKeyringRefused(t, "200,000 subpackets", m.assemble(huge), wantOf(m), openpgp.ErrKeyringForm, "longer than 512")
}

func TestAHashedAreaWhoseLastSubpacketIsCutIsRefusedByTheCount(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	body := bodyOf(t, m.sig(t, ceremony, nil))
	hl := int(binary.BigEndian.Uint16(body[4:6]))
	// Drop the last byte of the hashed area and move the rest up: the last subpacket says it is longer
	// than the area that is left.
	cut := cat(body[:6+hl-1], body[6+hl:])
	binary.BigEndian.PutUint16(cut[4:6], uint16(hl-1))
	_, _, err := openpgp.CheckCertificationBytes(withBody(cut), m.keyPacket(), m.uid, m.at)
	if err == nil || !strings.Contains(err.Error(), "whole subpackets") {
		t.Errorf("a cut subpacket: error = %v, want the words \"whole subpackets\"", err)
	}
}

// A certification with an expiry that is a key's whole life stays one of the page, whatever the clock.
func TestTheReaderComparesNoClockWithAnExpiryOrACreationTime(t *testing.T) {
	// A certification whose key expired long ago (life of one second) is read: the expiry is not
	// judged here. A key and a certification in the year 2106 are read too.
	m := newKeyringPrimary(t, "A", true)
	short := m.assemble(m.sig(t, ceremony, func(sp *sigSpec) { sp.Hashed[2].Data = u32(1) }))
	assertRead(t, "a key that expired a second after it was created", short, wantOf(m), m)
	late := time.Unix(1<<32-1, 0).UTC()
	file := m.assemble(m.sig(t, late, func(sp *sigSpec) { sp.Hashed[2].Data = u32(1) }))
	assertRead(t, "a certification in the last second of 2106", file, wantOf(m), m)
}

// A key that a certification names must be the key, not a fingerprint that a certificate repeats.
func TestACertificateWhoseCertificationCoversAnotherUserIDIsRefused(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	otherUID := m.withUserID(strings.Replace(m.uid, "Root A", "Root B", 1))
	sig := otherUID.sig(t, ceremony, nil)
	assertKeyringRefused(t, "a certification over another user ID", m.assemble(sig), wantOf(m), openpgp.ErrKeyringForm, "certification 1", "hash tag")
}

func TestTheCertificationsOfACertificateAreCountedFromOne(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	good := m.sig(t, ceremony, nil)
	bad := m.sig(t, ceremony.Add(time.Hour), func(sp *sigSpec) { sp.Type = 0x10 })
	assertKeyringRefused(t, "the second certification is the bad one", m.assemble(good, bad), wantOf(m), openpgp.ErrKeyringForm, "certification 2")
}

func TestTwoCertificationsOfOneCertificateOutOfCreationOrderAreRefusedAndInOrderAreNot(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	early, late := m.sig(t, ceremony, nil), m.sig(t, ceremony.Add(time.Hour), nil)
	assertRead(t, "in order", m.assemble(early, late), wantOf(m), m)
	assertKeyringRefused(t, "out of order", m.assemble(late, early), wantOf(m), openpgp.ErrKeyringForm, "certification 2", "before")
	// A third one that is before the second but after the first is out of order too.
	mid := m.sig(t, ceremony.Add(30*time.Minute), nil)
	assertKeyringRefused(t, "the third before the second", m.assemble(early, late, mid), wantOf(m), openpgp.ErrKeyringForm, "certification 3", "before")
	// A certification before the key is refused as the first one of a certificate.
	before := m.sig(t, created.Add(-time.Second), nil)
	assertKeyringRefused(t, "before the key", m.assemble(before), wantOf(m), openpgp.ErrKeyringForm, "certification 1", "before")
}
