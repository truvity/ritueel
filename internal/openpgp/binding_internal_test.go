package openpgp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"testing"
)

// The bound on the walk of a subpacket area. parseArea has no limit on the number of subpackets,
// and frame.go is not changed for this reader: binding.go counts the subpackets with scanArea
// before parseArea is called, so that a hostile area costs at most maxBindingSubpackets steps.

func TestTheConstantsOfTheBindingReader(t *testing.T) {
	if maxBindingSubpackets != 32 {
		t.Errorf("maxBindingSubpackets = %d, want 32", maxBindingSubpackets)
	}
	if maxBoundFile != 256*1024 {
		t.Errorf("maxBoundFile = %d, want 256 KiB", maxBoundFile)
	}
	if criticalSubpacket != 9 {
		t.Errorf("criticalSubpacket = %d, want 9, the key expiration time", criticalSubpacket)
	}
}

// emptySubpackets is n subpackets of one byte each: a length of 2 and a type and a byte.
func emptySubpackets(n int) []byte {
	return bytes.Repeat([]byte{0x02, 0x64, 0x01}, n)
}

func TestScanAreaCountsTheSubpacketsAndStopsAtTheLimit(t *testing.T) {
	for _, c := range []struct {
		name  string
		area  []byte
		limit int
		n     int
		err   error
	}{
		{"nil", nil, 32, 0, nil},
		{"empty", []byte{}, 32, 0, nil},
		{"one subpacket", emptySubpackets(1), 32, 1, nil},
		{"31 subpackets", emptySubpackets(31), 32, 31, nil},
		{"exactly 32 subpackets", emptySubpackets(32), 32, 32, nil},
		{"33 subpackets", emptySubpackets(33), 32, 33, errAreaTooMany},
		{"34 subpackets", emptySubpackets(34), 32, 33, errAreaTooMany},
		{"100000 subpackets", emptySubpackets(100000), 32, 33, errAreaTooMany},
		{"a limit of 0 and one subpacket", emptySubpackets(1), 0, 1, errAreaTooMany},
		{"a limit of 0 and none", nil, 0, 0, nil},
		{"a limit of 1 and two subpackets", emptySubpackets(2), 1, 2, errAreaTooMany},
		{"a limit of 1 and one subpacket", emptySubpackets(1), 1, 1, nil},
		// The scan stops at the limit and does not read on: what follows the 33rd subpacket is not looked at.
		{"33 subpackets and then a bad length", append(emptySubpackets(33), 0), 32, 33, errAreaTooMany},
		{"33 subpackets and then a length that runs out", append(emptySubpackets(33), 0xFF, 0xFF), 32, 33, errAreaTooMany},
		{"32 subpackets and then anything: more than the limit", append(emptySubpackets(32), 0), 32, 33, errAreaTooMany},
		// The three forms of the length (RFC 9580, section 5.2.3.7), at their edges.
		{"a one-byte length of 191", append([]byte{191, 1}, make([]byte, 190)...), 32, 1, nil},
		{"a two-byte length of 192", append([]byte{192, 0, 1}, make([]byte, 191)...), 32, 1, nil},
		{"a two-byte length of 193", append([]byte{192, 1, 1}, make([]byte, 192)...), 32, 1, nil},
		{"a two-byte length of 16319", append([]byte{254, 255, 1}, make([]byte, 16318)...), 32, 1, nil},
		{"a five-byte length of 1", []byte{255, 0, 0, 0, 1, 1}, 32, 1, nil},
		{"a five-byte length of 2", []byte{255, 0, 0, 0, 2, 1, 7}, 32, 1, nil},
		// A length that is zero or that leaves the area.
		{"a one-byte length of 0", []byte{0}, 32, 0, errFrame},
		{"a one-byte length of 0 after a subpacket", append(emptySubpackets(1), 0), 32, 1, errFrame},
		{"a one-byte length that runs past the area", []byte{3, 1, 2}, 32, 0, errFrame},
		{"a one-byte length that runs past the area by one", []byte{2, 1}, 32, 0, errFrame},
		{"a two-byte length with no second byte", []byte{192}, 32, 0, errFrame},
		{"a two-byte length that runs past the area", []byte{192, 0, 1, 2}, 32, 0, errFrame},
		{"a five-byte length with four bytes", []byte{255, 0, 0, 0}, 32, 0, errFrame},
		{"a five-byte length of 0", []byte{255, 0, 0, 0, 0}, 32, 0, errFrame},
		{"a five-byte length of 0 with a byte after", []byte{255, 0, 0, 0, 0, 1}, 32, 0, errFrame},
		{"a five-byte length that runs past the area", []byte{255, 0, 0, 0, 5, 1, 2}, 32, 0, errFrame},
		{"a five-byte length of 2^32 - 1", []byte{255, 255, 255, 255, 255, 1, 2}, 32, 0, errFrame},
		{"a five-byte length of 2^31", []byte{255, 128, 0, 0, 0, 1, 2}, 32, 0, errFrame},
	} {
		n, err := scanArea(c.area, c.limit)
		if n != c.n || !errors.Is(err, c.err) || (c.err == nil) != (err == nil) {
			t.Errorf("%s: scanArea = %d, %v; want %d, %v", c.name, n, err, c.n, c.err)
		}
	}
}

// scanArea and parseArea read an area by the same rule: the same faults, and the same number of
// subpackets when there is no fault and the count is within the limit.
func TestScanAreaAndParseAreaAgree(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	pieces := [][]byte{
		{0}, {1}, {2, 9, 9}, {191}, {192}, {192, 0}, {192, 0, 5}, {254, 255}, {255}, {255, 0, 0, 0, 0},
		{255, 0, 0, 0, 3, 1, 2, 3}, {2, 0x80 | 9, 1}, {5, 2, 1, 2, 3, 4}, {1, 33},
	}
	for range 4000 {
		var area []byte
		for range rng.IntN(12) {
			area = append(area, pieces[rng.IntN(len(pieces))]...)
		}
		parsed, perr := parseArea(area)
		n, serr := scanArea(area, 1<<20)
		if (perr == nil) != (serr == nil) {
			t.Fatalf("area % x: parseArea error %v, scanArea error %v", area, perr, serr)
		}
		if perr == nil && n != len(parsed) {
			t.Fatalf("area % x: parseArea read %d subpackets, scanArea counted %d", area, len(parsed), n)
		}
	}
}

// What the walk costs does not depend on the size of the area once it is over the limit: the scan
// stops at the 33rd subpacket, and the shared reader is not called for it. The signature body
// below has an area of 33 subpackets and one of 20000, both refused before parseArea allocates.
func TestAnAreaOverTheLimitCostsTheSameWhateverItsSize(t *testing.T) {
	if raceEnabled {
		t.Skip("the number of allocations of a call is not the same under the race detector")
	}
	body := func(n int) []byte {
		hashed := emptySubpackets(n)
		b := []byte{4, sigSubkeyBinding, algoECDSA, hashSHA384, byte(len(hashed) >> 8), byte(len(hashed))}
		b = append(b, hashed...)
		b = append(b, 0, 0)
		return append(b, 0xAA, 0xBB, 0, 1, 1, 0, 1, 1)
	}
	small, large := body(33), body(20000)
	if len(large) > 65535 {
		t.Fatalf("the test body is %d bytes", len(large))
	}
	for _, in := range [][]byte{small, large} {
		if err := scanSigAreas(in); err == nil {
			t.Fatal("an area of more than 32 subpackets was accepted")
		}
	}
	allocs := func(in []byte) float64 {
		return testing.AllocsPerRun(20, func() {
			if _, _, err := readBindingPacket(wrap(tagSignature, in)); err == nil {
				t.Fatal("an area of more than 32 subpackets was read")
			}
		})
	}
	if a, b := allocs(small), allocs(large); a != b {
		t.Errorf("a refused area of 33 subpackets costs %v allocations and one of 20000 costs %v: the area is walked to its end", a, b)
	}
	// The control: an area of 32 subpackets is read by parseArea, which allocates for them.
	ok := body(32)
	if _, _, err := readBindingPacket(wrap(tagSignature, ok)); err != nil {
		t.Fatalf("an area of 32 subpackets: %v", err)
	}
	if a := testing.AllocsPerRun(20, func() { _, _, _ = readBindingPacket(wrap(tagSignature, ok)) }); a <= allocs(small) {
		t.Errorf("an area that is read costs %v allocations, no more than the refused one (%v): the test measures nothing", a, allocs(small))
	}
}

func TestScanSigAreasWalksTheTwoAreasAndNothingElse(t *testing.T) {
	area := func(h, u []byte) []byte {
		b := []byte{4, sigSubkeyBinding, algoECDSA, hashSHA384, byte(len(h) >> 8), byte(len(h))}
		b = append(b, h...)
		b = append(b, byte(len(u)>>8), byte(len(u)))
		return append(b, u...)
	}
	for _, c := range []struct {
		name string
		body []byte
		ok   bool
	}{
		{"two empty areas", area(nil, nil), true},
		{"32 and 32", area(emptySubpackets(32), emptySubpackets(32)), true},
		{"33 in the hashed area", area(emptySubpackets(33), nil), false},
		{"33 in the unhashed area", area(nil, emptySubpackets(33)), false},
		{"33 in both", area(emptySubpackets(33), emptySubpackets(33)), false},
		{"a zero length in the hashed area", area([]byte{0}, nil), false},
		{"a zero length in the unhashed area", area(nil, []byte{0}), false},
		{"version 3", append([]byte{3}, area(nil, nil)[1:]...), false},
		{"version 5", append([]byte{5}, area(nil, nil)[1:]...), false},
		{"five bytes", []byte{4, 0x18, 19, 9, 0}, false},
		{"nothing", nil, false},
		{"no length for the unhashed area", []byte{4, 0x18, 19, 9, 0, 0}, false},
		{"one byte of the unhashed length", []byte{4, 0x18, 19, 9, 0, 0, 0}, false},
		{"a hashed area past the body", []byte{4, 0x18, 19, 9, 0, 9, 1, 2, 3, 0, 0}, false},
		{"an unhashed area past the body", []byte{4, 0x18, 19, 9, 0, 0, 0, 9, 1, 2}, false},
		{"an unhashed area one byte past the body", []byte{4, 0x18, 19, 9, 0, 0, 0, 3, 1, 2}, false},
		{"an unhashed area that fills the body exactly", []byte{4, 0x18, 19, 9, 0, 0, 0, 2, 1, 2}, true},
		{"a hashed area that leaves no room for the unhashed length", []byte{4, 0x18, 19, 9, 0, 2, 1, 2, 0}, false},
		{"a hashed area that leaves room for the unhashed length only", []byte{4, 0x18, 19, 9, 0, 0, 0, 0}, true},
	} {
		err := scanSigAreas(c.body)
		if (err == nil) != c.ok {
			t.Errorf("%s: scanSigAreas = %v, want ok=%v", c.name, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrBinding) {
			t.Errorf("%s: the fault is %v, want an ErrBinding", c.name, err)
		}
	}
}

func TestReadBindingPacketIsOneWholeVersion4SignaturePacket(t *testing.T) {
	body := append([]byte{4, sigSubkeyBinding, algoECDSA, hashSHA384, 0, 0, 0, 0}, 0xAA, 0xBB, 0, 1, 1, 0, 1, 1)
	for _, c := range []struct {
		name string
		pkt  []byte
		ok   bool
	}{
		{"a whole signature packet", wrap(tagSignature, body), true},
		{"the same, old format", append([]byte{0x80 | tagSignature<<2, byte(len(body))}, body...), true},
		{"the same, a five-byte length", append([]byte{0xC0 | tagSignature, 0xFF, 0, 0, 0, byte(len(body))}, body...), true},
		{"another tag", wrap(tagSubkey, body), false},
		{"a byte after", append(wrap(tagSignature, body), 0), false},
		{"nothing", nil, false},
		{"a cut packet", wrap(tagSignature, body)[:10], false},
		{"longer than the limit", append(wrap(tagSignature, body), make([]byte, maxBoundFile)...), false},
	} {
		got, a, err := readBindingPacket(c.pkt)
		if (err == nil) != c.ok {
			t.Errorf("%s: readBindingPacket = %v, want ok=%v", c.name, err, c.ok)
		}
		if err != nil && (got != nil || a.fields != nil || !errors.Is(err, ErrBinding)) {
			t.Errorf("%s: a fault returned a part, or is not an ErrBinding: %v", c.name, err)
		}
		if err == nil && !bytes.Equal(got, body) {
			t.Errorf("%s: the body is not the body of the packet", c.name)
		}
	}
}

func TestReadSigValuesReadsTheHashTagAndTwoNumbersAndNothingMore(t *testing.T) {
	num := func(b ...byte) []byte {
		out := []byte{0, byte(8*(len(b)-1) + bitLen(b[0]))}
		return append(out, b...)
	}
	two := append(num(0x81, 2), num(0x07)...)
	for _, c := range []struct {
		name string
		rest []byte
		ok   bool
	}{
		{"a hash tag and two numbers", append([]byte{0xAA, 0xBB}, two...), true},
		{"nothing", nil, false},
		{"one byte", []byte{1}, false},
		{"the tag only", []byte{1, 2}, false},
		{"the tag and one number", append([]byte{1, 2}, num(5)...), false},
		{"a byte after", append(append([]byte{1, 2}, two...), 0), false},
		{"a leading zero byte", append([]byte{1, 2, 0, 9, 0, 1}, num(5)...), false},
		{"a bit length of zero", append([]byte{1, 2, 0, 0}, num(5)...), false},
		{"a bit length that is too big", append([]byte{1, 2, 0, 16, 1}, num(5)...), false},
	} {
		tag, r, s, err := readSigValues(c.rest)
		if (err == nil) != c.ok {
			t.Errorf("%s: readSigValues = %v, want ok=%v", c.name, err, c.ok)
		}
		if err != nil && (tag != nil || r != nil || s != nil || !errors.Is(err, ErrBinding)) {
			t.Errorf("%s: a fault returned a part, or is not an ErrBinding: %v", c.name, err)
		}
		if err == nil && (!bytes.Equal(tag, []byte{0xAA, 0xBB}) || !bytes.Equal(r, []byte{0x81, 2}) || !bytes.Equal(s, []byte{7})) {
			t.Errorf("%s: tag % x, r % x, s % x", c.name, tag, r, s)
		}
	}
}

// A subpacket of the area is read by its length in the form that the standard gives the smallest
// for it, and in a longer form too: the length is the number of bytes after it, and the walk adds
// the form's own width.
func TestScanAreaCountsEachSubpacketOnceInEveryLengthForm(t *testing.T) {
	var area []byte
	data := bytes.Repeat([]byte{7}, 300)
	// one-byte, two-byte and five-byte forms for the same kind of subpacket.
	area = append(area, 3, 100, 1, 2)
	area = append(area, 192, 108, 100)
	area = append(area, data[:299]...)
	five := make([]byte, 5)
	five[0] = 255
	binary.BigEndian.PutUint32(five[1:], 4)
	area = append(area, five...)
	area = append(area, 100, 1, 2, 3)
	if n, err := scanArea(area, 32); err != nil || n != 3 {
		t.Errorf("scanArea = %d, %v; want 3 subpackets", n, err)
	}
	parsed, err := parseArea(area)
	if err != nil || len(parsed) != 3 {
		t.Errorf("parseArea = %d subpackets, %v; want 3", len(parsed), err)
	}
}

// FuzzScanArea gives scanArea any bytes: it never panics, never counts past the limit, and agrees with the
// shared reader on what it accepts. The seeds are areas of a binding.
func FuzzScanArea(f *testing.F) {
	f.Add([]byte{}, uint8(32))
	f.Add(emptySubpackets(33), uint8(32))
	f.Add(emptySubpackets(5), uint8(3))
	f.Add([]byte{255, 0, 0, 0, 0}, uint8(32))
	f.Add([]byte{192}, uint8(32))
	f.Add([]byte{5, 2, 0, 0, 0, 1, 2, 5, 0x80 | 9, 0, 1, 0, 0}, uint8(32))
	f.Fuzz(func(t *testing.T, area []byte, limit uint8) {
		n, err := scanArea(area, int(limit))
		switch {
		case err == nil:
			if n > int(limit) {
				t.Fatalf("scanArea counted %d past the limit %d without an error", n, limit)
			}
			parsed, perr := parseArea(area)
			if perr != nil || len(parsed) != n {
				t.Fatalf("scanArea accepted %d subpackets; parseArea read %d, %v", n, len(parsed), perr)
			}
		case errors.Is(err, errAreaTooMany):
			if n != int(limit)+1 {
				t.Fatalf("a count past the limit %d returned %d", limit, n)
			}
			if parsed, perr := parseArea(area); perr == nil && len(parsed) <= int(limit) {
				t.Fatalf("scanArea says more than %d subpackets; parseArea reads %d", limit, len(parsed))
			}
		case errors.Is(err, errFrame):
			if n > int(limit) {
				t.Fatalf("a framing fault came with a count of %d, past the limit %d", n, limit)
			}
			if _, perr := parseArea(area); perr == nil && len(area) > 0 {
				// parseArea reads the whole area, scanArea may have stopped at a fault that parseArea also finds.
				t.Fatalf("scanArea refused an area that parseArea reads")
			}
		default:
			t.Fatalf("scanArea returned an error of no known kind: %v", err)
		}
	})
}

// splitSig reads a version 4 signature and no other: a body whose first byte is another number is
// refused whatever follows, so that the layout of a version 3 or version 6 signature is never read as
// the layout of version 4.
func TestSplitSigReadsVersion4AndNoOtherVersion(t *testing.T) {
	good := []byte{4, sigSubkeyBinding, algoECDSA, hashSHA384, 0, 0, 0, 0, 0xAA, 0xBB, 0, 1, 1, 0, 1, 1}
	if _, err := splitSig(good); err != nil {
		t.Fatalf("a version 4 body: %v", err)
	}
	for version := range 256 {
		if version == 4 {
			continue
		}
		body := bytes.Clone(good)
		body[0] = byte(version)
		if a, err := splitSig(body); !errors.Is(err, errFrame) || a.fields != nil || a.hashed != nil || a.unhashed != nil || a.rest != nil {
			t.Errorf("version %d: splitSig = %v, %v; want errFrame and nothing", version, a, err)
		}
	}
}
