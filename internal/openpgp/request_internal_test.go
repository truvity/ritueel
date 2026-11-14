package openpgp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// splitPacket is the framing under every reader of a request. When it refuses, it returns no tag, no
// body and no rest, so that no caller can use a half-read packet.
func TestSplitPacketReturnsNothingOnEveryPathOfRefusal(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"no bytes", nil},
		{"one byte", []byte{0xC2}},
		{"a header without the high bit", []byte{0x42, 0x00}},
		{"a new-format two-octet length that is cut", []byte{0xC2, 0xC5}},
		{"a new-format five-octet length that is cut", []byte{0xC2, 0xFF, 0, 0, 0}},
		{"a new-format partial length", []byte{0xC2, 0xE5, 1, 2}},
		{"a new-format length that leaves the packet", []byte{0xC2, 0x05, 1}},
		{"an old-format two-octet length that is cut", []byte{0x85, 0x00}},
		{"an old-format four-octet length that is cut", []byte{0x8A, 0, 0, 0}},
		{"an old-format indeterminate length", []byte{0x8B, 1, 2, 3}},
		{"an old-format length that leaves the packet", []byte{0x88, 0x05, 1}},
		{"a new-format length of 4 GiB", []byte{0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tag, body, rest, err := splitPacket(c.b)
			if err == nil {
				t.Fatal("the packet was read")
			}
			if tag != 0 || body != nil || rest != nil {
				t.Errorf("tag %d, body %d bytes and rest %d bytes came back with the error", tag, len(body), len(rest))
			}
		})
	}
}

// readMPI returns the bytes of the number, without the two bytes of its length, and what follows.
func TestReadMPIReturnsTheBytesOfTheNumberAndWhatFollows(t *testing.T) {
	value, rest, err := readMPI([]byte{0x00, 0x09, 0x01, 0xFF, 0xAA, 0xBB})
	if err != nil || !bytes.Equal(value, []byte{0x01, 0xFF}) || !bytes.Equal(rest, []byte{0xAA, 0xBB}) {
		t.Errorf("value % x, rest % x, error %v, want 01 ff, aa bb and no error", value, rest, err)
	}
	for _, bad := range [][]byte{nil, {0}, {0, 0}, {0, 0, 1}, {0, 9, 1}, {0, 9, 0, 0xFF}, {0, 8, 0x7F}, {0, 7, 0xFF}} {
		if v, r, err := readMPI(bad); err == nil || v != nil || r != nil {
			t.Errorf("% x: value % x, rest % x, error %v, want a refusal that returns nothing", bad, v, r, err)
		}
	}
}

// The hash prefix of a key writes the length of the body in two bytes, high byte first.
func TestHashPrefixHasThePrefixByteAndTheTwoByteLengthOfTheBody(t *testing.T) {
	for _, n := range []int{0, 1, 111, 255, 256, 600, 65535} {
		body := make([]byte, n)
		got := hashPrefix(body)
		if len(got) != 3+n || got[0] != 0x99 || got[1] != byte(n>>8) || got[2] != byte(n) {
			t.Errorf("a body of %d bytes: prefix % x", n, got[:3])
		}
	}
}

// A subpacket of 16 MiB and more is written with the five-octet length, the four bytes in full.
func TestASubpacketLengthIsWrittenInFourBytesWhenItIsVeryLong(t *testing.T) {
	for _, c := range []struct {
		data int
		want []byte
	}{
		{0, []byte{1, 5}},
		{190, []byte{191, 5}},
		{191, []byte{0xC0, 0x00, 5}},
		{16318, []byte{0xFE, 0xFF, 5}},
		{16319, []byte{0xFF, 0, 0, 0x3F, 0xC0, 5}},
		{1<<24 + 5, []byte{0xFF, 0x01, 0x00, 0x00, 0x06, 5}},
		{1<<25 + 1, []byte{0xFF, 0x02, 0x00, 0x00, 0x02, 5}},
	} {
		got := subpacket{typ: 5, data: make([]byte, c.data)}.encode()
		if !bytes.HasPrefix(got, c.want[:len(c.want)-1]) || got[len(c.want)-1] != 5 || len(got) != len(c.want)+c.data {
			t.Errorf("a subpacket of %d bytes: header % x, want % x", c.data, got[:len(c.want)], c.want)
		}
	}
}

// readKey reads exactly one packet of the tag it is asked for, and nothing after it: a packet of the
// other tag, a packet that is cut and a packet with a byte after it are refused, and nothing comes
// back with the error.
func TestReadKeyReadsOnePacketOfTheTagItIsAskedFor(t *testing.T) {
	k, err := newKey(testKey(t), testTime)
	if err != nil {
		t.Fatal(err)
	}
	sub := wrap(tagSubkey, k.body)
	primary := wrap(tagPublicKey, k.body)
	if got, err := readKey(sub, tagSubkey); err != nil || !bytes.Equal(got.body, k.body) {
		t.Fatalf("a subkey packet: %v", err)
	}
	if got, err := readKey(primary, tagPublicKey); err != nil || !bytes.Equal(got.body, k.body) {
		t.Fatalf("a primary packet: %v", err)
	}
	for name, c := range map[string]struct {
		pkt []byte
		tag byte
	}{
		"a subkey packet read as a primary":       {sub, tagPublicKey},
		"a primary packet read as a subkey":       {primary, tagSubkey},
		"a subkey packet and a byte after it":     {append(bytes.Clone(sub), 0), tagSubkey},
		"a primary packet and a byte after it":    {append(bytes.Clone(primary), 0xC2), tagPublicKey},
		"a subkey packet and a second one":        {append(bytes.Clone(sub), sub...), tagSubkey},
		"a cut subkey packet":                     {sub[:len(sub)-1], tagSubkey},
		"no bytes":                                {nil, tagSubkey},
		"a subkey packet read for the tag 0":      {sub, 0},
		"a subkey packet read for the user ID":    {sub, tagUserID},
		"a signature-tagged packet with the body": {wrap(tagSignature, k.body), tagSignature},
	} {
		if got, err := readKey(c.pkt, c.tag); err == nil || got != nil {
			t.Errorf("%s: read, with error %v", name, err)
		}
	}
}

func testKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

var testTime = time.Unix(1767225600, 0).UTC()
