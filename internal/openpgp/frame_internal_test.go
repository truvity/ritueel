package openpgp

import (
	"bytes"
	"math/big"
	"testing"
)

func bigFrom(v int64) *big.Int { return big.NewInt(v) }

// The length forms of RFC 9580, sections 4.2.1.1 to 4.2.1.3 (packets) and 5.2.3.7 (subpackets),
// written out by hand for the sizes at the edges of each form and compared with what the package
// writes and reads.

func TestAPacketHeaderHasTheLengthFormOfRFC9580(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0xCD, 0}},
		{1, []byte{0xCD, 1}},
		{191, []byte{0xCD, 191}},
		{192, []byte{0xCD, 0xC0, 0x00}},
		{193, []byte{0xCD, 0xC0, 0x01}},
		{255, []byte{0xCD, 0xC0, 0x3F}},
		{256, []byte{0xCD, 0xC0, 0x40}},
		{8383, []byte{0xCD, 0xDF, 0xFF}},
		{8384, []byte{0xCD, 0xFF, 0x00, 0x00, 0x20, 0xC0}},
		{65536, []byte{0xCD, 0xFF, 0x00, 0x01, 0x00, 0x00}},
	}
	for _, c := range cases {
		if got := header(13, c.n); !bytes.Equal(got, c.want) {
			t.Errorf("header(13, %d) = % x, want % x", c.n, got, c.want)
		}
		pkt := append(append([]byte{}, c.want...), make([]byte, c.n)...)
		tag, body, rest, err := splitPacket(pkt)
		if err != nil || tag != 13 || len(body) != c.n || len(rest) != 0 {
			t.Errorf("splitPacket of a packet of %d bytes: tag %d, body %d, rest %d, %v", c.n, tag, len(body), len(rest), err)
		}
	}
}

func TestAPacketHeaderOfTheOldFormatIsRead(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		n    int
	}{
		{"one octet of length", append([]byte{0x80 | 13<<2, 3}, 1, 2, 3), 3},
		{"two octets of length", append([]byte{0x80 | 13<<2 | 1, 0x01, 0x00}, make([]byte, 256)...), 256},
		{"four octets of length", append([]byte{0x80 | 13<<2 | 2, 0, 0, 0x01, 0x00}, make([]byte, 256)...), 256},
	}
	for _, c := range cases {
		tag, body, rest, err := splitPacket(c.pkt)
		if err != nil || tag != 13 || len(body) != c.n || len(rest) != 0 {
			t.Errorf("%s: tag %d, body %d, rest %d, %v", c.name, tag, len(body), len(rest), err)
		}
	}
}

func TestAPacketHeaderThatIsNotAPacketHeaderIsRefused(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":                             nil,
		"one byte":                          {0xCD},
		"the leading bit clear":             {0x4D, 0x01, 0x00},
		"a partial length":                  {0xCD, 0xE1, 0x00},
		"an indeterminate old length":       {0x80 | 13<<2 | 3, 0x00},
		"a two-octet length cut short":      {0xCD, 0xC0},
		"a five-octet length cut short":     {0xCD, 0xFF, 0, 0, 0},
		"a body shorter than its length":    {0xCD, 0x05, 1, 2},
		"a length that overflows":           {0xCD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		"an old two-octet length cut short": {0x80 | 13<<2 | 1, 0x00},
	} {
		if _, _, _, err := splitPacket(b); err == nil {
			t.Errorf("%s: splitPacket accepts % x", name, b)
		}
	}
}

func TestASubpacketHasTheLengthFormOfRFC9580(t *testing.T) {
	// The length counts the type octet. The one-octet form ends at a length of 191 (190 bytes of
	// data), the two-octet form at a length of 16319 (16318 bytes of data), and the five-octet form
	// follows.
	cases := []struct {
		dataLen int
		want    []byte
	}{
		{0, []byte{1}},
		{190, []byte{191}},
		{191, []byte{0xC0, 0x00}},
		{192, []byte{0xC0, 0x01}},
		{16318, []byte{0xFE, 0xFF}},
		{16319, []byte{0xFF, 0x00, 0x00, 0x3F, 0xC0}},
		{16320, []byte{0xFF, 0x00, 0x00, 0x3F, 0xC1}},
	}
	for _, c := range cases {
		got := subpacket{typ: 101, data: make([]byte, c.dataLen)}.encode()
		if !bytes.HasPrefix(got, c.want) {
			t.Errorf("a subpacket of %d bytes of data starts % x, want % x", c.dataLen, got[:len(c.want)], c.want)
		}
		hl := len(c.want)
		if len(got) != hl+1+c.dataLen {
			t.Errorf("a subpacket of %d bytes of data is %d bytes, want %d", c.dataLen, len(got), hl+1+c.dataLen)
		}
		subs, err := parseArea(got)
		if err != nil || len(subs) != 1 || len(subs[0].data) != c.dataLen || subs[0].typ != 101 {
			t.Errorf("a subpacket of %d bytes of data does not read back: %v", c.dataLen, err)
		}
	}
}

func TestASubpacketAreaIsReadByTheLengthFormOfRFC9580(t *testing.T) {
	two := append([]byte{0xC0, 0x00, 101}, make([]byte, 191)...) // length 192 = (0xC0-192)<<8 + 0 + 192, with the type
	five := append([]byte{0xFF, 0, 0, 0, 4, 101}, 1, 2, 3)
	for name, c := range map[string]struct {
		area []byte
		n    int
	}{"a two-octet length": {two, 191}, "a five-octet length": {five, 3}} {
		subs, err := parseArea(c.area)
		if err != nil || len(subs) != 1 || len(subs[0].data) != c.n || subs[0].typ != 101 {
			t.Errorf("%s: %v, %d subpackets", name, err, len(subs))
		}
	}
	if _, err := parseArea([]byte{0xC0}); err == nil {
		t.Error("a two-octet length cut short is accepted")
	}
	if _, err := parseArea([]byte{0xFF, 0, 0}); err == nil {
		t.Error("a five-octet length cut short is accepted")
	}
	if _, err := parseArea([]byte{0}); err == nil {
		t.Error("a subpacket of length 0 (no type octet) is accepted")
	}
}

func TestAnMPIHasItsBitLengthAndNoLeadingZeroByte(t *testing.T) {
	if got := mpi(bigFrom(0x01)); !bytes.Equal(got, []byte{0, 1, 1}) {
		t.Errorf("mpi(1) = % x", got)
	}
	if got := mpi(bigFrom(0x0100)); !bytes.Equal(got, []byte{0, 9, 1, 0}) {
		t.Errorf("mpi(256) = % x", got)
	}
	if got := mpi(bigFrom(0xFF)); !bytes.Equal(got, []byte{0, 8, 0xFF}) {
		t.Errorf("mpi(255) = % x", got)
	}
}
