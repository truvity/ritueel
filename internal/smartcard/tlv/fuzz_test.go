package tlv_test

import (
	"bytes"
	"testing"

	"ritueel.id/ritueel/internal/smartcard/tlv"
)

func count(nodes []tlv.Node) int {
	n := len(nodes)
	for i := range nodes {
		n += count(nodes[i].Children)
	}
	return n
}

// FuzzParse holds that Parse never panics, that a tree it returns is within the limits, and that
// Encode writes it back as the very bytes that were read (the reader accepts one form of each length, so
// the bytes and the tree are the same thing), and that those bytes read as the same tree.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"", "00", "FF", "C0 00", "7A 05 93 03 00 00 2A", "7F66 08 02 02 08 00 02 02 08 00",
		"6E 16 4F 02 D2 76 5F52 02 00 73 73 0B C4 02 01 03 7F66 04 02 02 00 FF",
		"C0 81 80", "C0 82 01 00", "C0 80", "C0 83 00 00 00", "9F8101 01 AA", "5F 81 81 01 00", "73 03 C0 05 00",
	} {
		f.Add(unhex(f, s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		nodes, err := tlv.Parse(data)
		if err != nil {
			if nodes != nil {
				t.Fatal("nodes with an error")
			}
			return
		}
		if count(nodes) > tlv.MaxNodes {
			t.Fatal("more nodes than the limit")
		}
		enc, err := tlv.Encode(nodes)
		if err != nil {
			t.Fatalf("Encode refused what Parse returned: %v", err)
		}
		if !bytes.Equal(enc, data) {
			t.Fatalf("Encode(Parse(x)) is not x: %x vs %x", enc, data)
		}
		again, err := tlv.Parse(enc)
		if err != nil || count(again) != count(nodes) {
			t.Fatalf("re-parse: %v", err)
		}
		if len(data) > 0 && len(data) < 64 {
			if _, err := tlv.ParseOne(data); err == nil && len(nodes) != 1 {
				t.Fatal("ParseOne accepted more than one object")
			}
		}
	})
}

// FuzzEncode holds that a tree Encode accepts is read back by Parse as the same bytes.
func FuzzEncode(f *testing.F) {
	f.Add(uint32(0x7F66), []byte{1, 2, 3}, uint32(0xC0), []byte{4})
	f.Add(uint32(0x73), []byte{}, uint32(0x5F52), []byte{})
	f.Fuzz(func(t *testing.T, tag uint32, value []byte, childTag uint32, childValue []byte) {
		n := tlv.Node{Tag: tlv.Tag(tag), Value: value}
		if n.Tag.Constructed() {
			n = tlv.Node{Tag: n.Tag, Children: []tlv.Node{{Tag: tlv.Tag(childTag), Value: childValue}}}
		}
		enc, err := tlv.Encode([]tlv.Node{n})
		if err != nil {
			return
		}
		nodes, err := tlv.Parse(enc)
		if err != nil {
			t.Fatalf("Parse refused what Encode wrote: %v", err)
		}
		back, err := tlv.Encode(nodes)
		if err != nil || !bytes.Equal(back, enc) {
			t.Fatalf("not stable: %v", err)
		}
	})
}
