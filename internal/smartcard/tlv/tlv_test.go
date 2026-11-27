package tlv_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/smartcard/tlv"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The shape of the objects of the card application (specification 3.4.1, section 4.4): a signature
// counter, the extended length information and a tree that nests three levels.
func TestParseCardObjects(t *testing.T) {
	counter := unhex(t, "7A 05 93 03 00 00 2A")
	nodes, err := tlv.Parse(counter)
	if err != nil {
		t.Fatal(err)
	}
	n, err := tlv.Find(nodes, 0x7A, 0x93)
	if err != nil || !bytes.Equal(n.Value, []byte{0, 0, 0x2A}) {
		t.Fatalf("counter: %v %x", err, n)
	}

	ext := unhex(t, "7F66 08 02 02 08 00 02 02 08 00")
	nodes, err = tlv.Parse(ext)
	if err != nil || len(nodes) != 1 || nodes[0].Tag != 0x7F66 || !nodes[0].Tag.Constructed() || len(nodes[0].Children) != 2 {
		t.Fatalf("7F66: %v %+v", err, nodes)
	}

	// 6E { 4F, 5F52, 73 { C4, 7F66 } }: one, two and three levels, tags of one and two bytes.
	tree := unhex(t, "6E 16 4F 02 D2 76 5F52 02 00 73 73 0B C4 02 01 03 7F66 04 02 02 00 FF")
	nodes, err = tlv.Parse(tree)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := tlv.Find(nodes, 0x6E, 0x73, 0x7F66, 0x02); err != nil || !bytes.Equal(n.Value, []byte{0, 0xFF}) {
		t.Fatalf("7F66 below 73: %v %+v", err, n)
	}
	if n, err := tlv.Find(nodes, 0x6E, 0x73, 0xC4); err != nil || !bytes.Equal(n.Value, []byte{1, 3}) {
		t.Fatalf("C4: %v %+v", err, n)
	}
	got, err := tlv.Encode(nodes)
	if err != nil || !bytes.Equal(got, tree) {
		t.Fatalf("encode: %v %x", err, got)
	}
}

func TestTagForms(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want tlv.Tag
		cons bool
	}{
		{"C4 00", 0xC4, false},
		{"73 00", 0x73, true},
		{"5F52 00", 0x5F52, false},
		{"7F21 00", 0x7F21, true},
		{"9F8101 00", 0x9F8101, false},
		{"BF8101 00", 0xBF8101, true},
	} {
		n, err := tlv.ParseOne(unhex(t, tc.in))
		if err != nil || n.Tag != tc.want || n.Tag.Constructed() != tc.cons {
			t.Errorf("%s: %v %+v", tc.in, err, n)
		}
	}
	if s := tlv.Tag(0x7F66).String(); s != "7F66" {
		t.Errorf("String: %q", s)
	}
}

func TestLengthForms(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 255, 256, 1000, 65000} {
		in := tlv.Node{Tag: 0xC0, Value: make([]byte, n)}
		enc, err := tlv.Encode([]tlv.Node{in})
		if err != nil {
			t.Fatal(err)
		}
		wantHeader := 2
		switch {
		case n >= 256:
			wantHeader = 4
		case n >= 128:
			wantHeader = 3
		}
		if len(enc) != n+wantHeader {
			t.Errorf("%d: encoded %d bytes, want %d", n, len(enc), n+wantHeader)
		}
		out, err := tlv.ParseOne(enc)
		if err != nil || len(out.Value) != n {
			t.Errorf("%d: %v", n, err)
		}
	}
}

func TestRefusals(t *testing.T) {
	long := strings.Repeat("00", 300)
	for _, tc := range []struct {
		name string
		in   string
		want error
	}{
		{"no length", "C0", tlv.ErrTruncated},
		{"cut tag", "5F", tlv.ErrTruncated},
		{"cut three byte tag", "9F81", tlv.ErrTruncated},
		{"cut 81", "C0 81", tlv.ErrTruncated},
		{"cut 82", "C0 82 01", tlv.ErrTruncated},
		{"indefinite", "C0 80 00 00", tlv.ErrIndefiniteLength},
		{"constructed indefinite", "73 80 C0 00 00 00", tlv.ErrIndefiniteLength},
		{"form 83", "C0 83 00 00 01 00", tlv.ErrLengthForm},
		{"form FF", "C0 FF", tlv.ErrLengthForm},
		{"length past data", "C0 05 00 00", tlv.ErrLengthPastData},
		{"81 past data", "C0 81 90 00", tlv.ErrLengthPastData},
		{"child past parent", "73 03 C0 05 00 00 00 00 00", tlv.ErrLengthPastData},
		{"81 for short", "C0 81 05 0000000000", tlv.ErrLengthNotMinimal},
		{"82 for one byte", "C0 82 00 FF " + long[:2*255], tlv.ErrLengthNotMinimal},
		{"padding 00", "00", tlv.ErrPadding},
		{"padding FF", "FF 00", tlv.ErrPadding},
		{"padding after a node", "C0 00 00", tlv.ErrPadding},
		{"padding inside", "73 03 C0 00 FF", tlv.ErrPadding},
		{"tag number below 31", "5F 1E 00", tlv.ErrTag},
		{"tag number zero", "5F 00 00", tlv.ErrTag},
		{"three byte tag with a zero number part", "5F 80 01 00", tlv.ErrTag},
		{"four byte tag", "5F 81 81 01 00", tlv.ErrTagTooLong},
		{"constructed content not whole", "73 02 C0 05", tlv.ErrLengthPastData},
		{"constructed with a stray byte", "73 01 C0", tlv.ErrTruncated},
	} {
		nodes, err := tlv.Parse(unhex(t, tc.in))
		if !errors.Is(err, tc.want) || nodes != nil {
			t.Errorf("%s: %v %v, want %v", tc.name, err, nodes, tc.want)
		}
	}
	if _, err := tlv.ParseOne(unhex(t, "C0 00 C0 00")); !errors.Is(err, tlv.ErrTrailing) {
		t.Errorf("trailing: %v", err)
	}
	if _, err := tlv.ParseOne(nil); !errors.Is(err, tlv.ErrTruncated) {
		t.Errorf("empty ParseOne: %v", err)
	}
	if nodes, err := tlv.Parse(nil); err != nil || len(nodes) != 0 {
		t.Errorf("empty Parse: %v %v", err, nodes)
	}
}

func TestOffsetInError(t *testing.T) {
	_, err := tlv.Parse(unhex(t, "C0 01 AA 73 03 C0 05 00"))
	if err == nil || !strings.Contains(err.Error(), "at byte 6") {
		t.Fatalf("%v", err)
	}
}

func nest(levels int) []byte {
	// levels of the constructed tag 30, innermost holds one primitive object.
	b := []byte{0xC0, 0x00}
	for range levels {
		b = append([]byte{0x30, byte(len(b))}, b...)
	}
	return b
}

func TestLimits(t *testing.T) {
	if _, err := tlv.Parse(nest(tlv.MaxDepth - 1)); err != nil {
		t.Fatalf("depth at the limit: %v", err)
	}
	if _, err := tlv.Parse(nest(tlv.MaxDepth)); !errors.Is(err, tlv.ErrTooDeep) {
		t.Fatalf("depth over the limit: %v", err)
	}
	if _, err := tlv.Parse(bytes.Repeat([]byte{0xC0, 0x00}, tlv.MaxNodes)); err != nil {
		t.Fatalf("nodes at the limit: %v", err)
	}
	if _, err := tlv.Parse(bytes.Repeat([]byte{0xC0, 0x00}, tlv.MaxNodes+1)); !errors.Is(err, tlv.ErrTooManyNodes) {
		t.Fatalf("nodes over the limit: %v", err)
	}
	if _, err := tlv.Parse(make([]byte, tlv.MaxSize+1)); !errors.Is(err, tlv.ErrTooLarge) {
		t.Fatalf("size over the limit: %v", err)
	}
	// The same limits hold for Encode, so that what it writes can be read back.
	if _, err := tlv.Encode([]tlv.Node{{Tag: 0xC0, Value: make([]byte, tlv.MaxSize)}}); !errors.Is(err, tlv.ErrTooLarge) {
		t.Fatalf("encode size: %v", err)
	}
	deep := tlv.Node{Tag: 0xC0}
	for range tlv.MaxDepth {
		deep = tlv.Node{Tag: 0x30, Children: []tlv.Node{deep}}
	}
	if _, err := tlv.Encode([]tlv.Node{deep}); !errors.Is(err, tlv.ErrTooDeep) {
		t.Fatalf("encode depth: %v", err)
	}
	many := make([]tlv.Node, tlv.MaxNodes+1)
	for i := range many {
		many[i] = tlv.Node{Tag: 0xC0}
	}
	if _, err := tlv.Encode(many); !errors.Is(err, tlv.ErrTooManyNodes) {
		t.Fatalf("encode nodes: %v", err)
	}
}

func TestEncodeRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		node tlv.Node
		want error
	}{
		{"zero tag", tlv.Node{Tag: 0}, tlv.ErrPadding},
		{"FF tag", tlv.Node{Tag: 0xFF}, tlv.ErrPadding},
		{"tag 1F alone", tlv.Node{Tag: 0x1F}, tlv.ErrTag},
		{"tag number below 31", tlv.Node{Tag: 0x5F1E}, tlv.ErrTag},
		{"four bytes", tlv.Node{Tag: 0x1F818101}, tlv.ErrTagTooLong},
		{"primitive with children", tlv.Node{Tag: 0xC0, Children: []tlv.Node{{Tag: 0xC0}}}, tlv.ErrNodeShape},
		{"constructed with a value", tlv.Node{Tag: 0x73, Value: []byte{1}}, tlv.ErrNodeShape},
	} {
		out, err := tlv.Encode([]tlv.Node{tc.node})
		if !errors.Is(err, tc.want) || out != nil {
			t.Errorf("%s: %v %x", tc.name, err, out)
		}
	}
}

func TestFind(t *testing.T) {
	nodes, err := tlv.Parse(unhex(t, "6E 0B 73 05 C0 01 AA C1 00 C4 00 C4 00"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tlv.Find(nodes, 0x6E, 0xC4); !errors.Is(err, tlv.ErrAmbiguous) {
		t.Errorf("two C4: %v", err)
	}
	if _, err := tlv.Find(nodes, 0x6E, 0x73, 0xC0); err != nil {
		t.Errorf("path: %v", err)
	}
	if _, err := tlv.Find(nodes, 0x6E, 0x73, 0xC2); !errors.Is(err, tlv.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	if _, err := tlv.Find(nodes, 0x6E, 0xC0, 0xC0); !errors.Is(err, tlv.ErrNotFound) {
		t.Errorf("below a primitive: %v", err)
	}
	if _, err := tlv.Find(nodes); !errors.Is(err, tlv.ErrNotFound) {
		t.Errorf("empty path: %v", err)
	}
}

func TestParseCopies(t *testing.T) {
	in := unhex(t, "C0 02 AA BB")
	nodes, err := tlv.Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	clear(in)
	if !bytes.Equal(nodes[0].Value, []byte{0xAA, 0xBB}) {
		t.Fatalf("the result shares the input: %x", nodes[0].Value)
	}
}
