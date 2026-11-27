package tlv_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/smartcard/tlv"
)

// The tests of this file are written from the rules of the standard and not from the code: ITU-T X.690
// clause 8.1.2 (the identifier octets), clause 8.1.3 (the length octets), ISO/IEC 7816-4 clause 5.2.2
// (BER-TLV data objects) and the OpenPGP smart card application, specification 3.4.1, section 4.4.
// Every expected tree and every expected byte is spelled out by hand.

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// prim and cons build the expected trees.
func prim(tag tlv.Tag, value ...byte) tlv.Node { return tlv.Node{Tag: tag, Value: value} }
func cons(tag tlv.Tag, children ...tlv.Node) tlv.Node {
	return tlv.Node{Tag: tag, Children: children}
}

// sameTree compares two trees; an empty value and a missing one are the same thing.
func sameTree(a, b []tlv.Node) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Tag != b[i].Tag || !bytes.Equal(a[i].Value, b[i].Value) || !sameTree(a[i].Children, b[i].Children) {
			return false
		}
	}
	return true
}

func repeat(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

type wellFormedCase struct {
	name string
	in   []byte
	want []tlv.Node
}

// wellFormed is the table of inputs that the standard makes whole data objects, with the tree each one
// reads as. Each one is also written back by Encode as the same bytes.
func wellFormed(t testing.TB) []wellFormedCase {
	h := func(s string) []byte { return mustHex(t, s) }
	// The deepest tree the limit allows: eight levels, the innermost holding a primitive object.
	deepest := h("C0 01 AA")
	deepTree := prim(0xC0, 0xAA)
	for range 7 {
		deepest = cat([]byte{0x30, byte(len(deepest))}, deepest)
		deepTree = cons(0x30, deepTree)
	}
	// The same with a constructed object that is empty at the eighth level.
	deepEmpty := h("30 00")
	deepEmptyTree := cons(0x30)
	for range 7 {
		deepEmpty = cat([]byte{0x30, byte(len(deepEmpty))}, deepEmpty)
		deepEmptyTree = cons(0x30, deepEmptyTree)
	}
	// A constructed object whose content is 128 bytes: the first length that needs the form 0x81.
	var kids64 []tlv.Node
	for range 64 {
		kids64 = append(kids64, prim(0xC0))
	}
	return []wellFormedCase{
		{"no object", nil, nil},
		{"one byte tag, empty value", h("C0 00"), []tlv.Node{prim(0xC0)}},
		{"one byte tag, value", h("C4 01 03"), []tlv.Node{prim(0xC4, 3)}},
		{"two byte tag", h("5F52 02 00 31"), []tlv.Node{prim(0x5F52, 0x00, 0x31)}},
		{"two byte tag, lowest number", h("1F1F 00"), []tlv.Node{prim(0x1F1F)}},
		{"two byte tag, highest number", h("1F7F 00"), []tlv.Node{prim(0x1F7F)}},
		{"three byte tag", h("9F8101 01 AA"), []tlv.Node{prim(0x9F8101, 0xAA)}},
		{"three byte tag, lowest number (128)", h("1F8100 00"), []tlv.Node{prim(0x1F8100)}},
		{"three byte tag, highest number (16383)", h("1FFF7F 00"), []tlv.Node{prim(0x1FFF7F)}},
		{"two byte constructed tag", h("7F66 08 02 02 08 00 02 02 08 00"),
			[]tlv.Node{cons(0x7F66, prim(0x02, 0x08, 0x00), prim(0x02, 0x08, 0x00))}},
		{"three byte constructed tag", h("BF8101 03 C0 01 AA"), []tlv.Node{cons(0xBF8101, prim(0xC0, 0xAA))}},
		{"constructed, empty", h("73 00"), []tlv.Node{cons(0x73)}},
		{"siblings", h("C0 01 AA C1 00 C2 02 BB CC"), []tlv.Node{prim(0xC0, 0xAA), prim(0xC1), prim(0xC2, 0xBB, 0xCC)}},
		{"siblings with tags of three lengths", h("C0 00 5F52 00 9F8101 00"), []tlv.Node{prim(0xC0), prim(0x5F52), prim(0x9F8101)}},
		{"constructed beside primitive", h("73 03 C0 01 AA C1 00"),
			[]tlv.Node{cons(0x73, prim(0xC0, 0xAA)), prim(0xC1)}},
		{"length 127, the last short form", cat(h("C0 7F"), repeat(1, 127)), []tlv.Node{prim(0xC0, repeat(1, 127)...)}},
		{"length 128, the first 0x81 form", cat(h("C0 81 80"), repeat(2, 128)), []tlv.Node{prim(0xC0, repeat(2, 128)...)}},
		{"length 255, the last 0x81 form", cat(h("C0 81 FF"), repeat(3, 255)), []tlv.Node{prim(0xC0, repeat(3, 255)...)}},
		{"length 256, the first 0x82 form", cat(h("C0 82 01 00"), repeat(4, 256)), []tlv.Node{prim(0xC0, repeat(4, 256)...)}},
		{"length 65531, the most that a tag of one byte leaves room for",
			cat(h("C0 82 FF FB"), repeat(5, 65531)), []tlv.Node{prim(0xC0, repeat(5, 65531)...)}},
		{"length 65529 under a tag of three bytes", cat(h("9F8101 82 FF F9"), repeat(6, 65529)),
			[]tlv.Node{prim(0x9F8101, repeat(6, 65529)...)}},
		{"constructed of 128 bytes", cat(h("73 81 80"), bytes.Repeat(h("C0 00"), 64)), []tlv.Node{cons(0x73, kids64...)}},
		{"eight levels", deepest, []tlv.Node{deepTree}},
		{"eight levels, the last one constructed and empty", deepEmpty, []tlv.Node{deepEmptyTree}},
		{"the application related data of a card",
			h("6E 16 4F 02 D2 76 5F52 02 00 73 73 0B C4 02 01 03 7F66 04 02 02 00 FF"),
			[]tlv.Node{cons(0x6E,
				prim(0x4F, 0xD2, 0x76),
				prim(0x5F52, 0x00, 0x73),
				cons(0x73, prim(0xC4, 0x01, 0x03), cons(0x7F66, prim(0x02, 0x00, 0xFF))),
			)}},
	}
}

func TestWellFormedInputs(t *testing.T) {
	for _, tc := range wellFormed(t) {
		nodes, err := tlv.Parse(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !sameTree(nodes, tc.want) {
			t.Errorf("%s: tree %+v", tc.name, nodes)
		}
		enc, err := tlv.Encode(nodes)
		if err != nil || !bytes.Equal(enc, tc.in) {
			t.Errorf("%s: Encode(Parse(x)) != x (%v)", tc.name, err)
		}
		// Encode of the hand-written tree gives the same bytes.
		enc, err = tlv.Encode(tc.want)
		if err != nil || !bytes.Equal(enc, tc.in) {
			t.Errorf("%s: Encode(want) != x (%v)", tc.name, err)
		}
		one, err := tlv.ParseOne(tc.in)
		if len(tc.want) == 1 && (err != nil || !sameTree([]tlv.Node{one}, tc.want)) {
			t.Errorf("%s: ParseOne: %v", tc.name, err)
		}
		if len(tc.want) != 1 && err == nil {
			t.Errorf("%s: ParseOne accepted %d objects", tc.name, len(tc.want))
		}
	}
}

// TestRefusalsOneByOne has the smallest input for each named error, and the byte offset that the error
// names (-1: the error names none). The offsets are counted by hand.
func TestRefusalsOneByOne(t *testing.T) {
	deep9 := mustHex(t, "C0 00")
	for range 8 {
		deep9 = cat([]byte{0x30, byte(len(deep9))}, deep9)
	}
	deep9Empty := mustHex(t, "30 00")
	for range 8 {
		deep9Empty = cat([]byte{0x30, byte(len(deep9Empty))}, deep9Empty)
	}
	for _, tc := range []struct {
		name   string
		in     []byte
		want   error
		offset int
	}{
		{"a tag, no length", mustHex(t, "C0"), tlv.ErrTruncated, 1},
		{"a tag cut after its first byte", mustHex(t, "5F"), tlv.ErrTruncated, 0},
		{"a tag cut after its second byte", mustHex(t, "5F 81"), tlv.ErrTruncated, 0},
		{"0x81 with no byte", mustHex(t, "C0 81"), tlv.ErrTruncated, 1},
		{"0x82 with one byte", mustHex(t, "C0 82 01"), tlv.ErrTruncated, 1},
		{"0x82 with no byte", mustHex(t, "C0 82"), tlv.ErrTruncated, 1},
		{"length one past the data", mustHex(t, "C0 01"), tlv.ErrLengthPastData, 1},
		{"0x81 length one past the data", cat(mustHex(t, "C0 81 80"), repeat(0, 127)), tlv.ErrLengthPastData, 1},
		{"0x82 length one past the data", cat(mustHex(t, "C0 82 01 00"), repeat(0, 255)), tlv.ErrLengthPastData, 1},
		{"0x82 length 65531 with 65530 bytes", cat(mustHex(t, "C0 82 FF FB"), repeat(0, 65530)), tlv.ErrLengthPastData, 1},
		{"indefinite length", mustHex(t, "C0 80"), tlv.ErrIndefiniteLength, 1},
		{"length form 0x83", mustHex(t, "C0 83"), tlv.ErrLengthForm, 1},
		{"length form 0xFF", mustHex(t, "C0 FF"), tlv.ErrLengthForm, 1},
		{"0x81 for 127", mustHex(t, "C0 81 7F"), tlv.ErrLengthNotMinimal, 1},
		{"0x81 for 0", mustHex(t, "C0 81 00"), tlv.ErrLengthNotMinimal, 1},
		{"0x82 for 255", mustHex(t, "C0 82 00 FF"), tlv.ErrLengthNotMinimal, 1},
		{"0x82 for 0", mustHex(t, "C0 82 00 00"), tlv.ErrLengthNotMinimal, 1},
		{"tag number 30 in two bytes", mustHex(t, "5F 1E"), tlv.ErrTag, 0},
		{"tag number 0 in two bytes", mustHex(t, "5F 00"), tlv.ErrTag, 0},
		{"three byte tag with a zero number part", mustHex(t, "5F 80"), tlv.ErrTag, 0},
		{"four byte tag", mustHex(t, "5F 81 81"), tlv.ErrTagTooLong, 0},
		{"four byte tag, all high", mustHex(t, "5F FF FF"), tlv.ErrTagTooLong, 0},
		{"padding 00 alone", mustHex(t, "00"), tlv.ErrPadding, 0},
		{"padding FF alone", mustHex(t, "FF"), tlv.ErrPadding, 0},
		{"padding 00 at the start", mustHex(t, "00 C0 00"), tlv.ErrPadding, 0},
		{"padding FF at the start", mustHex(t, "FF C0 00"), tlv.ErrPadding, 0},
		{"padding 00 between siblings", mustHex(t, "C0 00 00 C1 00"), tlv.ErrPadding, 2},
		{"padding FF between siblings", mustHex(t, "C0 00 FF C1 00"), tlv.ErrPadding, 2},
		{"padding 00 at the end", mustHex(t, "C0 00 C1 00 00"), tlv.ErrPadding, 4},
		{"padding FF at the end", mustHex(t, "C0 00 C1 00 FF"), tlv.ErrPadding, 4},
		{"padding 00 inside a constructed object", mustHex(t, "73 01 00"), tlv.ErrPadding, 2},
		{"padding FF between siblings inside", mustHex(t, "73 05 C0 00 FF C1 00"), tlv.ErrPadding, 4},
		{"padding 00 at the end inside", mustHex(t, "73 03 C0 00 00"), tlv.ErrPadding, 4},
		{"the size limit and one byte more", cat(mustHex(t, "C0 82 FF FC"), repeat(0, 65532)), tlv.ErrTooLarge, -1},
		{"nine levels", deep9, tlv.ErrTooDeep, 16},
		{"nine levels, the last constructed and empty", deep9Empty, tlv.ErrTooDeep, 16},
		{"1025 objects", bytes.Repeat(mustHex(t, "C0 00"), tlv.MaxNodes+1), tlv.ErrTooManyNodes, 2 * tlv.MaxNodes},
		{"a parent and 1024 children", cat(mustHex(t, "73 82 08 00"), bytes.Repeat(mustHex(t, "C0 00"), 1024)), tlv.ErrTooManyNodes, 4 + 2*1023},
	} {
		nodes, err := tlv.Parse(tc.in)
		if !errors.Is(err, tc.want) || nodes != nil {
			t.Errorf("%s: %v %v, want %v", tc.name, err, nodes, tc.want)
			continue
		}
		if tc.offset >= 0 && !strings.HasSuffix(err.Error(), fmt.Sprintf("(at byte %d)", tc.offset)) {
			t.Errorf("%s: the error names another offset than %d: %v", tc.name, tc.offset, err)
		}
		// A refusal of the one object is the same refusal, and shows no byte of the data.
		// (When the fault comes after a whole object, the one-object reader says first that bytes follow it.)
		if _, err := tlv.ParseOne(tc.in); !errors.Is(err, tc.want) && !errors.Is(err, tlv.ErrTrailing) {
			t.Errorf("%s: ParseOne: %v", tc.name, err)
		}
		if len(tc.in) < 100 && strings.Contains(strings.ToLower(err.Error()), hex.EncodeToString(tc.in)) {
			t.Errorf("%s: the error shows the data: %v", tc.name, err)
		}
	}
	if _, err := tlv.ParseOne(mustHex(t, "C0 00 C0 00")); !errors.Is(err, tlv.ErrTrailing) {
		t.Errorf("trailing: %v", err)
	}
	if _, err := tlv.ParseOne(mustHex(t, "C0 00 00")); !errors.Is(err, tlv.ErrTrailing) {
		t.Errorf("one trailing byte: %v", err)
	}
}

// TestLengthOnePastAtEveryLevel makes a tree of 1 to 8 levels and, one level at a time, raises that
// object's length by one without adding a byte: the object then runs one byte past the object that
// holds it (or past the data, at the top level).
func TestLengthOnePastAtEveryLevel(t *testing.T) {
	for wrappers := 0; wrappers <= tlv.MaxDepth-1; wrappers++ {
		valid := mustHex(t, "C0 01 AA")
		for range wrappers {
			valid = cat([]byte{0x30, byte(len(valid))}, valid)
		}
		if _, err := tlv.Parse(valid); err != nil {
			t.Fatalf("%d wrappers: %v", wrappers, err)
		}
		// Object j (0 is the outermost) has its tag at byte 2j and its length at byte 2j+1.
		for j := 0; j <= wrappers; j++ {
			bad := bytes.Clone(valid)
			bad[2*j+1]++
			_, err := tlv.Parse(bad)
			if !errors.Is(err, tlv.ErrLengthPastData) || !strings.HasSuffix(err.Error(), fmt.Sprintf("(at byte %d)", 2*j+1)) {
				t.Errorf("%d levels, level %d raised: %v", wrappers+1, j+1, err)
			}
		}
	}
}

func TestLimitsAtTheEdge(t *testing.T) {
	// Size: 65535 bytes in all is read, 65536 is not (the first row of wellFormed holds the 65535).
	if _, err := tlv.Parse(cat(mustHex(t, "C0 82 FF FB"), repeat(0, 65531))); err != nil {
		t.Errorf("65535 bytes: %v", err)
	}
	if _, err := tlv.ParseOne(cat(mustHex(t, "C0 82 FF FB"), repeat(0, 65531), []byte{0})); !errors.Is(err, tlv.ErrTooLarge) {
		t.Errorf("65536 bytes in ParseOne: %v", err)
	}
	// A length that states 65535 cannot be whole: its header makes the data longer than the limit.
	if _, err := tlv.Parse(cat(mustHex(t, "C0 82 FF FF"), repeat(0, 65535))); !errors.Is(err, tlv.ErrTooLarge) {
		t.Errorf("length 65535: %v", err)
	}
	if _, err := tlv.Parse(mustHex(t, "C0 82 FF FF")); !errors.Is(err, tlv.ErrLengthPastData) {
		t.Errorf("length 65535, no data: %v", err)
	}
	// Depth: eight levels, never nine (see wellFormed and TestRefusalsOneByOne). Nodes: a parent and
	// 1023 children are 1024 objects.
	if _, err := tlv.Parse(cat(mustHex(t, "73 82 07 FE"), bytes.Repeat(mustHex(t, "C0 00"), 1023))); err != nil {
		t.Errorf("1024 objects in two levels: %v", err)
	}
	// Nodes count at every level together: 512 constructed siblings of one child each are 1024.
	if _, err := tlv.Parse(bytes.Repeat(mustHex(t, "73 02 C0 00"), 512)); err != nil {
		t.Errorf("512 pairs: %v", err)
	}
	if _, err := tlv.Parse(cat(bytes.Repeat(mustHex(t, "73 02 C0 00"), 512), mustHex(t, "C0 00"))); !errors.Is(err, tlv.ErrTooManyNodes) {
		t.Errorf("512 pairs and one: %v", err)
	}
	// Encode keeps the same limits, so that it never writes what Parse refuses.
	for _, tc := range []struct {
		name string
		tag  tlv.Tag
		n    int
		want error
	}{
		{"65531 under one byte", 0xC0, 65531, nil},
		{"65532 under one byte", 0xC0, 65532, tlv.ErrTooLarge},
		{"65529 under three bytes", 0x9F8101, 65529, nil},
		{"65530 under three bytes", 0x9F8101, 65530, tlv.ErrTooLarge},
	} {
		enc, err := tlv.Encode([]tlv.Node{prim(tc.tag, make([]byte, tc.n)...)})
		if !errors.Is(err, tc.want) || (tc.want == nil) != (enc != nil) || len(enc) > tlv.MaxSize {
			t.Errorf("%s: %v %d", tc.name, err, len(enc))
		}
	}
	deep := prim(0xC0)
	for range tlv.MaxDepth - 1 {
		deep = cons(0x30, deep)
	}
	if _, err := tlv.Encode([]tlv.Node{deep}); err != nil {
		t.Errorf("encode, eight levels: %v", err)
	}
	if _, err := tlv.Encode([]tlv.Node{cons(0x30, deep)}); !errors.Is(err, tlv.ErrTooDeep) {
		t.Errorf("encode, nine levels: %v", err)
	}
	kids := make([]tlv.Node, 1023)
	for i := range kids {
		kids[i] = prim(0xC0)
	}
	if _, err := tlv.Encode([]tlv.Node{cons(0x73, kids...)}); err != nil {
		t.Errorf("encode, 1024 objects: %v", err)
	}
	if _, err := tlv.Encode([]tlv.Node{cons(0x73, append(kids, prim(0xC0))...)}); !errors.Is(err, tlv.ErrTooManyNodes) {
		t.Errorf("encode, 1025 objects: %v", err)
	}
}

// validTag is the rule of X.690 clause 8.1.2 for the bytes of one tag, written again here: the first byte
// is not 00 or FF (the card application has no padding), its low five bits are 11111 exactly when more
// bytes follow, every byte of a number but the last has its high bit set, the number is at least 31 and
// has no leading zero part, and the card application takes no more than three bytes.
func validTag(b []byte) bool {
	switch len(b) {
	case 1:
		return b[0] != 0x00 && b[0] != 0xFF && b[0]&0x1F != 0x1F
	case 2:
		return b[0] != 0xFF && b[0]&0x1F == 0x1F && b[1]&0x80 == 0 && b[1] >= 0x1F
	case 3:
		return b[0] != 0xFF && b[0]&0x1F == 0x1F && b[1]&0x80 != 0 && b[1]&0x7F != 0 && b[2]&0x80 == 0
	}
	return false
}

func TestEveryTag(t *testing.T) {
	check := func(tag tlv.Tag, b []byte) {
		t.Helper()
		var n tlv.Node
		if tag.Constructed() {
			n = cons(tag)
		} else {
			n = prim(tag)
		}
		enc, err := tlv.Encode([]tlv.Node{n})
		if want := validTag(b); (err == nil) != want {
			t.Fatalf("tag %X: Encode error %v, valid %v", b, err, want)
		}
		if err != nil {
			if enc != nil {
				t.Fatalf("tag %X: bytes with an error", b)
			}
			return
		}
		if !bytes.Equal(enc, cat(b, []byte{0})) {
			t.Fatalf("tag %X: encoded as %X", b, enc)
		}
		back, err := tlv.Parse(enc)
		if err != nil || len(back) != 1 || back[0].Tag != tag {
			t.Fatalf("tag %X: Parse of its own bytes: %v", b, err)
		}
		// Bit 6 of the first byte says constructed.
		if tag.Constructed() != (b[0]&0x20 != 0) {
			t.Fatalf("tag %X: Constructed() is %v", b, tag.Constructed())
		}
		if tag.String() != strings.ToUpper(hex.EncodeToString(b)) {
			t.Fatalf("tag %X: String() is %q", b, tag.String())
		}
	}
	for v := range 0x100 {
		check(tlv.Tag(v), []byte{byte(v)})
	}
	for v := 0x100; v < 0x10000; v++ {
		check(tlv.Tag(v), []byte{byte(v >> 8), byte(v)})
	}
	for _, first := range []byte{0x1F, 0x3F, 0x5F, 0x7F, 0x9F, 0xBF, 0xDF, 0xFF, 0xC0, 0x73} {
		for second := range 0x100 {
			for third := range 0x100 {
				check(tlv.Tag(uint32(first)<<16|uint32(second)<<8|uint32(third)), []byte{first, byte(second), byte(third)})
			}
		}
	}
	// Four bytes and more are refused by Encode, and the first byte decides nothing about it.
	for _, tag := range []tlv.Tag{0x01000000, 0x1F818101, 0x7F7F7F7F, 0xFFFFFFFF} {
		if enc, err := tlv.Encode([]tlv.Node{prim(tag)}); !errors.Is(err, tlv.ErrTagTooLong) || enc != nil {
			t.Errorf("tag %X: %v", uint32(tag), err)
		}
	}
	for _, tag := range []tlv.Tag{0, 0xFF} {
		if _, err := tlv.Encode([]tlv.Node{prim(tag)}); !errors.Is(err, tlv.ErrPadding) {
			t.Errorf("tag %X: %v", uint32(tag), err)
		}
		if tag.Constructed() || !strings.HasPrefix(tag.String(), "invalid(") {
			t.Errorf("tag %X: Constructed %v String %q", uint32(tag), tag.Constructed(), tag.String())
		}
	}
}

// outcome is what Parse made of data: the tree or the error text.
func outcome(data []byte) string {
	nodes, err := tlv.Parse(data)
	if err != nil {
		return "error: " + err.Error()
	}
	enc, encErr := tlv.Encode(nodes)
	return fmt.Sprintf("%v|%X|%v", nodes, enc, encErr)
}

// withTail returns data, as a slice that has room after it filled with fill: a reader that passes the
// end of its input would find the bytes.
func withTail(data []byte, fill byte) []byte {
	buf := append(bytes.Clone(data), repeat(fill, 512)...)
	return buf[:len(data):len(buf)]
}

// checkProperties holds the properties of every input: Parse does not panic, does not look past the end
// of its input (the result is the same with any bytes after it, and the same on a slice that has no room
// after it), names one of the named errors, and what it accepts, Encode writes back as the same bytes.
func checkProperties(t *testing.T, data []byte) {
	t.Helper()
	exact := outcome(bytes.Clone(data))
	if a, b := outcome(withTail(data, 0x00)), outcome(withTail(data, 0xFF)); a != exact || b != exact {
		t.Fatalf("%X: the result depends on the bytes after the input", data)
	}
	nodes, err := tlv.Parse(data)
	if err != nil {
		known := []error{tlv.ErrTruncated, tlv.ErrLengthPastData, tlv.ErrIndefiniteLength, tlv.ErrLengthForm,
			tlv.ErrLengthNotMinimal, tlv.ErrTag, tlv.ErrTagTooLong, tlv.ErrPadding, tlv.ErrTooLarge, tlv.ErrTooDeep, tlv.ErrTooManyNodes}
		named := false
		for _, k := range known {
			named = named || errors.Is(err, k)
		}
		if !named || nodes != nil {
			t.Fatalf("%X: %v", data, err)
		}
		return
	}
	enc, err := tlv.Encode(nodes)
	if err != nil || !bytes.Equal(enc, data) {
		t.Fatalf("%X: Encode(Parse(x)) = %X, %v", data, enc, err)
	}
}

func TestPropertiesOverShortInputs(t *testing.T) {
	// Every input of one and two bytes, and of three bytes after the first bytes that matter.
	checkProperties(t, nil)
	for a := range 0x100 {
		checkProperties(t, []byte{byte(a)})
		for b := range 0x100 {
			checkProperties(t, []byte{byte(a), byte(b)})
		}
	}
	for _, a := range []byte{0x00, 0xFF, 0x1F, 0x5F, 0x7F, 0xC0, 0x73} {
		for b := range 0x100 {
			for c := range 0x100 {
				checkProperties(t, []byte{a, byte(b), byte(c)})
			}
		}
	}
}

func TestPropertiesOverEveryPrefixAndEveryByte(t *testing.T) {
	for _, tc := range wellFormed(t) {
		if len(tc.in) > 600 {
			continue
		}
		for p := range len(tc.in) {
			checkProperties(t, tc.in[:p])
		}
		if len(tc.in) > 64 {
			continue
		}
		// Every value of every byte of the shorter inputs.
		for i := range tc.in {
			for v := range 0x100 {
				m := bytes.Clone(tc.in)
				m[i] = byte(v)
				checkProperties(t, m)
			}
		}
	}
	// The same for the longer ones, at the bytes that carry a length and for a few values.
	for _, tc := range wellFormed(t) {
		if len(tc.in) <= 64 {
			continue
		}
		for _, i := range []int{0, 1, 2, 3, 4} {
			if i >= len(tc.in) {
				continue
			}
			for _, v := range []byte{0x00, 0x01, 0x7F, 0x80, 0x81, 0x82, 0x83, 0xFF} {
				m := bytes.Clone(tc.in)
				m[i] = v
				checkProperties(t, m)
			}
		}
	}
}

func TestFindPaths(t *testing.T) {
	// 6E { 73 { C0, C1, C4 }, 73-free 4F, 7F66 { 02 } } and a second 6E-level 4F inside the first 73 only.
	nodes, err := tlv.Parse(mustHex(t, "6E 15 73 07 C0 01 AA C1 00 C4 00 4F 01 10 7F66 04 02 02 00 FF 4F 00"))
	if err != nil {
		t.Fatal(err)
	}
	// Three levels, and a tag of two bytes under a constructed one.
	got, err := tlv.Find(nodes, 0x6E, 0x73, 0xC0)
	if err != nil || !bytes.Equal(got.Value, []byte{0xAA}) {
		t.Fatalf("path of three: %v %v", err, got)
	}
	if got, err = tlv.Find(nodes, 0x6E, 0x7F66, 0x02); err != nil || !bytes.Equal(got.Value, []byte{0, 0xFF}) {
		t.Fatalf("path through a tag of two bytes: %v %v", err, got)
	}
	// The node is in the tree, not a copy.
	got.Value[0] = 0x55
	if again, _ := tlv.Find(nodes, 0x6E, 0x7F66, 0x02); again.Value[0] != 0x55 {
		t.Error("Find returned a copy")
	}
	// The same tag in two different levels is no ambiguity; twice in one level is.
	if _, err := tlv.Find(nodes, 0x6E, 0x4F); !errors.Is(err, tlv.ErrAmbiguous) {
		t.Errorf("4F twice in 6E: %v", err)
	}
	// An ambiguous step in the middle of a path, and in the first step.
	two, err := tlv.Parse(mustHex(t, "6E 05 73 03 C0 01 AA 6E 00"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tlv.Find(two, 0x6E, 0x73, 0xC0); !errors.Is(err, tlv.ErrAmbiguous) {
		t.Errorf("6E twice at the top: %v", err)
	}
	mid, err := tlv.Parse(mustHex(t, "6E 0A 73 03 C0 01 AA 73 03 C0 01 BB"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tlv.Find(mid, 0x6E, 0x73, 0xC0); !errors.Is(err, tlv.ErrAmbiguous) {
		t.Errorf("73 twice in the middle: %v", err)
	}
	// A missing step, a step past a primitive object, an empty list.
	for _, path := range [][]tlv.Tag{{0x6F}, {0x6E, 0x74}, {0x6E, 0x73, 0xC0, 0x01}, {0x6E, 0x73, 0xC0, 0xC0}} {
		if _, err := tlv.Find(nodes, path...); !errors.Is(err, tlv.ErrNotFound) {
			t.Errorf("%v: %v", path, err)
		}
	}
	if _, err := tlv.Find(nil, 0x6E); !errors.Is(err, tlv.ErrNotFound) {
		t.Errorf("no nodes: %v", err)
	}
	// The error names the tag.
	if _, err := tlv.Find(nodes, 0x6E, 0x4F); err == nil || !strings.Contains(err.Error(), "4F") {
		t.Errorf("the error does not name the tag: %v", err)
	}
}

func TestEncodeLengthForms(t *testing.T) {
	for _, tc := range []struct {
		n      int
		header string
	}{
		{0, "C0 00"}, {1, "C0 01"}, {127, "C0 7F"}, {128, "C0 81 80"}, {255, "C0 81 FF"}, {256, "C0 82 01 00"},
		{257, "C0 82 01 01"}, {65531, "C0 82 FF FB"},
	} {
		enc, err := tlv.Encode([]tlv.Node{prim(0xC0, make([]byte, tc.n)...)})
		want := cat(mustHex(t, tc.header), make([]byte, tc.n))
		if err != nil || !bytes.Equal(enc, want) {
			t.Errorf("%d: %v %X...", tc.n, err, enc[:min(len(enc), 6)])
		}
	}
	// A constructed object takes its length from its content.
	var kids []tlv.Node
	for range 64 {
		kids = append(kids, prim(0xC0))
	}
	enc, err := tlv.Encode([]tlv.Node{cons(0x73, kids...)})
	if err != nil || !bytes.HasPrefix(enc, mustHex(t, "73 81 80 C0 00")) || len(enc) != 3+128 {
		t.Errorf("constructed of 128 bytes: %v %X", err, enc[:min(len(enc), 8)])
	}
	if enc, err := tlv.Encode(nil); err != nil || len(enc) != 0 {
		t.Errorf("no nodes: %v %X", err, enc)
	}
}

func TestEncodeLeavesItsInputAlone(t *testing.T) {
	v := []byte{1, 2, 3}
	nodes := []tlv.Node{cons(0x73, prim(0xC0, v...))}
	enc, err := tlv.Encode(nodes)
	if err != nil {
		t.Fatal(err)
	}
	clear(enc)
	if !bytes.Equal(v, []byte{1, 2, 3}) || !bytes.Equal(nodes[0].Children[0].Value, []byte{1, 2, 3}) {
		t.Fatal("the output of Encode shares the value of a node")
	}
}
