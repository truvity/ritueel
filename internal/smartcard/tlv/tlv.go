// Package tlv reads and writes the BER-TLV data objects that a smart card speaks, as the OpenPGP smart
// card application (specification 3.4.1, section 4.4) and ISO/IEC 7816-4 (clause 5.2.2, BER-TLV data
// objects) use them. It belongs to the code that speaks to a card (internal/smartcard); it is not the
// reader of the card files of a bundle, which package internal/cards is.
//
// A data object is a tag, a length and a value. The tag has one, two or three bytes (ITU-T X.690,
// clause 8.1.2): a first byte whose low five bits are not all ones is a whole tag; if they are all ones
// the tag goes on, and a byte with its high bit set says that one more byte follows. The tag is kept as
// a [Tag], its bytes read as a big-endian number, so the tag 7F66 is Tag(0x7F66). Bit 6 of the first
// byte says that the value is itself a sequence of data objects (a constructed object); [Parse] parses
// it into [Node.Children] and keeps no raw value for it. A caller that holds an opaque value under a
// constructed tag, such as a certificate, does not give that value to [Parse].
//
// The length is definite, in the short form (one byte, up to 127) or in the forms 0x81 (one length
// byte) and 0x82 (two length bytes), as the card specification uses them. The indefinite form 0x80 and
// every form above 0x82 are refused, and so is a length that is not in its shortest form: the reader is
// strict, so that one byte string has one tree and Encode(Parse(x)) is x exactly. Nothing in the
// card specification or in the vendor's documents shows a card that sends a longer form than it needs;
// if a real card does, the named error [ErrLengthNotMinimal] says so, and the rule is relaxed with that
// proof in hand.
//
// Padding is refused. ISO/IEC 7816-4 leaves 00 and FF out of the tags and lets some files use them as
// filler between objects; the data objects of the card application do not, and a filler byte would
// make two byte strings one tree. A first tag byte of 00 or FF is [ErrPadding], in any place.
//
// Every byte is accounted for: the data is exactly a sequence of whole objects, and a constructed
// object is exactly a sequence of whole objects. A fault names the byte offset, counted from the start
// of the data given to [Parse], and never shows a byte of the data. Three limits keep a hostile answer
// small: [MaxSize] bytes in all, [MaxDepth] levels and [MaxNodes] objects. Parse copies every value,
// so a caller may wipe its input and the result separately.
package tlv

import (
	"errors"
	"fmt"
)

// The limits of [Parse] and [Encode]. They are far above any object of the card application (a
// certificate is at most 2048 bytes, the application related data holds about thirty objects at four
// levels) and low enough that a hostile answer costs little. MaxSize is the largest length that the
// forms 0x81 and 0x82 can state.
const (
	// MaxSize is the most bytes of data that Parse reads and Encode writes.
	MaxSize = 65535
	// MaxDepth is the most levels of nesting; the objects of the top level are level 1.
	MaxDepth = 8
	// MaxNodes is the most data objects in a tree, at every level together.
	MaxNodes = 1024
)

var (
	// ErrTruncated marks data that ends inside a tag or inside a length.
	ErrTruncated = errors.New("tlv: data ends inside a tag or a length")
	// ErrLengthPastData marks a length that runs past the end of the data, or past the end of the
	// constructed object that holds it.
	ErrLengthPastData = errors.New("tlv: the length runs past the data")
	// ErrIndefiniteLength marks the length byte 0x80, the indefinite form, which the card
	// application does not use.
	ErrIndefiniteLength = errors.New("tlv: indefinite length")
	// ErrLengthForm marks a first length byte above 0x82: a length of three bytes or more.
	ErrLengthForm = errors.New("tlv: length form above 0x82")
	// ErrLengthNotMinimal marks a length that is written in a longer form than it needs: 0x81 for a
	// value below 128, or 0x82 for a value below 256.
	ErrLengthNotMinimal = errors.New("tlv: length not in its shortest form")
	// ErrTag marks a tag that is not well formed: a long form whose number is below 31, or whose
	// first number byte is zero.
	ErrTag = errors.New("tlv: tag not well formed")
	// ErrTagTooLong marks a tag of four bytes or more.
	ErrTagTooLong = errors.New("tlv: tag longer than three bytes")
	// ErrPadding marks a first tag byte of 00 or FF.
	ErrPadding = errors.New("tlv: padding byte where a tag was expected")
	// ErrTrailing marks bytes after the one object that [ParseOne] was asked to read.
	ErrTrailing = errors.New("tlv: bytes after the object")
	// ErrTooLarge marks data, or a tree, of more than [MaxSize] bytes.
	ErrTooLarge = errors.New("tlv: more than the size limit")
	// ErrTooDeep marks nesting of more than [MaxDepth] levels.
	ErrTooDeep = errors.New("tlv: nested deeper than the limit")
	// ErrTooManyNodes marks a tree of more than [MaxNodes] objects.
	ErrTooManyNodes = errors.New("tlv: more objects than the limit")
	// ErrNodeShape marks a node that Encode refuses: a primitive tag with children, or a constructed
	// tag with a value.
	ErrNodeShape = errors.New("tlv: node is not of the shape its tag says")
	// ErrNotFound marks a path of tags that leads to no object.
	ErrNotFound = errors.New("tlv: no object with the tag")
	// ErrAmbiguous marks a path of tags where a step finds the tag twice in one level.
	ErrAmbiguous = errors.New("tlv: the tag appears more than once in its level")
)

// Tag is the tag of a data object: its one, two or three bytes read as a big-endian number.
type Tag uint32

// Constructed reports whether the tag says that the value is a sequence of data objects (bit 6 of the
// first byte).
func (t Tag) Constructed() bool {
	b, _ := t.bytes()
	return len(b) > 0 && b[0]&0x20 != 0
}

// String is the tag as upper-case hexadecimal, two digits for each byte.
func (t Tag) String() string {
	b, ok := t.bytes()
	if !ok {
		return fmt.Sprintf("invalid(%X)", uint32(t))
	}
	return fmt.Sprintf("%X", b)
}

// bytes returns the bytes of a tag that is well formed.
func (t Tag) bytes() ([]byte, bool) {
	switch {
	case t == 0 || t > 0xFFFFFF:
		return nil, false
	case t <= 0xFF:
		b := []byte{byte(t)}
		if b[0] == 0xFF || b[0]&0x1F == 0x1F {
			return nil, false
		}
		return b, true
	case t <= 0xFFFF:
		b := []byte{byte(t >> 8), byte(t)}
		// Two bytes: the first announces a long form, the second ends it and is at least 31.
		if b[0] == 0xFF || b[0]&0x1F != 0x1F || b[1]&0x80 != 0 || b[1] < 0x1F {
			return nil, false
		}
		return b, true
	default:
		b := []byte{byte(t >> 16), byte(t >> 8), byte(t)}
		// Three bytes: the middle byte continues, with a number part that is not zero, and the last ends it.
		if b[0] == 0xFF || b[0]&0x1F != 0x1F || b[1]&0x80 == 0 || b[1]&0x7F == 0 || b[2]&0x80 != 0 {
			return nil, false
		}
		return b, true
	}
}

// Node is one data object. A node whose tag is constructed holds its objects in Children and has no
// Value; any other node holds its Value and has no Children.
type Node struct {
	Tag      Tag
	Value    []byte
	Children []Node
}

// budget counts what a parse or an encode has used against the limits.
type budget struct{ nodes int }

func (b *budget) node() error {
	b.nodes++
	if b.nodes > MaxNodes {
		return ErrTooManyNodes
	}
	return nil
}

// Parse reads data as a sequence of whole data objects and returns them, with the objects of every
// constructed one parsed into its Children. It returns no nodes with an error. Empty data is no
// objects and no error. The error wraps one of the named errors above and names the byte offset.
func Parse(data []byte) ([]Node, error) {
	if len(data) > MaxSize {
		return nil, ErrTooLarge
	}
	var b budget
	nodes, err := parseSeq(data, 0, 1, &b)
	if err != nil {
		return nil, err
	}
	return nodes, nil
}

// ParseOne reads data as exactly one data object. Bytes after it are an [ErrTrailing].
func ParseOne(data []byte) (Node, error) {
	if len(data) > MaxSize {
		return Node{}, ErrTooLarge
	}
	var b budget
	n, used, err := parseNode(data, 0, 1, &b)
	if err != nil {
		return Node{}, err
	}
	if used != len(data) {
		return Node{}, fault(ErrTrailing, used)
	}
	return n, nil
}

// fault wraps a named error with the offset it was found at.
func fault(err error, offset int) error { return fmt.Errorf("%w (at byte %d)", err, offset) }

// parseSeq reads the whole of data as objects. base is the offset of data in the input of the call.
func parseSeq(data []byte, base, depth int, b *budget) ([]Node, error) {
	var nodes []Node
	for off := 0; off < len(data); {
		n, used, err := parseNode(data[off:], base+off, depth, b)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
		off += used
	}
	return nodes, nil
}

// parseNode reads one object at the start of data and returns it with the bytes it used.
func parseNode(data []byte, base, depth int, b *budget) (Node, int, error) {
	if depth > MaxDepth {
		return Node{}, 0, fault(ErrTooDeep, base)
	}
	if err := b.node(); err != nil {
		return Node{}, 0, fault(err, base)
	}
	tag, tagLen, err := readTag(data)
	if err != nil {
		return Node{}, 0, fault(err, base)
	}
	length, lenLen, err := readLength(data[tagLen:])
	if err != nil {
		return Node{}, 0, fault(err, base+tagLen)
	}
	start := tagLen + lenLen
	if length > len(data)-start {
		return Node{}, 0, fault(ErrLengthPastData, base+tagLen)
	}
	value := data[start : start+length]
	n := Node{Tag: tag}
	if tag.Constructed() {
		n.Children, err = parseSeq(value, base+start, depth+1, b)
		if err != nil {
			return Node{}, 0, err
		}
	} else {
		n.Value = append([]byte{}, value...)
	}
	return n, start + length, nil
}

// readTag reads the tag at the start of data and returns it with its length in bytes.
func readTag(data []byte) (Tag, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrTruncated
	}
	first := data[0]
	switch {
	case first == 0x00 || first == 0xFF:
		return 0, 0, ErrPadding
	case first&0x1F != 0x1F:
		return Tag(first), 1, nil
	}
	if len(data) < 2 {
		return 0, 0, ErrTruncated
	}
	second := data[1]
	if second&0x80 == 0 {
		// Two bytes. A number below 31 would have fitted in the first byte.
		if second < 0x1F {
			return 0, 0, ErrTag
		}
		return Tag(uint32(first)<<8 | uint32(second)), 2, nil
	}
	if second&0x7F == 0 {
		return 0, 0, ErrTag
	}
	if len(data) < 3 {
		return 0, 0, ErrTruncated
	}
	third := data[2]
	if third&0x80 != 0 {
		return 0, 0, ErrTagTooLong
	}
	return Tag(uint32(first)<<16 | uint32(second)<<8 | uint32(third)), 3, nil
}

// readLength reads the length at the start of data and returns it with its length in bytes.
func readLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrTruncated
	}
	switch first := data[0]; {
	case first < 0x80:
		return int(first), 1, nil
	case first == 0x80:
		return 0, 0, ErrIndefiniteLength
	case first == 0x81:
		if len(data) < 2 {
			return 0, 0, ErrTruncated
		}
		if data[1] < 0x80 {
			return 0, 0, ErrLengthNotMinimal
		}
		return int(data[1]), 2, nil
	case first == 0x82:
		if len(data) < 3 {
			return 0, 0, ErrTruncated
		}
		n := int(data[1])<<8 | int(data[2])
		if n < 0x100 {
			return 0, 0, ErrLengthNotMinimal
		}
		return n, 3, nil
	default:
		return 0, 0, ErrLengthForm
	}
}

// Encode writes the nodes as data objects, each length in its shortest form. It refuses a tag that is
// not well formed ([ErrTag], [ErrPadding], [ErrTagTooLong] for a value above three bytes), a node of
// the wrong shape ([ErrNodeShape]) and a tree beyond the limits, so that Parse reads back what Encode
// wrote. Encode returns no bytes with an error.
func Encode(nodes []Node) ([]byte, error) {
	var b budget
	out, err := encodeSeq(nil, nodes, 1, &b)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func encodeSeq(dst []byte, nodes []Node, depth int, b *budget) ([]byte, error) {
	for i := range nodes {
		var err error
		if dst, err = encodeNode(dst, &nodes[i], depth, b); err != nil {
			return nil, err
		}
	}
	return dst, nil
}

func encodeNode(dst []byte, n *Node, depth int, b *budget) ([]byte, error) {
	if depth > MaxDepth {
		return nil, ErrTooDeep
	}
	if err := b.node(); err != nil {
		return nil, err
	}
	tagBytes, ok := n.Tag.bytes()
	if !ok {
		return nil, tagFault(n.Tag)
	}
	var value []byte
	if n.Tag.Constructed() {
		if len(n.Value) != 0 {
			return nil, ErrNodeShape
		}
		var err error
		if value, err = encodeSeq(nil, n.Children, depth+1, b); err != nil {
			return nil, err
		}
	} else {
		if len(n.Children) != 0 {
			return nil, ErrNodeShape
		}
		value = n.Value
	}
	if len(value) > MaxSize {
		return nil, ErrTooLarge
	}
	dst = append(dst, tagBytes...)
	switch {
	case len(value) < 0x80:
		dst = append(dst, byte(len(value)))
	case len(value) < 0x100:
		dst = append(dst, 0x81, byte(len(value)))
	default:
		dst = append(dst, 0x82, byte(len(value)>>8), byte(len(value)))
	}
	dst = append(dst, value...)
	if len(dst) > MaxSize {
		return nil, ErrTooLarge
	}
	return dst, nil
}

// tagFault names why a tag that is not well formed is refused.
func tagFault(t Tag) error {
	if t > 0xFFFFFF {
		return ErrTagTooLong
	}
	first := t
	for first > 0xFF {
		first >>= 8
	}
	if first == 0x00 || first == 0xFF {
		return ErrPadding
	}
	return ErrTag
}

// Find follows a path of tags: the first tag is looked for among nodes, the second among the children
// of the node found, and so on. With one tag it finds a node at the top level. A step that finds no
// node is [ErrNotFound]; a step that finds two is [ErrAmbiguous], because a card that repeats a tag in
// one level has said something that no caller should pick one reading of. The node returned is in the
// tree it was found in, not a copy.
func Find(nodes []Node, path ...Tag) (*Node, error) {
	if len(path) == 0 {
		return nil, ErrNotFound
	}
	var found *Node
	for _, tag := range path {
		found = nil
		for i := range nodes {
			if nodes[i].Tag != tag {
				continue
			}
			if found != nil {
				return nil, fmt.Errorf("%w: %s", ErrAmbiguous, tag)
			}
			found = &nodes[i]
		}
		if found == nil {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, tag)
		}
		nodes = found.Children
	}
	return found, nil
}
