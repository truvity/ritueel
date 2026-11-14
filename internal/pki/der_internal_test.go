package pki

import (
	"bytes"
	"errors"
	"testing"
)

// The DER writer at the edges of its length forms and of its limit: every length that changes the form, written and
// read back by the standard library's own parser rules (the first octets are checked by hand), and the content that is
// one octet too long, which is an error and never a wrong length.
func TestTLVLengthForms(t *testing.T) {
	cases := []struct {
		n      int
		header []byte
	}{
		{0, []byte{0x04, 0x00}},
		{1, []byte{0x04, 0x01}},
		{126, []byte{0x04, 0x7e}},
		{127, []byte{0x04, 0x7f}},
		{128, []byte{0x04, 0x81, 0x80}},
		{129, []byte{0x04, 0x81, 0x81}},
		{255, []byte{0x04, 0x81, 0xff}},
		{256, []byte{0x04, 0x82, 0x01, 0x00}},
		{257, []byte{0x04, 0x82, 0x01, 0x01}},
		{65535, []byte{0x04, 0x82, 0xff, 0xff}},
		{65536, []byte{0x04, 0x83, 0x01, 0x00, 0x00}},
		{65537, []byte{0x04, 0x83, 0x01, 0x00, 0x01}},
		{1<<24 - 2, []byte{0x04, 0x83, 0xff, 0xff, 0xfe}},
		{1<<24 - 1, []byte{0x04, 0x83, 0xff, 0xff, 0xff}},
	}
	for _, c := range cases {
		out, err := tlv(0x04, make([]byte, c.n))
		if err != nil {
			t.Errorf("content of %d octets: %v", c.n, err)
			continue
		}
		if !bytes.HasPrefix(out, c.header) || len(out) != len(c.header)+c.n {
			t.Errorf("content of %d octets: header %x, total %d, want header %x and total %d", c.n, out[:min(len(out), 6)], len(out), c.header, len(c.header)+c.n)
		}
	}
	if maxContent != 1<<24-1 {
		t.Errorf("maxContent = %d", maxContent)
	}
}

func TestTLVRefusesContentThatIsTooLong(t *testing.T) {
	for _, n := range []int{1 << 24, 1<<24 + 1, 1<<24 + 1000} {
		out, err := tlv(0x04, make([]byte, n))
		if !errors.Is(err, errTooLong) || out != nil {
			t.Errorf("content of %d octets: %v, %d octets", n, err, len(out))
		}
	}
	// The parts add up: two that fit alone do not fit together, and the limit is of the sum.
	half := make([]byte, 1<<23)
	if out, err := tlv(0x30, half, half[:len(half)-1]); err != nil || len(out) != 1<<24-1+5 {
		t.Errorf("two parts of 2^24-1 octets together: %v, %d octets", err, len(out))
	}
	if out, err := tlv(0x30, half, half); !errors.Is(err, errTooLong) || out != nil {
		t.Errorf("two parts of 2^24 octets together: %v, %d octets", err, len(out))
	}
	// Many small parts that add up past the limit.
	var parts [][]byte
	for i := 0; i < 17; i++ {
		parts = append(parts, make([]byte, 1<<20))
	}
	if _, err := tlv(0x30, parts...); !errors.Is(err, errTooLong) {
		t.Errorf("seventeen parts of 2^20 octets: %v", err)
	}
	// The wrappers pass the limit on.
	if _, err := seq(make([]byte, 1<<24)); !errors.Is(err, errTooLong) {
		t.Errorf("seq: %v", err)
	}
	if _, err := extension(oidKeyUsage, true, make([]byte, 1<<24)); !errors.Is(err, errTooLong) {
		t.Errorf("extension with a value of 2^24 octets: %v", err)
	}
	// The octet string of the extension adds its own header: a value that fits the limit alone may not fit in the sequence
	// that holds it, and it is an error and not a wrong length.
	if ext, err := extension(oidKeyUsage, false, make([]byte, 1<<24-1-20)); err != nil && !errors.Is(err, errTooLong) {
		t.Errorf("an extension near the limit: %v", err)
	} else if err == nil && len(ext) < 1<<24-1-20 {
		t.Errorf("an extension near the limit is %d octets", len(ext))
	}
}

// short is for content that is short by construction: it panics when it is not, so that a fault of the package is
// not taken for the fault of an input.
func TestShortPanicsOnContentThatIsNotShort(t *testing.T) {
	for name, f := range map[string]func(){
		"short":    func() { short(0x04, make([]byte, 1<<24)) },
		"shortSeq": func() { shortSeq(make([]byte, 1<<24)) },
	} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("%s did not panic on 2^24 octets", name)
				}
			}()
			f()
		}()
	}
	for name, f := range map[string]func() []byte{
		"short":    func() []byte { return short(0x04, make([]byte, 1<<24-1)) },
		"shortSeq": func() []byte { return shortSeq(make([]byte, 1<<24-1)) },
	} {
		if out := f(); len(out) != 1<<24-1+5 {
			t.Errorf("%s of 2^24-1 octets: %d octets", name, len(out))
		}
	}
}

// The named-bit form of a key usage: the bits are numbered from the most significant, the trailing zero bits are left
// out, and the first octet says how many bits of the last one are unused. No bit is no value.
func TestKeyUsageValueIsTheNamedBitForm(t *testing.T) {
	cases := []struct {
		bits []int
		want []byte
	}{
		{nil, nil},
		{[]int{usageDigitalSignature}, []byte{0x03, 0x02, 0x07, 0x80}},
		{[]int{usageKeyCertSign}, []byte{0x03, 0x02, 0x02, 0x04}},
		{[]int{usageCRLSign}, []byte{0x03, 0x02, 0x01, 0x02}},
		{[]int{usageKeyCertSign, usageCRLSign}, []byte{0x03, 0x02, 0x01, 0x06}},
		{[]int{usageCRLSign, usageKeyCertSign}, []byte{0x03, 0x02, 0x01, 0x06}},
		{[]int{usageDigitalSignature, usageKeyCertSign, usageCRLSign}, []byte{0x03, 0x02, 0x01, 0x86}},
		{[]int{usageKeyCertSign, usageKeyCertSign}, []byte{0x03, 0x02, 0x02, 0x04}},
	}
	for _, c := range cases {
		if got := keyUsageValue(c.bits...); !bytes.Equal(got, c.want) {
			t.Errorf("keyUsageValue(%v) = %x, want %x", c.bits, got, c.want)
		}
	}
}

// canonicalText is the text as OpenSSL canonicalises it: white space (the space and TAB to CR) at the ends dropped, a run
// of white space inside as one space, ASCII letters in lower case, every byte of 0x80 and above left as it is.
func TestCanonicalText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{" ", ""},
		{"   ", ""},
		{"\t", ""},
		{" \t\n\v\f\r ", ""},
		{"a", "a"},
		{"A", "a"},
		{"ABC xyz", "abc xyz"},
		{"  a", "a"},
		{"a  ", "a"},
		{"  a  ", "a"},
		{"a b", "a b"},
		{"a  b", "a b"},
		{"a   b", "a b"},
		{"a\tb", "a b"},
		{"a \t\r\n b", "a b"},
		{"a b  c   d", "a b c d"},
		{"a b c", "a b c"},
		{"a\x0bb", "a b"},
		{"a\x0cb", "a b"},
		{"a\x08b", "a\x08b"},
		{"a\x0eb", "a\x0eb"},
		{"a\x1fb", "a\x1fb"},
		{"@[`{", "@[`{"},
		{"AZaz", "azaz"},
		{"É", "É"},
		{"a é", "a é"},
		{"a b", "a b"},
		{" a ", " a "},
		{"\u0080", "\u0080"},
		{"a\u0080 b", "a\u0080 b"},
		{"　a　", "　a　"},
	}
	for _, c := range cases {
		if got := canonicalText([]byte(c.in)); got != c.want {
			t.Errorf("canonicalText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
