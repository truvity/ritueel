package pki_test

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"testing"
	"testing/iotest"

	"ritueel.id/ritueel/internal/pki"
)

func repeat(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func TestNewSerial(t *testing.T) {
	// 20 octets in, 159 bits out at most: the top bit is cleared.
	cases := []struct {
		name   string
		in     []byte
		want   string // the serial in hex, "" for a refusal
		bitLen int
	}{
		{"all ones", repeat(0xff, 20), "7f" + hexRepeat("ff", 19), 159},
		{"all ones but the top bit is cleared", append([]byte{0x80}, repeat(0xff, 19)...), hexRepeat("ff", 19), 152},
		{"the top bit alone is cleared away: zero", append([]byte{0x80}, repeat(0, 19)...), "", 0},
		{"all zeros", repeat(0, 20), "", 0},
		{"one", append(repeat(0, 19), 1), "", 0},
		{"63 bits", append(repeat(0, 12), 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff), "", 0},
		{"63 bits, the top one only", append(append(repeat(0, 12), 0x40), repeat(0, 7)...), "", 0},
		{"64 bits, the top one only", append(append(repeat(0, 12), 0x80), repeat(0, 7)...), "8000000000000000", 64},
		{"64 bits, all ones", append(repeat(0, 12), repeat(0xff, 8)...), "ffffffffffffffff", 64},
		{"65 bits", append(append(repeat(0, 11), 0x01), repeat(0, 8)...), "010000000000000000", 65},
		{"158 bits", append([]byte{0x20}, repeat(0, 19)...), "20" + hexRepeat("00", 19), 158},
		{"159 bits, the top one only", append([]byte{0x40}, repeat(0, 19)...), "40" + hexRepeat("00", 19), 159},
		{"a leading zero octet is allowed when the rest is long enough", append([]byte{0x00}, repeat(0xab, 19)...), hexRepeat("ab", 19), 152},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := bytes.NewReader(append(append([]byte(nil), c.in...), repeat(0x55, 7)...))
			n, err := pki.NewSerial(r)
			if c.want == "" {
				refused(t, err, pki.ErrParams)
				if n != nil {
					t.Errorf("a serial %v came with the error", n)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if n.Cmp(hexBig(t, c.want)) != 0 {
				t.Errorf("serial = %x, want %s", n, c.want)
			}
			if n.BitLen() != c.bitLen {
				t.Errorf("bit length = %d, want %d", n.BitLen(), c.bitLen)
			}
			// It read exactly 20 octets.
			if r.Len() != 7 {
				t.Errorf("%d octets are left, want 7: it read %d", r.Len(), 27-r.Len())
			}
			if err := pki.CheckSerial(n); err != nil {
				t.Errorf("CheckSerial refuses the serial that NewSerial made: %v", err)
			}
		})
	}
}

func hexRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestNewSerialRandomSource(t *testing.T) {
	// A nil reader is crypto/rand.
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		n, err := pki.NewSerial(nil)
		if err != nil {
			t.Fatal(err)
		}
		if n.Sign() <= 0 || n.BitLen() < 64 || n.BitLen() > 159 || len(n.Bytes()) > 20 {
			t.Fatalf("serial %x is outside the profile", n)
		}
		if seen[n.String()] {
			t.Fatalf("serial %x came twice", n)
		}
		seen[n.String()] = true
	}
	if len(seen) != 1000 {
		t.Fatalf("%d distinct serials, want 1000", len(seen))
	}
}

func TestNewSerialReaders(t *testing.T) {
	boom := errors.New("the source is down")
	ok20 := repeat(0x5a, 20)
	cases := []struct {
		name   string
		r      io.Reader
		accept bool
	}{
		{"one octet at a time", iotest.OneByteReader(bytes.NewReader(ok20)), true},
		{"data with the error at the end", iotest.DataErrReader(bytes.NewReader(ok20)), true},
		{"a half reader", iotest.HalfReader(bytes.NewReader(ok20)), true},
		{"a reader that fails at once", failReader{boom}, false},
		{"an empty reader", bytes.NewReader(nil), false},
		{"19 octets", bytes.NewReader(ok20[:19]), false},
		{"1 octet", bytes.NewReader(ok20[:1]), false},
		{"a reader that fails after 10 octets", io.MultiReader(bytes.NewReader(ok20[:10]), failReader{boom}), false},
		{"a timeout", iotest.TimeoutReader(iotest.OneByteReader(bytes.NewReader(ok20))), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, err := pki.NewSerial(c.r)
			if c.accept {
				if err != nil || n == nil {
					t.Fatalf("NewSerial = %v, %v", n, err)
				}
				return
			}
			refused(t, err, pki.ErrParams)
			if n != nil {
				t.Errorf("a serial %v came with the error", n)
			}
		})
	}
	t.Run("the error of the reader is reachable", func(t *testing.T) {
		_, err := pki.NewSerial(failReader{boom})
		if !errors.Is(err, boom) {
			t.Errorf("errors.Is(err, boom) is false: %v", err)
		}
		refused(t, err, pki.ErrParams)
	})
}

func TestCheckSerial(t *testing.T) {
	pow := func(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }
	minus1 := func(n *big.Int) *big.Int { return new(big.Int).Sub(n, big.NewInt(1)) }
	cases := []struct {
		name   string
		n      *big.Int
		accept bool
	}{
		{"nil", nil, false},
		{"zero", big.NewInt(0), false},
		{"minus one", big.NewInt(-1), false},
		{"a negative number of 100 bits", new(big.Int).Neg(pow(100)), false},
		{"one", big.NewInt(1), false},
		{"2^62", pow(62), false},
		{"2^63 - 1, 63 bits", minus1(pow(63)), false},
		{"2^63, 64 bits", pow(63), true},
		{"2^64 - 1, 64 bits", minus1(pow(64)), true},
		{"2^64, 65 bits", pow(64), true},
		{"2^100", pow(100), true},
		{"2^158, 159 bits", pow(158), true},
		{"2^159 - 1, 159 bits", minus1(pow(159)), true},
		{"2^159, 160 bits", pow(159), false},
		{"2^160 - 1", minus1(pow(160)), false},
		{"2^200", pow(200), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := pki.CheckSerial(c.n)
			if c.accept {
				if err != nil {
					t.Errorf("CheckSerial refuses it: %v", err)
				}
				return
			}
			refused(t, err, pki.ErrParams)
		})
	}
}
