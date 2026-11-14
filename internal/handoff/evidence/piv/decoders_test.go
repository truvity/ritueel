package piv_test

import (
	"bytes"
	"strconv"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/piv"
)

// The four readers of the extension values, on their own, for every length and for the values at the edges
// of what the page says. They never panic.

func TestDecodeFirmware(t *testing.T) {
	for n := 0; n <= 6; n++ {
		raw := bytes.Repeat([]byte{7}, n)
		got, err := piv.DecodeFirmware(raw)
		if n == 3 {
			if err != nil || got != "7.7.7" {
				t.Errorf("three octets: %q, %v", got, err)
			}
			continue
		}
		if err == nil || got != "" {
			t.Errorf("%d octets: %q, %v", n, got, err)
		}
	}
	if got, _ := piv.DecodeFirmware(nil); got != "" {
		t.Errorf("nil: %q", got)
	}
	// The three numbers are written in decimal, each from its own octet.
	for _, c := range []struct {
		raw  []byte
		want string
	}{
		{[]byte{5, 8, 0}, "5.8.0"}, {[]byte{1, 2, 3}, "1.2.3"}, {[]byte{0, 0, 0}, "0.0.0"},
		{[]byte{255, 0, 1}, "255.0.1"}, {[]byte{0, 255, 0}, "0.255.0"}, {[]byte{0, 0, 255}, "0.0.255"},
		{[]byte{10, 20, 30}, "10.20.30"}, {[]byte{9, 10, 11}, "9.10.11"},
	} {
		if got, err := piv.DecodeFirmware(c.raw); err != nil || got != c.want {
			t.Errorf("%v: %q, %v, want %q", c.raw, got, err, c.want)
		}
	}
}

func TestDecodeSerial(t *testing.T) {
	// Every value of the one-octet content is read by the rule of DER: 1 to 127 are numbers, 0 is not
	// positive, 128 to 255 are negative.
	for b := 0; b < 256; b++ {
		got, err := piv.DecodeSerial([]byte{0x02, 0x01, byte(b)})
		if b >= 1 && b <= 127 {
			if err != nil || got != strconv.Itoa(b) {
				t.Errorf("content %#x: %q, %v", b, got, err)
			}
			continue
		}
		if err == nil || got != "" {
			t.Errorf("content %#x: %q, %v", b, got, err)
		}
	}
	// A leading zero is allowed only when the next octet has its high bit set.
	for b := 0; b < 256; b++ {
		got, err := piv.DecodeSerial([]byte{0x02, 0x02, 0x00, byte(b)})
		if b >= 0x80 {
			if err != nil || got != strconv.Itoa(b) {
				t.Errorf("0x00 %#x: %q, %v", b, got, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("0x00 %#x is read: %q", b, got)
		}
	}
	// Lengths of 1 to 9 octets of content, the first with the high bit clear and the rest 0xff.
	for n := 1; n <= 9; n++ {
		content := bytes.Repeat([]byte{0xff}, n)
		content[0] = 0x7f
		got, err := piv.DecodeSerial(append([]byte{0x02, byte(n)}, content...))
		if n <= 8 {
			if err != nil || got == "" {
				t.Errorf("%d octets: %q, %v", n, got, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%d octets are read: %q", n, got)
		}
	}
	// The biggest value that fits in 8 octets with the high bit clear, and its text.
	if got, err := piv.DecodeSerial([]byte{0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); err != nil || got != "9223372036854775807" {
		t.Errorf("max int64: %q, %v", got, err)
	}
	// The value is read big-endian.
	if got, err := piv.DecodeSerial([]byte{0x02, 0x03, 0x01, 0x02, 0x03}); err != nil || got != "66051" {
		t.Errorf("0x010203: %q, %v", got, err)
	}
	// The length byte and the length of the value must agree; the tag is INTEGER.
	for tag := 0; tag < 256; tag++ {
		got, err := piv.DecodeSerial([]byte{byte(tag), 0x01, 0x05})
		if tag == 0x02 {
			if err != nil || got != "5" {
				t.Errorf("tag 2: %q, %v", got, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("tag %#x is read", tag)
		}
	}
	for l := 0; l < 256; l++ {
		_, err := piv.DecodeSerial([]byte{0x02, byte(l), 0x05})
		if (err == nil) != (l == 1) {
			t.Errorf("length byte %d: %v", l, err)
		}
	}
	for n := 0; n < 4; n++ {
		if got, err := piv.DecodeSerial(bytes.Repeat([]byte{0x02}, n)); err == nil {
			t.Errorf("%d bytes of 0x02: %q", n, got)
		}
	}
	if got, err := piv.DecodeSerial(nil); err == nil || got != "" {
		t.Errorf("nil: %q, %v", got, err)
	}
}

func TestDecodePolicy(t *testing.T) {
	pins := map[byte]handoff.PINPolicy{1: handoff.PINNever, 2: handoff.PINOnce, 3: handoff.PINAlways}
	touches := map[byte]string{1: "never", 2: "always", 3: "cached"}
	for p := 0; p < 256; p++ {
		for h := 0; h < 256; h++ {
			pin, touch, err := piv.DecodePolicy([]byte{byte(p), byte(h)})
			wp, okP := pins[byte(p)]
			wh, okH := touches[byte(h)]
			if okP && okH {
				if err != nil || pin != wp || touch != wh {
					t.Fatalf("%d,%d: %q %q %v", p, h, pin, touch, err)
				}
				continue
			}
			if err == nil || pin != "" || touch != "" {
				t.Fatalf("%d,%d: %q %q %v", p, h, pin, touch, err)
			}
		}
	}
	for n := 0; n <= 5; n++ {
		if n == 2 {
			continue
		}
		if pin, touch, err := piv.DecodePolicy(bytes.Repeat([]byte{1}, n)); err == nil || pin != "" || touch != "" {
			t.Errorf("%d octets: %q %q %v", n, pin, touch, err)
		}
	}
	if _, _, err := piv.DecodePolicy(nil); err == nil {
		t.Error("nil")
	}
}

func TestDecodeFormFactor(t *testing.T) {
	for b := 0; b < 256; b++ {
		got, err := piv.DecodeFormFactor([]byte{byte(b)})
		if err != nil || got != strconv.Itoa(b) {
			t.Errorf("%d: %q, %v", b, got, err)
		}
	}
	for _, n := range []int{0, 2, 3, 100} {
		if got, err := piv.DecodeFormFactor(bytes.Repeat([]byte{2}, n)); err == nil || got != "" {
			t.Errorf("%d octets: %q, %v", n, got, err)
		}
	}
	if _, err := piv.DecodeFormFactor(nil); err == nil {
		t.Error("nil")
	}
}
