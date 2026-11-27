package apdu_test

import (
	"bytes"
	"errors"
	"runtime"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

// The body of a command in secrets: how Command.Encode writes it, and what it does with the edges that a
// PIN has (empty, wiped, a pair with one part gone, a secret in two commands, a wipe during the encoding).
// The expected bytes are written by hand.

func pinA() []byte { return []byte("Xk9#mQ2$") }
func pinB() []byte { return []byte("Zr4&vT8!jW") }

func TestSecretBodyEncodesAsPlainData(t *testing.T) {
	a, b := pinA(), pinB()
	for _, tc := range []struct {
		name     string
		cmd      apdu.Command
		extended bool
		want     []byte
	}{
		{"short, one secret", apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(apdu.NewSecret(a)), false, join(hx(t, "00200081 08"), a)},
		{"short, one secret and Le", apdu.Command{INS: 0x20, P2: 0x81, Le: 256}.WithSecretData(apdu.NewSecret(a)), false, join(hx(t, "00200081 08"), a, hx(t, "00"))},
		{"extended, one secret", apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(apdu.NewSecret(a)), true, join(hx(t, "00200081 00 0008"), a)},
		{"extended, one secret and Le", apdu.Command{INS: 0x20, P2: 0x81, Le: 65536}.WithSecretData(apdu.NewSecret(a)), true, join(hx(t, "00200081 00 0008"), a, hx(t, "0000"))},
		// The pair: the first secret, then the second, with no separator (specification 3.4.1, 7.2.3).
		{"short, the pair", apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(apdu.NewSecret(a), apdu.NewSecret(b)), false, join(hx(t, "00240081 12"), a, b)},
		{"short, the pair, reversed", apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(apdu.NewSecret(b), apdu.NewSecret(a)), false, join(hx(t, "00240081 12"), b, a)},
		{"extended, the pair", apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(apdu.NewSecret(a), apdu.NewSecret(b)), true, join(hx(t, "00240081 00 0012"), a, b)},
		{"the largest short body", apdu.Command{INS: 0x24, P2: 0x81}.WithSecretData(apdu.NewSecret(body(255))), false, join(hx(t, "00240081 FF"), body(255))},
		{"256 bytes in the extended form", apdu.Command{INS: 0x24, P2: 0x81}.WithSecretData(apdu.NewSecret(body(256))), true, join(hx(t, "00240081 00 0100"), body(256))},
	} {
		got, err := tc.cmd.Encode(tc.extended)
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Errorf("%s: %v %x", tc.name, err, got[:min(len(got), 20)])
		}
		// BodyLen is what the encoding holds, and Data is empty.
		if tc.cmd.BodyLen() != len(tc.want)-hdr(tc.want, tc.cmd.Le, tc.extended) || len(tc.cmd.Data) != 0 || !tc.cmd.HasSecret() {
			t.Errorf("%s: BodyLen %d, Data %d bytes", tc.name, tc.cmd.BodyLen(), len(tc.cmd.Data))
		}
	}
	if _, err := (apdu.Command{INS: 0x24}.WithSecretData(apdu.NewSecret(body(256)))).Encode(false); !errors.Is(err, apdu.ErrDataTooLong) {
		t.Errorf("256 bytes in the short form: %v", err)
	}
	if _, err := (apdu.Command{INS: 0x24}.WithSecretPair(apdu.NewSecret(body(200)), apdu.NewSecret(body(56)))).Encode(false); !errors.Is(err, apdu.ErrDataTooLong) {
		t.Errorf("the pair's 256 bytes in the short form: %v", err)
	}
	if _, err := (apdu.Command{INS: 0x24}.WithSecretData(apdu.NewSecret(body(65536)))).Encode(true); !errors.Is(err, apdu.ErrDataTooLong) {
		t.Errorf("65536 bytes in the extended form: %v", err)
	}
}

// hdr is the number of bytes of an encoded command that are not its body: the four of the header, Lc and Le.
func hdr(enc []byte, le int, extended bool) int {
	n := 4
	body := len(enc) - 4
	if le > 0 {
		if extended {
			body -= 2
			n += 2
		} else {
			body--
			n++
		}
	}
	if body > 0 {
		if extended {
			n += 3
		} else {
			n++
		}
	}
	if le > 0 && extended && body <= 0 {
		n++ // case 2E: the marker byte
	}
	return n
}

func TestBodyLenAgainstTheEncoding(t *testing.T) {
	for _, n := range []int{0, 1, 2, 7, 8, 127, 128, 255} {
		for _, le := range []int{0, 1, 256} {
			for name, c := range map[string]apdu.Command{
				"plain":  {INS: 0xDA, Data: body(n), Le: le},
				"secret": apdu.Command{INS: 0xDA, Le: le}.WithSecretData(apdu.NewSecret(body(n))),
				"pair":   apdu.Command{INS: 0xDA, Le: le}.WithSecretPair(apdu.NewSecret(body(n/2)), apdu.NewSecret(body(n-n/2))),
			} {
				want, _ := apdu.Command{INS: 0xDA, Data: body(n), Le: le}.Encode(false)
				got, err := c.Encode(false)
				if name == "secret" && n == 0 || name == "pair" && n < 2 {
					// A part with no byte is never encoded: see TestEmptyAndWipedSecretBodies.
					if !errors.Is(err, apdu.ErrSecretEmpty) || got != nil || c.BodyLen() != n {
						t.Errorf("%s, %d bytes: %v", name, n, err)
					}
					continue
				}
				if err != nil || c.BodyLen() != n || len(got) != len(want) {
					t.Errorf("%s, %d bytes, Le %d: BodyLen %d, %d bytes encoded, plain %d (%v)", name, n, le, c.BodyLen(), len(got), len(want), err)
				}
				if name == "pair" && n > 0 && (c.SecretParts() != 2 || !c.HasSecret()) || name == "secret" && (c.SecretParts() != 1 || !c.HasSecret()) || name == "plain" && (c.HasSecret() || c.SecretParts() != 0) {
					t.Errorf("%s: parts %d", name, c.SecretParts())
				}
				// A secret body encodes as the bytes of a plain body of the same content (the pair, of its two halves).
				if name != "pair" && !bytes.Equal(got, want) {
					t.Errorf("%s, %d bytes, Le %d: %x, want %x", name, n, le, got, want)
				}
			}
		}
	}
}

func TestSecretAndPlainDataTogether(t *testing.T) {
	s := apdu.NewSecret(pinA())
	for name, c := range map[string]apdu.Command{
		"Data set after the secret": func() apdu.Command { c := apdu.Command{INS: 0x20}.WithSecretData(s); c.Data = []byte{1}; return c }(),
		"Data set after the pair": func() apdu.Command {
			c := apdu.Command{INS: 0x24}.WithSecretPair(s, s)
			c.Data = []byte{1, 2}
			return c
		}(),
		"Data of 255 bytes and a pair": func() apdu.Command { c := apdu.Command{INS: 0x24}.WithSecretPair(s, s); c.Data = body(255); return c }(),
		"a wiped secret and plain Data": func() apdu.Command {
			w := apdu.NewSecret(pinA())
			w.Wipe()
			c := apdu.Command{INS: 0x20}.WithSecretData(w)
			c.Data = []byte{1}
			return c
		}(),
	} {
		for _, ext := range []bool{false, true} {
			if got, err := c.Encode(ext); !errors.Is(err, apdu.ErrBodyConflict) || got != nil {
				t.Errorf("%s (extended %v): %v %x", name, ext, err, got)
			}
		}
	}
	// WithSecretData puts the secret in place of Data, and clears it; a secret and no Data is no conflict.
	c := apdu.Command{INS: 0x20, Data: []byte{9, 9}}.WithSecretData(s)
	if len(c.Data) != 0 || c.BodyLen() != 8 {
		t.Errorf("Data was kept: %x", c.Data)
	}
	if got, err := c.Encode(false); err != nil || !bytes.Equal(got, join(hx(t, "00200000 08"), pinA())) {
		t.Errorf("%v %x", err, got)
	}
	// A command can go back to plain data by WithSecretData of nothing... and its Data is then the caller's again.
	c = apdu.Command{INS: 0x20}.WithSecretData(apdu.Secret{})
	c.Data = []byte{1}
	if c.HasSecret() {
		t.Error("the zero Secret counts as a secret")
	}
	if got, err := c.Encode(false); err != nil || !bytes.Equal(got, hx(t, "00200000 01 01")) {
		t.Errorf("%v %x", err, got)
	}
}

// What a Secret that holds nothing does in Encode: it is refused. A wiped, an empty or a missing part never
// becomes a body of zeros, and never becomes no body (a VERIFY with a header and no PIN, or a change with one
// PIN where two were meant). The error is ErrSecretEmpty, which is also an ErrSecretChanged; nothing is
// returned. The command that was never given a secret (the zero Secret) is a plain command.
func TestEmptyAndWipedSecretBodies(t *testing.T) {
	a, b := pinA(), pinB()
	wiped := func(p []byte) apdu.Secret { s := apdu.NewSecret(p); s.Wipe(); return s }
	for name, c := range map[string]apdu.Command{
		"an empty secret":          apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(apdu.NewSecret(nil)),
		"an empty non-nil secret":  apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(apdu.NewSecret([]byte{})),
		"a wiped secret":           apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(wiped(a)),
		"a wiped secret and Le":    apdu.Command{INS: 0x20, P2: 0x81, Le: 256}.WithSecretData(wiped(a)),
		"a pair, both wiped":       apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(wiped(a), wiped(b)),
		"a pair, the first wiped":  apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(wiped(a), apdu.NewSecret(b)),
		"a pair, the second wiped": apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(apdu.NewSecret(a), wiped(b)),
		"a pair, the second empty": apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(apdu.NewSecret(a), apdu.NewSecret(nil)),
		"a pair, the first empty":  apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(apdu.NewSecret(nil), apdu.NewSecret(b)),
	} {
		for _, ext := range []bool{false, true} {
			got, err := c.Encode(ext)
			if !errors.Is(err, apdu.ErrSecretEmpty) || !errors.Is(err, apdu.ErrSecretChanged) || got != nil {
				t.Errorf("%s (extended %v): %v %x", name, ext, err, got)
			}
		}
		if !c.HasSecret() {
			t.Errorf("%s: HasSecret is false: a wiped secret still marks the command as one whose body is secret", name)
		}
	}
	if errors.Is(apdu.ErrSecretChanged, apdu.ErrSecretEmpty) {
		t.Error("ErrSecretChanged is an ErrSecretEmpty: it is the other way round")
	}
	// A command that never had a secret is a plain one, and has no body.
	c := apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(apdu.Secret{})
	if got, err := c.Encode(false); err != nil || !bytes.Equal(got, hx(t, "00200081")) || c.HasSecret() {
		t.Errorf("the zero Secret: %v %x", err, got)
	}
	// SecretParts counts the secrets that the command was given, wiped or not; PartLen is 0 for one that is
	// wiped, absent or out of range, and the length of the bytes for one that is not.
	if n := (apdu.Command{}.WithSecretPair(wiped(a), wiped(b))).SecretParts(); n != 2 {
		t.Errorf("SecretParts of a wiped pair: %d", n)
	}
	if n := (apdu.Command{}.WithSecretData(apdu.Secret{})).SecretParts(); n != 0 {
		t.Errorf("SecretParts of the zero secret: %d", n)
	}
	pair := apdu.Command{}.WithSecretPair(apdu.NewSecret(a), apdu.NewSecret(b))
	one := apdu.Command{}.WithSecretData(apdu.NewSecret(a))
	half := apdu.Command{}.WithSecretPair(wiped(a), apdu.NewSecret(b))
	for name, tc := range map[string]struct {
		c    apdu.Command
		want [4]int // PartLen(-1), (0), (1), (2)
	}{
		"a pair":            {pair, [4]int{0, len(a), len(b), 0}},
		"one":               {one, [4]int{0, len(a), 0, 0}},
		"a pair, one wiped": {half, [4]int{0, 0, len(b), 0}},
		"plain":             {apdu.Command{Data: a}, [4]int{0, 0, 0, 0}},
	} {
		got := [4]int{tc.c.PartLen(-1), tc.c.PartLen(0), tc.c.PartLen(1), tc.c.PartLen(2)}
		if got != tc.want {
			t.Errorf("%s: PartLen %v, want %v", name, got, tc.want)
		}
	}
}

// EncodedLen is the length of what Encode returns, for every body and Le, in both forms.
func TestEncodedLenIsTheLengthOfTheEncoding(t *testing.T) {
	for _, n := range []int{0, 1, 2, 8, 127, 128, 255, 256, 1000, 65535} {
		for _, le := range []int{0, 1, 255, 256, 257, 65535, 65536} {
			for _, ext := range []bool{false, true} {
				enc, err := apdu.Command{INS: 0xDA, Data: body(n), Le: le}.Encode(ext)
				if err != nil {
					continue
				}
				if got := apdu.EncodedLen(n, le, ext); got != len(enc) {
					t.Errorf("body %d, Le %d, extended %v: EncodedLen %d, Encode %d", n, le, ext, got, len(enc))
				}
				if n > 0 {
					sec, err := apdu.Command{INS: 0xDA, Le: le}.WithSecretData(apdu.NewSecret(body(n))).Encode(ext)
					if err != nil || len(sec) != len(enc) {
						t.Errorf("secret body %d, Le %d, extended %v: %v", n, le, ext, err)
					}
				}
			}
		}
	}
}

// A secret may be the body of several commands, and Encode does not use it up: it is the caller's to wipe.
func TestOneSecretInTwoCommands(t *testing.T) {
	s := apdu.NewSecret(pinA())
	c1 := apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(s)
	c2 := apdu.Command{INS: 0x20, P2: 0x82}.WithSecretData(s)
	c3 := apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(s, s)
	for range 3 {
		for _, c := range []apdu.Command{c1, c2} {
			got, err := c.Encode(false)
			if err != nil || !bytes.Equal(got[5:], pinA()) {
				t.Fatalf("%v %x", err, got)
			}
			clear(got) // the bytes that Encode returned are the caller's, and clearing them does not reach the secret
		}
		got, err := c3.Encode(true)
		if err != nil || !bytes.Equal(got[7:], append(pinA(), pinA()...)) {
			t.Fatalf("%v %x", err, got)
		}
	}
	if s.Len() != len(pinA()) {
		t.Fatal("Encode used the secret up")
	}
	var kept []byte
	s.Use(func(b []byte) { kept = bytes.Clone(b) })
	if !bytes.Equal(kept, pinA()) {
		t.Fatal("Encode changed the secret")
	}
	// A wipe reaches every command that shares the secret.
	s.Wipe()
	for _, c := range []apdu.Command{c1, c2, c3} {
		if got, err := c.Encode(false); !errors.Is(err, apdu.ErrSecretEmpty) || got != nil {
			t.Errorf("after the wipe: %v %x", err, got)
		}
	}
	if c1.BodyLen() != 0 || c3.BodyLen() != 0 {
		t.Error("BodyLen after the wipe")
	}
}

// A wipe during the encoding. What Encode guarantees, with the race detector on: each secret is read under
// its own lock, so there is no data race. The length of each part is read once, and the bytes are taken only
// if they are that long; a part that is empty, or that was wiped in between, makes Encode clear what it wrote
// and return ErrSecretChanged with no bytes. So the result is the whole body or an error: never a part of a
// PIN, never one PIN where two were meant, never a body of zeros, never no body.
func TestWipeDuringEncode(t *testing.T) {
	a, b := pinA(), pinB()
	full := join(hx(t, "00240081 12"), a, b)
	for round := range 600 {
		s1, s2 := apdu.NewSecret(a), apdu.NewSecret(b)
		c := apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(s1, s2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range round % 5 {
				runtime.Gosched()
			}
			switch round % 3 {
			case 0:
				s1.Wipe()
			case 1:
				s2.Wipe()
			default:
				s1.Wipe()
				s2.Wipe()
			}
		}()
		var got []byte
		var err error
		go func() {
			defer wg.Done()
			got, err = c.Encode(false)
		}()
		wg.Wait()
		switch {
		case err != nil:
			if !errors.Is(err, apdu.ErrSecretChanged) || got != nil {
				t.Fatalf("round %d: %v %x", round, err, got)
			}
		case bytes.Equal(got, full):
		default:
			t.Fatalf("round %d: neither the whole body nor an error: %x", round, got)
		}
	}
}
