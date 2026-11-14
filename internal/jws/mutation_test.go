package jws_test

import (
	"bytes"
	"testing"

	"ritueel.id/ritueel/internal/jws"
)

// readsAndVerifies reports whether a file is read and every signature of it verifies over payload.
func readsAndVerifies(data, payload []byte) bool {
	g, err := jws.ParseGeneral(data, typList)
	if err != nil {
		return false
	}
	for _, s := range g.Signatures {
		if s.Verify(payload) != nil {
			return false
		}
	}
	return true
}

var masks = []byte{0x01, 0x20, 0x80, 0xff}

func TestEveryChangeOfTheFileOrThePayloadIsRefused(t *testing.T) {
	f := newFixture(t)
	good := file(f.entry())
	if !readsAndVerifies(good, f.payload) {
		t.Fatal("the base case is not accepted")
	}
	t.Run("one flipped byte of the file", func(t *testing.T) {
		n := 0
		for i := range good {
			for _, m := range masks {
				mut := bytes.Clone(good)
				mut[i] ^= m
				n++
				if readsAndVerifies(mut, f.payload) {
					t.Fatalf("byte %d xor %#x is accepted", i, m)
				}
			}
		}
		if n == 0 {
			t.Fatal("nothing was checked")
		}
	})
	t.Run("a file cut at every length", func(t *testing.T) {
		for n := range len(good) {
			if readsAndVerifies(good[:n], f.payload) {
				t.Fatalf("a file of %d of %d bytes is accepted", n, len(good))
			}
		}
	})
	t.Run("a byte added after the file", func(t *testing.T) {
		for _, b := range []byte{'x', '}', ',', 0, 0xff} {
			if readsAndVerifies(append(bytes.Clone(good), b), f.payload) {
				t.Errorf("byte %#x after the object is accepted", b)
			}
		}
	})
	t.Run("a byte inserted at every position", func(t *testing.T) {
		for i := 0; i <= len(good); i++ {
			mut := append(append(bytes.Clone(good[:i]), 'A'), good[i:]...)
			if readsAndVerifies(mut, f.payload) {
				t.Fatalf("a byte inserted at %d is accepted", i)
			}
		}
	})
	t.Run("one flipped byte of the payload", func(t *testing.T) {
		for i := range f.payload {
			for _, m := range masks {
				mut := bytes.Clone(f.payload)
				mut[i] ^= m
				if readsAndVerifies(good, mut) {
					t.Fatalf("payload byte %d xor %#x is accepted", i, m)
				}
			}
		}
	})
	t.Run("a payload cut at every length and one byte added", func(t *testing.T) {
		for n := range len(f.payload) {
			if readsAndVerifies(good, f.payload[:n]) {
				t.Fatalf("payload cut to %d bytes is accepted", n)
			}
		}
		for _, b := range []byte{' ', '\n', 0, 'x'} {
			if readsAndVerifies(good, append(bytes.Clone(f.payload), b)) {
				t.Errorf("payload with %#x added is accepted", b)
			}
		}
	})
	t.Run("two signatures where one is changed at every byte", func(t *testing.T) {
		two := file(f.entry(), goodEntry(t, f.other, typList, f.payload))
		if !readsAndVerifies(two, f.payload) {
			t.Fatal("the base case is not accepted")
		}
		for i := range two {
			mut := bytes.Clone(two)
			mut[i] ^= 0x01
			if readsAndVerifies(mut, f.payload) {
				t.Fatalf("byte %d is accepted", i)
			}
		}
	})
}

func TestEveryChangeOfACompactJWSIsRefused(t *testing.T) {
	k := newKey(t)
	payload := []byte(`{"version":1,"x509_spki_sha256":"` + k.pin + `"}`)
	good := goodCompact(t, k, typRemoval, payload)
	accepted := func(s string) bool {
		c, err := jws.ParseCompact(s, typRemoval)
		return err == nil && c.Verify() == nil
	}
	if !accepted(good) {
		t.Fatal("the base case is not accepted")
	}
	for i := range len(good) {
		for _, m := range masks {
			mut := []byte(good)
			mut[i] ^= m
			if accepted(string(mut)) {
				t.Fatalf("byte %d xor %#x is accepted", i, m)
			}
		}
	}
	for n := range len(good) {
		if accepted(good[:n]) {
			t.Fatalf("cut to %d bytes is accepted", n)
		}
	}
	for _, tail := range []string{"A", ".", "=", "\n", " ", "\x00"} {
		if accepted(good + tail) {
			t.Errorf("%q after the text is accepted", tail)
		}
	}
}
