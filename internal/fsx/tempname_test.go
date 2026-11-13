package fsx_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

func TestTempNameShapeOverTenThousandDraws(t *testing.T) {
	w := &fsx.Writer{}
	seen := map[string]bool{}
	chars := map[rune]bool{}
	for i := 0; i < 10_000; i++ {
		n, err := w.TempName()
		if err != nil {
			t.Fatal(err)
		}
		if len(n) != 15 {
			t.Fatalf("temporary name %q has %d characters, want 15", n, len(n))
		}
		if !strings.HasPrefix(n, fsx.TempPrefix) {
			t.Fatalf("temporary name %q does not start with %q", n, fsx.TempPrefix)
		}
		for _, r := range n[len(fsx.TempPrefix):] {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				t.Fatalf("temporary name %q has the character %q, want lower-case letters and digits", n, r)
			}
			chars[r] = true
		}
		if seen[n] {
			t.Fatalf("temporary name %q was drawn twice in 10,000 draws", n)
		}
		seen[n] = true
	}
	if len(chars) != 36 {
		t.Fatalf("the draws used %d of the 36 characters", len(chars))
	}
}

func TestTempNameReadsOnlyTheRandomSource(t *testing.T) {
	f := newMemFS("/b")
	w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
	if _, err := w.TempName(); err != nil {
		t.Fatal(err)
	}
	if f.opCount() != 0 {
		t.Fatalf("TempName reached the file system: %v", f.opList())
	}
}

func TestTempNameFromARepeatingSourceRepeats(t *testing.T) {
	a, _ := (&fsx.Writer{Rand: newDetRand(5)}).TempName()
	b, _ := (&fsx.Writer{Rand: newDetRand(5)}).TempName()
	c, _ := (&fsx.Writer{Rand: newDetRand(6)}).TempName()
	if a != b || a == c {
		t.Fatalf("names %q %q %q: the name must be a function of the source", a, b, c)
	}
}

func TestTempNameErrorFromTheRandomSource(t *testing.T) {
	boom := errors.New("no entropy")
	_, err := (&fsx.Writer{Rand: failingReader{boom}}).TempName()
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want an error that wraps the reader's", err)
	}
	_, err = (&fsx.Writer{Rand: strings.NewReader("abc")}).TempName()
	if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a source that ends early: %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestTempNameWithOnlyUnusableBytesGivesUpAndDoesNotLoop(t *testing.T) {
	for _, b := range []byte{0xff, 0xfc} {
		r := &constReader{b: b}
		n, err := (&fsx.Writer{Rand: r}).TempName()
		if err == nil {
			t.Fatalf("byte %#x: got the name %q from a source of unusable bytes", b, n)
		}
		if n != "" {
			t.Fatalf("byte %#x: a name %q came back with an error", b, n)
		}
		if r.reads == 0 || r.reads > 1000 {
			t.Fatalf("byte %#x: %d reads before giving up, want a small fixed number", b, r.reads)
		}
	}
}

func TestTempNameSkipsUnusableBytesAndKeepsTheUsableOnes(t *testing.T) {
	// First an 11-byte read of nothing usable, then 11 usable bytes.
	src := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{0xff}, 11)), bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
	n, err := (&fsx.Writer{Rand: src}).TempName()
	if err != nil {
		t.Fatal(err)
	}
	if len(n) != 15 || !strings.HasPrefix(n, fsx.TempPrefix) {
		t.Fatalf("got %q", n)
	}
	// Mixed bytes in one read: the unusable ones are skipped, never mapped, so the next read
	// supplies the rest.
	mixed := append(bytes.Repeat([]byte{0xff, 1}, 5), 0xfe)
	src = io.MultiReader(bytes.NewReader(mixed), bytes.NewReader(bytes.Repeat([]byte{2}, 11)))
	n, err = (&fsx.Writer{Rand: src}).TempName()
	if err != nil || len(n) != 15 {
		t.Fatalf("got %q, %v", n, err)
	}
}
