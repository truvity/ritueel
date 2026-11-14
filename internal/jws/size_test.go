package jws_test

import (
	"bytes"
	"testing"

	"ritueel.id/ritueel/internal/jws"
)

// limit is the page's size for a file of the format: 256 KiB. The test says the number itself,
// so that a change of the constant in the package is seen.
const limit = 256 * 1024

func TestConstants(t *testing.T) {
	if jws.MaxBytes != limit {
		t.Errorf("MaxBytes is %d, the page says 256 KiB (%d)", jws.MaxBytes, limit)
	}
	if jws.SignatureSize != 96 {
		t.Errorf("SignatureSize is %d, ES384 is 96 bytes", jws.SignatureSize)
	}
	if jws.AlgES384 != "ES384" {
		t.Errorf("AlgES384 is %q", jws.AlgES384)
	}
}

func TestParseGeneralSizes(t *testing.T) {
	f := newFixture(t)
	good := file(f.entry())
	pad := func(n int) []byte { return append(bytes.Clone(good), bytes.Repeat([]byte{' '}, n-len(good))...) }
	t.Run("at the limit", func(t *testing.T) {
		g, err := jws.ParseGeneral(pad(limit), typList)
		if err != nil {
			t.Fatal(err)
		}
		if err := g.Signatures[0].Verify(f.payload); err != nil {
			t.Error(err)
		}
	})
	t.Run("one byte over", func(t *testing.T) { refuses(t, pad(limit+1), typList) })
	t.Run("far over", func(t *testing.T) { refuses(t, pad(4*limit), typList) })
	t.Run("one byte under", func(t *testing.T) {
		if _, err := jws.ParseGeneral(pad(limit-1), typList); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a file of the limit that is no JWS", func(t *testing.T) { refuses(t, bytes.Repeat([]byte{'x'}, limit), typList) })
	t.Run("many signatures within the limit are all read", func(t *testing.T) {
		// No count of signatures is capped by the format; the size is. Each costs one certificate
		// read and one check, so the file at its limit is the most work a host does.
		var entries []string
		keys := []*key{}
		for size := 2; size < limit-3000; {
			k := newKey(t)
			e := goodEntry(t, k, typList, f.payload)
			keys = append(keys, k)
			entries = append(entries, e)
			size += len(e) + 1
			if len(entries) >= 150 {
				break
			}
		}
		g, err := jws.ParseGeneral(file(entries...), typList)
		if err != nil {
			t.Fatal(err)
		}
		if len(g.Signatures) != len(entries) {
			t.Fatalf("read %d of %d signatures", len(g.Signatures), len(entries))
		}
		for i, s := range g.Signatures {
			if s.Header.Kid != keys[i].pin {
				t.Fatalf("signature %d is not in the order of the file", i)
			}
			if err := s.Verify(f.payload); err != nil {
				t.Fatalf("signature %d: %v", i, err)
			}
		}
	})
}

// compactOf returns a compact JWS of exactly size bytes whose payload is a run of one byte.
func compactOf(t *testing.T, k *key, size int) string {
	t.Helper()
	for spaces := range 12 {
		h := goodHeader(k, typRemoval)
		text := b64u([]byte(h.json() + string(bytes.Repeat([]byte{' '}, spaces))))
		l := size - len(text) - 2 - 128 // the length of the payload text
		if l < 4 || l%4 == 1 {
			continue
		}
		n := l/4*3 + map[int]int{0: 0, 2: 1, 3: 2}[l%4]
		payload := bytes.Repeat([]byte{'x'}, n)
		if len(b64u(payload)) != l {
			t.Fatalf("payload of %d bytes is not %d characters", n, l)
		}
		return compact(text, b64u(payload), sigOver(t, k, text, payload))
	}
	t.Fatalf("no header that makes a compact JWS of %d bytes", size)
	return ""
}

func TestParseCompactSizes(t *testing.T) {
	k := newKey(t)
	for _, size := range []int{limit - 1, limit} {
		s := compactOf(t, k, size)
		if len(s) != size {
			t.Fatalf("made %d bytes, want %d", len(s), size)
		}
		c, err := jws.ParseCompact(s, typRemoval)
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if err := c.Verify(); err != nil {
			t.Errorf("%d bytes: %v", size, err)
		}
	}
	for _, size := range []int{limit + 1, limit + 2, 4 * limit} {
		s := compactOf(t, k, size)
		if len(s) != size {
			t.Fatalf("made %d bytes, want %d", len(s), size)
		}
		refusesCompact(t, s, typRemoval)
	}
}
