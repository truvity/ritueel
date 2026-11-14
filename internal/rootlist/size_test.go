package rootlist_test

import (
	"bytes"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

// limit is the page's size for the list: 256 KiB. The test says the number itself, so that a change
// of the constant in the package is seen.
const limit = 256 * 1024

// padTo writes spaces after a JSON text until it is n bytes long: white space after the object is
// allowed, so the padded text is a good list that is exactly as long as asked.
func padTo(data []byte, n int) []byte {
	return append(bytes.Clone(data), bytes.Repeat([]byte{' '}, n-len(data))...)
}

func TestSizeOfTheList(t *testing.T) {
	b := newBase(t)
	w := b.w
	j := b.cand.json()
	trust := b.trust(t)
	for _, c := range []struct {
		name string
		size int
		want bool
	}{
		{"one byte under the limit", limit - 1, true},
		{"at the limit", limit, true},
		{"one byte over the limit", limit + 1, false},
		{"two bytes over the limit", limit + 2, false},
		{"four times the limit", 4 * limit, false},
	} {
		t.Run("Verify: "+c.name, func(t *testing.T) {
			data := padTo(j, c.size)
			v := rootlist.Verify(signedBytes(t, data, w.a), trust, now)
			if c.want {
				accepts(t, v)
				return
			}
			// The signature covers the long list, so checks 1 to 4 pass and check 5 refuses it.
			refuses(t, v, rootlist.Malformed, 5)
		})
		t.Run("ParseList: "+c.name, func(t *testing.T) {
			l, err := rootlist.ParseList(padTo(j, c.size))
			if c.want != (err == nil) || c.want != (l != nil) {
				t.Errorf("accepted = %v, want %v (%v)", err == nil, c.want, err)
			}
		})
		t.Run("ParseHeld: "+c.name, func(t *testing.T) {
			h, err := rootlist.ParseHeld(padTo(j, c.size))
			if c.want != (err == nil) || c.want != (h != nil) {
				t.Errorf("accepted = %v, want %v (%v)", err == nil, c.want, err)
			}
		})
	}
	t.Run("a list over the limit is refused for its size, not for its version", func(t *testing.T) {
		// The version is read from a document that is within the limit only. A list of version 2 that
		// is too long is malformed, and a list of version 2 within the limit is version-unsupported.
		v2 := replace(t, j, `"version":1`, `"version":2`)
		refuses(t, rootlist.Verify(signedBytes(t, padTo(v2, limit+1), w.a), trust, now), rootlist.Malformed, 5)
		refuses(t, rootlist.Verify(signedBytes(t, padTo(v2, limit), w.a), trust, now), rootlist.VersionUnsupported, 4)
	})
	t.Run("the limit is 256 KiB", func(t *testing.T) {
		if rootlist.MaxBytes != limit {
			t.Fatalf("MaxBytes is %d", rootlist.MaxBytes)
		}
	})
	t.Run("a list of the limit that holds many root keys", func(t *testing.T) {
		// 26 labels is all there are; the rest of the room is white space.
		var keys []*key
		for c := 'A'; c <= 'Z'; c++ {
			keys = append(keys, newKey(t, string(c)))
		}
		held := heldOf(t, listOf(7, keys...))
		cand := padTo(listOf(8, keys...).json(), limit)
		accepts(t, rootlist.Verify(signedBytes(t, cand, keys[0]), held, now))
	})
}

func TestSizeOfTheSignatureFile(t *testing.T) {
	b := newBase(t)
	w := b.w
	j := b.cand.json()
	trust := b.trust(t)
	good := sign(t, j, w.a)
	for _, c := range []struct {
		name string
		size int
		want bool
	}{
		{"one byte under the limit", limit - 1, true},
		{"at the limit", limit, true},
		{"one byte over the limit", limit + 1, false},
		{"four times the limit", 4 * limit, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := rootlist.Verify(rootlist.Signed{JSON: j, JWS: padTo(good, c.size)}, trust, now)
			if c.want {
				accepts(t, v)
				return
			}
			refuses(t, v, rootlist.Malformed, 1)
		})
	}
	t.Run("a file of the limit and no more that is not a signature file", func(t *testing.T) {
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: j, JWS: bytes.Repeat([]byte{'x'}, limit)}, trust, now), rootlist.Malformed, 1)
	})
}

// authorisationOf is a valid removal authorisation of k that is exactly size bytes long: the header
// carries white space after its object, which JSON allows.
func authorisationOf(t testing.TB, k *key, size int) string {
	t.Helper()
	payload := removalPayload(k.pin)
	h := goodHeader(k, typRemoval).json()
	want := size - 2 - 128 - len(b64u(payload)) // the length of the protected text
	for n := len(h); n < len(h)+8+want; n++ {
		if n/3*4+[]int{0, 2, 3}[n%3] != want {
			continue
		}
		p := b64u([]byte(h + strings.Repeat(" ", n-len(h))))
		s := p + "." + b64u(payload) + "." + sigOver(t, k, p, payload)
		if len(s) != size {
			t.Fatalf("made %d bytes, want %d", len(s), size)
		}
		return s
	}
	t.Fatalf("no header gives an authorisation of %d bytes", size)
	return ""
}

func TestSizeOfTheRemovalAuthorisation(t *testing.T) {
	w := newWorld(t)
	held := []string{w.a.pin, w.b.pin}
	cand := listFor(t, 8, w.b)
	for _, c := range []struct {
		name string
		size int
		want bool
	}{
		{"two bytes under the limit", limit - 2, true},
		{"at the limit", limit, true},
		{"one byte over the limit", limit + 1, false},
		{"two bytes over the limit", limit + 2, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := rootlist.Removal{Label: "A", X509SPKISHA256: w.a.pin, Authorisation: authorisationOf(t, w.a, c.size)}
			err := rootlist.CheckRemoval(r, cand, held)
			if c.want != (err == nil) {
				t.Errorf("accepted = %v, want %v (%v)", err == nil, c.want, err)
			}
		})
	}
}

func TestSizeOfTheCABundle(t *testing.T) {
	w := newWorld(t)
	l := listFor(t, 7, w.a, w.b)
	good := bundleOf(7, w.a, w.b)
	// No bundle of the page is as long as the limit, so a longer text is no bundle: the check says
	// so, and a text at the limit is read as a bundle and refused for what it holds. The two are
	// told apart by the words of the detail ("longer").
	over := rootlist.VerifyCABundle([]byte(good+strings.Repeat("x", limit+1-len(good))), l)
	mismatch(t, over)
	if !strings.Contains(over.Detail, "longer") {
		t.Errorf("one byte over the limit is not refused for its size: %q", over.Detail)
	}
	at := rootlist.VerifyCABundle([]byte(good+strings.Repeat("x", limit-len(good))), l)
	mismatch(t, at)
	if strings.Contains(at.Detail, "longer") {
		t.Errorf("a text at the limit is refused for its size: %q", at.Detail)
	}
	under := rootlist.VerifyCABundle([]byte(good+strings.Repeat("x", limit-1-len(good))), l)
	mismatch(t, under)
	if strings.Contains(under.Detail, "longer") {
		t.Errorf("a text under the limit is refused for its size: %q", under.Detail)
	}
	mismatch(t, rootlist.VerifyCABundle(bytes.Repeat([]byte{'x'}, 4*limit), l))
}

func TestSizeOfThePins(t *testing.T) {
	// Pins have no size limit of their own; many of them are read.
	w := newWorld(t)
	pins := []string{w.a.pin, w.b.pin}
	for i := range 2000 {
		pins = append(pins, strings.Repeat("0", 60)+itoa4(i))
	}
	tr, err := rootlist.PinTrust(pins)
	if err != nil {
		t.Fatal(err)
	}
	// All the pins are read: the verdict is about the root keys that the list does not carry.
	refuses(t, rootlist.Verify(signed(t, listOf(1, w.a, w.b), w.a), tr, now), rootlist.InsufficientSigners, 10)
}

func itoa4(n int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[(n>>12)&15], digits[(n>>8)&15], digits[(n>>4)&15], digits[n&15]})
}
