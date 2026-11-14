package openpgp

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // the version 4 fingerprint is a SHA-1 by the standard
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// The parsers of this package read bytes that a requester sent. These targets feed them anything and
// check what has to hold when they accept. None of them starts a program.

func vectorFile(tb testing.TB, elem ...string) []byte {
	tb.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "testdata", "hand-off", "v1"}, elem...)...))
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func FuzzSplitPacket(f *testing.F) {
	for _, name := range []string{"pki/test-primary-a.pgp", "responses/pgp-software-valid.bound.pgp", "requests/pgp-software-valid.subkey.pgp"} {
		f.Add(vectorFile(f, name))
	}
	f.Add([]byte{0xC2, 0x00})
	f.Add([]byte{0x88, 0x01, 0x00})
	f.Add([]byte{0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0xC2, 0xE1, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		tag, body, rest, err := splitPacket(b)
		if err != nil {
			if tag != 0 || body != nil || rest != nil {
				t.Fatalf("an error with a tag %d, a body of %d and a rest of %d", tag, len(body), len(rest))
			}
			return
		}
		if tag > 0x3F {
			t.Fatalf("the tag %d does not fit six bits", tag)
		}
		if len(body)+len(rest) > len(b) || !bytes.HasSuffix(b, rest) {
			t.Fatalf("the body of %d and the rest of %d do not come from the input of %d", len(body), len(rest), len(b))
		}
		if len(b)-len(rest)-len(body) < 2 {
			t.Fatalf("the packet has a header of %d bytes", len(b)-len(rest)-len(body))
		}
		// What was read, written again in the new format, reads as the same packet.
		again := wrap(tag, body)
		tag2, body2, rest2, err := splitPacket(again)
		if err != nil || tag2 != tag || !bytes.Equal(body2, body) || len(rest2) != 0 {
			t.Fatalf("a packet written again does not read as the same: %v", err)
		}
	})
}

func FuzzParseArea(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{5, 2, 0x69, 0x55, 0xb9, 0x01})
	f.Add([]byte{0xC0, 0x00, 2})
	f.Add([]byte{0xFF, 0, 0, 0, 2, 2, 7})
	f.Add([]byte{1, 2, 1})
	f.Add([]byte{0, 2})
	f.Fuzz(func(t *testing.T, b []byte) {
		subs, err := parseArea(b)
		if err != nil {
			if subs != nil {
				t.Fatal("an error with subpackets")
			}
			return
		}
		total := 0
		for _, s := range subs {
			if s.typ > 0x7F {
				t.Fatalf("the type %d has the critical bit", s.typ)
			}
			total += len(s.data) + 2 // at least a length octet and the type
		}
		if total > len(b)+len(subs)*4 {
			t.Fatalf("the subpackets are longer than the area")
		}
		// Written again and read again, the same subpackets come back.
		back, err := parseArea(encodeArea(subs))
		if err != nil || !equalSubs(subs, back) {
			t.Fatalf("subpackets written again do not read the same: %v", err)
		}
	})
}

func equalSubs(a, b []subpacket) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].typ != b[i].typ || a[i].critical != b[i].critical || !bytes.Equal(a[i].data, b[i].data) {
			return false
		}
	}
	return true
}

func FuzzSplitSig(f *testing.F) {
	for _, name := range []string{"responses/pgp-software-valid.bound.pgp", "requests/pgp-software-valid.subkey.pgp", "pki/test-primary-a.pgp"} {
		b := vectorFile(f, name)
		for len(b) > 0 {
			tag, body, rest, err := splitPacket(b)
			if err != nil {
				break
			}
			if tag == tagSignature {
				f.Add(bytes.Clone(body))
			}
			b = rest
		}
	}
	f.Add([]byte{4, 0x13, 19, 9, 0, 0, 0, 0})
	f.Add([]byte{4, 0x13, 19, 9, 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, body []byte) {
		a, err := splitSig(body)
		if err != nil {
			return
		}
		if len(a.rest) > len(body) || !bytes.HasSuffix(body, a.rest) {
			t.Fatal("the rest is not the end of the body")
		}
		if body[0] != 4 {
			t.Fatalf("a signature of version %d was accepted", body[0])
		}
		hl := int(body[4])<<8 | int(body[5])
		again, err := parseArea(body[6 : 6+hl])
		if err != nil || !equalSubs(again, a.hashed) {
			t.Fatal("the hashed area does not read as the area of the body")
		}
	})
}

func FuzzReadKey(f *testing.F) {
	for _, name := range []string{"pki/test-primary-a.pgp", "requests/pgp-software-valid.subkey.pgp", "requests/pgp-ed25519.subkey.pgp"} {
		b := vectorFile(f, name)
		if _, _, rest, err := splitPacket(b); err == nil {
			f.Add(bytes.Clone(b[:len(b)-len(rest)]), byte(tagSubkey))
			f.Add(bytes.Clone(b[:len(b)-len(rest)]), byte(tagPublicKey))
		}
	}
	f.Fuzz(func(t *testing.T, pkt []byte, tag byte) {
		k, err := readKey(pkt, tag)
		if err != nil {
			if k != nil {
				t.Fatal("an error with a key")
			}
			return
		}
		if tag != tagSubkey && tag != tagPublicKey {
			t.Fatalf("a key was read from a packet with the tag %d", tag)
		}
		if len(k.fp) != 20 || len(k.keyID) != 8 || !bytes.Equal(k.keyID, k.fp[12:]) {
			t.Fatalf("the identifiers are %d and %d bytes", len(k.fp), len(k.keyID))
		}
		// The fingerprint is the SHA-1 of 0x99, the length and the body.
		h := sha1.New() //nolint:gosec // see the import
		h.Write(hashPrefix(k.body))
		if !bytes.Equal(h.Sum(nil), k.fp) {
			t.Fatal("the fingerprint is not the one of the standard")
		}
		if k.ec == nil || k.ec.Curve.Params().Name != "P-384" {
			t.Fatal("the key is not on P-384")
		}
		if _, err := k.ec.Bytes(); err != nil {
			t.Fatalf("the point is not on the curve: %v", err)
		}
		if !bytes.Equal(wrap(tag, k.body)[len(header(tag, len(k.body))):], k.body) {
			t.Fatal("the body is not what the packet holds")
		}
		_, body, _, err := splitPacket(pkt)
		if err != nil || !bytes.Equal(body, k.body) {
			t.Fatal("the body of the key is not the body of the packet")
		}
	})
}

func FuzzCheckUserID(f *testing.F) {
	f.Add("Example Test Release Root A (TEST ONLY) <release@example.org>")
	f.Add("a\nb")
	f.Add("a\u202eb")
	f.Add("")
	f.Add(" a")
	f.Add("x <a@b> Release Root A <c@d>")
	f.Add("Acme Release Root A <a@b>")
	f.Fuzz(func(t *testing.T, id string) {
		if err := checkUserID(id); err != nil {
			return
		}
		if len(id) == 0 || len(id) > 1024 || !utf8.ValidString(id) {
			t.Fatalf("a user ID of %d bytes was accepted", len(id))
		}
		if id[0] == ' ' || id[len(id)-1] == ' ' {
			t.Fatal("a user ID with a space at an end was accepted")
		}
		for _, r := range id {
			if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Co, unicode.Cs, unicode.M) ||
				(unicode.IsSpace(r) && r != ' ') || r == utf8.RuneError || r > 0x7E {
				t.Fatalf("a user ID with U+%04X was accepted", r)
			}
		}
		// The form of the page: the parts are the ones that UserID makes a text of.
		rest, _ := strings.CutSuffix(id, ">")
		i := strings.LastIndex(rest, " <")
		head, address := rest[:i], rest[i+2:]
		test := strings.HasSuffix(head, " (TEST ONLY)")
		head, _ = strings.CutSuffix(head, " (TEST ONLY)")
		j := strings.LastIndex(head, " Release Root ")
		if again, err := UserID(head[:j], head[j+len(" Release Root "):], address, test); err != nil || again != id {
			t.Fatalf("a user ID that UserID does not make from its parts was accepted: %q, %q, %v", id, again, err)
		}
	})
}
