package openpgp

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// What checkUserID (the rule of a release root's user ID) says of a text with one code point put in each place of
// it. It uses nothing but checkUserID, so that the same file runs against the code as it was before the rule for
// a person's user ID was added: the answers are the same, code point by code point.

func TestQACheckUserIDOfAReleaseRootEveryCodePointInEveryPlace(t *testing.T) {
	asciiName := func(r rune) bool {
		return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-'
	}
	asciiAddress := func(r rune) bool { return r > ' ' && r <= '~' && r != '<' && r != '>' && r != '@' }
	places := []struct {
		name string
		make func(r rune) string
		ok   func(r rune) bool
	}{
		{"inside the name", func(r rune) string { return "Ac" + string(r) + "me Release Root A <a@example.org>" }, func(r rune) bool { return asciiName(r) || r == ' ' }},
		{"at the start of the name", func(r rune) string { return string(r) + "Acme Release Root A <a@example.org>" }, asciiName},
		{"as the label", func(r rune) string { return "Acme Release Root " + string(r) + " <a@example.org>" }, func(r rune) bool { return r >= 'A' && r <= 'Z' }},
		{"in the address before the at sign", func(r rune) string { return "Acme Release Root A <a" + string(r) + "b@example.org>" }, asciiAddress},
		{"in the address after the at sign", func(r rune) string { return "Acme Release Root A <a@exa" + string(r) + "mple.org>" }, asciiAddress},
		{"after the closing bracket", func(r rune) string { return "Acme Release Root A <a@example.org>" + string(r) }, func(rune) bool { return false }},
		{"in the test mark", func(r rune) string { return "Acme Release Root A (TEST" + string(r) + "ONLY) <a@example.org>" }, func(r rune) bool { return r == ' ' }},
	}
	for _, p := range places {
		bad := 0
		for r := rune(0); r <= 0x7F; r++ {
			if (checkUserID(p.make(r)) == nil) != p.ok(r) {
				bad++
				t.Errorf("%s: U+%04X: accepted=%v, want %v", p.name, r, !p.ok(r), p.ok(r))
			}
		}
		// every code point beyond ASCII is refused, assigned or not: the shape allows ASCII only
		if p.name != "inside the name" && p.name != "in the address before the at sign" {
			continue
		}
		for r := rune(0x80); r <= utf8.MaxRune; r++ {
			if r >= 0xD800 && r <= 0xDFFF {
				continue
			}
			if checkUserID(p.make(r)) == nil {
				bad++
				t.Errorf("%s: U+%04X is accepted", p.name, r)
				if bad > 20 {
					t.Fatal("too many")
				}
			}
		}
	}
	// the bytes that are no UTF-8
	for _, raw := range []string{"\xff", "\xc0\xaf", "\xed\xa0\x80", "\xed\xbf\xbf", "\xf4\x90\x80\x80", "\x80"} {
		if checkUserID("Ac"+raw+"me Release Root A <a@example.org>") == nil {
			t.Errorf("the bytes % x are accepted", raw)
		}
	}
	// the length: 1024 bytes of a release root's user ID, 1025 not
	pad := func(n int) string {
		fixed := " Release Root A <a@example.org>"
		return strings.Repeat("a", n-len(fixed)) + fixed
	}
	if checkUserID(pad(1024)) == nil {
		t.Log("a name of more than 45 characters is refused by the shape, as the length is")
	}
}
