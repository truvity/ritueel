package openpgp

import "testing"

// isAssigned is what the rule that a user ID holds no code point with no meaning stands on. The shape of a
// release root's user ID refuses every code point beyond ASCII, so no answer of checkUserID shows it: the
// function is held on its own.
func TestQAIsAssigned(t *testing.T) {
	for _, c := range []struct {
		r    rune
		want bool
		what string
	}{
		{'A', true, "a letter"}, {'5', true, "a digit"}, {'-', true, "a punctuation mark"}, {'$', true, "a symbol"},
		{' ', true, "a space"}, {0x00e9, true, "a letter with an accent"}, {0x0301, true, "a combining mark"},
		{0x4e00, true, "a Han character"}, {0x1f600, true, "an emoji"},
		{0x0000, true, "a control"}, {0x200b, true, "a format character"}, {0xe000, true, "a private-use code point"},
		{0xf0000, true, "a private-use code point of a plane"}, {0xd800, true, "a surrogate"},
		{0x0378, false, "a hole of the Greek block"}, {0x0380, false, "another hole"}, {0x2fe0, false, "a hole after the radicals"},
		{0xfdd0, false, "a noncharacter"}, {0xfffe, false, "a noncharacter at the end of a plane"},
		{0x1fffe, false, "a noncharacter of plane 1"}, {0x10ffff, false, "the last code point"},
		{0xe0080, false, "a hole in the tags plane"}, {0x35000, false, "a hole in plane 3"},
	} {
		if got := isAssigned(c.r); got != c.want {
			t.Errorf("U+%04X (%s): isAssigned is %v, want %v", c.r, c.what, got, c.want)
		}
	}
}
