package openpgp

import (
	"errors"
	"strings"
	"testing"
)

// The two rules for the text of a user ID of a person's own key: a new one (checkPersonUserID: the
// character rules of a release root's user ID and no shape) and one that the key has already
// (checkExistingUserID: its exact bytes, whatever their shape).

func TestCheckPersonUserID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		ok   bool
	}{
		{"name and address", "Example Person <person@example.org>", true},
		{"a comment", "Example Person (work) <person@example.org>", true},
		{"no address", "Example Person", true},
		{"letters outside ASCII", "Zoë Müller-Łukasiewicz <zoe@example.org>", true},
		{"other scripts", "例 示 <person@example.org>", true},
		{"a release root's shape is allowed", "Example Release Root A <release@example.org>", true},
		{"as long as it may be", strings.Repeat("a", maxUserID), true},
		{"empty", "", false},
		{"one byte too long", strings.Repeat("a", maxUserID+1), false},
		{"not UTF-8", "Example \xff Person", false},
		{"a line break", "Example\nPerson", false},
		{"a tab", "Example\tPerson", false},
		{"a NUL", "Example\x00Person", false},
		{"an escape", "Example\x1bPerson", false},
		{"DEL", "Example\x7fPerson", false},
		{"a C1 control", "Example\u0085Person", false},
		{"a right-to-left mark", "Example\u200fPerson", false},
		{"a zero-width space", "Example\u200bPerson", false},
		{"a bidirectional override", "Example \u202eerson", false},
		{"a line separator", "Example\u2028Person", false},
		{"a no-break space", "Example\u00a0Person", false},
		{"a private-use character", "Example\ue000Person", false},
		{"a combining mark", "Zoe\u0308 Person", false},
		{"a noncharacter", "Example\ufdd0Person", false},
		{"a code point with no meaning", "Example\u0378Person", false},
	}
	for _, c := range cases {
		err := checkPersonUserID(c.id)
		if (err == nil) != c.ok {
			t.Errorf("%s: %q: error %v, want ok=%v", c.name, c.id, err, c.ok)
		}
		if err != nil && !isParams(err) {
			t.Errorf("%s: %v is not an ErrParams", c.name, err)
		}
	}
	// checkUserID still requires the shape, with the same character rules
	if checkUserID("Example Person <person@example.org>") == nil {
		t.Error("checkUserID takes a user ID that is not a release root's")
	}
	if checkUserID("Example Release Root A <release@example.org>") != nil {
		t.Error("checkUserID refuses a release root's user ID")
	}
}

func TestCheckExistingUserID(t *testing.T) {
	cases := []struct {
		name string
		text string
		ok   bool
	}{
		{"name and address", "Example Person <person@example.org>", true},
		{"a comment", "Example Person (the old one) <person@example.org>", true},
		{"no address", "Example Person", true},
		{"letters outside ASCII", "Zoë Müller-Łukasiewicz <zoe@example.org>", true},
		{"a decomposed accent", "Zoe\u0308 Person <zoe@example.org>", true},
		{"a no-break space", "Example\u00a0Person", true},
		{"a private-use character", "Example\ue000Person", true},
		{"as long as the reader reads", strings.Repeat("a", MaxForeignUserIDBytes), true},
		{"longer than the limit of a person's new one", strings.Repeat("a", maxUserID+1), true},
		{"empty", "", false},
		{"one byte past the limit of the reader", strings.Repeat("a", MaxForeignUserIDBytes+1), false},
		{"not UTF-8", "Example \xff Person", false},
		{"an overlong encoding", "Example \xc0\xaf Person", false},
		{"a line break", "Example\nPerson", false},
		{"a carriage return", "Example\rPerson", false},
		{"a NUL", "Example\x00Person", false},
		{"an escape", "Example\x1b[31mPerson", false},
		{"a C1 control", "Example\u009bPerson", false},
		{"a zero-width joiner", "Example\u200dPerson", false},
		{"a bidirectional isolate", "Example\u2066Person", false},
		{"a line separator", "Example\u2028Person", false},
		{"a paragraph separator", "Example\u2029Person", false},
	}
	for _, c := range cases {
		err := checkExistingUserID([]byte(c.text))
		if (err == nil) != c.ok {
			t.Errorf("%s: %q: error %v, want ok=%v", c.name, c.text, err, c.ok)
		}
		if err != nil && !isParams(err) {
			t.Errorf("%s: %v is not an ErrParams", c.name, err)
		}
	}
}

func isParams(err error) bool { return errors.Is(err, ErrParams) }
