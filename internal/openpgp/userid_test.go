package openpgp_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// The rules of the pages for the parts of the user ID (docs/reference/bundle.md, "The OpenPGP
// primary" and the keys `name` and `label` of ritueel.yaml):
//
//   - the name is 1 to 45 characters: the ASCII letters, the digits, single spaces and hyphens, with
//     no space at the start or the end;
//   - the label is one upper-case letter, A to Z, in ASCII;
//   - the user ID is "<name> Release Root <label> <release_address>", and a test root adds
//     " (TEST ONLY)" before the address.
//
// No page gives the characters of the address. The rule that the tests hold it to is the one of the
// task: printable ASCII with no space, no '<' and no '>', and exactly one '@'.

func userID(t testing.TB, name, label, address string, test bool) string {
	t.Helper()
	id, err := openpgp.UserID(name, label, address, test)
	if err != nil {
		t.Fatalf("UserID(%q, %q, %q, %v): %v", name, label, address, test, err)
	}
	return id
}

func TestTheUserIDOfATestRootIsTheOneOfTheVector(t *testing.T) {
	_, ps := vectorPrimary(t, "a")
	got := userID(t, "Example Test", "A", "release@example.org", true)
	want := "Example Test Release Root A (TEST ONLY) <release@example.org>"
	if got != want {
		t.Errorf("UserID = %q, want %q", got, want)
	}
	if string(ps[1].Body) != got {
		t.Errorf("the vector's user ID is %q, UserID gives %q", ps[1].Body, got)
	}
	if ps[1].Tag != tagUserID {
		t.Errorf("the second packet of the vector has tag %d", ps[1].Tag)
	}
}

func TestTheUserIDOfARealRootHasNoTestMark(t *testing.T) {
	got := userID(t, "Acme", "B", "release@example.org", false)
	if want := "Acme Release Root B <release@example.org>"; got != want {
		t.Errorf("UserID = %q, want %q", got, want)
	}
	if strings.Contains(got, "TEST") {
		t.Errorf("a real root's user ID names a test: %q", got)
	}
}

func TestTheTestMarkStandsBeforeTheAddress(t *testing.T) {
	got := userID(t, "Acme", "C", "a@example.org", true)
	if !strings.HasSuffix(got, " (TEST ONLY) <a@example.org>") {
		t.Errorf("UserID = %q, want the test mark before the address", got)
	}
}

func TestTheUserIDOfThePageExampleIsMadeFromItsParts(t *testing.T) {
	got := userID(t, "Example", "A", "release@example.com", false)
	if want := "Example Release Root A <release@example.com>"; got != want {
		t.Errorf("UserID = %q, want %q (the example of the page)", got, want)
	}
}

// refusedParts runs UserID on parts that the rules refuse: an ErrParams, and no text.
func refusedParts(t *testing.T, name, label, address string) {
	t.Helper()
	got, err := openpgp.UserID(name, label, address, false)
	if !errors.Is(err, openpgp.ErrParams) {
		t.Errorf("UserID(%q, %q, %q) error = %v, want one that wraps ErrParams", name, label, address, err)
	}
	if got != "" {
		t.Errorf("UserID(%q, %q, %q) = %q with an error, want no text", name, label, address, got)
	}
	got, err = openpgp.UserID(name, label, address, true)
	if !errors.Is(err, openpgp.ErrParams) || got != "" {
		t.Errorf("the same for a test root: %q, %v", got, err)
	}
}

func TestANameThatTheKeyNameOfThePageAllowsIsAccepted(t *testing.T) {
	for _, name := range []string{
		"A", "a", "0", "Example Test", "Acme", "Acme-Corp", "Acme Corp 2", "a-b", "a - b", "-", "--", "- -", "1234567890",
		"Zz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "x-1 y-2",
		strings.Repeat("a", 45), strings.Repeat("a-", 22) + "a",
	} {
		t.Run(name, func(t *testing.T) {
			got := userID(t, name, "A", "release@example.org", false)
			if want := name + " Release Root A <release@example.org>"; got != want {
				t.Errorf("UserID = %q, want %q", got, want)
			}
		})
	}
}

func TestANameThatTheKeyNameOfThePageRefusesIsRefused(t *testing.T) {
	cases := []struct{ name, v string }{
		{"empty", ""},
		{"46 characters", strings.Repeat("a", 46)},
		{"46 characters with spaces", strings.Repeat("a ", 22) + "ab"},
		{"100 characters", strings.Repeat("a", 100)},
		{"a space at the start", " Acme"},
		{"a space at the end", "Acme "},
		{"only a space", " "},
		{"two spaces in a row", "Acme  Corp"},
		{"three spaces in a row", "Acme   Corp"},
		{"a tab", "Acme\tCorp"},
		{"a line feed", "Acme\nCorp"},
		{"a line feed at the end", "Acme\n"},
		{"a carriage return", "Acme\rCorp"},
		{"a NUL", "Acme\x00"},
		{"an escape", "\x1b[31mAcme"},
		{"a delete character", "Acme\x7f"},
		{"a no-break space", "Acme\u00A0Corp"},
		{"an ideographic space", "Acme\u3000Corp"},
		{"a zero-width space", "Acme\u200BCorp"},
		{"the right-to-left override", "Acme\u202ECorp"},
		{"a byte order mark", "\uFEFFAcme"},
		{"a combining mark after a letter", "Acme\u0301"},
		{"a combining mark alone", "\u0301"},
		{"a variation selector", "Acme\uFE0F"},
		{"a code point with no assigned meaning (U+0378)", "Acme\u0378"},
		{"a private-use code point", "Acme\uE000"},
		{"a noncharacter", "Acme\uFDD0"},
		{"bytes that are not UTF-8", "Acme\xff"},
		{"a letter with an accent", "Acm\u00E9"},
		{"a Polish letter", "Za\u017C\u00F3\u0142\u0107"},
		{"a Cyrillic letter that looks like a Latin one", "Acme\u0430"},
		{"a Greek letter", "Acme\u03B1"},
		{"a full-width letter", "\uFF21cme"},
		{"an emoji", "Acme \U0001F600"},
		{"a digit of another script", "Acme\u0663"},
		{"an underscore", "Acme_Corp"},
		{"a dot", "Acme.Corp"},
		{"a comma", "Acme,Corp"},
		{"an at sign", "acme@corp"},
		{"an ampersand", "Acme&Corp"},
		{"an apostrophe", "Acme's"},
		{"a parenthesis", "Acme (TEST ONLY)"},
		{"an opening angle bracket", "Acme<Corp"},
		{"a closing angle bracket", "Acme>Corp"},
		{"both angle brackets and an address", "x <a@b> Release Root B"},
		{"an angle bracket at the start", "<Acme"},
		{"a closing angle bracket at the end", "Acme>"},
		{"a slash", "Acme/Corp"},
		{"a colon", "Acme:Corp"},
		{"a plus sign", "Acme+Corp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { refusedParts(t, c.v, "A", "release@example.org") })
	}
}

func TestTheNameEdgeOfFortyFiveCharactersHoldsWhateverTheCharacters(t *testing.T) {
	// The edge is counted in characters of the name and does not depend on which ones: 45 of each kind
	// of allowed character is accepted and 46 is refused.
	for _, name := range []string{
		strings.Repeat("a", 45), strings.Repeat("Z", 45), strings.Repeat("7", 45), strings.Repeat("-", 45), strings.Repeat("a ", 22) + "a",
	} {
		if len(name) != 45 {
			t.Fatalf("the test builds %d characters", len(name))
		}
		if got := userID(t, name, "A", "release@example.org", false); !strings.HasPrefix(got, name+" Release Root A <") {
			t.Errorf("a name of 45 characters: %q", got)
		}
		refusedParts(t, name+"b", "A", "release@example.org")
	}
}

func TestEveryLetterFromAToZIsALabel(t *testing.T) {
	for l := 'A'; l <= 'Z'; l++ {
		got := userID(t, "Acme", string(l), "release@example.org", false)
		if want := fmt.Sprintf("Acme Release Root %c <release@example.org>", l); got != want {
			t.Errorf("UserID = %q, want %q", got, want)
		}
	}
}

func TestALabelThatIsNotOneUpperCaseAsciiLetterIsRefused(t *testing.T) {
	cases := []struct{ name, v string }{
		{"empty", ""},
		{"a lower-case letter", "a"},
		{"the letter before A (@)", "@"},
		{"the letter after Z ([)", "["},
		{"a backtick", "`"},
		{"two letters", "AB"},
		{"a letter and a space", "A "},
		{"a space and a letter", " A"},
		{"a space", " "},
		{"a digit", "1"},
		{"a hyphen", "-"},
		{"an opening angle bracket", "<"},
		{"a closing angle bracket", ">"},
		{"a letter and an angle bracket", "A>"},
		{"a letter with an accent", "\u00C1"},
		{"a Cyrillic letter that looks like A", "\u0410"},
		{"a Greek letter", "\u0391"},
		{"a full-width letter", "\uFF21"},
		{"a letter and a combining mark", "A\u0301"},
		{"a line feed", "\n"},
		{"a letter and a line feed", "A\n"},
		{"a NUL", "\x00"},
		{"a letter and the test mark", "A (TEST ONLY)"},
		{"bytes that are not UTF-8", "\xff"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { refusedParts(t, "Acme", c.v, "release@example.org") })
	}
}

func TestAnAddressOfPrintableAsciiWithOneAtSignIsAccepted(t *testing.T) {
	for _, address := range []string{
		"release@example.org", "a@b", "first.last@example.org", "first.last+tag@example.org", "a-b_c@sub.example.org",
		"!@~", "~@!", "#$%&'*+/=?^_`{|}~-@x.y", "\"quoted\"@example.org", "(a);:,[]\\@example.org", "Ab@cd",
		"release@example.org" + strings.Repeat("o", 100),
	} {
		t.Run(address, func(t *testing.T) {
			got := userID(t, "Acme", "A", address, false)
			if want := "Acme Release Root A <" + address + ">"; got != want {
				t.Errorf("UserID = %q, want %q", got, want)
			}
		})
	}
}

func TestAnAddressThatIsNotPrintableAsciiWithOneAtSignIsRefused(t *testing.T) {
	cases := []struct{ name, v string }{
		{"empty", ""},
		{"no at sign", "release.example.org"},
		{"only an at sign", "@"},
		{"two at signs", "a@b@c"},
		{"two at signs in a row", "a@@b"},
		{"three at signs", "a@b@c@d"},
		{"nothing before the at sign", "@example.org"},
		{"nothing after the at sign", "release@"},
		{"a space", "rel ease@example.org"},
		{"a space at the start", " release@example.org"},
		{"a space at the end", "release@example.org "},
		{"a space after the at sign", "release@ example.org"},
		{"a tab", "rel\tease@example.org"},
		{"a line feed", "release@example.org\n"},
		{"a line feed inside", "rel\nease@example.org"},
		{"a carriage return", "release@example.org\r"},
		{"a NUL", "release@example.org\x00"},
		{"an escape", "rel\x1bease@example.org"},
		{"a control character, 0x1F", "rel\x1fease@example.org"},
		{"a delete character, 0x7F", "rel\x7fease@example.org"},
		{"an opening angle bracket", "rel<ease@example.org"},
		{"a closing angle bracket", "rel>ease@example.org"},
		{"a closing angle bracket at the end", "release@example.org>"},
		{"an opening angle bracket at the start", "<release@example.org"},
		{"an address in angle brackets", "<release@example.org>"},
		{"both brackets and a second address", "a@b> Release Root B <c@d"},
		{"a letter with an accent", "rel\u00E9@example.org"},
		{"a non-ASCII domain", "release@ex\u00E4mple.org"},
		{"a Cyrillic letter", "rel\u0435ase@example.org"},
		{"an ideographic space", "rel\u3000ease@example.org"},
		{"a no-break space", "rel\u00A0ease@example.org"},
		{"a zero-width space", "rel\u200Bease@example.org"},
		{"the right-to-left override", "rel\u202Eease@example.org"},
		{"a combining mark", "rele\u0301ase@example.org"},
		{"a code point with no assigned meaning (U+0378)", "rel\u0378ease@example.org"},
		{"a private-use code point", "rel\uE000ease@example.org"},
		{"a noncharacter", "rel\uFDD0ease@example.org"},
		{"an emoji", "release@example.org\U0001F600"},
		{"bytes that are not UTF-8", "rel\xffease@example.org"},
		{"an at sign that is full-width and a real one", "a\uFF20b@c"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { refusedParts(t, "Acme", "A", c.v) })
	}
}

// The edges of the printable range for the address: 0x21 and 0x7E are in, 0x20 and 0x7F are out.
func TestTheAddressRangeOfPrintableAsciiEndsAtTheTwoEdges(t *testing.T) {
	for c := 0x00; c <= 0xFF; c++ {
		if c == '@' {
			continue
		}
		address := "a" + string(rune(c)) + "@b"
		if c >= 0x80 {
			address = "a" + string([]byte{byte(c)}) + "@b"
		}
		ok := c >= 0x21 && c <= 0x7E && c != '<' && c != '>'
		_, err := openpgp.UserID("Acme", "A", address, false)
		if ok != (err == nil) {
			t.Errorf("an address with the byte %#02x: error %v, accepted = %v", c, err, ok)
		}
	}
}

// What UserID makes, NewPrimary and ExtendPrimary take; and what the doc of UserID says: its text is
// accepted by them.
func TestWhatUserIDMakesNewPrimaryAndExtendPrimaryAccept(t *testing.T) {
	cases := []struct {
		name, label, address string
		test                 bool
	}{
		{"Example Test", "A", "release@example.org", true},
		{"Acme", "B", "a@b", false},
		{"A", "Z", "!@~", true},
		{strings.Repeat("a", 45), "M", "release@example.org", false},
		{"Release Root", "A", "a@b", false},
		{"Acme Release Root", "A", "a@b", true},
		{"Zz Release Root Q", "A", "a@b", false},
		{"-", "A", "a@b", false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s %s %v", c.name, c.label, c.test), func(t *testing.T) {
			id := userID(t, c.name, c.label, c.address, c.test)
			s := newSigner(t)
			p := s.params()
			p.UserID = id
			cert, err := openpgp.NewPrimary(nil, p)
			if err != nil {
				t.Fatalf("NewPrimary: %v", err)
			}
			if got := string(splitPackets(t, cert)[1].Body); got != id {
				t.Errorf("the user ID packet holds %q, want %q", got, id)
			}
			if _, err := openpgp.ExtendPrimary(nil, p); err != nil {
				t.Errorf("ExtendPrimary: %v", err)
			}
		})
	}
}

// The doc of UserID: "The text that comes out is accepted by NewPrimary and ExtendPrimary". A user
// ID has at most 1024 bytes there, so an address that makes it longer has to be refused by UserID.
func TestWhatUserIDMakesIsNeverLongerThanNewPrimaryAccepts(t *testing.T) {
	for _, test := range []bool{false, true} {
		for _, over := range []int{0, 1, 2, 100} {
			t.Run(fmt.Sprintf("test %v, %d over", test, over), func(t *testing.T) {
				base := len(userID(t, "A", "A", "a@b", test))
				address := strings.Repeat("a", 1024-base+over) + "a@b"
				id, err := openpgp.UserID("A", "A", address, test)
				if err != nil {
					if over == 0 {
						t.Fatalf("a user ID of exactly 1024 bytes is refused: %v", err)
					}
					if !errors.Is(err, openpgp.ErrParams) || id != "" {
						t.Errorf("UserID = %q, %v, want an ErrParams and no text", id, err)
					}
					return
				}
				s := newSigner(t)
				p := s.params()
				p.UserID = id
				if _, err := openpgp.NewPrimary(nil, p); err != nil {
					t.Errorf("UserID made a text of %d bytes that NewPrimary refuses: %v", len(id), err)
				}
			})
		}
	}
}

// What NewPrimary and ExtendPrimary refuse, and return no bytes for: a user ID that is not exactly
// the form of the page, whatever it holds, and one with a part that breaks the rules of that part.
func TestAUserIDThatIsNotOfThePageFormIsRefusedWithoutAskingTheSigner(t *testing.T) {
	cases := []struct{ name, id string }{
		{"nothing at all", ""},
		{"only a space", " "},
		{"a name alone", "Acme"},
		{"a name and an address", "Acme <a@example.org>"},
		{"a person's name and an address", "Example Person <o@example.org>"},
		{"no address", "Acme Release Root A"},
		{"no label", "Acme Release Root <a@example.org>"},
		{"no name", "Release Root A <a@example.org>"},
		{"no name and a space", " Release Root A <a@example.org>"},
		{"an empty label", "Acme Release Root  <a@example.org>"},
		{"two letters as the label", "Acme Release Root AB <a@example.org>"},
		{"a lower-case label", "Acme Release Root a <a@example.org>"},
		{"a digit as the label", "Acme Release Root 1 <a@example.org>"},
		{"the label and the test mark in the wrong order", "Acme Release Root (TEST ONLY) A <a@example.org>"},
		{"the test mark in lower case", "Acme Release Root A (test only) <a@example.org>"},
		{"the test mark twice", "Acme Release Root A (TEST ONLY) (TEST ONLY) <a@example.org>"},
		{"the test mark with no space before the address", "Acme Release Root A (TEST ONLY)<a@example.org>"},
		{"the test mark with two spaces", "Acme Release Root A  (TEST ONLY) <a@example.org>"},
		{"the test mark and no space before it", "Acme Release Root A(TEST ONLY) <a@example.org>"},
		{"two spaces before the address", "Acme Release Root A  <a@example.org>"},
		{"no space before the address", "Acme Release Root A<a@example.org>"},
		{"two spaces before the label", "Acme Release Root  A <a@example.org>"},
		{"two spaces in the name", "Acme  Corp Release Root A <a@example.org>"},
		{"the words in lower case", "Acme release root A <a@example.org>"},
		{"another word for the root", "Acme Release Key A <a@example.org>"},
		{"a word after the address", "Acme Release Root A <a@example.org> x"},
		{"a word before the name", "x <y> Acme Release Root A <a@example.org>"},
		{"a name that holds an address", "x <a@b> Release Root A <c@d>"},
		{"a name that holds an address and a label", "x <a@b> Release Root B Release Root A <c@d>"},
		{"a name that ends with an opening angle bracket", "Acme < Release Root A <a@example.org>"},
		{"a name that holds an angle bracket", "Ac<me Release Root A <a@example.org>"},
		{"a name that holds a closing angle bracket", "Ac>me Release Root A <a@example.org>"},
		{"an address with two angle brackets in front", "Acme Release Root A <<a@example.org>"},
		{"an address with two angle brackets behind", "Acme Release Root A <a@example.org>>"},
		{"an address with no closing bracket", "Acme Release Root A <a@example.org"},
		{"an address with no opening bracket", "Acme Release Root A a@example.org>"},
		{"an empty address", "Acme Release Root A <>"},
		{"an address with two at signs", "Acme Release Root A <a@b@example.org>"},
		{"an address with no at sign", "Acme Release Root A <example.org>"},
		{"an address with a space", "Acme Release Root A <a b@example.org>"},
		{"an address with only an at sign", "Acme Release Root A <@>"},
		{"an address with nothing before the at sign", "Acme Release Root A <@example.org>"},
		{"an address with nothing after the at sign", "Acme Release Root A <a@>"},
		{"an address with an angle bracket inside", "Acme Release Root A <a<b@example.org>"},
		{"a name of 46 characters", strings.Repeat("a", 46) + " Release Root A <a@example.org>"},
		{"a name with a space at the start", " Acme Release Root A <a@example.org>"},
		{"a name with a letter of another script", "Acm\u00E9 Release Root A <a@example.org>"},
		{"a name with a combining mark", "Acme\u0301 Release Root A <a@example.org>"},
		{"a name with a code point with no assigned meaning", "Acme\u0378 Release Root A <a@example.org>"},
		{"a name with a Cyrillic letter", "Acm\u0435 Release Root A <a@example.org>"},
		{"a name with a tab", "Acme\tCorp Release Root A <a@example.org>"},
		{"an address with a combining mark", "Acme Release Root A <a@example\u0301.org>"},
		{"a label that is a Cyrillic letter", "Acme Release Root \u0410 <a@example.org>"},
		{"a line feed", "Acme Release Root A <a@example.org>\nExtra"},
		{"a line feed at the end", "Acme Release Root A <a@example.org>\n"},
		{"a carriage return", "Acme Release Root A\r <a@example.org>"},
		{"a carriage return and a line feed", "Acme\r\nRelease Root A <a@example.org>"},
		{"a NUL", "Acme Release Root A <a@example.org>\x00"},
		{"an escape", "Acme \x1b[31mRelease Root A <a@example.org>"},
		{"a tab", "Acme\tRelease Root A <a@example.org>"},
		{"a delete character", "Acme Release\x7f Root A <a@example.org>"},
		{"a control character of the second block (next line, U+0085)", "Acme Release Root A <a@example.org>\u0085x"},
		{"the right-to-left override", "Acme Release Root A \u202E<a@example.org>"},
		{"a zero-width space", "Acme Release Root \u200BA <a@example.org>"},
		{"a byte order mark", "\uFEFFAcme Release Root A <a@example.org>"},
		{"a line separator", "Acme Release Root A\u2028<a@example.org>"},
		{"a paragraph separator", "Acme Release Root A\u2029<a@example.org>"},
		{"a no-break space", "Acme Release Root\u00A0A <a@example.org>"},
		{"an ideographic space", "Acme Release Root\u3000A <a@example.org>"},
		{"a private-use code point", "Acme Release Root \uE000 <a@example.org>"},
		{"a noncharacter", "Acme Release Root \uFDD0 <a@example.org>"},
		{"a noncharacter of another plane (U+1FFFE)", "Acme Release Root \U0001fffe <a@example.org>"},
		{"the last code point (U+10FFFF)", "Acme Release Root \U0010ffff <a@example.org>"},
		{"the noncharacter U+FFFF", "Acme Release Root \uFFFF <a@example.org>"},
		{"a lone surrogate written as UTF-8", "Acme Release Root \xed\xa0\x80 <a@example.org>"},
		{"bytes that are not UTF-8", "Acme Release Root \xff <a@example.org>"},
		{"a space at the start", " Acme Release Root A <a@example.org>"},
		{"a space at the end", "Acme Release Root A <a@example.org> "},
		{"1025 bytes of letters", strings.Repeat("a", 1025)},
		{"a user ID of 1025 bytes of the right form", "A Release Root A <" + strings.Repeat("a", 1025-len("A Release Root A <")-len("@b>")) + "@b>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSigner(t)
			p := s.params()
			p.UserID = c.id
			assertRefused(t, "NewPrimary", func() ([]byte, error) { return openpgp.NewPrimary(nil, p) }, openpgp.ErrParams)
			assertRefused(t, "ExtendPrimary", func() ([]byte, error) { return openpgp.ExtendPrimary(nil, p) }, openpgp.ErrParams)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times for a user ID that is refused", s.calls)
			}
		})
	}
}

func TestTheUserIDOfAPrimaryHasAtMostOneKilobyteOfTheRightForm(t *testing.T) {
	for _, n := range []int{22, 100, 189, 190, 191, 192, 193, 255, 256, 1023, 1024} {
		id := userIDOfLength(n)
		if len(id) != n {
			t.Fatalf("the test builds %d bytes, not %d", len(id), n)
		}
		s := newSigner(t)
		p := s.params()
		p.UserID = id
		cert, err := openpgp.NewPrimary(nil, p)
		if err != nil || len(cert) == 0 {
			t.Errorf("a user ID of %d bytes: %v", n, err)
		}
		if _, err := openpgp.ExtendPrimary(nil, p); err != nil {
			t.Errorf("ExtendPrimary with a user ID of %d bytes: %v", n, err)
		}
	}
}

// userIDOfLength is a user ID of the page's form of n bytes (n of 22 or more): a real root's, with a
// long address.
func userIDOfLength(n int) string {
	const head, tail = "A Release Root A <", "@b>"
	return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
}

// The packet of a user ID has the length form of its size: the sizes either side of 192, where the
// one-octet form ends.
func TestAUserIDHasTheLengthFormOfItsSizeAtTheEdgesOfTheForms(t *testing.T) {
	for _, n := range []int{22, 100, 190, 191, 192, 193, 255, 256, 1024} {
		s := newSigner(t)
		p := s.params()
		p.UserID = userIDOfLength(n)
		cert, err := openpgp.NewPrimary(nil, p)
		if err != nil {
			t.Fatalf("a user ID of %d bytes: %v", n, err)
		}
		ps := splitPackets(t, cert)
		if got := tags(ps); !bytes.Equal(got, []byte{tagPublicKey, tagUserID, tagSignature}) || string(ps[1].Body) != p.UserID {
			t.Errorf("a user ID of %d bytes: tags % d, body of %d bytes", n, got, len(ps[1].Body))
		}
		wantHeader := 2
		if n >= 192 {
			wantHeader = 3
		}
		if ps[1].HeaderLen != wantHeader {
			t.Errorf("a user ID of %d bytes has a header of %d bytes, want %d", n, ps[1].HeaderLen, wantHeader)
		}
	}
}
