package wanted_test

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// The wanted card file (docs/reference/cards.md, "The card file"; record 0003, rules 5, 10 and 11; record 0006,
// rule 5). One strict YAML file for each card, want/cards/NAME.yaml, with version 1, a serial, a kind, the
// applications that the bundle uses and, optionally, the rows of other bundles. The names of this file start with
// card.

// The five card files of a good set. Each is accepted.
const (
	cardRootA = `version: 1
serial: "10000001"
kind: root
applications: [piv, fido2]
other_rows: [3]
`
	cardRootB = `version: 1
serial: "10000002"
kind: root
applications: [piv, fido2]
`
	cardDayOne = `version: 1
serial: "10000003"
kind: day-to-day
applications: [openpgp, fido2]
`
	cardServerOne = `version: 1
serial: "10000004"
kind: server
applications: [piv]
`
	cardPracticeOne = `version: 1
serial: "10000005"
kind: rehearsal
applications: [piv]
`
	// cardPageExample is the example of the page.
	cardPageExample = `version: 1
serial: "00000000"
kind: root
applications: [piv]
`
)

// cardPath is the path that the errors of a card file carry.
func cardPath(name string) string { return "want/cards/" + name + ".yaml" }

// mustCard parses a card file and fails the test when the reader refuses it or returns a card that is not valid.
func mustCard(t testing.TB, name, text string) *wanted.Card {
	t.Helper()
	c, err := wanted.ParseCard(name, []byte(text))
	if err != nil {
		t.Fatalf("the reader refuses a card file that must be accepted: %v\n%s", err, text)
	}
	if c == nil || !c.Valid() {
		t.Fatalf("no error, and the card is %+v", c)
	}
	return c
}

// refuseCard parses a card file as the card "root-a", checks that the reader returns an error and no card, and
// checks the fault as wantFault does.
func refuseCard(t testing.TB, text string, line int, words ...string) *wanted.Error {
	t.Helper()
	c, err := wanted.ParseCard("root-a", []byte(text))
	if c != nil {
		t.Errorf("a card beside the error %v", err)
	}
	return wantFault(t, err, cardPath("root-a"), line, words...)
}

func TestParseCardAcceptsTheGoodFiles(t *testing.T) {
	rows := []struct {
		name  string
		text  string
		kind  wanted.CardKind
		ser   string
		apps  []wanted.Application
		other []int
	}{
		{"root-a", cardRootA, wanted.CardRoot, "10000001", []wanted.Application{wanted.AppPIV, wanted.AppFIDO2}, []int{3}},
		{"root-b", cardRootB, wanted.CardRoot, "10000002", []wanted.Application{wanted.AppPIV, wanted.AppFIDO2}, nil},
		{"day-one", cardDayOne, wanted.CardDayToDay, "10000003", []wanted.Application{wanted.AppOpenPGP, wanted.AppFIDO2}, nil},
		{"server-one", cardServerOne, wanted.CardServer, "10000004", []wanted.Application{wanted.AppPIV}, nil},
		{"practice-one", cardPracticeOne, wanted.CardRehearsal, "10000005", []wanted.Application{wanted.AppPIV}, nil},
		{"the-page-example", cardPageExample, wanted.CardRoot, "00000000", []wanted.Application{wanted.AppPIV}, nil},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			data := []byte(r.text)
			c, err := wanted.ParseCard(r.name, data)
			if err != nil {
				t.Fatalf("ParseCard: %v", err)
			}
			if !c.Valid() {
				t.Error("Valid() is false for a card the reader made")
			}
			if c.Name != r.name || c.Serial != r.ser || c.Kind != r.kind {
				t.Errorf("name %q serial %q kind %q", c.Name, c.Serial, c.Kind)
			}
			if !slices.Equal(c.Applications, r.apps) {
				t.Errorf("applications %v, want %v", c.Applications, r.apps)
			}
			if !slices.Equal(c.OtherRows, r.other) {
				t.Errorf("other rows %v, want %v", c.OtherRows, r.other)
			}
			if c.File.Path != cardPath(r.name) {
				t.Errorf("path %q", c.File.Path)
			}
			if string(c.File.Data) != r.text || c.File.SHA256 != sha256hex(data) {
				t.Error("the bytes or the digest of the file are not the input's")
			}
			// The card keeps its own copy of the bytes: a changed input slice changes nothing.
			data[0] ^= 0xff
			if string(c.File.Data) != r.text {
				t.Error("File.Data shares memory with the input")
			}
			// And in the other direction.
			c.File.Data[0] ^= 0xff
			if data[0] == r.text[0] {
				t.Error("the input shares memory with File.Data")
			}
		})
	}
}

func TestParseCardKeepsTheOrderAndTheValuesAsWritten(t *testing.T) {
	const head = "version: 1\nserial: \"10000001\"\nkind: root\n"
	rows := []struct {
		name   string
		text   string
		apps   []wanted.Application
		other  []int
		serial string
	}{
		{"applications in another order", head + "applications: [fido2, piv]\n", []wanted.Application{wanted.AppFIDO2, wanted.AppPIV}, nil, "10000001"},
		{"all three applications", head + "applications: [openpgp, fido2, piv]\n", []wanted.Application{wanted.AppOpenPGP, wanted.AppFIDO2, wanted.AppPIV}, nil, "10000001"},
		{"applications as a block list", head + "applications:\n  - fido2\n  - piv\n", []wanted.Application{wanted.AppFIDO2, wanted.AppPIV}, nil, "10000001"},
		{"rows in another order", head + "applications: [piv]\nother_rows: [4, 2]\n", []wanted.Application{wanted.AppPIV}, []int{4, 2}, "10000001"},
		{"all five rows", head + "applications: [piv]\nother_rows: [2, 3, 4, 5, 6]\n", []wanted.Application{wanted.AppPIV}, []int{2, 3, 4, 5, 6}, "10000001"},
		{"rows in reverse", head + "applications: [piv]\nother_rows: [6, 5, 4, 3, 2]\n", []wanted.Application{wanted.AppPIV}, []int{6, 5, 4, 3, 2}, "10000001"},
		{"rows as a block list", head + "applications: [piv]\nother_rows:\n  - 6\n  - 2\n", []wanted.Application{wanted.AppPIV}, []int{6, 2}, "10000001"},
		{"an empty list of rows", head + "applications: [piv]\nother_rows: []\n", []wanted.Application{wanted.AppPIV}, nil, "10000001"},
		{"an empty list of rows without piv", head + "applications: [fido2]\nother_rows: []\n", []wanted.Application{wanted.AppFIDO2}, nil, "10000001"},
		{"a serial of one digit", "version: 1\nserial: \"7\"\nkind: root\napplications: [piv]\n", []wanted.Application{wanted.AppPIV}, nil, "7"},
		{"a serial of ten digits", "version: 1\nserial: \"1234567890\"\nkind: root\napplications: [piv]\n", []wanted.Application{wanted.AppPIV}, nil, "1234567890"},
		{"a serial of leading zeros", "version: 1\nserial: \"0000000001\"\nkind: root\napplications: [piv]\n", []wanted.Application{wanted.AppPIV}, nil, "0000000001"},
		{"a serial of one zero", "version: 1\nserial: \"0\"\nkind: root\napplications: [piv]\n", []wanted.Application{wanted.AppPIV}, nil, "0"},
		{"a single-quoted serial", "version: 1\nserial: '10000001'\nkind: root\napplications: [piv]\n", []wanted.Application{wanted.AppPIV}, nil, "10000001"},
		{"members in another order", "applications: [piv]\nkind: root\nserial: \"10000001\"\nversion: 1\n", []wanted.Application{wanted.AppPIV}, nil, "10000001"},
		{"a flow mapping as the root", "{version: 1, serial: \"10000001\", kind: root, applications: [piv], other_rows: [2]}\n", []wanted.Application{wanted.AppPIV}, []int{2}, "10000001"},
		{"quoted keys", "\"version\": 1\n'serial': \"10000001\"\n\"kind\": root\napplications: [piv]\n", []wanted.Application{wanted.AppPIV}, nil, "10000001"},
		{"a comment before and after the members", "# a card\nversion: 1 # one\n# note\nserial: \"10000001\" # the serial\nkind: root\napplications: [piv]\n# end\n", []wanted.Application{wanted.AppPIV}, nil, "10000001"},
		{"a first line of three hyphens", "---\n" + cardServerOne, []wanted.Application{wanted.AppPIV}, nil, "10000004"},
		{"a marker with a comment", "--- # the card\n" + cardServerOne, []wanted.Application{wanted.AppPIV}, nil, "10000004"},
		{"no final line feed", strings.TrimSuffix(cardServerOne, "\n"), []wanted.Application{wanted.AppPIV}, nil, "10000004"},
		{"blank lines", "\n\n" + strings.Replace(cardServerOne, "kind", "\nkind", 1), []wanted.Application{wanted.AppPIV}, nil, "10000004"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			c := mustCard(t, "card-name", r.text)
			if !slices.Equal(c.Applications, r.apps) {
				t.Errorf("applications %v, want %v", c.Applications, r.apps)
			}
			if !slices.Equal(c.OtherRows, r.other) {
				t.Errorf("other rows %v, want %v", c.OtherRows, r.other)
			}
			if c.Serial != r.serial {
				t.Errorf("serial %q, want %q", c.Serial, r.serial)
			}
			if r.other == nil && c.OtherRows != nil {
				t.Errorf("an absent or empty list of rows gives %#v, want nil", c.OtherRows)
			}
		})
	}
}

// Every kind that the page lists is read.
func TestParseCardReadsEveryKindOfThePage(t *testing.T) {
	for kind, want := range map[string]wanted.CardKind{
		"root": wanted.CardRoot, "day-to-day": wanted.CardDayToDay, "server": wanted.CardServer, "rehearsal": wanted.CardRehearsal,
	} {
		c := mustCard(t, "k", "version: 1\nserial: \"1\"\nkind: "+kind+"\napplications: [piv]\n")
		if c.Kind != want || string(c.Kind) != kind {
			t.Errorf("kind %s gives %q", kind, c.Kind)
		}
	}
	// The constants are the words of record 0003, rule 11.
	if wanted.CardRoot != "root" || wanted.CardDayToDay != "day-to-day" || wanted.CardServer != "server" || wanted.CardRehearsal != "rehearsal" {
		t.Error("a kind constant is not the word of the page")
	}
	if wanted.AppPIV != "piv" || wanted.AppOpenPGP != "openpgp" || wanted.AppFIDO2 != "fido2" {
		t.Error("an application constant is not the word of the page")
	}
}

// The limits of the page and the code stand where they are named.
func TestTheLimitsOfACardFile(t *testing.T) {
	if wanted.MaxFiles != 1000 {
		t.Errorf("MaxFiles = %d: the folder of the card files is listed up to the limit of the other wanted folders", wanted.MaxFiles)
	}
	if wanted.CardsDir != "want/cards" {
		t.Errorf("CardsDir = %q", wanted.CardsDir)
	}
	if wanted.MaxCards != 64 || wanted.MaxSerialDigits != 10 || wanted.MaxApplications != 3 {
		t.Errorf("MaxCards %d, MaxSerialDigits %d, MaxApplications %d", wanted.MaxCards, wanted.MaxSerialDigits, wanted.MaxApplications)
	}
	// Row 1 is the card's own jobs (record 0003, rule 3): a bundle holds rows 2 to 6, five rows.
	if wanted.FirstBundleRow != 2 || wanted.LastRow != 6 || wanted.MaxOtherRows != 5 {
		t.Errorf("rows %d to %d, at most %d", wanted.FirstBundleRow, wanted.LastRow, wanted.MaxOtherRows)
	}
}

func TestParseCardAtTheLimitOfTheSizeOfAFile(t *testing.T) {
	pad := func(n int) string {
		// A comment line of n bytes in all, including its line feed.
		return "#" + strings.Repeat("x", n-2) + "\n"
	}
	exact := cardServerOne + pad(wanted.MaxBytes-len(cardServerOne))
	if len(exact) != wanted.MaxBytes {
		t.Fatalf("the test file is %d bytes", len(exact))
	}
	c := mustCard(t, "big", exact)
	if len(c.File.Data) != wanted.MaxBytes {
		t.Errorf("File.Data is %d bytes", len(c.File.Data))
	}
	over := cardServerOne + pad(wanted.MaxBytes-len(cardServerOne)+1)
	e := wantFault(t, parseErr(over), "want/cards/root-a.yaml", 0, "longer than")
	if e.Unwrap() != nil {
		t.Errorf("the fault of a file over the limit has a cause: %v", e.Unwrap())
	}
}

// parseErr parses text as the card "root-a" and returns the error, failing the test when a card is returned.
func parseErr(text string) error {
	c, err := wanted.ParseCard("root-a", []byte(text))
	if c != nil {
		return nil
	}
	return err
}

func TestParseCardNamesTheFileInEveryFault(t *testing.T) {
	// The name of the card is the name of the file, and the path of an error is the path of that file.
	_, err := wanted.ParseCard("day-one", []byte(strings.Replace(cardDayOne, "version: 1", "version: 2", 1)))
	_ = wantFault(t, err, "want/cards/day-one.yaml", 1, "version must be 1")
}

func TestParseCardRefusesANameThatIsNotTheNameOfAFile(t *testing.T) {
	long := strings.Repeat("a", 64)
	for _, name := range []string{
		"", "Root-A", "ROOT", "a.b", "a/b", "../x", "/", "a\\b", ".", "..", ".rt-abc", ".rt-k3j9x0a1b2c", "-a", "a b", " a", "a ", "root_a",
		"root-a.yaml", "root-a.yml", "a\x00b", "a\nb", "a\x1bb", "a\xffb", "a\u202eb", "\u00e9", "a:b", "a*", long, strings.Repeat("a", 5000),
	} {
		t.Run(shortName(name), func(t *testing.T) {
			c, err := wanted.ParseCard(name, []byte(cardServerOne))
			if c != nil {
				t.Errorf("a card for the name %q", name)
			}
			e := wantFault(t, err, "", 0)
			if !printable(e.Error()) {
				t.Errorf("the text of the error is not printable: %+q", e.Error())
			}
			// The path carries the name that the caller gave, escaped: a name of 5,000 characters is the caller's.
			if len(e.Error()) > len(name)*6+400 {
				t.Errorf("the error is %d bytes for a name of %d", len(e.Error()), len(name))
			}
			// The name is checked before the bytes: bytes that fail too give the same refusal.
			c2, err2 := wanted.ParseCard(name, []byte("not: [valid"))
			if c2 != nil || err2 == nil || err2.Error() != err.Error() {
				t.Errorf("a bad name and bad bytes: %v / %v", err, err2)
			}
		})
	}
	// The negative control: a name at its limits is accepted.
	for _, name := range []string{"a", "0", "0day", "root-a", "a-", "a--b", strings.Repeat("a", 63), strings.Repeat("9", 63)} {
		mustCard(t, name, cardServerOne)
	}
}

// shortName makes a name for a sub-test out of a hostile text.
func shortName(s string) string {
	if s == "" {
		return "empty"
	}
	if len(s) > 20 {
		s = s[:20]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e || r == '/' {
			return '_'
		}
		return r
	}, s)
}

func TestSerialKey(t *testing.T) {
	rows := []struct{ serial, key string }{
		{"0123", "123"}, {"123", "123"}, {"00000123", "123"}, {"0", "0"}, {"00", "0"}, {"0000", "0"}, {"0000000000", "0"},
		{"1", "1"}, {"10", "10"}, {"1000000000", "1000000000"}, {"1234567890", "1234567890"}, {"9999999999", "9999999999"},
		{"0000000001", "1"}, {"0123456789", "123456789"}, {"10000001", "10000001"}, {"10000010", "10000010"},
		// What is not 1 to 10 digits gives no key.
		{"", ""}, {"12345678901", ""}, {"00000000000", ""}, {strings.Repeat("1", 10000), ""}, {strings.Repeat("0", 11), ""},
		{"a", ""}, {"12a", ""}, {"a12", ""}, {"1 2", ""}, {" 12", ""}, {"12 ", ""}, {"+1", ""}, {"-1", ""}, {"1.0", ""}, {"1e3", ""},
		{"0x1", ""}, {"1_0", ""}, {"\n", ""}, {"12\n", ""}, {"\x00", ""}, {"1\x002", ""}, {"\xff", ""},
		{"\u0661\u0662\u0663", ""}, // Arabic-Indic digits
		{"\uff11\uff12\uff13", ""}, // fullwidth digits
		{"1\u20322", ""},           // a prime
		{"\u00b2", ""},             // superscript two
		{"\u202e123", ""},          // a bidirectional control before digits
		{"123\u200b", ""},          // a zero-width space after digits
	}
	for _, r := range rows {
		if got := wanted.SerialKey(r.serial); got != r.key {
			t.Errorf("SerialKey(%.20q) = %q, want %q", r.serial, got, r.key)
		}
	}
	// Two serials of one number are one key, and two numbers are two keys.
	if wanted.SerialKey("0123") != wanted.SerialKey("123") {
		t.Error("0123 and 123 are two cards")
	}
	if wanted.SerialKey("10000001") == wanted.SerialKey("10000010") {
		t.Error("two numbers give one key")
	}
	// Every digit string of up to four digits gives a key that differs for every number, and none for zero twice.
	seen := map[string]string{}
	for n := 0; n < 10000; n++ {
		for _, width := range []int{4, 5, 10} {
			s := strings.Repeat("0", width) + strconv.Itoa(n)
			s = s[len(s)-width:]
			k := wanted.SerialKey(s)
			if k == "" {
				t.Fatalf("no key for %q", s)
			}
			if prev, ok := seen[k]; ok && prev != strconv.Itoa(n) {
				t.Fatalf("the key %q is for %s and %d", k, prev, n)
			}
			seen[k] = strconv.Itoa(n)
			if k != strconv.Itoa(n) {
				t.Fatalf("the key of %q is %q, want %d", s, k, n)
			}
		}
	}
}

func TestACardThatTheReaderDidNotMakeIsNotValid(t *testing.T) {
	var nilCard *wanted.Card
	if nilCard.Valid() {
		t.Error("a nil card is valid")
	}
	if (&wanted.Card{}).Valid() {
		t.Error("a zero card is valid")
	}
	var zero wanted.Card
	if zero.Valid() {
		t.Error("a zero value is valid")
	}
	// A card that a caller built by hand with every member filled in.
	hand := &wanted.Card{
		File:         wanted.File{Path: cardPath("root-a"), Data: []byte(cardRootA), SHA256: sha256hex([]byte(cardRootA))},
		Name:         "root-a",
		Serial:       "10000001",
		Kind:         wanted.CardRoot,
		Applications: []wanted.Application{wanted.AppPIV},
		OtherRows:    []int{3},
	}
	if hand.Valid() {
		t.Error("a card built by hand is valid")
	}
	// A card from the reader is valid, and so is a card of the loader (see the list tests).
	if !mustCard(t, "root-a", cardRootA).Valid() {
		t.Error("a card of the reader is not valid")
	}
	// A refusal gives no card to ask.
	c, err := wanted.ParseCard("root-a", []byte("version: 2\n"))
	if c != nil || err == nil || c.Valid() {
		t.Errorf("a refused file gave %v, %v", c, err)
	}
}
