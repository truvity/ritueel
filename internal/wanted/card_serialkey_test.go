package wanted_test

import (
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// A card has one identity for its serial however it is written (docs/reference/cards.md, the member serial: "It
// identifies the card in every later check"; record 0003, rule 5). The method SerialKey of a Card is that identity,
// and a comparison of two cards uses it and never the text of Serial.

// cardWithSerial reads a good card file that has the given serial, written in quotes.
func cardWithSerial(t testing.TB, serial string) *wanted.Card {
	t.Helper()
	return mustCard(t, "root-a", "version: 1\nserial: \""+serial+"\"\nkind: root\napplications: [piv]\n")
}

func TestCardSerialKeyGivesTheDigitsWithoutLeadingZeros(t *testing.T) {
	rows := []struct{ name, serial, key string }{
		{"leading zeros", "0123", "123"},
		{"no leading zero", "123", "123"},
		{"the zeros of the page example", "00000123", "123"},
		{"a single zero", "0", "0"},
		{"two zeros", "00", "0"},
		{"zeros only", "0000", "0"},
		{"the longest serial of zeros", "0000000000", "0"},
		{"one digit", "1", "1"},
		{"a serial of one and zeros", "1000000000", "1000000000"},
		{"the longest serial", "1234567890", "1234567890"},
		{"the longest serial of nines", "9999999999", "9999999999"},
		{"the longest serial with a leading zero", "0123456789", "123456789"},
		{"nine zeros and a one", "0000000001", "1"},
		{"zeros inside are kept", "1020", "1020"},
		{"zeros at the end are kept", "0100", "100"},
	}
	for _, r := range rows {
		c := cardWithSerial(t, r.serial)
		if c.Serial != r.serial {
			t.Errorf("%s: the serial is kept as written: %q, want %q", r.name, c.Serial, r.serial)
		}
		if got := c.SerialKey(); got != r.key {
			t.Errorf("%s: SerialKey of %q is %q, want %q", r.name, r.serial, got, r.key)
		}
	}
}

func TestTwoSpellingsOfOneSerialGiveOneKey(t *testing.T) {
	spellings := [][]string{
		{"7", "07", "007", "0000000007"},
		{"123", "0123", "00000123", "0000000123"},
		{"0", "00", "000", "0000000000"},
		{"1000000000"},
		{"9999999999"},
	}
	for _, group := range spellings {
		first := cardWithSerial(t, group[0])
		for _, s := range group[1:] {
			c := cardWithSerial(t, s)
			if c.Serial != s {
				t.Errorf("the serial %q is kept as %q", s, c.Serial)
			}
			if c.SerialKey() != first.SerialKey() {
				t.Errorf("%q and %q are two cards: %q and %q", group[0], s, first.SerialKey(), c.SerialKey())
			}
			if c.SerialKey() == "" {
				t.Errorf("no key for %q", s)
			}
		}
	}
}

func TestTwoNumbersGiveTwoKeys(t *testing.T) {
	pairs := [][2]string{
		{"10000001", "10000010"}, {"1", "10"}, {"0", "1"}, {"0100", "1"}, {"0010", "0100"}, {"9999999999", "9999999998"},
		{"1000000000", "0100000000"}, {"0", "0000000010"},
	}
	for _, p := range pairs {
		a, b := cardWithSerial(t, p[0]), cardWithSerial(t, p[1])
		if a.SerialKey() == b.SerialKey() {
			t.Errorf("%q and %q give one key %q", p[0], p[1], a.SerialKey())
		}
	}
	// Over every number of up to four digits, written in three widths, the key is the number and no two numbers meet.
	seen := map[string]int{}
	for n := 0; n < 10000; n++ {
		for _, width := range []int{4, 6, 10} {
			s := strings.Repeat("0", width) + strconv.Itoa(n)
			c := wanted.Card{Serial: s[len(s)-width:]}
			if got := c.SerialKey(); got != strconv.Itoa(n) {
				t.Fatalf("the key of %q is %q, want %d", c.Serial, got, n)
			}
			seen[c.SerialKey()] = n
		}
	}
	if len(seen) != 10000 {
		t.Errorf("10,000 numbers gave %d keys", len(seen))
	}
}

func TestCardSerialKeyOfACardThatIsNotMade(t *testing.T) {
	var nilCard *wanted.Card
	if got := nilCard.SerialKey(); got != "" {
		t.Errorf("the key of a nil Card is %q, want the empty text", got)
	}
	if got := (&wanted.Card{}).SerialKey(); got != "" {
		t.Errorf("the key of a zero Card is %q, want the empty text", got)
	}
	var zero wanted.Card
	if got := zero.SerialKey(); got != "" {
		t.Errorf("the key of a zero value is %q, want the empty text", got)
	}
	// A Card that a caller built with a serial that no card file can hold has no key, so that two such cards are
	// never the same card.
	for _, serial := range []string{
		"12a", "a", "1 2", " 12", "12 ", "+1", "-1", "1.0", "0x1", "1\x002", "\xff", "١٢", "\n",
		"12345678901", "00000000000", strings.Repeat("1", 10000), strings.Repeat("0", 10000),
	} {
		c := wanted.Card{Serial: serial}
		if got := c.SerialKey(); got != "" {
			t.Errorf("a hand-built Card with the serial %.20q has the key %q, want the empty text", serial, got)
		}
	}
}

func TestCardSerialKeyIsTheKeyOfTheSerialForEveryCardOfTheTests(t *testing.T) {
	for _, text := range []string{cardRootA, cardRootB, cardDayOne, cardServerOne, cardPracticeOne, cardPageExample} {
		c := mustCard(t, "root-a", text)
		serial := c.Serial
		got, want := c.SerialKey(), wanted.SerialKey(serial)
		if got != want || got == "" {
			t.Errorf("the method gives %q and the function gives %q for %q", got, want, serial)
		}
		// Asking changes nothing: the serial is kept as written, and a second ask gives the same key.
		if c.Serial != serial || c.SerialKey() != got {
			t.Errorf("SerialKey changed the card: the serial %q is now %q, the key %q is now %q", serial, c.Serial, got, c.SerialKey())
		}
	}
}

func TestCardSerialKeyDoesNotDependOnTheOtherMembers(t *testing.T) {
	a := mustCard(t, "root-a", "version: 1\nserial: \"0042\"\nkind: root\napplications: [piv, fido2]\nother_rows: [3]\n")
	b := mustCard(t, "root-a", "version: 1\nserial: \"42\"\nkind: server\napplications: [openpgp]\n")
	if a.SerialKey() != b.SerialKey() || a.SerialKey() != "42" {
		t.Errorf("the keys are %q and %q, want both 42", a.SerialKey(), b.SerialKey())
	}
	if a.Name == b.Name && a.Kind == b.Kind {
		t.Error("the two cards must differ in everything but the serial")
	}
}

func FuzzCardSerialKey(f *testing.F) {
	for _, s := range []string{"", "0", "00", "0123", "123", "1234567890", "12345678901", "a", "\xff", "١", "-1", " 1", "0000000000", strings.Repeat("9", 300)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, serial string) {
		c := wanted.Card{Serial: serial}
		key := c.SerialKey()
		if key != wanted.SerialKey(serial) {
			t.Fatalf("the method gives %q and the function gives %q for %.30q", key, wanted.SerialKey(serial), serial)
		}
		if key == "" {
			return
		}
		if len(serial) < 1 || len(serial) > wanted.MaxSerialDigits || len(key) > len(serial) {
			t.Fatalf("a key %q for the serial %.30q", key, serial)
		}
		for i := 0; i < len(key); i++ {
			if key[i] < '0' || key[i] > '9' {
				t.Fatalf("the key %q is not digits", key)
			}
		}
		if len(key) > 1 && key[0] == '0' {
			t.Fatalf("the key %q has a leading zero", key)
		}
		if !strings.HasSuffix(serial, key) || strings.Trim(serial[:len(serial)-len(key)], "0") != "" {
			t.Fatalf("the key %q is not the serial %q without leading zeros", key, serial)
		}
		// One more spelling of the same number is the same card, and the key of a key is the key.
		again := wanted.Card{Serial: "0" + key}
		if len(key) < wanted.MaxSerialDigits && again.SerialKey() != key {
			t.Fatalf("0%s has the key %q, want %q", key, again.SerialKey(), key)
		}
		if (&wanted.Card{Serial: key}).SerialKey() != key {
			t.Fatalf("the key %q is not its own key", key)
		}
	})
}
