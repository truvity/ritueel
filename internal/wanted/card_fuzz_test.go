//go:build linux || darwin

package wanted_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// The fuzz targets of the card file read bytes and names in memory or in a folder of the iteration only: they start
// no program and touch no card. Run in the ordinary way they run their seeds; `go test -fuzz` mutates them.

// cardSeeds are the good files and the refused files of the tests.
func cardSeeds() []string {
	seeds := []string{
		cardRootA, cardRootB, cardDayOne, cardServerOne, cardPracticeOne, cardPageExample, "", "---\n", "{}", "[]",
		"version: 1\nserial: \"0\"\nkind: root\napplications: [piv]\nother_rows: []\n",
		"version: 1\nserial: \"1234567890\"\nkind: rehearsal\napplications: [openpgp, fido2, piv]\nother_rows: [6, 5, 4, 3, 2]\n",
		"version: 1\nserial: \"1\"\nkind: root\napplications: [fido2]\nother_rows: [3]\n",
		"version: 1\nserial: 1\nkind: root\napplications: [piv]\n",
		"version: 1\nserial: \"1\"\nkind: root\napplications: [piv]\nholder: Example Person\n",
		"version: 1\nserial: \"1\"\nkind: root\napplications: [piv]\nother_rows: [2, 3, 4, 5, 6, 2]\n",
		"version: 1\nserial: \"" + strings.Repeat("9", 300) + "\"\nkind: root\napplications: [piv]\n",
		"version: 1\nserial: \"1\"\nkind: root\napplications: [" + strings.TrimSuffix(strings.Repeat("piv, ", 50), ", ") + "]\n",
		"x: &a [1]\ny: *a\n", "<<: {a: 1}\n", "? a\n: b\n", "a: !!str b\n", "%YAML 1.2\n---\na: 1\n", "a: 1\n...\n---\nb: 2\n",
		"\ufeffversion: 1\n", "version: 1\r\n", "version:\t1\n", "version: 1\n# \u202e\n", "a: \xff\n", strings.Repeat("[", 300),
	}
	for _, r := range cardRefusals() {
		seeds = append(seeds, strings.Replace(cardBase, r.from, r.bad, 1))
	}
	for _, r := range strictRows() {
		seeds = append(seeds, r.text)
	}
	return seeds
}

// cardText writes a card in the one form that the reader reads, so that what was read can be read again.
func cardText(c *wanted.Card) string {
	var b strings.Builder
	b.WriteString("version: 1\n")
	fmt.Fprintf(&b, "serial: %q\n", c.Serial)
	fmt.Fprintf(&b, "kind: %s\n", c.Kind)
	apps := make([]string, len(c.Applications))
	for i, a := range c.Applications {
		apps[i] = string(a)
	}
	fmt.Fprintf(&b, "applications: [%s]\n", strings.Join(apps, ", "))
	if len(c.OtherRows) > 0 {
		rows := make([]string, len(c.OtherRows))
		for i, r := range c.OtherRows {
			rows[i] = fmt.Sprint(r)
		}
		fmt.Fprintf(&b, "other_rows: [%s]\n", strings.Join(rows, ", "))
	}
	return b.String()
}

func FuzzParseCard(f *testing.F) {
	for _, s := range cardSeeds() {
		f.Add("root-a", []byte(s))
	}
	f.Add("", []byte(cardRootA))
	f.Add("Root-A", []byte(cardRootA))
	f.Add(".rt-abc", []byte(cardRootA))
	f.Add("a\xffb", []byte(cardRootA))
	f.Add(strings.Repeat("a", 64), []byte(cardRootA))
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		c, err := wanted.ParseCard(name, data)
		var file wanted.File
		if c != nil {
			file = c.File
			if !c.Valid() || c.Name != name || wanted.ValidName(name) != nil || c.File.Path != "want/cards/"+name+".yaml" {
				t.Fatalf("a card that breaks what the reader promises: %+v", c)
			}
			if wanted.SerialKey(c.Serial) == "" || len(c.Serial) > wanted.MaxSerialDigits {
				t.Fatalf("a serial that the key refuses: %q", c.Serial)
			}
			switch c.Kind {
			case wanted.CardRoot, wanted.CardDayToDay, wanted.CardServer, wanted.CardRehearsal:
			default:
				t.Fatalf("a kind that the page does not have: %q", c.Kind)
			}
			if n := len(c.Applications); n < 1 || n > wanted.MaxApplications {
				t.Fatalf("%d applications", n)
			}
			for i, a := range c.Applications {
				if a != wanted.AppPIV && a != wanted.AppOpenPGP && a != wanted.AppFIDO2 {
					t.Fatalf("an application that the page does not have: %q", a)
				}
				if slices.Contains(c.Applications[:i], a) {
					t.Fatalf("an application twice: %v", c.Applications)
				}
			}
			if c.OtherRows != nil && len(c.OtherRows) == 0 {
				t.Fatal("an empty list of rows that is not nil")
			}
			if len(c.OtherRows) > wanted.MaxOtherRows {
				t.Fatalf("%d rows", len(c.OtherRows))
			}
			for i, r := range c.OtherRows {
				if r < wanted.FirstBundleRow || r > wanted.LastRow || slices.Contains(c.OtherRows[:i], r) {
					t.Fatalf("a row out of range or twice: %v", c.OtherRows)
				}
			}
			if len(c.OtherRows) > 0 && !slices.Contains(c.Applications, wanted.AppPIV) {
				t.Fatalf("rows on a card without piv: %v %v", c.OtherRows, c.Applications)
			}
			// What was read is read again from the same bytes, and from the text that is made out of it.
			again, err2 := wanted.ParseCard(name, data)
			if err2 != nil || !equalCards(c, again) {
				t.Fatalf("a second reading differs: %v", err2)
			}
			text := cardText(c)
			third, err3 := wanted.ParseCard(name, []byte(text))
			if err3 != nil {
				t.Fatalf("the card does not read again from its own text %q: %v", text, err3)
			}
			if third.Serial != c.Serial || third.Kind != c.Kind || !slices.Equal(third.Applications, c.Applications) || !slices.Equal(third.OtherRows, c.OtherRows) {
				t.Fatalf("the card changes when written and read again: %+v / %+v", c, third)
			}
		}
		if c == nil && err == nil {
			t.Fatal("neither a card nor an error")
		}
		if c != nil && err != nil {
			t.Fatalf("a card beside the error %v", err)
		}
		checkResult(t, "card", data, c != nil, file, err)
	})
}

// equalCards compares two cards by what the reader made.
func equalCards(a, b *wanted.Card) bool {
	return a.Name == b.Name && a.Serial == b.Serial && a.Kind == b.Kind && slices.Equal(a.Applications, b.Applications) &&
		slices.Equal(a.OtherRows, b.OtherRows) && a.File.SHA256 == b.File.SHA256 && a.File.Path == b.File.Path
}

// FuzzListCardNames lists a folder whose file names and contents come from the fuzzer, and loads every name that
// the listing returns. No outside program is started and nothing is written outside the folder of the iteration.
func FuzzListCardNames(f *testing.F) {
	f.Add("a.yaml", cardRootA, "b.yaml", cardRootB, byte(0))
	f.Add("a.yaml", cardRootA, "A.yaml", cardRootA, byte(0))
	f.Add("a.yaml", "", "b.txt", "x", byte(1))
	f.Add("x\x01.yaml", cardRootA, "y", "", byte(2))
	f.Add(".rt-abc.yaml", cardRootA, "b.yaml", "version: 1\nholder: x\n", byte(4))
	f.Add("a.yaml", cardRootA, "a.yaml.yaml", cardRootA, byte(8))
	f.Fuzz(func(t *testing.T, n1, t1, n2, t2 string, flags byte) {
		dir := t.TempDir()
		cards := filepath.Join(dir, "want", "cards")
		if err := os.MkdirAll(cards, 0o755); err != nil {
			t.Fatal(err)
		}
		for i, n := range []string{n1, n2} {
			if n == "" || strings.ContainsAny(n, "/\x00") || n == "." || n == ".." || len(n) > 200 {
				continue
			}
			text := []string{t1, t2}[i]
			if flags&(1<<i) != 0 {
				// A folder in place of the file.
				_ = os.Mkdir(filepath.Join(cards, n), 0o755)
				continue
			}
			_ = os.WriteFile(filepath.Join(cards, n), []byte(text), 0o644)
		}
		fsys, err := fsx.OpenFS(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = fsys.Close() }()
		names, err := wanted.ListCardNames(fsys)
		if err != nil {
			if names != nil {
				t.Fatalf("an error with %d names", len(names))
			}
			if !printableASCII(err.Error()) {
				t.Fatalf("an error that is not printable: %+q", err.Error())
			}
			return
		}
		if !slices.IsSorted(names) {
			t.Fatalf("the names are not in order: %q", names)
		}
		for _, name := range names {
			if wanted.ValidName(name) != nil {
				t.Fatalf("a listed name that is not a valid name: %q", name)
			}
			c, err := wanted.LoadCard(fsys, name)
			if err != nil {
				if c != nil || !printableASCII(err.Error()) {
					t.Fatalf("LoadCard(%q): %v, %+v", name, err, c)
				}
				continue
			}
			if !c.Valid() || c.Name != name || c.File.Path != "want/cards/"+name+".yaml" {
				t.Fatalf("a card that is not what the reader makes: %+v", c)
			}
		}
	})
}
