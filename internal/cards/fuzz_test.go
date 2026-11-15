package cards_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/cards"
	"ritueel.id/ritueel/internal/wanted"
)

// The fuzz targets read bytes and names in memory only. They start no program and touch no card. Run in the
// ordinary way they run their seeds; `go test -fuzz` mutates them.

func inspectSeeds() []string {
	seeds := []string{cardRootA, cardRootB, cardDayOne, cardServerOne, cardPracticeOne, "", "---\n", "{}", "[]", "\ufeff" + cardRootA,
		strings.Repeat("[", 300), "a: &x [1]\nb: *x\n", "version: 1\r\n", "version:\t1\n", "x: \xff\n",
		"version: 1\nserial: \"" + strings.Repeat("9", 300) + "\"\nkind: root\napplications: [piv]\n",
		"version: 1\nserial: \"0\"\nkind: root\napplications: [piv]\nother_rows: [2, 3, 4, 5, 6]\n",
		"version: 1\nserial: \"00\"\nkind: server\napplications: [piv]\n",
		"version: 1\nserial: \"1\"\nkind: root\napplications: [piv]\nholder: Example Person\n",
	}
	for _, b := range badCards() {
		seeds = append(seeds, b.text)
	}
	return seeds
}

// checkReport holds what Inspect promises about a report of the files that it was given (name to text).
func checkReport(t *testing.T, rep *cards.Report, files map[string][]byte) {
	t.Helper()
	if !rep.Valid() {
		t.Fatal("a report that is not valid beside no error")
	}
	// Every file is a card or a finding of its own, and nothing else is.
	invalid := map[string]bool{}
	twice := 0
	for _, f := range rep.Findings {
		if !f.Level.Valid() || !printable(f.Line()) || !printable(f.Path) || !printable(f.Detail) || len(f.Detail) > 240 || strings.ContainsAny(f.Line(), "\r\n") {
			t.Fatalf("a finding that is not usable: %+q", f)
		}
		if !strings.HasPrefix(f.Path, "want/cards/") || !strings.HasSuffix(f.Path, ".yaml") {
			t.Fatalf("a path that is not a card file: %q", f.Path)
		}
		switch f.Code {
		case cards.FileInvalid:
			invalid[f.Path] = true
		case cards.SerialTwice:
			twice++
		default:
			t.Fatalf("a code that is not in the table: %q", f.Code)
		}
	}
	keys := map[string]bool{}
	seen := map[string]bool{}
	for _, c := range rep.Cards {
		if !c.Valid() || c.SerialKey() == "" || seen[c.Name] || invalid[cardFile(c.Name)] {
			t.Fatalf("a card that is not usable or is in two lists: %+v", c)
		}
		seen[c.Name] = true
		keys[c.SerialKey()] = true
		data, ok := files[c.Name]
		if !ok || string(c.File.Data) != string(data) {
			t.Fatalf("the card %q does not hold the bytes of its file", c.Name)
		}
		if again, err := wanted.ParseCard(c.Name, data); err != nil || again.SerialKey() != c.SerialKey() || again.Kind != c.Kind {
			t.Fatalf("a card that the reader does not read again: %v", err)
		}
	}
	if len(rep.Cards)+len(invalid) != len(files) {
		t.Fatalf("%d cards and %d invalid files for %d files", len(rep.Cards), len(invalid), len(files))
	}
	if twice != len(rep.Cards)-len(keys) {
		t.Fatalf("%d findings of a card named twice for %d cards with %d serials", twice, len(rep.Cards), len(keys))
	}
	if !slices.IsSortedFunc(rep.Findings, func(a, b cards.Finding) int {
		ca, cb := slices.Index(cards.Codes(), a.Code), slices.Index(cards.Codes(), b.Code)
		if ca != cb {
			return ca - cb
		}
		return strings.Compare(a.Path, b.Path)
	}) {
		t.Fatalf("the findings are not in order: %+v", rep.Findings)
	}
	for name, data := range files {
		_, err := wanted.ParseCard(name, data)
		if (err == nil) == invalid[cardFile(name)] {
			t.Fatalf("the file %q is judged otherwise than by the reader", name)
		}
	}
	if rep.Clean() != (len(rep.Findings) == 0) {
		t.Fatalf("Clean = %v for %d findings", rep.Clean(), len(rep.Findings))
	}
}

func FuzzInspect(f *testing.F) {
	for _, s := range inspectSeeds() {
		f.Add("a", []byte(s), []byte(cardRootB))
		f.Add("b", []byte(cardRootB), []byte(s))
	}
	f.Add("a", []byte(cardRootA), []byte(cardRootA))
	f.Add("", []byte(cardRootA), []byte(cardRootB))
	f.Add("A", []byte(cardRootA), []byte(cardRootB))
	f.Add("a\xffb", []byte(cardRootA), []byte(cardRootB))
	f.Add(".rt-x", []byte(cardRootA), []byte(cardRootB))
	f.Fuzz(func(t *testing.T, name string, one, two []byte) {
		n := newDir()
		n.put("want/cards/zz.yaml", &node{kind: "file", data: two})
		n.kids["want"].kids["cards"].kids[name+".yaml"] = &node{kind: "file", data: one}
		rep, err := cards.Inspect(t.Context(), n.open(nil))
		cerr := cards.Check(t.Context(), n.open(nil))
		if err != nil {
			if rep != nil || cerr == nil || !printable(err.Error()) {
				t.Fatalf("Inspect = %+v, %+q; Check = %v", rep, err, cerr)
			}
			if wanted.ValidName(name) == nil && name+".yaml" != "zz.yaml" {
				t.Fatalf("an error for good names: %v", err)
			}
			return
		}
		files := map[string][]byte{"zz": two}
		// A name that starts with ".rt-" is the leftover of a stopped write: the lister skips it, so it is no
		// card and no finding.
		if name != "zz" && !strings.HasPrefix(strings.ToLower(name), ".rt-") {
			files[name] = one
		}
		checkReport(t, rep, files)
		if (cerr == nil) != rep.Clean() {
			t.Fatalf("Check = %v and Clean = %v", cerr, rep.Clean())
		}
		if cerr != nil {
			var we *wanted.Error
			if !errors.As(cerr, &we) || we.Path != rep.Refusals()[0].Path || !printable(cerr.Error()) {
				t.Fatalf("Check = %+q, want a fault at %q", cerr, rep.Refusals()[0].Path)
			}
		}
	})
}

func FuzzInspectManyFiles(f *testing.F) {
	f.Add([]byte(cardRootA), []byte(cardRootB), []byte(cardDayOne), uint8(3))
	f.Add([]byte(cardRootA), []byte(cardRootA), []byte("x"), uint8(70))
	f.Add([]byte(""), []byte(""), []byte(""), uint8(0))
	f.Fuzz(func(t *testing.T, a, b, c []byte, count uint8) {
		files := map[string][]byte{}
		n := newDir()
		n.put("want/cards", newDir())
		pool := [][]byte{a, b, c}
		for i := range int(count) {
			name := "c" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			data := pool[i%3]
			files[name] = data
			n.kids["want"].kids["cards"].kids[name+".yaml"] = &node{kind: "file", data: data}
		}
		p := &probe{}
		rep, err := cards.Inspect(t.Context(), n.open(p))
		if len(files) > wanted.MaxCards {
			if err == nil || rep != nil || p.readsUnder("want/cards") != 0 {
				t.Fatalf("%d files: %+v, %v, %d reads", len(files), rep, err, p.readsUnder("want/cards"))
			}
			return
		}
		if err != nil {
			t.Fatalf("%d files: %v", len(files), err)
		}
		checkReport(t, rep, files)
		if len(p.read) != len(files) {
			t.Fatalf("%d reads for %d files", len(p.read), len(files))
		}
	})
}
