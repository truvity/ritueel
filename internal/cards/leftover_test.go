//go:build linux || darwin

package cards_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/cards"
	"ritueel.id/ritueel/internal/wanted"
)

// A name that starts with ".rt-", in any case of the letters, is the leftover of a stopped write (record
// 0006, rule 45). The lister of want/cards skips it, so the check does not read it, does not count it
// toward the limit of card files and gives no finding for it, whatever it holds and whatever kind of entry
// it is. The names of this file start with lo.

// loNames are leftover names: the prefix in several cases of the letters, and a name that holds a whole
// card file name after the prefix.
var loNames = []string{".rt-a.yaml", ".RT-b.yaml", ".Rt-c.yaml", ".rT-d.yaml", ".rt-.yaml", ".rt-root-a.yaml", ".rt-A B\xff.yaml", ".rt-x"}

// loContent is what a leftover can hold: a good card file that repeats a card of the set, a file that
// fails its reader, no bytes and bytes that are not text.
var loContent = map[string]string{
	"a copy of a card of the set": cardRootA,
	"a file that fails":           "version: 2\nserial: \"1\"\n",
	"an empty file":               "",
	"bytes that are not text":     "\xff\xfe\x00 not: [yaml",
}

func TestALeftoverInTheCardFolderIsNotReadNotCountedAndNoFinding(t *testing.T) {
	for what, text := range loContent {
		for _, name := range loNames {
			t.Run(fmt.Sprintf("%s %+q", what, name), func(t *testing.T) {
				n := memBundle(goodSet())
				n.put("want/cards/"+name, &node{kind: "file", data: []byte(text)})
				p := &probe{}
				rep := mustInspect(t, n.open(p))
				if got := names(rep); !slices.Equal(got, goodNames) {
					t.Errorf("cards = %q, want %q", got, goodNames)
				}
				if len(rep.Findings) != 0 || !rep.Clean() {
					t.Errorf("findings = %+v", rep.Findings)
				}
				if got := p.readsUnder("want/cards"); got != len(goodNames) {
					t.Errorf("%d files read, want %d: %q", got, len(goodNames), p.read)
				}
				for _, r := range p.read {
					if strings.Contains(strings.ToLower(r), ".rt-") {
						t.Errorf("the leftover was read: %q", r)
					}
				}
				if err := cards.Check(t.Context(), n.open(nil)); err != nil {
					t.Errorf("Check: %v", err)
				}
			})
		}
	}
}

func TestAReportWithLeftoversIsTheReportWithoutThem(t *testing.T) {
	plain := mustInspect(t, memBundle(with(goodSet(), map[string]string{cardFile("zz-bad"): "version: 2\n"})).open(nil))
	files := with(goodSet(), map[string]string{cardFile("zz-bad"): "version: 2\n"})
	for _, name := range loNames {
		files["want/cards/"+name] = cardRootB
	}
	got := mustInspect(t, memBundle(files).open(nil))
	if !slices.Equal(names(got), names(plain)) || len(got.Findings) != len(plain.Findings) {
		t.Fatalf("cards %q findings %+v, want cards %q findings %+v", names(got), got.Findings, names(plain), plain.Findings)
	}
	for i := range plain.Findings {
		if got.Findings[i] != plain.Findings[i] {
			t.Errorf("finding %d = %+v, want %+v", i, got.Findings[i], plain.Findings[i])
		}
	}
}

func TestLeftoversDoNotCountTowardTheLimitOfCardFiles(t *testing.T) {
	files := numbered(wanted.MaxCards)
	for i := range 3 * wanted.MaxCards {
		files[fmt.Sprintf("want/cards/.rt-%04d.yaml", i)] = cardRootA
	}
	p := &probe{}
	rep := mustInspect(t, memBundle(files).open(p))
	if len(rep.Cards) != wanted.MaxCards || len(rep.Findings) != 0 {
		t.Errorf("%d cards, findings %+v", len(rep.Cards), rep.Findings)
	}
	if got := p.readsUnder("want/cards"); got != wanted.MaxCards {
		t.Errorf("%d files read, want %d", got, wanted.MaxCards)
	}
	// One card file more than the limit is still the error, with any number of leftovers beside it.
	files["want/cards/c9999.yaml"] = cardText("9999", "server")
	p = &probe{}
	rep, err := cards.Inspect(t.Context(), memBundle(files).open(p))
	if err == nil || rep != nil || p.readsUnder("want/cards") != 0 {
		t.Errorf("Inspect = %+v, %v; %d files read", rep, err, p.readsUnder("want/cards"))
	}
}

// A name that only looks like the prefix is not a leftover: it is read as any other name and is an error.
func TestANameThatOnlyLooksLikeTheLeftoverPrefixIsStillAnError(t *testing.T) {
	for _, name := range []string{".rt.yaml", ".rtx.yaml", ".r-t-a.yaml", " .rt-a.yaml", "x.rt-a.yaml", "rt-a.yml", "..rt-a.yaml", ".rt_a.yaml"} {
		t.Run(fmt.Sprintf("%+q", name), func(t *testing.T) {
			n := memBundle(goodSet())
			n.put("want/cards/"+name, &node{kind: "file", data: []byte(cardRootB)})
			rep, err := cards.Inspect(t.Context(), n.open(nil))
			if err == nil || rep != nil {
				t.Fatalf("Inspect = %+v, %v", rep, err)
			}
		})
	}
}

// Whatever kind of entry the leftover is, on a real disk: a file, a folder (with files in it), a link to a
// good file, a link to nowhere, a FIFO that would block a read. None is opened, followed or changed.
func TestALeftoverOfAnyKindOnTheDiskIsSkippedAndNothingIsChanged(t *testing.T) {
	dir, fsys := diskBundle(t, with(goodSet(), map[string]string{
		"want/cards/.rt-file.yaml":           "version: 2\n",
		"want/cards/.RT-folder/inner.yaml":   cardRootA,
		"want/cards/.rt-folder2/.rt-in.yaml": "x",
	}))
	cardsDir := filepath.Join(dir, "want", "cards")
	for name, target := range map[string]string{".rt-link.yaml": "root-a.yaml", ".rt-dangling.yaml": "nowhere", ".rt-outside": "/"} {
		if err := os.Symlink(target, filepath.Join(cardsDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(cardsDir, ".rt-fifo.yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cardsDir, ".rt-unreadable.yaml"), []byte(cardRootB), 0o000); err != nil {
		t.Fatal(err)
	}
	before := tree(t, dir)
	rep := mustInspect(t, fsys)
	if got := names(rep); !slices.Equal(got, goodNames) || !rep.Clean() {
		t.Errorf("cards = %q, findings %+v", got, rep.Findings)
	}
	if err := cards.Check(t.Context(), fsys); err != nil {
		t.Errorf("Check: %v", err)
	}
	if after := tree(t, dir); !slices.Equal(before, after) {
		t.Errorf("Inspect changed the folder:\n%q\n%q", before, after)
	}
}

// A leftover beside a card file that fails does not hide the finding, and a leftover beside a name that is
// refused does not hide the refusal.
func TestALeftoverDoesNotHideAFindingOrARefusal(t *testing.T) {
	files := with(goodSet(), map[string]string{cardFile("zz-bad"): "version: 2\n", "want/cards/.rt-a.yaml": cardRootB, "want/cards/.RT-z.yaml": cardRootB})
	rep := mustInspect(t, memBundle(files).open(nil))
	if got := paths(rep.Findings); !slices.Equal(got, []string{cardFile("zz-bad")}) {
		t.Errorf("findings = %q", got)
	}
	n := memBundle(with(files, map[string]string{"want/cards/Bad.yaml": cardRootB}))
	if rep, err := cards.Inspect(t.Context(), n.open(nil)); err == nil || rep != nil || !strings.Contains(err.Error(), "want/cards/Bad.yaml") {
		t.Errorf("Inspect = %+v, %v", rep, err)
	}
}
