//go:build linux || darwin

package history

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// One bound counts every name that a run looks at: the names of history/, of trust/ and of each
// ceremony folder, and the names of the walk inside the trust sets and the folders of copies. Stray
// names in any of them count. A run that meets the bound ends with ErrTooMuch and is never clean.
// Before, only the walk was counted, and a bundle of many ceremony folders with many stray names in
// each was clean, with notices, after as long as it took to list them.

func TestEveryNameThatARunLooksAtCountsTowardOneBound(t *testing.T) {
	// A record that lists no set: history/ holds one folder (1 name); the ceremony folder holds five
	// (plan, attempt, wanted, transcript, record); wanted/ holds one copy. There is no trust/, so
	// the strays of the test are the only names of trust/ when they are put there.
	const base = 1 + 5 + 1
	const strays = 7
	for _, place := range []string{"history", "trust", "ceremony folder"} {
		t.Run(place, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(noSet)
			dir := map[string]string{"history": "history", "trust": "trust", "ceremony folder": "history/" + r.folder}[place]
			for i := 0; i < strays; i++ {
				b.put(fmt.Sprintf("%s/stray%d.txt", dir, i), []byte("x"))
			}
			root, err := fsx.OpenFS(b.dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			lim := limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: MaxFindingsPerCode, walkEntries: base + strays}
			rep, err := runFS(t, root, &lim)
			if err != nil {
				t.Fatalf("a limit of %d names, which is what the bundle holds: %v", lim.walkEntries, err)
			}
			if len(rep.Findings) != strays {
				t.Errorf("findings: %v", findingsOf(rep))
			}
			lim.walkEntries--
			rep, err = runFS(t, root, &lim)
			if !errors.Is(err, ErrTooMuch) || rep != nil {
				t.Errorf("a limit of %d names: Check = %v, %v; want ErrTooMuch", lim.walkEntries, rep, err)
			}
		})
	}
}

// The folder with no history, listed to see whether it is a bundle, counts too.
func TestListingOfTheRootCountsTowardTheBound(t *testing.T) {
	dir := t.TempDir()
	b := &bundle{t: t, dir: dir}
	b.put("ritueel.yaml", []byte("name: x\n"))
	b.put("a.txt", []byte("x"))
	b.put("b.txt", []byte("x"))
	root, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	lim := limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: MaxFindingsPerCode, walkEntries: 3}
	if _, err := runFS(t, root, &lim); err != nil {
		t.Fatalf("a limit of 3 names, the three of the root: %v", err)
	}
	lim.walkEntries = 2
	if _, err := runFS(t, root, &lim); !errors.Is(err, ErrTooMuch) {
		t.Errorf("a limit of 2 names: err = %v, want ErrTooMuch", err)
	}
}

// Ceremony folders that each hold many stray names: the sum is what is bounded, so a bundle of many
// folders cannot make a run list without end.
func TestManyCeremonyFoldersEachWithManyStrayNamesEndTheRunWithTooMuch(t *testing.T) {
	per := fsx.MaxDirEntries - 10
	folders := MaxWalkEntries/per + 1
	if folders*per <= MaxWalkEntries {
		t.Fatal("the test does not exceed the bound")
	}
	m := newMem()
	m.file("ritueel.yaml", "name: x\n")
	m.put("history", newMem())
	for f := 0; f < folders; f++ {
		for i := 0; i < per; i++ {
			m.file(fmt.Sprintf("history/2026%04dT100000Z-apply/stray%d.txt", f, i), "x")
		}
	}
	rep, err := runMem(t, m)
	if !errors.Is(err, ErrTooMuch) || rep != nil {
		t.Fatalf("Check = %v, %v; want ErrTooMuch", rep, err)
	}
	if !printable(err.Error()) {
		t.Errorf("the text of the error is not printable ASCII: %q", err)
	}
	// One folder with as many strays is under the bound and is listed.
	m2 := newMem()
	m2.file("ritueel.yaml", "name: x\n")
	for i := 0; i < per; i++ {
		m2.file(fmt.Sprintf("history/2026%04dT100000Z-apply/stray%d.txt", 0, i), "x")
	}
	rep, err = runMem(t, m2)
	if err != nil || rep == nil || !rep.Clean() {
		t.Errorf("one folder of %d strays: %v", per, err)
	}
}

// A name that carries a space is written with the escape of a space, so that a name cannot put words
// into a line. Before, a leftover name such as ".rt-x history: 3 ceremony records, end a36562f0" was
// shown as it is, and a search of the output for the end found the forged words in the middle of a line.
func TestNoLineHoldsASpaceInsideAPathOrAName(t *testing.T) {
	names := []string{
		"a b",
		"x: fork history c1",
		"history: 3 ceremony records, end a36562f0",
		"chain-broken history",
		".rt-x history: 3 ceremony records, end a36562f0",
		".RT-a b",
		"a\tb",
		" leading",
		"trailing ",
		"two  spaces",
	}
	places := []string{"history", "trust", "ceremony"}
	for _, place := range places {
		for _, name := range names {
			t.Run(place+" "+name, func(t *testing.T) {
				b := newBundle(t)
				r := b.apply(noSet)
				dir := map[string]string{"history": "history", "trust": "trust", "ceremony": "history/" + r.folder}[place]
				b.mkdir(dir)
				entry(t, b, dir, name, false)
				rep := b.run()
				if len(rep.Findings) != 1 {
					t.Fatalf("findings: %v", findingsOf(rep))
				}
				f := rep.Findings[0]
				if strings.Contains(f.Path, " ") {
					t.Errorf("the path holds a space: %q", f.Path)
				}
				line := f.Line()
				// The line is the code, one space, the path, a colon and a space, the detail: the first
				// space ends the code and the path has none, so a reader splits it with no doubt.
				code, rest, ok := strings.Cut(line, " ")
				if !ok || code != string(f.Code) || !strings.HasPrefix(rest, f.Path+": ") {
					t.Errorf("the line %q is not code, path, colon, detail", line)
				}
				if strings.HasPrefix(line, "history:") || !isCodeWord(code) {
					t.Errorf("the line %q starts like something that is not a finding", line)
				}
				if want := dir + "/" + escaped(name); f.Path != want {
					t.Errorf("path %q, want %q", f.Path, want)
				}
			})
		}
	}
}

func isCodeWord(s string) bool {
	for _, c := range Codes() {
		if string(c) == s {
			return true
		}
	}
	return false
}
