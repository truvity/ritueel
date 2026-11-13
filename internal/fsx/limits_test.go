package fsx_test

// The two limits of a read: a journal of more than MaxJournalLines lines, and a folder of more than
// MaxDirEntries names, are refused with ErrTooMany, and nothing is returned in part.

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

const (
	textTooMany = "the file or folder holds more lines or names than the limit of a read"
)

func TestTheLimitsAreSixtyFiveThousandFiveHundredAndThirtySix(t *testing.T) {
	if fsx.MaxJournalLines != 65536 || fsx.MaxDirEntries != 65536 {
		t.Fatalf("MaxJournalLines %d, MaxDirEntries %d, want 65536 each", fsx.MaxJournalLines, fsx.MaxDirEntries)
	}
}

func TestReadJournalAtTheLimitOfLines(t *testing.T) {
	for _, c := range []struct {
		name    string
		lines   int
		partial string
		tooMany bool
	}{
		{"none", 0, "", false},
		{"one", 1, "", false},
		{"one below the limit", fsx.MaxJournalLines - 1, "", false},
		{"exactly the limit", fsx.MaxJournalLines, "", false},
		{"exactly the limit and a torn line", fsx.MaxJournalLines, "torn", false},
		{"one above the limit", fsx.MaxJournalLines + 1, "", true},
		{"one above the limit and a torn line", fsx.MaxJournalLines + 1, "torn", true},
		{"far above the limit", 3 * fsx.MaxJournalLines, "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newMemFS("b")
			f.addFile("b/j", append(bytes.Repeat([]byte("x\n"), c.lines), c.partial...))
			root := f.Root()
			defer func() { _ = root.Close() }()
			lines, partial, err := fsx.ReadJournal(root, "b/j")
			if c.tooMany {
				fe := asError(t, err)
				want := fmt.Sprintf(`fsx: read "b/j": %s: %d lines, more than 65536`, textTooMany, c.lines)
				if !errors.Is(err, fsx.ErrTooMany) || fe.Step != fsx.StepRead || fe.Path != "b/j" || err.Error() != want {
					t.Fatalf("got %v, want a read error at b/j that wraps ErrTooMany with the text\n  %s", err, want)
				}
				if lines != nil || partial != nil {
					t.Fatalf("%d lines and %d partial bytes came back with the error: nothing in part", len(lines), len(partial))
				}
				return
			}
			if err != nil || len(lines) != c.lines || string(partial) != c.partial {
				t.Fatalf("%d lines, partial %q, %v, want %d lines and %q", len(lines), partial, err, c.lines, c.partial)
			}
			for i, l := range lines {
				if string(l) != "x" {
					t.Fatalf("line %d is %q", i, l)
				}
			}
			if c.partial == "" && partial != nil {
				t.Fatalf("partial %q, want nil", partial)
			}
		})
	}
}

// TestReadJournalOfALotOfLineBreaksAllocatesNoSliceOfThem: 8 MiB of line breaks is refused after
// the lines are counted, before a slice for them is made. A slice of eight million lines is
// 192 MiB; the bound is far below that, and above the 8 MiB that the read of the file takes.
func TestReadJournalOfALotOfLineBreaksAllocatesNoSliceOfThem(t *testing.T) {
	f := newMemFS("b")
	f.addFile("b/j", bytes.Repeat([]byte{'\n'}, fsx.MaxReadSize))
	root := f.Root()
	defer func() { _ = root.Close() }()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _, err := fsx.ReadJournal(root, "b/j")
	runtime.ReadMemStats(&after)
	if !errors.Is(err, fsx.ErrTooMany) {
		t.Fatalf("got %v, want ErrTooMany", err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 24<<20 {
		t.Fatalf("the refusal allocated %d MiB: a slice of the lines was made", got>>20)
	}
	// and the largest journal that is accepted is made with one slice for its lines
	f2 := newMemFS("b")
	f2.addFile("b/j", bytes.Repeat([]byte("x\n"), fsx.MaxJournalLines))
	r2 := f2.Root()
	defer func() { _ = r2.Close() }()
	allocs := testing.AllocsPerRun(3, func() { _, _, _ = fsx.ReadJournal(r2, "b/j") })
	if allocs > 20 {
		t.Fatalf("a read of %d lines made %d allocations: the slice of lines is made once", fsx.MaxJournalLines, int(allocs))
	}
}

func TestReadDirAtTheLimitOfNames(t *testing.T) {
	for _, c := range []struct {
		name    string
		n       int
		tooMany bool
	}{
		{"none", 0, false},
		{"one below the limit", fsx.MaxDirEntries - 1, false},
		{"exactly the limit", fsx.MaxDirEntries, false},
		{"one above the limit", fsx.MaxDirEntries + 1, true},
		{"far above the limit", 200_000, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newMemFS("b")
			f.addNames("b", c.n)
			root := f.Root()
			defer func() { _ = root.Close() }()
			ents, err := fsx.ReadDir(root, "b")
			if c.tooMany {
				fe := asError(t, err)
				want := fmt.Sprintf(`fsx: read "b": %s: more than 65536 names`, textTooMany)
				if !errors.Is(err, fsx.ErrTooMany) || fe.Step != fsx.StepRead || fe.Path != "b" || err.Error() != want {
					t.Fatalf("got %v, want a read error at b that wraps ErrTooMany with the text\n  %s", err, want)
				}
				if ents != nil {
					t.Fatalf("%d entries came back with the error: nothing in part", len(ents))
				}
				// it stopped early: at most the limit and a little more names were asked for
				if f.namesAsked > fsx.MaxDirEntries+1024 {
					t.Fatalf("%d names were read of a folder of %d: the read did not stop at the limit", f.namesAsked, c.n)
				}
				return
			}
			if err != nil || len(ents) != c.n {
				t.Fatalf("%d entries, %v, want %d", len(ents), err, c.n)
			}
			for i, e := range ents {
				if e.Name() != fmt.Sprintf("n%06d", i) {
					t.Fatalf("entry %d is %s: the order is by name", i, e.Name())
				}
			}
		})
	}
}

func TestReadDirOfTheRootAtTheLimitOfNames(t *testing.T) {
	f := newMemFS()
	f.addNames(".", fsx.MaxDirEntries+1)
	root := f.Root()
	defer func() { _ = root.Close() }()
	_, err := fsx.ReadDir(root, ".")
	fe := asError(t, err)
	if !errors.Is(err, fsx.ErrTooMany) || fe.Step != fsx.StepRead || fe.Path != "." {
		t.Fatalf("got %v, want a read error at . that wraps ErrTooMany", err)
	}
}

// TestReadDirChecksTheLimitAgainForAnFSThatDoesNotKeepIt: the package function does not trust the
// FS, whose own promise is the first check.
func TestReadDirChecksTheLimitAgainForAnFSThatDoesNotKeepIt(t *testing.T) {
	for _, c := range []struct {
		n       int
		tooMany bool
	}{{fsx.MaxDirEntries, false}, {fsx.MaxDirEntries + 1, true}, {fsx.MaxDirEntries + 5000, true}} {
		f := newMemFS("b")
		f.addNames("b", c.n)
		f.ignoreDirLimit = true
		root := f.Root()
		ents, err := fsx.ReadDir(root, "b")
		_ = root.Close()
		if !c.tooMany {
			if err != nil || len(ents) != c.n {
				t.Fatalf("%d names: %d entries, %v", c.n, len(ents), err)
			}
			continue
		}
		want := fmt.Sprintf(`fsx: read "b": %s: %d names, more than 65536`, textTooMany, c.n)
		if !errors.Is(err, fsx.ErrTooMany) || err.Error() != want || ents != nil {
			t.Fatalf("%d names: %d entries, %v, want ErrTooMany with the text\n  %s", c.n, len(ents), err, want)
		}
	}
}

func TestTheHandlesAreClosedAfterATooLargeRead(t *testing.T) {
	f := newMemFS("b")
	f.addNames("b", fsx.MaxDirEntries+1)
	f.addFile("j", bytes.Repeat([]byte("x\n"), fsx.MaxJournalLines+1))
	root := f.Root()
	defer func() { _ = root.Close() }()
	if _, err := fsx.ReadDir(root, "b"); !errors.Is(err, fsx.ErrTooMany) {
		t.Fatal(err)
	}
	if _, _, err := fsx.ReadJournal(root, "j"); !errors.Is(err, fsx.ErrTooMany) {
		t.Fatal(err)
	}
	if d, fl := f.handles(); d != 1 || fl != 0 {
		t.Fatalf("%d folders and %d files open (%s), want the root alone", d, fl, f.describeOpen())
	}
}
