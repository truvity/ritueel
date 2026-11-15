package ceremony_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// The copies of the wanted files have a limit of their own, half of what Record reads in all, so
// that a folder that WritePlan accepts can be recorded after the keys exist.
const copiesLimit = 128 << 20

// recordLimit is what Record reads in all.
const recordLimit = 256 << 20

// A folder whose copies are exactly at the limit is written by WritePlan, goes through the whole
// ceremony, and is recorded; the check of the history reads it clean.
func TestAFolderOfCopiesAtTheLimitIsWrittenAndRecorded(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 128 MiB")
	}
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	s.copies = bigCopies(copiesLimit)
	n := 0
	for _, c := range s.copies {
		n += len(c.Data)
	}
	if n != copiesLimit {
		t.Fatalf("the copies of the test hold %d bytes", n)
	}
	fl := newFlow(t, b, s)
	fl.must("")
	if rep := b.check(); !rep.Clean() || rep.Records != 1 {
		t.Errorf("findings %+v", rep.Findings)
	}
	var onDisk int64
	err := filepath.WalkDir(b.path("history", name1, "wanted"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			st, serr := d.Info()
			if serr != nil {
				return serr
			}
			onDisk += st.Size()
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if onDisk != copiesLimit {
		t.Errorf("the copies on the disk hold %d bytes, not %d", onDisk, copiesLimit)
	}
}

// One byte over the limit of the copies is refused by WritePlan before any write, and by Adopt as a
// mismatch of the folder; neither leaves anything that a second call cannot see.
func TestOneByteOverTheLimitOfTheCopiesLeavesNothingBehind(t *testing.T) {
	t.Run("WritePlan", func(t *testing.T) {
		s := newSpec(name1, 1, "")
		copies := bigCopies(copiesLimit + 1)
		b := newBundle(t)
		f, _ := ceremony.NewFolder(b.w, name1)
		before := tree(t, b.dir)
		err := f.WritePlan(planFor(t, s, copies), copies)
		wantKind(t, err, ceremony.ErrInvalidInput)
		if !strings.Contains(err.Error(), fmt.Sprint(copiesLimit)) {
			t.Errorf("the reason does not say the limit of %d bytes: %v", copiesLimit, err)
		}
		if got := b.r.snapshot(); len(got) != 0 {
			t.Errorf("a refused input reached the file system: %v", got)
		}
		sameTree(t, "WritePlan", before, tree(t, b.dir))
		// The same Folder, and a second Folder of the same name, take the right input.
		good := newSpec(name1, 1, "")
		if err := f.WritePlan(good.plan(t), good.copies); err != nil {
			t.Errorf("the right input after the refusal: %v", err)
		}
	})
	t.Run("WritePlan, the limit of Record", func(t *testing.T) {
		s := newSpec(name1, 1, "")
		copies := bigCopies(recordLimit)
		b := newBundle(t)
		f, _ := ceremony.NewFolder(b.w, name1)
		err := f.WritePlan(planFor(t, s, copies), copies)
		wantKind(t, err, ceremony.ErrInvalidInput)
		if got := b.r.snapshot(); len(got) != 0 {
			t.Errorf("a refused input reached the file system: %v", got)
		}
	})
	t.Run("Adopt", func(t *testing.T) {
		if testing.Short() {
			t.Skip("reads 128 MiB of zeros")
		}
		b, plan := sparseFolder(t, copiesLimit+1)
		before := tree(t, b.dir)
		f, b2, copies, err := adoptCopies(t, b, name1, plan)
		wantKind(t, err, ceremony.ErrDiskMismatch)
		if !strings.Contains(err.Error(), fmt.Sprint(copiesLimit)) {
			t.Errorf("the reason does not say the limit of %d bytes: %v", copiesLimit, err)
		}
		if copies != nil {
			t.Error("copies with an error")
		}
		if errors.Is(err, ceremony.ErrFolderStopped) {
			t.Error("a refusal stopped the folder")
		}
		if got := b2.r.snapshot(); len(got) != 0 {
			t.Errorf("Adopt changed the file system: %v", got)
		}
		sameTree(t, "Adopt", before, tree(t, b.dir))
		// The same Folder asks again and is refused again for the same reason: nothing was marked.
		if _, err := f.Adopt(plan); !errors.Is(err, ceremony.ErrDiskMismatch) {
			t.Errorf("a second Adopt: %v", err)
		}
	})
}

// A folder that WritePlan could write at the limit of the copies is recorded even when everything
// else that Record reads is as large as the rest of its limit lets it be: the folder of copies at the
// limit, and files that make Record read exactly 256 MiB, are recorded, and one byte more is not.
func TestAFolderOfCopiesAtTheLimitIsRecordedWithTheRestAtTheLimitOfRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("reads 256 MiB of zeros")
	}
	build := func(t *testing.T, extra int) *flow {
		t.Helper()
		b, plan := sparseFolder(t, copiesLimit)
		b2 := openBundle(t, b.dir, 0)
		f, err := ceremony.NewFolder(b2.w, name1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Adopt(plan); err != nil {
			t.Fatalf("Adopt: %v", err)
		}
		s := newSpec(name1, 1, "")
		s.copies = bigCopies(copiesLimit)
		fl := &flow{t: t, b: b2, s: s, f: f, con: ceremony.NewConsole(&strings.Builder{}, &strings.Builder{})}
		fl.skipTo("start")
		fl.must("artifacts")
		rest := 0
		err = filepath.WalkDir(b2.path("history", name1), func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				st, serr := d.Info()
				if serr != nil {
					return serr
				}
				rest += int(st.Size())
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		in := s.artifactPaths()
		for _, p := range in {
			rest += len(b2.read(filepath.FromSlash(p)))
		}
		left := recordLimit + extra - rest
		for i := 0; left > 0; i++ {
			n := min(left, fsx.MaxReadSize)
			left -= n
			p := fmt.Sprintf("big/f%02d.bin", i)
			full := b2.path(filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			file, err := os.Create(full)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(int64(n)); err != nil {
				t.Fatal(err)
			}
			_ = file.Close()
			in = append(in, p)
		}
		fl.in = func(ri *ceremony.RecordIn) { ri.Artifacts = in }
		return fl
	}
	t.Run("exactly the limit of Record", func(t *testing.T) {
		fl := build(t, 0)
		if err := fl.run(""); err != nil {
			t.Fatalf("copies at the limit and the rest of 256 MiB in all: %v", err)
		}
		if rep := fl.b.check(); !rep.Clean() || rep.Records != 1 {
			t.Errorf("findings %+v", rep.Findings)
		}
	})
	t.Run("one byte over the limit of Record", func(t *testing.T) {
		fl := build(t, 1)
		err := fl.run("")
		if err == nil {
			t.Fatal("256 MiB and one byte were recorded")
		}
		wantKind(t, errors.Unwrap(err), ceremony.ErrInvalidInput)
		noRecord(t, fl)
	})
}

// The limit of one copy is not the limit of all of them: a copy of exactly the size that fsx reads
// is taken, a byte more is refused, and the two limits stay as they were.
func TestTheLimitOfOneCopyStaysAsItWas(t *testing.T) {
	one := func(n int) []wanted.File {
		d := make([]byte, n)
		return append(newSpec(name1, 1, "").copies, wanted.File{Path: "want/one.bin", Data: d, SHA256: sum(d)})
	}
	for _, c := range []struct {
		name string
		n    int
		ok   bool
	}{
		{"exactly the size that fsx reads", fsx.MaxReadSize, true},
		{"one byte more", fsx.MaxReadSize + 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newBundle(t)
			f, _ := ceremony.NewFolder(b.w, name1)
			copies := one(c.n)
			err := f.WritePlan(planFor(t, newSpec(name1, 1, ""), copies), copies)
			if c.ok {
				if err != nil {
					t.Fatalf("WritePlan: %v", err)
				}
				return
			}
			wantKind(t, err, ceremony.ErrInvalidInput)
			if got := b.r.snapshot(); len(got) != 0 {
				t.Errorf("a refused input reached the file system: %v", got)
			}
		})
	}
}
