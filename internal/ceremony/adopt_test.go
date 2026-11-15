package ceremony_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/wanted"
)

// planned makes a planned folder with WritePlan and returns the bundle, the spec and the plan.
func planned(t *testing.T) (*bundle, *spec, []byte) {
	t.Helper()
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	fl := newFlow(t, b, s)
	fl.must("plan")
	return b, s, s.plan(t)
}

// adoptIn opens the bundle again, as another process does, and calls Adopt on a new Folder.
func adoptIn(t *testing.T, b *bundle, name string, plan []byte) (*ceremony.Folder, *bundle, error) {
	t.Helper()
	f, b2, _, err := adoptCopies(t, b, name, plan)
	return f, b2, err
}

// adoptCopies is adoptIn with the copies that Adopt returns.
func adoptCopies(t *testing.T, b *bundle, name string, plan []byte) (*ceremony.Folder, *bundle, []wanted.File, error) {
	t.Helper()
	b2 := openBundle(t, b.dir, 0)
	f, err := ceremony.NewFolder(b2.w, name)
	if err != nil {
		t.Fatal(err)
	}
	copies, err := f.Adopt(plan)
	return f, b2, copies, err
}

func TestAdoptTakesAFolderThatWritePlanMadeAndWritesNothing(t *testing.T) {
	b, s, plan := planned(t)
	before := tree(t, b.dir)
	f, b2, err := adoptIn(t, b, name1, plan)
	if err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	if got := b2.r.snapshot(); len(got) != 0 {
		t.Errorf("Adopt changed the file system: %v", got)
	}
	sameTree(t, "Adopt", before, tree(t, b.dir))

	// The adopted folder is a planned folder: the ceremony goes on from Start, and is whole.
	fl := &flow{t: t, b: b2, s: s, f: f, con: ceremony.NewConsole(&bytes.Buffer{}, &bytes.Buffer{})}
	for _, st := range stages[1:] {
		if err := fl.step(st); err != nil {
			t.Fatalf("stage %s after Adopt: %v", st, err)
		}
	}
	if rep := b2.check(); !rep.Clean() || rep.Records != 1 {
		t.Errorf("findings %+v", rep.Findings)
	}
}

func TestAdoptRefusesWhatIsNotTheFolderThatWasWritten(t *testing.T) {
	flip := func(p string, from, to string) func(t *testing.T, b *bundle) {
		return func(t *testing.T, b *bundle) {
			t.Helper()
			data := b.read(filepath.FromSlash(p))
			if !bytes.Contains(data, []byte(from)) {
				t.Fatalf("%s holds no %q", p, from)
			}
			if err := os.WriteFile(b.path(filepath.FromSlash(p)), bytes.Replace(data, []byte(from), []byte(to), 1), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	d := "history/" + name1 + "/"
	cases := map[string]func(t *testing.T, b *bundle){
		"plan.json changed by one byte": flip(d+"plan.json", "acme-card", "acme-cars"),
		"a copy changed by one byte":    flip(d+"wanted/want/roots/x509.yaml", "x509", "x508"),
		"a copy missing": func(t *testing.T, b *bundle) {
			if err := os.Remove(b.path("history", name1, "wanted", "ritueel.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"a deeper copy missing": func(t *testing.T, b *bundle) {
			if err := os.Remove(b.path("history", name1, "wanted", "want", "roots", "x509.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"an empty folder in wanted/": func(t *testing.T, b *bundle) { mustMkdir(t, b.path("history", name1, "wanted", "x")) },
		"an empty folder inside a listed folder": func(t *testing.T, b *bundle) {
			mustMkdir(t, b.path("history", name1, "wanted", "want", "roots", "y"))
		},
		"an empty folder inside a listed folder, one level up": func(t *testing.T, b *bundle) {
			mustMkdir(t, b.path("history", name1, "wanted", "want", "y"))
		},
		"a deeper empty folder in an unlisted folder": func(t *testing.T, b *bundle) {
			mustMkdir(t, b.path("history", name1, "wanted", "p", "q", "r"))
		},
		"a file in an unlisted folder": func(t *testing.T, b *bundle) {
			mustMkdir(t, b.path("history", name1, "wanted", "zz"))
			mustWrite(t, b.path("history", name1, "wanted", "zz", "f.yaml"), "x")
		},
		"a folder where a copy belongs": func(t *testing.T, b *bundle) {
			p := b.path("history", name1, "wanted", "want", "roots", "x509.yaml")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustMkdir(t, p)
		},
		"a link to a folder in wanted/": func(t *testing.T, b *bundle) {
			mustMkdir(t, b.path("elsewhere"))
			mustLink(t, b.path("elsewhere"), b.path("history", name1, "wanted", "dir"))
		},
		"an empty folder whose name is not UTF-8": func(t *testing.T, b *bundle) {
			mustMkdir(t, b.path("history", name1, "wanted", "d\xff\xfe"))
		},
		"a file whose name is not UTF-8": func(t *testing.T, b *bundle) {
			mustWrite(t, b.path("history", name1, "wanted", "f\xc3.yaml"), "x")
		},
		"a folder whose name has a bidirectional character": func(t *testing.T, b *bundle) {
			mustMkdir(t, b.path("history", name1, "wanted", "d\u202ex"))
		},
		"an extra file in wanted/": func(t *testing.T, b *bundle) { mustWrite(t, b.path("history", name1, "wanted", "extra.yaml"), "x") },
		"an extra file in a folder of wanted/": func(t *testing.T, b *bundle) {
			mustWrite(t, b.path("history", name1, "wanted", "want", "roots", "other.yaml"), "x")
		},
		"an extra entry in the ceremony folder": func(t *testing.T, b *bundle) {
			mustWrite(t, b.path("history", name1, "attempt.json"), "{}")
		},
		"a journal in the ceremony folder": func(t *testing.T, b *bundle) {
			mustWrite(t, b.path("history", name1, "births.jsonl"), "")
		},
		"a record in the ceremony folder": func(t *testing.T, b *bundle) {
			mustWrite(t, b.path("history", name1, "record.json"), "{}")
		},
		"a leftover temporary name in wanted/": func(t *testing.T, b *bundle) {
			mustWrite(t, b.path("history", name1, "wanted", ".rt-abcdefghijk"), "x")
		},
		"a leftover temporary name in the ceremony folder": func(t *testing.T, b *bundle) {
			mustWrite(t, b.path("history", name1, ".rt-abcdefghijk"), "x")
		},
		"a link in wanted/": func(t *testing.T, b *bundle) {
			mustLink(t, "ritueel.yaml", b.path("history", name1, "wanted", "link.yaml"))
		},
		"a link instead of a copy": func(t *testing.T, b *bundle) {
			p := b.path("history", name1, "wanted", "ritueel.yaml")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, b.path("elsewhere.yaml"), "version: 1\nname: acme\n")
			mustLink(t, b.path("elsewhere.yaml"), p)
		},
		"a pipe in wanted/": func(t *testing.T, b *bundle) {
			if err := syscall.Mkfifo(b.path("history", name1, "wanted", "pipe"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a folder where plan.json belongs": func(t *testing.T, b *bundle) {
			p := b.path("history", name1, "plan.json")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustMkdir(t, p)
		},
		"a link where plan.json belongs": func(t *testing.T, b *bundle) {
			p := b.path("history", name1, "plan.json")
			orig := b.read("history", name1, "plan.json")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, b.path("plan-elsewhere.json"), string(orig))
			mustLink(t, b.path("plan-elsewhere.json"), p)
		},
		"no plan.json": func(t *testing.T, b *bundle) {
			if err := os.Remove(b.path("history", name1, "plan.json")); err != nil {
				t.Fatal(err)
			}
		},
		"no wanted/": func(t *testing.T, b *bundle) {
			if err := os.RemoveAll(b.path("history", name1, "wanted")); err != nil {
				t.Fatal(err)
			}
		},
		"wanted that is a file": func(t *testing.T, b *bundle) {
			p := b.path("history", name1, "wanted")
			if err := os.RemoveAll(p); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, p, "x")
		},
		"a name wanted/ cannot hold": func(t *testing.T, b *bundle) {
			mustWrite(t, b.path("history", name1, "wanted", "a b.yaml"), "x")
		},
		"a name with an escape character": func(t *testing.T, b *bundle) {
			mustWrite(t, b.path("history", name1, "wanted", "a\x1b[31m"), "x")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b, _, plan := planned(t)
			mutate(t, b)
			before := tree(t, b.dir)
			f, b2, copies, err := adoptCopies(t, b, name1, plan)
			wantKind(t, err, ceremony.ErrDiskMismatch)
			if copies != nil {
				t.Errorf("a refused Adopt returned %d copies", len(copies))
			}
			if got := b2.r.snapshot(); len(got) != 0 {
				t.Errorf("a refused Adopt changed the file system: %v", got)
			}
			sameTree(t, "Adopt", before, tree(t, b.dir))
			// The folder stays new: it is not adopted, and a call that needs a planned folder is
			// out of order.
			wantKind(t, f.End(), ceremony.ErrOutOfOrder)
			_, err = f.Start(newSpec(name1, 1, "").attempt(t, plan))
			wantKind(t, err, ceremony.ErrOutOfOrder)
		})
	}
}

// A plan that is not the one on the disk, but is a good plan of this ceremony.
func TestAdoptRefusesAnotherPlanThanTheOneOnTheDisk(t *testing.T) {
	b, s, _ := planned(t)
	other := *s
	other.edit = func(m map[string]any) { m["made_at"] = "2026-11-14T10:00:01Z" }
	_, _, err := adoptIn(t, b, name1, other.plan(t))
	wantKind(t, err, ceremony.ErrDiskMismatch)
}

func TestAdoptRefusesABadPlanBeforeItReadsTheDisk(t *testing.T) {
	b, s, plan := planned(t)
	cases := map[string][]byte{
		"empty":         nil,
		"not JSON":      []byte("["),
		"not canonical": bytes.Replace(plan, []byte(`"command":"apply"`), []byte(`"command": "apply"`), 1),
		"other ceremony": func() []byte {
			o := newSpec("20261114T120000Z-apply", 1, "")
			o.copies = s.copies
			return o.plan(t)
		}(),
		"trailing line feed": append(append([]byte{}, plan...), '\n'),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			_, b2, err := adoptIn(t, b, name1, p)
			wantKind(t, err, ceremony.ErrInvalidInput)
			if got := b2.r.snapshot(); len(got) != 0 {
				t.Errorf("changes: %v", got)
			}
		})
	}
}

func TestAdoptOfAFolderThatIsNotThere(t *testing.T) {
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	f, _ := ceremony.NewFolder(b.w, name1)
	// no history/ at all, then a history/ with another folder
	wantKind(t, adoptErr(f, s.plan(t)), ceremony.ErrDiskMismatch)
	mustMkdir(t, b.path("history", name2))
	wantKind(t, adoptErr(f, s.plan(t)), ceremony.ErrDiskMismatch)
	if got := b.r.snapshot(); len(got) != 0 {
		t.Errorf("changes: %v", got)
	}
}

func TestAdoptIsRefusedWhenTheFolderIsALinkOrAFile(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, b *bundle){
		"a file": func(t *testing.T, b *bundle) { mustWrite(t, b.path("history", name1), "x") },
		"a link": func(t *testing.T, b *bundle) {
			mustMkdir(t, b.path("elsewhere"))
			mustLink(t, b.path("elsewhere"), b.path("history", name1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			mustMkdir(t, b.path("history"))
			setup(t, b)
			f, _ := ceremony.NewFolder(b.w, name1)
			err := adoptErr(f, newSpec(name1, 1, "").plan(t))
			if err == nil {
				t.Fatal("Adopt took a folder that is not a folder")
			}
			wantKind(t, f.End(), ceremony.ErrOutOfOrder)
		})
	}
}

// After a refusal that the person fixes, the same Folder adopts.
func TestAdoptAgainAfterTheFolderIsRepaired(t *testing.T) {
	b, _, plan := planned(t)
	p := b.path("history", name1, "wanted", "extra.yaml")
	mustWrite(t, p, "x")
	f, b2, err := adoptIn(t, b, name1, plan)
	wantKind(t, err, ceremony.ErrDiskMismatch)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Adopt(plan); err != nil {
		t.Errorf("Adopt after the repair: %v", err)
	}
	if got := b2.r.snapshot(); len(got) != 0 {
		t.Errorf("changes: %v", got)
	}
}

// A plan that has an attempt is not adopted: the page says that ritueel refuses to run that plan
// again, because its serials may have been used.
func TestAdoptRefusesAPlanThatHasAnAttempt(t *testing.T) {
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	newFlow(t, b, s).must("start")
	_, _, err := adoptIn(t, b, name1, s.plan(t))
	wantKind(t, err, ceremony.ErrDiskMismatch)
}

// wanted/ is bounded in the number of entries and in depth before Adopt reads a file.
func TestAdoptBoundsTheWalkOfWanted(t *testing.T) {
	t.Run("too many entries", func(t *testing.T) {
		b, _, plan := planned(t)
		dir := b.path("history", name1, "wanted", "many")
		mustMkdir(t, dir)
		for i := 0; i < 4*(wanted.MaxFiles+2)+1; i++ {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d", i)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		_, _, err := adoptIn(t, b, name1, plan)
		wantKind(t, err, ceremony.ErrDiskMismatch)
		if !strings.Contains(err.Error(), "more than") {
			t.Errorf("the refusal is not the one of the limit: %v", err)
		}
	})
	t.Run("twelve folders in a row are too deep", func(t *testing.T) {
		b, _, plan := planned(t)
		deep := []string{"history", name1, "wanted", "chain"}
		for i := 1; i < files.MaxPathElements; i++ {
			deep = append(deep, "d")
		}
		mustMkdir(t, b.path(deep...))
		_, _, err := adoptIn(t, b, name1, plan)
		wantKind(t, err, ceremony.ErrDiskMismatch)
		if !strings.Contains(err.Error(), "deeper") {
			t.Errorf("the refusal is not the one of the depth: %v", err)
		}
	})
	t.Run("too deep", func(t *testing.T) {
		b, _, plan := planned(t)
		deep := []string{"history", name1, "wanted"}
		for i := 0; i < 13; i++ {
			deep = append(deep, "d")
		}
		mustMkdir(t, b.path(deep...))
		_, _, err := adoptIn(t, b, name1, plan)
		wantKind(t, err, ceremony.ErrDiskMismatch)
	})
}

// The text of an error holds no byte beyond printable ASCII even when the folder holds a hostile
// name, and the name is escaped.
func TestAdoptErrorNamesAHostileEntryOnlyEscaped(t *testing.T) {
	b, _, plan := planned(t)
	mustWrite(t, b.path("history", name1, "wanted", "x\x1b[2J\u202e.yaml"), "x")
	_, _, err := adoptIn(t, b, name1, plan)
	wantKind(t, err, ceremony.ErrDiskMismatch)
	if strings.Contains(err.Error(), "\x1b") || strings.Contains(err.Error(), "\u202e") {
		t.Errorf("the error shows the raw name: %q", err)
	}
	var fe *ceremony.FolderError
	if !errors.As(err, &fe) || !strings.Contains(fe.Reason, `\x1b`) && !strings.Contains(fe.Reason, `\u001b`) {
		t.Errorf("the reason does not show the escape: %q", err)
	}
}

// adoptErr is Adopt for a caller that wants the error only.
func adoptErr(f *ceremony.Folder, plan []byte) error {
	_, err := f.Adopt(plan)
	return err
}

// plannedMany is a planned folder with copies in several folders, written by WritePlan.
func plannedMany(t *testing.T) (*bundle, *spec, []byte) {
	t.Helper()
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	s.copies = append(s.copies,
		wantedFile("zz.yaml", "version: 1\nlast: true\n"),
		wantedFile("want/a.yaml", "version: 1\nname: a\n"),
		wantedFile("want/a/b/c.yaml", "deep: true\n"),
		wantedFile("want/roots/x509.d/key.yaml", "key: 1\n"),
	)
	fl := newFlow(t, b, s)
	fl.must("plan")
	return b, s, s.plan(t)
}

// Adopt returns the copies that it read and compared, in the order of the plan's wanted list (the
// order of the paths), with the bytes and the digests of the files on the disk.
func TestAdoptReturnsTheCopiesItReadInTheOrderOfThePlan(t *testing.T) {
	b, s, plan := plannedMany(t)
	_, _, copies, err := adoptCopies(t, b, name1, plan)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{"ritueel.yaml", "want/a.yaml", "want/a/b/c.yaml", "want/roots/x509.d/key.yaml", "want/roots/x509.yaml", "zz.yaml"}
	if len(copies) != len(wantPaths) {
		t.Fatalf("%d copies, want %d", len(copies), len(wantPaths))
	}
	given := map[string]wanted.File{}
	for _, c := range s.copies {
		given[c.Path] = c
	}
	for i, c := range copies {
		if c.Path != wantPaths[i] {
			t.Errorf("copy %d is %s, want %s", i, c.Path, wantPaths[i])
		}
		if !bytes.Equal(c.Data, given[c.Path].Data) {
			t.Errorf("the bytes of %s are not the bytes that were written", c.Path)
		}
		if c.SHA256 != sum(c.Data) || c.SHA256 != given[c.Path].SHA256 {
			t.Errorf("the digest of %s is %s", c.Path, c.SHA256)
		}
	}
}

// The bytes that Adopt returns are the bytes that it compared: a file that is changed on the disk
// after Adopt is not in the result, and the result is what the plan lists.
func TestAdoptReturnsTheBytesItComparedAndNotAFreshRead(t *testing.T) {
	b, _, plan := plannedMany(t)
	b2 := openBundle(t, b.dir, 0)
	f, _ := ceremony.NewFolder(b2.w, name1)
	copies, err := f.Adopt(plan)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, b.path("history", name1, "wanted", "zz.yaml"), "changed after the adopt\n")
	for _, c := range copies {
		if c.Path == "zz.yaml" && string(c.Data) != "version: 1\nlast: true\n" {
			t.Errorf("the copy holds %q", c.Data)
		}
	}
}

// The result shares nothing with the Folder or with the caller: the caller changes the plan that it
// gave and every byte and entry of the result, and the ceremony goes on to a record that the check
// of the history finds clean; a second Adopt of the same folder returns the original bytes.
func TestAdoptResultSharesNothingWithTheFolder(t *testing.T) {
	b, s, plan := plannedMany(t)
	want := append([]byte(nil), plan...)
	f, b2, copies, err := adoptCopies(t, b, name1, plan)
	if err != nil {
		t.Fatal(err)
	}
	flipAll(plan, copies)
	fl := &flow{t: t, b: b2, s: s, f: f, con: ceremony.NewConsole(&bytes.Buffer{}, &bytes.Buffer{})}
	for _, st := range stages[1:] {
		if err := fl.step(st); err != nil {
			t.Fatalf("stage %s after Adopt: %v", st, err)
		}
	}
	if rep := b2.check(); !rep.Clean() || rep.Records != 1 {
		t.Errorf("findings %+v", rep.Findings)
	}
	if got := fl.file("plan.json"); !bytes.Equal(got, want) {
		t.Error("plan.json is not the plan")
	}
	// Two Adopts of one planned folder give two results that share no array: what the caller does
	// to the first changes nothing in the second.
	b3, _, plan3 := plannedMany(t)
	_, _, first, err := adoptCopies(t, b3, name1, plan3)
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		for j := range first[i].Data {
			first[i].Data[j] = 0
		}
	}
	_, _, second, err := adoptCopies(t, b3, name1, plan3)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range second {
		if c.SHA256 != sum(c.Data) {
			t.Errorf("the second result holds changed bytes for %s", c.Path)
		}
	}
	// The copies of one result do not share an array either.
	for i := range second {
		for j := range second {
			if i != j && len(second[i].Data) > 0 && len(second[j].Data) > 0 && &second[i].Data[0] == &second[j].Data[0] {
				t.Errorf("copies %d and %d share their bytes", i, j)
			}
		}
	}
}

// A copy of zero length is a copy: it is listed, read and returned with the digest of nothing.
func TestAdoptReturnsAnEmptyCopy(t *testing.T) {
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	s.copies = append(s.copies, wantedFile("want/empty.yaml", ""))
	newFlow(t, b, s).must("plan")
	_, _, copies, err := adoptCopies(t, b, name1, s.plan(t))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range copies {
		if c.Path == "want/empty.yaml" {
			found = true
			if len(c.Data) != 0 || c.SHA256 != sum(nil) {
				t.Errorf("the empty copy is %q, %s", c.Data, c.SHA256)
			}
		}
	}
	if !found {
		t.Error("the empty copy is not in the result")
	}
}

// An empty folder is refused wherever it stands, and after it is taken away the same Folder adopts.
func TestAdoptAfterAnEmptyFolderIsTakenAway(t *testing.T) {
	b, _, plan := plannedMany(t)
	p := b.path("history", name1, "wanted", "want", "a", "empty")
	mustMkdir(t, p)
	f, b2, copies, err := adoptCopies(t, b, name1, plan)
	wantKind(t, err, ceremony.ErrDiskMismatch)
	if copies != nil {
		t.Error("copies with an error")
	}
	if !strings.Contains(err.Error(), "folder") {
		t.Errorf("the reason does not say a folder: %v", err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	copies, err = f.Adopt(plan)
	if err != nil || len(copies) != 6 {
		t.Fatalf("Adopt after the repair: %d copies, %v", len(copies), err)
	}
	if got := b2.r.snapshot(); len(got) != 0 {
		t.Errorf("changes: %v", got)
	}
}

// sparseFolder writes the planned folder of copies of the given sizes without writing their bytes:
// each copy is a sparse file of zeros, and the plan lists the digest of those zeros.
func sparseFolder(t *testing.T, total int) (*bundle, []byte) {
	t.Helper()
	copies := bigCopies(total)
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	plan := planFor(t, s, copies)
	root := b.path("history", name1)
	mustMkdir(t, root)
	mustWrite(t, filepath.Join(root, "plan.json"), string(plan))
	for _, c := range copies {
		full := filepath.Join(root, "wanted", filepath.FromSlash(c.Path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if c.Path == "ritueel.yaml" {
			mustWrite(t, full, string(c.Data))
			continue
		}
		f, err := os.Create(full)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(int64(len(c.Data))); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	return b, plan
}

// The copies together are at most half of the bytes that Record reads in all, as for WritePlan:
// 128 MiB are adopted, and one byte more is refused as a mismatch.
func TestAdoptTakesAtMost128MiBOfCopiesInAll(t *testing.T) {
	if testing.Short() {
		t.Skip("reads 128 MiB of zeros")
	}
	const limit = 128 << 20
	t.Run("exactly the limit", func(t *testing.T) {
		b, plan := sparseFolder(t, limit)
		_, _, copies, err := adoptCopies(t, b, name1, plan)
		if err != nil {
			t.Fatalf("128 MiB: %v", err)
		}
		n := 0
		for _, c := range copies {
			n += len(c.Data)
		}
		if n != limit {
			t.Errorf("the copies hold %d bytes", n)
		}
	})
	t.Run("one byte over", func(t *testing.T) {
		b, plan := sparseFolder(t, limit+1)
		_, b2, copies, err := adoptCopies(t, b, name1, plan)
		wantKind(t, err, ceremony.ErrDiskMismatch)
		if !strings.Contains(err.Error(), "in all") {
			t.Errorf("the reason is not the one of the total: %v", err)
		}
		if copies != nil {
			t.Error("copies with an error")
		}
		if got := b2.r.snapshot(); len(got) != 0 {
			t.Errorf("changes: %v", got)
		}
	})
}

// A file that is renamed to a name that the plan does not list leaves the count of files right
// and the list wrong: the file that is there and not listed is refused by its name.
func TestAdoptRefusesAFileThatIsNotListedWhenTheCountIsRight(t *testing.T) {
	b, _, plan := plannedMany(t)
	from := b.path("history", name1, "wanted", "want", "a.yaml")
	to := b.path("history", name1, "wanted", "want", "b.yaml")
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
	_, _, copies, err := adoptCopies(t, b, name1, plan)
	wantKind(t, err, ceremony.ErrDiskMismatch)
	if copies != nil {
		t.Error("copies with an error")
	}
	if !strings.Contains(err.Error(), "does not list") {
		t.Errorf("the reason is not the one of a file that is not listed: %v", err)
	}
}
