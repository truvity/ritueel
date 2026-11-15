//go:build linux || darwin

package history

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// Things that a folder on disk can hold in place of a root list: a link, a pipe, a folder, a file
// of 8 MiB and a byte. They are made in a temporary folder; the run must end, and the list after
// them is judged as a list with no known list before it.

func TestRootReturnsRealFilesInPlaceOfARootList(t *testing.T) {
	kinds := map[string]func(b *bundle, p string){
		"a symbolic link to a file": func(b *bundle, p string) { b.symlink("keys.txt", p) },
		"a symbolic link to itself": func(b *bundle, p string) { b.symlink("root-list.json", p) },
		"a symbolic link out of the bundle": func(b *bundle, p string) {
			b.symlink("/etc/hostname", p)
		},
		"a pipe":             func(b *bundle, p string) { b.fifo(p) },
		"a folder":           func(b *bundle, p string) { b.mkdir(p) },
		"a file over 8 MiB":  func(b *bundle, p string) { b.sparse(p, 8<<20+1) },
		"a file of one byte": func(b *bundle, p string) { b.put(p, []byte("{")) },
	}
	for name, mk := range kinds {
		t.Run(name, func(t *testing.T) {
			b := chainBundle(t, false, inOrder(rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0), rootsJSON(0, ent{"A", pa, ""}))...)
			b.remove(listPathOf(setN(2)))
			mk(b, listPathOf(setN(2)))
			rep := b.run()
			has(t, rep, AnchorUnknown, listPathOf(setN(2)))
			got := returnsOf(rep)
			if len(got) != 1 || got[0].Path != listPathOf(setN(3)) || !strings.Contains(got[0].Detail, "cannot be read") {
				t.Errorf("findings %v", lines(got))
			}
			// Nothing was written to the bundle by the run.
			if _, err := os.Lstat(b.abs(listPathOf(setN(3)))); err != nil {
				t.Error(err)
			}
		})
	}
}

// A root list that is a symbolic link is not followed, so that a link to a list that exists makes no
// key known.
func TestRootReturnsALinkToAnotherRootListIsNotFollowed(t *testing.T) {
	b := chainBundle(t, false, inOrder(rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0), rootsJSON(0, ent{"A", pa, ""}))...)
	b.remove(listPathOf(setN(2)))
	b.symlink("../"+setN(1)+"/root-list.json", listPathOf(setN(2)))
	rep := b.run()
	got := returnsOf(rep)
	if len(got) != 1 || !strings.Contains(got[0].Detail, "cannot be read") {
		t.Errorf("findings %v", lines(got))
	}
}

// cancelAfterRead ends the context when a file of the name file has been read.
type cancelAfterRead struct {
	fsx.FS
	file   string
	cancel context.CancelFunc
}

func (c cancelAfterRead) OpenDir(name string) (fsx.FS, error) {
	d, err := c.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return cancelAfterRead{d, c.file, c.cancel}, nil
}

func (c cancelAfterRead) ReadFile(name string) ([]byte, error) {
	data, err := c.FS.ReadFile(name)
	if name == c.file {
		c.cancel()
	}
	return data, err
}

// A context that ends after the last root list was read stops the run with the error of the
// context and no report: the walk of the lists looks at its context.
func TestRootReturnsContextEndedAfterTheListsWereReadStopsTheRun(t *testing.T) {
	b := chainBundle(t, false, inOrder(rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0, ent{"B", pb, ""}))...)
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rep, err := Check(ctx, cancelAfterRead{FS: root, file: "root-list.json", cancel: cancel})
	if !errors.Is(err, context.Canceled) || rep != nil {
		t.Errorf("Check = %v, %v; want context.Canceled", rep, err)
	}
}

// The finding names the first list that held the fingerprint, under any pin, and not the last one
// (record 0006, rule 54: the fingerprint of an entry that left is on no later list, under any pin).
func TestRootReturnsNamesTheFirstListThatHeldTheFingerprint(t *testing.T) {
	rep := runLists(t,
		rootsJSON(0, ent{"A", pa, f1}),
		rootsJSON(0, ent{"A", pb, f1}),
		rootsJSON(0, ent{"A", pc, f1}),
		rootsJSON(0, ent{"D", pd, ""}),
		rootsJSON(0, ent{"A", pinOf(5), f1}),
	)
	// Lists 2 and 3 are swaps of the pin and have their own findings; the list of the question is 5.
	got := atPath(returnsOf(rep), listPathOf(setN(5)))
	if len(got) != 1 {
		t.Fatalf("%d findings at list 5: %v", len(got), lines(returnsOf(rep)))
	}
	for _, want := range []string{wFP(f1) + wRule, wHeldFP(setN(1)), wBefore(setN(4))} {
		if !strings.Contains(got[0].Detail, want) {
			t.Errorf("the detail %q lacks %q", got[0].Detail, want)
		}
	}
	// The same, with the entry under a pin that no list held: the first list that held it at all.
	rep = runLists(t,
		rootsJSON(0, ent{"A", pa, f1}),
		rootsJSON(0, ent{"A", pb, f1}),
		rootsJSON(0, ent{"D", pd, ""}),
		rootsJSON(0, ent{"E", pc, f1}),
	)
	got = atPath(returnsOf(rep), listPathOf(setN(4)))
	if len(got) != 1 || !strings.Contains(got[0].Detail, wFP(f1)+wRule+"; "+wHeldFP(setN(1))+"; "+wBefore(setN(3))) {
		t.Errorf("findings %v", lines(returnsOf(rep)))
	}
}

// atPath keeps the findings at one path.
func atPath(fs []Finding, path string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Path == path {
			out = append(out, f)
		}
	}
	return out
}
