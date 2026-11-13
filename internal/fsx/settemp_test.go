package fsx_test

// WriteSet lists its temporary folder right after it opens it, and stops if it is not empty: another
// actor can put something into the folder between the Mkdir and the OpenDir, and the files of the set
// must not be written beside it nor the folder renamed into place.

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

func TestWriteSetStopsWhenItsTemporaryFolderIsNotEmptyWhenOpened(t *testing.T) {
	for _, c := range []struct {
		name    string
		planted []nodeKind
	}{
		{"a file", []nodeKind{nodeFile}},
		{"a folder", []nodeKind{nodeDir}},
		{"a link", []nodeKind{nodeLink}},
		{"a FIFO", []nodeKind{nodeFifo}},
		{"three of them", []nodeKind{nodeFile, nodeDir, nodeLink}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newMemFS("b", "b/t")
			f.afterMkdir = func(f *memFS, made *node) {
				for i, k := range c.planted {
					f.plant(made, "planted"+string(rune('a'+i)), k)
				}
			}
			w := newWriter(t, f, 1)
			err := w.WriteSet("b/t/0007-acme", []fsx.NewFile{
				{Name: "keys.json", Data: []byte("keys"), Perm: 0o600},
				{Name: "root.json", Data: []byte("root"), Perm: 0o600},
			})
			fe := requireFailed(t, err)
			if fe.Step != fsx.StepOpenDir || !strings.HasPrefix(fe.Path, "b/t/"+fsx.TempPrefix) || strings.Count(fe.Path, "/") != 2 {
				t.Fatalf("got %v, want an open-dir error at the temporary folder", err)
			}
			if !errors.Is(err, fsx.ErrNotEmpty) {
				t.Fatalf("got %v, want an error that wraps ErrNotEmpty", err)
			}
			want := `: fsx: the temporary folder is not empty when it is opened: it holds ` + string(rune('0'+len(c.planted))) + ` entries`
			if !strings.HasSuffix(err.Error(), want) {
				t.Fatalf("the text is %q, want it to end with %q", err.Error(), want)
			}
			// nothing was written into it, nothing renamed, and what was planted is left
			for _, o := range f.opList() {
				switch o.Kind {
				case kCreate, kWrite, kSync, kClose, kRename, kSyncDir:
					t.Fatalf("a call after the listing that writes: %v", o)
				}
			}
			live := f.Live()
			if live.isDir("b/t/0007-acme") {
				t.Fatal("the folder of the set stands at its final name")
			}
			var tmp string
			for _, p := range live.list() {
				if strings.HasPrefix(p, "b/t/"+fsx.TempPrefix) && strings.Count(p, "/") == 2 {
					tmp = p
				}
			}
			if tmp != fe.Path {
				t.Fatalf("the temporary folder is %q, the error says %q", tmp, fe.Path)
			}
			var inside []string
			for _, p := range live.list() {
				if strings.HasPrefix(p, tmp+"/") && strings.Count(p, "/") == 3 {
					inside = append(inside, p[len(tmp)+1:])
				}
			}
			slices.Sort(inside)
			if len(inside) != len(c.planted) {
				t.Fatalf("the temporary folder holds %v, want only what was planted (%d)", inside, len(c.planted))
			}
			requireStoppedBy(t, w.Mkdir("b/other", 0o700), fe)
			requireOpen(t, f, 0)
		})
	}
}

func TestWriteSetListsItsTemporaryFolderOnceAndFindsItEmpty(t *testing.T) {
	f := newMemFS("b")
	w := newWriter(t, f, 1)
	if err := w.WriteSet("b/s", []fsx.NewFile{{Name: "a", Data: []byte("1"), Perm: 0o600}}); err != nil {
		t.Fatal(err)
	}
	lists := 0
	for _, o := range f.opList() {
		if o.Kind == kReadDir {
			lists++
			if !strings.HasPrefix(o.Path, "b/"+fsx.TempPrefix) {
				t.Fatalf("a listing of %s, want the temporary folder", o.Path)
			}
		}
	}
	if lists != 1 {
		t.Fatalf("%d listings, want one", lists)
	}
}

func TestAFailedListingOfTheTemporaryFolderStopsInTheSameStep(t *testing.T) {
	errList := errors.New("the stick could not list it")
	f := newMemFS("b")
	w := newWriter(t, f, 1)
	f.failOn(kReadDir, 1, errList)
	err := w.WriteSet("b/s", []fsx.NewFile{{Name: "a", Data: []byte("1"), Perm: 0o600}})
	fe := requireFailed(t, err)
	if fe.Step != fsx.StepOpenDir || !errors.Is(err, errList) || errors.Is(err, fsx.ErrNotEmpty) {
		t.Fatalf("got %v, want an open-dir error that wraps the cause and not ErrNotEmpty", err)
	}
	for _, o := range f.opList() {
		if o.Kind == kCreate || o.Kind == kRename {
			t.Fatalf("a call after the failed listing: %v", o)
		}
	}
}
