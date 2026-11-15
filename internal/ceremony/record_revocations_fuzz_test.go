package ceremony_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/history"
)

// The two inputs of Folder.Record that come from outside the program in a ceremony of two kinds of
// key: the list of revocation entries (text here: one entry on each line, its three members
// divided by a bar) and the bytes of a root.json on the disk. The laws: no panic; a refusal is a
// *FolderError of the kind ErrInvalidInput or ErrDiskMismatch, in printable ASCII, with no byte
// written; a record that is written is the one that the plan asks for, read back by its reader, and
// the check of the history finds nothing in it.

func entriesFromText(data []byte) []files.RevocationEntry {
	var list []files.RevocationEntry
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, "|")
		var e files.RevocationEntry
		if len(parts) > 0 {
			e.Label = parts[0]
		}
		if len(parts) > 1 {
			e.Reason = parts[1]
		}
		if len(parts) > 2 {
			e.SHA256 = parts[2]
		}
		list = append(list, e)
		if len(list) > 200 {
			break
		}
	}
	return list
}

func textOfEntries(list []files.RevocationEntry) []byte {
	var lines []string
	for _, e := range list {
		lines = append(lines, e.Label+"|"+e.Reason+"|"+e.SHA256)
	}
	return []byte(strings.Join(lines, "\n"))
}

// fuzzTB is the testing.TB that the helpers of this package take, for a fuzz target: the methods
// that a fuzz target may not call on the F (Helper, Fatal, Error and the like) go to the T of the
// call that is running, and the folder of the files and the clean up stay with the F.
type fuzzTB struct {
	testing.TB
	cur  *testing.T
	root string
	mu   sync.Mutex
	done []func()
}

func (s *fuzzTB) TempDir() string {
	d, err := os.MkdirTemp(s.root, "k")
	if err != nil {
		panic(err)
	}
	return d
}

func (s *fuzzTB) Cleanup(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = append(s.done, f)
}

func (s *fuzzTB) Helper() {}
func (s *fuzzTB) Fatal(args ...any) {
	if s.cur != nil {
		s.cur.Fatal(args...)
	}
	s.TB.Fatal(args...)
}

func (s *fuzzTB) Fatalf(format string, args ...any) {
	if s.cur != nil {
		s.cur.Fatalf(format, args...)
	}
	s.TB.Fatalf(format, args...)
}

func (s *fuzzTB) Error(args ...any) {
	if s.cur != nil {
		s.cur.Error(args...)
		return
	}
	s.TB.Error(args...)
}

func (s *fuzzTB) Errorf(format string, args ...any) {
	if s.cur != nil {
		s.cur.Errorf(format, args...)
		return
	}
	s.TB.Errorf(format, args...)
}

// fuzzCeremony keeps one ceremony that stands before Record for as many calls as are refused, and
// makes another after one was written.
type fuzzCeremony struct {
	tb *fuzzTB
	k  *tk
}

func newFuzzCeremony(f *testing.F) *fuzzCeremony {
	tb := &fuzzTB{TB: f, root: f.TempDir()}
	f.Cleanup(func() {
		tb.mu.Lock()
		defer tb.mu.Unlock()
		for i := len(tb.done) - 1; i >= 0; i-- {
			tb.done[i]()
		}
	})
	return &fuzzCeremony{tb: tb}
}

func (z *fuzzCeremony) current() *tk {
	if z.k == nil {
		k, err := tryTK(z.tb, tkOpts{}, 0)
		if err != nil {
			z.tb.Fatal(err)
		}
		z.k = k
	}
	return z.k
}

// historyFails reports the findings that fail the check of the history of the ceremony's bundle.
func historyFails(t *testing.T, k *tk) []history.Finding {
	rep, err := history.Check(context.Background(), k.b.raw)
	if err != nil {
		t.Fatalf("history.Check: %v", err)
	}
	return rep.Failing()
}

func FuzzRecordRevocationList(f *testing.F) {
	z := newFuzzCeremony(f)
	good := z.current().wantRevocations()
	f.Add(textOfEntries(good))
	f.Add(textOfEntries(good[:2]))
	f.Add(textOfEntries(append(append([]files.RevocationEntry(nil), good...), good[0])))
	f.Add(textOfEntries([]files.RevocationEntry{good[1], good[0], good[2]}))
	f.Add([]byte(""))
	f.Add([]byte("\n\n"))
	f.Add([]byte("A|compromised|" + strings.Repeat("g", 64)))
	f.Add([]byte("a|retired|" + strings.Repeat("1", 64)))
	f.Add([]byte("\xff|\x00|\xfe"))
	f.Fuzz(func(t *testing.T, data []byte) {
		z.tb.cur = t
		defer func() { z.tb.cur = nil }()
		k := z.current()
		before := k.b.r.mark()
		list := entriesFromText(data)
		out, err := k.fl.f.Record(func() ceremony.RecordIn { in := k.recordIn(); in.Revocations = list; return in }())
		if err != nil {
			if out != nil {
				t.Fatalf("bytes come with the error %v", err)
			}
			if !errors.Is(err, ceremony.ErrInvalidInput) && !errors.Is(err, ceremony.ErrDiskMismatch) {
				t.Fatalf("the error is of no kind of a refused input: %v", err)
			}
			if errors.Is(err, ceremony.ErrFolderStopped) {
				t.Fatalf("a refusal stopped the folder: %v", err)
			}
			if txt := err.Error(); !pfPrintable(txt) || len(txt) > 4000 {
				t.Fatalf("the error text is not short and printable: %.200q", txt)
			}
			if got := k.b.r.since(before); len(got) != 0 {
				t.Fatalf("a refused record reached the file system: %v", got)
			}
			return
		}
		z.k = nil // the folder holds its record now
		r, err := files.ReadRecord(out)
		if err != nil {
			t.Fatalf("the reader refuses the record that was written: %v", err)
		}
		if !reflect.DeepEqual(r.Revocations, k.wantRevocations()) {
			t.Fatalf("a record was written with the list %+v, and the plan asks for %+v", r.Revocations, k.wantRevocations())
		}
		if f := historyFails(t, k); len(f) != 0 {
			t.Fatalf("history.Check finds %+v", f)
		}
	})
}

func FuzzRecordRootJSONOnDisk(f *testing.F) {
	z := newFuzzCeremony(f)
	k := z.current()
	good, err := os.ReadFile(k.b.path("roots", "A", "root.json"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(``))
	f.Add([]byte(strings.Replace(string(good), `"superseded"`, `"retired"`, 1)))
	f.Add([]byte(strings.Replace(string(good), `"revocations"`, `"revocation"`, 1)))
	f.Add(append(append([]byte(nil), good...), '\n'))
	f.Add([]byte(strings.Repeat("{", 5000)))
	f.Add([]byte("\xff\xfe"))
	f.Fuzz(func(t *testing.T, data []byte) {
		z.tb.cur = t
		defer func() { z.tb.cur = nil }()
		k := z.current()
		path := k.b.path("roots", "A", "root.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		before := k.b.r.mark()
		out, err := k.record(nil)
		if err != nil {
			if out != nil {
				t.Fatalf("bytes come with the error %v", err)
			}
			if errors.Is(err, ceremony.ErrFolderStopped) {
				t.Fatalf("a refusal stopped the folder: %v", err)
			}
			if txt := err.Error(); !pfPrintable(txt) || len(txt) > 4000 {
				t.Fatalf("the error text is not short and printable: %.200q", txt)
			}
			if got := k.b.r.since(before); len(got) != 0 {
				t.Fatalf("a refused record reached the file system: %v", got)
			}
			return
		}
		z.k = nil
		// A record is written only over a root.json that its reader takes and that holds the digests
		// of the list.
		rj, err := files.ReadRootJSON(data)
		if err != nil {
			t.Fatalf("a record was written over a root.json that its reader refuses: %v", err)
		}
		if rj.RemovalSHA256 != k.removal("A") || rj.Revocations["compromised"] != k.packet("A", "compromised") || rj.Revocations["superseded"] != k.packet("A", "superseded") {
			t.Fatalf("a record was written over a root.json that holds other digests: %+v", rj)
		}
	})
}
