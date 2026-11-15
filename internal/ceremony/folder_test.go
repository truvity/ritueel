package ceremony_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/strictjson"
	"ritueel.id/ritueel/internal/wanted"
)

// wantKind fails unless err is a *FolderError that is of every kind that is named, whose text is
// printable ASCII and not long.
func wantKind(t testing.TB, err error, kinds ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want one of kind %v", kinds)
	}
	for _, k := range kinds {
		if !errors.Is(err, k) {
			t.Errorf("error %q is not of kind %q", err, k)
		}
	}
	var fe *ceremony.FolderError
	if !errors.As(err, &fe) {
		t.Fatalf("error %T is not a *FolderError: %v", err, err)
	}
	if fe.Op == "" || fe.Reason == "" {
		t.Errorf("FolderError with an empty Op or Reason: %+v", fe)
	}
	text := err.Error()
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] > 0x7e {
			t.Errorf("the error text holds the byte %#x: %.100q", text[i], text)
			break
		}
	}
	if len(text) > 1200 {
		t.Errorf("the error text is %d bytes", len(text))
	}
}

func TestNewFolderChecksTheNameAndTouchesNoDisk(t *testing.T) {
	b := newBundle(t)
	before := tree(t, b.dir)
	good := []string{name1, "a", "20261114T100000Z-apply-3fa9c1d2", strings.Repeat("a", 255), "A.b_c-d", "history"}
	for _, n := range good {
		if _, err := ceremony.NewFolder(b.w, n); err != nil {
			t.Errorf("NewFolder(%.30q) = %v", n, err)
		}
	}
	bad := []string{
		"", ".", "..", "a b", " a", "a ", ".rt-abc", ".RT-ABCDEF", ".Rt-x", "a/b", "/a", "a\\b", "a:b",
		strings.Repeat("a", 256), "a\x00b", "a\nb", "\x1b[31m", "caf\xc3\xa9", "\xff\xfe", "a\u202eb", "nul", "COM1", "a.",
		"a*", "a?", "a|b", "a\"b", "a<b", "a>b", "a\tb", "a\u00a0b",
	}
	for _, n := range bad {
		f, err := ceremony.NewFolder(b.w, n)
		if err == nil || f != nil {
			t.Errorf("NewFolder(%.30q) = %v, %v; want an error and no folder", n, f, err)
			continue
		}
		wantKind(t, err, ceremony.ErrInvalidInput)
		if err := fsx.CheckName(n); err == nil {
			t.Errorf("fsx.CheckName accepts %.30q, which the test calls bad", n)
		}
	}
	if f, err := ceremony.NewFolder(nil, name1); err == nil || f != nil {
		t.Errorf("NewFolder with no writer = %v, %v", f, err)
	} else {
		wantKind(t, err, ceremony.ErrInvalidInput)
	}
	if got := b.r.snapshot(); len(got) != 0 {
		t.Errorf("NewFolder reached the file system: %v", got)
	}
	sameTree(t, "NewFolder", before, tree(t, b.dir))
}

// every method of a nil, a zero and a new-but-not-made Folder returns an error and writes nothing.
func TestZeroAndNilFolderFailClosed(t *testing.T) {
	b := newBundle(t)
	before := tree(t, b.dir)
	s := newSpec(name1, 1, "")
	plan := s.plan(t)
	for name, f := range map[string]*ceremony.Folder{"nil": nil, "zero": {}, "new(Folder)": new(ceremony.Folder)} {
		t.Run(name, func(t *testing.T) {
			wantKind(t, f.WritePlan(plan, s.copies), ceremony.ErrOutOfOrder)
			wantKind(t, adoptErr(f, plan), ceremony.ErrOutOfOrder)
			tr, err := f.Start(s.attempt(t, plan))
			if tr != nil {
				t.Error("Start returned a Trace with its error")
			}
			wantKind(t, err, ceremony.ErrOutOfOrder)
			wantKind(t, f.End(), ceremony.ErrOutOfOrder)
			wantKind(t, f.WriteTranscript([]byte("x\n")), ceremony.ErrOutOfOrder)
			out, err := f.Record(ceremony.RecordIn{Command: "apply", Outcome: "completed"})
			if out != nil {
				t.Error("Record returned bytes with its error")
			}
			wantKind(t, err, ceremony.ErrOutOfOrder)
		})
	}
	if got := b.r.snapshot(); len(got) != 0 {
		t.Errorf("a zero Folder reached the file system: %v", got)
	}
	sameTree(t, "a zero Folder", before, tree(t, b.dir))
}

// calls are the six calls of a Folder with arguments that are right for a Folder in its place.
func calls(t *testing.T, s *spec, plan []byte) map[string]func(f *ceremony.Folder) error {
	return map[string]func(f *ceremony.Folder) error{
		"WritePlan": func(f *ceremony.Folder) error { return f.WritePlan(plan, s.copies) },
		"Adopt":     func(f *ceremony.Folder) error { return adoptErr(f, plan) },
		"Start": func(f *ceremony.Folder) error {
			tr, err := f.Start(s.attempt(t, plan))
			if err != nil && tr != nil {
				t.Error("Start returned a Trace with an error")
			}
			return err
		},
		"End":             func(f *ceremony.Folder) error { return f.End() },
		"WriteTranscript": func(f *ceremony.Folder) error { return f.WriteTranscript([]byte("a line\n")) },
		"Record": func(f *ceremony.Folder) error {
			out, err := f.Record(ceremony.RecordIn{Command: files.CommandApply, Outcome: files.OutcomeCompleted})
			if err != nil && out != nil {
				t.Error("Record returned bytes with an error")
			}
			return err
		},
	}
}

// For every state of a folder, every call but the one that the state allows is an error of kind
// ErrOutOfOrder, writes nothing, and does not stop the folder.
func TestEveryCallOutOfOrderIsRefusedAndWritesNothing(t *testing.T) {
	states := []struct {
		name, upTo, allow string
	}{
		{"new", "", "WritePlan"},
		{"planned", "plan", "Start"},
		{"started", "start", "End"},
		{"ended", "end", "WriteTranscript"},
		{"transcribed", "transcript", "Record"},
		{"recorded", "record", ""},
	}
	plan := newSpec(name1, 1, "").plan(t)
	names := []string{"WritePlan", "Adopt", "Start", "End", "WriteTranscript", "Record"}
	for _, st := range states {
		for _, call := range names {
			if call == st.allow || (st.name == "new" && call == "Adopt") {
				continue // Adopt is also a first call; it reads a folder that is not there
			}
			t.Run(st.name+"/"+call, func(t *testing.T) {
				b := newBundle(t)
				s := newSpec(name1, 1, "")
				fl := newFlow(t, b, s)
				if st.upTo != "" {
					fl.must(st.upTo)
				}
				before, events := tree(t, b.dir), b.r.mark()
				err := calls(t, s, plan)[call](fl.f)
				wantKind(t, err, ceremony.ErrOutOfOrder)
				if errors.Is(err, ceremony.ErrFolderStopped) || errors.Is(err, fsx.ErrStopped) {
					t.Error("a call out of order stopped the folder")
				}
				if got := b.r.since(events); len(got) != 0 {
					t.Errorf("the call reached the file system: %v", got)
				}
				sameTree(t, call+" in the state "+st.name, before, tree(t, b.dir))
			})
		}
	}
}

// A call out of order, one by one, in a fresh folder: the disk and the file system are untouched,
// and the folder goes on afterwards.
func TestOutOfOrderCallThenTheRightOneStillWorks(t *testing.T) {
	cases := []struct {
		name string
		upTo string
		call func(fl *flow) error
		next string // the stage from which the rest of the ceremony continues
	}{
		{"Start before WritePlan", "", func(fl *flow) error { _, err := fl.f.Start(fl.s.attempt(t, fl.s.plan(t))); return err }, "plan"},
		{"End before Start", "plan", func(fl *flow) error { return fl.f.End() }, "start"},
		{"WriteTranscript before Start", "plan", func(fl *flow) error { return fl.f.WriteTranscript([]byte("x\n")) }, "start"},
		{"WriteTranscript before End", "start", func(fl *flow) error { return fl.f.WriteTranscript([]byte("x\n")) }, "births"},
		{"Record before the transcript", "end", func(fl *flow) error {
			_, err := fl.f.Record(ceremony.RecordIn{Command: "apply", Outcome: "completed"})
			return err
		}, "transcript"},
		{"WritePlan twice", "plan", func(fl *flow) error { return fl.f.WritePlan(fl.s.plan(t), fl.s.copies) }, "start"},
		{"Adopt after WritePlan", "plan", func(fl *flow) error { return adoptErr(fl.f, fl.s.plan(t)) }, "start"},
		{"Start twice", "start", func(fl *flow) error {
			_, err := fl.f.Start(fl.s.attempt(t, fl.s.plan(t)))
			return err
		}, "births"},
		{"WritePlan after Start", "start", func(fl *flow) error { return fl.f.WritePlan(fl.s.plan(t), fl.s.copies) }, "births"},
		{"End twice", "end", func(fl *flow) error { return fl.f.End() }, "transcript"},
		{"WriteTranscript twice", "transcript", func(fl *flow) error { return fl.f.WriteTranscript([]byte("again\n")) }, "artifacts"},
		{"a call after Record", "record", func(fl *flow) error {
			_, err := fl.f.Record(ceremony.RecordIn{Command: "apply", Outcome: "completed"})
			return err
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newBundle(t)
			fl := newFlow(t, b, newSpec(name1, 1, ""))
			if c.upTo != "" {
				fl.must(c.upTo)
			}
			before, events := tree(t, b.dir), b.r.mark()
			wantKind(t, c.call(fl), ceremony.ErrOutOfOrder)
			if got := b.r.since(events); len(got) != 0 {
				t.Errorf("the refused call reached the file system: %v", got)
			}
			sameTree(t, c.name, before, tree(t, b.dir))
			if c.next == "" {
				return
			}
			start := 0
			for i, st := range stages {
				if st == c.next {
					start = i
				}
			}
			for _, st := range stages[start:] {
				if err := fl.step(st); err != nil {
					t.Fatalf("after the refused call, stage %s: %v", st, err)
				}
			}
			if rep := b.check(); !rep.Clean() || rep.Records != 1 {
				t.Errorf("the ceremony after a refused call: %+v", rep.Findings)
			}
		})
	}
}

// WritePlan makes history/ only when it is absent, and a name that is taken is refused before any
// write, without stopping the writer.
func TestWritePlanMakesHistoryOnlyWhenAbsent(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		b := newBundle(t)
		newFlow(t, b, newSpec(name1, 1, "")).must("plan")
		n := 0
		for _, e := range b.r.snapshot() {
			if e == "mkdir history" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("history/ was made %d times, want once", n)
		}
	})
	t.Run("present", func(t *testing.T) {
		b := newBundle(t)
		if err := os.Mkdir(b.path("history"), 0o755); err != nil {
			t.Fatal(err)
		}
		newFlow(t, b, newSpec(name1, 1, "")).must("")
		for _, e := range b.r.snapshot() {
			if e == "mkdir history" {
				t.Error("an existing history/ was made again")
			}
		}
		if rep := b.check(); !rep.Clean() || rep.Records != 1 {
			t.Errorf("findings %+v", rep.Findings)
		}
	})
	t.Run("two ceremonies, one history", func(t *testing.T) {
		b := newBundle(t)
		fl := newFlow(t, b, newSpec(name1, 1, ""))
		fl.must("")
		fl2 := newFlow(t, b, newSpec(name2, 2, sum(fl.out)))
		fl2.must("")
		n := 0
		for _, e := range b.r.snapshot() {
			if e == "mkdir history" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("history/ was made %d times for two ceremonies", n)
		}
	})
}

func TestWritePlanRefusesATakenNameWithoutStoppingTheWriter(t *testing.T) {
	cases := map[string]func(t *testing.T, b *bundle){
		"a folder":                    func(t *testing.T, b *bundle) { mustMkdir(t, b.path("history", name1)) },
		"a folder with another case":  func(t *testing.T, b *bundle) { mustMkdir(t, b.path("history", strings.ToUpper(name1))) },
		"a folder with a lower case":  func(t *testing.T, b *bundle) { mustMkdir(t, b.path("history", strings.ToLower(name1))) },
		"a file":                      func(t *testing.T, b *bundle) { mustWrite(t, b.path("history", name1), "x") },
		"a link":                      func(t *testing.T, b *bundle) { mustLink(t, "elsewhere", b.path("history", name1)) },
		"a dangling link, other case": func(t *testing.T, b *bundle) { mustLink(t, "nowhere", b.path("history", strings.ToLower(name1))) },
		"a leftover that is the folder": func(t *testing.T, b *bundle) {
			mustMkdir(t, b.path("history", name1))
			mustWrite(t, b.path("history", name1, "plan.json"), "{}")
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			mustMkdir(t, b.path("history"))
			setup(t, b)
			s := newSpec(name1, 1, "")
			f, err := ceremony.NewFolder(b.w, name1)
			if err != nil {
				t.Fatal(err)
			}
			before := tree(t, b.dir)
			err = f.WritePlan(s.plan(t), s.copies)
			wantKind(t, err, fs.ErrExist)
			if errors.Is(err, ceremony.ErrFolderStopped) || errors.Is(err, fsx.ErrStopped) {
				t.Errorf("a taken name stopped the folder: %v", err)
			}
			if got := b.r.snapshot(); len(got) != 0 {
				t.Errorf("a taken name reached the file system with changes: %v", got)
			}
			sameTree(t, "WritePlan on a taken name", before, tree(t, b.dir))
			// The writer is not stopped: a write of another name works.
			if err := b.w.Mkdir("history/"+name2, 0o755); err != nil {
				t.Errorf("the writer is stopped after a taken name: %v", err)
			}
			// And the folder is not stopped either: a call out of order still says so.
			wantKind(t, f.End(), ceremony.ErrOutOfOrder)
		})
	}
}

func TestWritePlanRefusesAHistoryThatIsNotAFolder(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, b *bundle){
		"a file": func(t *testing.T, b *bundle) { mustWrite(t, b.path("history"), "x") },
		"a link to a folder": func(t *testing.T, b *bundle) {
			mustMkdir(t, b.path("elsewhere"))
			mustLink(t, "elsewhere", b.path("history"))
		},
		"a dangling link": func(t *testing.T, b *bundle) { mustLink(t, "nowhere", b.path("history")) },
	} {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			setup(t, b)
			s := newSpec(name1, 1, "")
			f, _ := ceremony.NewFolder(b.w, name1)
			before := tree(t, b.dir)
			err := f.WritePlan(s.plan(t), s.copies)
			if err == nil {
				t.Fatal("WritePlan went on through a history that is not a folder")
			}
			if got := b.r.snapshot(); len(got) != 0 {
				t.Errorf("changes reached the file system: %v", got)
			}
			sameTree(t, "WritePlan", before, tree(t, b.dir))
			if errors.Is(err, ceremony.ErrFolderStopped) || errors.Is(err, fsx.ErrStopped) {
				t.Errorf("a history/ that is not a folder stopped the folder: %v", err)
			}
			// The writer is not stopped, and the person who puts history/ right finds the same
			// Folder ready.
			if err := b.w.Mkdir("other-folder", 0o755); err != nil {
				t.Errorf("the writer is stopped: %v", err)
			}
			if err := os.Remove(b.path("history")); err != nil {
				t.Fatal(err)
			}
			if err := f.WritePlan(s.plan(t), s.copies); err != nil {
				t.Errorf("WritePlan after history/ was put right: %v", err)
			}
		})
	}
}

func mustMkdir(t testing.TB, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t testing.TB, p, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustLink(t testing.TB, target, p string) {
	t.Helper()
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

// pathOf makes a path of n elements ending in a file name.
func pathOf(n int) string {
	e := make([]string, n)
	for i := range e {
		e[i] = "d"
	}
	e[n-1] = "f.yaml"
	return strings.Join(e, "/")
}

// planFor makes the plan of s with exactly the wanted files named by copies, and returns it.
func planFor(t testing.TB, s *spec, copies []wanted.File) []byte {
	t.Helper()
	c := *s
	c.copies = copies
	return c.plan(t)
}

// Every plan and copy that the folder refuses before it writes: ErrInvalidInput, nothing written,
// and the same Folder takes the right plan afterwards.
func TestWritePlanRefusesBadInputBeforeAnyWrite(t *testing.T) {
	base := func() []wanted.File {
		return []wanted.File{wantedFile("ritueel.yaml", "version: 1\n"), wantedFile("want/roots/x509.yaml", "kind: x509\n")}
	}
	s0 := newSpec(name1, 1, "")
	good := planFor(t, s0, base())
	altered := func(f func(c []wanted.File) []wanted.File) []wanted.File { return f(base()) }
	big := strings.Repeat("x", 100)

	type tc struct {
		name   string
		plan   func() []byte
		copies []wanted.File
	}
	other := newSpec("20261114T120000Z-apply", 1, "")
	cases := []tc{
		{"no plan", func() []byte { return nil }, base()},
		{"an empty plan", func() []byte { return []byte{} }, base()},
		{"a plan that is not JSON", func() []byte { return []byte("not json") }, base()},
		{"a plan over the size limit", func() []byte { return bytes.Repeat([]byte{' '}, strictjson.DefaultMaxBytes+1) }, base()},
		{"a plan with a line feed at its end", func() []byte { return append(append([]byte{}, good...), '\n') }, base()},
		{"a plan with spaces (not canonical)", func() []byte {
			return bytes.Replace(good, []byte(`"command":"apply"`), []byte(`"command": "apply"`), 1)
		}, base()},
		{"a plan of another ceremony", func() []byte { return planFor(t, other, base()) }, base()},
		{"a plan with another version", func() []byte { return bytes.Replace(good, []byte(`"version":1`), []byte(`"version":2`), 1) }, base()},
		{"a plan with no trust_sequence", func() []byte { return bytes.Replace(good, []byte(`"trust_sequence":1`), []byte(`"x":1`), 1) }, base()},
		{"no copies", func() []byte { return good }, nil},
		{"a copy missing", func() []byte { return good }, base()[:1]},
		{"a copy too many", func() []byte { return good }, append(base(), wantedFile("extra.yaml", "x"))},
		{"a copy with another path", func() []byte { return good }, altered(func(c []wanted.File) []wanted.File { c[1].Path = "want/roots/other.yaml"; return c })},
		{"a copy with other bytes", func() []byte { return good }, altered(func(c []wanted.File) []wanted.File { c[1].Data = []byte("kind: ssh\n"); c[1].SHA256 = ""; return c })},
		{"a copy whose own digest is wrong", func() []byte { return good }, altered(func(c []wanted.File) []wanted.File { c[1].SHA256 = rep('9'); return c })},
		{"a copy given twice", func() []byte { return good }, altered(func(c []wanted.File) []wanted.File { c[1] = c[0]; return c })},
		{"a copy whose digest is an upper-case one", func() []byte { return good }, altered(func(c []wanted.File) []wanted.File { c[1].SHA256 = strings.ToUpper(c[1].SHA256); return c })},
		{"a copy of a path of 13 elements", func() []byte {
			return planFor(t, s0, []wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile(pathOf(13), "k")})
		},
			[]wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile(pathOf(13), "k")}},
		{"an absolute path", func() []byte {
			return planFor(t, s0, []wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile("/etc/x.yaml", "k")})
		},
			[]wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile("/etc/x.yaml", "k")}},
		{"a path with ..", func() []byte {
			return planFor(t, s0, []wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile("../x.yaml", "k")})
		},
			[]wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile("../x.yaml", "k")}},
		{"a path with a backslash", func() []byte {
			return planFor(t, s0, []wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile(`a\b.yaml`, "k")})
		},
			[]wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile(`a\b.yaml`, "k")}},
		{"a path with an escape character", func() []byte {
			return planFor(t, s0, []wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile("a\x1b[31m.yaml", "k")})
		},
			[]wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile("a\x1b[31m.yaml", "k")}},
		{"a path that is a temporary name", func() []byte {
			return planFor(t, s0, []wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile(".rt-abcdefghij", "k")})
		},
			[]wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile(".rt-abcdefghij", "k")}},
		{"two paths that differ only in case", func() []byte {
			return planFor(t, s0, []wanted.File{wantedFile("A/x.yaml", "v"), wantedFile("a/y.yaml", "k")})
		},
			[]wanted.File{wantedFile("A/x.yaml", "v"), wantedFile("a/y.yaml", "k")}},
		{"the same file in two cases", func() []byte {
			return planFor(t, s0, []wanted.File{wantedFile("x.yaml", "v"), wantedFile("X.yaml", "k")})
		},
			[]wanted.File{wantedFile("x.yaml", "v"), wantedFile("X.yaml", "k")}},
		{"a file that is also a folder", func() []byte { return planFor(t, s0, []wanted.File{wantedFile("a", "v"), wantedFile("a/b", "k")}) },
			[]wanted.File{wantedFile("a", "v"), wantedFile("a/b", "k")}},
		{"a file that is also a folder, other case", func() []byte { return planFor(t, s0, []wanted.File{wantedFile("A", "v"), wantedFile("a/b", "k")}) },
			[]wanted.File{wantedFile("A", "v"), wantedFile("a/b", "k")}},
		{"a path listed twice by the plan", func() []byte {
			return planFor(t, s0, []wanted.File{wantedFile("a.yaml", "v"), wantedFile("a.yaml", "v"), wantedFile("b.yaml", big)})
		}, []wanted.File{wantedFile("a.yaml", "v"), wantedFile("b.yaml", big), wantedFile("c.yaml", "z")}},
		{"a plan that lists no wanted file", func() []byte {
			s := *s0
			s.edit = func(m map[string]any) { delete(m, "wanted") }
			return s.plan(t)
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newBundle(t)
			f, err := ceremony.NewFolder(b.w, name1)
			if err != nil {
				t.Fatal(err)
			}
			before := tree(t, b.dir)
			err = f.WritePlan(c.plan(), c.copies)
			wantKind(t, err, ceremony.ErrInvalidInput)
			if errors.Is(err, ceremony.ErrFolderStopped) {
				t.Error("an input that was refused stopped the folder")
			}
			if got := b.r.snapshot(); len(got) != 0 {
				t.Errorf("the refused input reached the file system: %v", got)
			}
			sameTree(t, "WritePlan", before, tree(t, b.dir))
			// The folder is still new, and the writer is not stopped: the right input works.
			if err := f.WritePlan(good, base()); err != nil {
				t.Fatalf("the right plan after a refused one: %v", err)
			}
		})
	}
}

// 1,002 wanted files are the most (ritueel.yaml, one more and the 1,000 of the listing); one more
// is refused before a write.
func TestWritePlanTakesAtMostMaxFilesPlusTwoCopies(t *testing.T) {
	mk := func(n int) []wanted.File {
		c := make([]wanted.File, n)
		for i := range c {
			c[i] = wantedFile("want/roots/r"+strings.Repeat("0", 5-len(itoa(i)))+itoa(i)+".yaml", "k")
		}
		return c
	}
	s := newSpec(name1, 1, "")
	over := mk(wanted.MaxFiles + 3)
	b := newBundle(t)
	f, _ := ceremony.NewFolder(b.w, name1)
	err := f.WritePlan(planFor(t, s, over), over)
	wantKind(t, err, ceremony.ErrInvalidInput)
	if got := b.r.snapshot(); len(got) != 0 {
		t.Errorf("%d changing calls for a plan with too many files", len(got))
	}
	if testing.Short() {
		t.Skip("writing 1,002 copies is slow")
	}
	at := mk(wanted.MaxFiles + 2)
	b2 := newBundle(t)
	f2, _ := ceremony.NewFolder(b2.w, name1)
	if err := f2.WritePlan(planFor(t, s, at), at); err != nil {
		t.Fatalf("1,002 copies: %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for ; i > 0; i /= 10 {
		d = append([]byte{byte('0' + i%10)}, d...)
	}
	return string(d)
}

// A path of 12 elements is the deepest; it is written and adopted.
func TestWritePlanTakesAPathOfTwelveElements(t *testing.T) {
	s := newSpec(name1, 1, "")
	copies := []wanted.File{wantedFile("ritueel.yaml", "v"), wantedFile(pathOf(files.MaxPathElements), "k")}
	plan := planFor(t, s, copies)
	b := newBundle(t)
	f, _ := ceremony.NewFolder(b.w, name1)
	if err := f.WritePlan(plan, copies); err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join(append([]string{"history", name1, "wanted"}, strings.Split(pathOf(12), "/")...)...)
	if got := b.read(rel); string(got) != "k" {
		t.Errorf("the deepest copy holds %q", got)
	}
	b2 := openBundle(t, b.dir, 0)
	h, _ := ceremony.NewFolder(b2.w, name1)
	if _, err := h.Adopt(plan); err != nil {
		t.Errorf("Adopt of a path of 12 elements: %v", err)
	}
}

// The plan and the copies are copied: a caller that changes its bytes after the call changes
// nothing that the folder wrote or later checks.
func TestWritePlanKeepsItsOwnCopyOfTheInput(t *testing.T) {
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	fl := newFlow(t, b, s)
	plan := s.plan(t)
	want := append([]byte(nil), plan...)
	copies := make([]wanted.File, len(s.copies))
	for i, c := range s.copies {
		copies[i] = wanted.File{Path: c.Path, Data: append([]byte(nil), c.Data...), SHA256: c.SHA256}
	}
	if err := fl.f.WritePlan(plan, copies); err != nil {
		t.Fatal(err)
	}
	for i := range plan {
		plan[i] = 'x'
	}
	for _, c := range copies {
		for i := range c.Data {
			c.Data[i] = 'y'
		}
	}
	if got := fl.file("plan.json"); !bytes.Equal(got, want) {
		t.Error("plan.json is not the plan that was given")
	}
	for _, c := range s.copies {
		if got := b.read("history", name1, "wanted", filepath.FromSlash(c.Path)); !bytes.Equal(got, c.Data) {
			t.Errorf("the copy %s is not the bytes that were given", c.Path)
		}
	}
	// The ceremony goes on and is recorded: the folder did not keep the caller's bytes.
	for _, st := range stages[1:] {
		if err := fl.step(st); err != nil {
			t.Fatalf("stage %s: %v", st, err)
		}
	}
	if rep := b.check(); !rep.Clean() || rep.Records != 1 {
		t.Errorf("findings %+v", rep.Findings)
	}
}

// flipAll changes every byte of what a caller gave, and the entries of its list of copies.
func flipAll(plan []byte, copies []wanted.File) {
	for i := range plan {
		plan[i] ^= 0xff
	}
	for i := range copies {
		for j := range copies[i].Data {
			copies[i].Data[j] ^= 0xff
		}
		copies[i].Path = "x/changed.yaml"
		copies[i].SHA256 = rep('9')
		copies[i].Data = []byte("replaced")
	}
}

// A caller that changes its plan and its copies at any moment of the call changes nothing: the
// call works on its own copy of them from its top. The caller's bytes are changed from inside the
// file system, once before each changing call, and at the read of history/ that comes before the
// first of them.
func TestWritePlanIsNotChangedByACallerThatChangesItsBytesDuringTheCall(t *testing.T) {
	moreCopies := func(s *spec) {
		s.copies = append(s.copies, wantedFile("want/a/b/c.yaml", "deep"), wantedFile("zz.yaml", "last"))
	}
	s0 := newSpec(name1, 1, "")
	moreCopies(s0)
	b0 := newBundle(t)
	newFlow(t, b0, s0).must("plan")
	total := b0.r.mark()
	if total < 20 {
		t.Fatalf("a WritePlan makes only %d changing calls", total)
	}
	for n := 0; n <= total; n++ {
		b := newBundle(t)
		s := newSpec(name1, 1, "")
		moreCopies(s)
		fl := newFlow(t, b, s)
		plan := s.plan(t)
		want := append([]byte(nil), plan...)
		copies := make([]wanted.File, len(s.copies))
		for i, c := range s.copies {
			copies[i] = wanted.File{Path: c.Path, Data: append([]byte(nil), c.Data...), SHA256: c.SHA256}
		}
		var once sync.Once
		fired := false
		change := func() { once.Do(func() { fired = true; flipAll(plan, copies) }) }
		if n == 0 {
			b.r.openHook = func(path string) {
				if path == "history" {
					change()
				}
			}
		} else {
			b.r.hook = func(i int, _ string) {
				if i == n {
					change()
				}
			}
		}
		if err := fl.f.WritePlan(plan, copies); err != nil {
			t.Fatalf("change at call %d: %v", n, err)
		}
		b.r.hook, b.r.openHook = nil, nil
		if !fired {
			t.Fatalf("change at call %d: the file system was never called at that point", n)
		}
		if got := fl.file("plan.json"); !bytes.Equal(got, want) {
			t.Fatalf("change at call %d: plan.json is not the plan that was given", n)
		}
		for _, c := range s.copies {
			if got := b.read("history", name1, "wanted", filepath.FromSlash(c.Path)); !bytes.Equal(got, c.Data) {
				t.Fatalf("change at call %d: the copy %s is not the bytes that were given", n, c.Path)
			}
		}
		if _, err := os.Lstat(b.path("history", name1, "wanted", "x")); err == nil {
			t.Fatalf("change at call %d: a path of the changed list was written", n)
		}
		// The folder of the same state as one that was not touched: it goes on to a record.
		for _, st := range stages[1:] {
			if err := fl.step(st); err != nil {
				t.Fatalf("change at call %d, stage %s: %v", n, st, err)
			}
		}
		if rep := b.check(); !rep.Clean() || rep.Records != 1 {
			t.Fatalf("change at call %d: findings %+v", n, rep.Findings)
		}
	}
}

// bigCopies makes the copies of a plan whose bytes are exactly total in all: ritueel.yaml and
// copies of 8 MiB that share one array of zeros, the last one the rest.
func bigCopies(total int) []wanted.File {
	const max = 8 << 20
	zeros := make([]byte, max)
	small := wantedFile("ritueel.yaml", "version: 1\nname: acme\n")
	copies := []wanted.File{small}
	left := total - len(small.Data)
	for i := 0; left > 0; i++ {
		n := min(left, max)
		d := zeros[:n:n]
		copies = append(copies, wanted.File{Path: fmt.Sprintf("want/big/f%02d.bin", i), Data: d, SHA256: sum(d)})
		left -= n
	}
	return copies
}

// The copies together are at most half of the bytes that Record reads in all, 128 MiB, so that a
// folder that is written can still be recorded: one byte more is refused before any write, and
// exactly that many pass the check and reach the writer.
func TestWritePlanTakesAtMost128MiBOfCopiesInAll(t *testing.T) {
	const limit = 128 << 20
	s := newSpec(name1, 1, "")
	t.Run("one byte over", func(t *testing.T) {
		copies := bigCopies(limit + 1)
		b := newBundle(t)
		f, _ := ceremony.NewFolder(b.w, name1)
		before := tree(t, b.dir)
		err := f.WritePlan(planFor(t, s, copies), copies)
		wantKind(t, err, ceremony.ErrInvalidInput)
		if !strings.Contains(err.Error(), "in all") {
			t.Errorf("the reason is not the one of the total: %v", err)
		}
		if errors.Is(err, ceremony.ErrFolderStopped) {
			t.Error("a refusal stopped the folder")
		}
		if got := b.r.snapshot(); len(got) != 0 {
			t.Errorf("a refused input reached the file system: %v", got)
		}
		sameTree(t, "WritePlan", before, tree(t, b.dir))
		// The Folder is still new: the right input is taken.
		good := newSpec(name1, 1, "")
		if err := f.WritePlan(good.plan(t), good.copies); err != nil {
			t.Errorf("the right input after the refusal: %v", err)
		}
	})
	t.Run("exactly the limit", func(t *testing.T) {
		copies := bigCopies(limit)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "ritueel.yaml"), []byte(manifestText), 0o644); err != nil {
			t.Fatal(err)
		}
		b := openBundle(t, dir, 1)
		f, _ := ceremony.NewFolder(b.w, name1)
		// The first changing call fails: the call went past every check of its input, to the writer.
		err := f.WritePlan(planFor(t, s, copies), copies)
		if !errors.Is(err, errCut) {
			t.Fatalf("a set of exactly 128 MiB did not reach the writer: %v", err)
		}
	})
	t.Run("many small ones that add up", func(t *testing.T) {
		copies := bigCopies(limit - 100)
		extra := wanted.File{Path: "want/extra.bin", Data: make([]byte, 101)}
		extra.SHA256 = sum(extra.Data)
		copies = append(copies, extra)
		b := newBundle(t)
		f, _ := ceremony.NewFolder(b.w, name1)
		err := f.WritePlan(planFor(t, s, copies), copies)
		wantKind(t, err, ceremony.ErrInvalidInput)
		if got := b.r.snapshot(); len(got) != 0 {
			t.Errorf("a refused input reached the file system: %v", got)
		}
	})
}
