//go:build linux || darwin

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
)

// The fuzz targets of the command. Each reads no file of the machine and starts no program: the
// bundle is in memory, the report is a value, and the arguments are strings. The seeds run under
// "go test"; a person runs each target for a time with "go test -fuzz".

// ---------------------------------------------------------------------------------------------
// A bundle in memory.

type mnode struct {
	kind string // "file", "dir", "link", "fifo"
	data []byte
	kids map[string]*mnode
}

// memFS is a folder of a bundle in memory. It keeps the promises of fsx.FS that matter to a reader:
// it follows no link, a FIFO is not a regular file and is not waited on, a name that is not there
// is fs.ErrNotExist. A call that would write is counted and refused.
type memFS struct {
	n   *mnode
	log *memLog
}

type memLog struct{ writes []string }

var errMemWrite = errors.New("memFS: a write")

func newMem() *mnode { return &mnode{kind: "dir", kids: map[string]*mnode{}} }

// put makes the entry at path, with the folders before it.
func (m *mnode) put(path string, n *mnode) {
	cur := m
	parts := strings.Split(path, "/")
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur.kids[p]
		if !ok || next.kind != "dir" {
			next = newMem()
			cur.kids[p] = next
		}
		cur = next
	}
	cur.kids[parts[len(parts)-1]] = n
}

func (m *mnode) file(path, content string) { m.put(path, &mnode{kind: "file", data: []byte(content)}) }

func (f memFS) OpenDir(name string) (fsx.FS, error) {
	k, ok := f.n.kids[name]
	switch {
	case !ok:
		return nil, fmt.Errorf("open %s: %w", name, fs.ErrNotExist)
	case k.kind == "link":
		return nil, fmt.Errorf("open %s: %w", name, fsx.ErrLink)
	case k.kind != "dir":
		return nil, fmt.Errorf("open %s: not a directory", name)
	}
	return memFS{n: k, log: f.log}, nil
}

func (f memFS) ReadFile(name string) ([]byte, error) {
	k, ok := f.n.kids[name]
	switch {
	case !ok:
		return nil, fmt.Errorf("read %s: %w", name, fs.ErrNotExist)
	case k.kind == "link":
		return nil, fmt.Errorf("read %s: %w", name, fsx.ErrLink)
	case k.kind != "file":
		return nil, fmt.Errorf("read %s: %w", name, fsx.ErrNotRegular)
	case len(k.data) > fsx.MaxReadSize:
		return nil, fmt.Errorf("read %s: %w", name, fsx.ErrTooLarge)
	}
	return slices.Clone(k.data), nil
}

func (f memFS) ReadDir() ([]fs.DirEntry, error) {
	names := make([]string, 0, len(f.n.kids))
	for name := range f.n.kids {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]fs.DirEntry, 0, len(names))
	for _, name := range names {
		out = append(out, memEntry{name: name, n: f.n.kids[name]})
	}
	return out, nil
}

func (f memFS) Close() error { return nil }

func (f memFS) note(call string) { f.log.writes = append(f.log.writes, call) }

func (f memFS) Mkdir(name string, _ fs.FileMode) error { f.note("Mkdir " + name); return errMemWrite }
func (f memFS) CreateExcl(name string, _ fs.FileMode) (fsx.File, error) {
	f.note("CreateExcl " + name)
	return nil, errMemWrite
}
func (f memFS) RenameNoReplace(a, b string) error {
	f.note("Rename " + a + " " + b)
	return errMemWrite
}
func (f memFS) Sync() error { f.note("Sync"); return errMemWrite }

type memEntry struct {
	name string
	n    *mnode
}

func (e memEntry) Name() string { return e.name }
func (e memEntry) IsDir() bool  { return e.n.kind == "dir" }
func (e memEntry) Type() fs.FileMode {
	switch e.n.kind {
	case "dir":
		return fs.ModeDir
	case "link":
		return fs.ModeSymlink
	case "fifo":
		return fs.ModeNamedPipe
	}
	return 0
}
func (e memEntry) Info() (fs.FileInfo, error) { return memInfo{e}, nil }

type memInfo struct{ e memEntry }

func (i memInfo) Name() string       { return i.e.name }
func (i memInfo) Size() int64        { return int64(len(i.e.n.data)) }
func (i memInfo) Mode() fs.FileMode  { return i.e.Type() | 0o644 }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return i.e.IsDir() }
func (i memInfo) Sys() any           { return nil }

// memBundle is a bundle of two good ceremonies and a third whose files are the given bytes, with
// the manifest, the wanted copy and the keys as they should be.
func memBundle(record, transcript, attempt, plan, rootList string) *mnode {
	root := newMem()
	root.file("ritueel.yaml", "name: test\n")
	first := hbMake(1, "", true)
	second := hbMake(2, first.digest, true)
	third := hbMake(3, second.digest, false)
	for _, c := range []hbCeremony{first, second} {
		addCeremony(root, c)
	}
	base := "history/" + third.folder + "/"
	root.file(base+"record.json", record)
	root.file(base+"transcript.txt", transcript)
	root.file(base+"attempt.json", attempt)
	root.file(base+"plan.json", plan)
	root.file(base+"wanted/ritueel.yaml", third.wanted)
	root.file("trust/"+third.set+"/keys.txt", third.keys)
	root.file("trust/"+third.set+"/root-list.json", rootList)
	return root
}

func addCeremony(root *mnode, c hbCeremony) {
	base := c.base()
	root.file(base+"plan.json", c.plan)
	root.file(base+"attempt.json", c.attempt)
	root.file(base+"wanted/ritueel.yaml", c.wanted)
	root.file(base+"transcript.txt", c.transcript)
	root.file("trust/"+c.set+"/keys.txt", c.keys)
	root.file("trust/"+c.set+"/root-list.json", c.rootList)
	if c.record != "" {
		root.file(base+"record.json", c.record)
	}
}

// ---------------------------------------------------------------------------------------------
// What every outcome of the command holds.

var endLineForm = regexp.MustCompile(`^history: [0-9]+ ceremony records(, end [0-9a-f]{8})?\n$`)

// holdOutcome checks what is true of every result of the command, whatever the bundle was:
//   - an error is nothing written on standard error and no result, unless it is a refusal;
//   - a refusal has reasons, each a code the library has, no end line, and lines of printable ASCII;
//   - a result is exit code 0, with the end line in its form and the warnings the report had.
func holdOutcome(t *testing.T, res *Result, err error, stderr string) {
	t.Helper()
	if !onlyPrintable(stderr) {
		t.Fatalf("a byte outside printable ASCII on standard error: %q", stderr)
	}
	if strings.Contains(stderr, "\n\n") {
		t.Fatalf("an empty line: %q", stderr)
	}
	for _, l := range chLines(stderr) {
		if strings.HasPrefix(l, "history:") || strings.HasPrefix(l, "ritueel:") {
			t.Fatalf("a line that reads as the end line or as the program's: %q", l)
		}
	}
	switch {
	case err != nil && res != nil:
		t.Fatalf("a result and an error")
	case err == nil && res == nil:
		t.Fatalf("neither a result nor an error")
	case err != nil:
		code, _ := ExitFor(err)
		switch code {
		case ExitFailure:
			if stderr != "" {
				t.Fatalf("an error that did not check wrote lines: %q", stderr)
			}
		case ExitRefused:
			reasons := reasonsOf(err)
			if len(reasons) == 0 {
				t.Fatalf("a refusal with no reason")
			}
			for _, r := range reasons {
				if !slices.Contains(history.Codes(), history.Code(r)) {
					t.Fatalf("a reason that is not a code: %q", r)
				}
				if history.Code(r).Notice() {
					t.Fatalf("a notice is a reason: %q", r)
				}
			}
			for _, w := range warningsOf(err) {
				if !history.Code(w).Notice() {
					t.Fatalf("a warning that is not a notice: %q", w)
				}
			}
			if stderr == "" {
				t.Fatalf("a refusal with no line")
			}
		default:
			t.Fatalf("exit code %d", code)
		}
	default:
		if res.ExitCode != ExitOK || !endLineForm.MatchString(res.Text) || len(res.Reasons) != 0 || res.Error != "" {
			t.Fatalf("a result of %+v", res)
		}
		for _, w := range res.Warnings {
			if !history.Code(w).Notice() {
				t.Fatalf("a warning that is not a notice: %q", w)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------

// FuzzCheckHistoryBundle takes the bytes of the five files of the newest ceremony of a bundle and
// one entry with a hostile name in one of five places. Whatever they are: no panic, no write, the
// run ends, and the outcome holds what holdOutcome says. A second run on the same bundle gives the
// same outcome.
func FuzzCheckHistoryBundle(f *testing.F) {
	first := hbMake(1, "", true)
	second := hbMake(2, first.digest, true)
	whole := hbMake(3, second.digest, true)
	open := hbMake(3, second.digest, false)
	f.Add(whole.record, whole.transcript, whole.attempt, whole.plan, whole.rootList, "", uint8(0))
	f.Add(open.record, open.transcript, open.attempt, open.plan, open.rootList, "x", uint8(1))
	f.Add("", "", open.attempt, open.plan, open.rootList, "", uint8(0))
	f.Add(`{"version":2}`, "x", "{}", "{}", "{}", "a b", uint8(5))
	f.Add(`{`, "", "", "", "", "\x1b[0m", uint8(200))
	f.Add(whole.record+"\n", whole.transcript, whole.attempt, whole.plan, whole.rootList, "n", uint8(37))
	f.Add(strings.Repeat("[", 5000), "", "", "", "", "", uint8(9))
	f.Fuzz(func(t *testing.T, record, transcript, attempt, plan, rootList, name string, pick uint8) {
		root := memBundle(record, transcript, attempt, plan, rootList)
		if name != "" && !strings.ContainsAny(name, "/\x00") && name != "." && name != ".." {
			third := hbMake(3, second.digest, false)
			where := []string{"history", "trust", "history/" + third.folder, "trust/" + third.set, "history/" + third.folder + "/wanted"}[int(pick)%5]
			kind := []string{"file", "dir", "link", "fifo"}[int(pick/5)%4]
			n := &mnode{kind: kind, data: []byte("x")}
			if kind == "dir" {
				n.kids = map[string]*mnode{"record.json": {kind: "file", data: []byte("not a record")}}
			}
			root.put(where+"/"+name, n)
		}
		log := &memLog{}
		var out strings.Builder
		res, err := checkHistory(t.Context(), memFS{n: root, log: log}, &out)
		if len(log.writes) != 0 {
			t.Fatalf("a call that writes: %v", log.writes)
		}
		holdOutcome(t, res, err, out.String())

		var again strings.Builder
		res2, err2 := checkHistory(t.Context(), memFS{n: root, log: log}, &again)
		if again.String() != out.String() || (err == nil) != (err2 == nil) || (res == nil) != (res2 == nil) {
			t.Fatalf("a second run differs")
		}
		if res != nil && res.Text != res2.Text {
			t.Fatalf("the end line differs: %q and %q", res.Text, res2.Text)
		}
		if err != nil && err.Error() != err2.Error() {
			t.Fatalf("the error differs: %q and %q", err, err2)
		}
	})
}

// FuzzHistoryOutcome takes arbitrary strings for the code, the path and the detail of findings, and
// arbitrary numbers for the count and for what was left out, and builds a report in memory. Whatever
// it is: no panic, every line is one line of printable ASCII, and the exit code is 3 exactly when
// a finding has a code that fails.
func FuzzHistoryOutcome(f *testing.F) {
	f.Add("file-digest", "trust/1/keys.txt", "detail", "unexpected-file", "p", "d", 3, 0, goodEnd, uint8(1))
	f.Add("unexpected-file", "", "", "unfinished-ceremony", "trust/4", "open", 0, 5, "", uint8(0))
	f.Add("x\x1b[0m", "a\nb", "\xff\xfe", "\n", "\u202e", "\x00", -1, -7, "abc", uint8(2))
	f.Add("", "", "", "", "", "", 1<<40, 1<<40, strings.Repeat("g", 64), uint8(3))
	f.Add("fork", "p", strings.Repeat("d\n", 4000), "chain-broken", "q", "r", 1, 1, goodEnd, uint8(1))
	f.Fuzz(func(t *testing.T, code1, path1, detail1, code2, path2, detail2 string, records, omitted int, end string, nends uint8) {
		rep := &history.Report{
			Records: records,
			Findings: []history.Finding{
				{Code: history.Code(code1), Path: path1, Detail: detail1},
				{Code: history.Code(code2), Path: path2, Detail: detail2},
			},
			Omitted: omitted,
		}
		for i := 0; i < int(nends%4); i++ {
			rep.Ends = append(rep.Ends, end)
		}
		fails := history.Code(code1).Fails() || history.Code(code2).Fails()
		var out strings.Builder
		res, err := historyOutcome(rep, &out)
		stderr := out.String()
		if !onlyPrintable(stderr) {
			t.Fatalf("a byte outside printable ASCII: %q", stderr)
		}
		wantLines := 2
		if omitted > 0 {
			wantLines++
		}
		if stderr != "" && strings.Count(stderr, "\n") != wantLines {
			t.Fatalf("%d lines, want %d: %q", strings.Count(stderr, "\n"), wantLines, stderr)
		}
		switch {
		case fails:
			if res != nil || err == nil {
				t.Fatalf("a failing finding gave %v, %v", res, err)
			}
			if code, _ := ExitFor(err); code != ExitRefused {
				t.Fatalf("exit code %d for a failing finding", code)
			}
			if len(reasonsOf(err)) == 0 {
				t.Fatal("a refusal with no reason")
			}
		case err != nil:
			if code, _ := ExitFor(err); code != ExitFailure || stderr != "" {
				t.Fatalf("exit code %d with lines %q for a report that is not whole", code, stderr)
			}
		default:
			if res.ExitCode != ExitOK || !endLineForm.MatchString(res.Text) {
				t.Fatalf("%+v", res)
			}
			if records <= 0 && strings.Contains(res.Text, "end") {
				t.Fatalf("an end for no record: %q", res.Text)
			}
		}
		// The same through the program: the object is one object, whatever the report.
		r := runSynthetic(t, rep, "check", "history", "--output", "json")
		if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
			t.Fatalf("a byte outside printable ASCII: %q, %q", r.stdout, r.stderr)
		}
		if strings.Count(r.stdout, "\n") != 1 {
			t.Fatalf("standard output is not one object: %q", r.stdout)
		}
	})
}

// FuzzCheckHistoryArgs gives the program one argument of any bytes in three places. It is a usage
// error each time, whatever the bytes, and nothing that is not printable reaches the terminal.
func FuzzCheckHistoryArgs(f *testing.F) {
	for _, s := range []string{"", "x", "--", "-", "--dir", "--dir=/", "json", "text", "history", "\x1b[0m", "a\nb", "\xff", "\u0430", strings.Repeat("a", 5000), "-h", "--help", "--output=json"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, arg string) {
		for _, args := range [][]string{
			{"check", "history", "--", arg},
			{"check", "history", "--", arg, arg},
			{"--output", arg, "check", "history"},
			{"check", arg},
			{"--output", "json", "check", "history", "--", arg},
		} {
			// A word, a flag or an output mode that happens to be right makes a run that looks at the
			// current folder, which has no manifest here, so it is a usage error as well; the one
			// exception is a help flag.
			r := run(t, args...)
			// The library of flags reads a help flag in several spellings (-h, --h, -help, --help,
			// with white space around it or a value after an equals sign) as the help flag, and
			// help is exit code 0 with the usage on standard output.
			if isHelpFlag(arg) {
				continue
			}
			if r.code != ExitUsage {
				t.Fatalf("%q: exit %d, want 2: %q", args, r.code, r.stderr)
			}
			if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
				t.Fatalf("%q: a byte outside printable ASCII: %q %q", args, r.stdout, r.stderr)
			}
			if strings.Contains(r.stderr, "internal error") {
				t.Fatalf("%q: a panic: %q", args, r.stderr)
			}
		}
	})
}

// FuzzBundleDirName makes one entry of the current folder with the name of the bytes, and asks for
// the folder with no --dir. The answer is the current folder exactly when the name is the manifest
// and the entry is a regular file; otherwise it is a usage error that names --dir. It is never any
// other error and never a panic.
func FuzzBundleDirName(f *testing.F) {
	for _, s := range []string{"ritueel.yaml", "Ritueel.yaml", "ritueel.yaml ", "x", "a b", "\x1b", "\xff", "ritueel.yml", "-"} {
		f.Add(s, uint8(0))
	}
	f.Fuzz(func(t *testing.T, name string, kind uint8) {
		if name == "" || name == "." || name == ".." || len(name) > 200 || strings.ContainsAny(name, "/\x00") {
			t.Skip("not a name a folder can hold")
		}
		dir := t.TempDir()
		p := filepath.Join(dir, name)
		var err error
		regular := false
		switch kind % 3 {
		case 0:
			err = os.WriteFile(p, []byte("x"), 0o644)
			regular = true
		case 1:
			err = os.Mkdir(p, 0o755)
		default:
			err = os.Symlink("target", p)
		}
		if err != nil {
			t.Skipf("this file system cannot hold the name: %v", err)
		}
		t.Chdir(dir)
		got, err := bundleDir(&Call{})
		if name == manifestName && regular {
			if err != nil || got != "." {
				t.Fatalf("%q: %q, %v; want the current folder", name, got, err)
			}
			return
		}
		var u UsageError
		if !errors.As(err, &u) || got != "" || !strings.Contains(u.Error(), "--dir") {
			t.Fatalf("%q (kind %d): %q, %v; want a usage error that names --dir", name, kind%3, got, err)
		}
	})
}

// isHelpFlag says whether the library of flags would read arg as its help flag.
func isHelpFlag(arg string) bool {
	name := strings.TrimLeft(strings.TrimSpace(arg), "-")
	name, _, _ = strings.Cut(name, "=")
	return strings.HasPrefix(strings.TrimSpace(arg), "-") && (name == "h" || name == "help")
}
