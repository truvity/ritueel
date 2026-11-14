//go:build linux || darwin

package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
)

// The tests of "ritueel check history" run the real command through Run, on bundles that
// check_bundle_test.go makes by hand. What they assert is what docs/reference/cli.md (the bullet
// "check history") and docs/reference/ceremony-record.md ("The hash chain") say. The tests do not
// run in parallel, and none sleeps or waits on timing.

// chRun runs the command line and holds what no run may ever do: end with an exit code that
// "check history" does not have, end by a panic (Run turns one into exit code 1 and the text
// "internal error"), or write a byte that is not printable ASCII.
func chRun(t *testing.T, args ...string) result {
	t.Helper()
	r := run(t, args...)
	if !slices.Contains([]ExitCode{ExitOK, ExitFailure, ExitUsage, ExitRefused}, r.code) {
		t.Errorf("%v: exit code %d, which check history never returns", args, r.code)
	}
	if strings.Contains(r.stderr, "internal error") {
		t.Errorf("%v: the command panicked: %q", args, r.stderr)
	}
	terminalSafe(t, r)
	return r
}

// chHist runs "check history --dir dir" with the arguments after it.
func chHist(t *testing.T, dir string, extra ...string) result {
	t.Helper()
	return chRun(t, append([]string{"check", "history", "--dir", dir}, extra...)...)
}

// chJSON runs the same with --output json.
func chJSON(t *testing.T, dir string) result {
	t.Helper()
	return chRun(t, "check", "history", "--dir", dir, "--output", "json")
}

// chLines splits what a stream holds into its lines.
func chLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// chReport is what the library says about the folder: the oracle for the lines and the codes.
func chReport(t testing.TB, dir string) *history.Report {
	t.Helper()
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fsys.Close() }()
	rep, err := history.Check(t.Context(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// chCodes returns codes as strings; nil for none.
func chCodes(codes []history.Code) []string {
	var out []string
	for _, c := range codes {
		out = append(out, string(c))
	}
	return out
}

// chWantLines is what standard error holds for a report: one line for each finding and each
// notice in the library's order (the line is the library's own), then the line of what was left
// out, then the program's warning line for each notice code, then the refusal line when a finding
// fails.
func chWantLines(rep *history.Report) []string {
	var out []string
	for _, f := range rep.Findings {
		out = append(out, f.Line())
	}
	if rep.Omitted > 0 {
		out = append(out, itoaOmitted(rep.Omitted))
	}
	for _, w := range rep.Warnings() {
		out = append(out, "ritueel: warning: "+string(w))
	}
	if r := rep.Reasons(); len(r) > 0 {
		out = append(out, "ritueel: refused: "+strings.Join(chCodes(r), ", "))
	}
	return out
}

func itoaOmitted(n int) string { return strconv.Itoa(n) + " more findings not shown" }

func itoa(n int) string { return strconv.Itoa(n) }

// chEnd is the end line of a bundle: the count and the first eight characters of the digest of
// the newest record, worked out by the test.
func chEnd(count int, digest string) string {
	if count == 0 {
		return "history: 0 ceremony records\n"
	}
	return "history: " + itoa(count) + " ceremony records, end " + digest[:8] + "\n"
}

// chWantDone checks an object of a run that ended with exit 0: exactly the members of every
// command, and the warnings given.
func chWantDone(t *testing.T, r result, warnings []string) {
	t.Helper()
	wantObject(t, jsonObject(t, r), map[string]any{
		"output": 1, "command": "check", "exit_code": 0, "outcome": "done", "warnings": warnings,
	})
}

// chWantRefused checks the object of a refusal: reasons, warnings, no error.
func chWantRefused(t *testing.T, r result, reasons, warnings []string) {
	t.Helper()
	wantObject(t, jsonObject(t, r), map[string]any{
		"output": 1, "command": "check", "exit_code": 3, "outcome": "refused", "reasons": reasons, "warnings": warnings,
	})
}

// chWantFailed checks the object of a run that did not check: exit 1, an error, no reasons.
func chWantFailed(t *testing.T, r result) map[string]any {
	t.Helper()
	obj := jsonObject(t, r)
	wantObject(t, obj, map[string]any{
		"output": 1, "command": "check", "exit_code": 1, "outcome": "failed", "error": "<any>",
	})
	return obj
}

// ---------------------------------------------------------------------------------------------
// The word.

func TestCheckWordNeedsASecondWord(t *testing.T) {
	for _, args := range [][]string{
		{"check"},
		{"check", "nosuch"},
		{"check", "History"},
		{"check", "history-"},
		{"check", ""},
	} {
		r := chRun(t, args...)
		if r.code != ExitUsage || r.stdout != "" {
			t.Errorf("%q: exit %d, stdout %q; want exit 2 and nothing on standard output", args, r.code, r.stdout)
		}
		if !strings.Contains(r.stderr, "ritueel: check") {
			t.Errorf("%q: the error does not name the word check: %q", args, r.stderr)
		}
		j := chRun(t, append([]string{"--output", "json"}, args...)...)
		obj := jsonObject(t, j)
		wantObject(t, obj, map[string]any{
			"output": 1, "command": "check", "exit_code": 2, "outcome": "usage", "error": "<any>",
		})
	}
}

func TestCheckHistoryTakesNoArgumentAndNoFlagOfItsOwn(t *testing.T) {
	b := newHB(t, 1)
	for _, extra := range [][]string{
		{"extra"},
		{"--", "extra"},
		{"a", "b"},
		{""},
		{"--bogus"},
		{"-x"},
		{"--held", "f"},
		{"--pin", "f"},
	} {
		r := chHist(t, b.dir, extra...)
		if r.code != ExitUsage || r.stdout != "" {
			t.Errorf("%q: exit %d, stdout %q; want exit 2 and nothing on standard output", extra, r.code, r.stdout)
		}
		args := append([]string{"check", "history", "--dir", b.dir, "--output", "json"}, extra...)
		j := chRun(t, args...)
		wantObject(t, jsonObject(t, j), map[string]any{
			"output": 1, "command": "check", "exit_code": 2, "outcome": "usage", "error": "<any>",
		})
	}
	// The argument is refused before the folder is looked at: a missing folder is still exit 2.
	r := chRun(t, "check", "history", "extra", "--dir", filepath.Join(b.dir, "nosuch"))
	if r.code != ExitUsage {
		t.Errorf("an argument and a folder that is not there: exit %d, want 2", r.code)
	}
}

func TestCheckHistoryHelp(t *testing.T) {
	b := newHB(t, 1)
	for _, args := range [][]string{
		{"check", "history", "--help"},
		{"check", "history", "-h"},
		{"--output", "json", "check", "history", "--help"},
		{"check", "history", "--help", "--output", "json"},
		{"--dir", b.dir, "check", "history", "--help"},
	} {
		r := chRun(t, args...)
		if r.code != ExitOK {
			t.Errorf("%v: exit %d, want 0", args, r.code)
		}
		if !strings.Contains(r.stdout, "history") || !strings.Contains(r.stdout, "--dir") {
			t.Errorf("%v: the usage on standard output does not name the word and the flag: %q", args, r.stdout)
		}
		if strings.HasPrefix(strings.TrimSpace(r.stdout), "{") {
			t.Errorf("%v: a JSON object was written for --help: %q", args, r.stdout)
		}
		if r.stderr != "" {
			t.Errorf("%v: standard error = %q, want empty", args, r.stderr)
		}
	}
	r := chRun(t, "check", "--help")
	if r.code != ExitOK || !strings.Contains(r.stdout, "history") {
		t.Errorf("check --help: exit %d, stdout %q; want 0 and a list that holds history", r.code, r.stdout)
	}
	if u := chRun(t, "--help"); !strings.Contains(u.stdout, "check") {
		t.Errorf("the usage of the program does not list check: %q", u.stdout)
	}
}

// --dir and --output belong to the program: before the first word, between the words or after the
// last, the run is the same (docs/reference/cli.md, "Where a flag goes").
func TestFlagsOfTheProgramGoWhereverThePageSaysItMay(t *testing.T) {
	clean := newHB(t, 3)
	broken := newHB(t, 3)
	broken.rewrite(t, "trust/"+broken.cs[2].set+"/keys.txt", func(s string) string { return s + "x" })
	unfinished := newHB(t, 2)
	unfinished.add(t, false)
	dirs := map[string]string{
		"clean": clean.dir, "refused": broken.dir, "notice": unfinished.dir, "missing": filepath.Join(clean.dir, "nosuch"),
	}
	for name, dir := range dirs {
		for _, mode := range [][]string{nil, {"--output", "json"}, {"--output=json"}, {"--output", "text"}} {
			d := []string{"--dir", dir}
			dEq := []string{"--dir=" + dir}
			forms := [][]string{
				slices.Concat([]string{"check", "history"}, d, mode),
				slices.Concat(d, mode, []string{"check", "history"}),
				slices.Concat(dEq, mode, []string{"check", "history"}),
				slices.Concat(mode, []string{"check"}, d, []string{"history"}),
				slices.Concat([]string{"check"}, d, []string{"history"}, mode),
				slices.Concat([]string{"check", "history"}, mode, dEq),
				slices.Concat([]string{"check"}, mode, []string{"history"}, d),
			}
			want := chRun(t, forms[0]...)
			if want.stdout == "" && want.stderr == "" {
				t.Fatalf("%s %v: the first form wrote nothing", name, mode)
			}
			for _, form := range forms[1:] {
				if got := chRun(t, form...); got != want {
					t.Errorf("%s: %v gives %+v, but %v gives %+v", name, form, got, forms[0], want)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// A clean run.

func TestCleanRunPrintsTheEndLineAndNothingElse(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5} {
		b := newHB(t, n)
		want := chEnd(n, b.end())
		r := chHist(t, b.dir)
		if r.code != ExitOK || r.stdout != want || r.stderr != "" {
			t.Errorf("%d ceremonies: exit %d, stdout %q, stderr %q; want 0, %q and nothing", n, r.code, r.stdout, r.stderr, want)
		}
		if !strings.Contains(want, itoa(n)+" ceremony records") {
			t.Fatalf("the test's own line has the wrong count: %q", want)
		}
		j := chJSON(t, b.dir)
		if j.code != ExitOK || j.stderr != "" {
			t.Errorf("%d ceremonies, JSON: exit %d, stderr %q", n, j.code, j.stderr)
		}
		chWantDone(t, j, []string{})
		if strings.Contains(j.stdout, "history:") || strings.Contains(j.stdout, b.end()[:8]) {
			t.Errorf("the JSON object holds the end line or the end: %q", j.stdout)
		}
	}
}

func TestEndIsTheEndOfTheChainAndNotAnyOtherRecord(t *testing.T) {
	b := newHB(t, 3)
	r := chHist(t, b.dir)
	for i := 0; i < 2; i++ {
		if strings.Contains(r.stdout, b.cs[i].digest[:8]) {
			t.Errorf("the end line shows the record %d: %q", i+1, r.stdout)
		}
	}
	if !strings.Contains(r.stdout, "end "+b.cs[2].digest[:8]) {
		t.Errorf("the end line does not show the newest record %s: %q", b.cs[2].digest[:8], r.stdout)
	}
}

func TestBundleWithNoCeremonyHasTheZeroLine(t *testing.T) {
	const zero = "history: 0 ceremony records\n"
	t.Run("an empty history folder", func(t *testing.T) {
		b := newHB(t, 0)
		r := chHist(t, b.dir)
		if r.code != ExitOK || r.stdout != zero || r.stderr != "" {
			t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
		}
		chWantDone(t, chJSON(t, b.dir), []string{})
	})
	t.Run("no history folder and a manifest", func(t *testing.T) {
		b := newHB(t, 0)
		b.remove(t, "history")
		r := chHist(t, b.dir)
		if r.code != ExitOK || r.stdout != zero || r.stderr != "" {
			t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
		}
		j := chJSON(t, b.dir)
		chWantDone(t, j, []string{})
		if strings.Contains(j.stdout, "history:") {
			t.Errorf("the JSON object holds the zero line: %q", j.stdout)
		}
	})
}

// The copy of a bundle on a stick has no ritueel.yaml (record 0005, rule 30), so --dir does not
// ask for one when there is a history folder.
func TestCopyOnAStickHasNoManifestAndIsChecked(t *testing.T) {
	b := newHB(t, 3)
	b.remove(t, "ritueel.yaml")
	r := chHist(t, b.dir)
	if want := chEnd(3, b.end()); r.code != ExitOK || r.stdout != want || r.stderr != "" {
		t.Errorf("exit %d, stdout %q, stderr %q; want 0, %q", r.code, r.stdout, r.stderr, want)
	}
}

func TestPathWithATrailingSlashAndADotIsTheSameFolder(t *testing.T) {
	b := newHB(t, 2)
	want := chEnd(2, b.end())
	for _, dir := range []string{b.dir + "/", b.dir + "/.", filepath.Join(b.dir, "history", "..")} {
		r := chHist(t, dir)
		if r.code != ExitOK || r.stdout != want {
			t.Errorf("--dir %q: exit %d, stdout %q, stderr %q; want 0 and %q", dir, r.code, r.stdout, r.stderr, want)
		}
	}
}

func TestDefaultFolderIsTheCurrentOneWhenItHoldsTheManifest(t *testing.T) {
	b := newHB(t, 3)
	t.Chdir(b.dir)
	r := chRun(t, "check", "history")
	if want := chEnd(3, b.end()); r.code != ExitOK || r.stdout != want || r.stderr != "" {
		t.Errorf("exit %d, stdout %q, stderr %q; want 0, %q", r.code, r.stdout, r.stderr, want)
	}
	// An empty --dir is not given.
	r = chRun(t, "--dir", "", "check", "history")
	if want := chEnd(3, b.end()); r.code != ExitOK || r.stdout != want {
		t.Errorf("--dir \"\": exit %d, stdout %q, stderr %q; want the default folder", r.code, r.stdout, r.stderr)
	}
	chWantDone(t, chRun(t, "check", "history", "--output", "json"), []string{})
	// A bundle that is a different folder is checked when --dir names it, and the current folder is
	// not read.
	other := newHB(t, 1)
	r = chHist(t, other.dir)
	if want := chEnd(1, other.end()); r.stdout != want {
		t.Errorf("--dir wins over the current folder: stdout %q, want %q", r.stdout, want)
	}
}

func TestReadOnlyBundleIsCheckedAndNotChanged(t *testing.T) {
	cases := map[string]func(*hbundle){
		"clean": func(*hbundle) {},
		"a finding": func(b *hbundle) {
			b.rewrite(t, "trust/"+b.cs[1].set+"/keys.txt", func(s string) string { return s + "x" })
		},
		"a notice":   func(b *hbundle) { hbWrite(t, b.dir, "history/notes.txt", "x") },
		"unfinished": func(b *hbundle) { b.add(t, false) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := newHB(t, 3)
			mutate(b)
			open := chHist(t, b.dir)
			// Every folder loses its write permission. A cleanup first gives it back, so that the
			// folder of the test can be removed; it runs before the removal.
			var dirs []string
			err := filepath.WalkDir(b.dir, func(p string, d fs.DirEntry, err error) error {
				if err == nil && d.IsDir() {
					dirs = append(dirs, p)
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				for _, d := range dirs {
					_ = os.Chmod(d, 0o755)
				}
			})
			for i := len(dirs) - 1; i >= 0; i-- {
				if err := os.Chmod(dirs[i], 0o555); err != nil {
					t.Fatal(err)
				}
			}
			before := hbTree(t, b.dir)
			got := chHist(t, b.dir)
			if got != open {
				t.Errorf("a read-only folder gives %+v, a writable one %+v", got, open)
			}
			hbSameTree(t, before, hbTree(t, b.dir))
		})
	}
}

// ---------------------------------------------------------------------------------------------
// Not checked: exit code 1.

// chWantNotChecked checks a run that did not check: exit 1, nothing on standard output, no finding
// line (the only lines are the program's own), an error member and no reasons.
func chWantNotChecked(t *testing.T, name string, text, js result) {
	t.Helper()
	if text.code != ExitFailure {
		t.Errorf("%s: exit %d, want 1; stderr %q", name, text.code, text.stderr)
	}
	if text.stdout != "" {
		t.Errorf("%s: standard output = %q, want nothing", name, text.stdout)
	}
	for _, l := range chLines(text.stderr) {
		if !strings.HasPrefix(l, "ritueel: ") {
			t.Errorf("%s: a line that is not the program's: %q", name, l)
		}
	}
	if len(chLines(text.stderr)) != 1 {
		t.Errorf("%s: standard error holds %d lines, want the one line of the error: %q", name, len(chLines(text.stderr)), text.stderr)
	}
	if js.code != ExitFailure {
		t.Errorf("%s (JSON): exit %d, want 1", name, js.code)
	}
	chWantFailed(t, js)
	if js.stderr != text.stderr {
		t.Errorf("%s: standard error differs between the modes: %q and %q", name, text.stderr, js.stderr)
	}
}

func TestFolderThatIsNotABundleIsNotChecked(t *testing.T) {
	scratch := t.TempDir()
	good := newHB(t, 2)
	file := filepath.Join(scratch, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(scratch, "link")
	if err := os.Symlink(good.dir, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(scratch, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("this system cannot make a FIFO, and the test needs one: %v", err)
	}
	empty := filepath.Join(scratch, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(scratch, "other")
	hbWrite(t, other, "notes.txt", "x")
	cases := []struct{ name, dir, text string }{
		{"a folder with neither a history folder nor a manifest", empty, "not a bundle"},
		{"a folder with other files only", other, "not a bundle"},
		{"a path that does not exist", filepath.Join(scratch, "nosuch"), ""},
		{"a regular file", file, ""},
		{"a symbolic link to a good bundle", link, ""},
		{"a symbolic link with a trailing slash", link + "/", ""},
		{"a FIFO", fifo, ""},
	}
	for _, tc := range cases {
		text := chHist(t, tc.dir)
		js := chJSON(t, tc.dir)
		chWantNotChecked(t, tc.name, text, js)
		if tc.text != "" && !strings.Contains(text.stderr, tc.text) {
			t.Errorf("%s: the text does not say %q: %q", tc.name, tc.text, text.stderr)
		}
	}
	// A symbolic link is not followed even though the bundle behind it is good.
	if r := chHist(t, link); strings.Contains(r.stdout, "history:") {
		t.Errorf("the link was followed: %q", r.stdout)
	}
}

func TestUnreadableFolderIsNotChecked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test runs as root, and root reads a folder whatever its mode: it needs an ordinary user")
	}
	probe := func(t *testing.T, b *hbundle, rel string, mode os.FileMode) {
		t.Helper()
		p := b.path(rel)
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
		if f, err := os.Open(p); err == nil {
			_ = f.Close()
			t.Fatalf("%s can still be opened with mode %o: the test cannot make it unreadable", rel, mode)
		}
	}
	t.Run("the bundle folder", func(t *testing.T) {
		b := newHB(t, 2)
		probe(t, b, ".", 0)
		chWantNotChecked(t, "mode 000", chHist(t, b.dir), chJSON(t, b.dir))
	})
	t.Run("the history folder", func(t *testing.T) {
		b := newHB(t, 2)
		probe(t, b, "history", 0)
		chWantNotChecked(t, "history mode 000", chHist(t, b.dir), chJSON(t, b.dir))
	})
	t.Run("the trust folder", func(t *testing.T) {
		b := newHB(t, 2)
		probe(t, b, "trust", 0)
		chWantNotChecked(t, "trust mode 000", chHist(t, b.dir), chJSON(t, b.dir))
	})
	// A listed file that cannot be read is exit code 1, and only "does not exist" is a finding
	// ("The hash chain", the paragraph before "check history reads files only").
	t.Run("a listed file that cannot be read", func(t *testing.T) {
		b := newHB(t, 2)
		probe(t, b, "trust/"+b.cs[1].set+"/keys.txt", 0)
		chWantNotChecked(t, "keys.txt mode 000", chHist(t, b.dir), chJSON(t, b.dir))
	})
	t.Run("a record that cannot be read", func(t *testing.T) {
		b := newHB(t, 2)
		probe(t, b, b.recordPath(2), 0)
		text := chHist(t, b.dir)
		if text.code == ExitOK {
			t.Errorf("a record with mode 000 gave exit 0: %+v", text)
		}
		if text.stdout != "" {
			t.Errorf("standard output = %q", text.stdout)
		}
	})
	t.Run("the transcript that cannot be read", func(t *testing.T) {
		b := newHB(t, 2)
		probe(t, b, b.folderPath(2)+"/transcript.txt", 0)
		chWantNotChecked(t, "transcript mode 000", chHist(t, b.dir), chJSON(t, b.dir))
	})
}

func TestFailuresOfTheFileSystemAreNotChecked(t *testing.T) {
	b := newHB(t, 2)
	tooMany := &fsx.Error{Step: fsx.StepRead, Path: "history", Err: fsx.ErrTooMany}
	cases := []struct {
		name string
		wrap func(fsx.FS) fsx.FS
	}{
		{"too many names in the root", func(f fsx.FS) fsx.FS { return &failingFS{FS: f, err: tooMany} }},
		{"too many names in history", func(f fsx.FS) fsx.FS { return &failingFS{FS: f, name: "history", err: tooMany} }},
		{"too many names in trust", func(f fsx.FS) fsx.FS { return &failingFS{FS: f, name: "trust", err: tooMany} }},
		{"no permission for history", func(f fsx.FS) fsx.FS {
			return &failingFS{FS: f, name: "history", err: &fsx.Error{Step: fsx.StepOpenDir, Path: "history", Err: fs.ErrPermission}}
		}},
		{"no permission for a ceremony folder", func(f fsx.FS) fsx.FS {
			return &failingFS{FS: f, name: b.cs[1].folder, err: &fsx.Error{Step: fsx.StepOpenDir, Path: "x", Err: fs.ErrPermission}}
		}},
		{"a record that cannot be read", func(f fsx.FS) fsx.FS {
			return &failingRead{FS: f, name: "record.json", err: fs.ErrPermission}
		}},
		{"a file that cannot be read", func(f fsx.FS) fsx.FS {
			return &failingRead{FS: f, name: "keys.txt", err: fs.ErrPermission}
		}},
		{"a failing disk", func(f fsx.FS) fsx.FS {
			return &failingRead{FS: f, name: "transcript.txt", err: errors.New("input/output error")}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner, err := fsx.OpenFS(b.dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = inner.Close() }()
			var out strings.Builder
			res, err := checkHistory(t.Context(), tc.wrap(inner), &out)
			if err == nil || res != nil {
				t.Fatalf("a failing file system gave result %v and error %v; want an error and no result", res, err)
			}
			if code, outcome := ExitFor(err); code != ExitFailure || outcome != OutcomeFailed {
				t.Errorf("exit %d (%s), want 1 (failed): %v", code, outcome, err)
			}
			if out.String() != "" {
				t.Errorf("a run that did not check wrote lines: %q", out.String())
			}
		})
	}
}

// A context that ends is exit code 1 and never clean: before the run, and in the middle of it.
func TestEndedContextIsNotChecked(t *testing.T) {
	b := newHB(t, 3)
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	var env struct{ out, err strings.Builder }
	code := Run(ended, []string{"check", "history", "--dir", b.dir}, Env{Stdout: &env.out, Stderr: &env.err, Build: testBuild})
	if code != ExitFailure || env.out.String() != "" {
		t.Errorf("Run with an ended context: exit %d, stdout %q, stderr %q; want 1 and nothing on standard output", code, env.out.String(), env.err.String())
	}
	for _, l := range chLines(env.err.String()) {
		if !strings.HasPrefix(l, "ritueel: ") {
			t.Errorf("a line that is not the program's: %q", l)
		}
	}

	inner, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inner.Close() }()
	var out strings.Builder
	res, err := checkHistory(ended, inner, &out)
	if res != nil || !errors.Is(err, context.Canceled) || out.String() != "" {
		t.Errorf("checkHistory with an ended context: %v, %v, %q; want no result, context.Canceled, nothing written", res, err, out.String())
	}

	// The context ends in the middle of the run: the cancelling folder cancels at its fourth
	// OpenDir. No timing is involved: the call that cancels is a call of the run.
	for after := 1; after <= 6; after++ {
		mid, stop := context.WithCancel(t.Context())
		fsys := &cancellingFS{FS: inner, after: after, cancel: stop}
		var out strings.Builder
		res, err := checkHistory(mid, fsys, &out)
		stop()
		if fsys.opens < after {
			t.Logf("the run ended after %d opens, before the cancel at %d: it needs fewer", fsys.opens, after)
			continue
		}
		if res != nil || err == nil || out.String() != "" {
			t.Errorf("a context that ends at open %d: result %v, error %v, written %q; want an error and nothing written", after, res, err, out.String())
		}
	}
}

// cancellingFS cancels a context at its nth OpenDir, in this folder and in the ones it opens.
type cancellingFS struct {
	fsx.FS
	after  int
	cancel context.CancelFunc
	opens  int
	parent *cancellingFS
}

func (c *cancellingFS) root() *cancellingFS {
	if c.parent != nil {
		return c.parent
	}
	return c
}

func (c *cancellingFS) OpenDir(name string) (fsx.FS, error) {
	r := c.root()
	r.opens++
	if r.opens == r.after {
		r.cancel()
	}
	d, err := c.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &cancellingFS{FS: d, parent: r}, nil
}

// A FIFO where a file belongs must not hang the command: the test ends the run with a deadline,
// which is a failure of the test and not a way to pass.
func TestPipesAreNotWaitedOn(t *testing.T) {
	b := newHB(t, 2)
	for _, rel := range []string{
		b.recordPath(2), b.folderPath(2) + "/plan.json", b.folderPath(2) + "/attempt.json", b.folderPath(2) + "/transcript.txt",
		b.folderPath(2) + "/wanted/ritueel.yaml", "trust/" + b.cs[1].set + "/keys.txt", "trust/" + b.cs[1].set + "/root-list.json",
	} {
		b := newHB(t, 2)
		if err := os.Remove(b.path(rel)); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(b.path(rel), 0o600); err != nil {
			t.Fatalf("cannot make a FIFO: %v", err)
		}
		ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)
		inner, err := fsx.OpenFS(b.dir)
		if err != nil {
			stop()
			t.Fatal(err)
		}
		var out strings.Builder
		res, err := checkHistory(ctx, inner, &out)
		if ctx.Err() != nil {
			t.Errorf("%s: the run was still going after 20 seconds: it waited on a FIFO", rel)
		}
		stop()
		_ = inner.Close()
		if err == nil && res != nil && res.ExitCode == ExitOK {
			t.Errorf("%s: a FIFO in place of a file gave a clean run: %q", rel, res.Text)
		}
		if err != nil {
			if code, _ := ExitFor(err); code != ExitRefused && code != ExitFailure {
				t.Errorf("%s: exit %d", rel, code)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Findings that fail: exit code 3.

// faultCase makes a bundle with one fault. reasons are the codes the page gives for it, exactly, in
// the order of the table of "The hash chain" (the order of history.Codes); a fault that cannot be
// made alone says so.
type faultCase struct {
	name    string
	code    string // the code under test
	build   func(t *testing.T) *hbundle
	reasons []string
}

const aaaa = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func faultCases() []faultCase {
	set3 := func(b *hbundle) string { return "trust/" + b.cs[2].set + "/" }
	return []faultCase{
		{"a changed byte of an artifact", "file-digest", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.rewrite(t, set3(b)+"keys.txt", func(s string) string { return strings.Replace(s, "keys", "kayz", 1) })
			return b
		}, []string{"file-digest"}},
		{"an artifact that is a folder", "file-digest", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.remove(t, set3(b)+"keys.txt")
			if err := os.Mkdir(b.path(set3(b)+"keys.txt"), 0o755); err != nil {
				t.Fatal(err)
			}
			return b
		}, []string{"file-digest"}},
		{"a changed wanted copy", "file-digest", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.rewrite(t, b.folderPath(2)+"/wanted/ritueel.yaml", func(s string) string { return s + "x" })
			return b
		}, []string{"file-digest"}},
		{"a changed plan", "file-digest", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.rewrite(t, b.folderPath(1)+"/plan.json", func(s string) string { return s + " " })
			return b
		}, []string{"file-digest"}},
		{"a removed artifact", "file-missing", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.remove(t, set3(b)+"keys.txt")
			return b
		}, []string{"file-missing"}},
		{"a removed transcript", "file-missing", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.remove(t, b.folderPath(2)+"/transcript.txt")
			return b
		}, []string{"file-missing"}},
		{"a changed transcript", "transcript-digest", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.rewrite(t, b.folderPath(3)+"/transcript.txt", func(s string) string { return s + "x" })
			return b
		}, []string{"transcript-digest"}},
		{"a record that names a predecessor that is not there", "chain-broken", func(t *testing.T) *hbundle {
			b := newHB(t, 2)
			b.add(t, true, func(c *hbCeremony) { c.prev = aaaa; c.noSet = true })
			return b
		}, []string{"chain-broken"}},
		{"a removed middle record", "chain-broken", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.remove(t, b.recordPath(2))
			return b
		}, []string{"chain-broken", "trust-set-unlisted", "anchor-unknown"}},
		{"two records that name one predecessor", "fork", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			c := hbMake(4, b.cs[1].digest, true)
			hbWriteCeremony(t, b.dir, c)
			b.cs = append(b.cs, c)
			return b
		}, []string{"fork"}},
		{"a copy of a record in a second folder", "fork", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			data, err := os.ReadFile(b.path(b.recordPath(3)))
			if err != nil {
				t.Fatal(err)
			}
			hbWrite(t, b.dir, "history/copy/record.json", string(data))
			return b
		}, []string{"fork", "record-invalid", "file-missing"}},
		{"a record that is not in canonical form", "record-not-canonical", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.rewrite(t, b.recordPath(3), func(s string) string { return s + "\n" })
			return b
		}, []string{"record-not-canonical"}},
		{"a record of a version that is not known", "record-version-unknown", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.rewrite(t, b.recordPath(3), func(s string) string { return strings.Replace(s, `"version":1`, `"version":2`, 1) })
			return b
		}, []string{"record-off-chain", "record-version-unknown", "trust-set-unlisted"}},
		{"a record that breaks a rule of the page", "record-invalid", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.rewrite(t, b.recordPath(3), func(s string) string { return strings.Replace(s, `"outcome":"completed"`, `"outcome":"done"`, 1) })
			return b
		}, []string{"record-off-chain", "record-invalid", "trust-set-unlisted"}},
		{"a record whose predecessor cannot be read", "record-off-chain", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.rewrite(t, b.recordPath(2), func(s string) string { return strings.Replace(s, `"outcome":"completed"`, `"outcome":"done"`, 1) })
			return b
		}, []string{"chain-broken", "record-off-chain", "record-invalid", "trust-set-unlisted", "anchor-unknown"}},
		{"a file in a trust set that no record lists", "file-unlisted", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			hbWrite(t, b.dir, set3(b)+"extra.txt", "x")
			return b
		}, []string{"file-unlisted"}},
		{"a trust set that no record lists and no attempt", "trust-set-unlisted", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			b.remove(t, b.recordPath(3))
			b.remove(t, b.folderPath(3)+"/attempt.json")
			return b
		}, []string{"trust-set-unlisted"}},
		{"a root list that names a record that is not there", "anchor-unknown", func(t *testing.T) *hbundle {
			b := newHB(t, 2)
			b.add(t, true, func(c *hbCeremony) { c.rootList = `{"last_record_sha256":"` + aaaa + `","version":1}` })
			return b
		}, []string{"anchor-unknown"}},
		{"a folder with a space in history", "unexpected-name", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			if err := os.Mkdir(b.path("history/a b"), 0o755); err != nil {
				t.Fatal(err)
			}
			return b
		}, []string{"unexpected-name"}},
		{"a link where a ceremony folder belongs", "unexpected-name", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			if err := os.Symlink(b.dir, b.path("history/link")); err != nil {
				t.Fatal(err)
			}
			return b
		}, []string{"unexpected-name"}},
		{"a FIFO where a trust set belongs", "unexpected-name", func(t *testing.T) *hbundle {
			b := newHB(t, 3)
			if err := syscall.Mkfifo(b.path("trust/pipe"), 0o600); err != nil {
				t.Fatal(err)
			}
			return b
		}, []string{"unexpected-name"}},
	}
}

func TestEveryFailingFindingIsExitCodeThree(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range faultCases() {
		covered[tc.code] = true
		t.Run(tc.name, func(t *testing.T) {
			b := tc.build(t)
			rep := chReport(t, b.dir)
			if !slices.Equal(chCodes(rep.Reasons()), tc.reasons) {
				t.Fatalf("the bundle of the test gives the reasons %v, and the test expects %v: the test's bundle is not the fault it names", chCodes(rep.Reasons()), tc.reasons)
			}
			if !slices.Contains(tc.reasons, tc.code) {
				t.Fatalf("the test names the code %s and does not expect it", tc.code)
			}
			want := chWantLines(rep)
			if len(rep.Warnings()) != 0 {
				t.Fatalf("the test's bundle holds notices %v", rep.Warnings())
			}

			text := chHist(t, b.dir)
			if text.code != ExitRefused || text.stdout != "" {
				t.Fatalf("exit %d, stdout %q, stderr %q; want exit 3 and nothing on standard output", text.code, text.stdout, text.stderr)
			}
			if got := chLines(text.stderr); !slices.Equal(got, want) {
				t.Errorf("standard error:\n got %q\nwant %q", got, want)
			}
			if got := chLines(text.stderr); got[len(got)-1] != "ritueel: refused: "+strings.Join(tc.reasons, ", ") {
				t.Errorf("the last line is %q", got[len(got)-1])
			}
			found := false
			for _, l := range chLines(text.stderr) {
				if strings.HasPrefix(l, tc.code+" ") {
					found = true
				}
			}
			if !found {
				t.Errorf("no line of %s on standard error: %q", tc.code, text.stderr)
			}

			js := chJSON(t, b.dir)
			if js.code != ExitRefused || js.stderr != text.stderr {
				t.Errorf("JSON: exit %d; the lines on standard error differ from the text mode: %q and %q", js.code, js.stderr, text.stderr)
			}
			chWantRefused(t, js, tc.reasons, []string{})
			if strings.Contains(js.stdout, "history:") {
				t.Errorf("an end line in the JSON of a refusal: %q", js.stdout)
			}
		})
	}
	// Every code that fails has a case of its own in this table.
	for _, c := range history.Codes() {
		if c.Fails() && !covered[string(c)] {
			t.Errorf("the failing code %s has no case", c)
		}
	}
}

// Three faults at once: each code is in reasons once, in the library's order, and not in the order
// the files were damaged or listed; each finding has its own line; the refusal line lists the codes
// in that order.
func TestSeveralFaultsAreListedOnceEachInTheOrderOfThePage(t *testing.T) {
	b := newHB(t, 3)
	// Damaged in the reverse of the page's order: a file nobody lists, then a changed artifact, then
	// a changed transcript.
	hbWrite(t, b.dir, "trust/"+b.cs[0].set+"/extra.txt", "x")
	hbWrite(t, b.dir, "trust/"+b.cs[0].set+"/extra2.txt", "x")
	b.rewrite(t, "trust/"+b.cs[1].set+"/keys.txt", func(s string) string { return s + "x" })
	b.rewrite(t, "trust/"+b.cs[2].set+"/keys.txt", func(s string) string { return s + "x" })
	b.rewrite(t, b.folderPath(3)+"/transcript.txt", func(s string) string { return s + "x" })
	want := []string{"transcript-digest", "file-digest", "file-unlisted"}
	rep := chReport(t, b.dir)
	if !slices.Equal(chCodes(rep.Reasons()), want) || len(rep.Findings) != 5 {
		t.Fatalf("the bundle gives %v with %d findings; the test expects %v with 5", chCodes(rep.Reasons()), len(rep.Findings), want)
	}
	r := chHist(t, b.dir)
	if r.code != ExitRefused || r.stdout != "" {
		t.Fatalf("exit %d, stdout %q", r.code, r.stdout)
	}
	lines := chLines(r.stderr)
	if !slices.Equal(lines, chWantLines(rep)) {
		t.Errorf("standard error:\n got %q\nwant %q", lines, chWantLines(rep))
	}
	if len(lines) != 6 || lines[5] != "ritueel: refused: transcript-digest, file-digest, file-unlisted" {
		t.Errorf("want five finding lines and one refusal line: %q", lines)
	}
	chWantRefused(t, chJSON(t, b.dir), want, []string{})
}

// ---------------------------------------------------------------------------------------------
// Notices: exit code 0.

func TestUnfinishedCeremonyIsANoticeAndTheEndIsTheEndBeforeIt(t *testing.T) {
	b := newHB(t, 3)
	b.add(t, false)
	rep := chReport(t, b.dir)
	if !slices.Equal(chCodes(rep.Warnings()), []string{"unfinished-ceremony"}) || len(rep.Reasons()) != 0 {
		t.Fatalf("the test's bundle gives warnings %v and reasons %v", rep.Warnings(), rep.Reasons())
	}
	r := chHist(t, b.dir)
	// The end shown is the end before the unfinished ceremony, with the lower count.
	if want := chEnd(3, b.cs[2].digest); r.code != ExitOK || r.stdout != want {
		t.Errorf("exit %d, stdout %q; want 0 and %q", r.code, r.stdout, want)
	}
	wantErr := []string{rep.Findings[0].Line(), "ritueel: warning: unfinished-ceremony"}
	if got := chLines(r.stderr); !slices.Equal(got, wantErr) || !strings.HasPrefix(got[0], "unfinished-ceremony trust/"+b.cs[3].set+":") {
		t.Errorf("standard error = %q, want %q", got, wantErr)
	}
	j := chJSON(t, b.dir)
	if j.code != ExitOK || j.stderr != r.stderr {
		t.Errorf("JSON: exit %d, standard error %q; want 0 and the lines of the text mode", j.code, j.stderr)
	}
	chWantDone(t, j, []string{"unfinished-ceremony"})
	if strings.Contains(j.stdout, "history:") {
		t.Errorf("an end line in the JSON: %q", j.stdout)
	}
}

func TestRemovedNewestRecordIsTheNoticeAndTheEndLineShowsTheLowerCount(t *testing.T) {
	b := newHB(t, 3)
	b.remove(t, b.recordPath(3))
	r := chHist(t, b.dir)
	if want := chEnd(2, b.cs[1].digest); r.code != ExitOK || r.stdout != want {
		t.Errorf("exit %d, stdout %q; want 0 and %q", r.code, r.stdout, want)
	}
	if !strings.Contains(r.stderr, "unfinished-ceremony") || strings.Contains(r.stdout, b.cs[2].digest[:8]) {
		t.Errorf("standard error %q, stdout %q", r.stderr, r.stdout)
	}
}

func TestAStrayFileIsANotice(t *testing.T) {
	cases := map[string]string{
		"history/notes.txt":                            "a file where a ceremony folder belongs",
		"trust/notes.txt":                              "a file where a trust set belongs",
		"history/.rt-abcdefghijk":                      "a leftover temporary name",
		"history/.rt-ABCDEFGHIJK":                      "a leftover temporary name in upper case",
		"trust/.rt-abcdefghijk":                        "a leftover temporary name in trust",
		"trust/" + hbSet(1) + "/.DS_Store":             "a name a desktop system writes in a trust set",
		"trust/" + hbSet(1) + "/Thumbs.db":             "a name a desktop system writes in a trust set",
		"trust/" + hbSet(1) + "/._keys":                "a name a desktop system writes in a trust set",
		"history/" + hbFolder(1) + "/wanted/extra.txt": "a copy that the record does not list",
		"history/" + hbFolder(1) + "/notes.txt":        "a file in a ceremony folder that no record lists",
	}
	for rel, what := range cases {
		t.Run(what, func(t *testing.T) {
			b := newHB(t, 3)
			hbWrite(t, b.dir, rel, "x")
			rep := chReport(t, b.dir)
			if !slices.Equal(chCodes(rep.Warnings()), []string{"unexpected-file"}) || len(rep.Reasons()) != 0 {
				t.Fatalf("%s: the library gives warnings %v and reasons %v; the test expects one notice", rel, rep.Warnings(), rep.Reasons())
			}
			r := chHist(t, b.dir)
			if want := chEnd(3, b.end()); r.code != ExitOK || r.stdout != want {
				t.Errorf("exit %d, stdout %q; want 0 and %q", r.code, r.stdout, want)
			}
			if got, want := chLines(r.stderr), chWantLines(rep); !slices.Equal(got, want) {
				t.Errorf("standard error:\n got %q\nwant %q", got, want)
			}
			if !strings.HasPrefix(chLines(r.stderr)[0], "unexpected-file ") {
				t.Errorf("the first line is not the notice: %q", r.stderr)
			}
			j := chJSON(t, b.dir)
			chWantDone(t, j, []string{"unexpected-file"})
		})
	}
}

// Two notices of one code are one entry of warnings and two lines; the two codes are in the
// library's order, and the program's warning line follows the lines of the command.
func TestNoticesAreListedOnceByCodeAndInTheOrderOfTheLibrary(t *testing.T) {
	b := newHB(t, 2)
	b.add(t, false)
	hbWrite(t, b.dir, "history/b.txt", "x")
	hbWrite(t, b.dir, "history/a.txt", "x")
	rep := chReport(t, b.dir)
	if !slices.Equal(chCodes(rep.Warnings()), []string{"unfinished-ceremony", "unexpected-file"}) || len(rep.Findings) != 3 {
		t.Fatalf("the bundle gives %v with %d findings", chCodes(rep.Warnings()), len(rep.Findings))
	}
	r := chHist(t, b.dir)
	want := chWantLines(rep)
	if got := chLines(r.stderr); !slices.Equal(got, want) || len(want) != 5 {
		t.Errorf("standard error:\n got %q\nwant %q", got, want)
	}
	if r.code != ExitOK || r.stdout != chEnd(2, b.cs[1].digest) {
		t.Errorf("exit %d, stdout %q", r.code, r.stdout)
	}
	chWantDone(t, chJSON(t, b.dir), []string{"unfinished-ceremony", "unexpected-file"})
}

// A notice together with a failing finding: exit 3, reasons hold only the failing codes, warnings
// still hold the notice, and standard error holds the finding lines, then the warning lines, then
// the refusal line.
func TestNoticeWithAFailingFinding(t *testing.T) {
	b := newHB(t, 3)
	hbWrite(t, b.dir, "history/notes.txt", "x")
	b.rewrite(t, "trust/"+b.cs[2].set+"/keys.txt", func(s string) string { return s + "x" })
	rep := chReport(t, b.dir)
	if !slices.Equal(chCodes(rep.Reasons()), []string{"file-digest"}) || !slices.Equal(chCodes(rep.Warnings()), []string{"unexpected-file"}) {
		t.Fatalf("the bundle gives reasons %v and warnings %v", rep.Reasons(), rep.Warnings())
	}
	r := chHist(t, b.dir)
	if r.code != ExitRefused || r.stdout != "" {
		t.Fatalf("exit %d, stdout %q", r.code, r.stdout)
	}
	want := []string{
		"file-digest trust/" + b.cs[2].set + "/keys.txt: listed by " + b.cs[2].folder + " as an artifact: expected ",
		"unexpected-file history/notes.txt: ",
		"ritueel: warning: unexpected-file",
		"ritueel: refused: file-digest",
	}
	got := chLines(r.stderr)
	if len(got) != len(want) {
		t.Fatalf("standard error holds %d lines: %q", len(got), got)
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w) {
			t.Errorf("line %d = %q, want it to start with %q", i, got[i], w)
		}
	}
	if !slices.Equal(got, chWantLines(rep)) {
		t.Errorf("standard error differs from the library's lines: %q", got)
	}
	chWantRefused(t, chJSON(t, b.dir), []string{"file-digest"}, []string{"unexpected-file"})
}

// ---------------------------------------------------------------------------------------------
// What was left out.

func TestFindingsLeftOutAreCounted(t *testing.T) {
	t.Run("a notice", func(t *testing.T) {
		b := newHB(t, 2)
		for i := 0; i < 1001; i++ {
			hbWrite(t, b.dir, "history/stray"+itoa(10000+i)+".txt", "")
		}
		rep := chReport(t, b.dir)
		if len(rep.Findings) != 1000 || rep.Omitted != 1 {
			t.Fatalf("the library holds %d findings and %d left out; the test expects 1000 and 1", len(rep.Findings), rep.Omitted)
		}
		r := chHist(t, b.dir)
		if r.code != ExitOK || r.stdout != chEnd(2, b.end()) {
			t.Fatalf("exit %d, stdout %q", r.code, r.stdout)
		}
		lines := chLines(r.stderr)
		if len(lines) != 1002 {
			t.Fatalf("standard error holds %d lines, want 1000 notices, the line of what was left out and the warning line", len(lines))
		}
		if lines[1000] != "1 more findings not shown" || lines[1001] != "ritueel: warning: unexpected-file" {
			t.Errorf("the last lines are %q and %q", lines[1000], lines[1001])
		}
		for _, l := range lines[:1000] {
			if !strings.HasPrefix(l, "unexpected-file history/stray1") {
				t.Fatalf("a line that is not a notice: %q", l)
			}
		}
		j := chJSON(t, b.dir)
		chWantDone(t, j, []string{"unexpected-file"})
	})
	t.Run("a finding that fails", func(t *testing.T) {
		b := newHB(t, 2)
		for i := 0; i < 1005; i++ {
			if err := os.Mkdir(b.path("history/a b "+itoa(10000+i)), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		rep := chReport(t, b.dir)
		if len(rep.Findings) != 1000 || rep.Omitted != 5 {
			t.Fatalf("the library holds %d findings and %d left out; the test expects 1000 and 5", len(rep.Findings), rep.Omitted)
		}
		r := chHist(t, b.dir)
		if r.code != ExitRefused || r.stdout != "" {
			t.Fatalf("exit %d, stdout %q", r.code, r.stdout)
		}
		lines := chLines(r.stderr)
		if len(lines) != 1002 || lines[1000] != "5 more findings not shown" || lines[1001] != "ritueel: refused: unexpected-name" {
			t.Errorf("%d lines; the last are %q", len(lines), lines[len(lines)-2:])
		}
		chWantRefused(t, chJSON(t, b.dir), []string{"unexpected-name"}, []string{})
	})
	t.Run("nothing left out", func(t *testing.T) {
		b := newHB(t, 2)
		hbWrite(t, b.dir, "history/s.txt", "")
		if r := chHist(t, b.dir); strings.Contains(r.stderr, "more findings") {
			t.Errorf("a line of what was left out when nothing was: %q", r.stderr)
		}
	})
}

// ---------------------------------------------------------------------------------------------
// What reaches a terminal.

func TestNamesFromTheBundleAreShownWithEscapes(t *testing.T) {
	names := map[string]string{
		"an escape":             "x\x1b[31my",
		"a Cyrillic a":          "p\u0430th",
		"a backslash":           `a\b`,
		"a newline":             "a\nb",
		"a space":               "a b",
		"a byte that is no UTF": "a\xffb",
		"a tab":                 "a\tb",
		"a bell":                "a\ab",
		"a delete":              "a\x7fb",
		"a right-to-left mark":  "a\u202eb",
		"a colon and a word":    "a: ritueel: refused: nothing",
		"a long name":           strings.Repeat("a b", 80),
	}
	for what, name := range names {
		t.Run(what, func(t *testing.T) {
			b := newHB(t, 2)
			dir := b.path("history/" + name)
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Skipf("this file system cannot hold the name: %v", err)
			}
			rep := chReport(t, b.dir)
			if !slices.Equal(chCodes(rep.Reasons()), []string{"unexpected-name"}) {
				t.Fatalf("the library gives %v for the name %q", chCodes(rep.Reasons()), name)
			}
			text := chHist(t, b.dir)
			js := chJSON(t, b.dir)
			for _, s := range []string{text.stdout, text.stderr, js.stdout, js.stderr} {
				if !onlyPrintable(s) {
					t.Errorf("a byte outside printable ASCII: %q", s)
				}
			}
			if text.code != ExitRefused || js.code != ExitRefused {
				t.Errorf("exit %d and %d, want 3", text.code, js.code)
			}
			lines := chLines(text.stderr)
			if len(lines) != 2 || !strings.HasPrefix(lines[0], "unexpected-name history/") || lines[1] != "ritueel: refused: unexpected-name" {
				t.Errorf("a name made more or other lines than the finding and the refusal: %q", lines)
			}
			if lines[0] != rep.Findings[0].Line() {
				t.Errorf("the line is not the line of the library:\n got %q\nwant %q", lines[0], rep.Findings[0].Line())
			}
			// What the name writes in words must not read like a line of the program.
			if strings.Count(text.stderr, "ritueel: refused") != 1 {
				t.Errorf("a name made a second refusal line: %q", text.stderr)
			}
		})
	}
}

func TestTwoDifferentNamesNeverPrintAsTheSameLine(t *testing.T) {
	// "a b" shows a space as \x20, and a name that holds a backslash and the four characters x20
	// shows the backslash doubled.
	one, two := newHB(t, 1), newHB(t, 1)
	if err := os.Mkdir(one.path("history/a b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(two.path(`history/a\x20b`), 0o755); err != nil {
		t.Fatal(err)
	}
	r1, r2 := chHist(t, one.dir), chHist(t, two.dir)
	if r1.stderr == r2.stderr {
		t.Errorf("two different names print as the same: %q", r1.stderr)
	}
	for _, r := range []result{r1, r2} {
		if r.code != ExitRefused {
			t.Errorf("exit %d, want 3", r.code)
		}
	}
}

// A path of --dir that holds a control code is written with an escape in the error and in the
// member "error", as every text is.
func TestFolderNameInAnErrorIsEscaped(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no\x1b[31m such\u0430\xff")
	for _, mode := range []string{"text", "json"} {
		r := chRun(t, "check", "history", "--dir", dir, "--output", mode)
		if r.code != ExitFailure || !onlyPrintable(r.stderr) || !onlyPrintable(r.stdout) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", mode, r.code, r.stdout, r.stderr)
		}
		if strings.Contains(r.stderr, "\x1b") || strings.Contains(r.stdout, "\x1b") {
			t.Errorf("%s: a raw escape reached the terminal", mode)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// No write.

func TestCommandWritesNothing(t *testing.T) {
	cases := map[string]func(*hbundle){
		"clean": func(*hbundle) {},
		"a changed artifact": func(b *hbundle) {
			b.rewrite(t, "trust/"+b.cs[1].set+"/keys.txt", func(s string) string { return s + "x" })
		},
		"a removed record":       func(b *hbundle) { b.remove(t, b.recordPath(2)) },
		"a notice":               func(b *hbundle) { hbWrite(t, b.dir, "history/notes.txt", "x") },
		"an unfinished ceremony": func(b *hbundle) { b.add(t, false) },
		"a fork": func(b *hbundle) {
			c := hbMake(4, b.cs[1].digest, true)
			hbWriteCeremony(t, b.dir, c)
		},
		"a temporary name": func(b *hbundle) { hbWrite(t, b.dir, "history/.rt-abcdefghijk", "x") },
		"a hostile name":   func(b *hbundle) { _ = os.Mkdir(b.path("history/a b"), 0o755) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := newHB(t, 3)
			mutate(b)
			before := hbTree(t, b.dir)
			g, count := openGuarded(t, b.dir)
			var out strings.Builder
			res, err := checkHistory(t.Context(), g, &out)
			if res == nil && err == nil {
				t.Fatal("neither a result nor an error")
			}
			if len(count.writes) != 0 {
				t.Errorf("the command called a method that writes: %v", count.writes)
			}
			if count.reads == 0 || count.opens == 0 {
				t.Errorf("the guard saw %d reads and %d opens: the command read nothing, so the check checked nothing", count.reads, count.opens)
			}
			hbSameTree(t, before, hbTree(t, b.dir))
		})
	}
}

// The command reads the bundle with fsx only; it never writes into the current folder or the
// folder of the program either.
func TestRunLeavesTheCurrentFolderAsItWas(t *testing.T) {
	b := newHB(t, 2)
	here := t.TempDir()
	hbWrite(t, here, "ritueel.yaml", "name: here\n")
	t.Chdir(here)
	before := hbTree(t, here)
	chHist(t, b.dir)
	chRun(t, "check", "history")
	chRun(t, "check", "history", "--output", "json")
	hbSameTree(t, before, hbTree(t, here))
}

// ---------------------------------------------------------------------------------------------
// The exit codes.

// "check history" returns the exit codes 0, 1, 2 and 3 and no other (docs/reference/cli.md, the
// table of the first version's commands). chRun fails a run with another code; this test runs the
// whole set of kinds of bundle and folder once more, to make that a test of its own.
func TestNoRunEndsWithAnotherExitCode(t *testing.T) {
	seen := map[ExitCode]bool{}
	var dirs []string
	for _, tc := range faultCases() {
		dirs = append(dirs, tc.build(t).dir)
	}
	dirs = append(dirs, newHB(t, 3).dir, newHB(t, 0).dir, t.TempDir(), filepath.Join(t.TempDir(), "nosuch"))
	for _, d := range dirs {
		for _, mode := range []string{"text", "json"} {
			r := chRun(t, "check", "history", "--dir", d, "--output", mode)
			seen[r.code] = true
		}
	}
	for _, code := range []ExitCode{ExitOK, ExitFailure, ExitRefused} {
		if !seen[code] {
			t.Errorf("the set of folders never ended with exit code %d", code)
		}
	}
	for code := range seen {
		if !slices.Contains([]ExitCode{ExitOK, ExitFailure, ExitRefused}, code) {
			t.Errorf("exit code %d", code)
		}
	}
}

// Earlier objects are unchanged by this command: version prints what it printed.
func TestVersionIsUnchanged(t *testing.T) {
	r := run(t, "version", "--output", "json")
	wantObject(t, jsonObject(t, r), map[string]any{
		"output": 1, "command": "version", "exit_code": 0, "outcome": "done", "version": "v1.2.3", "commit": "abc",
	})
	if r := run(t, "version"); r.stdout != versionText {
		t.Errorf("version prints %q, want %q", r.stdout, versionText)
	}
}

// ---------------------------------------------------------------------------------------------
// The seams of the command.

// A nil context is the background context: the run is made and does not panic.
func TestNilContextIsTheBackgroundContext(t *testing.T) {
	b := newHB(t, 2)
	fsys, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fsys.Close() }()
	var none context.Context
	var out strings.Builder
	res, err := checkHistory(none, fsys, &out)
	if err != nil || res == nil || res.Text != chEnd(2, b.end()) {
		t.Errorf("%+v, %v; want the end line", res, err)
	}
}

// A context that has ended is refused before the folder is read, whatever the folder holds. The
// folder here is one that cannot be read at all, so a run that looked at it would say so with
// another error.
func TestEndedContextIsRefusedBeforeAnyRead(t *testing.T) {
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	g, count := openGuarded(t, newHB(t, 1).dir)
	var out strings.Builder
	res, err := checkHistory(ended, g, &out)
	if res != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("%v, %v; want context.Canceled", res, err)
	}
	if count.opens != 0 || count.reads != 0 {
		t.Errorf("the run looked at the folder: %d opens, %d reads", count.opens, count.reads)
	}
}

// openFolders is the number of file descriptors that this process holds.
func openFolders(t *testing.T) int {
	t.Helper()
	for _, p := range []string{"/proc/self/fd", "/dev/fd"} {
		ents, err := os.ReadDir(p)
		if err == nil {
			return len(ents)
		}
	}
	t.Skip("this system does not list the open files of a process")
	return 0
}

// The folder of the bundle is closed after every run, whatever the run found: a command that reads
// a bundle is run once, but a long-lived process runs it again.
func TestEveryRunClosesTheFolders(t *testing.T) {
	clean := newHB(t, 2)
	refused := newHB(t, 2)
	refused.rewrite(t, "trust/"+refused.cs[1].set+"/keys.txt", func(s string) string { return s + "x" })
	notBundle := t.TempDir()
	here := newHB(t, 1)
	run := func() {
		chHist(t, clean.dir)
		chHist(t, refused.dir)
		chHist(t, notBundle)
		chHist(t, filepath.Join(notBundle, "nosuch"))
		chHist(t, clean.dir, "extra")
		chRun(t, "check", "history", "--dir", clean.dir, "--output", "json")
	}
	run() // the first run opens what the program opens once
	before := openFolders(t)
	for i := 0; i < 10; i++ {
		run()
	}
	// t.Chdir holds a descriptor until its test ends, so the runs in the current folder are in
	// tests of their own.
	t.Run("a current folder that holds the manifest", func(t *testing.T) {
		t.Chdir(here.dir)
		chRun(t, "check", "history")
	})
	t.Run("a current folder that does not", func(t *testing.T) {
		t.Chdir(notBundle)
		chRun(t, "check", "history")
	})
	if after := openFolders(t); after != before {
		t.Errorf("%d file descriptors before the runs and %d after: a folder was left open", before, after)
	}
}

// ---------------------------------------------------------------------------------------------
// The order of the names.

// pageOrder is the order of the table of "The hash chain" in docs/reference/ceremony-record.md, and
// the order in which the lines and the reasons are given. The test writes it out, so that a change
// of the order in the library is a change that a test sees.
var pageOrder = []string{
	"chain-broken", "fork", "record-off-chain", "record-not-canonical", "record-version-unknown", "record-invalid",
	"transcript-digest", "file-digest", "file-missing", "file-unlisted", "trust-set-unlisted", "unfinished-ceremony",
	"anchor-unknown", "unexpected-name", "unexpected-file",
}

func TestTheLibraryKeepsTheOrderOfThePage(t *testing.T) {
	if got := chCodes(history.Codes()); !slices.Equal(got, pageOrder) {
		t.Errorf("the codes are in the order\n %v\nand the page has\n %v", got, pageOrder)
	}
}

// A bundle with a fault of many kinds at once. The names in reasons and the lines are in the order
// of the page, and not in the order in which the files were damaged.
func TestManyKindsOfFaultAreGivenInTheOrderOfThePage(t *testing.T) {
	b := newHB(t, 3)
	// unexpected-file and unexpected-name first, the first codes of the page last.
	hbWrite(t, b.dir, "history/notes.txt", "x")
	if err := os.Mkdir(b.path("history/a b"), 0o755); err != nil {
		t.Fatal(err)
	}
	hbWrite(t, b.dir, "trust/"+b.cs[0].set+"/extra.txt", "x")
	b.remove(t, "trust/"+b.cs[2].set+"/keys.txt")
	b.rewrite(t, "trust/"+b.cs[1].set+"/keys.txt", func(s string) string { return s + "x" })
	b.rewrite(t, b.folderPath(1)+"/transcript.txt", func(s string) string { return s + "x" })
	// a record that names a predecessor that is not there, and a second record after record 2
	b.add(t, true, func(c *hbCeremony) { c.prev = aaaa; c.noSet = true })
	fork := hbMake(5, b.cs[1].digest, true)
	hbWriteCeremony(t, b.dir, fork)

	rep := chReport(t, b.dir)
	want := []string{"chain-broken", "fork", "transcript-digest", "file-digest", "file-missing", "file-unlisted", "unexpected-name"}
	got := chCodes(rep.Reasons())
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Fatalf("the test's bundle gives %v, which lacks %s", got, w)
		}
	}
	pos := func(c string) int { return slices.Index(pageOrder, c) }
	if !slices.IsSortedFunc(got, func(a, b string) int { return pos(a) - pos(b) }) {
		t.Errorf("reasons %v are not in the order of the page", got)
	}
	r := chHist(t, b.dir)
	if r.code != ExitRefused || r.stdout != "" {
		t.Fatalf("exit %d, stdout %q", r.code, r.stdout)
	}
	lines := chLines(r.stderr)
	var order []int
	for _, l := range lines {
		code, _, _ := strings.Cut(l, " ")
		if i := pos(code); i >= 0 {
			order = append(order, i)
		}
	}
	if !slices.IsSorted(order) || len(order) != len(rep.Findings) {
		t.Errorf("the lines are not in the order of the page: %q", lines)
	}
	if !slices.Equal(lines, chWantLines(rep)) {
		t.Errorf("the lines differ from the library's")
	}
	if last := lines[len(lines)-1]; last != "ritueel: refused: "+strings.Join(got, ", ") {
		t.Errorf("the last line is %q", last)
	}
	// Both unexpected-name (fails) and unexpected-file (a notice) are there, the name first.
	iName, iFile := -1, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "unexpected-name ") && iName < 0 {
			iName = i
		}
		if strings.HasPrefix(l, "unexpected-file ") && iFile < 0 {
			iFile = i
		}
	}
	if iName < 0 || iFile < 0 || iName > iFile {
		t.Errorf("unexpected-name at line %d and unexpected-file at line %d", iName, iFile)
	}
	chWantRefused(t, chJSON(t, b.dir), got, []string{"unexpected-file"})
}

// ---------------------------------------------------------------------------------------------
// The streams.

// An end line that could not be written is a run that did not succeed: the person would not see the
// end of the history that they came for (docs/reference/cli.md, "check history": the end line is on
// standard output). The lines on standard error are not the result: a stream that fails there changes
// nothing.
func TestEndLineThatCannotBeWrittenIsNotSuccess(t *testing.T) {
	b := newHB(t, 2)
	var stderr strings.Builder
	code := Run(t.Context(), []string{"check", "history", "--dir", b.dir}, Env{
		Stdout: &failingWriter{err: errors.New("disk full")}, Stderr: &stderr, Build: testBuild,
	})
	if code != ExitFailure || !strings.Contains(stderr.String(), "disk full") {
		t.Errorf("exit %d, stderr %q; want 1 and the cause", code, stderr.String())
	}
	code = Run(t.Context(), []string{"check", "history", "--dir", b.dir, "--output", "json"}, Env{
		Stdout: &failingWriter{err: errors.New("disk full")}, Stderr: &stderr, Build: testBuild,
	})
	if code != ExitFailure {
		t.Errorf("JSON: exit %d, want 1", code)
	}

	// Standard error that fails does not change the result of a check.
	b.rewrite(t, "trust/"+b.cs[1].set+"/keys.txt", func(s string) string { return s + "x" })
	var out strings.Builder
	code = Run(t.Context(), []string{"check", "history", "--dir", b.dir}, Env{
		Stdout: &out, Stderr: &failingWriter{err: errors.New("closed")}, Build: testBuild,
	})
	if code != ExitRefused || out.String() != "" {
		t.Errorf("a failing standard error: exit %d, stdout %q; want 3 and nothing", code, out.String())
	}
}

// The link of the page is the last element of the path. A link earlier in the path is the person's
// own path, and the folder behind it is checked.
func TestLinkInTheMiddleOfThePathIsThePersonsOwn(t *testing.T) {
	b := newHB(t, 2)
	root := t.TempDir()
	if err := os.Symlink(filepath.Dir(b.dir), filepath.Join(root, "up")); err != nil {
		t.Fatal(err)
	}
	r := chHist(t, filepath.Join(root, "up", filepath.Base(b.dir)))
	if want := chEnd(2, b.end()); r.code != ExitOK || r.stdout != want {
		t.Errorf("exit %d, stdout %q, stderr %q; want 0 and %q", r.code, r.stdout, r.stderr, want)
	}
}
