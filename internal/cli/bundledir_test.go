//go:build linux || darwin

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// The folder of a command that reads a bundle (docs/reference/cli.md, the flag --dir): the folder
// that --dir names; with none, the current folder when it holds ritueel.yaml as a regular file;
// else a usage error that names --dir. These tests change the working folder and do not run in
// parallel.

func callWithDir(dir string) *Call { return &Call{Global: Global{Dir: dir}} }

// here makes a folder with the given entries, moves the test into it and returns it. An entry that
// ends in "/" is a folder, "name -> target" a symbolic link, "name |" a FIFO, any other a file.
func here(t *testing.T, entries ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e, "/"):
			if err := os.Mkdir(filepath.Join(dir, strings.TrimSuffix(e, "/")), 0o755); err != nil {
				t.Fatal(err)
			}
		case strings.Contains(e, " -> "):
			name, target, _ := strings.Cut(e, " -> ")
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		case strings.HasSuffix(e, " |"):
			if err := syscall.Mkfifo(filepath.Join(dir, strings.TrimSuffix(e, " |")), 0o600); err != nil {
				t.Fatalf("cannot make a FIFO, and the test needs one: %v", err)
			}
		default:
			if err := os.WriteFile(filepath.Join(dir, e), []byte("name: x\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Chdir(dir)
	return dir
}

func TestBundleDirIsTheFlagWhenGiven(t *testing.T) {
	for _, entries := range [][]string{nil, {"ritueel.yaml"}, {"ritueel.yaml/"}} {
		here(t, entries...)
		for _, dir := range []string{"somewhere", "/no/such/folder", "a b", "x/../y", "."} {
			got, err := bundleDir(callWithDir(dir))
			if err != nil || got != dir {
				t.Errorf("--dir %q with %v here: %q, %v; want the flag as it is", dir, entries, got, err)
			}
		}
	}
	// The folder of the flag is not opened and not looked at: a name that does not exist is not an
	// error here, the command that opens it says so.
	if _, err := bundleDir(callWithDir(filepath.Join(t.TempDir(), "nosuch"))); err != nil {
		t.Errorf("a folder that does not exist: %v", err)
	}
}

func TestBundleDirIsTheCurrentFolderWithTheManifest(t *testing.T) {
	for _, dir := range []string{""} {
		here(t, "ritueel.yaml")
		got, err := bundleDir(callWithDir(dir))
		if err != nil || got != "." {
			t.Errorf("--dir %q with the manifest here: %q, %v; want \".\"", dir, got, err)
		}
	}
	// The manifest among other entries, whatever the order of the names.
	here(t, "a", "b/", "ritueel.yaml", "z", "history/")
	if got, err := bundleDir(&Call{}); err != nil || got != "." {
		t.Errorf("the manifest among others: %q, %v", got, err)
	}
}

func TestBundleDirWithNoFlagAndNoManifestIsAUsageErrorThatNamesTheFlag(t *testing.T) {
	cases := []struct {
		name    string
		entries []string
	}{
		{"an empty folder", nil},
		{"other files", []string{"history/", "trust/", "notes.txt"}},
		{"a manifest that is a folder", []string{"ritueel.yaml/"}},
		{"a manifest that is a link to a file", []string{"real.yaml", "ritueel.yaml -> real.yaml"}},
		{"a manifest that is a link to nothing", []string{"ritueel.yaml -> nowhere"}},
		{"a manifest that is a link to a folder", []string{"real/", "ritueel.yaml -> real"}},
		{"a manifest that is a FIFO", []string{"ritueel.yaml |"}},
		{"another case", []string{"Ritueel.yaml", "RITUEEL.YAML"}},
		{"another ending", []string{"ritueel.yml", "ritueel.yaml.bak", "ritueel.json"}},
		{"a name with a space", []string{"ritueel.yaml ", " ritueel.yaml"}},
		{"a longer name", []string{"xritueel.yaml", "ritueel.yamlx"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			here(t, tc.entries...)
			got, err := bundleDir(&Call{})
			var u UsageError
			if !errors.As(err, &u) {
				t.Fatalf("%q, %v; want a usage error", got, err)
			}
			if got != "" {
				t.Errorf("a folder %q with an error", got)
			}
			if !strings.Contains(u.Error(), "--dir") {
				t.Errorf("the text does not name --dir: %q", u.Error())
			}
			if code, _ := ExitFor(err); code != ExitUsage {
				t.Errorf("exit %d, want 2", code)
			}
		})
	}
}

// Through the program: the usage error is exit 2, names --dir, and an empty --dir is not given.
func TestNoFolderIsExitTwoThroughTheProgram(t *testing.T) {
	here(t, "history/")
	for _, args := range [][]string{
		{"check", "history"},
		{"--dir", "", "check", "history"},
		{"check", "history", "--dir="},
		{"check", "history", "--dir", ""},
	} {
		r := chRun(t, args...)
		if r.code != ExitUsage || r.stdout != "" || !strings.Contains(r.stderr, "--dir") {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want 2, nothing and a text that names --dir", args, r.code, r.stdout, r.stderr)
		}
		j := chRun(t, append(args, "--output", "json")...)
		obj := jsonObject(t, j)
		wantObject(t, obj, map[string]any{
			"output": 1, "command": "check", "exit_code": 2, "outcome": "usage", "error": "<any>",
		})
		if s, _ := obj["error"].(string); !strings.Contains(s, "--dir") {
			t.Errorf("%q: the member error does not name --dir: %q", args, s)
		}
		if _, ok := obj["reasons"]; ok {
			t.Errorf("%q: a usage error has reasons: %v", args, obj)
		}
	}
	// A folder named history with no manifest is not a default: only the manifest is.
	if r := chRun(t, "check", "history"); r.code != ExitUsage {
		t.Errorf("a history folder and no manifest: exit %d, want 2", r.code)
	}
}

func TestBundleDirOfAFolderThatCannotBeListedIsNotAUsageError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test runs as root, and root lists any folder: it needs an ordinary user")
	}
	dir := here(t, "ritueel.yaml")
	if err := os.Chmod(dir, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if f, err := os.Open("."); err == nil {
		_ = f.Close()
		t.Fatal("the folder can still be listed with mode 111: the test cannot make it unreadable")
	}
	got, err := bundleDir(&Call{})
	var u UsageError
	if err == nil || errors.As(err, &u) || got != "" {
		t.Errorf("%q, %v; want an error that is not a usage error", got, err)
	}
	if code, _ := ExitFor(err); code != ExitFailure {
		t.Errorf("exit %d, want 1", code)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("the error does not say why the folder cannot be looked at: %v", err)
	}
	r := chRun(t, "check", "history")
	if r.code != ExitFailure || r.stdout != "" {
		t.Errorf("through the program: exit %d, stdout %q", r.code, r.stdout)
	}
}

// A folder with more names than a read lists is exit code 1, not a usage error and not a bundle.
func TestBundleDirOfAFolderWithTooManyNames(t *testing.T) {
	if testing.Short() {
		t.Skip("makes more than 65,536 files")
	}
	dir := here(t, "ritueel.yaml")
	for i := 0; i <= fsx.MaxDirEntries; i++ {
		f, err := os.Create(filepath.Join(dir, "f"+itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	got, err := bundleDir(&Call{})
	var u UsageError
	if err == nil || errors.As(err, &u) || got != "" {
		t.Fatalf("%q, %v; want an error that is not a usage error", got, err)
	}
	if !errors.Is(err, fsx.ErrTooMany) {
		t.Errorf("the error does not say that there are too many names: %v", err)
	}
	r := chRun(t, "check", "history")
	if r.code != ExitFailure || r.stdout != "" {
		t.Errorf("through the program: exit %d, stdout %q", r.code, r.stdout)
	}
	// With --dir the current folder is not listed at all.
	b := newHB(t, 1)
	if r := chHist(t, b.dir); r.code != ExitOK {
		t.Errorf("--dir with a crowded current folder: exit %d", r.code)
	}
}

// The folder is only looked at: bundleDir creates nothing and changes nothing.
func TestBundleDirChangesNothing(t *testing.T) {
	dir := here(t, "ritueel.yaml", "history/", "x.txt")
	before := hbTree(t, dir)
	for i := 0; i < 2; i++ {
		if _, err := bundleDir(&Call{}); err != nil {
			t.Fatal(err)
		}
	}
	hbSameTree(t, before, hbTree(t, dir))
}
