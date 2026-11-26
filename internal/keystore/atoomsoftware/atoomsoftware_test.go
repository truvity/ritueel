//go:build linux || darwin

package atoomsoftware_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"connectrpc.com/connect"

	keyv1alpha1 "github.com/truvity/atoom/key/gen/atoom/key/v1alpha1"
	"github.com/truvity/atoom/key/purpose"
	"github.com/truvity/atoom/key/software"

	"ritueel.id/ritueel/internal/keydir"
	"ritueel.id/ritueel/internal/keystore/atoomsoftware"
	"ritueel.id/ritueel/internal/keystore/port"
)

// The folder test-only-keys, which the package makes or takes, and what it never does: refuse nothing but what
// it says it refuses, change nothing that it refuses, print nothing, and write nothing outside its folder.
// The tests do not run in parallel: some change the process-wide umask, the streams or the logger.

const purposeA = "x509-root-a"

// keyDir is a new key directory in the folder of the test, with the mode 0700.
func keyDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// snapshot is what stands under dir: the kind, the mode, the target of a link and the digest of a file,
// for each path.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		line := fmt.Sprintf("%v", fi.Mode())
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			line += " -> " + target
		case fi.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			line += fmt.Sprintf(" %x", sum[:8])
		}
		out[rel] = line
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameSnapshot(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	var diff []string
	for k, v := range before {
		if w, ok := after[k]; !ok {
			diff = append(diff, "- "+k)
		} else if v != w {
			diff = append(diff, "~ "+k+": "+v+" to "+w)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			diff = append(diff, "+ "+k)
		}
	}
	slices.Sort(diff)
	if len(diff) != 0 {
		t.Errorf("%s changed the disk:\n%s", what, strings.Join(diff, "\n"))
	}
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// chmod sets the mode whatever the umask is.
func chmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestAnAbsentFolderIsMadeWithTheMode0700AndHoldsNothingBeforeTheFirstKey(t *testing.T) {
	dir := keyDir(t)
	link, err := atoomsoftware.Open(dir, []string{purposeA})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = link.Close() }()
	if got := names(t, dir); !slices.Equal(got, []string{keydir.TestOnlyFolder}) {
		t.Fatalf("the key directory holds %q, want only the folder %s", got, keydir.TestOnlyFolder)
	}
	st, err := os.Lstat(filepath.Join(dir, keydir.TestOnlyFolder))
	if err != nil || !st.IsDir() || st.Mode() != fs.ModeDir|0o700 {
		t.Errorf("the folder is %v, %v; want a folder of the mode 0700", st, err)
	}
	if got := names(t, filepath.Join(dir, keydir.TestOnlyFolder)); len(got) != 0 {
		t.Errorf("the folder holds %q before any key was made", got)
	}
	// The driver answers, and it declared the purpose.
	info, err := port.Describe(context.Background(), link.Client())
	if err != nil || info.Store != "software" {
		t.Errorf("Describe = %+v, %v", info, err)
	}
}

func TestTheModeOfAMadeFolderIs0700WhateverTheUmaskIs(t *testing.T) {
	for _, mask := range []int{0o077, 0o022, 0o000, 0o200} {
		t.Run(fmt.Sprintf("umask %04o", mask), func(t *testing.T) {
			dir := keyDir(t) // made before the mask is set, so that the test's own folders are made
			old := syscall.Umask(mask)
			defer syscall.Umask(old)
			link, err := atoomsoftware.Open(dir, []string{purposeA})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = link.Close() }()
			st, err := os.Lstat(filepath.Join(dir, keydir.TestOnlyFolder))
			if err != nil || st.Mode() != fs.ModeDir|0o700 {
				t.Errorf("the folder is %v, %v; want the mode 0700", st, err)
			}
		})
	}
}

func TestAnEmptyRealFolderOfTheMode0700WithTheRightOwnerIsTakenAsItIs(t *testing.T) {
	dir := keyDir(t)
	state := filepath.Join(dir, keydir.TestOnlyFolder)
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	chmod(t, state, 0o700)
	before, err := os.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	snap := snapshot(t, dir)
	link, err := atoomsoftware.Open(dir, []string{purposeA})
	if err != nil {
		t.Fatalf("Open of an empty folder: %v", err)
	}
	defer func() { _ = link.Close() }()
	after, err := os.Stat(state)
	if err != nil || !os.SameFile(before, after) {
		t.Errorf("the folder was replaced: %v", err)
	}
	sameSnapshot(t, "Open of an empty folder that fits", snap, snapshot(t, dir))
}

// Each refusal of the folder, and what it leaves: nothing is changed, replaced or removed.
func TestAFolderThatIsNotEmptyOrNotAFolderIsRefusedAndNothingIsChanged(t *testing.T) {
	cases := []struct {
		name   string
		make   func(t *testing.T, dir, state string)
		is     error
		isNot  error
		noPath bool // the text of the error holds no path
	}{
		{"a folder with a file", func(t *testing.T, _, state string) {
			mustMkdir(t, state, 0o700)
			mustWrite(t, filepath.Join(state, "x509-root-a.p8"), "old key")
		}, atoomsoftware.ErrFolderExists, atoomsoftware.ErrStateRefused, true},
		{"a folder with a temporary file", func(t *testing.T, _, state string) {
			mustMkdir(t, state, 0o700)
			mustWrite(t, filepath.Join(state, ".tmp-x509-root-a"), "half a key")
		}, atoomsoftware.ErrFolderExists, atoomsoftware.ErrStateRefused, true},
		{"a folder with an empty folder", func(t *testing.T, _, state string) {
			mustMkdir(t, state, 0o700)
			mustMkdir(t, filepath.Join(state, "inner"), 0o700)
		}, atoomsoftware.ErrFolderExists, atoomsoftware.ErrStateRefused, true},
		{"a file", func(t *testing.T, _, state string) { mustWrite(t, state, "a file") },
			atoomsoftware.ErrFolderExists, atoomsoftware.ErrStateRefused, true},
		{"an empty file", func(t *testing.T, _, state string) { mustWrite(t, state, "") },
			atoomsoftware.ErrFolderExists, atoomsoftware.ErrStateRefused, true},
		{"a link to an empty folder", func(t *testing.T, dir, state string) {
			target := filepath.Join(dir, "elsewhere")
			mustMkdir(t, target, 0o700)
			if err := os.Symlink(target, state); err != nil {
				t.Fatal(err)
			}
		}, atoomsoftware.ErrFolderExists, atoomsoftware.ErrStateRefused, true},
		{"a link to nothing", func(t *testing.T, dir, state string) {
			if err := os.Symlink(filepath.Join(dir, "nowhere"), state); err != nil {
				t.Fatal(err)
			}
		}, atoomsoftware.ErrFolderExists, atoomsoftware.ErrStateRefused, true},
		{"a pipe", func(t *testing.T, _, state string) {
			if err := syscall.Mkfifo(state, 0o600); err != nil {
				t.Fatal(err)
			}
		}, atoomsoftware.ErrFolderExists, atoomsoftware.ErrStateRefused, true},
		{"an empty folder of the mode 0755", func(t *testing.T, _, state string) { mustMkdir(t, state, 0o755) },
			atoomsoftware.ErrStateRefused, atoomsoftware.ErrFolderExists, true},
		{"an empty folder of the mode 0750", func(t *testing.T, _, state string) { mustMkdir(t, state, 0o750) },
			atoomsoftware.ErrStateRefused, atoomsoftware.ErrFolderExists, true},
		{"an empty folder of the mode 0500", func(t *testing.T, _, state string) { mustMkdir(t, state, 0o500) },
			atoomsoftware.ErrStateRefused, atoomsoftware.ErrFolderExists, true},
		{"an empty folder of the mode 0600", func(t *testing.T, _, state string) { mustMkdir(t, state, 0o600) },
			atoomsoftware.ErrStateRefused, atoomsoftware.ErrFolderExists, true},
		{"an empty folder of the mode 0700 with the sticky bit", func(t *testing.T, _, state string) {
			mustMkdir(t, state, 0o700)
			chmod(t, state, 0o700|fs.ModeSticky)
		}, atoomsoftware.ErrStateRefused, atoomsoftware.ErrFolderExists, true},
		{"an empty folder of the mode 0700 with the setgid bit", func(t *testing.T, _, state string) {
			mustMkdir(t, state, 0o700)
			chmod(t, state, 0o700|fs.ModeSetgid)
		}, atoomsoftware.ErrStateRefused, atoomsoftware.ErrFolderExists, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := keyDir(t)
			state := filepath.Join(dir, keydir.TestOnlyFolder)
			c.make(t, dir, state)
			before := snapshot(t, dir)
			link, err := atoomsoftware.Open(dir, []string{purposeA})
			if link != nil {
				_ = link.Close()
				t.Fatalf("a link was made over %s", c.name)
			}
			if !errors.Is(err, c.is) || errors.Is(err, c.isNot) {
				t.Fatalf("Open = %v, want %v and not %v", err, c.is, c.isNot)
			}
			if c.noPath && strings.Contains(err.Error(), dir) {
				t.Errorf("the text of the refusal holds a path: %q", err)
			}
			// The mode of a folder that a test made unreadable is looked at as it is; restore the owner's bits
			// only so that the folder of the test can be removed.
			sameSnapshot(t, "a refused Open", before, snapshot(t, dir))
			if st, err := os.Lstat(state); err == nil && st.IsDir() {
				chmod(t, state, 0o700)
			}
		})
	}
}

func mustMkdir(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	chmod(t, path, mode)
}

func mustWrite(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The text of the refusal of the driver holds the path of its folder, and the package maps it to one fixed text.
func TestTheRefusalOfTheDriverIsMappedToOneFixedTextWithNoPath(t *testing.T) {
	dir := keyDir(t)
	state := filepath.Join(dir, keydir.TestOnlyFolder)
	mustMkdir(t, state, 0o755)
	// The premise: the driver's own text names the folder, so the mapping has something to take out.
	own := software.Check(state, []purpose.Declaration{{Name: purposeA, Algorithm: purpose.ES384, Operations: []purpose.Operation{purpose.Sign}}})
	var problems *software.Problems
	if !errors.As(own, &problems) || !strings.Contains(own.Error(), state) {
		t.Fatalf("the driver's own refusal does not name its folder, so this test proves nothing: %v", own)
	}
	_, err := atoomsoftware.Open(dir, []string{purposeA})
	if !errors.Is(err, atoomsoftware.ErrStateRefused) {
		t.Fatalf("Open = %v, want ErrStateRefused", err)
	}
	if err != atoomsoftware.ErrStateRefused { //nolint:errorlint // the text is the one fixed error, not a wrapper of the driver's
		t.Errorf("the refusal is %T %q, want the fixed error itself", err, err)
	}
	for _, part := range []string{dir, state, filepath.Base(filepath.Dir(dir)), "0755"} {
		if strings.Contains(err.Error(), part) {
			t.Errorf("the text holds %q: %s", part, err)
		}
	}
	var again *software.Problems
	if errors.As(err, &again) {
		t.Error("the driver's own error can be reached from the fixed text")
	}
}

func TestAnErrorOfTheMakingOfTheFolderHoldsNoPath(t *testing.T) {
	root := t.TempDir()
	cases := map[string]string{
		"the key directory does not exist": filepath.Join(root, "absent-parent-dir"),
		"the key directory is a file":      filepath.Join(root, "afile"),
	}
	mustWrite(t, cases["the key directory is a file"], "x")
	for name, dir := range cases {
		t.Run(name, func(t *testing.T) {
			link, err := atoomsoftware.Open(dir, []string{purposeA})
			if link != nil || err == nil {
				t.Fatalf("Open = %v, %v", link, err)
			}
			if strings.Contains(err.Error(), root) || strings.Contains(err.Error(), dir) {
				t.Errorf("the text holds a path: %q", err)
			}
			if !strings.Contains(err.Error(), keydir.TestOnlyFolder) {
				t.Errorf("the text does not name the folder: %q", err)
			}
		})
	}
}

func TestAStartThatTheDriverCannotMakeSaysSoAndMakesNoKey(t *testing.T) {
	dir := keyDir(t)
	link, err := atoomsoftware.Open(dir, nil) // the driver wants at least one purpose
	if link != nil || err == nil {
		t.Fatalf("Open with no purpose = %v, %v", link, err)
	}
	if strings.Contains(err.Error(), dir) {
		t.Errorf("the text holds the path: %q", err)
	}
	if got := names(t, filepath.Join(dir, keydir.TestOnlyFolder)); len(got) != 0 {
		t.Errorf("the folder holds %q", got)
	}
}

// capture holds the three places where a driver could write: standard output, standard error and the
// default logger of the process.
type capture struct {
	stdout, stderr *os.File
	outR, errR     *os.File
	outBuf, errBuf bytes.Buffer
	logs           lockedBuffer
	wg             sync.WaitGroup
	oldOut, oldErr *os.File
	oldLogger      *slog.Logger
	oldLogOut      io.Writer
	oldFlags       int
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func startCapture(t *testing.T) *capture {
	t.Helper()
	c := &capture{oldOut: os.Stdout, oldErr: os.Stderr, oldLogger: slog.Default(), oldLogOut: log.Writer(), oldFlags: log.Flags()}
	var err error
	if c.outR, c.stdout, err = os.Pipe(); err != nil {
		t.Fatal(err)
	}
	if c.errR, c.stderr, err = os.Pipe(); err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = c.stdout, c.stderr
	// The default logger of the process writes to its own buffer, at every level, and so does the log package.
	slog.SetDefault(slog.New(slog.NewTextHandler(&c.logs, &slog.HandlerOptions{Level: slog.LevelDebug - 4})))
	log.SetOutput(&c.logs)
	c.wg.Add(2)
	go func() { defer c.wg.Done(); _, _ = io.Copy(&c.outBuf, c.outR) }()
	go func() { defer c.wg.Done(); _, _ = io.Copy(&c.errBuf, c.errR) }()
	t.Cleanup(func() { c.restore() })
	return c
}

func (c *capture) restore() {
	os.Stdout, os.Stderr = c.oldOut, c.oldErr
	slog.SetDefault(c.oldLogger)
	log.SetOutput(c.oldLogOut)
	log.SetFlags(c.oldFlags)
}

// finish puts the streams back, ends the capture and returns what was written to each place.
func (c *capture) finish() (stdout, stderr, logs string) {
	c.restore()
	_ = c.stdout.Close()
	_ = c.stderr.Close()
	c.wg.Wait()
	_ = c.outR.Close()
	_ = c.errR.Close()
	return c.outBuf.String(), c.errBuf.String(), c.logs.String()
}

// The driver is told to discard its log, so that it prints nothing and does not touch the logger of the
// process: while it starts, makes a key, signs, and refuses (an undeclared purpose, a second Ensure, a start
// over a folder it refuses), nothing reaches standard output, standard error or the default logger.
func TestTheDriverPrintsAndLogsNothingWhileItStartsMakesAKeyAndRefuses(t *testing.T) {
	// A caller that raises the level of the default logger or sets one of its own gets no line from the driver.
	cp := startCapture(t)
	dir := keyDir(t)
	link, err := atoomsoftware.Open(dir, []string{purposeA, "x509-root-b"})
	if err != nil {
		cp.finish()
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	k, err := port.Birth(ctx, link.Client(), purposeA)
	if err != nil {
		cp.finish()
		t.Fatalf("Birth: %v", err)
	}
	_ = k.Close()
	// Refusals that the driver logs when it has a logger that speaks: an existing key, a purpose that is not
	// declared, a wrong algorithm.
	if _, err := port.Birth(ctx, link.Client(), purposeA); !errors.Is(err, port.ErrKeyExists) {
		t.Errorf("a second Birth: %v", err)
	}
	if _, err := link.Client().Ensure(ctx, connect.NewRequest(&keyv1alpha1.EnsureRequest{Purpose: "not-declared", Algorithm: "ES384"})); err == nil {
		t.Error("an undeclared purpose was served")
	}
	if _, err := link.Client().Ensure(ctx, connect.NewRequest(&keyv1alpha1.EnsureRequest{Purpose: "x509-root-b", Algorithm: "RS256"})); err == nil {
		t.Error("a wrong algorithm was served")
	}
	if _, err := link.Client().Sign(ctx, connect.NewRequest(&keyv1alpha1.SignRequest{Purpose: "x509-root-b", Algorithm: "ES384", Digest: make([]byte, 48)})); err == nil {
		t.Error("a signature without a key was served")
	}
	_ = link.Close()
	// A start over a folder that the driver refuses.
	bad := keyDir(t)
	mustMkdir(t, filepath.Join(bad, keydir.TestOnlyFolder), 0o755)
	if _, err := atoomsoftware.Open(bad, []string{purposeA}); !errors.Is(err, atoomsoftware.ErrStateRefused) {
		t.Errorf("Open over a folder of the mode 0755: %v", err)
	}
	// A start over a folder that holds a key: the keys of an earlier use are never adopted.
	again := keyDir(t)
	first, err := atoomsoftware.Open(again, []string{purposeA})
	if err != nil {
		t.Fatal(err)
	}
	kk, err := port.Birth(ctx, first.Client(), purposeA)
	if err != nil {
		t.Fatal(err)
	}
	_ = kk.Close()
	_ = first.Close()
	if _, err := atoomsoftware.Open(again, []string{purposeA}); !errors.Is(err, atoomsoftware.ErrFolderExists) {
		t.Errorf("Open over a folder that holds a key: %v", err)
	}

	stdout, stderr, logs := cp.finish()
	if stdout != "" || stderr != "" || logs != "" {
		t.Errorf("the driver wrote something:\nstandard output: %q\nstandard error: %q\ndefault logger: %q", stdout, stderr, logs)
	}
}

// The premise of the test above: a driver that was given the default logger does speak, so an empty capture
// means something. It uses the driver as it stands, with a logger that the test makes.
func TestADriverWithTheDefaultLoggerWouldHaveSpokenSoTheCaptureCanTellTheDifference(t *testing.T) {
	cp := startCapture(t)
	dir := keyDir(t)
	state := filepath.Join(dir, keydir.TestOnlyFolder)
	mustMkdir(t, state, 0o700)
	svc, err := software.New(software.Options{StateDir: state, Purposes: []purpose.Declaration{{Name: purposeA, Algorithm: purpose.ES384, Operations: []purpose.Operation{purpose.Sign}}}})
	if err != nil {
		cp.finish()
		t.Fatal(err)
	}
	// Ensure on the service, with no logger given: the default logger is read at each line.
	if _, err := svc.Ensure(context.Background(), connect.NewRequest(&keyv1alpha1.EnsureRequest{Purpose: purposeA, Algorithm: "ES384"})); err != nil {
		cp.finish()
		t.Fatal(err)
	}
	_, _ = fmt.Fprint(os.Stdout, "to standard output")
	_, _ = fmt.Fprint(os.Stderr, "to standard error")
	stdout, stderr, logs := cp.finish()
	if !strings.Contains(logs, "key made") {
		t.Errorf("a driver with no logger of its own did not write to the default logger: %q", logs)
	}
	if stdout != "to standard output" || stderr != "to standard error" {
		t.Errorf("the capture of the streams does not work: %q, %q", stdout, stderr)
	}
}

// Nothing is written beside the folder: not in the key directory, not next to it, not in the working directory
// or the home of the user, however many keys are made.
func TestTheDriverWritesNoFileOutsideItsFolder(t *testing.T) {
	home, cwd, parent := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".state"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".data"))
	t.Setenv("TMPDIR", filepath.Join(parent, "tmp"))
	if err := os.Mkdir(filepath.Join(parent, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	dir := filepath.Join(parent, "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	beforeParent, beforeHome, beforeCwd := snapshot(t, parent), snapshot(t, home), snapshot(t, cwd)
	link, err := atoomsoftware.Open(dir, []string{purposeA, "x509-root-b"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{purposeA, "x509-root-b"} {
		k, err := port.Birth(context.Background(), link.Client(), p)
		if err != nil {
			t.Fatalf("Birth of %s: %v", p, err)
		}
		_ = k.Close()
	}
	_ = link.Close()

	if got := names(t, dir); !slices.Equal(got, []string{keydir.TestOnlyFolder}) {
		t.Errorf("the key directory holds %q, want only the folder %s", got, keydir.TestOnlyFolder)
	}
	if got := names(t, filepath.Join(dir, keydir.TestOnlyFolder)); !slices.Equal(got, []string{"x509-root-a.p8", "x509-root-b.p8"}) {
		t.Errorf("the folder holds %q, want the two key files and no temporary file", got)
	}
	afterParent := snapshot(t, parent)
	for k := range afterParent {
		if k != "keys" && !strings.HasPrefix(k, "keys"+string(filepath.Separator)) {
			if _, had := beforeParent[k]; !had {
				t.Errorf("a file appeared next to the key directory: %s", k)
			}
		}
	}
	sameSnapshot(t, "the driver, outside its folder (the working directory)", beforeCwd, snapshot(t, cwd))
	sameSnapshot(t, "the driver, outside its folder (the home)", beforeHome, snapshot(t, home))
	for _, f := range []string{"x509-root-a.p8", "x509-root-b.p8"} {
		st, err := os.Stat(filepath.Join(dir, keydir.TestOnlyFolder, f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v; want a file of the mode 0600", f, st, err)
		}
	}
}

func TestACloseStopsTheLinkAndLeavesTheKeysAndASecondCloseDoesNothing(t *testing.T) {
	dir := keyDir(t)
	link, err := atoomsoftware.Open(dir, []string{purposeA})
	if err != nil {
		t.Fatal(err)
	}
	k, err := port.Birth(context.Background(), link.Client(), purposeA)
	if err != nil {
		t.Fatal(err)
	}
	_ = k.Close()
	snap := snapshot(t, dir)
	if err := link.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := link.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
	var none *atoomsoftware.Link
	if err := none.Close(); err != nil {
		t.Errorf("Close of a nil Link: %v", err)
	}
	if _, err := port.Describe(context.Background(), link.Client()); err == nil {
		t.Error("the link answers after Close")
	}
	sameSnapshot(t, "Close", snap, snapshot(t, dir))
}
