package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// readSources reads the module's own Go files and go.mod. This test builds a program from
// files it would otherwise never open, and the go tool keeps a passing result until a file
// the test opened changes: without these reads, a change to the code under internal/ would
// leave the test reported as "(cached)" and it would not run again.
func readSources(t *testing.T) {
	t.Helper()
	root := filepath.Join("..", "..")
	read := func(path string) {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatalf("reading a source file: %v", err)
		}
	}
	read(filepath.Join(root, "go.mod"))
	read(filepath.Join(root, "go.sum"))
	for _, dir := range []string{filepath.Join(root, "internal"), "."} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") {
				read(path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
}

// The program is built the way the release builds it (no cgo, paths trimmed, the version and
// the commit stamped in) and run as a process, so that what is checked is the real
// executable: its exit code, its standard output and its standard error.
func TestProgram(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is not on PATH: cannot build the program for this test")
	}

	readSources(t)

	const (
		stampedVersion = "v9.8.7-test"
		stampedCommit  = "0123456789abcdef0123456789abcdef01234567"
		pkg            = "ritueel.id/ritueel/internal/buildinfo"
	)
	exe := filepath.Join(t.TempDir(), "ritueel")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	build := exec.CommandContext(t.Context(), goBin, "build", "-trimpath",
		"-ldflags", "-X "+pkg+".version="+stampedVersion+" -X "+pkg+".commit="+stampedCommit,
		"-o", exe, "ritueel.id/ritueel/cmd/ritueel")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}

	runExe := func(t *testing.T, args ...string) (code int, stdout, stderr string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), exe, args...)
		cmd.Dir = t.TempDir()
		var out, errOut bytes.Buffer
		cmd.Stdin = strings.NewReader("")
		cmd.Stdout = &out
		cmd.Stderr = &errOut
		err := cmd.Run()
		var ee *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &ee):
			code = ee.ExitCode()
		default:
			t.Fatalf("running the program: %v", err)
		}
		return code, out.String(), errOut.String()
	}

	t.Run("version", func(t *testing.T) {
		code, stdout, stderr := runExe(t, "version")
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
		if want := "ritueel " + stampedVersion + " (commit " + stampedCommit + ")\n"; stdout != want {
			t.Errorf("stdout = %q, want %q", stdout, want)
		}
		if stderr != "" {
			t.Errorf("stderr = %q, want empty", stderr)
		}
	})

	t.Run("no arguments", func(t *testing.T) {
		code, stdout, stderr := runExe(t)
		if code != 2 {
			t.Errorf("exit code = %d, want 2", code)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty", stdout)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Error("stderr is empty, want a message")
		}
	})

	t.Run("version as JSON", func(t *testing.T) {
		code, stdout, stderr := runExe(t, "version", "--output", "json")
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
		if stderr != "" {
			t.Errorf("stderr = %q, want empty", stderr)
		}
		if strings.Count(stdout, "\n") != 1 || !strings.HasSuffix(stdout, "\n") {
			t.Fatalf("stdout is not one line: %q", stdout)
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(stdout), &obj); err != nil {
			t.Fatalf("stdout is not a JSON object: %v: %q", err, stdout)
		}
		want := map[string]any{
			"output":    float64(1),
			"command":   "version",
			"exit_code": float64(0),
			"outcome":   "done",
			"version":   stampedVersion,
			"commit":    stampedCommit,
		}
		if len(obj) != len(want) {
			t.Errorf("object has %d members, want %d: %v", len(obj), len(want), obj)
		}
		for k, w := range want {
			if obj[k] != w {
				t.Errorf("member %q = %v, want %v", k, obj[k], w)
			}
		}
	})
}
