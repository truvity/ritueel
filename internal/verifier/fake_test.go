package verifier_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// fakeTB stands in for a test: a call that fails or skips it is recorded, and stops the goroutine it
// was made in, as a real test does. Everything else (TempDir, Setenv, Cleanup) is the real test's.
type fakeTB struct {
	testing.TB
	failed  bool
	skipped bool
	message string
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatalf(format string, args ...any) {
	f.failed = true
	f.message = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func (f *fakeTB) Fatal(args ...any) {
	f.failed = true
	f.message = fmt.Sprint(args...)
	runtime.Goexit()
}

func (f *fakeTB) Skipf(format string, args ...any) {
	f.skipped = true
	f.message = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func (f *fakeTB) Skip(args ...any) {
	f.skipped = true
	f.message = fmt.Sprint(args...)
	runtime.Goexit()
}

// runFake runs f with a fake test in its own goroutine and returns what happened to it.
func runFake(t *testing.T, f func(tb testing.TB)) *fakeTB {
	t.Helper()
	fake := &fakeTB{TB: t}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		f(fake)
	}()
	wg.Wait()
	return fake
}

// writeTool writes an executable shell script called name into a new folder and returns the folder.
func writeTool(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil { //nolint:gosec // a test tool has to be executable
		t.Fatal(err)
	}
	return dir
}

// printable reports whether s holds printable ASCII only: bytes 0x20 to 0x7e.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
