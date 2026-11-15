package ceremonytest_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
)

// fakeTB is a testing.TB that records the first failure instead of failing the test, and stops the
// goroutine that made it, as Fatalf does. Everything else is the test's own.
type fakeTB struct {
	testing.TB
	mu  sync.Mutex
	msg string
}

func (f *fakeTB) fail(msg string) {
	f.mu.Lock()
	if f.msg == "" {
		f.msg = msg
	}
	f.mu.Unlock()
	runtime.Goexit()
}

func (f *fakeTB) Fatalf(format string, args ...any) { f.fail(fmt.Sprintf(format, args...)) }
func (f *fakeTB) Fatal(args ...any)                 { f.fail(fmt.Sprint(args...)) }
func (f *fakeTB) FailNow()                          { f.fail("FailNow") }
func (f *fakeTB) Errorf(format string, args ...any) { f.msg = fmt.Sprintf(format, args...) }
func (f *fakeTB) Helper()                           {}

// failsWith runs f in a goroutine with a testing.TB that records a failure, and returns the text
// of the failure; it fails the test when f does not fail.
func failsWith(t *testing.T, f func(tb testing.TB)) string {
	t.Helper()
	ft := &fakeTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f(ft)
	}()
	<-done
	if ft.msg == "" {
		t.Fatal("the call did not fail the test")
	}
	return ft.msg
}

// entry is one file or folder of a tree.
type entry struct {
	dir  bool
	size int64
	mode fs.FileMode
	sum  string
}

// treeOf reads every entry of a folder by its relative "/" path; a link or a special file is a
// fault of the bundle and fails the test.
func treeOf(t testing.TB, dir string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		e := entry{dir: d.IsDir(), size: info.Size(), mode: info.Mode().Perm()}
		switch {
		case d.IsDir():
		case info.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			h := sha256.Sum256(data)
			e.sum = hex.EncodeToString(h[:])
		default:
			t.Fatalf("%s is neither a file nor a folder", rel)
		}
		out[filepath.ToSlash(rel)] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var setFolder = regexp.MustCompile(`^trust/[0-9]+-[0-9a-f]{8}`)

// shape names the files of a tree with the name of the trust set written as "trust/N-*", so that
// the files of two bundles that differ only in the digest in that name can be compared.
func shape(tree map[string]entry) []string {
	var out []string
	for p, e := range tree {
		if e.dir {
			continue
		}
		out = append(out, setFolder.ReplaceAllString(p, "trust/N-*"))
	}
	slices.Sort(out)
	return out
}

// isLeftover says that a path has a temporary name in it: what a cut in the middle of a write leaves.
func isLeftover(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if strings.HasPrefix(strings.ToLower(part), ".rt-") {
			return true
		}
	}
	return false
}

// check runs history.Check and history.Inspect on the bundle and requires one report.
func check(t testing.TB, dir string) (*history.Report, *history.Inspection) {
	t.Helper()
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fsys.Close() }()
	rep, err := history.Check(context.Background(), fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	in, err := history.Inspect(context.Background(), fsys)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if rep.Records != in.Report.Records || len(rep.Findings) != len(in.Report.Findings) {
		t.Fatalf("Check and Inspect differ: %+v, %+v", rep, in.Report)
	}
	for i := range rep.Findings {
		if rep.Findings[i] != in.Report.Findings[i] {
			t.Fatalf("Check and Inspect differ at %d: %+v, %+v", i, rep.Findings[i], in.Report.Findings[i])
		}
	}
	return rep, in
}

// codes are the codes of the findings of a report, each once.
func codes(rep *history.Report) []history.Code {
	var out []history.Code
	for _, f := range rep.Findings {
		if !slices.Contains(out, f.Code) {
			out = append(out, f.Code)
		}
	}
	return out
}

// digestOf is the SHA-256 of the file, in lower-case hexadecimal.
func digestOf(t testing.TB, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// lines is the number of lines of a file; 0 for an empty file.
func lines(t testing.TB, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(data, []byte("\n"))
}
