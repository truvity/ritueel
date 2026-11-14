package kms_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/kms"
	"ritueel.id/ritueel/internal/handoff/evidence/kms/kmsreplay"
	"ritueel.id/ritueel/internal/testrepo"
)

// The two packages are held to their imports and to the places they are used.
const (
	kmsDir    = "internal/handoff/evidence/kms"
	replayDir = "internal/handoff/evidence/kms/kmsreplay"
	replayPkg = "ritueel.id/ritueel/internal/handoff/evidence/kms/kmsreplay"
)

// Compile-time checks that the verifier and the replay are what the plugs ask for.
var (
	_ handoff.EvidenceVerifier = (*kms.Verifier)(nil)
	_ kms.Connector            = (*kmsreplay.Replay)(nil)
)

// importsOf returns the import paths of a Go source text.
func importsOf(t testing.TB, name, src string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var out []string
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, p)
	}
	return out
}

// sourceFiles lists the non-test Go files under the folder of the module, with their paths relative to the
// module root.
func sourceFiles(t testing.TB, dirs ...string) []string {
	t.Helper()
	root := testrepo.Root(t)
	var out []string
	for _, d := range dirs {
		base := filepath.Join(root, d)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(out)
	return out
}

// importsReplay reports whether the source imports the replay package, and is the check of the guard.
func importsReplay(t testing.TB, name, src string) bool {
	for _, p := range importsOf(t, name, src) {
		if p == replayPkg || strings.HasPrefix(p, replayPkg+"/") {
			return true
		}
	}
	return false
}

// No non-test file outside the replay's own folder imports the replay: a stub that a user supplies would be a
// copy of what the certifier must read itself.
func TestNoProgramFileImportsTheReplay(t *testing.T) {
	// The check finds what it looks for: a source that does import the replay is found, one that does not is not.
	if !importsReplay(t, "x.go", "package x\nimport _ \""+replayPkg+"\"\n") {
		t.Fatal("the check does not see an import of the replay")
	}
	if !importsReplay(t, "x.go", "package x\nimport (\n\t\"fmt\"\n\tr \""+replayPkg+"\"\n)\n") {
		t.Fatal("the check does not see an import of the replay in a list")
	}
	if importsReplay(t, "x.go", "package x\nimport \"ritueel.id/ritueel/internal/handoff/evidence/kms\"\n") {
		t.Fatal("the check sees an import of the replay in an import of the verifier")
	}

	files := sourceFiles(t, "cmd", "internal", "tools")
	if len(files) < 50 {
		t.Fatalf("the walk found %d files: a check that finds nothing to check fails", len(files))
	}
	seenReplay := false
	for _, rel := range files {
		if strings.HasPrefix(rel, replayDir+"/") {
			seenReplay = true
			continue
		}
		src, err := os.ReadFile(filepath.Join(testrepo.Root(t), rel))
		if err != nil {
			t.Fatal(err)
		}
		if importsReplay(t, rel, string(src)) {
			t.Errorf("%s imports the replay", rel)
		}
	}
	if !seenReplay {
		t.Fatalf("the walk did not find the files of %s", replayDir)
	}
}

// The non-test files of the two packages need no network, no program, no file and no AWS client.
func TestTheTwoPackagesImportNothingThatReachesOutside(t *testing.T) {
	forbidden := func(p string) bool {
		switch p {
		case "net", "net/http", "net/url", "os", "os/exec", "syscall", "io/ioutil", "plugin", "unsafe":
			return true
		}
		return strings.HasPrefix(p, "net/") || strings.HasPrefix(p, "github.com/aws/") || strings.HasPrefix(p, "aws/") ||
			strings.Contains(p, "aws-sdk")
	}
	if !forbidden("net/http") || !forbidden("github.com/aws/aws-sdk-go-v2/service/kms") || !forbidden("os") || forbidden("context") {
		t.Fatal("the rule does not say what it should")
	}
	files := sourceFiles(t, kmsDir)
	var inKMS, inReplay int
	for _, rel := range files {
		if strings.HasPrefix(rel, replayDir+"/") {
			inReplay++
		} else {
			inKMS++
		}
		src, err := os.ReadFile(filepath.Join(testrepo.Root(t), rel))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range importsOf(t, rel, string(src)) {
			if forbidden(p) {
				t.Errorf("%s imports %s", rel, p)
			}
		}
	}
	if inKMS < 6 || inReplay < 2 {
		t.Fatalf("the walk found %d files of the verifier and %d of the replay: a check that finds nothing to check fails", inKMS, inReplay)
	}
}

// The non-test files of the verifier do not import the replay, so the verifier has no test seam of its own.
func TestTheVerifierDoesNotImportTheReplay(t *testing.T) {
	for _, rel := range sourceFiles(t, kmsDir) {
		if strings.HasPrefix(rel, replayDir+"/") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(testrepo.Root(t), rel))
		if err != nil {
			t.Fatal(err)
		}
		if importsReplay(t, rel, string(src)) {
			t.Errorf("%s imports the replay", rel)
		}
	}
}

// The module does not take an AWS client with this part.
func TestTheModuleHasNoAWSClient(t *testing.T) {
	for _, name := range []string{"go.mod", "go.sum"} {
		data := testrepo.Read(t, name)
		if len(data) == 0 {
			t.Fatalf("%s is empty", name)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "aws-sdk") || strings.Contains(line, "github.com/aws/") {
				t.Errorf("%s: %s", name, line)
			}
		}
	}
}
