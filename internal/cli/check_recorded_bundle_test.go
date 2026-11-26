//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony/ceremonytest"
	"ritueel.id/ritueel/internal/testrepo"
)

// The bundle in testdata/recorded-bundles/first-apply-x509-test-root was written by an earlier
// build of the program (its README says which and how). A history that an earlier build wrote must
// pass "check history" in every later build, so these tests run the command on a copy of it.

const recordedBundleEnd = "history: 1 ceremony records, end a19947c6\n"

// recordedBundleFiles is every file of the recorded bundle. The list is written here so that a file
// that is added to the folder or lost from it fails the test and is not skipped silently.
var recordedBundleFiles = []string{
	"history/20261120T100000Z-apply/attempt.json",
	"history/20261120T100000Z-apply/births.jsonl",
	"history/20261120T100000Z-apply/plan.json",
	"history/20261120T100000Z-apply/record.json",
	"history/20261120T100000Z-apply/signatures.jsonl",
	"history/20261120T100000Z-apply/transcript.txt",
	"history/20261120T100000Z-apply/wanted/ritueel.yaml",
	"history/20261120T100000Z-apply/wanted/want/roots/x509.yaml",
	"ritueel.yaml",
	"roots/A/root.json",
	"roots/B/root.json",
	"trust/1-9c9a9768/ca-bundle.pem",
	"trust/1-9c9a9768/root-list.json",
	"trust/1-9c9a9768/root-list.jws",
	"want/roots/x509.yaml",
}

// recordedBundle copies the recorded bundle into a folder of the test and returns the copy.
func recordedBundle(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "ca")
	ceremonytest.Copy(t, testrepo.Path(t, "testdata", "recorded-bundles", "first-apply-x509-test-root"), dst)
	return dst
}

func checkHistoryOf(t *testing.T, dir string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--dir", dir, "check", "history"}, Env{
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr, Build: testBuild, Now: func() time.Time { return apClock },
	})
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func filesOf(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

func TestTheRecordedBundleOfTheFirstApplyOfAnX509TestRootStillPassesCheckHistory(t *testing.T) {
	dir := recordedBundle(t)
	if got := filesOf(t, dir); !slices.Equal(got, recordedBundleFiles) {
		t.Fatalf("the recorded bundle holds %v, want %v", got, recordedBundleFiles)
	}
	r := checkHistoryOf(t, dir)
	if r.code != ExitOK || r.stdout != recordedBundleEnd || r.stderr != "" {
		t.Fatalf("check history: exit %d, stdout %q, stderr %q; want exit 0 and %q", r.code, r.stdout, r.stderr, recordedBundleEnd)
	}
}

// The negative control: the same command on the same copy with one byte of one recorded file
// changed does not give the answer of the unchanged copy. Without it a check that looks at nothing
// would pass the test above. The files that the record lists by digest are refused. The record is
// the head of the chain: a byte changed in it is not refused (a single record is its own end), but
// the end of the chain, which the end line shows, is no longer the same. The live wanted files,
// ritueel.yaml and want/roots/x509.yaml, are not read by the check: it reads their copies in the
// ceremony folder, so a change of the live ones is not tested here.
func TestACheckHistoryOfTheRecordedBundleDoesNotGiveTheSameAnswerForOneChangedByteOfAFileItReads(t *testing.T) {
	for _, name := range recordedBundleFiles {
		if name == "ritueel.yaml" || name == "want/roots/x509.yaml" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			dir := recordedBundle(t)
			p := filepath.Join(dir, filepath.FromSlash(name))
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			data[len(data)/2] ^= 1
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
			r := checkHistoryOf(t, dir)
			if strings.HasSuffix(name, "/record.json") {
				if r.code == ExitOK && r.stdout == recordedBundleEnd {
					t.Fatalf("one changed byte in the record gives the same end of the chain: %q", r.stdout)
				}
				return
			}
			if r.code != ExitRefused || r.stdout != "" || !strings.Contains(r.stderr, "ritueel: refused: ") {
				t.Fatalf("one changed byte in %s: exit %d, stdout %q, stderr %q; want a refusal", name, r.code, r.stdout, r.stderr)
			}
		})
	}
}
