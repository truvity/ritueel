//go:build linux || darwin

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// Fuzz targets of the two commands. Each reads bytes that a person does not control: the files of a request and
// of the bundle for check request, the name of the folder for new, and the text of a verdict for the output. Each
// runs the command in process, on a folder of the test, and starts no program. The seeds run under "go test"; a
// person runs a target for a time with "go test -fuzz".
//
// The properties are the ones every input must keep: the command ends, with an exit code that its page gives,
// writes only printable ASCII, calls a request accepted only with the exit code 0 and nine passed checks, and
// leaves the bundle as it found it.

// fuzzFiles are the files of the bundle that a fuzz input replaces, one at a time.
var fuzzFiles = []string{
	"requests/x509-software-valid/x509-software-valid.csr.pem",
	"requests/x509-software-valid/x509-software-valid.proof.json",
	"ritueel.yaml",
	"want/delegations/" + crqDelegation + ".yaml",
	"want/roots/" + crqRoot + ".yaml",
	"trust/" + crqTrustSet + "/root-list.json",
	"trust/" + crqTrustSet + "/ca-bundle.pem",
}

func FuzzCheckRequestFiles(f *testing.F) {
	m := crqManifestOf(f)
	c := m.byID(f, "x509-software-valid")
	tree := crqBundleTree(f, m, c)
	for i, p := range fuzzFiles {
		data, ok := tree[p]
		if !ok {
			f.Fatalf("the bundle holds no %s", p)
		}
		f.Add(uint8(i), data)
		f.Add(uint8(i), []byte{})
		f.Add(uint8(i), append([]byte{0xef, 0xbb, 0xbf}, data...))
		f.Add(uint8(i), []byte("---\n---\n"))
		f.Add(uint8(i), []byte("&a [*a]"))
		f.Add(uint8(i), []byte("\xff\xfe\x00"))
		if len(data) > 4 {
			f.Add(uint8(i), data[:len(data)/2])
			cut := append([]byte{}, data...)
			cut[len(cut)/2] ^= 0x20
			f.Add(uint8(i), cut)
		}
	}
	dir := f.TempDir()
	crqWrite(f, dir, tree)
	now := m.clock(f)
	stem := c.stem(f)
	before := crqSnapshot(f, dir)
	f.Fuzz(func(t *testing.T, which uint8, data []byte) {
		rel := fuzzFiles[int(which)%len(fuzzFiles)]
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(p, tree[rel], 0o644); err != nil {
				t.Fatal(err)
			}
			crqSame(t, "the command", before, crqSnapshot(t, dir))
		}()
		for _, withDelegation := range []bool{true, false} {
			args := []string{"check", "request", stem, "--dir", dir, "--output", "json"}
			if withDelegation {
				args = append(args, "--delegation", crqDelegation)
			}
			r := crqRun(t, now, args...)
			if r.code != ExitOK && r.code != ExitFailure && r.code != ExitRefused {
				t.Fatalf("exit code %d\n%s%s", int(r.code), r.stdout, r.stderr)
			}
			if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
				t.Fatalf("a byte that is not printable ASCII: %q %q", r.stdout, r.stderr)
			}
			obj := object(t, r.stdout)
			if obj["command"] != "check" || obj["exit_code"] != json.Number(string(rune('0'+int(r.code)))) {
				t.Fatalf("object %v for the exit code %d", obj, int(r.code))
			}
			// The text mode gives the same exit code, and its last line says the same thing.
			textArgs := []string{"check", "request", stem, "--dir", dir}
			if withDelegation {
				textArgs = append(textArgs, "--delegation", crqDelegation)
			}
			tr := crqRun(t, now, textArgs...)
			if tr.code != r.code || !onlyPrintable(tr.stdout) || !onlyPrintable(tr.stderr) {
				t.Fatalf("text mode: exit code %d (json %d), output %q %q", int(tr.code), int(r.code), tr.stdout, tr.stderr)
			}
			last := ""
			if lines := strings.Split(strings.TrimSuffix(tr.stdout, "\n"), "\n"); tr.stdout != "" {
				last = lines[len(lines)-1]
			}
			switch {
			case r.code == ExitOK && last != "request "+stem+": accepted",
				r.code == ExitRefused && !strings.HasPrefix(last, "request "+stem+": refused: "),
				r.code == ExitFailure && tr.stdout != "" && !strings.HasPrefix(last, "request "+stem+": not complete: check "):
				t.Fatalf("exit code %d and the last line %q", int(r.code), last)
			}
			if strings.Contains(tr.stdout, ": accepted") && r.code != ExitOK {
				t.Fatalf("a request that was not accepted is called accepted: %q", tr.stdout)
			}
			switch r.code {
			case ExitOK:
				checks := crqChecks(t, obj)
				if len(checks) != 9 {
					t.Fatalf("exit code 0 with %d checks", len(checks))
				}
				for _, ch := range checks {
					if ch[1] != "passed" {
						t.Fatalf("exit code 0 with a check that did not pass: %s", r.stdout)
					}
				}
				if !withDelegation {
					t.Fatalf("a request with no delegation is accepted: %s", r.stdout)
				}
				if w := stringsOf(obj["warnings"]); len(w) != 1 || w[0] != trustSetWarningText {
					t.Fatalf("an accepted request has the warnings %q, want the one warning about the trust set", w)
				}
			case ExitRefused:
				reasons := stringsOf(obj["reasons"])
				if len(reasons) != 1 || !knownCode(reasons[0]) || len(crqChecks(t, obj)) != 9 {
					t.Fatalf("a refusal that is not one known code and nine checks: %s", r.stdout)
				}
				if w := stringsOf(obj["warnings"]); len(w) != 1 || w[0] != trustSetWarningText {
					t.Fatalf("a refusal has the warnings %q, want the one warning about the trust set", w)
				}
				if !strings.HasPrefix(r.stderr, trustSetStderrLine+"ritueel: refused: ") {
					t.Fatalf("a refusal has the standard error %q, want the warning about the trust set and then the refusal", r.stderr)
				}
			case ExitFailure:
				if obj["outcome"] != "failed" {
					t.Fatalf("exit code 1 with the outcome %v", obj["outcome"])
				}
				if msg, _ := obj["error"].(string); msg == "" {
					t.Fatalf("exit code 1 with no error: %s", r.stdout)
				}
				if _, ok := obj["checks"]; ok {
					// A request that no check refused and that was not judged in full: nine results, one that
					// did not run, and the words that say so.
					checks := crqChecks(t, obj)
					notRun := false
					for _, ch := range checks {
						notRun = notRun || ch[1] == "not-run"
					}
					if len(checks) != 9 || !notRun {
						t.Fatalf("exit code 1 with checks that are not nine results with one not run: %s", r.stdout)
					}
					if msg, _ := obj["error"].(string); !strings.Contains(msg, "is not accepted and not refused: check ") {
						t.Fatalf("exit code 1 with checks and an error that does not say so: %s", r.stdout)
					}
					// The warning about the trust set comes last, and once.
					w := stringsOf(obj["warnings"])
					if len(w) < 1 || w[len(w)-1] != trustSetWarningText {
						t.Fatalf("a request that is not complete has the warnings %q, want the one about the trust set last", w)
					}
					for _, other := range w[:len(w)-1] {
						if other == trustSetWarningText {
							t.Fatalf("the warning about the trust set is not last: %q", w)
						}
					}
				} else if w := stringsOf(obj["warnings"]); len(w) != 0 {
					// A run that stopped before it had nine results has no warning about the trust set.
					t.Fatalf("a run with no nine results has the warnings %q", w)
				}
			}
		}
	})
}

func stringsOf(v any) []string {
	out, _ := stringList(v)
	return out
}

// knownCode reports whether code is one of the reason codes of the hand-off contract.
func knownCode(code string) bool {
	switch handoff.Code(code) {
	case "version-unsupported", "malformed", "request-mismatch", "algorithm-unsupported", "possession-invalid",
		"store-not-allowed", "proof-invalid", "key-mismatch", "policy", "unknown-primary":
		return true
	}
	return false
}

// The name of the folder for new: any bytes, in a parent that is free and in a parent below a bundle. The command
// ends with the exit code 0 or 1, writes printable ASCII, makes at most the one folder, a folder that it reports
// as made holds a ritueel.yaml, and nothing is made below a bundle.
func FuzzNewName(f *testing.F) {
	for _, s := range []string{"acme", "a b", "", ".", "..", "../x", ".rt-x", "CON", "a\x00b", "a\nb", "\u0435", "a/b", "a//b", "a/../b", strings.Repeat("a", 256), "é", "-x", "--dir"} {
		f.Add(s, false)
		f.Add(s, true)
	}
	free := f.TempDir()
	under := f.TempDir()
	if err := os.WriteFile(filepath.Join(under, "ritueel.yaml"), []byte(newSettingsText), 0o644); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, name string, nested bool) {
		parent := free
		if nested {
			parent = under
		}
		r := run(t, "new", parent+"/"+name)
		if r.code != ExitOK && r.code != ExitFailure {
			t.Fatalf("exit code %d for %q: %s", int(r.code), name, r.stderr)
		}
		if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
			t.Fatalf("a byte that is not printable ASCII for %q: %q %q", name, r.stdout, r.stderr)
		}
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		if nested {
			if r.code == ExitOK || len(entries) != 1 {
				t.Fatalf("a bundle was made below a bundle for %q: exit code %d, %d entries", name, int(r.code), len(entries))
			}
			return
		}
		if len(entries) > 1 {
			t.Fatalf("new made %d entries in the parent for %q", len(entries), name)
		}
		if r.code == ExitOK {
			if len(entries) != 1 {
				t.Fatalf("exit code 0 and no folder for %q", name)
			}
			if _, err := os.Stat(filepath.Join(parent, entries[0].Name(), "ritueel.yaml")); err != nil {
				t.Fatalf("exit code 0 and no ritueel.yaml for %q: %v", name, err)
			}
		}
		for _, e := range entries {
			if err := os.RemoveAll(filepath.Join(parent, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// The text of a verdict: whatever a code, a detail, a name or a rule holds, the output is printable ASCII, a
// refusal is exit code 3 with its one line, and the word accepted is in no output of a verdict that was not
// accepted.
func FuzzTheTextOfAVerdict(f *testing.F) {
	f.Add("policy", "the key is not allowed", "rule", "name", uint8(4))
	f.Add("a\x1b[31m", "b\u202e\n", "\u0435", "\x00", uint8(0))
	f.Add("", "", "", "", uint8(8))
	f.Fuzz(func(t *testing.T, code, detail, rule, name string, failedAt uint8) {
		n := int(failedAt) % 10
		v := handoff.Verdict{}
		for i := 0; i < 9; i++ {
			st := handoff.StatusPassed
			if i+1 > n && n < 9 {
				st = handoff.StatusNotRun
			}
			v.Checks = append(v.Checks, handoff.CheckResult{N: i + 1, Name: name, Status: st})
		}
		if n >= 1 && n <= 9 {
			v.Checks[n-1].Status = handoff.StatusFailed
			v.Code, v.Detail = handoff.Code(code), detail
		}
		if n == 0 {
			v.Checks[8].Status = handoff.StatusNotRun
			v.Checks[8].NotRun = []string{rule}
		}
		for _, delegation := range []string{"", "d"} {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
				return requestOutcome("stem", delegation, v)
			}})
			for _, args := range [][]string{{"fake"}, {"--output", "json", "fake"}} {
				r := run(t, args...)
				if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
					t.Fatalf("a byte that is not printable ASCII: %q %q", r.stdout, r.stderr)
				}
				if r.code != ExitFailure && r.code != ExitRefused {
					t.Fatalf("exit code %d: a verdict made by hand is neither accepted nor anything but a refusal or a failure", int(r.code))
				}
				if strings.Contains(r.stdout, ": accepted") {
					t.Fatalf("a verdict that was not accepted is called accepted: %q", r.stdout)
				}
				if r.code == ExitRefused && !strings.Contains(r.stderr, "ritueel: ") {
					t.Fatalf("a refusal with no line: %q", r.stderr)
				}
			}
		}
	})
}
