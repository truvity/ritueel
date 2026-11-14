package verifier_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/verifier"
)

func TestRequireToolsEnv(t *testing.T) {
	if verifier.RequireToolsEnv != "RITUEEL_REQUIRE_TOOLS" {
		t.Errorf("RequireToolsEnv = %q", verifier.RequireToolsEnv)
	}
}

func TestRequireFindsATool(t *testing.T) {
	dir := writeTool(t, "ritueel-fake-tool", "exit 0")
	t.Setenv("PATH", dir)
	for _, env := range []string{"", "0", "1"} {
		t.Run("with the variable "+env, func(t *testing.T) {
			t.Setenv(verifier.RequireToolsEnv, env)
			var got string
			fake := runFake(t, func(tb testing.TB) { got = verifier.Require(tb, "ritueel-fake-tool") })
			if fake.skipped || fake.failed {
				t.Fatalf("the test was skipped (%v) or failed (%v): %s", fake.skipped, fake.failed, fake.message)
			}
			if want := filepath.Join(dir, "ritueel-fake-tool"); got != want {
				t.Errorf("Require = %q, want %q", got, want)
			}
		})
	}
}

// A missing tool skips the test, unless the variable is exactly 1, and then it fails: a skip would
// be a check that did not run.
func TestRequireMissingTool(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	cases := []struct {
		name string
		set  bool
		env  string
		fail bool
	}{
		{"the variable unset", false, "", false},
		{"the variable empty", true, "", false},
		{"the variable 0", true, "0", false},
		{"the variable true", true, "true", false},
		{"the variable 2", true, "2", false},
		{"the variable 1", true, "1", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.set {
				t.Setenv(verifier.RequireToolsEnv, c.env)
			} else {
				unsetenv(t, verifier.RequireToolsEnv)
			}
			fake := runFake(t, func(tb testing.TB) { verifier.Require(tb, "ritueel-no-such-tool") })
			if c.fail && (!fake.failed || fake.skipped) {
				t.Errorf("failed = %v, skipped = %v, want a failure", fake.failed, fake.skipped)
			}
			if !c.fail && (fake.failed || !fake.skipped) {
				t.Errorf("failed = %v, skipped = %v, want a skip", fake.failed, fake.skipped)
			}
			if !strings.Contains(fake.message, "ritueel-no-such-tool") || !strings.Contains(fake.message, verifier.RequireToolsEnv) {
				t.Errorf("the message does not name the tool and the variable: %q", fake.message)
			}
		})
	}
}

// unsetenv removes a variable for the length of the test and puts it back.
func unsetenv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "") // registers the restore of the value it had, or of its absence
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
}

// A name that is not a tool: a file that is not executable, a folder with the name, and a name with
// a slash (which is a path and not a search).
func TestRequireWhatIsNotATool(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plain-file"), []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil { //nolint:gosec // a file that is not executable is the point
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "a-folder"), 0o755); err != nil { //nolint:gosec // a folder has to be enterable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	unsetenv(t, verifier.RequireToolsEnv)
	for _, name := range []string{"plain-file", "a-folder", "", "no-such-name"} {
		t.Run("the name "+name, func(t *testing.T) {
			fake := runFake(t, func(tb testing.TB) { verifier.Require(tb, name) })
			if !fake.skipped || fake.failed {
				t.Errorf("failed = %v, skipped = %v, want a skip", fake.failed, fake.skipped)
			}
		})
	}
	t.Setenv(verifier.RequireToolsEnv, "1")
	t.Run("a file that is not executable fails when the variable is 1", func(t *testing.T) {
		fake := runFake(t, func(tb testing.TB) { verifier.Require(tb, "plain-file") })
		if !fake.failed || fake.skipped {
			t.Errorf("failed = %v, skipped = %v, want a failure", fake.failed, fake.skipped)
		}
	})
}

// The tool is found on the PATH of the moment: with it emptied nothing is found, as the first check
// of the brief runs it, in a real test run in a subprocess.
func TestRequireInASubprocess(t *testing.T) {
	cases := []struct {
		name     string
		env      []string
		wantExit int
		wantLine string
	}{
		{"the variable unset: skipped", nil, 0, "--- SKIP: TestRequireChild"},
		{"the variable 1: failed", []string{verifier.RequireToolsEnv + "=1"}, 1, "--- FAIL: TestRequireChild"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRequireChild$", "-test.v")
			env := []string{"PATH=", "RITUEEL_TEST_CHILD=1"}
			for _, kv := range os.Environ() {
				if strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, verifier.RequireToolsEnv+"=") || strings.HasPrefix(kv, "RITUEEL_TEST_CHILD=") {
					continue
				}
				env = append(env, kv)
			}
			env = append(env, c.env...)
			cmd.Env = env
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			code := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != c.wantExit {
				t.Errorf("exit code = %d, want %d:\n%s", code, c.wantExit, out.String())
			}
			if !strings.Contains(out.String(), c.wantLine) {
				t.Errorf("the output has no %q:\n%s", c.wantLine, out.String())
			}
		})
	}
}

// TestRequireChild is the test that the subprocess runs. In a normal run it does nothing.
func TestRequireChild(t *testing.T) {
	if os.Getenv("RITUEEL_TEST_CHILD") != "1" {
		return
	}
	verifier.Require(t, "openssl")
	t.Log("the tool was found with an empty PATH")
}

// The name of the tool is shown in the message, escaped: control characters, bytes that are not
// UTF-8, letters that look like others and a quote do not reach the text as they are.
func TestRequireEscapesTheToolName(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	names := map[string]string{
		"an escape character":      "a\x1bb",
		"a newline":                "a\nb",
		"a NUL":                    "a\x00b",
		"a byte that is not UTF-8": "a\xffb",
		"a Cyrillic letter":        "op" + string(rune(0x0435)) + "nssl",
		"a right-to-left mark":     "a" + string(rune(0x202e)) + "b",
		"an emoji":                 "a" + string(rune(0x1f600)),
		"a quote":                  "a\"b",
	}
	for label, name := range names {
		for _, env := range []string{"", "1"} {
			t.Run(label+" with the variable "+env, func(t *testing.T) {
				if env == "" {
					unsetenv(t, verifier.RequireToolsEnv)
				} else {
					t.Setenv(verifier.RequireToolsEnv, env)
				}
				fake := runFake(t, func(tb testing.TB) { verifier.Require(tb, name) })
				if fake.skipped == (env == "1") || fake.failed != (env == "1") {
					t.Fatalf("skipped = %v, failed = %v with the variable %q", fake.skipped, fake.failed, env)
				}
				if !printable(fake.message) {
					t.Errorf("the message is not printable ASCII: %q", fake.message)
				}
				if !strings.Contains(fake.message, verifier.RequireToolsEnv) {
					t.Errorf("the message does not name the variable: %q", fake.message)
				}
			})
		}
	}
	t.Run("the escapes are the ones of the other texts", func(t *testing.T) {
		unsetenv(t, verifier.RequireToolsEnv)
		fake := runFake(t, func(tb testing.TB) { verifier.Require(tb, "a\x1bb") })
		if !strings.Contains(fake.message, `"a\u001bb"`) {
			t.Errorf("the message is %q, want the name as \"a\\u001bb\"", fake.message)
		}
		fake = runFake(t, func(tb testing.TB) { verifier.Require(tb, "plain-name") })
		if !strings.Contains(fake.message, `"plain-name"`) {
			t.Errorf("the message is %q, want the plain name in quotes", fake.message)
		}
	})
}
