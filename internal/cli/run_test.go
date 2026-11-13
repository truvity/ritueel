package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/buildinfo"
)

// The tests in this package that change the command table (withSpecs) must not run in
// parallel, and none of them does.

var testBuild = buildinfo.Info{Version: "v1.2.3", Commit: "abc"}

const (
	versionText = "ritueel v1.2.3 (commit abc)\n"
	nilEnvVar   = "RITUEEL_CLI_TEST_NIL_ENV_ARGS"
)

// nilEnvArgs are the argument lists the nil-environment test runs in a separate process.
var nilEnvArgs = [][]string{
	{"version"},
	{"--output", "json", "version"},
	{"nosuch"},
	{},
	{"--output", "json", "nosuch"},
	{"--help"},
}

// TestMain lets the test binary run itself with an Env whose streams are all nil, so that the
// test can see the process's real standard streams (see TestNilEnvWritesNothing).
func TestMain(m *testing.M) {
	if raw := os.Getenv(nilEnvVar); raw != "" {
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			os.Exit(99)
		}
		code := Run(context.Background(), args, Env{Build: testBuild})
		os.Exit(int(code))
	}
	os.Exit(m.Run())
}

// result is one run of the command line.
type result struct {
	code           ExitCode
	stdout, stderr string
}

// run runs the command line in process with fresh buffers and the fixed build.
func run(t *testing.T, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(t.Context(), args, Env{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
		Build:  testBuild,
	})
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// object decodes standard output as exactly one JSON object followed by one newline and
// nothing else.
func object(t *testing.T, stdout string) map[string]any {
	t.Helper()
	if !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("standard output does not end with a newline: %q", stdout)
	}
	if n := strings.Count(stdout, "\n"); n != 1 {
		t.Fatalf("standard output has %d newlines, want exactly 1: %q", n, stdout)
	}
	dec := json.NewDecoder(strings.NewReader(stdout))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		t.Fatalf("standard output is not a JSON object: %v: %q", err, stdout)
	}
	if rest := strings.TrimSpace(stdout[dec.InputOffset():]); rest != "" {
		t.Fatalf("standard output holds more than the one object: %q", rest)
	}
	return obj
}

func keysOf(m map[string]any) []string {
	return slices.Sorted(maps.Keys(m))
}

// wantObject checks the exact set of members and the values of the members given.
func wantObject(t *testing.T, obj map[string]any, want map[string]any) {
	t.Helper()
	if got, wantKeys := keysOf(obj), keysOf(want); !slices.Equal(got, wantKeys) {
		t.Errorf("members = %v, want %v (object %v)", got, wantKeys, obj)
	}
	for k, w := range want {
		g, ok := obj[k]
		if !ok {
			continue
		}
		if s, isString := w.(string); isString && s == "<any>" {
			if str, _ := g.(string); str == "" {
				t.Errorf("member %q is empty or not a string: %v", k, g)
			}
			continue
		}
		var gotText string
		switch gv := g.(type) {
		case json.Number:
			gotText = gv.String()
		default:
			gotText = fmt.Sprint(gv)
		}
		if gotText != fmt.Sprint(w) {
			t.Errorf("member %q = %v, want %v", k, g, w)
		}
	}
}

// withSpecs replaces the command table for the length of the test.
func withSpecs(t *testing.T, replacement ...spec) {
	t.Helper()
	saved := specs
	t.Cleanup(func() { specs = saved })
	specs = replacement
}

func TestVersionText(t *testing.T) {
	r := run(t, "version")
	if r.code != ExitOK {
		t.Errorf("exit code = %d, want 0", int(r.code))
	}
	if r.stdout != versionText {
		t.Errorf("stdout = %q, want %q", r.stdout, versionText)
	}
	if r.stderr != "" {
		t.Errorf("stderr = %q, want empty", r.stderr)
	}
}

func TestExplicitTextOutput(t *testing.T) {
	for _, args := range [][]string{
		{"--output", "text", "version"},
		{"version", "--output", "text"},
		{"--output=text", "version"},
	} {
		r := run(t, args...)
		if r.code != ExitOK || r.stdout != versionText || r.stderr != "" {
			t.Errorf("%v: got (%d, %q, %q)", args, int(r.code), r.stdout, r.stderr)
		}
	}
}

func TestVersionJSON(t *testing.T) {
	want := map[string]any{
		"output":    1,
		"command":   "version",
		"exit_code": 0,
		"outcome":   "done",
		"version":   "v1.2.3",
		"commit":    "abc",
	}
	for _, args := range [][]string{
		{"version", "--output", "json"},
		{"--output", "json", "version"},
		{"--output=json", "version"},
		{"version", "--output=json"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			r := run(t, args...)
			if r.code != ExitOK {
				t.Errorf("exit code = %d, want 0", int(r.code))
			}
			if r.stderr != "" {
				t.Errorf("stderr = %q, want empty", r.stderr)
			}
			wantObject(t, object(t, r.stdout), want)
		})
	}
}

// The values in the object are the ones of the build, not constants.
func TestVersionJSONCarriesTheBuild(t *testing.T) {
	var stdout bytes.Buffer
	code := Run(t.Context(), []string{"--output", "json", "version"}, Env{
		Stdout: &stdout,
		Build:  buildinfo.Info{Version: "v7.0.1-rc.2", Commit: "0011223344"},
	})
	if code != ExitOK {
		t.Fatalf("exit code = %d, want 0", int(code))
	}
	wantObject(t, object(t, stdout.String()), map[string]any{
		"output": 1, "command": "version", "exit_code": 0, "outcome": "done",
		"version": "v7.0.1-rc.2", "commit": "0011223344",
	})
}

func TestUsageErrorsInText(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"empty argument list", []string{}},
		{"unknown command", []string{"nosuch"}},
		{"unknown command after global flag", []string{"--dir", "x", "nosuch"}},
		{"help is not a command word", []string{"help"}},
		{"unknown output value after the command", []string{"version", "--output", "xml"}},
		{"unknown output value before the command", []string{"--output", "xml"}},
		{"unknown output value with the command", []string{"--output", "xml", "version"}},
		{"empty output value", []string{"--output="}},
		{"empty output value with the command", []string{"--output=", "version"}},
		{"output without a value", []string{"--output"}},
		{"output without a value after the command", []string{"version", "--output"}},
		{"dir without a value", []string{"--dir"}},
		{"unknown flag before the command", []string{"--nosuchflag", "version"}},
		{"unknown flag after the command", []string{"version", "--nosuchflag"}},
		{"extra argument", []string{"version", "extra"}},
		{"uppercase output value", []string{"--output", "JSON", "version"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, tt.args...)
			if r.code != ExitUsage {
				t.Errorf("exit code = %d, want 2", int(r.code))
			}
			if r.stdout != "" {
				t.Errorf("stdout = %q, want empty", r.stdout)
			}
			if strings.TrimSpace(r.stderr) == "" {
				t.Error("stderr is empty, want a message")
			}
		})
	}
}

// With --output json, a usage error is one object whose outcome is "usage". The message is
// on standard error as well.
func TestUsageErrorsInJSON(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		command string
	}{
		{"unknown command", []string{"--output", "json", "nosuch"}, ""},
		{"unknown command with the equals form", []string{"--output=json", "nosuch"}, ""},
		{"help is not a command word", []string{"--output", "json", "help"}, ""},
		{"no command", []string{"--output", "json"}, ""},
		{"unknown flag after the output flag", []string{"--output", "json", "--nosuchflag", "version"}, ""},
		{"extra argument", []string{"version", "extra", "--output", "json"}, "version"},
		{"extra argument, output first", []string{"--output", "json", "version", "extra"}, "version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, tt.args...)
			if r.code != ExitUsage {
				t.Errorf("exit code = %d, want 2", int(r.code))
			}
			obj := object(t, r.stdout)
			wantObject(t, obj, map[string]any{
				"output":    1,
				"command":   tt.command,
				"exit_code": 2,
				"outcome":   "usage",
				"error":     "<any>",
			})
			msg, _ := obj["error"].(string)
			if !strings.Contains(r.stderr, msg) {
				t.Errorf("stderr %q does not hold the message %q", r.stderr, msg)
			}
		})
	}
}

// Only arguments so broken that the output mode is unknown print no object, in any mode.
func TestNoObjectWhenTheModeIsNotKnown(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"unknown value after the command", []string{"version", "--output", "xml"}},
		{"unknown value before the command", []string{"--output", "xml"}},
		{"unknown value, no command", []string{"--output", "xml", "nosuch"}},
		{"empty value", []string{"--output="}},
		{"no value", []string{"--output"}},
		{"unknown flag before the output flag", []string{"--nosuchflag", "--output", "json", "version"}},
		{"unknown value, then json", []string{"--output", "xml", "--output", "json", "version"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, tt.args...)
			if r.code != ExitUsage {
				t.Errorf("exit code = %d, want 2", int(r.code))
			}
			if r.stdout != "" {
				t.Errorf("stdout = %q, want empty: no object when the mode is not known", r.stdout)
			}
			if strings.TrimSpace(r.stderr) == "" {
				t.Error("stderr is empty, want a message")
			}
		})
	}
}

func TestHelpIsNotACommand(t *testing.T) {
	for _, args := range [][]string{
		{"--help"},
		{"-h"},
		{"version", "--help"},
		{"version", "-h"},
		{"--output", "json", "--help"},
		{"--output", "json", "version", "--help"},
		{"--output=json", "-h"},
		{"version", "--help", "--output", "json"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			r := run(t, args...)
			if r.code != ExitOK {
				t.Errorf("exit code = %d, want 0", int(r.code))
			}
			if r.stderr != "" {
				t.Errorf("stderr = %q, want empty", r.stderr)
			}
			if !strings.Contains(r.stdout, "version") {
				t.Errorf("the usage does not name version: %q", r.stdout)
			}
			if strings.HasPrefix(strings.TrimSpace(r.stdout), "{") {
				t.Errorf("help printed a JSON object: %q", r.stdout)
			}
			var anyJSON map[string]any
			if json.Unmarshal([]byte(r.stdout), &anyJSON) == nil {
				t.Errorf("help printed a JSON object: %q", r.stdout)
			}
		})
	}
}

// The usage lists the command words that exist and no "help" command.
func TestUsageListsOnlyTheCommands(t *testing.T) {
	r := run(t, "--help")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0", int(r.code))
	}
	inCommands := false
	var commands []string
	for line := range strings.SplitSeq(r.stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasSuffix(trimmed, ":") && strings.ToUpper(trimmed) == trimmed:
			inCommands = trimmed == "COMMANDS:"
		case trimmed == "":
			// A blank line does not end the section: the library puts one under the title.
		case inCommands:
			word, _, _ := strings.Cut(trimmed, " ")
			commands = append(commands, strings.TrimSuffix(word, ","))
		}
	}
	if !slices.Equal(commands, []string{"version"}) {
		t.Errorf("commands in the usage = %v, want [version]\n%s", commands, r.stdout)
	}
	if strings.Contains(r.stdout, "Shows a list of commands") {
		t.Errorf("the usage lists a help command:\n%s", r.stdout)
	}
	// The same words in a second place: the usage of the program shows the global flags.
	for _, flag := range []string{"--dir", "--output"} {
		if !strings.Contains(r.stdout, flag) {
			t.Errorf("the usage does not name %s:\n%s", flag, r.stdout)
		}
	}
}

func TestHelpWordIsUsageEvenInJSON(t *testing.T) {
	r := run(t, "--output", "json", "help")
	if r.code != ExitUsage {
		t.Fatalf("exit code = %d, want 2", int(r.code))
	}
	obj := object(t, r.stdout)
	if obj["outcome"] != "usage" {
		t.Errorf("outcome = %v, want usage", obj["outcome"])
	}
}

func TestGlobalFlagsAreAccepted(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"double dash before the word", []string{"--", "version"}},
		{"dir before the word", []string{"--dir", "x", "version"}},
		{"dir after the word", []string{"version", "--dir", "x"}},
		{"dir with an equals sign", []string{"--dir=x", "version"}},
		{"dir on both sides", []string{"--dir", "x", "version", "--dir", "y"}},
		{"dir with the output flag", []string{"--dir", "x", "--output", "text", "version"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, tt.args...)
			if r.code != ExitOK {
				t.Errorf("exit code = %d, want 0 (stderr %q)", int(r.code), r.stderr)
			}
			if r.stdout != versionText {
				t.Errorf("stdout = %q, want %q", r.stdout, versionText)
			}
			if r.stderr != "" {
				t.Errorf("stderr = %q, want empty", r.stderr)
			}
		})
	}

	r := run(t, "--dir", "x", "--output", "json", "version")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", int(r.code), r.stderr)
	}
	wantObject(t, object(t, r.stdout), map[string]any{
		"output": 1, "command": "version", "exit_code": 0, "outcome": "done",
		"version": "v1.2.3", "commit": "abc",
	})
}

// Two runs in one process share nothing: the output mode and the folder of one do not leak
// into the next.
func TestRunsShareNoState(t *testing.T) {
	jsonWant := map[string]any{
		"output": 1, "command": "version", "exit_code": 0, "outcome": "done",
		"version": "v1.2.3", "commit": "abc",
	}

	first := run(t, "--output", "json", "version")
	if first.code != ExitOK {
		t.Fatalf("first run: exit code = %d", int(first.code))
	}
	wantObject(t, object(t, first.stdout), jsonWant)

	second := run(t, "version")
	if second.code != ExitOK || second.stdout != versionText || second.stderr != "" {
		t.Errorf("second run (text after json) = (%d, %q, %q), want plain text", int(second.code), second.stdout, second.stderr)
	}

	third := run(t, "--output", "json", "version")
	if third.code != ExitOK || third.stderr != "" {
		t.Errorf("third run: (%d, %q)", int(third.code), third.stderr)
	}
	wantObject(t, object(t, third.stdout), jsonWant)

	// A failed run does not leave its mode or its command behind either.
	bad := run(t, "--output", "json", "nosuch")
	if bad.code != ExitUsage {
		t.Errorf("failed run: exit code = %d, want 2", int(bad.code))
	}
	after := run(t, "version")
	if after.code != ExitOK || after.stdout != versionText || after.stderr != "" {
		t.Errorf("text run after a json failure = (%d, %q, %q)", int(after.code), after.stdout, after.stderr)
	}
	badText := run(t, "--output", "xml")
	if badText.code != ExitUsage || badText.stdout != "" {
		t.Errorf("run with an unknown mode after a json run = (%d, %q)", int(badText.code), badText.stdout)
	}
	again := run(t, "--dir", "somewhere", "version")
	if again.code != ExitOK || again.stdout != versionText {
		t.Errorf("run after --dir = (%d, %q)", int(again.code), again.stdout)
	}

	// The command word and the result of a finished run are not left behind: a failure with
	// no command word names none, and help prints the usage, not an earlier result.
	bad = run(t, "--output", "json", "nosuch")
	wantObject(t, object(t, bad.stdout), map[string]any{
		"output": 1, "command": "", "exit_code": 2, "outcome": "usage", "error": "<any>",
	})
	help := run(t, "--help")
	if help.code != ExitOK || strings.Contains(help.stdout, "commit abc") {
		t.Errorf("help after a version run = (%d, %q), want the usage only", int(help.code), help.stdout)
	}
	helpJSON := run(t, "--output", "json", "--help")
	if helpJSON.code != ExitOK || strings.Contains(helpJSON.stdout, `"commit"`) {
		t.Errorf("json help after a version run = (%d, %q), want the usage only", int(helpJSON.code), helpJSON.stdout)
	}
}

// The folder of one run is not the folder of the next.
func TestRunsShareNoFolder(t *testing.T) {
	var dirs []string
	withSpecs(t, spec{name: "fake", usage: "a test command", run: func(_ context.Context, c *Call) (*Result, error) {
		dirs = append(dirs, c.Global.Dir)
		return &Result{}, nil
	}})
	for _, args := range [][]string{{"--dir", "first", "fake"}, {"fake"}, {"fake", "--dir", "third"}, {"fake"}} {
		if r := run(t, args...); r.code != ExitOK {
			t.Fatalf("%v: exit code = %d", args, int(r.code))
		}
	}
	if want := []string{"first", "", "third", ""}; !slices.Equal(dirs, want) {
		t.Errorf("folders seen by the command = %q, want %q", dirs, want)
	}
}

// The same Env value can be used for two runs; each run writes to its streams only once.
func TestRunTwiceOnOneEnv(t *testing.T) {
	var stdout, stderr bytes.Buffer
	env := Env{Stdout: &stdout, Stderr: &stderr, Build: testBuild}
	if code := Run(t.Context(), []string{"version"}, env); code != ExitOK {
		t.Fatalf("exit code = %d", int(code))
	}
	if code := Run(t.Context(), []string{"version"}, env); code != ExitOK {
		t.Fatalf("exit code = %d", int(code))
	}
	if got, want := stdout.String(), versionText+versionText; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

// With every stream nil, the run returns the right code and writes nothing to the real
// standard streams. It runs in a separate process (the test binary itself, see TestMain), so
// that the real file descriptors 1 and 2 are the ones looked at.
func TestNilEnvWritesNothing(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find the test binary: %v", err)
	}
	wantCodes := []ExitCode{ExitOK, ExitOK, ExitUsage, ExitUsage, ExitUsage, ExitOK}
	for i, args := range nilEnvArgs {
		t.Run(strings.Join(append([]string{"run"}, args...), " "), func(t *testing.T) {
			raw, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), exe)
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), nilEnvVar+"="+string(raw))
			var stdout, stderr bytes.Buffer
			cmd.Stdin = strings.NewReader("")
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err = cmd.Run()
			code := 0
			if err != nil {
				var ee *exec.ExitError
				if !errors.As(err, &ee) {
					t.Fatalf("running the test binary: %v", err)
				}
				code = ee.ExitCode()
			}
			if code != int(wantCodes[i]) {
				t.Errorf("exit code = %d, want %d", code, int(wantCodes[i]))
			}
			if stdout.Len() != 0 {
				t.Errorf("wrote to the real standard output: %q", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("wrote to the real standard error: %q", stderr.String())
			}
		})
	}
}

// A usage error comes back as a code. The library never ends the process: if it did, the
// test binary would stop here and the test run would fail.
func TestUsageErrorNeverEndsTheProcess(t *testing.T) {
	for range 3 {
		for _, args := range [][]string{
			nil,
			{"nosuch"},
			{"--nosuchflag"},
			{"--output", "xml"},
			{"--output"},
			{"version", "extra"},
			{"--output", "json", "version", "extra"},
			{"help"},
		} {
			if r := run(t, args...); r.code != ExitUsage {
				t.Errorf("%v: exit code = %d, want 2", args, int(r.code))
			}
		}
	}
	// A command that returns a usage error, coded and wrapped, also comes back.
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		return nil, fmt.Errorf("outer: %w", UsageError{Msg: "inner"})
	}})
	if r := run(t, "fake"); r.code != ExitUsage {
		t.Errorf("wrapped usage error from a command: exit code = %d, want 2", int(r.code))
	}
}

func TestCommandResults(t *testing.T) {
	plain := errors.New("disk on fire")
	tests := []struct {
		name        string
		err         error
		code        ExitCode
		outcome     string
		reasons     []string
		errorText   string
		wantReasons bool
	}{
		{"usage error", UsageError{Msg: "wrong form"}, 2, "usage", nil, "wrong form", false},
		{"usage error pointer", &UsageError{Msg: "wrong form"}, 2, "usage", nil, "wrong form", false},
		{"refusal", Refusal{Reasons: []string{"policy", "plan-stale"}, Msg: "no"}, 3, "refused", []string{"policy", "plan-stale"}, "no", true},
		{"refusal pointer", &Refusal{Reasons: []string{"policy"}, Msg: "no"}, 3, "refused", []string{"policy"}, "no", true},
		{"refusal with reasons only", Refusal{Reasons: []string{"declined"}}, 3, "refused", []string{"declined"}, "refused: declined", true},
		{"refusal with no reasons", Refusal{Msg: "no"}, 3, "refused", nil, "no", false},
		{"backend refusal", BackendRefusal{Reasons: []string{"pin-locked"}, Msg: "the card said no"}, 4, "refused", []string{"pin-locked"}, "the card said no", true},
		{"backend refusal pointer", &BackendRefusal{Reasons: []string{"kms-session"}}, 4, "refused", []string{"kms-session"}, "refused by the card or the backend: kms-session", true},
		{"not confirmed", NotConfirmed{}, 5, "not-confirmed", nil, "not confirmed", false},
		{"not confirmed pointer", &NotConfirmed{}, 5, "not-confirmed", nil, "not confirmed", false},
		{"plain error", plain, 1, "failed", nil, "disk on fire", false},
		{"wrapped plain error", fmt.Errorf("while writing: %w", plain), 1, "failed", nil, "while writing: disk on fire", false},
		{"wrapped refusal", fmt.Errorf("apply: %w", Refusal{Reasons: []string{"policy"}, Msg: "no"}), 3, "refused", []string{"policy"}, "apply: no", true},
		{"wrapped backend refusal", fmt.Errorf("sign: %w", BackendRefusal{Reasons: []string{"pin-locked"}, Msg: "locked"}), 4, "refused", []string{"pin-locked"}, "sign: locked", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "a test command", run: func(context.Context, *Call) (*Result, error) {
				return nil, tt.err
			}})
			wantStderr := "ritueel: " + tt.errorText + "\n"

			t.Run("json", func(t *testing.T) {
				r := run(t, "--output", "json", "fake")
				if r.code != tt.code {
					t.Errorf("exit code = %d, want %d", int(r.code), int(tt.code))
				}
				obj := object(t, r.stdout)
				_, hasReasons := obj["reasons"]
				if hasReasons != tt.wantReasons {
					t.Errorf("reasons present = %v, want %v (object %v)", hasReasons, tt.wantReasons, obj)
				}
				if hasReasons {
					var got []string
					list, _ := obj["reasons"].([]any)
					for _, v := range list {
						s, _ := v.(string)
						got = append(got, s)
					}
					if !slices.Equal(got, tt.reasons) {
						t.Errorf("reasons = %v, want %v", got, tt.reasons)
					}
					delete(obj, "reasons")
				}
				wantObject(t, obj, map[string]any{
					"output":    1,
					"command":   "fake",
					"exit_code": int(tt.code),
					"outcome":   tt.outcome,
					"error":     tt.errorText,
				})
				if !strings.HasPrefix(r.stderr, wantStderr) {
					t.Errorf("stderr = %q, want it to start with %q", r.stderr, wantStderr)
				}
			})

			t.Run("text", func(t *testing.T) {
				r := run(t, "fake")
				if r.code != tt.code {
					t.Errorf("exit code = %d, want %d", int(r.code), int(tt.code))
				}
				if r.stdout != "" {
					t.Errorf("stdout = %q, want empty", r.stdout)
				}
				if !strings.HasPrefix(r.stderr, wantStderr) {
					t.Errorf("stderr = %q, want it to start with %q", r.stderr, wantStderr)
				}
			})
		})
	}
}

// A command that ends well may still return a status code (10, 11, 12): the outcome is done.
func TestCommandReturningAStatusCode(t *testing.T) {
	for _, code := range []ExitCode{ExitNotice, ExitAlert, ExitCritical} {
		t.Run(fmt.Sprint(int(code)), func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "a test command", run: func(context.Context, *Call) (*Result, error) {
				return &Result{ExitCode: code, Text: "findings\n"}, nil
			}})
			text := run(t, "fake")
			if text.code != code || text.stdout != "findings\n" || text.stderr != "" {
				t.Errorf("text: (%d, %q, %q)", int(text.code), text.stdout, text.stderr)
			}
			js := run(t, "--output", "json", "fake")
			if js.code != code || js.stderr != "" {
				t.Errorf("json: (%d, %q)", int(js.code), js.stderr)
			}
			wantObject(t, object(t, js.stdout), map[string]any{
				"output": 1, "command": "fake", "exit_code": int(code), "outcome": "done",
			})
		})
	}
}

// What a command is given: its arguments, the folder and the mode from the global flags,
// before or after the word.
func TestCommandCall(t *testing.T) {
	var got *Call
	withSpecs(t, spec{name: "fake", usage: "a test command", run: func(_ context.Context, c *Call) (*Result, error) {
		got = c
		return &Result{}, nil
	}})

	for _, args := range [][]string{
		{"--dir", "d", "--output", "json", "fake", "a", "b"},
		{"fake", "--dir", "d", "--output", "json", "a", "b"},
		{"--dir=d", "fake", "a", "--output=json", "b"},
	} {
		got = nil
		r := run(t, args...)
		if r.code != ExitOK {
			t.Fatalf("%v: exit code = %d (stderr %q)", args, int(r.code), r.stderr)
		}
		if got == nil {
			t.Fatalf("%v: the command did not run", args)
		}
		if got.Global.Dir != "d" || got.Global.Output != OutputJSON {
			t.Errorf("%v: Global = %+v, want dir d and json", args, got.Global)
		}
		if !slices.Equal(got.Args, []string{"a", "b"}) {
			t.Errorf("%v: Args = %v, want [a b]", args, got.Args)
		}
		if got.Env.Build != testBuild {
			t.Errorf("%v: Build = %+v", args, got.Env.Build)
		}
	}

	got = nil
	run(t, "fake")
	if got == nil || got.Global.Dir != "" || got.Global.Output != OutputText {
		t.Errorf("defaults: Global = %+v, want empty dir and text", got)
	}
}

// The command table is the one place a command word is added; the test above replaced it and
// the cleanup put it back.
func TestWithSpecsRestoresTheTable(t *testing.T) {
	before := slices.Clone(specs)
	t.Run("replace", func(t *testing.T) {
		withSpecs(t)
		if len(specs) != 0 {
			t.Fatal("the table was not replaced")
		}
		if r := run(t, "version"); r.code != ExitUsage {
			t.Errorf("version with an empty table: exit code = %d, want 2", int(r.code))
		}
	})
	if len(specs) != len(before) || specs[0].name != "version" {
		t.Errorf("the table was not restored: %v", specs)
	}
	if r := run(t, "version"); r.code != ExitOK {
		t.Errorf("version after the restore: exit code = %d, want 0", int(r.code))
	}
}
