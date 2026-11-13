package cli

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	ucli "github.com/urfave/cli/v3"
)

// The tests in this file change the command table (withSpecs) and do not run in parallel.

// seen is what the fake commands record about the calls they got.
type seen struct {
	calls  int
	leaf   string // the word that ran, "verify root-list"
	args   []string
	global Global

	held      string
	pins      []string
	strict    bool
	heldSet   bool
	pinSet    bool
	strictSet bool
	other     string
	otherSet  bool
}

func (s *seen) record(leaf string, c *Call) {
	s.calls++
	s.leaf = leaf
	s.args = slices.Clone(c.Args)
	s.global = c.Global
	// Only what the word declares is read: an accessor panics on a name that the word does not
	// declare, and the words of this table declare held, pin and strict only in two places.
	declares := func(name string) bool { return slices.Contains(c.flags, name) }
	if declares("held") {
		s.held = c.FlagString("held")
		s.heldSet = c.FlagSet("held")
	}
	if declares("pin") {
		s.pins = c.FlagStrings("pin")
		s.pinSet = c.FlagSet("pin")
	}
	if declares("strict") {
		s.strict = c.FlagBool("strict")
		s.strictSet = c.FlagSet("strict")
	}
}

// words is a command table with two words that have second words and flags of their own, and one
// plain word with a flag.
func words(rec *seen) []spec {
	rootListFlags := func() []ucli.Flag {
		return []ucli.Flag{
			&ucli.StringFlag{Name: "held", Usage: "the list held now, from `FILE`"},
			&ucli.StringSliceFlag{Name: "pin", Usage: "a pin, repeatable"},
			&ucli.BoolFlag{Name: "strict", Usage: "refuse more"},
		}
	}
	crlFlags := func() []ucli.Flag {
		return []ucli.Flag{&ucli.StringFlag{Name: "other", Usage: "something of crl only"}}
	}
	return []spec{
		{name: "verify", usage: "verify a file", subs: []spec{
			{name: "root-list", usage: "verify a root list", argsUsage: "FILE", flags: rootListFlags,
				run: func(_ context.Context, c *Call) (*Result, error) {
					rec.record("verify root-list", c)
					return &Result{Text: "root list ok\n"}, nil
				}},
			{name: "crl", usage: "verify a revocation list", flags: crlFlags,
				run: func(_ context.Context, c *Call) (*Result, error) {
					rec.record("verify crl", c)
					rec.other = c.FlagString("other")
					rec.otherSet = c.FlagSet("other")
					return &Result{Text: "crl ok\n"}, nil
				}},
			{name: "refuse", usage: "always refuses",
				run: func(_ context.Context, c *Call) (*Result, error) {
					rec.record("verify refuse", c)
					return nil, Refusal{Reasons: []string{"policy"}, Msg: "no"}
				}},
		}},
		{name: "check", usage: "check something", subs: []spec{
			{name: "history", usage: "check a history", argsUsage: "[FILE...]",
				run: func(_ context.Context, c *Call) (*Result, error) {
					rec.record("check history", c)
					return &Result{Text: "history ok\n"}, nil
				}},
		}},
		{name: "plain", usage: "a word with no second word", argsUsage: "[FILE...]",
			flags: func() []ucli.Flag {
				return []ucli.Flag{&ucli.StringFlag{Name: "held"}, &ucli.StringSliceFlag{Name: "pin"}, &ucli.BoolFlag{Name: "strict"}}
			},
			run: func(_ context.Context, c *Call) (*Result, error) {
				rec.record("plain", c)
				return &Result{Text: "plain ok\n"}, nil
			}},
	}
}

// runEnv runs the command line with the fake clock given (nil: none) and returns what it printed.
func runEnv(t *testing.T, now func() time.Time, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(t.Context(), args, Env{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
		Build:  testBuild,
		Now:    now,
	})
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func TestSecondWordsAreReached(t *testing.T) {
	tests := []struct {
		args []string
		leaf string
		out  string
	}{
		{[]string{"verify", "root-list", "f.json"}, "verify root-list", "root list ok\n"},
		{[]string{"verify", "crl", "f.crl"}, "verify crl", "crl ok\n"},
		{[]string{"check", "history"}, "check history", "history ok\n"},
		{[]string{"plain", "x"}, "plain", "plain ok\n"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			rec := &seen{}
			withSpecs(t, words(rec)...)
			r := run(t, tt.args...)
			if r.code != ExitOK {
				t.Fatalf("exit code = %d, want 0; stderr %q", int(r.code), r.stderr)
			}
			if rec.calls != 1 || rec.leaf != tt.leaf {
				t.Errorf("calls = %d, leaf = %q, want one call of %q", rec.calls, rec.leaf, tt.leaf)
			}
			if r.stdout != tt.out {
				t.Errorf("stdout = %q, want %q", r.stdout, tt.out)
			}
			if r.stderr != "" {
				t.Errorf("stderr = %q, want empty", r.stderr)
			}
		})
	}
}

func TestPositionalArgumentsAreAfterTheSecondWord(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"none", []string{"verify", "root-list"}, []string{}},
		{"one", []string{"verify", "root-list", "a.json"}, []string{"a.json"}},
		{"two", []string{"verify", "root-list", "a.json", "b.json"}, []string{"a.json", "b.json"}},
		{"after the flags", []string{"verify", "root-list", "--held", "h.json", "a.json"}, []string{"a.json"}},
		{"before the flags", []string{"verify", "root-list", "a.json", "--held", "h.json"}, []string{"a.json"}},
		{"on both sides of a flag", []string{"verify", "root-list", "a.json", "--held", "h.json", "b.json"}, []string{"a.json", "b.json"}},
		{"after a boolean flag", []string{"verify", "root-list", "--strict", "a.json"}, []string{"a.json"}},
		{"after the end of the flags", []string{"verify", "root-list", "--", "--held", "a.json"}, []string{"--held", "a.json"}},
		{"a word of another sub is only an argument", []string{"verify", "root-list", "crl"}, []string{"crl"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &seen{}
			withSpecs(t, words(rec)...)
			if r := run(t, tt.args...); r.code != ExitOK {
				t.Fatalf("exit code = %d, want 0; stderr %q", int(r.code), r.stderr)
			}
			if rec.leaf != "verify root-list" || !slices.Equal(rec.args, tt.want) {
				t.Errorf("leaf = %q, args = %q, want verify root-list with %q", rec.leaf, rec.args, tt.want)
			}
		})
	}
}

func TestFlagsOfASecondWord(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		held      string
		pins      []string
		strict    bool
		heldSet   bool
		pinSet    bool
		strictSet bool
	}{
		{"none given", []string{"verify", "root-list", "f"}, "", nil, false, false, false, false},
		{"a string flag", []string{"verify", "root-list", "--held", "h.json", "f"}, "h.json", nil, false, true, false, false},
		{"a string flag with an equals sign", []string{"verify", "root-list", "--held=h.json", "f"}, "h.json", nil, false, true, false, false},
		{"a string flag given an empty value", []string{"verify", "root-list", "--held=", "f"}, "", nil, false, true, false, false},
		{"a string flag after the argument", []string{"verify", "root-list", "f", "--held", "h.json"}, "h.json", nil, false, true, false, false},
		{"the last use of a string flag wins", []string{"verify", "root-list", "--held", "a", "--held", "b"}, "b", nil, false, true, false, false},
		{"a boolean flag", []string{"verify", "root-list", "--strict", "f"}, "", nil, true, false, false, true},
		{"a boolean flag set to false", []string{"verify", "root-list", "--strict=false", "f"}, "", nil, false, false, false, true},
		{"a boolean flag set to true", []string{"verify", "root-list", "--strict=true", "f"}, "", nil, true, false, false, true},
		{"one pin", []string{"verify", "root-list", "--pin", "a"}, "", []string{"a"}, false, false, true, false},
		{"two pins, in the order given", []string{"verify", "root-list", "--pin", "a", "--pin", "b"}, "", []string{"a", "b"}, false, false, true, false},
		{"two pins, not in alphabetical order", []string{"verify", "root-list", "--pin", "b", "--pin", "a"}, "", []string{"b", "a"}, false, false, true, false},
		{"a comma stays inside a value", []string{"verify", "root-list", "--pin", "a,b", "--pin", "c"}, "", []string{"a,b", "c"}, false, false, true, false},
		{"pins around other flags", []string{"verify", "root-list", "--pin", "a", "--held", "h", "--pin", "b", "f", "--pin", "c"}, "h", []string{"a", "b", "c"}, false, true, true, false},
		{"all of them", []string{"verify", "root-list", "f", "--held", "F", "--pin", "A", "--pin", "B", "--strict"}, "F", []string{"A", "B"}, true, true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &seen{}
			withSpecs(t, words(rec)...)
			if r := run(t, tt.args...); r.code != ExitOK {
				t.Fatalf("exit code = %d, want 0; stderr %q", int(r.code), r.stderr)
			}
			if rec.held != tt.held || rec.strict != tt.strict || !slices.Equal(rec.pins, tt.pins) {
				t.Errorf("held = %q, pins = %q, strict = %v; want %q, %q, %v", rec.held, rec.pins, rec.strict, tt.held, tt.pins, tt.strict)
			}
			if rec.heldSet != tt.heldSet || rec.pinSet != tt.pinSet || rec.strictSet != tt.strictSet {
				t.Errorf("FlagSet held, pin, strict = %v, %v, %v; want %v, %v, %v",
					rec.heldSet, rec.pinSet, rec.strictSet, tt.heldSet, tt.pinSet, tt.strictSet)
			}
		})
	}
}

func TestFlagsOfAWordWithoutSecondWords(t *testing.T) {
	rec := &seen{}
	withSpecs(t, words(rec)...)
	if r := run(t, "plain", "--held", "h", "--pin", "x,y", "--pin", "z", "--strict", "f"); r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0; stderr %q", int(r.code), r.stderr)
	}
	if rec.held != "h" || !slices.Equal(rec.pins, []string{"x,y", "z"}) || !rec.strict || !slices.Equal(rec.args, []string{"f"}) {
		t.Errorf("held = %q, pins = %q, strict = %v, args = %q", rec.held, rec.pins, rec.strict, rec.args)
	}
}

func TestEachSecondWordHasItsOwnFlags(t *testing.T) {
	rec := &seen{}
	withSpecs(t, words(rec)...)
	if r := run(t, "verify", "crl", "--other", "o", "f"); r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0; stderr %q", int(r.code), r.stderr)
	}
	if rec.leaf != "verify crl" || rec.other != "o" || !rec.otherSet || rec.heldSet {
		t.Errorf("leaf = %q, other = %q (set %v), held set %v", rec.leaf, rec.other, rec.otherSet, rec.heldSet)
	}
}

// A flag of the library keeps "was set" in the flag value, so a table that handed out the same
// flag values to every run would carry a flag from one run into the next.
func TestFlagsAreFreshForEveryRun(t *testing.T) {
	rec := &seen{}
	withSpecs(t, words(rec)...)
	if r := run(t, "verify", "root-list", "--held", "h", "--pin", "a", "--strict", "f"); r.code != ExitOK {
		t.Fatalf("first run: exit code = %d; stderr %q", int(r.code), r.stderr)
	}
	if !rec.heldSet || !rec.pinSet || !rec.strictSet {
		t.Fatalf("the first run did not see its flags: %+v", rec)
	}
	if r := run(t, "verify", "root-list", "f"); r.code != ExitOK {
		t.Fatalf("second run: exit code = %d; stderr %q", int(r.code), r.stderr)
	}
	if rec.heldSet || rec.pinSet || rec.strictSet {
		t.Errorf("FlagSet held, pin, strict = %v, %v, %v in a run that gave no flag, want false", rec.heldSet, rec.pinSet, rec.strictSet)
	}
	if rec.held != "" || len(rec.pins) != 0 || rec.strict {
		t.Errorf("held = %q, pins = %q, strict = %v in a run that gave no flag", rec.held, rec.pins, rec.strict)
	}
	// And a third run, after a second that gave other values.
	run(t, "verify", "root-list", "--pin", "z", "f")
	if want := []string{"z"}; !slices.Equal(rec.pins, want) {
		t.Errorf("pins = %q, want %q (no pin of an earlier run)", rec.pins, want)
	}
}

func TestGlobalFlagsBeforeBetweenAndAfterTheWords(t *testing.T) {
	positions := [][]string{
		{"%G", "verify", "root-list", "f"},
		{"verify", "%G", "root-list", "f"},
		{"verify", "root-list", "%G", "f"},
		{"verify", "root-list", "f", "%G"},
	}
	for _, pos := range positions {
		for _, tc := range []struct {
			name  string
			flag  []string
			check func(*testing.T, *seen, result)
		}{
			{"dir", []string{"--dir", "bundle"}, func(t *testing.T, rec *seen, _ result) {
				if rec.global.Dir != "bundle" {
					t.Errorf("Dir = %q, want bundle", rec.global.Dir)
				}
			}},
			{"dir with an equals sign", []string{"--dir=bundle"}, func(t *testing.T, rec *seen, _ result) {
				if rec.global.Dir != "bundle" {
					t.Errorf("Dir = %q, want bundle", rec.global.Dir)
				}
			}},
			{"output json", []string{"--output", "json"}, func(t *testing.T, rec *seen, r result) {
				if rec.global.Output != OutputJSON {
					t.Errorf("Output = %q, want json", rec.global.Output)
				}
				wantObject(t, object(t, r.stdout), map[string]any{
					"output": 1, "command": "verify", "exit_code": 0, "outcome": "done",
				})
			}},
		} {
			var args []string
			for _, a := range pos {
				if a == "%G" {
					args = append(args, tc.flag...)
				} else {
					args = append(args, a)
				}
			}
			t.Run(tc.name+": "+strings.Join(args, " "), func(t *testing.T) {
				rec := &seen{}
				withSpecs(t, words(rec)...)
				r := run(t, args...)
				if r.code != ExitOK {
					t.Fatalf("exit code = %d, want 0; stderr %q", int(r.code), r.stderr)
				}
				if rec.leaf != "verify root-list" || !slices.Equal(rec.args, []string{"f"}) {
					t.Errorf("leaf = %q, args = %q", rec.leaf, rec.args)
				}
				tc.check(t, rec, r)
			})
		}
	}
}

func TestGlobalFlagsRunTogetherWithFlagsOfTheWord(t *testing.T) {
	rec := &seen{}
	withSpecs(t, words(rec)...)
	r := run(t, "--dir", "d", "verify", "--output", "json", "root-list", "--held", "h", "--pin", "p", "f", "--strict")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0; stderr %q", int(r.code), r.stderr)
	}
	if rec.global.Dir != "d" || rec.global.Output != OutputJSON || rec.held != "h" || !slices.Equal(rec.pins, []string{"p"}) || !rec.strict {
		t.Errorf("global = %+v, held = %q, pins = %q, strict = %v", rec.global, rec.held, rec.pins, rec.strict)
	}
	if obj := object(t, r.stdout); obj["command"] != "verify" {
		t.Errorf("command = %v, want verify", obj["command"])
	}
}

func TestAGlobalFlagIsReadThroughTheCall(t *testing.T) {
	var got string
	withSpecs(t, spec{name: "plain", usage: "u", run: func(_ context.Context, c *Call) (*Result, error) {
		got = c.FlagString("dir")
		return &Result{}, nil
	}})
	if r := run(t, "plain", "--dir", "somewhere"); r.code != ExitOK {
		t.Fatalf("exit code = %d; stderr %q", int(r.code), r.stderr)
	}
	if got != "somewhere" {
		t.Errorf("FlagString(dir) = %q, want somewhere", got)
	}
}

func TestUsageErrorsOfSecondWords(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		command string
		inError string
	}{
		{"the first word alone", []string{"verify"}, "verify", "verify needs a second word"},
		{"another group word alone", []string{"check"}, "check", "check needs a second word"},
		{"an unknown second word", []string{"verify", "bogus"}, "verify", `verify: unknown command "bogus"`},
		{"an unknown second word with an argument", []string{"verify", "bogus", "f"}, "verify", `unknown command "bogus"`},
		{"a second word of another word", []string{"verify", "history"}, "verify", `unknown command "history"`},
		{"an unknown second word of the other word", []string{"check", "crl"}, "check", `check: unknown command "crl"`},
		{"a flag of the second word before it", []string{"verify", "--held", "x", "root-list"}, "verify", "held"},
		{"a flag of the second word with the second word missing", []string{"verify", "--held", "x"}, "verify", "held"},
		{"a flag of sub A given to sub B", []string{"verify", "crl", "--held", "x"}, "verify", "held"},
		{"a flag of sub B given to sub A", []string{"verify", "root-list", "--other", "x"}, "verify", "other"},
		{"an unknown flag after the second word", []string{"verify", "root-list", "--bogus"}, "verify", "bogus"},
		{"an unknown flag between the words", []string{"verify", "--bogus", "root-list"}, "verify", "bogus"},
		{"an unknown flag of a second word with value", []string{"verify", "crl", "--bogus", "x", "f"}, "verify", "bogus"},
		{"an unknown flag of another group", []string{"check", "history", "--bogus"}, "check", "bogus"},
		{"an unknown flag of a plain word", []string{"plain", "--bogus"}, "plain", "bogus"},
		{"a flag without its value", []string{"verify", "root-list", "--held"}, "verify", "held"},
		{"a flag that is not a boolean given a bad value", []string{"verify", "root-list", "--strict=maybe"}, "verify", "strict"},
		{"a flag of a word that has no flags", []string{"check", "history", "--held", "x"}, "check", "held"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &seen{}
			withSpecs(t, words(rec)...)
			// Text.
			text := run(t, tt.args...)
			if text.code != ExitUsage {
				t.Fatalf("exit code = %d, want 2; stderr %q", int(text.code), text.stderr)
			}
			if text.stdout != "" {
				t.Errorf("stdout = %q, want empty", text.stdout)
			}
			if !strings.Contains(text.stderr, tt.inError) {
				t.Errorf("stderr = %q, want it to hold %q", text.stderr, tt.inError)
			}
			if !strings.Contains(text.stderr, `Run "ritueel --help" for the usage.`) {
				t.Errorf("stderr does not point to the usage: %q", text.stderr)
			}
			// JSON.
			withFlag := append([]string{"--output", "json"}, tt.args...)
			js := run(t, withFlag...)
			if js.code != ExitUsage {
				t.Fatalf("json: exit code = %d, want 2", int(js.code))
			}
			obj := object(t, js.stdout)
			wantObject(t, obj, map[string]any{
				"output": 1, "command": tt.command, "exit_code": 2, "outcome": "usage", "error": "<any>",
			})
			if msg, _ := obj["error"].(string); !strings.Contains(msg, tt.inError) {
				t.Errorf("error = %q, want it to hold %q", msg, tt.inError)
			}
			if rec.calls != 0 {
				t.Errorf("a command ran %d times for a usage error", rec.calls)
			}
		})
	}
}

func TestACommandAfterAUsageErrorStillRuns(t *testing.T) {
	// Nothing of a failed run is left behind for the next one.
	rec := &seen{}
	withSpecs(t, words(rec)...)
	if r := run(t, "verify", "root-list", "--bogus"); r.code != ExitUsage {
		t.Fatalf("exit code = %d, want 2", int(r.code))
	}
	r := run(t, "--output", "json", "plain", "f")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d, want 0; stderr %q", int(r.code), r.stderr)
	}
	if obj := object(t, r.stdout); obj["command"] != "plain" {
		t.Errorf("command = %v, want plain", obj["command"])
	}
}

func TestCommandIsTheFirstWord(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		code    ExitCode
		command string
		outcome string
	}{
		{"a second word that succeeds", []string{"--output", "json", "verify", "root-list", "f"}, ExitOK, "verify", "done"},
		{"the other second word", []string{"--output", "json", "verify", "crl"}, ExitOK, "verify", "done"},
		{"a second word of another word", []string{"--output", "json", "check", "history"}, ExitOK, "check", "done"},
		{"a word with no second word", []string{"--output", "json", "plain"}, ExitOK, "plain", "done"},
		{"a second word that refuses", []string{"--output", "json", "verify", "refuse"}, ExitRefused, "verify", "refused"},
		{"the output flag last", []string{"verify", "refuse", "--output", "json"}, ExitRefused, "verify", "refused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &seen{}
			withSpecs(t, words(rec)...)
			r := run(t, tt.args...)
			if r.code != tt.code {
				t.Fatalf("exit code = %d, want %d; stderr %q", int(r.code), int(tt.code), r.stderr)
			}
			obj := object(t, r.stdout)
			if obj["command"] != tt.command || obj["outcome"] != tt.outcome {
				t.Errorf("command = %v, outcome = %v; want %s, %s", obj["command"], obj["outcome"], tt.command, tt.outcome)
			}
		})
	}
}

func TestACommandPanicInASecondWordIsNamedByItsFirstWord(t *testing.T) {
	withSpecs(t, spec{name: "verify", usage: "u", subs: []spec{
		{name: "boom", usage: "u", run: func(context.Context, *Call) (*Result, error) { panic("boom") }},
	}})
	r := run(t, "--output", "json", "verify", "boom")
	if r.code != ExitFailure {
		t.Fatalf("exit code = %d, want 1", int(r.code))
	}
	obj := object(t, r.stdout)
	if obj["command"] != "verify" || obj["outcome"] != "failed" {
		t.Errorf("command = %v, outcome = %v; want verify, failed", obj["command"], obj["outcome"])
	}
}

func TestThreeLevelsOfWords(t *testing.T) {
	var ran bool
	withSpecs(t, spec{name: "tool", usage: "u", subs: []spec{
		{name: "group", usage: "u", subs: []spec{
			{name: "leaf", usage: "u", run: func(_ context.Context, c *Call) (*Result, error) {
				ran = true
				if !slices.Equal(c.Args, []string{"x"}) {
					t.Errorf("args = %q, want [x]", c.Args)
				}
				return &Result{}, nil
			}},
		}},
	}})
	r := run(t, "--output", "json", "tool", "group", "leaf", "x")
	if r.code != ExitOK || !ran {
		t.Fatalf("exit code = %d, ran = %v; stderr %q", int(r.code), ran, r.stderr)
	}
	if obj := object(t, r.stdout); obj["command"] != "tool" {
		t.Errorf("command = %v, want the first word, tool", obj["command"])
	}
	r = run(t, "--output", "json", "tool", "group")
	if r.code != ExitUsage {
		t.Fatalf("exit code = %d, want 2", int(r.code))
	}
	obj := object(t, r.stdout)
	if msg, _ := obj["error"].(string); obj["command"] != "tool" || !strings.Contains(msg, "tool group needs a second word") {
		t.Errorf("command = %v, error = %q", obj["command"], msg)
	}
}

func TestHelpOfWordsExitsZeroWithTheUsageOnStandardOutput(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string // each must be in the usage
		not  []string // none may be
	}{
		{"a group word", []string{"verify", "--help"}, []string{"verify a file", "root-list", "crl"}, []string{"Shows a list of commands"}},
		{"a second word", []string{"verify", "root-list", "--help"}, []string{"verify a root list", "FILE", "--held", "--pin", "--strict"}, []string{"--other"}},
		{"the other second word", []string{"verify", "crl", "--help"}, []string{"verify a revocation list", "--other"}, []string{"--held", "--pin"}},
		{"a second word of another word", []string{"check", "history", "--help"}, []string{"check a history", "[FILE...]"}, nil},
		{"a plain word", []string{"plain", "--help"}, []string{"a word with no second word", "--held"}, nil},
		{"a second word, the short flag", []string{"verify", "root-list", "-h"}, []string{"--held"}, nil},
		{"the help flag before the words", []string{"--help", "verify", "root-list"}, []string{"ritueel"}, nil},
		{"a second word, in JSON mode", []string{"--output", "json", "verify", "root-list", "--help"}, []string{"--held"}, nil},
		{"the help flag after other flags", []string{"verify", "root-list", "--held", "x", "--help"}, []string{"--pin"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &seen{}
			withSpecs(t, words(rec)...)
			r := run(t, tt.args...)
			if r.code != ExitOK {
				t.Fatalf("exit code = %d, want 0; stderr %q", int(r.code), r.stderr)
			}
			if r.stderr != "" {
				t.Errorf("stderr = %q, want empty", r.stderr)
			}
			for _, w := range tt.want {
				if !strings.Contains(r.stdout, w) {
					t.Errorf("the usage does not hold %q:\n%s", w, r.stdout)
				}
			}
			for _, w := range tt.not {
				if strings.Contains(r.stdout, w) {
					t.Errorf("the usage holds %q:\n%s", w, r.stdout)
				}
			}
			if rec.calls != 0 {
				t.Errorf("a command ran %d times for --help", rec.calls)
			}
			if strings.Contains(r.stdout, `"exit_code"`) {
				t.Errorf("help wrote a JSON object:\n%s", r.stdout)
			}
		})
	}
}

func TestHelpOfAGroupWordListsItsSecondWordsOnly(t *testing.T) {
	rec := &seen{}
	withSpecs(t, words(rec)...)
	r := run(t, "verify", "--help")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d; stderr %q", int(r.code), r.stderr)
	}
	if got, want := usageCommands(t, r.stdout), []string{"root-list", "crl", "refuse"}; !slices.Equal(got, want) {
		t.Errorf("second words in the usage = %v, want %v\n%s", got, want, r.stdout)
	}
}

func TestTheProgramUsageListsTheFirstWordsOnly(t *testing.T) {
	rec := &seen{}
	withSpecs(t, words(rec)...)
	r := run(t, "--help")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d; stderr %q", int(r.code), r.stderr)
	}
	if got, want := usageCommands(t, r.stdout), []string{"verify", "check", "plain"}; !slices.Equal(got, want) {
		t.Errorf("commands in the usage = %v, want %v\n%s", got, want, r.stdout)
	}
}

func TestEnvNowReachesTheCommand(t *testing.T) {
	fixed := time.Date(2026, time.November, 13, 12, 30, 0, 0, time.UTC)
	calls := 0
	clock := func() time.Time {
		calls++
		return fixed
	}
	var got time.Time
	withSpecs(t, spec{name: "verify", usage: "u", subs: []spec{
		{name: "root-list", usage: "u", run: func(_ context.Context, c *Call) (*Result, error) {
			got = c.Env.Now()
			return &Result{}, nil
		}},
	}}, spec{name: "plain", usage: "u", run: func(_ context.Context, c *Call) (*Result, error) {
		got = c.Env.Now()
		return &Result{}, nil
	}})
	for _, args := range [][]string{{"verify", "root-list"}, {"plain"}} {
		got = time.Time{}
		calls = 0
		if r := runEnv(t, clock, args...); r.code != ExitOK {
			t.Fatalf("%v: exit code = %d; stderr %q", args, int(r.code), r.stderr)
		}
		if !got.Equal(fixed) {
			t.Errorf("%v: Now() = %v, want %v", args, got, fixed)
		}
		if calls != 1 {
			t.Errorf("%v: the clock was called %d times, want 1 (Run must not read it)", args, calls)
		}
	}
}

func TestANilNowBecomesTheRealClock(t *testing.T) {
	var got time.Time
	var hadNow bool
	withSpecs(t, spec{name: "plain", usage: "u", run: func(_ context.Context, c *Call) (*Result, error) {
		hadNow = c.Env.Now != nil
		if hadNow {
			got = c.Env.Now()
		}
		return &Result{}, nil
	}})
	before := time.Now()
	r := runEnv(t, nil, "plain")
	after := time.Now()
	if r.code != ExitOK {
		t.Fatalf("exit code = %d; stderr %q", int(r.code), r.stderr)
	}
	if !hadNow {
		t.Fatal("Env.Now is nil in the command")
	}
	if got.Before(before) || got.After(after) {
		t.Errorf("Now() = %v, want a time between %v and %v", got, before, after)
	}
	// The run on the plain helper, which sets no clock, behaves the same.
	hadNow = false
	if r := run(t, "plain"); r.code != ExitOK || !hadNow {
		t.Errorf("run without a clock: exit code = %d, had a clock = %v", int(r.code), hadNow)
	}
}

func TestEnvWithDefaultsKeepsTheClockOfTheCaller(t *testing.T) {
	fixed := time.Date(2020, time.January, 2, 3, 4, 5, 0, time.UTC)
	env := Env{Now: func() time.Time { return fixed }}.withDefaults()
	if !env.Now().Equal(fixed) {
		t.Errorf("Now() = %v, want %v", env.Now(), fixed)
	}
	if empty := (Env{}).withDefaults(); empty.Now == nil {
		t.Error("a nil clock was not replaced")
	}
}

// usageCommands reads the names in the COMMANDS section of a usage text, in the order they are
// listed.
func usageCommands(t *testing.T, usage string) []string {
	t.Helper()
	inCommands := false
	var commands []string
	for line := range strings.SplitSeq(usage, "\n") {
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
	return commands
}
