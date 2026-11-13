package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	ucli "github.com/urfave/cli/v3"
)

// A mistake of the programmer (a flag name that clashes, a flag that the word did not declare, an
// outcome that disagrees with the exit code, a code that has no decided outcome, a command that
// returns nothing) is a panic with a text that says which, and a run turns it into the exit code 1
// and the text. And what reaches the terminal is printable ASCII.

// ranFailed checks a run that ended with the exit code 1 and the text of a panic, in the text mode
// and in the JSON mode, and returns nothing else: standard output is empty in the text mode, and in
// the JSON mode it is the one object with the exit code 1, the outcome failed and the text.
func ranFailed(t *testing.T, command string, msg string, args ...string) {
	t.Helper()
	text := run(t, args...)
	wantLine := "ritueel: internal error: " + msg + "\n"
	if text.code != ExitFailure || text.stdout != "" || text.stderr != wantLine {
		t.Errorf("text: (%d, %q, %q)\nwant (1, \"\", %q)", int(text.code), text.stdout, text.stderr, wantLine)
	}
	js := run(t, append([]string{"--output", "json"}, args...)...)
	if js.code != ExitFailure || js.stderr != wantLine {
		t.Errorf("json: (%d, %q)", int(js.code), js.stderr)
		return
	}
	obj := object(t, js.stdout)
	wantObject(t, obj, map[string]any{"output": 1, "command": command, "exit_code": 1, "outcome": "failed", "error": "internal error: " + msg})
}

// ranFailedAtBuild is ranFailed for a mistake in the table of words, which the run finds before it
// has read a flag: the output mode is not known, so no object is written, in the JSON mode either.
func ranFailedAtBuild(t *testing.T, msg string, args ...string) {
	t.Helper()
	wantLine := "ritueel: internal error: " + msg + "\n"
	for _, a := range [][]string{args, append([]string{"--output", "json"}, args...), nil, {"--help"}} {
		r := run(t, a...)
		if r.code != ExitFailure || r.stdout != "" || r.stderr != wantLine {
			t.Errorf("%q: (%d, %q, %q)\nwant (1, \"\", %q)", a, int(r.code), r.stdout, r.stderr, wantLine)
		}
	}
}

func okResult(context.Context, *Call) (*Result, error) { return &Result{Text: "ok\n"}, nil }

func flagsOf(names ...string) func() []ucli.Flag {
	return func() []ucli.Flag {
		var fs []ucli.Flag
		for _, n := range names {
			fs = append(fs, &ucli.StringFlag{Name: n})
		}
		return fs
	}
}

func TestEverythingThatReachesTheTerminalIsPrintableASCII(t *testing.T) {
	bad := "a\x1b[31m b\xffc v" + string(rune(0x0435)) + "rsion line" + "\n" + "break" + string(rune(0x1F600))
	// The message as Escape writes it: each escape built from its code point.
	wantMsg := "a" + u(0x1b) + "[31m b" + u(0xFFFD) + "c v" + u(0x0435) + "rsion line" + u(10) + "break" + u(0xD83D) + u(0xDE00)
	cases := []struct {
		name    string
		run     commandFunc
		code    ExitCode
		outcome string
		line    string // standard error, whole
		reasons bool
	}{
		{"a plain error", func(context.Context, *Call) (*Result, error) { return nil, errors.New(bad) }, ExitFailure, "failed", "ritueel: " + wantMsg + "\n", false},
		{"a wrapped error", func(context.Context, *Call) (*Result, error) {
			return nil, fmt.Errorf("while reading: %w", errors.New(bad))
		}, ExitFailure, "failed", "ritueel: while reading: " + wantMsg + "\n", false},
		{"a usage error", func(context.Context, *Call) (*Result, error) { return nil, UsageError{Msg: bad} }, ExitUsage, "usage", "ritueel: " + wantMsg + "\n" + helpLine, false},
		{"a refusal", func(context.Context, *Call) (*Result, error) { return nil, Refusal{Msg: bad, Reasons: []string{"r"}} }, ExitRefused, "refused", "ritueel: " + wantMsg + "\n", true},
		{"a refusal by the backend", func(context.Context, *Call) (*Result, error) {
			return nil, BackendRefusal{Msg: bad, Reasons: []string{"r"}}
		}, ExitBackend, "refused", "ritueel: " + wantMsg + "\n", true},
		{"a panic with a text", func(context.Context, *Call) (*Result, error) { panic(bad) }, ExitFailure, "failed", "ritueel: internal error: " + wantMsg + "\n", false},
		{"a panic with an error", func(context.Context, *Call) (*Result, error) { panic(errors.New(bad)) }, ExitFailure, "failed", "ritueel: internal error: " + wantMsg + "\n", false},
		{"a panic with a value that prints as text", func(context.Context, *Call) (*Result, error) { panic(fmt.Stringer(stringerOf(bad))) }, ExitFailure, "failed", "ritueel: internal error: " + wantMsg + "\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: tc.run})
			text := run(t, "fake")
			if text.code != tc.code || text.stdout != "" || text.stderr != tc.line {
				t.Errorf("text: (%d, %q, %q)\nwant (%d, \"\", %q)", int(text.code), text.stdout, text.stderr, int(tc.code), tc.line)
			}
			if !onlyPrintable(text.stderr) {
				t.Errorf("stderr holds a byte that is not printable ASCII or a line break: %q", text.stderr)
			}
			js := run(t, "--output", "json", "fake")
			if js.code != tc.code || js.stderr != tc.line {
				t.Errorf("json: (%d, %q)", int(js.code), js.stderr)
			}
			if !onlyPrintable(js.stdout) || strings.Count(js.stdout, "\n") != 1 {
				t.Errorf("stdout holds a byte that is not printable ASCII, or more than the one line break: %q", js.stdout)
			}
			obj := object(t, js.stdout)
			wantErr := strings.TrimSuffix(strings.TrimPrefix(strings.SplitN(tc.line, "\n", 2)[0], "ritueel: "), "\n")
			if obj["error"] != wantErr || obj["outcome"] != tc.outcome || obj["exit_code"].(interface{ String() string }).String() != fmt.Sprint(int(tc.code)) {
				t.Errorf("object = %v", obj)
			}
			if tc.reasons && obj["reasons"] == nil {
				t.Errorf("no reasons in %v", obj)
			}
		})
	}
	t.Run("a line break in the message is shown, and the program's own is kept", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, errors.New("one\ntwo\r\nthree") }})
		r := run(t, "fake")
		if want := "ritueel: one" + u(10) + "two" + u(13) + u(10) + "three\n"; r.stderr != want || strings.Count(r.stderr, "\n") != 1 {
			t.Errorf("stderr = %q, want %q", r.stderr, want)
		}
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, UsageError{Msg: "one\ntwo"} }})
		r = run(t, "fake")
		if want := "ritueel: one" + u(10) + "two\n" + helpLine; r.stderr != want || strings.Count(r.stderr, "\n") != 2 {
			t.Errorf("usage stderr = %q, want %q", r.stderr, want)
		}
	})
	t.Run("the failure to write the result is escaped too", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: okResult})
		var stderr strings.Builder
		code := Run(t.Context(), []string{"fake"}, Env{Stdout: brokenWriter{errors.New("disk \x1b\xff full")}, Stderr: &stderr, Build: testBuild})
		if want := "ritueel: write the result: disk " + u(0x1b) + u(0xFFFD) + " full\n"; code != ExitFailure || stderr.String() != want {
			t.Errorf("(%d, %q), want (1, %q)", int(code), stderr.String(), want)
		}
	})
	t.Run("a text that is already ASCII is as it was", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, errors.New(`plain "quoted" \ text: 100%`) }})
		if r := run(t, "fake"); r.stderr != "ritueel: plain \"quoted\" \\ text: 100%\n" {
			t.Errorf("%q", r.stderr)
		}
	})
	t.Run("what a command puts in its result text is its own", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return &Result{Text: "caf" + string(rune(0xE9)) + "\n"}, nil
		}})
		if r := run(t, "fake"); r.stdout != "caf"+string(rune(0xE9))+"\n" {
			t.Errorf("%q", r.stdout)
		}
	})
}

type stringerOf string

func (s stringerOf) String() string { return string(s) }

type brokenWriter struct{ err error }

func (w brokenWriter) Write([]byte) (int, error) { return 0, w.err }

// ---- a flag name that clashes ------------------------------------------------------------

func TestAFlagNameThatClashesIsAProgrammerError(t *testing.T) {
	for _, name := range []string{"dir", "output", "help", "h"} {
		t.Run(name, func(t *testing.T) {
			msg := fmt.Sprintf("cli: the word %q declares the flag %q, which is reserved for the program (dir, output) and for help (help, h); choose another name", "fake", name)
			withSpecs(t, spec{name: "fake", usage: "u", flags: flagsOf(name), run: okResult})
			ranFailedAtBuild(t, msg, "fake")
			// The table is built at every run, so every word of it is refused, and so is the root.
			ranFailedAtBuild(t, msg)
			// A second word is named by its path.
			withSpecs(t, spec{name: "verify", usage: "u", subs: []spec{{name: "crl", usage: "u", flags: flagsOf(name), run: okResult}}})
			ranFailedAtBuild(t, fmt.Sprintf("cli: the word %q declares the flag %q, which is reserved for the program (dir, output) and for help (help, h); choose another name", "verify crl", name), "verify", "crl")
			// A word above declares it.
			withSpecs(t, spec{name: "verify", usage: "u", flags: flagsOf(name), subs: []spec{{name: "crl", usage: "u", run: okResult}}})
			ranFailedAtBuild(t, fmt.Sprintf("cli: the word %q declares the flag %q, which is reserved for the program (dir, output) and for help (help, h); choose another name", "verify", name), "verify", "crl")
		})
	}
	t.Run("an alias of a flag is a name too", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", flags: func() []ucli.Flag {
			return []ucli.Flag{&ucli.StringFlag{Name: "fine", Aliases: []string{"output"}}}
		}, run: okResult})
		ranFailedAtBuild(t, `cli: the word "fake" declares the flag "output", which is reserved for the program (dir, output) and for help (help, h); choose another name`, "fake")
	})
	t.Run("a word that does not clash is run, and a word with a name like a reserved one is not a clash", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", flags: flagsOf("directory", "outputs", "Dir", "hh"), run: okResult})
		if r := run(t, "fake"); r.code != ExitOK || r.stdout != "ok\n" {
			t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
		}
	})
}

func TestAFlagNameDeclaredTwiceAlongTheChainIsAProgrammerError(t *testing.T) {
	twice := func(word, name string) string {
		return fmt.Sprintf("cli: the word %q declares the flag %q twice, or a word above it declares it already; choose another name", word, name)
	}
	t.Run("twice in one word", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", flags: flagsOf("a", "b", "a"), run: okResult})
		ranFailedAtBuild(t, twice("fake", "a"), "fake")
	})
	t.Run("a flag and an alias of another that are one name", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", flags: func() []ucli.Flag {
			return []ucli.Flag{&ucli.StringFlag{Name: "a"}, &ucli.StringFlag{Name: "b", Aliases: []string{"a"}}}
		}, run: okResult})
		ranFailedAtBuild(t, twice("fake", "a"), "fake")
	})
	t.Run("a word and a second word", func(t *testing.T) {
		withSpecs(t, spec{name: "verify", usage: "u", flags: flagsOf("held"), subs: []spec{{name: "crl", usage: "u", flags: flagsOf("held"), run: okResult}}})
		ranFailedAtBuild(t, twice("verify crl", "held"), "verify", "crl")
	})
	t.Run("a word and a second word of a second word", func(t *testing.T) {
		withSpecs(t, spec{name: "a", usage: "u", flags: flagsOf("x"), subs: []spec{{name: "b", usage: "u", subs: []spec{{name: "c", usage: "u", flags: flagsOf("y", "x"), run: okResult}}}}})
		ranFailedAtBuild(t, twice("a b c", "x"), "a", "b", "c")
	})
	t.Run("two second words of one word may share a name", func(t *testing.T) {
		withSpecs(t, spec{name: "verify", usage: "u", subs: []spec{
			{name: "crl", usage: "u", flags: flagsOf("held"), run: okResult},
			{name: "list", usage: "u", flags: flagsOf("held"), run: okResult},
		}})
		for _, sub := range []string{"crl", "list"} {
			if r := run(t, "verify", sub, "--held", "x"); r.code != ExitOK {
				t.Errorf("%s: (%d, %q)", sub, int(r.code), r.stderr)
			}
		}
	})
	t.Run("two words may share a name", func(t *testing.T) {
		withSpecs(t, spec{name: "one", usage: "u", flags: flagsOf("held"), run: okResult}, spec{name: "two", usage: "u", flags: flagsOf("held"), run: okResult})
		for _, w := range []string{"one", "two"} {
			if r := run(t, w, "--held", "x"); r.code != ExitOK {
				t.Errorf("%s: (%d, %q)", w, int(r.code), r.stderr)
			}
		}
	})
}

// ---- the accessors -----------------------------------------------------------------------

func TestAnAccessorPanicsOnAFlagTheWordDidNotDeclare(t *testing.T) {
	type access struct {
		name string
		read func(c *Call)
	}
	accessors := []access{
		{"FlagString", func(c *Call) { c.FlagString("nope") }},
		{"FlagStrings", func(c *Call) { c.FlagStrings("nope") }},
		{"FlagBool", func(c *Call) { c.FlagBool("nope") }},
		{"FlagSet", func(c *Call) { c.FlagSet("nope") }},
	}
	for _, a := range accessors {
		t.Run(a.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", flags: flagsOf("held"), run: func(_ context.Context, c *Call) (*Result, error) {
				a.read(c)
				return &Result{}, nil
			}})
			ranFailed(t, "fake", `cli: the word "fake" has no flag "nope"; the flags that can be asked are ["held" "dir" "output"]`, "fake")
		})
	}
	t.Run("a second word is named by its path, and the flags of the word above are askable", func(t *testing.T) {
		withSpecs(t, spec{name: "verify", usage: "u", flags: flagsOf("above"), subs: []spec{
			{name: "crl", usage: "u", flags: flagsOf("own"), run: func(_ context.Context, c *Call) (*Result, error) {
				_ = c.FlagString("above") // the word above
				_ = c.FlagString("own")
				_ = c.FlagString("dir")
				_ = c.FlagString("output")
				c.FlagBool("held") // a flag of a sibling
				return &Result{}, nil
			}},
		}})
		ranFailed(t, "verify", `cli: the word "verify crl" has no flag "held"; the flags that can be asked are ["above" "own" "dir" "output"]`, "verify", "crl", "--above", "x")
	})
	t.Run("the declared flags and the two global ones are askable, by every accessor", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", flags: func() []ucli.Flag {
			return []ucli.Flag{&ucli.StringFlag{Name: "s"}, &ucli.StringSliceFlag{Name: "l"}, &ucli.BoolFlag{Name: "b"}}
		}, run: func(_ context.Context, c *Call) (*Result, error) {
			if c.FlagString("s") != "v" || len(c.FlagStrings("l")) != 2 || !c.FlagBool("b") || !c.FlagSet("s") || c.FlagSet("l") && false {
				return nil, errors.New("wrong values")
			}
			if c.FlagString("dir") != "d" || !c.FlagSet("dir") || c.FlagSet("nothing-here-is-not-asked") {
				return nil, errors.New("wrong global")
			}
			return &Result{Text: "ok\n"}, nil
		}})
		// The last read panics: "nothing-here-is-not-asked" is no flag of the word.
		ranFailed(t, "fake", `cli: the word "fake" has no flag "nothing-here-is-not-asked"; the flags that can be asked are ["s" "l" "b" "dir" "output"]`, "fake", "--s", "v", "--l", "1", "--l", "2", "--b", "--dir", "d")
	})
	t.Run("a flag that was not given is asked without a panic", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", flags: flagsOf("held"), run: func(_ context.Context, c *Call) (*Result, error) {
			if c.FlagString("held") != "" || c.FlagSet("held") || len(c.FlagStrings("held")) != 0 || c.FlagBool("held") {
				return nil, errors.New("a flag that was not given has a value")
			}
			return &Result{Text: "ok\n"}, nil
		}})
		if r := run(t, "fake"); r.code != ExitOK || r.stdout != "ok\n" {
			t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
		}
	})
	t.Run("a Call that holds no command", func(t *testing.T) {
		for _, a := range accessors {
			msg := recoverText(t, func() { a.read(&Call{}) })
			if want := `cli: the flag "nope" was asked of a Call that holds no command; only the Call that Run gives to a command has flags`; msg != want {
				t.Errorf("%s: %q, want %q", a.name, msg, want)
			}
		}
		if msg := recoverText(t, func() { (*Call)(nil).FlagString("x") }); msg == "" {
			t.Error("a nil Call did not panic")
		}
	})
}

// recoverText returns the text of the panic of f as a string, "" when it did not panic.
func recoverText(t *testing.T, f func()) (msg string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	f()
	return ""
}

// ---- the outcome follows the exit code -----------------------------------------------------

type oddCoded struct {
	code    ExitCode
	outcome Outcome
}

func (e oddCoded) Error() string         { return "odd" }
func (e oddCoded) ExitCode() ExitCode    { return e.code }
func (e oddCoded) Outcome() Outcome      { return e.outcome }
func (e oddCoded) ReasonCodes() []string { return nil }

var outcomeOfCode = map[ExitCode]Outcome{
	ExitOK: OutcomeDone, ExitFailure: OutcomeFailed, ExitUsage: OutcomeUsage,
	ExitRefused: OutcomeRefused, ExitBackend: OutcomeRefused, ExitNotConfirmed: OutcomeNotConfirmed,
}

func TestTheOutcomeFollowsTheExitCode(t *testing.T) {
	all := []Outcome{OutcomeDone, OutcomeFailed, OutcomeUsage, OutcomeRefused, OutcomeNotConfirmed}
	for code := ExitOK; code <= ExitNotConfirmed; code++ {
		want := outcomeOfCode[code]
		t.Run(fmt.Sprintf("a result with the code %d", int(code)), func(t *testing.T) {
			// With no outcome given, and with the right one: the outcome of the code.
			for _, given := range []Outcome{"", want} {
				withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
					return &Result{ExitCode: code, Outcome: given, Text: "t\n"}, nil
				}})
				js := run(t, "--output", "json", "fake")
				if js.code != code || js.stderr != "" {
					t.Errorf("given %q: json (%d, %q)", given, int(js.code), js.stderr)
				}
				wantObject(t, object(t, js.stdout), map[string]any{"output": 1, "command": "fake", "exit_code": int(code), "outcome": string(want)})
				text := run(t, "fake")
				if text.code != code || text.stdout != "t\n" || text.stderr != "" {
					t.Errorf("given %q: text (%d, %q, %q)", given, int(text.code), text.stdout, text.stderr)
				}
			}
			// With any other outcome: a mistake of the programmer.
			for _, given := range all {
				if given == want {
					continue
				}
				withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
					return &Result{ExitCode: code, Outcome: given}, nil
				}})
				ranFailed(t, "fake", fmt.Sprintf("cli: the exit code %d goes with the outcome %q, and the command gave %q", int(code), string(want), string(given)), "fake")
			}
			// An outcome that is no outcome at all.
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
				return &Result{ExitCode: code, Outcome: "nonsense"}, nil
			}})
			ranFailed(t, "fake", fmt.Sprintf("cli: the exit code %d goes with the outcome %q, and the command gave %q", int(code), string(want), "nonsense"), "fake")
		})
		t.Run(fmt.Sprintf("an error with the code %d", int(code)), func(t *testing.T) {
			if code == ExitOK {
				return // an error that carries 0 is no error of the table; ExitFor gives it as it is
			}
			// The error that agrees: the exit code and the outcome of the code.
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
				return nil, oddCoded{code: code, outcome: want}
			}})
			js := run(t, "--output", "json", "fake")
			if js.code != code || js.stderr != "ritueel: odd\n"+map[bool]string{true: helpLine, false: ""}[code == ExitUsage] {
				t.Errorf("agreeing: (%d, %q)", int(js.code), js.stderr)
			}
			wantObject(t, object(t, js.stdout), map[string]any{"output": 1, "command": "fake", "exit_code": int(code), "outcome": string(want), "error": "odd"})
			// The error that disagrees.
			for _, given := range all {
				if given == want {
					continue
				}
				withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
					return nil, oddCoded{code: code, outcome: given}
				}})
				ranFailed(t, "fake", fmt.Sprintf("cli: the exit code %d goes with the outcome %q, and the command gave %q", int(code), string(want), string(given)), "fake")
			}
		})
	}
	t.Run("the result of the code 3 with no outcome is refused", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return &Result{ExitCode: ExitRefused, Reasons: []string{"x"}}, nil
		}})
		js := run(t, "--output", "json", "fake")
		obj := object(t, js.stdout)
		if obj["outcome"] != "refused" || obj["command"] != "fake" || len(obj["reasons"].([]any)) != 1 {
			t.Errorf("object = %v", obj)
		}
	})
	t.Run("the errors of the package carry the outcome of their code", func(t *testing.T) {
		for _, tc := range []struct {
			err  Coded
			code ExitCode
		}{
			{UsageError{Msg: "u"}, ExitUsage}, {Refusal{Reasons: []string{"a"}}, ExitRefused},
			{BackendRefusal{Reasons: []string{"a"}}, ExitBackend}, {NotConfirmed{}, ExitNotConfirmed},
		} {
			if tc.err.ExitCode() != tc.code || tc.err.Outcome() != outcomeOfCode[tc.code] {
				t.Errorf("%T: %d, %q", tc.err, int(tc.err.ExitCode()), tc.err.Outcome())
			}
			code, outcome := ExitFor(tc.err)
			if code != tc.code || outcome != outcomeOfCode[tc.code] {
				t.Errorf("ExitFor(%T) = %d, %q", tc.err, int(code), outcome)
			}
		}
		if code, outcome := ExitFor(nil); code != ExitOK || outcome != OutcomeDone {
			t.Errorf("ExitFor(nil) = %d, %q", int(code), outcome)
		}
		if code, outcome := ExitFor(errors.New("x")); code != ExitFailure || outcome != OutcomeFailed {
			t.Errorf("ExitFor(error) = %d, %q", int(code), outcome)
		}
	})
}

func TestAnExitCodeWithNoDecidedOutcomeOrOutsideTheTable(t *testing.T) {
	undecided := func(code int) string {
		return fmt.Sprintf("cli: the exit code %d has no decided outcome: docs/reference/cli.md must decide its outcome before a command returns it", code)
	}
	outside := func(code int) string {
		return fmt.Sprintf("cli: the exit code %d is not in the table of docs/reference/cli.md", code)
	}
	cases := []struct {
		code ExitCode
		msg  string
	}{
		{10, undecided(10)}, {11, undecided(11)}, {12, undecided(12)},
		{6, outside(6)}, {7, outside(7)}, {9, outside(9)}, {13, outside(13)}, {99, outside(99)}, {126, outside(126)}, {255, outside(255)}, {256, outside(256)}, {-1, outside(-1)},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(int(tc.code)), func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return &Result{ExitCode: tc.code}, nil }})
			ranFailed(t, "fake", tc.msg, "fake")
			// A coded error with that code, whatever outcome it names.
			for _, o := range []Outcome{"", OutcomeDone, OutcomeFailed} {
				withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, oddCoded{code: tc.code, outcome: o} }})
				ranFailed(t, "fake", tc.msg, "fake")
			}
		})
	}
	t.Run("the table itself", func(t *testing.T) {
		for code, want := range outcomeOfCode {
			if got := outcomeOf(code); got != want {
				t.Errorf("outcomeOf(%d) = %q, want %q", int(code), got, want)
			}
		}
		for _, code := range []ExitCode{10, 11, 12, 6, 13, -1, 1000} {
			if msg := recoverText(t, func() { outcomeOf(code) }); msg == "" {
				t.Errorf("outcomeOf(%d) did not panic", int(code))
			}
		}
	})
}

func TestACommandThatReturnsNothingIsAProgrammerError(t *testing.T) {
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, nil }})
	ranFailed(t, "fake", `cli: the command "fake" returned neither a result nor an error`, "fake")
	withSpecs(t, spec{name: "verify", usage: "u", subs: []spec{{name: "crl", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, nil }}}})
	ranFailed(t, "verify", `cli: the command "verify crl" returned neither a result nor an error`, "verify", "crl")
	// A result that is empty is a result: the command ended as it should and has nothing to say.
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return &Result{}, nil }})
	if r := run(t, "fake"); r.code != ExitOK || r.stdout != "" || r.stderr != "" {
		t.Errorf("an empty result: (%d, %q, %q)", int(r.code), r.stdout, r.stderr)
	}
	// Both a result and an error: the error is the answer.
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		return &Result{Text: "ignored\n"}, errors.New("boom")
	}})
	if r := run(t, "fake"); r.code != ExitFailure || r.stdout != "" || r.stderr != "ritueel: boom\n" {
		t.Errorf("a result and an error: (%d, %q, %q)", int(r.code), r.stdout, r.stderr)
	}
}
