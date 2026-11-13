package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The tree of a returned error. A command may return an error that holds others (errors.Join, or
// fmt.Errorf with several %w, or WithWarnings around either). Two rules hold for the whole tree:
//
//   - the warnings of every error in it are given, the errors inside before the error that wraps them,
//     depth first and left to right, and none is dropped or counted once;
//   - at most one error in it carries an exit code: more than one is a fault of the programmer (no page
//     says which code and which reasons win), and the run ends with the exit code 1 and the text of the
//     panic, before any code is chosen.

// withW is a plain error with a warning.
func withW(msg, warning string) error { return WithWarnings(errors.New(msg), warning) }

// joined is the message that errors.Join gives two or more errors, as the program shows it: the line
// break between the messages is written \u000a.
func joined(msgs ...string) string { return strings.Join(msgs, u(10)) }

// oneCode is the text of the panic of an error that holds more than one error with an exit code; types
// are the Go types in walk order.
func oneCode(word string, types ...string) string {
	return fmt.Sprintf("cli: the command %q returned an error that holds %d errors with an exit code (%s), and no page says which code and which reasons win; a command that refuses for several reasons returns one Refusal that lists all the reason codes, and joins no other error that has an exit code", word, len(types), strings.Join(types, ", "))
}

// codedWrapper is an error that carries a code and wraps another error that carries one: the tree has
// two coded errors, and it is refused.
type codedWrapper struct{ err error }

func (e codedWrapper) Error() string       { return "wrapper: " + e.err.Error() }
func (e codedWrapper) Unwrap() error       { return e.err }
func (codedWrapper) ExitCode() ExitCode    { return ExitRefused }
func (codedWrapper) Outcome() Outcome      { return OutcomeRefused }
func (codedWrapper) ReasonCodes() []string { return []string{"outer"} }

func TestWarningsFromTheWholeTreeOfAnError(t *testing.T) {
	a, b, c, d := withW("e1", "from-a"), withW("e2", "from-b"), withW("e3", "from-c"), withW("e4", "from-d")
	plain1, plain2 := errors.New("p1"), errors.New("p2")
	r1 := func() error { return WithWarnings(Refusal{Reasons: []string{"ra"}, Msg: "m1"}, "wa") }
	failed := func(msg string, warnings ...string) map[string]any {
		return members(ExitFailure, "failed", map[string]any{"error": msg, "warnings": warnings})
	}
	cases := []outcomeCase{
		{"two joined errors, both with warnings", func() (*Result, error) { return nil, errors.Join(a, b) }, ExitFailure, "",
			warnLines("from-a", "from-b") + "ritueel: " + joined("e1", "e2") + "\n", failed(joined("e1", "e2"), "from-a", "from-b")},
		{"two errors under fmt.Errorf with two %w", func() (*Result, error) { return nil, fmt.Errorf("x: %w, %w", a, b) }, ExitFailure, "",
			warnLines("from-a", "from-b") + "ritueel: x: e1, e2\n", failed("x: e1, e2", "from-a", "from-b")},
		{"WithWarnings around a join adds its own last", func() (*Result, error) { return nil, WithWarnings(errors.Join(a, b), "outer") }, ExitFailure, "",
			warnLines("from-a", "from-b", "outer") + "ritueel: " + joined("e1", "e2") + "\n", failed(joined("e1", "e2"), "from-a", "from-b", "outer")},
		{"the same value twice gives its warnings twice", func() (*Result, error) { return nil, errors.Join(a, a) }, ExitFailure, "",
			warnLines("from-a", "from-a") + "ritueel: " + joined("e1", "e1") + "\n", failed(joined("e1", "e1"), "from-a", "from-a")},
		{"a wrapper around a join, joined again: inner first at every level", func() (*Result, error) {
			return nil, errors.Join(WithWarnings(errors.Join(a, b), "mid"), withW("e5", "from-e"))
		}, ExitFailure, "",
			warnLines("from-a", "from-b", "mid", "from-e") + "ritueel: " + joined("e1", "e2", "e5") + "\n",
			failed(joined("e1", "e2", "e5"), "from-a", "from-b", "mid", "from-e")},
		{"three levels of joins", func() (*Result, error) {
			return nil, errors.Join(errors.Join(a, errors.Join(b, c)), d)
		}, ExitFailure, "",
			warnLines("from-a", "from-b", "from-c", "from-d") + "ritueel: " + joined("e1", "e2", "e3", "e4") + "\n",
			failed(joined("e1", "e2", "e3", "e4"), "from-a", "from-b", "from-c", "from-d")},
		{"three levels with a wrapper at each level", func() (*Result, error) {
			inner := WithWarnings(errors.Join(b, c), "w-inner")
			mid := WithWarnings(fmt.Errorf("mid: %w; %w", a, inner), "w-mid")
			return nil, WithWarnings(errors.Join(mid, d), "w-top")
		}, ExitFailure, "",
			warnLines("from-a", "from-b", "from-c", "w-inner", "w-mid", "from-d", "w-top") + "ritueel: " + joined("mid: e1; e2"+u(10)+"e3", "e4") + "\n",
			failed(joined("mid: e1; e2"+u(10)+"e3", "e4"), "from-a", "from-b", "from-c", "w-inner", "w-mid", "from-d", "w-top")},
		{"a wrapper with three %w where only the middle part carries warnings", func() (*Result, error) {
			return nil, fmt.Errorf("%w; %w; %w", plain1, b, plain2)
		}, ExitFailure, "",
			warnLines("from-b") + "ritueel: p1; e2; p2\n", failed("p1; e2; p2", "from-b")},
		{"a wrapper with two %w where only the last part carries warnings", func() (*Result, error) {
			return nil, fmt.Errorf("%w; %w", plain1, b)
		}, ExitFailure, "",
			warnLines("from-b") + "ritueel: p1; e2\n", failed("p1; e2", "from-b")},
		{"a wrapper with two %w where only the first part carries warnings", func() (*Result, error) {
			return nil, fmt.Errorf("%w; %w", a, plain2)
		}, ExitFailure, "",
			warnLines("from-a") + "ritueel: e1; p2\n", failed("e1; p2", "from-a")},
		{"a join with no warning anywhere", func() (*Result, error) { return nil, errors.Join(plain1, plain2) }, ExitFailure, "",
			"ritueel: " + joined("p1", "p2") + "\n", failed(joined("p1", "p2"))},
		{"a join with a nil error inside: errors.Join leaves it out", func() (*Result, error) { return nil, errors.Join(nil, a) }, ExitFailure, "",
			warnLines("from-a") + "ritueel: e1\n", failed("e1", "from-a")},
		{"a join with nil on both sides of an error", func() (*Result, error) { return nil, errors.Join(nil, a, nil, b, nil) }, ExitFailure, "",
			warnLines("from-a", "from-b") + "ritueel: " + joined("e1", "e2") + "\n", failed(joined("e1", "e2"), "from-a", "from-b")},
		{"a nil %w operand is no part of the tree", func() (*Result, error) { return nil, fmt.Errorf("%w|%w", nil, a) }, ExitFailure, "",
			warnLines("from-a") + "ritueel: %!w(<nil>)|e1\n", failed("%!w(<nil>)|e1", "from-a")},
		{"a join, then a refusal with warnings: the refusal gives the code and the reasons", func() (*Result, error) {
			return nil, errors.Join(a, r1())
		}, ExitRefused, "",
			warnLines("from-a", "wa") + "ritueel: " + joined("e1", "m1") + "\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"ra"}, "warnings": []string{"from-a", "wa"}})},
		{"a refusal first, then a plain error with a warning", func() (*Result, error) {
			return nil, errors.Join(r1(), a)
		}, ExitRefused, "",
			warnLines("wa", "from-a") + "ritueel: " + joined("m1", "e1") + "\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"ra"}, "warnings": []string{"wa", "from-a"}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkOutcome(t, tc) })
	}
}

// Many joined errors keep their order, in the object and on standard error.
func TestManyJoinedErrorsKeepTheirOrder(t *testing.T) {
	const n = 200
	build := func(every int) (errs []error, want []string, msgs []string) {
		for i := 0; i < n; i++ {
			msg := fmt.Sprintf("e%03d", (i*37)%n) // an order that is not sorted
			msgs = append(msgs, msg)
			if i%every == 0 {
				w := fmt.Sprintf("w-%03d", (i*37)%n)
				errs = append(errs, WithWarnings(errors.New(msg), w))
				want = append(want, w)
			} else {
				errs = append(errs, errors.New(msg))
			}
		}
		return errs, want, msgs
	}
	for _, every := range []int{1, 3} {
		errs, want, msgs := build(every)
		cases := []outcomeCase{
			{fmt.Sprintf("a join of %d, a warning on every %dth", n, every), func() (*Result, error) { return nil, errors.Join(errs...) }, ExitFailure, "",
				warnLines(want...) + "ritueel: " + joined(msgs...) + "\n",
				members(ExitFailure, "failed", map[string]any{"error": joined(msgs...), "warnings": want})},
			{fmt.Sprintf("a join of %d in two halves, joined again", n), func() (*Result, error) {
				return nil, errors.Join(errors.Join(errs[:n/2]...), errors.Join(errs[n/2:]...))
			}, ExitFailure, "",
				warnLines(want...) + "ritueel: " + joined(msgs...) + "\n",
				members(ExitFailure, "failed", map[string]any{"error": joined(msgs...), "warnings": want})},
			{fmt.Sprintf("a join of %d, wrapped once more with a last warning", n), func() (*Result, error) {
				return nil, WithWarnings(errors.Join(errs...), "last")
			}, ExitFailure, "",
				warnLines(append(slices.Clone(want), "last")...) + "ritueel: " + joined(msgs...) + "\n",
				members(ExitFailure, "failed", map[string]any{"error": joined(msgs...), "warnings": append(slices.Clone(want), "last")})},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) { checkOutcome(t, tc) })
		}
	}
	t.Run("200 joined errors with one refusal in the middle", func(t *testing.T) {
		errs, want, _ := build(1)
		errs[100] = WithWarnings(Refusal{Reasons: []string{"mid"}, Msg: "m"}, "w-refusal")
		want[100] = "w-refusal"
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, errors.Join(errs...) }})
		r := run(t, "--output", "json", "fake")
		if r.code != ExitRefused {
			t.Fatalf("exit code = %d, want 3 (stderr %q)", int(r.code), r.stderr)
		}
		obj := object(t, r.stdout)
		if got, ok := stringList(obj["warnings"]); !ok || !slices.Equal(got, want) {
			t.Errorf("warnings differ from the walk order (%d, want %d)", len(got), len(want))
		}
		if got, ok := stringList(obj["reasons"]); !ok || !slices.Equal(got, []string{"mid"}) {
			t.Errorf("reasons = %#v", obj["reasons"])
		}
	})
}

// A join of nothing but nil is no error: the command has returned neither a result nor an error.
func TestAJoinOfNilIsNoError(t *testing.T) {
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, errors.Join(nil, nil) }})
	ranFailed(t, "fake", `cli: the command "fake" returned neither a result nor an error`, "fake")
}

// One coded error in the tree is the normal case, whatever surrounds it.
func TestOneCodedErrorInATreeIsNotAFault(t *testing.T) {
	plain := errors.New("p")
	refusal := Refusal{Reasons: []string{"ra"}, Msg: "m1"}
	cases := []outcomeCase{
		{"a plain error joined with a refusal", func() (*Result, error) { return nil, errors.Join(plain, refusal) }, ExitRefused, "",
			"ritueel: " + joined("p", "m1") + "\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"ra"}})},
		{"a refusal by pointer joined with a plain error", func() (*Result, error) {
			r := refusal
			return nil, errors.Join(&r, plain)
		}, ExitRefused, "",
			"ritueel: " + joined("m1", "p") + "\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"ra"}})},
		{"a refusal under fmt.Errorf and WithWarnings", func() (*Result, error) {
			return nil, fmt.Errorf("x: %w", WithWarnings(refusal, "w"))
		}, ExitRefused, "", warnLines("w") + "ritueel: x: m1\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"ra"}, "warnings": []string{"w"}})},
		{"a backend refusal in the second place of a join", func() (*Result, error) {
			return nil, errors.Join(plain, errors.New("q"), BackendRefusal{Reasons: []string{"rb"}, Msg: "m2"})
		}, ExitBackend, "", "ritueel: " + joined("p", "q", "m2") + "\n",
			members(ExitBackend, "refused", map[string]any{"reasons": []string{"rb"}})},
		{"two plain errors", func() (*Result, error) { return nil, errors.Join(plain, errors.New("q")) }, ExitFailure, "",
			"ritueel: " + joined("p", "q") + "\n",
			members(ExitFailure, "failed", map[string]any{"error": joined("p", "q")})},
		{"a usage error joined with a plain error", func() (*Result, error) {
			return nil, errors.Join(UsageError{Msg: "wrong"}, plain)
		}, ExitUsage, "", "ritueel: " + joined("wrong", "p") + "\n" + helpLine,
			members(ExitUsage, "usage", map[string]any{"error": joined("wrong", "p")})},
		{"not confirmed under a wrapper", func() (*Result, error) {
			return nil, fmt.Errorf("x: %w", WithWarnings(NotConfirmed{}, "w"))
		}, ExitNotConfirmed, "", warnLines("w") + "ritueel: x: not confirmed\n",
			members(ExitNotConfirmed, "not-confirmed", map[string]any{"warnings": []string{"w"}})},
		{"a refusal with several reasons in one value", func() (*Result, error) {
			return nil, WithWarnings(Refusal{Reasons: []string{"ra", "rb"}, Msg: "m"}, "w")
		}, ExitRefused, "", warnLines("w") + "ritueel: m\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"ra", "rb"}, "warnings": []string{"w"}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkOutcome(t, tc) })
	}
}

// More than one error with an exit code in one returned error is a fault of the programmer, in text and
// in JSON mode, for a word and for a second word.
func TestMoreThanOneExitCodeInAnErrorIsAProgrammerError(t *testing.T) {
	ra := func() error { return Refusal{Reasons: []string{"ra"}, Msg: "m1"} }
	rb := func() error { return BackendRefusal{Reasons: []string{"rb"}, Msg: "m2"} }
	cases := []struct {
		name  string
		make  func() error
		types []string
	}{
		{"a refusal and a backend refusal", func() error { return errors.Join(ra(), rb()) }, []string{"cli.Refusal", "cli.BackendRefusal"}},
		{"a backend refusal and a refusal", func() error { return errors.Join(rb(), ra()) }, []string{"cli.BackendRefusal", "cli.Refusal"}},
		{"the same refusal twice", func() error { r := ra(); return errors.Join(r, r) }, []string{"cli.Refusal", "cli.Refusal"}},
		{"a refusal and a usage error under fmt.Errorf with two %w", func() error {
			return fmt.Errorf("x: %w, %w", ra(), UsageError{Msg: "u"})
		}, []string{"cli.Refusal", "cli.UsageError"}},
		{"wrappers do not hide the count: WithWarnings around a join of a wrapped refusal and not-confirmed", func() error {
			return WithWarnings(errors.Join(WithWarnings(ra(), "w1"), NotConfirmed{}), "w2")
		}, []string{"cli.Refusal", "cli.NotConfirmed"}},
		{"two refusals by pointer", func() error {
			r1, r2 := Refusal{Reasons: []string{"a"}}, Refusal{Reasons: []string{"b"}}
			return errors.Join(&r1, &r2)
		}, []string{"*cli.Refusal", "*cli.Refusal"}},
		{"a refusal by pointer and a value", func() error {
			r1 := Refusal{Reasons: []string{"a"}}
			return errors.Join(&r1, rb())
		}, []string{"*cli.Refusal", "cli.BackendRefusal"}},
		{"three coded errors", func() error {
			return errors.Join(ra(), NotConfirmed{}, UsageError{Msg: "u"})
		}, []string{"cli.Refusal", "cli.NotConfirmed", "cli.UsageError"}},
		{"two deep in a tree, a plain error between them", func() error {
			return errors.Join(errors.Join(errors.New("p"), ra()), fmt.Errorf("y: %w", errors.Join(errors.New("q"), rb())))
		}, []string{"cli.Refusal", "cli.BackendRefusal"}},
		{"a coded error and a coded error that wraps one", func() error {
			return codedWrapper{err: ra()}
		}, []string{"cli.Refusal", "cli.codedWrapper"}},
		{"two usage errors", func() error { return errors.Join(UsageError{Msg: "a"}, UsageError{Msg: "b"}) }, []string{"cli.UsageError", "cli.UsageError"}},
		{"200 joined, two of them coded, at the ends", func() error {
			errs := make([]error, 200)
			for i := range errs {
				errs[i] = errors.New("p")
			}
			errs[0], errs[199] = NotConfirmed{}, ra()
			return errors.Join(errs...)
		}, []string{"cli.NotConfirmed", "cli.Refusal"}},
		{"a code that would be 0 is not the first thing reported: the count is", func() error {
			return errors.Join(oddCoded{code: ExitOK, outcome: OutcomeDone}, ra())
		}, []string{"cli.oddCoded", "cli.Refusal"}},
		{"an outcome that disagrees with its code is not the first thing reported: the count is", func() error {
			return errors.Join(oddCoded{code: ExitFailure, outcome: OutcomeRefused}, ra())
		}, []string{"cli.oddCoded", "cli.Refusal"}},
		{"a refusal with no reason code in a join of two is the count too", func() error {
			return errors.Join(Refusal{Msg: "no"}, rb())
		}, []string{"cli.Refusal", "cli.BackendRefusal"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, tc.make() }})
			ranFailed(t, "fake", oneCode("fake", tc.types...), "fake")
			// A second word names its path in the text.
			withSpecs(t, spec{name: "verify", usage: "u", subs: []spec{{name: "crl", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, tc.make() }}}})
			ranFailed(t, "verify", oneCode("verify crl", tc.types...), "verify", "crl")
		})
	}
	t.Run("the warnings of the panicking command are lost with the panic", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return nil, errors.Join(WithWarnings(ra(), "w1"), WithWarnings(rb(), "w2"))
		}})
		r := run(t, "fake")
		if want := "ritueel: internal error: " + oneCode("fake", "cli.Refusal", "cli.BackendRefusal") + "\n"; r.code != ExitFailure || r.stderr != want {
			t.Errorf("(%d, %q), want (1, %q)", int(r.code), r.stderr, want)
		}
	})
	t.Run("a Result and an error: the error is the answer, and it is checked", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return &Result{Text: "ignored\n"}, errors.Join(ra(), rb())
		}})
		ranFailed(t, "fake", oneCode("fake", "cli.Refusal", "cli.BackendRefusal"), "fake")
	})
}

// The same walk, asked directly.
func TestTheWalkOfAnErrorTree(t *testing.T) {
	a, b := withW("e1", "from-a"), withW("e2", "from-b")
	r := Refusal{Reasons: []string{"r"}}
	t.Run("warningsOf", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			err  error
			want []string
		}{
			{"nil", nil, nil},
			{"a plain error", errors.New("x"), nil},
			{"one", a, []string{"from-a"}},
			{"a join", errors.Join(a, b), []string{"from-a", "from-b"}},
			{"a join, the other way", errors.Join(b, a), []string{"from-b", "from-a"}},
			{"a wrapper around a join", WithWarnings(errors.Join(a, b), "o"), []string{"from-a", "from-b", "o"}},
			{"a wrapper in front of a wrapper", WithWarnings(WithWarnings(errors.New("x"), "1"), "2"), []string{"1", "2"}},
			{"a join in a join in a join", errors.Join(errors.Join(errors.Join(a), b), errors.Join(a)), []string{"from-a", "from-b", "from-a"}},
			{"fmt.Errorf with %w and %v: only the %w part", fmt.Errorf("%w %v", a, b), []string{"from-a"}}, //nolint:errorlint // the %v is the point: b is text, not a part of the tree
		} {
			if got := warningsOf(tc.err); !slices.Equal(got, tc.want) {
				t.Errorf("%s: warningsOf = %q, want %q", tc.name, got, tc.want)
			}
		}
	})
	t.Run("codedIn", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			err  error
			want int
		}{
			{"nil", nil, 0},
			{"a plain error", errors.New("x"), 0},
			{"a refusal", r, 1},
			{"a refusal by pointer", &r, 1},
			{"a refusal under fmt.Errorf", fmt.Errorf("x: %w", r), 1},
			{"a refusal under WithWarnings", WithWarnings(r, "w"), 1},
			{"two", errors.Join(r, BackendRefusal{}), 2},
			{"the same value twice", errors.Join(r, r), 2},
			{"a refusal and plain errors", errors.Join(errors.New("x"), r, errors.New("y")), 1},
			{"a type that is coded and wraps a coded error", codedWrapper{err: r}, 2},
		} {
			if got := codedIn(tc.err); len(got) != tc.want {
				t.Errorf("%s: codedIn = %d errors, want %d", tc.name, len(got), tc.want)
			}
		}
	})
	t.Run("checkOneCode names the types in walk order", func(t *testing.T) {
		want := oneCode("w", "cli.Refusal", "cli.NotConfirmed")
		if got := recoverText(t, func() { checkOneCode("w", errors.Join(r, NotConfirmed{})) }); got != want {
			t.Errorf("panic = %q, want %q", got, want)
		}
		if got := recoverText(t, func() { checkOneCode("w", errors.Join(errors.New("x"), r)) }); got != "" {
			t.Errorf("one coded error panicked: %q", got)
		}
	})
	t.Run("ExitFor and reasonsOf still take the first coded error", func(t *testing.T) {
		code, _ := ExitFor(errors.Join(BackendRefusal{Reasons: []string{"rb"}}, Refusal{Reasons: []string{"ra"}}))
		if code != ExitBackend {
			t.Errorf("ExitFor = %d, want 4", int(code))
		}
		if got := reasonsOf(errors.Join(Refusal{Reasons: []string{"ra"}}, BackendRefusal{Reasons: []string{"rb"}})); !slices.Equal(got, []string{"ra"}) {
			t.Errorf("reasonsOf = %q, want [ra]", got)
		}
	})
}
