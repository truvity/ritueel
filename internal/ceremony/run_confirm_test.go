//go:build linux || darwin

package ceremony_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
)

// The confirmation of a plan (record 0005, rule 9; record 0010, rule 13): the first eight characters
// typed at a terminal, or the whole digest from a script. Anything else is not a confirmation, exit
// code 5, and nothing is written.

// rtUntouched runs a direct apply that must not be confirmed and checks that nothing was written: the
// bundle and the key directory are as they were, and no history/ folder exists.
func rtUntouched(t *testing.T, r *rt, p *ceremony.PlanOut, f *ceremony.Found, c ceremony.Confirm) {
	t.Helper()
	before, keysBefore := r.tree(), r.keyTree()
	done, err := ceremony.Run(context.Background(), r.in(p, f, c))
	if done != nil || !errors.Is(err, ceremony.ErrNotConfirmed) || rtKind(err) != "not-confirmed" {
		t.Fatalf("Run = %v, %v; want ErrNotConfirmed", done, err)
	}
	if _, stopped := rtStopped(err); stopped {
		t.Error("a confirmation that was refused is a stop of a ceremony")
	}
	sameTree(t, "a confirmation that was refused", before, r.tree())
	sameTree(t, "a confirmation that was refused (key directory)", keysBefore, r.keyTree())
	if _, ok := r.tree()["history"]; ok {
		t.Error("history/ exists after a refused confirmation")
	}
	if !strings.Contains(r.stderr.String(), "not confirmed") {
		t.Errorf("the reason is not printed: %q", r.stderr.String())
	}
	if r.stdout.String() != "" {
		t.Errorf("a refused run printed on standard output: %q", r.stdout.String())
	}
}

func TestAWrongOrMissingFlagDigestIsNotConfirmedAndWritesNothing(t *testing.T) {
	r0 := rtNew(t)
	p0, _ := r0.plan()
	d := p0.SHA256
	other := strings.Repeat("0", 64)
	if other == d {
		other = strings.Repeat("1", 64)
	}
	cases := map[string]string{
		"empty":                "",
		"63 digits":            d[:63],
		"65 digits":            d + "0",
		"upper case":           strings.ToUpper(d),
		"mixed case":           strings.ToUpper(d[:32]) + d[32:],
		"another digest":       other,
		"the first eight":      d[:8],
		"a trailing newline":   d + "\n",
		"a leading space":      " " + d,
		"a prefix":             "sha256:" + d,
		"the digest twice":     d + d,
		"a digit changed":      d[:63] + string("0123456789abcdef"[(strings.IndexByte("0123456789abcdef", d[63])+1)%16]),
		"a zero byte":          d[:63] + "\x00",
		"not UTF-8":            d[:62] + "\xff\xfe",
		"a letter of a script": d[:63] + "а",
	}
	for name, digest := range cases {
		t.Run(name, func(t *testing.T) {
			r := rtNew(t)
			p, f := r.plan()
			if p.SHA256 != d {
				t.Fatal("the plan is not the same plan")
			}
			rtUntouched(t, r, p, f, ceremony.Confirm{Flag: true, Digest: digest})
		})
	}
}

func TestAFlagConfirmationReadsNoInputEvenAtATerminal(t *testing.T) {
	r := rtNew(t).typed("whatever\n")
	p, f := r.plan()
	if _, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p))); err != nil {
		t.Fatal(err)
	}
	if r.stdin.count() != 0 {
		t.Errorf("standard input was read %d times for a flag confirmation", r.stdin.count())
	}
	rec, _ := r.record(p.Name)
	if rec.Confirmation == nil || rec.Confirmation.By != "flag" {
		t.Errorf("confirmation = %+v", rec.Confirmation)
	}
}

func TestAWrongFlagDigestIsNotRescuedByATypedLine(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	r.typed(p.SHA256[:8] + "\n")
	rtUntouched(t, r, p, f, ceremony.Confirm{Flag: true, Digest: "wrong"})
	if r.stdin.count() != 0 {
		t.Error("the typed line was read after a wrong flag")
	}
}

func TestTheFirstEightCharactersTypedAtATerminalConfirmInEitherCase(t *testing.T) {
	r0 := rtNew(t)
	p0, _ := r0.plan()
	d := p0.SHA256
	cases := map[string]string{
		"lower case":        d[:8] + "\n",
		"upper case":        strings.ToUpper(d[:8]) + "\n",
		"mixed case":        strings.ToUpper(d[:4]) + d[4:8] + "\n",
		"carriage return":   d[:8] + "\r\n",
		"more lines follow": d[:8] + "\nmore\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			r := rtNew(t).typed(input)
			p, f := r.plan()
			done, err := ceremony.Run(context.Background(), r.in(p, f, ceremony.Confirm{}))
			if err != nil || done == nil {
				t.Fatalf("Run = %v, %v", done, err)
			}
			rec, _ := r.record(p.Name)
			if rec.Confirmation == nil || rec.Confirmation.By != "typed" {
				t.Errorf("confirmation = %+v, want by typed", rec.Confirmation)
			}
			tr := r.transcript(p.Name)
			for _, shown := range []string{r.stderr.String(), tr} {
				if !strings.Contains(shown, "type the first 8 characters of the plan digest") {
					t.Errorf("the prompt is not printed or not in the transcript")
				}
				if !strings.Contains(shown, "confirmed by typing") {
					t.Errorf("the confirmation line is missing")
				}
			}
			// What was typed is not printed again: the upper case form is nowhere (the digest is printed
			// in lower case).
			if strings.ToUpper(d[:8]) != d[:8] && (strings.Contains(r.stderr.String(), strings.ToUpper(d[:8])) || strings.Contains(tr, strings.ToUpper(d[:8]))) {
				t.Error("the typed text is printed or kept in the transcript")
			}
		})
	}
}

func TestATypedLineThatIsNotTheFirstEightCharactersIsNotConfirmedAndWritesNothing(t *testing.T) {
	r0 := rtNew(t)
	p0, _ := r0.plan()
	d := p0.SHA256
	badLast := string("0123456789abcdef"[(strings.IndexByte("0123456789abcdef", d[7])+1)%16])
	cases := map[string]string{
		"empty line":            "\n",
		"nothing at all":        "",
		"end of input at once":  "",
		"seven characters":      d[:7] + "\n",
		"nine characters":       d[:9] + "\n",
		"the whole digest":      d + "\n",
		"another last digit":    d[:7] + badLast + "\n",
		"no line feed":          d[:8],
		"a space inside":        d[:4] + " " + d[4:7] + "\n",
		"a leading space":       " " + d[:7] + "\n",
		"a trailing space":      d[:8] + " \n",
		"a letter past f":       d[:7] + "g\n",
		"a zero byte":           d[:7] + "\x00\n",
		"not UTF-8":             d[:6] + "\xff\xfe\n",
		"a digit of a script":   d[:7] + "٣\n",
		"a full width digit":    "０" + d[1:8] + "\n",
		"a line of 65 bytes":    d[:8] + strings.Repeat(" ", 56) + "\n",
		"a long line":           strings.Repeat("a", 4096) + "\n",
		"a carriage return":     d[:8] + "\r",
		"two carriage returns":  d[:8] + "\r\r\n",
		"enter only":            "\r\n",
		"the digits of another": strings.Repeat("0", 8) + "\n",
		"a line then the right": "x\n" + d[:8] + "\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			r := rtNew(t).typed(input)
			p, f := r.plan()
			if input == strings.Repeat("0", 8)+"\n" && strings.HasPrefix(p.SHA256, "00000000") {
				t.Skip("the plan digest starts with zeros")
			}
			rtUntouched(t, r, p, f, ceremony.Confirm{})
		})
	}
}

func TestATypedLineIsReadFromATerminalOnlyAndAPipedLineIsNotAPerson(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	r.stdin = &rtReader{r: strings.NewReader(p.SHA256[:8] + "\n")}
	r.term = false
	rtUntouched(t, r, p, f, ceremony.Confirm{})
	if r.stdin.count() != 0 {
		t.Errorf("standard input was read %d times when it is not a terminal", r.stdin.count())
	}
	if !strings.Contains(r.stderr.String(), "standard input is not a terminal") || !strings.Contains(r.stderr.String(), "--confirm DIGEST") {
		t.Errorf("the line does not say what a script does: %q", r.stderr.String())
	}
}

func TestATerminalWithNoInputReaderIsNotConfirmed(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	r.term = true
	r.stdin = nil
	rtUntouched(t, r, p, f, ceremony.Confirm{})
}

func TestATypedConfirmationReadsOneLineOfAtMost64Bytes(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	huge := &rtReader{r: io.LimitReader(rtEndless{}, 64<<20)}
	r.stdin, r.term = huge, true
	rtUntouched(t, r, p, f, ceremony.Confirm{})
	if got := huge.taken(); got > 64 {
		t.Errorf("%d bytes were taken from standard input, want at most 64", got)
	}
}

// rtEndless is a reader of letters with no line feed.
type rtEndless struct{}

func (rtEndless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestAReaderThatFailsIsNotConfirmed(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	r.stdin, r.term = &rtReader{r: rtBroken{}}, true
	rtUntouched(t, r, p, f, ceremony.Confirm{})
}

type rtBroken struct{}

func (rtBroken) Read([]byte) (int, error) { return 0, errors.New("test: the terminal is gone") }

func TestAConfirmationOfAnotherPlanIsNotAConfirmation(t *testing.T) {
	// Two plans of one bundle differ in the serials. The digest of the other one confirms nothing.
	r1, r2 := rtNew(t), rtNew(t)
	p1, f1 := r1.plan()
	p2raw, err := ceremony.MakePlan(r2.find(), rtOtherEnv())
	if err != nil {
		t.Fatal(err)
	}
	if p1.SHA256 == p2raw.SHA256 {
		t.Fatal("the two plans have one digest")
	}
	rtUntouched(t, r1, p1, f1, ceremony.Confirm{Flag: true, Digest: p2raw.SHA256})
	r3 := rtNew(t).typed(p2raw.SHA256[:8] + "\n")
	p3, f3 := r3.plan()
	rtUntouched(t, r3, p3, f3, ceremony.Confirm{})
}

func TestARunWhoseConsoleCannotShowThePlanIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	r.console = ceremony.NewConsole(rtFailing{}, r.stdout)
	before, keys := r.tree(), r.keyTree()
	done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
	if done != nil || err == nil || !errors.Is(err, ceremony.ErrPrintFailed) {
		t.Fatalf("Run = %v, %v; want an error that says the plan could not be shown", done, err)
	}
	if errors.Is(err, ceremony.ErrNotConfirmed) {
		t.Error("a plan that was not shown is not a refused confirmation")
	}
	sameTree(t, "a plan that could not be shown", before, r.tree())
	sameTree(t, "a plan that could not be shown (key directory)", keys, r.keyTree())
}

type rtFailing struct{}

func (rtFailing) Write([]byte) (int, error) { return 0, errors.New("test: the stream is closed") }
