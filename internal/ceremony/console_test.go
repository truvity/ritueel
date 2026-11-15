package ceremony_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
)

func transcriptOf(t *testing.T, c *ceremony.Console) string {
	t.Helper()
	b, err := c.Transcript()
	if err != nil {
		t.Fatalf("Transcript: %v", err)
	}
	return string(b)
}

func TestConsoleKeepsTheLinesOfBothStreamsInOrder(t *testing.T) {
	var errOut, out bytes.Buffer
	c := ceremony.NewConsole(&errOut, &out)
	c.Err("first %d", 1)
	c.Out("second %s", "two")
	c.Err("third")
	c.Out("")
	c.Out("fifth")
	if got, want := transcriptOf(t, c), "first 1\nsecond two\nthird\n\nfifth\n"; got != want {
		t.Errorf("transcript %q, want %q", got, want)
	}
	if got, want := errOut.String(), "first 1\nthird\n"; got != want {
		t.Errorf("standard error got %q, want %q", got, want)
	}
	if got, want := out.String(), "second two\n\nfifth\n"; got != want {
		t.Errorf("standard output got %q, want %q", got, want)
	}
}

// The same bytes go to the stream and into the transcript: what a person read is what is kept.
func TestConsoleKeepsExactlyWhatItPrinted(t *testing.T) {
	var both bytes.Buffer
	c := ceremony.NewConsole(&both, &both)
	for _, line := range []string{"plain", "caf\u00e9", "esc \x1b[31mred", strings.Repeat("x", 3000), "tab\there", "bidi \u202e text", "\u200bzero"} {
		c.Err("%s", line)
		c.Out("%s", line)
	}
	if transcriptOf(t, c) != both.String() {
		t.Errorf("the transcript is not what was printed:\n%q\n%q", transcriptOf(t, c), both.String())
	}
}

// Everything beyond printable ASCII is written as an escape, and one line is one line.
func TestConsoleEscapesWhatIsNotPrintableASCII(t *testing.T) {
	cases := []struct {
		name, format string
		args         []any
		want         string
	}{
		{"a line feed in the format", "a\nb", nil, `a\u000ab`},
		{"a line feed in an argument", "%s", []any{"a\nb"}, `a\u000ab`},
		{"a carriage return", "a\rb", nil, `a\u000db`},
		{"a tab", "a\tb", nil, `a\u0009b`},
		{"an escape character", "\x1b[31mred\x1b[0m", nil, `\u001b[31mred\u001b[0m`},
		{"a null", "a\x00b", nil, `a\u0000b`},
		{"a delete", "a\x7fb", nil, `a\u007fb`},
		{"a control of the range U+0080 to U+009F", "a\u0085b", nil, `a\u0085b`},
		{"a right-to-left override", "a\u202eb", nil, `a\u202eb`},
		{"a zero-width space", "a\u200bb", nil, `a\u200bb`},
		{"a byte order mark", "\ufeffa", nil, `\ufeffa`},
		{"a line separator", "a\u2028b", nil, `a\u2028b`},
		{"a letter with an accent", "caf\u00e9", nil, `caf\u00e9`},
		{"a letter of another script", "\u0416", nil, `\u0416`},
		{"a character above U+FFFF", "\U0001f600", nil, `\ud83d\ude00`},
		{"a byte that is not UTF-8", "a\xffb", nil, `a\ufffdb`},
		{"an argument that is not UTF-8", "%s", []any{"\xc3\x28"}, `\ufffd(`},
		{"a percent sign that is a verb with no argument", "100%d", nil, `100%!d(MISSING)`},
		{"an extra argument", "x", []any{1}, `x%!(EXTRA int=1)`},
		{"a space and punctuation", "a ~!{}|", nil, `a ~!{}|`},
		{"the last printable character", "~", nil, `~`},
		{"the first printable character", " ", nil, ` `},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			con := ceremony.NewConsole(io.Discard, &out)
			con.Out(c.format, c.args...)
			want := c.want + "\n"
			if out.String() != want {
				t.Errorf("printed %q, want %q", out.String(), want)
			}
			if got := transcriptOf(t, con); got != want {
				t.Errorf("kept %q, want %q", got, want)
			}
		})
	}
}

type panicky struct{}

func (panicky) String() string { panic("the method panicked") }

type badWriter struct{ calls int }

func (w *badWriter) Write(p []byte) (int, error) { w.calls++; return 0, errors.New("disk is full") }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("the stream panicked") }

func TestConsoleLimitsOfALine(t *testing.T) {
	for _, c := range []struct {
		name string
		n    int
		want int
		cut  bool
	}{
		{"1,023 bytes", 1023, 1023, false},
		{"exactly 1,024 bytes", 1024, 1024, false},
		{"1,025 bytes", 1025, 1024, true},
		{"4,000 bytes", 4000, 1024, true},
		{"100,000 bytes", 100000, 1024, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			con := ceremony.NewConsole(io.Discard, &out)
			con.Out("%s", strings.Repeat("a", c.n))
			line := strings.TrimSuffix(out.String(), "\n")
			if len(line) != c.want {
				t.Errorf("the line is %d bytes, want %d", len(line), c.want)
			}
			if c.cut && !strings.HasSuffix(line, "...") {
				t.Errorf("a cut line does not end with ...: %q", line[len(line)-10:])
			}
			if !c.cut && strings.HasSuffix(line, "...") {
				t.Error("a line that fits was cut")
			}
			if got := transcriptOf(t, con); got != out.String() {
				t.Error("the transcript is not what was printed")
			}
			if c.cut && !strings.HasPrefix(line, strings.Repeat("a", 1021)) {
				t.Error("the cut line does not keep the first 1,021 bytes")
			}
		})
	}
	t.Run("an escape is cut by its output", func(t *testing.T) {
		// 600 characters that are written as six bytes each: the line is cut after the escape.
		var out bytes.Buffer
		con := ceremony.NewConsole(io.Discard, &out)
		con.Out("%s", strings.Repeat("\u00e9", 600))
		line := strings.TrimSuffix(out.String(), "\n")
		if len(line) != 1024 || !strings.HasSuffix(line, "...") {
			t.Errorf("%d bytes: %q", len(line), line[len(line)-12:])
		}
		for i := 0; i < len(line); i++ {
			if line[i] < 0x20 || line[i] > 0x7e {
				t.Fatalf("byte %#x in a cut line", line[i])
			}
		}
	})
}

func TestConsoleLimitsOfATranscript(t *testing.T) {
	t.Run("4,096 lines are kept", func(t *testing.T) {
		con := ceremony.NewConsole(io.Discard, io.Discard)
		for i := 0; i < 4096; i++ {
			con.Out("l")
		}
		b, err := con.Transcript()
		if err != nil || len(b) != 4096*2 {
			t.Fatalf("%d bytes, %v", len(b), err)
		}
	})
	t.Run("the 4,097th line is an error at Transcript", func(t *testing.T) {
		var out bytes.Buffer
		con := ceremony.NewConsole(io.Discard, &out)
		for i := 0; i < 4097; i++ {
			con.Out("l")
		}
		b, err := con.Transcript()
		if b != nil || !errors.Is(err, ceremony.ErrTranscriptLimit) {
			t.Errorf("Transcript = %d bytes, %v; want ErrTranscriptLimit and no text", len(b), err)
		}
		if strings.Count(out.String(), "\n") != 4097 {
			t.Error("a person did not see the 4,097th line")
		}
		// The fault stays: more lines do not clear it.
		con.Out("again")
		if _, err := con.Transcript(); !errors.Is(err, ceremony.ErrTranscriptLimit) {
			t.Errorf("the fault was cleared: %v", err)
		}
	})
	t.Run("1 MiB exactly is kept, one byte more is an error", func(t *testing.T) {
		con := ceremony.NewConsole(io.Discard, io.Discard)
		line := strings.Repeat("a", 1023)
		for i := 0; i < 1024; i++ {
			con.Out("%s", line)
		}
		b, err := con.Transcript()
		if err != nil || len(b) != 1<<20 {
			t.Fatalf("%d bytes, %v", len(b), err)
		}
		con.Out("")
		if _, err := con.Transcript(); !errors.Is(err, ceremony.ErrTranscriptLimit) {
			t.Errorf("a line over 1 MiB: %v", err)
		}
	})
	t.Run("the limit of the line and the limit of the bytes", func(t *testing.T) {
		con := ceremony.NewConsole(io.Discard, io.Discard)
		for i := 0; i < 1100; i++ {
			con.Out("%s", strings.Repeat("a", 5000))
		}
		if _, err := con.Transcript(); !errors.Is(err, ceremony.ErrTranscriptLimit) {
			t.Errorf("1,100 lines of 1,024 bytes: %v", err)
		}
	})
}

func TestConsoleThatPrintedNothingHasAnEmptyTranscript(t *testing.T) {
	con := ceremony.NewConsole(io.Discard, io.Discard)
	b, err := con.Transcript()
	if err != nil || len(b) != 0 {
		t.Errorf("Transcript = %q, %v", b, err)
	}
}

func TestZeroAndNilConsolePrintNothingAndSayWhy(t *testing.T) {
	for name, con := range map[string]*ceremony.Console{"nil": nil, "zero": {}, "new": new(ceremony.Console)} {
		t.Run(name, func(t *testing.T) {
			con.Err("x %d", 1)
			con.Out("y")
			b, err := con.Transcript()
			if b != nil || !errors.Is(err, ceremony.ErrNoConsole) {
				t.Errorf("Transcript = %q, %v; want ErrNoConsole and no text", b, err)
			}
		})
	}
}

func TestConsoleWithAStreamThatFailsKeepsTheFault(t *testing.T) {
	cases := map[string]struct {
		w io.Writer
	}{
		"a write error":      {&badWriter{}},
		"a short write":      {shortWriter{}},
		"a panicking stream": {panicWriter{}},
		"a nil stream":       {nil},
		"a nil pointer":      {(*bytes.Buffer)(nil)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			con := ceremony.NewConsole(c.w, io.Discard)
			con.Err("one")
			con.Err("two")
			b, err := con.Transcript()
			if b != nil || !errors.Is(err, ceremony.ErrPrintFailed) {
				t.Errorf("Transcript = %q, %v; want ErrPrintFailed and no text", b, err)
			}
			if text := err.Error(); strings.ContainsAny(text, "\n\x1b") || len(text) > 600 {
				t.Errorf("the error text is not short and plain: %q", text)
			}
		})
	}
	t.Run("the other stream is not blamed", func(t *testing.T) {
		var out bytes.Buffer
		con := ceremony.NewConsole(&badWriter{}, &out)
		con.Out("fine")
		if got := transcriptOf(t, con); got != "fine\n" {
			t.Errorf("transcript %q", got)
		}
	})
	t.Run("a nil standard output", func(t *testing.T) {
		con := ceremony.NewConsole(io.Discard, nil)
		con.Out("lost")
		if _, err := con.Transcript(); !errors.Is(err, ceremony.ErrPrintFailed) || !strings.Contains(err.Error(), "no stream") {
			t.Errorf("err = %v, want ErrPrintFailed that says there is no stream", err)
		}
	})
	t.Run("the first fault is kept", func(t *testing.T) {
		con := ceremony.NewConsole(&badWriter{}, nil)
		con.Err("a")
		con.Out("b")
		_, err := con.Transcript()
		if !errors.Is(err, ceremony.ErrPrintFailed) || !strings.Contains(err.Error(), "disk is full") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestConsoleSurvivesAnArgumentWhoseMethodPanics(t *testing.T) {
	var out bytes.Buffer
	con := ceremony.NewConsole(io.Discard, &out)
	con.Out("before")
	con.Out("value %v", panicky{})
	con.Out("after")
	text := transcriptOf(t, con)
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 3 || lines[0] != "before" || lines[2] != "after" {
		t.Fatalf("transcript %q", text)
	}
	if !strings.Contains(lines[1], "PANIC") && !strings.Contains(lines[1], "could not be formatted") {
		t.Errorf("the panicking line is %q", lines[1])
	}
	if text != out.String() {
		t.Error("the transcript is not what was printed")
	}
}

// A hostile argument cannot make a line that a terminal acts on, or that looks like two lines.
func TestConsoleLineOfAHostileArgumentIsOneLineOfPrintableASCII(t *testing.T) {
	var out bytes.Buffer
	con := ceremony.NewConsole(&out, &out)
	hostile := "name\n\x1b]0;title\x07\x1b[2J\r\u202e\u2028\u0085fake line\nroot key A: x509 pin " + strings.Repeat("0", 64)
	con.Err("path %s", hostile)
	con.Err("%q", hostile)
	con.Err("%v %+v", hostile, []string{hostile})
	text := transcriptOf(t, con)
	if text != out.String() {
		t.Error("the transcript is not what was printed")
	}
	if strings.Count(text, "\n") != 3 {
		t.Errorf("3 lines were printed and the text has %d line feeds", strings.Count(text, "\n"))
	}
	for i := 0; i < len(text); i++ {
		if text[i] != '\n' && (text[i] < 0x20 || text[i] > 0x7e) {
			t.Fatalf("byte %#x in a printed line", text[i])
		}
	}
}

// Two goroutines that start behind a closed channel and print keep every line whole, with each
// line in the transcript and on the stream the same number of times.
func TestConsoleLinesOfManyGoroutinesStayWhole(t *testing.T) {
	var errOut, out syncBuffer
	con := ceremony.NewConsole(&errOut, &out)
	const goroutines, each = 8, 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < each; i++ {
				if g%2 == 0 {
					con.Err("goroutine %d line %d end", g, i)
				} else {
					con.Out("goroutine %d line %d end", g, i)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	text := transcriptOf(t, con)
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != goroutines*each {
		t.Fatalf("%d lines, want %d", len(lines), goroutines*each)
	}
	seen := map[string]int{}
	for _, l := range lines {
		var g, i int
		var rest string
		if n, err := fmt.Sscanf(l, "goroutine %d line %d %s", &g, &i, &rest); n != 3 || err != nil || rest != "end" {
			t.Fatalf("a line is not whole: %q", l)
		}
		seen[l]++
	}
	if len(seen) != goroutines*each {
		t.Errorf("%d different lines, want %d", len(seen), goroutines*each)
	}
	// Per goroutine, the lines are in the order they were printed in.
	last := make([]int, goroutines)
	for i := range last {
		last[i] = -1
	}
	for _, l := range lines {
		var g, i int
		_, _ = fmt.Sscanf(l, "goroutine %d line %d", &g, &i)
		if i != last[g]+1 {
			t.Fatalf("goroutine %d: line %d after line %d", g, i, last[g])
		}
		last[g] = i
	}
	if strings.Count(errOut.String(), "\n")+strings.Count(out.String(), "\n") != goroutines*each {
		t.Error("the streams do not hold every line")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A transcript from a Console is accepted by WriteTranscript: the two agree on the rules.
func TestATranscriptOfAConsoleIsWritten(t *testing.T) {
	con := ceremony.NewConsole(io.Discard, io.Discard)
	for _, s := range []string{"plan", "caf\u00e9 \u202e", "\x1b[2J", "\r\n", strings.Repeat("z", 5000), "\u2028", "\ufeff"} {
		con.Err("%s", s)
		con.Out("%s", s)
	}
	text, err := con.Transcript()
	if err != nil {
		t.Fatal(err)
	}
	b := newBundle(t)
	fl := newFlow(t, b, newSpec(name1, 1, ""))
	fl.must("end")
	if err := fl.f.WriteTranscript(text); err != nil {
		t.Errorf("WriteTranscript of a Console's transcript: %v", err)
	}
	if got := b.read("history", name1, "transcript.txt"); !bytes.Equal(got, text) {
		t.Error("transcript.txt is not the transcript of the Console")
	}
}
