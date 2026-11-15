package software

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
)

// ---- CheckPassphrase ----

func TestCheckPassphraseAcceptsAndRefusesExactlyAtTheEdges(t *testing.T) {
	rep := strings.Repeat
	cases := []struct {
		name string
		pass string
		ok   bool
	}{
		{"14 characters are refused", rep("a", 14), false},
		{"15 characters are accepted", rep("a", 15), true},
		{"16 characters are accepted", rep("a", 16), true},
		{"15 characters of 2 bytes (30 bytes) are accepted", rep("\u00e9", 15), true},
		{"14 characters of 2 bytes (28 bytes) are refused: the count is of characters, not bytes", rep("\u00e9", 14), false},
		{"15 characters of 3 bytes (45 bytes) are accepted", rep("\u65e5", 15), true},
		{"15 characters of 4 bytes (60 bytes) are accepted", rep("\U0001d518", 15), true},
		{"14 characters of 4 bytes (56 bytes) are refused", rep("\U0001d518", 14), false},
		{"1024 bytes are accepted", rep("a", MaxPassphraseBytes), true},
		{"1025 bytes are refused", rep("a", MaxPassphraseBytes+1), false},
		{"1024 bytes of 2-byte characters are accepted", rep("\u00e9", MaxPassphraseBytes/2), true},
		{"1026 bytes of 2-byte characters are refused", rep("\u00e9", MaxPassphraseBytes/2+1), false},
		{"an empty passphrase is refused", "", false},
		{"15 combining marks count as 15 characters: the rule counts code points", rep("\u0301", 15), true},
		{"14 combining marks are refused", rep("\u0301", 14), false},
		{"six words of three letters are accepted", "cat dog fox pig hen owl", true},
		{"15 spaces and a letter are accepted: nothing is trimmed and no strength is judged", rep(" ", 15) + "x", true},
		{"15 spaces are accepted: the package judges no strength", rep(" ", 15), true},
		{"14 spaces and a letter are accepted: they are 15 characters", rep(" ", 14) + "x", true},
		{"a leading and a trailing space are characters of the passphrase", " " + rep("a", 13) + " ", true},
		{"the same letter 15 times is accepted: the package judges no strength", rep("a", 15), true},
		{"a no-break space is a character, not a control character", rep("a", 14) + "\u00a0", true},
		{"a tab inside is refused", rep("a", 10) + "\t" + rep("a", 10), false},
		{"a NUL inside is refused", rep("a", 10) + "\x00" + rep("a", 10), false},
		{"a NUL at the end is refused", rep("a", 20) + "\x00", false},
		{"a carriage return inside is refused", rep("a", 10) + "\r" + rep("a", 10), false},
		{"a carriage return at the end is refused", rep("a", 20) + "\r", false},
		{"a line feed inside is refused", rep("a", 10) + "\n" + rep("a", 10), false},
		{"a line feed at the end is refused", rep("a", 20) + "\n", false},
		{"U+001F is refused", rep("a", 20) + "\u001f", false},
		{"U+007F is refused", rep("a", 20) + "\u007f", false},
		{"U+0080 is refused", rep("a", 20) + "\u0080", false},
		{"U+0085 is refused", rep("a", 20) + "\u0085", false},
		{"U+009F is refused", rep("a", 20) + "\u009f", false},
		{"U+00A0 is accepted", rep("a", 20) + "\u00a0", true},
		{"U+202E (right-to-left override) is refused: it is a format character", rep("a", 20) + "\u202e", false},
		{"U+202E first is refused", "\u202e" + rep("a", 20), false},
		{"U+200D (zero-width joiner) is refused: a format character", rep("a", 20) + "\u200d", false},
		{"U+200B (zero-width space) is refused: a format character", rep("a", 20) + "\u200b", false},
		{"U+FEFF (byte order mark) is refused: a format character", "\ufeff" + rep("a", 20), false},
		{"U+00AD (soft hyphen) is refused: a format character", rep("a", 20) + "\u00ad", false},
		{"one invalid byte inside is refused", rep("a", 10) + "\xff" + rep("a", 10), false},
		{"a truncated 3-byte sequence at the end is refused", rep("a", 20) + "\xe2\x82", false},
		{"an overlong NUL (C0 80) is refused", rep("a", 20) + "\xc0\x80", false},
		{"an encoded surrogate (ED A0 80) is refused", rep("a", 20) + "\xed\xa0\x80", false},
		{"a code point above U+10FFFF (F4 90 80 80) is refused", rep("a", 20) + "\xf4\x90\x80\x80", false},
		{"a lone continuation byte is refused", rep("a", 20) + "\x80", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := []byte(c.pass)
			err := CheckPassphrase(in)
			if string(in) != c.pass {
				t.Error("CheckPassphrase changed its argument")
			}
			if c.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			wantRefusal(t, err, ErrPassphrase, "passphrase")
		})
	}
}

func TestCheckPassphraseOfNilIsRefused(t *testing.T) {
	wantRefusal(t, CheckPassphrase(nil), ErrPassphrase, "passphrase")
	wantRefusal(t, CheckPassphrase([]byte{}), ErrPassphrase, "passphrase")
}

func TestCheckPassphraseErrorNamesTheRuleAndNoPartOfThePassphrase(t *testing.T) {
	secret := "hunter2-secret-words"
	for name, pass := range map[string]string{
		"too short":       secret[:10],
		"control":         secret + "\x00",
		"format":          secret + "\u202e",
		"invalid UTF-8":   secret + "\xff",
		"too long":        strings.Repeat(secret, 60),
		"long and bad":    strings.Repeat(secret, 60) + "\x00",
		"short and a tab": "hunter2\t",
	} {
		err := CheckPassphrase([]byte(pass))
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		text := fmt.Sprintf("%v %+v %#v %q", err, err, err, err)
		for _, part := range []string{"hunter", "secret", "words", "\x00", "\u202e", "\xff"} {
			if strings.Contains(text, part) {
				t.Errorf("%s: the error holds %q: %s", name, part, text)
			}
		}
		if strings.Contains(strings.ToLower(text), "close") || strings.Contains(text, "one character") {
			t.Errorf("%s: the error hints at how near the passphrase is: %s", name, text)
		}
	}
}

func TestCheckPassphraseNamesDifferentRulesInDifferentWords(t *testing.T) {
	texts := map[string]string{}
	for name, pass := range map[string][]byte{
		"short": []byte("short"), "control": []byte(strings.Repeat("a", 20) + "\x00"),
		"utf8": []byte(strings.Repeat("a", 20) + "\xff"), "long": bytes.Repeat([]byte("a"), 2000),
	} {
		texts[name] = CheckPassphrase(pass).Error()
	}
	seen := map[string]string{}
	for name, text := range texts {
		if other, ok := seen[text]; ok {
			t.Errorf("%s and %s give the same words: %s", name, other, text)
		}
		seen[text] = name
	}
}

// ---- ReaderSource ----

// countReader counts the bytes that it gave and records Close.
type countReader struct {
	r      io.Reader
	n      int
	closed bool
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func (c *countReader) Close() error { c.closed = true; return nil }

func readOne(t testing.TB, r io.Reader) ([]byte, error) {
	t.Helper()
	return ReaderSource(r).Passphrase(context.Background(), Purpose{Label: "A", File: FileX509})
}

func TestReaderSourceGivesOneLineForEachShapeOfLineEnd(t *testing.T) {
	line := strings.Repeat("p", 20)
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"a line that ends in a line feed", line + "\n", line, true},
		{"a line that ends in a carriage return and a line feed", line + "\r\n", line, true},
		{"a line that ends at the end of the input", line, line, true},
		{"only the first line is read", line + "\nsecond line is for the next call\n", line, true},
		{"only the first line is read when the lines end in CRLF", line + "\r\nsecond\r\n", line, true},
		{"spaces are kept at both ends", " " + line + " \n", " " + line + " ", true},
		{"a tab at the end is a control character", line + "\t\n", "", false},
		{"one carriage return in front of the line feed is removed, and a second one is a control character", line + "\r\r\n", "", false},
		{"a carriage return at the end of the input with no line feed stays and is refused", line + "\r", "", false},
		{"a carriage return inside the line is refused", line[:10] + "\r" + line[10:] + "\n", "", false},
		{"an empty input", "", "", false},
		{"an empty line", "\n", "", false},
		{"an empty line with a carriage return", "\r\n", "", false},
		{"a line feed first and then a good line: the empty first line is refused", "\n" + line + "\n", "", false},
		{"a short passphrase", "short\n", "", false},
		{"a NUL inside", line + "\x00" + line + "\n", "", false},
		{"invalid UTF-8", line + "\xff\n", "", false},
		{"a right-to-left override", line + "\u202e\n", "", false},
		{"1024 bytes and a line feed", strings.Repeat("a", MaxPassphraseBytes) + "\n", strings.Repeat("a", MaxPassphraseBytes), true},
		{"1024 bytes and a carriage return and a line feed", strings.Repeat("a", MaxPassphraseBytes) + "\r\n", strings.Repeat("a", MaxPassphraseBytes), true},
		{"1024 bytes at the end of the input", strings.Repeat("a", MaxPassphraseBytes), strings.Repeat("a", MaxPassphraseBytes), true},
		{"1025 bytes and a line feed", strings.Repeat("a", MaxPassphraseBytes+1) + "\n", "", false},
		{"1025 bytes at the end of the input", strings.Repeat("a", MaxPassphraseBytes+1), "", false},
		{"1026 bytes and a line feed", strings.Repeat("a", MaxPassphraseBytes+2) + "\n", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := readOne(t, strings.NewReader(c.in))
			if !c.ok {
				if got != nil {
					t.Errorf("a value came with an error: %d bytes", len(got))
				}
				wantRefusal(t, err, ErrPassphrase, "passphrase")
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if string(got) != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestReaderSourceReadsAtMostTheLimitPlusTwoBytesOfALongLine(t *testing.T) {
	for _, size := range []int{MaxPassphraseBytes + 2, MaxPassphraseBytes + 3, 5000, 1 << 20} {
		cr := &countReader{r: bytes.NewReader(bytes.Repeat([]byte("a"), size))}
		got, err := readOne(t, cr)
		if got != nil {
			t.Errorf("%d bytes: a value came with the error", size)
		}
		wantRefusal(t, err, ErrPassphrase, "passphrase")
		if cr.n > MaxPassphraseBytes+2 {
			t.Errorf("%d bytes of input: %d bytes were read, more than %d", size, cr.n, MaxPassphraseBytes+2)
		}
	}
}

func TestReaderSourceReadsNoByteAfterTheLineFeedAndTwoCallsGiveTwoLines(t *testing.T) {
	first, second := strings.Repeat("a", 20), strings.Repeat("b", 21)
	cr := &countReader{r: strings.NewReader(first + "\r\n" + second + "\nthird")}
	src := ReaderSource(cr)
	ctx := context.Background()
	got1, err := src.Passphrase(ctx, Purpose{Label: "A", File: FileX509})
	if err != nil || string(got1) != first {
		t.Fatalf("first: %q, %v", got1, err)
	}
	if cr.n != len(first)+2 {
		t.Errorf("the first call read %d bytes, want %d (up to and including its line feed)", cr.n, len(first)+2)
	}
	got2, err := src.Passphrase(ctx, Purpose{Label: "A", File: FileOpenPGP})
	if err != nil || string(got2) != second {
		t.Fatalf("second: %q, %v", got2, err)
	}
	if cr.n != len(first)+2+len(second)+1 {
		t.Errorf("the second call read up to %d bytes, want %d", cr.n, len(first)+2+len(second)+1)
	}
	// the third line has fewer than 15 characters: refused, but it is read to its end
	if _, err := src.Passphrase(ctx, Purpose{Label: "B", File: FileX509}); !errors.Is(err, ErrPassphrase) {
		t.Errorf("third: %v", err)
	}
	// the input is spent
	if _, err := src.Passphrase(ctx, Purpose{Label: "B", File: FileOpenPGP}); !errors.Is(err, ErrPassphrase) {
		t.Errorf("fourth: %v", err)
	}
}

func TestReaderSourceIgnoresThePurposeAndNeverClosesTheReader(t *testing.T) {
	cr := &countReader{r: strings.NewReader(strings.Repeat("a", 20) + "\n" + strings.Repeat("b", 20) + "\n")}
	src := ReaderSource(cr)
	for _, p := range []Purpose{{Label: "Z", File: FileRemoval}, {}} {
		if _, err := src.Passphrase(context.Background(), p); err != nil {
			t.Fatalf("%+v: %v", p, err)
		}
	}
	if cr.closed {
		t.Error("the reader was closed")
	}
}

func TestReaderSourceThroughIotestReaders(t *testing.T) {
	line := strings.Repeat("q", 24)
	data := line + "\r\n"
	t.Run("one byte at a time", func(t *testing.T) {
		got, err := readOne(t, iotest.OneByteReader(strings.NewReader(data)))
		if err != nil || string(got) != line {
			t.Fatalf("%q, %v", got, err)
		}
	})
	t.Run("data and the end in the same read", func(t *testing.T) {
		got, err := readOne(t, iotest.DataErrReader(strings.NewReader(line)))
		if err != nil || string(got) != line {
			t.Fatalf("%q, %v", got, err)
		}
	})
	t.Run("half reads", func(t *testing.T) {
		got, err := readOne(t, iotest.HalfReader(strings.NewReader(data)))
		if err != nil || string(got) != line {
			t.Fatalf("%q, %v", got, err)
		}
	})
	t.Run("a reader that always fails wraps its error in ErrPassphrase", func(t *testing.T) {
		boom := errors.New("the reader failed")
		got, err := readOne(t, iotest.ErrReader(boom))
		if got != nil {
			t.Error("a value came with the error")
		}
		wantRefusal(t, err, ErrPassphrase, "passphrase")
		if !errors.Is(err, boom) {
			t.Errorf("the error of the reader is not wrapped: %v", err)
		}
	})
	t.Run("a reader that times out after one read", func(t *testing.T) {
		got, err := readOne(t, iotest.TimeoutReader(strings.NewReader(data)))
		if got != nil {
			t.Error("a value came with the error")
		}
		wantRefusal(t, err, ErrPassphrase, "passphrase")
		if !errors.Is(err, iotest.ErrTimeout) {
			t.Errorf("the timeout is not wrapped: %v", err)
		}
	})
	t.Run("a reader that fails after part of a line", func(t *testing.T) {
		boom := errors.New("cut")
		r := io.MultiReader(strings.NewReader(line), iotest.ErrReader(boom))
		got, err := readOne(t, r)
		if got != nil {
			t.Error("a value came with the error")
		}
		wantRefusal(t, err, ErrPassphrase, "passphrase")
		if !errors.Is(err, boom) {
			t.Errorf("not wrapped: %v", err)
		}
	})
}

// emptyReader gives nothing and no error, for ever, and counts the reads.
type emptyReader struct{ reads int }

func (e *emptyReader) Read([]byte) (int, error) { e.reads++; return 0, nil }

func TestReaderSourceGivesUpOnAReaderThatGivesNothing(t *testing.T) {
	r := &emptyReader{}
	got, err := readOne(t, r)
	if got != nil {
		t.Error("a value came")
	}
	wantRefusal(t, err, ErrPassphrase, "passphrase")
	if r.reads == 0 || r.reads > 1000 {
		t.Errorf("%d reads", r.reads)
	}
}

func TestReaderSourceWithANilReaderOrANilSourceIsErrPassphrase(t *testing.T) {
	got, err := ReaderSource(nil).Passphrase(context.Background(), Purpose{})
	if got != nil {
		t.Error("a value came")
	}
	wantRefusal(t, err, ErrPassphrase, "passphrase")
	var typedNil *readerSource
	got, err = typedNil.Passphrase(context.Background(), Purpose{})
	if got != nil {
		t.Error("a value came")
	}
	wantRefusal(t, err, ErrPassphrase, "passphrase")
}

func TestReaderSourceWithACancelledContextReadsNothing(t *testing.T) {
	cr := &countReader{r: strings.NewReader(strings.Repeat("a", 20) + "\n")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := ReaderSource(cr).Passphrase(ctx, Purpose{})
	if got != nil {
		t.Error("a value came")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("the error is %v", err)
	}
	if cr.n != 0 {
		t.Errorf("%d bytes were read", cr.n)
	}
	//nolint:staticcheck // a nil context is the case under test
	if _, err := ReaderSource(cr).Passphrase(nil, Purpose{}); !errors.Is(err, ErrParams) {
		t.Errorf("a nil context: %v", err)
	}
	if cr.n != 0 {
		t.Errorf("%d bytes were read for a nil context", cr.n)
	}
}

func TestReaderSourceErrorsHoldNoPartOfTheLine(t *testing.T) {
	for name, in := range map[string]string{
		"short":           "hunter2-part\n",
		"control":         "hunter2-secret-words-here\x00\n",
		"invalid":         "hunter2-secret-words-here\xff\n",
		"too long":        strings.Repeat("hunter2", 400) + "\n",
		"too long no end": strings.Repeat("hunter2", 400),
	} {
		_, err := readOne(t, strings.NewReader(in))
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		text := fmt.Sprintf("%v|%+v|%#v|%q", err, err, err, err)
		if strings.Contains(text, "hunter") || strings.Contains(text, "\x00") || strings.Contains(text, "\xff") {
			t.Errorf("%s: the error holds a part of the line: %s", name, text)
		}
	}
}

func TestReaderSourceGivesAFreshSliceThatIsNotClearedBehindTheCaller(t *testing.T) {
	line := strings.Repeat("k", 20)
	src := ReaderSource(strings.NewReader(line + "\n" + line + "\n"))
	a, err := src.Passphrase(context.Background(), Purpose{})
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != line {
		t.Fatalf("the slice was cleared or changed: %q", a)
	}
	for i := range a {
		a[i] = 'x'
	}
	b, err := src.Passphrase(context.Background(), Purpose{})
	if err != nil || string(b) != line {
		t.Fatalf("%q, %v", b, err)
	}
	if &a[0] == &b[0] {
		t.Error("two calls gave the same memory")
	}
}

func TestReaderSourceReadsALineFromAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Skipf("no pipe: %v", err)
	}
	defer func() { _ = r.Close() }()
	line := strings.Repeat("w", 30)
	if _, err := w.WriteString(line + "\nrest\n"); err != nil { // fits in the buffer of the pipe
		t.Fatal(err)
	}
	got, err := readOne(t, r)
	if err != nil || string(got) != line {
		t.Errorf("%q, %v", got, err)
	}
	// the reader was not closed by the source: a write end can still be closed, and a read can follow
	_ = w.Close()
	rest := make([]byte, 5)
	if _, err := io.ReadFull(r, rest); err != nil || string(rest) != "rest\n" {
		t.Errorf("the pipe after the call: %q, %v", rest, err)
	}
}

func TestReaderSourceSeveralGoroutinesGetDifferentLines(t *testing.T) {
	const n = 8
	var in strings.Builder
	want := map[string]bool{}
	for i := range n {
		l := fmt.Sprintf("line number %02d of the descriptor", i)
		want[l] = true
		in.WriteString(l + "\n")
	}
	src := ReaderSource(strings.NewReader(in.String()))
	var wg sync.WaitGroup
	got := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := src.Passphrase(context.Background(), Purpose{Label: "A", File: FileX509})
			got[i], errs[i] = string(b), err
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if !want[got[i]] {
			t.Errorf("goroutine %d got %q, which is not a whole line", i, got[i])
		}
		delete(want, got[i])
	}
	if len(want) != 0 {
		t.Errorf("lines that nobody got: %v", want)
	}
}
