package ceremony

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/ceremony/files"
)

func TestCheckTranscriptTakesAPlainText(t *testing.T) {
	for name, in := range map[string]string{
		"one line":                  "plan\n",
		"an empty line":             "\n",
		"empty lines":               "\n\n\n",
		"printable ASCII":           " !\"#$%&'()*+,-./0123456789:;<=>?@AZ[\\]^_`az{|}~\n",
		"a letter with an accent":   "caf\u00e9\n",
		"another script":            "\u0416\u0438\n",
		"a character above U+FFFF":  "\U0001f600\n",
		"a no-break space":          "a\u00a0b\n",
		"the replacement character": "\ufffd\n",
		"4,096 lines":               strings.Repeat("a\n", 4096),
		"a line of 1,024 bytes":     strings.Repeat("a", 1024) + "\n",
		"a line of 1,024 bytes of a two-byte letter": strings.Repeat("\u00e9", 512) + "\n",
		"1 MiB": strings.Repeat(strings.Repeat("a", 1023)+"\n", 1024),
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkTranscript([]byte(in)); err != nil {
				t.Errorf("checkTranscript = %v", err)
			}
		})
	}
}

func TestCheckTranscriptRefusesWhatABreaksThePage(t *testing.T) {
	long := strings.Repeat("a", 1025) + "\n"
	for name, in := range map[string][]byte{
		"nothing":                   nil,
		"an empty text":             {},
		"no line feed at the end":   []byte("plan"),
		"no line feed after a line": []byte("a\nb"),
		"a carriage return":         []byte("a\r\n"),
		"a lone carriage return":    []byte("a\rb\n"),
		"a tab":                     []byte("a\tb\n"),
		"a null":                    []byte("a\x00b\n"),
		"a bell":                    []byte("a\x07b\n"),
		"a backspace":               []byte("a\x08b\n"),
		"a form feed":               []byte("a\x0cb\n"),
		"a vertical tab":            []byte("a\x0bb\n"),
		"an escape":                 []byte("a\x1bb\n"),
		"a terminal sequence":       []byte("\x1b[31mred\x1b[0m\n"),
		"a delete":                  []byte("a\x7fb\n"),
		"the first control of the range U+0080 to U+009F": []byte("a\u0080b\n"),
		"a next-line control":                             []byte("a\u0085b\n"),
		"the last control of the range U+0080 to U+009F":  []byte("a\u009fb\n"),
		"a left-to-right mark":                            []byte("a\u200eb\n"),
		"a right-to-left override":                        []byte("a\u202eb\n"),
		"a bidirectional isolate":                         []byte("a\u2066b\n"),
		"a zero-width space":                              []byte("a\u200bb\n"),
		"a zero-width joiner":                             []byte("a\u200db\n"),
		"a word joiner":                                   []byte("a\u2060b\n"),
		"a soft hyphen":                                   []byte("a\u00adb\n"),
		"a byte order mark":                               []byte("\ufeffa\n"),
		"a tag character":                                 []byte("a\U000e0041b\n"),
		"a line separator":                                []byte("a\u2028b\n"),
		"a paragraph separator":                           []byte("a\u2029b\n"),
		"not UTF-8":                                       []byte("a\xffb\n"),
		"a truncated UTF-8 sequence":                      []byte("a\xe2\x80\n"),
		"an overlong encoding":                            []byte("a\xc0\xafb\n"),
		"a surrogate":                                     []byte("a\xed\xa0\x80b\n"),
		"a line of 1,025 bytes":                           []byte(long),
		"a line of 1,025 bytes of letters":                []byte(strings.Repeat("\u00e9", 512) + "a\n"),
		"4,097 lines":                                     []byte(strings.Repeat("a\n", 4097)),
		"1 MiB and one byte":                              []byte(strings.Repeat(strings.Repeat("a", 1023)+"\n", 1024) + "\n"),
		"a long line after short ones":                    []byte("a\nb\n" + long),
	} {
		t.Run(name, func(t *testing.T) {
			err := checkTranscript(in)
			if err == nil {
				t.Fatal("checkTranscript accepted it")
			}
			text := err.Error()
			if len(text) > 200 {
				t.Errorf("the error is %d bytes long", len(text))
			}
			for i := 0; i < len(text); i++ {
				if text[i] < 0x20 || text[i] > 0x7e {
					t.Errorf("the error holds the byte %#x", text[i])
					break
				}
			}
			if len(in) > 8 && strings.Contains(text, string(in[:8])) && !strings.HasPrefix(string(in), "\n") {
				t.Errorf("the error holds the text: %q", text)
			}
		})
	}
}

// The width of a line is counted in bytes of the line and not in characters, and a refusal names the
// line that is too long.
func TestCheckTranscriptNamesTheLine(t *testing.T) {
	err := checkTranscript([]byte("a\nb\n" + strings.Repeat("a", 1025) + "\n"))
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("err = %v, want one that names line 3", err)
	}
	err = checkTranscript([]byte("a\nb\x1bc\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "U+001B") {
		t.Errorf("err = %v, want one that names line 2 and U+001B", err)
	}
}

// What a Console prints is always a transcript that the rules accept.
func TestWhatAConsolePrintsPassesTheRulesOfTheTranscript(t *testing.T) {
	for _, s := range []string{"", "plain", "\x1b[31m", "\r\n\t", "\u202e", "\u2028", "\ufeff", "\U000e0041", "\xff", strings.Repeat("\u00e9", 3000), "\u0085"} {
		c := NewConsole(io.Discard, io.Discard)
		c.Out("%s", s)
		c.Err("%s|", s)
		if _, err := c.Transcript(); err != nil {
			t.Errorf("Transcript of %q: %v", s, err)
		}
	}
}

func FuzzCheckTranscript(f *testing.F) {
	for _, s := range []string{
		"", "\n", "plan\n", "a\r\n", "\x1b[31m\n", "a\u202eb\n", "a\xffb\n", "a\u2028b\n", "caf\u00e9\n",
		strings.Repeat("a", 1025) + "\n", strings.Repeat("a\n", 4097), "\ufeff\n", "a\u200bb\n", "x\ty\n", "no newline",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		err := checkTranscript(b)
		if err != nil {
			text := err.Error()
			if len(text) > 300 {
				t.Fatalf("error of %d bytes", len(text))
			}
			for i := 0; i < len(text); i++ {
				if text[i] < 0x20 || text[i] > 0x7e {
					t.Fatalf("error text holds the byte %#x", text[i])
				}
			}
			return
		}
		// An accepted text is exactly what the page allows: checked here by another loop.
		if len(b) == 0 || len(b) > MaxTranscriptBytes || !utf8.Valid(b) || b[len(b)-1] != '\n' {
			t.Fatalf("accepted a text of %d bytes that breaks size, UTF-8 or the final line feed", len(b))
		}
		lines := bytes.Split(b[:len(b)-1], []byte{'\n'})
		if len(lines) > MaxTranscriptLines {
			t.Fatalf("accepted %d lines", len(lines))
		}
		for _, l := range lines {
			if len(l) > MaxTranscriptLineBytes {
				t.Fatalf("accepted a line of %d bytes", len(l))
			}
			for _, r := range string(l) {
				if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' || r == '\r' || r == '\t' || r == 0x1b {
					t.Fatalf("accepted U+%04X", r)
				}
			}
		}
	})
}

// Whatever a caller prints, the transcript of a Console is one line for each call, in printable
// ASCII, and the rules of the transcript accept it.
func FuzzConsoleTranscript(f *testing.F) {
	for _, s := range []string{"", "plain", "a\nb", "\x1b[2J", "\u202e", "\xff\xfe", strings.Repeat("x", 5000), "%d%s%v", "\u0085\u2028"} {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, format, arg string) {
		var out bytes.Buffer
		c := NewConsole(io.Discard, &out)
		c.Out(format, arg)
		c.Out("%s", arg)
		got, err := c.Transcript()
		if err != nil {
			t.Fatalf("Transcript: %v", err)
		}
		if !bytes.Equal(got, out.Bytes()) {
			t.Fatal("the transcript is not what was printed")
		}
		if n := bytes.Count(got, []byte{'\n'}); n != 2 {
			t.Fatalf("two calls made %d lines", n)
		}
		for _, c := range got {
			if c != '\n' && (c < 0x20 || c > 0x7e) {
				t.Fatalf("byte %#x in the transcript", c)
			}
		}
		for _, l := range bytes.Split(got[:len(got)-1], []byte{'\n'}) {
			if len(l) > MaxTranscriptLineBytes {
				t.Fatalf("a line of %d bytes", len(l))
			}
		}
		if err := checkTranscript(got); err != nil {
			t.Fatalf("checkTranscript: %v", err)
		}
	})
}

func TestJournalLinesSplitsOnlyAWholeJournal(t *testing.T) {
	two := "{\"a\":1}\n{\"b\":2}\n"
	cases := []struct {
		name string
		in   string
		ok   bool
		n    int
	}{
		{"nothing", "", true, 0},
		{"one line", "x\n", true, 1},
		{"two lines", two, true, 2},
		{"a half last line", "x\ny", false, 0},
		{"only a half line", "x", false, 0},
		{"a half last line of two characters", "x\nyy", false, 0},
		{"a half line of two characters", "xx", false, 0},
		{"a whole line without its line feed", `{"a":1}`, false, 0},
		{"an empty line", "\n", false, 0},
		{"an empty line between two", "x\n\ny\n", false, 0},
		{"an empty line at the end", "x\n\n", false, 0},
		{"112 lines", strings.Repeat("x\n", 112), true, 112},
		{"113 lines", strings.Repeat("x\n", 113), false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines, ok := journalLines([]byte(c.in))
			if ok != c.ok || len(lines) != c.n {
				t.Errorf("journalLines = %d lines, %v; want %d, %v", len(lines), ok, c.n, c.ok)
			}
			if !ok && lines != nil {
				t.Error("a refused journal came with lines")
			}
		})
	}
}

func FuzzJournalLines(f *testing.F) {
	for _, s := range []string{"", "x\n", "x\ny\n", "x", "\n", "x\n\n", strings.Repeat("a\n", 113), "a\r\nb\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		lines, ok := journalLines(b)
		if !ok {
			if lines != nil {
				t.Fatal("lines with a refusal")
			}
			return
		}
		if len(lines) > MaxJournalLines {
			t.Fatalf("%d lines", len(lines))
		}
		var back []byte
		for _, l := range lines {
			if len(l) == 0 || bytes.IndexByte(l, '\n') >= 0 {
				t.Fatalf("a line %q", l)
			}
			back = append(back, l...)
			back = append(back, '\n')
		}
		if !bytes.Equal(back, b) {
			t.Fatalf("the lines do not make the journal: %q and %q", back, b)
		}
	})
}

// The judge of a journal line that Append uses: an accepted line is the canonical form of the line
// that the reader read, for each of the two journals.
func FuzzJournalAppendCheck(f *testing.F) {
	birth, _ := (&files.BirthLine{At: "2026-11-14T10:00:00Z", Label: "A", Purpose: "x509-root", Store: "software", Place: "A.x509.key.pem", PublicKeySHA256: strings.Repeat("a", 64)}).Canonical()
	sig, _ := (&files.SignatureLine{At: "2026-11-14T10:00:00Z", N: 1, Kind: "root-list", Key: strings.Repeat("a", 64), SignatureSHA256: strings.Repeat("b", 64)}).Canonical()
	for _, s := range [][]byte{birth, sig, nil, []byte("{}"), append(append([]byte{}, birth...), '\n'), []byte(strings.Replace(string(birth), `"label":`, `"label": `, 1))} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, line []byte, births bool) {
		j := &fileJournal{kind: kindSignatures, op: "signatures.jsonl"}
		if births {
			j = &fileJournal{kind: kindBirths, op: "births.jsonl"}
		}
		label, err := j.check(line)
		if err != nil {
			if label != "" {
				t.Fatal("a label with an error")
			}
			return
		}
		if bytes.ContainsAny(line, "\r\n") || len(line) > files.MaxJournalLine {
			t.Fatalf("accepted a line of %d bytes with a line break", len(line))
		}
		var back []byte
		if births {
			l, err := files.ReadBirthLine(line)
			if err != nil {
				t.Fatalf("accepted a line that the reader refuses: %v", err)
			}
			if label != l.Label {
				t.Fatalf("label %q for %q", label, l.Label)
			}
			back, err = l.Canonical()
			if err != nil {
				t.Fatal(err)
			}
		} else {
			l, err := files.ReadSignatureLine(line)
			if err != nil || l.N != 1 || label != "" {
				t.Fatalf("accepted a signature line that is not number 1: %v %v", l, err)
			}
			back, err = l.Canonical()
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(back, line) {
			t.Fatalf("accepted a line that is not canonical: %q, canonical %q", line, back)
		}
	})
}
