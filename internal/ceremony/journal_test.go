package ceremony_test

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// started makes a ceremony folder in the state "started" and returns its trace.
func started(t *testing.T) (*bundle, *flow) {
	t.Helper()
	b := newBundle(t)
	fl := newFlow(t, b, newSpec(name1, 1, ""))
	fl.must("start")
	return b, fl
}

func TestOneLineIsOneWriteAndOneFlush(t *testing.T) {
	b, fl := started(t)
	for _, c := range []struct {
		journal ceremony.Journal
		file    string
		line    []byte
	}{
		{fl.tr.Births(), "births.jsonl", birthBytes(t, "A", rep('a'))},
		{fl.tr.Births(), "births.jsonl", birthBytes(t, "B", rep('b'))},
		{fl.tr.Signatures(), "signatures.jsonl", sigBytes(t, 1, "root-certificate", rep('a'))},
		{fl.tr.Signatures(), "signatures.jsonl", sigBytes(t, 2, "root-removal", rep('a'))},
	} {
		path := "history/" + name1 + "/" + c.file
		n := b.r.mark()
		if err := c.journal.Append(c.line); err != nil {
			t.Fatalf("Append to %s: %v", c.file, err)
		}
		got := b.r.since(n)
		want := []string{"write " + path, "sync-file " + path}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("one line of %s made the calls %v, want %v", c.file, got, want)
		}
	}
	births := string(b.read("history", name1, "births.jsonl"))
	want := string(birthBytes(t, "A", rep('a'))) + "\n" + string(birthBytes(t, "B", rep('b'))) + "\n"
	if births != want {
		t.Errorf("births.jsonl is %q, want %q", births, want)
	}
	// The same Journal is returned each time.
	if fl.tr.Births() != fl.tr.Births() || fl.tr.Signatures() != fl.tr.Signatures() {
		t.Error("Births or Signatures returns a new value at each call")
	}
}

// A line that its reader refuses, or that is not the canonical form of what the reader read,
// writes nothing and leaves the journal usable.
func TestARefusedLineWritesNothingAndTheJournalStaysUsable(t *testing.T) {
	good := birthBytes(t, "A", rep('a'))
	member := func(edit func(string) string) []byte { return []byte(edit(string(good))) }
	cases := map[string][]byte{
		"empty":                    nil,
		"a line feed":              []byte("\n"),
		"the line and a line feed": append(append([]byte{}, good...), '\n'),
		"a line feed inside":       member(func(s string) string { return strings.Replace(s, `"label"`, "\n\"label\"", 1) }),
		"a carriage return":        append(append([]byte{}, good...), '\r'),
		"spaces around":            append(append([]byte(" "), good...), ' '),
		"a space after a colon":    member(func(s string) string { return strings.Replace(s, `"label":`, `"label": `, 1) }),
		"members in another order": []byte(`{"label":"A",` + string(good[1:])),
		"a member twice": member(func(s string) string {
			return strings.Replace(s, `"store":"software"`, `"store":"software","store":"software"`, 1)
		}),
		"an extra member":            member(func(s string) string { return strings.Replace(s, `{"at"`, `{"zz":"1","at"`, 1) }),
		"a member missing":           member(func(s string) string { return strings.Replace(s, `,"store":"software"`, ``, 1) }),
		"a member null":              member(func(s string) string { return strings.Replace(s, `"store":"software"`, `"store":null`, 1) }),
		"a member of the wrong type": member(func(s string) string { return strings.Replace(s, `"label":"A"`, `"label":1`, 1) }),
		"a lower-case label":         member(func(s string) string { return strings.Replace(s, `"label":"A"`, `"label":"a"`, 1) }),
		"a label of two letters":     member(func(s string) string { return strings.Replace(s, `"label":"A"`, `"label":"AB"`, 1) }),
		"a time with a fraction":     member(func(s string) string { return strings.Replace(s, `10:00:00Z`, `10:00:00.5Z`, 1) }),
		"a digest in capitals":       member(func(s string) string { return strings.Replace(s, rep('a'), strings.ToUpper(rep('a')), 1) }),
		"a digest of 63 digits":      member(func(s string) string { return strings.Replace(s, rep('a'), rep('a')[:63], 1) }),
		"an escape in the place":     member(func(s string) string { return strings.Replace(s, `A.x509.key.pem`, `A\u001b[31m`, 1) }),
		"a place of 256 bytes":       member(func(s string) string { return strings.Replace(s, `A.x509.key.pem`, strings.Repeat("p", 256), 1) }),
		"not UTF-8":                  append(append([]byte(`{"at":"`), 0xff, 0xfe), []byte(`"}`)...),
		"not JSON":                   []byte("birth"),
		"a signature line":           sigBytes(t, 1, "root-certificate", rep('a')),
		"a line of 4097 bytes":       []byte(`{"at":"` + strings.Repeat("a", 4097) + `"}`),
		"deep nesting":               []byte(strings.Repeat("[", 5000)),
		"an array":                   []byte(`[]`),
		"a number":                   []byte(`1`),
		"a byte order mark":          append([]byte("\xef\xbb\xbf"), good...),
		"a number with a fraction":   []byte(`{"n":1.5}`),
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			b, fl := started(t)
			before := b.read("history", name1, "births.jsonl")
			mark := b.r.mark()
			keep := append([]byte(nil), line...)
			err := fl.tr.Births().Append(line)
			wantKind(t, err, ceremony.ErrInvalidInput)
			if errors.Is(err, ceremony.ErrFolderStopped) || errors.Is(err, fsx.ErrStopped) {
				t.Error("a refused line stopped the folder")
			}
			if !bytes.Equal(keep, line) {
				t.Error("Append changed the caller's bytes")
			}
			if got := b.r.since(mark); len(got) != 0 {
				t.Errorf("a refused line reached the file system: %v", got)
			}
			if got := b.read("history", name1, "births.jsonl"); !bytes.Equal(got, before) {
				t.Errorf("births.jsonl changed: %q", got)
			}
			if err := fl.tr.Births().Append(good); err != nil {
				t.Errorf("the journal is not usable after a refused line: %v", err)
			}
		})
	}
}

func TestABirthLabelTwiceIsRefused(t *testing.T) {
	b, fl := started(t)
	if err := fl.tr.Births().Append(birthBytes(t, "A", rep('a'))); err != nil {
		t.Fatal(err)
	}
	// The same label with other members is the same key born twice.
	other, err := (&files.BirthLine{At: "2026-11-14T10:00:05Z", Label: "A", Purpose: "x509-root", Store: "software", Place: "other.pem", PublicKeySHA256: rep('c')}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	mark := b.r.mark()
	wantKind(t, fl.tr.Births().Append(other), ceremony.ErrInvalidInput)
	wantKind(t, fl.tr.Births().Append(birthBytes(t, "A", rep('a'))), ceremony.ErrInvalidInput)
	if got := b.r.since(mark); len(got) != 0 {
		t.Errorf("a label twice reached the file system: %v", got)
	}
	if err := fl.tr.Births().Append(birthBytes(t, "B", rep('b'))); err != nil {
		t.Errorf("another label after a refusal: %v", err)
	}
	if lines := strings.Count(string(b.read("history", name1, "births.jsonl")), "\n"); lines != 2 {
		t.Errorf("births.jsonl has %d lines, want 2", lines)
	}
}

func TestEveryLabelOfAToZIsBornOnce(t *testing.T) {
	_, fl := started(t)
	for c := 'A'; c <= 'Z'; c++ {
		if err := fl.tr.Births().Append(birthBytes(t, string(c), sum([]byte{byte(c)}))); err != nil {
			t.Fatalf("label %c: %v", c, err)
		}
	}
	for c := 'A'; c <= 'Z'; c++ {
		wantKind(t, fl.tr.Births().Append(birthBytes(t, string(c), rep('a'))), ceremony.ErrInvalidInput)
	}
}

// The signature lines are numbered from 1 without a gap and without a repeat.
func TestSignatureNumbersAreTheNextOne(t *testing.T) {
	b, fl := started(t)
	sig := func(n int64) []byte { return sigBytes(t, n, "root-certificate", rep('a')) }
	for _, n := range []int64{2, 3, 100} {
		wantKind(t, fl.tr.Signatures().Append(sig(n)), ceremony.ErrInvalidInput)
	}
	if err := fl.tr.Signatures().Append(sig(1)); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int64{1, 3, 0} {
		bad := rawSigBytes(t, n)
		wantKind(t, fl.tr.Signatures().Append(bad), ceremony.ErrInvalidInput)
	}
	if err := fl.tr.Signatures().Append(sig(2)); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(b.read("history", name1, "signatures.jsonl")), "\n"); lines != 2 {
		t.Errorf("signatures.jsonl has %d lines, want 2", lines)
	}
	// A line of the other journal, and a bad kind, are refused as well.
	wantKind(t, fl.tr.Signatures().Append(birthBytes(t, "A", rep('a'))), ceremony.ErrInvalidInput)
	wantKind(t, fl.tr.Signatures().Append([]byte(strings.Replace(string(sig(3)), "root-certificate", "something", 1))), ceremony.ErrInvalidInput)
	wantKind(t, fl.tr.Births().Append(sig(3)), ceremony.ErrInvalidInput)
}

// A journal takes 4*26+8 = 112 lines and no more.
func TestAJournalTakesAtMost112Lines(t *testing.T) {
	if ceremony.MaxJournalLines != 112 || files.MaxJournalLines != 112 {
		t.Fatalf("the limits are %d and %d, want 112 (4 for each of 26 labels and 8 more)", ceremony.MaxJournalLines, files.MaxJournalLines)
	}
	b, fl := started(t)
	for n := int64(1); n <= 112; n++ {
		if err := fl.tr.Signatures().Append(sigBytes(t, n, "root-list", rep('a'))); err != nil {
			t.Fatalf("line %d: %v", n, err)
		}
	}
	mark := b.r.mark()
	err := fl.tr.Signatures().Append(rawSigBytes(t, 113))
	if err == nil {
		t.Fatal("the 113th line was written")
	}
	wantKind(t, err, ceremony.ErrInvalidInput)
	if got := b.r.since(mark); len(got) != 0 {
		t.Errorf("the 113th line reached the file system: %v", got)
	}
	if lines := strings.Count(string(b.read("history", name1, "signatures.jsonl")), "\n"); lines != 112 {
		t.Errorf("signatures.jsonl has %d lines", lines)
	}
	// A repeat of a line that fits is refused too, by the number and not by the size.
	wantKind(t, fl.tr.Signatures().Append(sigBytes(t, 112, "root-list", rep('a'))), ceremony.ErrInvalidInput)
}

func TestAJournalIsClosedByEnd(t *testing.T) {
	b, fl := started(t)
	if err := fl.tr.Births().Append(birthBytes(t, "A", rep('a'))); err != nil {
		t.Fatal(err)
	}
	if err := fl.f.End(); err != nil {
		t.Fatal(err)
	}
	before := tree(t, b.dir)
	mark := b.r.mark()
	for _, err := range []error{
		fl.tr.Births().Append(birthBytes(t, "B", rep('b'))),
		fl.tr.Signatures().Append(sigBytes(t, 1, "root-certificate", rep('a'))),
	} {
		wantKind(t, err, ceremony.ErrOutOfOrder)
		if errors.Is(err, ceremony.ErrFolderStopped) {
			t.Error("a line after End stopped the folder")
		}
	}
	if got := b.r.since(mark); len(got) != 0 {
		t.Errorf("a line after End reached the file system: %v", got)
	}
	sameTree(t, "Append after End", before, tree(t, b.dir))
	// The ceremony still goes on: the writer is not stopped.
	fl.con.Out("x")
	if err := fl.step("transcript"); err != nil {
		t.Errorf("WriteTranscript after a line that was refused: %v", err)
	}
}

// Two goroutines that start behind a closed channel and append the same label: one wins.
func TestTwoGoroutinesBornTheSameLabelOneWins(t *testing.T) {
	b, fl := started(t)
	line := birthBytes(t, "A", rep('a'))
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fl.tr.Births().Append(line)
		}()
	}
	close(start)
	wg.Wait()
	won := 0
	for _, err := range errs {
		if err == nil {
			won++
		} else {
			wantKind(t, err, ceremony.ErrInvalidInput)
		}
	}
	if won != 1 {
		t.Errorf("%d appends of one label succeeded, want 1", won)
	}
	if got := b.read("history", name1, "births.jsonl"); string(got) != string(line)+"\n" {
		t.Errorf("births.jsonl is %q", got)
	}
}

// Two goroutines that append numbered lines keep every line whole and the numbers in one order
// without a gap, whatever the order in which the goroutines run.
func TestTwoGoroutinesAppendNumberedLinesWholeAndInOrder(t *testing.T) {
	b, fl := started(t)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for n := int64(1); n <= 40; n++ {
				_ = fl.tr.Signatures().Append(sigBytes(t, n, "root-certificate", rep('a')))
			}
		}()
	}
	close(start)
	wg.Wait()
	data := b.read("history", name1, "signatures.jsonl")
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("signatures.jsonl does not end with a line feed: %q", data)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	for i, l := range lines {
		sl, err := files.ReadSignatureLine([]byte(l))
		if err != nil {
			t.Fatalf("line %d is not whole: %v: %q", i+1, err, l)
		}
		if sl.N != int64(i+1) {
			t.Fatalf("line %d has n=%d", i+1, sl.N)
		}
	}
	if len(lines) < 40 {
		t.Errorf("only %d of 40 numbered lines were written; the first goroutine alone writes all 40", len(lines))
	}
}

// A journal that a hand edit left with a half line, an empty line, a line that its reader refuses,
// a label twice or more than 112 lines is not a journal that a record lists. The refusal writes
// nothing and does not stop the folder: with the file put right, the record is written.
func TestRecordRefusesAJournalThatIsNotWhole(t *testing.T) {
	good := string(birthBytes(t, "A", rep('a'))) + "\n"
	sigLines := func(n int) string {
		var sb strings.Builder
		for i := 1; i <= n; i++ {
			sb.Write(rawSigBytes(t, int64(i)))
			sb.WriteByte('\n')
		}
		return sb.String()
	}
	cases := []struct {
		name, file, append string
	}{
		{"a half last line in the birth journal", "births.jsonl", `{"at":"2026-11-14T10:00:00Z","la`},
		{"a half last line in the journal of signatures", "signatures.jsonl", `{"at":"2026`},
		{"an empty line in the birth journal", "births.jsonl", "\n"},
		{"an empty line between two lines", "births.jsonl", "\n" + string(birthBytes(t, "B", rep('b'))) + "\n"},
		{"a line its reader refuses", "births.jsonl", "not a line\n"},
		{"a birth line that is not canonical", "births.jsonl", strings.Replace(string(birthBytes(t, "B", rep('b'))), `"label":`, `"label": `, 1) + "\n"},
		{"the same label twice", "births.jsonl", good},
		{"a birth line in the journal of signatures", "signatures.jsonl", good},
		{"a signature line that its reader refuses", "signatures.jsonl", "{}\n"},
		{"a fourth signature that the plan does not list", "signatures.jsonl", string(sigBytes(t, 4, "root-list", rep('a'))) + "\n"},
		{"a line with a carriage return", "births.jsonl", "x\r\n"},
		{"more than 112 lines", "signatures.jsonl", sigLines(113)},
		{"a signature that is not the next number", "signatures.jsonl", string(rawSigBytes(t, 7)) + "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newBundle(t)
			fl := newFlow(t, b, newSpec(name1, 1, ""))
			fl.must("end")
			path := b.path("history", name1, c.file)
			orig := b.read("history", name1, c.file)
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(c.append); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			err = fl.run("")
			if err == nil {
				t.Fatal("a record was written for a journal that is not whole")
			}
			wantKind(t, errors.Unwrap(err), ceremony.ErrDiskMismatch)
			if errors.Is(err, ceremony.ErrFolderStopped) {
				t.Error("the refusal stopped the folder")
			}
			if _, err := os.Lstat(b.path("history", name1, "record.json")); !os.IsNotExist(err) {
				t.Errorf("record.json exists after the refusal: %v", err)
			}
			if err := os.WriteFile(path, orig, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := fl.run(""); err != nil {
				t.Fatalf("the record after the journal was put right: %v", err)
			}
		})
	}
}

// A journal that was edited by hand to hold the right count of lines in the wrong order, or the
// right numbers with another kind or key than the plan has, is refused.
func TestRecordRefusesASignatureJournalThatDoesNotFollowThePlan(t *testing.T) {
	line := func(n int64, kind, key string) string { return string(sigBytes(t, n, kind, key)) + "\n" }
	cases := map[string]string{
		"the numbers out of order":   line(1, "root-certificate", rep('a')) + string(rawSigBytes(t, 3)) + "\n" + string(rawSigBytes(t, 2)) + "\n",
		"a number twice":             line(1, "root-certificate", rep('a')) + line(1, "root-removal", rep('a')) + line(3, "root-list", rep('a')),
		"the numbers from 2":         line(2, "root-certificate", rep('a')) + line(3, "root-removal", rep('a')) + line(4, "root-list", rep('a')),
		"another kind than the plan": line(1, "root-certificate", rep('a')) + line(2, "root-list", rep('a')) + line(3, "root-list", rep('a')),
		"another key than the plan":  line(1, "root-certificate", rep('a')) + line(2, "root-removal", rep('a')) + line(3, "root-list", rep('c')),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			fl := newFlow(t, b, newSpec(name1, 1, ""))
			fl.must("end")
			if err := os.WriteFile(b.path("history", name1, "signatures.jsonl"), []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			err := fl.run("")
			if err == nil {
				t.Fatal("a record was written")
			}
			wantKind(t, errors.Unwrap(err), ceremony.ErrDiskMismatch)
			if _, err := os.Lstat(b.path("history", name1, "record.json")); !os.IsNotExist(err) {
				t.Errorf("record.json exists: %v", err)
			}
		})
	}
}
