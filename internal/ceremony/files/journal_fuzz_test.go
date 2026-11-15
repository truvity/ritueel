package files_test

import (
	"bytes"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

func seedLines(f *testing.F, good string) {
	f.Add([]byte(good))
	f.Add([]byte(good[:len(good)/2]))
	f.Add([]byte(good + "\n"))
	f.Add([]byte(" " + good))
	f.Add([]byte(strings.Replace(good, `":"`, `": "`, 1)))
	f.Add([]byte(strings.Replace(good, `"at"`, `"zz"`, 1)))
	f.Add([]byte(strings.Replace(good, `:"`, `:null,"x":"`, 1)))
	f.Add([]byte(strings.TrimSuffix(good, "}") + `,"at":"x"}`))
	f.Add([]byte(strings.ToUpper(good)))
	f.Add([]byte(`{"n":1.5}`))
	f.Add([]byte(`{"n":-0}`))
	f.Add([]byte(`{"n":9007199254740993}`))
	f.Add([]byte("\xef\xbb\xbf" + good))
	f.Add([]byte(strings.Repeat("[", 5000)))
	f.Add([]byte(strings.Repeat("x", 4097)))
	f.Add([]byte{})
}

func FuzzReadBirthLine(f *testing.F) {
	seedLines(f, goldenBirth)
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := files.ReadBirthLine(data)
		if err != nil {
			if l != nil {
				t.Fatal("a line comes with its error")
			}
			refused(t, err)
			return
		}
		// An accepted line is the line that Canonical writes: nothing else is a line of the journal.
		canon, err := l.Canonical()
		if err != nil {
			t.Fatalf("a line that was read cannot be written: %v", err)
		}
		if !bytes.Equal(canon, data) {
			t.Fatalf("an accepted line is not its canonical form:\n%q\n%q", data, canon)
		}
		if len(data) > files.MaxJournalLine || bytes.ContainsAny(data, "\r\n") {
			t.Fatalf("accepted a line of %d bytes with a line break", len(data))
		}
		back, err := files.ReadBirthLine(canon)
		if err != nil || *back != *l {
			t.Fatalf("the canonical form is not read back to the same line: %v", err)
		}
		for i := 0; i < len(data); i++ {
			if data[i] < 0x20 || data[i] > 0x7e {
				t.Fatalf("an accepted line holds the byte %#x", data[i])
			}
		}
		if len(l.Label) != 1 || l.Label[0] < 'A' || l.Label[0] > 'Z' || len(l.PublicKeySHA256) != 64 || len(l.Place) > 255 {
			t.Fatalf("an accepted line breaks a rule of the page: %+v", l)
		}
	})
}

func FuzzReadSignatureLine(f *testing.F) {
	seedLines(f, goldenSig)
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := files.ReadSignatureLine(data)
		if err != nil {
			if l != nil {
				t.Fatal("a line comes with its error")
			}
			refused(t, err)
			return
		}
		canon, err := l.Canonical()
		if err != nil {
			t.Fatalf("a line that was read cannot be written: %v", err)
		}
		if !bytes.Equal(canon, data) {
			t.Fatalf("an accepted line is not its canonical form:\n%q\n%q", data, canon)
		}
		if len(data) > files.MaxJournalLine || bytes.ContainsAny(data, "\r\n") {
			t.Fatalf("accepted a line of %d bytes with a line break", len(data))
		}
		back, err := files.ReadSignatureLine(canon)
		if err != nil || *back != *l {
			t.Fatalf("the canonical form is not read back to the same line: %v", err)
		}
		if l.N < 1 || l.N > files.MaxJournalLines || (len(l.Key) != 64 && len(l.Key) != 40) || len(l.SignatureSHA256) != 64 {
			t.Fatalf("an accepted line breaks a rule of the page: %+v", l)
		}
	})
}
