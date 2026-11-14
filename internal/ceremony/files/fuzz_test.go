package files_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/strictjson"
)

// refused checks the promise of every reader about its errors: a *VersionError, a *FormatError or
// an error that wraps ErrMalformed, with a text of printable ASCII that is not long.
func refused(t *testing.T, err error) {
	t.Helper()
	var ve *files.VersionError
	var fe *files.FormatError
	if !errors.As(err, &ve) && !errors.As(err, &fe) && !errors.Is(err, strictjson.ErrMalformed) {
		t.Fatalf("the error is %T and none of the three kinds: %v", err, err)
	}
	if text := err.Error(); !printableASCII(text) || len(text) > 2000 {
		t.Fatalf("the error text is %d bytes and holds a byte beyond printable ASCII: %.200q", len(text), text)
	}
}

func seedFiles(f *testing.F, docs ...map[string]any) {
	for _, m := range docs {
		b := encode(f, m, nil)
		f.Add(b)
		f.Add(b[:len(b)/2])
		f.Add(append([]byte(" "), b...))
	}
	f.Add([]byte(`{"version":2,"x":{}}`))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":1,"version":1}`))
	f.Add([]byte(`{"version":-0}`))
	f.Add([]byte(`{"version":1.5}`))
	f.Add([]byte(`{"version":1,"ceremony":null}`))
	f.Add([]byte("\xef\xbb\xbf{}"))
	f.Add([]byte(`{"version":1,"ceremony":"a` + string(rune(0x5c)) + `ud800"}`))
	f.Add([]byte(strings.Repeat("[", 20000)))
	f.Add([]byte{})
}

func FuzzReadRecord(f *testing.F) {
	seedFiles(f, applyDoc(), closeDoc(), declineDoc())
	if r, err := (&files.Record{Version: 1, Ceremony: "c", Command: "apply", Outcome: "completed", PlanSHA256: dg('1'),
		TranscriptSHA256: dg('3'), Wanted: []files.FileRef{{Path: "ritueel.yaml", SHA256: dg('4')}}}).Canonical(); err == nil {
		f.Add(r)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := files.ReadRecord(data)
		if err != nil {
			if r != nil {
				t.Fatal("a record comes with an error")
			}
			refused(t, err)
			return
		}
		// What was read can be written, and what is written is read back to the same bytes.
		first, err := r.Canonical()
		if err != nil {
			t.Fatalf("a record that was read cannot be written: %v", err)
		}
		back, err := files.ReadRecord(first)
		if err != nil {
			t.Fatalf("the canonical bytes are not read back: %v\n%s", err, first)
		}
		second, err := back.Canonical()
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("the canonical bytes change on the second turn: %v\n%s\n%s", err, first, second)
		}
	})
}

func FuzzReadAttempt(f *testing.F) {
	seedFiles(f, attemptDoc())
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := files.ReadAttempt(data)
		if err != nil {
			if a != nil {
				t.Fatal("an attempt comes with an error")
			}
			refused(t, err)
			return
		}
		first, err := a.Canonical()
		if err != nil {
			t.Fatalf("an attempt that was read cannot be written: %v", err)
		}
		back, err := files.ReadAttempt(first)
		if err != nil {
			t.Fatalf("the canonical bytes are not read back: %v\n%s", err, first)
		}
		if second, err := back.Canonical(); err != nil || !bytes.Equal(first, second) {
			t.Fatalf("the canonical bytes change on the second turn: %v\n%s\n%s", err, first, second)
		}
	})
}

func FuzzReadPlan(f *testing.F) {
	seedFiles(f, planDoc())
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := files.ReadPlan(data)
		if err != nil {
			if p != nil {
				t.Fatal("a plan comes with an error")
			}
			refused(t, err)
			return
		}
		if p.TrustSequence == nil {
			t.Fatal("a plan was read with no trust_sequence")
		}
		first, err := p.Canonical()
		if err != nil {
			t.Fatalf("a plan that was read cannot be written: %v", err)
		}
		back, err := files.ReadPlan(first)
		if err != nil {
			t.Fatalf("the canonical bytes are not read back: %v\n%s", err, first)
		}
		if second, err := back.Canonical(); err != nil || !bytes.Equal(first, second) {
			t.Fatalf("the canonical bytes change on the second turn: %v\n%s\n%s", err, first, second)
		}
	})
}

// FuzzCheckPath: a path that CheckPath accepts holds only plain elements of the ASCII letters,
// digits, dot, hyphen and underscore.
func FuzzCheckPath(f *testing.F) {
	for _, s := range []string{"a", "a/b", "", "/", "..", "a//b", ".rt-x", "aux", "a b", "a\x00", strings.Repeat("a", 300)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		err := files.CheckPath(p)
		if err != nil {
			if !printableASCII(err.Error()) {
				t.Fatalf("the error is not printable ASCII: %q", err)
			}
			return
		}
		if len(p) == 0 || strings.Count(p, "/") >= files.MaxPathElements {
			t.Fatalf("CheckPath accepts a path of %d bytes with %d elements", len(p), strings.Count(p, "/")+1)
		}
		for _, e := range strings.Split(p, "/") {
			if e == "" || e == "." || e == ".." || len(e) > 255 || strings.HasPrefix(strings.ToLower(e), ".rt-") || strings.HasSuffix(e, ".") {
				t.Fatalf("CheckPath accepts %q, with the element %q", p, e)
			}
			for i := 0; i < len(e); i++ {
				c := e[i]
				if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '-' && c != '_' {
					t.Fatalf("CheckPath accepts %q, with the byte %#x", p, c)
				}
			}
		}
	})
}
