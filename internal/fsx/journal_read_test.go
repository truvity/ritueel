package fsx_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

func TestReadJournal(t *testing.T) {
	cases := []struct {
		name    string
		content string
		lines   []string
		partial *string // nil: no partial line
	}{
		{"empty", "", nil, nil},
		{"one whole line", "a\n", []string{"a"}, nil},
		{"two whole lines", "a\nb\n", []string{"a", "b"}, nil},
		{"a torn last line", "a\nb", []string{"a"}, ptr("b")},
		{"only a torn line", "abc", nil, ptr("abc")},
		{"a whole line and a torn one", "{\"n\":1}\n{\"n\":2,\"si", []string{`{"n":1}`}, ptr(`{"n":2,"si`)},
		{"an empty line in the middle", "a\n\nb\n", []string{"a", "", "b"}, nil},
		{"a newline only", "\n", []string{""}, nil},
		{"a carriage return is part of the line", "a\r\nb", []string{"a\r"}, ptr("b")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "j.jsonl")
			if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
			lines, partial, err := fsx.ReadJournal(fsx.OS, p)
			if err != nil {
				t.Fatal(err)
			}
			if len(lines) != len(c.lines) {
				t.Fatalf("%d lines %q, want %q", len(lines), lines, c.lines)
			}
			for i := range lines {
				if string(lines[i]) != c.lines[i] {
					t.Fatalf("line %d is %q, want %q", i, lines[i], c.lines[i])
				}
			}
			switch {
			case c.partial == nil && partial != nil:
				t.Fatalf("partial %q, want nil", partial)
			case c.partial != nil && (partial == nil || string(partial) != *c.partial):
				t.Fatalf("partial %q, want %q", partial, *c.partial)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestReadJournalAppendingToAReturnedLineDoesNotChangeTheNext(t *testing.T) {
	p := filepath.Join(t.TempDir(), "j.jsonl")
	if err := os.WriteFile(p, []byte("aa\nbb\ncc"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, partial, err := fsx.ReadJournal(fsx.OS, p)
	if err != nil {
		t.Fatal(err)
	}
	_ = append(lines[0], 'X')
	_ = append(partial, 'Y')
	if string(lines[1]) != "bb" || string(partial) != "cc" {
		t.Fatalf("an append to one slice changed another: %q %q", lines[1], partial)
	}
}

func TestReadJournalErrorsAndTheDefaultFileSystem(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := fsx.ReadJournal(fsx.OS, filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing journal: %v, want ErrNotExist", err)
	}
	if _, _, err := fsx.ReadJournal(fsx.OS, dir); err == nil {
		t.Fatal("a folder read as a journal gave no error")
	}
	p := filepath.Join(dir, "j.jsonl")
	if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, _, err := fsx.ReadJournal(nil, p) // nil means the real file system
	if err != nil || len(lines) != 1 {
		t.Fatalf("ReadJournal(nil, ...) = %q, %v", lines, err)
	}
}
