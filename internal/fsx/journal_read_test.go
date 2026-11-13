package fsx_test

import (
	"errors"
	"io/fs"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

func ptr[T any](v T) *T { return &v }

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
			f := newMemFS("b")
			f.addFile("b/j.jsonl", []byte(c.content))
			root := f.Root()
			defer func() { _ = root.Close() }()
			lines, partial, err := fsx.ReadJournal(root, "b/j.jsonl")
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

func TestReadJournalAppendingToAReturnedLineDoesNotChangeTheNext(t *testing.T) {
	f := newMemFS("b")
	f.addFile("b/j.jsonl", []byte("aa\nbb\ncc"))
	root := f.Root()
	defer func() { _ = root.Close() }()
	lines, partial, err := fsx.ReadJournal(root, "b/j.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	_ = append(lines[0], 'X')
	_ = append(lines[1], 'X')
	_ = append(partial, 'Y')
	if string(lines[1]) != "bb" || string(partial) != "cc" {
		t.Fatalf("an append to one slice changed another: %q %q", lines[1], partial)
	}
	again, p2, _ := fsx.ReadJournal(root, "b/j.jsonl")
	if string(again[0]) != "aa" || string(again[1]) != "bb" || string(p2) != "cc" {
		t.Fatalf("a second read: %q %q", again, p2)
	}
}

func TestReadJournalErrors(t *testing.T) {
	f := newMemFS("b", "b/dir")
	root := f.Root()
	defer func() { _ = root.Close() }()
	if _, _, err := fsx.ReadJournal(root, "b/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing journal: %v, want ErrNotExist", err)
	}
	if _, _, err := fsx.ReadJournal(root, "b/dir"); !errors.Is(err, fsx.ErrNotRegular) {
		t.Fatalf("a folder read as a journal: %v, want ErrNotRegular", err)
	}
}
