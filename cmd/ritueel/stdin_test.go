//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// stdinIsTerminal is the one fact that only the process knows: a typed confirmation is read only
// when standard input is a character device (record 0005, rule 9; record 0010, rule 13).
func TestStdinIsATerminalOnlyForACharacterDevice(t *testing.T) {
	old := os.Stdin
	t.Cleanup(func() { os.Stdin = old })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	os.Stdin = r
	if stdinIsTerminal() {
		t.Error("a pipe is a terminal")
	}

	file := filepath.Join(t.TempDir(), "in")
	if err := os.WriteFile(file, []byte("12345678\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = f
	if stdinIsTerminal() {
		t.Error("a file is a terminal")
	}
	_ = f.Close()
	if stdinIsTerminal() {
		t.Error("a closed file is a terminal")
	}

	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	os.Stdin = dir
	if stdinIsTerminal() {
		t.Error("a folder is a terminal")
	}

	os.Stdin = nil
	if stdinIsTerminal() {
		t.Error("no standard input is a terminal")
	}
}
