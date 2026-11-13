// Command elfcheck checks that a file is a static Linux ELF executable: an ELF file that asks
// for no interpreter (no PT_INTERP) and loads no shared library (no PT_DYNAMIC). The go-build
// recipe runs it on the release binary. It uses only the standard library.
//
// Usage: elfcheck FILE
package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run returns the exit code: 0 when the file is a static Linux ELF executable, 2 for a wrong
// command line and 1 for any other answer, with the reason on stderr.
func run(args []string, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: elfcheck FILE")
		return 2
	}
	if err := check(args[0]); err != nil {
		_, _ = fmt.Fprintf(stderr, "elfcheck: %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

// check returns nil when the file at path is a static Linux ELF executable.
func check(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		var fe *elf.FormatError
		if errors.As(err, &fe) {
			return fmt.Errorf("not an ELF file: %w", err)
		}
		return err
	}
	defer func() { _ = f.Close() }()

	if f.OSABI != elf.ELFOSABI_NONE && f.OSABI != elf.ELFOSABI_LINUX {
		return fmt.Errorf("not a Linux file (OS ABI %v)", f.OSABI)
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return fmt.Errorf("not an executable (type %v)", f.Type)
	}
	if len(f.Progs) == 0 {
		return errors.New("no program headers")
	}
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_INTERP:
			return errors.New("dynamically linked: it asks for an interpreter (PT_INTERP)")
		case elf.PT_DYNAMIC:
			return errors.New("dynamically linked: it has a dynamic section (PT_DYNAMIC)")
		}
	}
	return nil
}
