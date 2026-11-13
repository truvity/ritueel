// Command elfcheck checks that a file is a static Linux ELF executable for one named machine:
// a 64-bit little-endian ELF file of the type the --arch flag names (amd64 or arm64, the Go
// names), that asks for no interpreter (no PT_INTERP) and loads no shared library (no
// PT_DYNAMIC). The go-build and release recipes run it on the release binaries. It uses only the
// standard library.
//
// Usage: elfcheck --arch amd64|arm64 FILE
//
// The flag is required, so that a caller that forgets it does not get a weaker check.
package main

import (
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const usage = "usage: elfcheck --arch amd64|arm64 FILE"

// machines maps each accepted --arch value (a Go GOARCH name) to the ELF machine it stands for.
var machines = map[string]elf.Machine{
	"amd64": elf.EM_X86_64,
	"arm64": elf.EM_AARCH64,
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// archFlag is the value of --arch. It refuses to be set twice, so that two different answers on
// one command line are an error rather than a silent choice of the last.
type archFlag struct {
	value string
	set   bool
}

func (a *archFlag) String() string { return a.value }

func (a *archFlag) Set(v string) error {
	if a.set {
		return errors.New("--arch given more than once")
	}
	a.value, a.set = v, true
	return nil
}

// run returns the exit code: 0 when the file is a static Linux ELF executable for the machine
// that --arch names, 2 for a wrong command line (with the usage on stderr) and 1 for any other
// answer, with the reason on stderr.
func run(args []string, stderr io.Writer) int {
	var arch archFlag
	fs := flag.NewFlagSet("elfcheck", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&arch, "arch", "the machine the file must be built for: amd64 or arm64")
	if err := fs.Parse(args); err != nil {
		return usageError(stderr, err.Error())
	}
	if !arch.set {
		return usageError(stderr, "--arch is required")
	}
	if _, ok := machines[arch.value]; !ok {
		return usageError(stderr, fmt.Sprintf("unknown --arch %q: want amd64 or arm64", arch.value))
	}
	if fs.NArg() != 1 {
		return usageError(stderr, fmt.Sprintf("want exactly one FILE, got %d arguments", fs.NArg()))
	}
	path := fs.Arg(0)
	if err := check(path, arch.value); err != nil {
		_, _ = fmt.Fprintf(stderr, "elfcheck: %s: %v\n", path, err)
		return 1
	}
	return 0
}

// usageError writes the reason and the usage to stderr and returns the exit code 2.
func usageError(stderr io.Writer, reason string) int {
	_, _ = fmt.Fprintf(stderr, "elfcheck: %s\n%s\n", reason, usage)
	return 2
}

// check returns nil when the file at path is a static Linux ELF executable built for arch, a Go
// architecture name that is a key of machines.
func check(path, arch string) error {
	want, ok := machines[arch]
	if !ok {
		return fmt.Errorf("unknown architecture %q", arch)
	}
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
	if f.Class != elf.ELFCLASS64 {
		return fmt.Errorf("not a 64-bit file (class %v)", f.Class)
	}
	if f.Data != elf.ELFDATA2LSB {
		return fmt.Errorf("not a little-endian file (data encoding %v)", f.Data)
	}
	if f.Machine != want {
		return fmt.Errorf("built for the wrong machine: expected %s (%v), found %s", arch, want, describe(f.Machine))
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return fmt.Errorf("not an executable (type %v)", f.Type)
	}
	if len(f.Progs) == 0 {
		return errors.New("no program headers")
	}
	loads := 0
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_INTERP:
			return errors.New("dynamically linked: it asks for an interpreter (PT_INTERP)")
		case elf.PT_DYNAMIC:
			return errors.New("dynamically linked: it has a dynamic section (PT_DYNAMIC)")
		case elf.PT_LOAD:
			loads++
		}
	}
	if loads == 0 {
		return errors.New("nothing to load: no PT_LOAD program header")
	}
	return nil
}

// describe names a machine the way the flag does when it is one of the two, and by its ELF name
// otherwise.
func describe(m elf.Machine) string {
	for name, want := range machines {
		if m == want {
			return fmt.Sprintf("%s (%v)", name, m)
		}
	}
	return m.String()
}
