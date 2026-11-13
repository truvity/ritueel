package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// segment is one program header of a hand-made ELF file.
type segment struct {
	typ elf.ProgType
}

// elfFile makes the bytes of a minimal 64-bit little-endian ELF file with the given header
// fields and program headers. It has no sections.
func elfFile(osabi elf.OSABI, typ elf.Type, segs ...segment) []byte {
	const (
		ehsize    = 64
		phentsize = 56
	)
	var b bytes.Buffer
	ident := [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT), byte(osabi)}
	b.Write(ident[:])
	put := func(v any) {
		if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
			panic(err)
		}
	}
	put(uint16(typ))           // e_type
	put(uint16(elf.EM_X86_64)) // e_machine
	put(uint32(1))             // e_version
	put(uint64(0x1000))        // e_entry
	put(uint64(ehsize))        // e_phoff
	put(uint64(0))             // e_shoff
	put(uint32(0))             // e_flags
	put(uint16(ehsize))        // e_ehsize
	put(uint16(phentsize))     // e_phentsize
	put(uint16(len(segs)))     // e_phnum
	put(uint16(0))             // e_shentsize
	put(uint16(0))             // e_shnum
	put(uint16(0))             // e_shstrndx
	for _, s := range segs {
		put(uint32(s.typ))    // p_type
		put(uint32(elf.PF_R)) // p_flags
		put(uint64(0))        // p_offset
		put(uint64(0x1000))   // p_vaddr
		put(uint64(0x1000))   // p_paddr
		put(uint64(0))        // p_filesz
		put(uint64(0))        // p_memsz
		put(uint64(0x1000))   // p_align
	}
	return b.Bytes()
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// goTool finds the go tool or skips the test with a clear message.
func goTool(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is not on PATH: cannot compile a program for this test")
	}
	return path
}

// buildStatic compiles a tiny Go program, without cgo, for Linux on the machine's
// architecture, and returns the path of the executable. It is only read, never run.
func buildStatic(t *testing.T) string {
	t.Helper()
	goBin := goTool(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "tiny")
	cmd := exec.CommandContext(t.Context(), goBin, "build", "-o", out, src)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH="+runtime.GOARCH,
		"GOFLAGS=",
		"GOWORK=off",
		"GOTOOLCHAIN=local",
		"GO111MODULE=off",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	return out
}

func TestCheckAcceptsAStaticExecutable(t *testing.T) {
	path := buildStatic(t)
	if err := check(path); err != nil {
		t.Errorf("check refused a static Go executable: %v", err)
	}
	var stderr bytes.Buffer
	if code := run([]string{path}, &stderr); code != 0 {
		t.Errorf("run = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("run wrote to stderr for a good file: %q", stderr.String())
	}
}

func TestCheckRefusesFilesThatAreNotELF(t *testing.T) {
	dir := t.TempDir()
	text := filepath.Join(dir, "text.txt")
	empty := filepath.Join(dir, "empty")
	short := filepath.Join(dir, "short")
	for path, data := range map[string]string{
		text:  "#!/bin/sh\necho hello\n",
		empty: "",
		short: "\x7fEL",
	} {
		if err := os.WriteFile(path, []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, path := range map[string]string{"text file": text, "empty file": empty, "truncated magic": short} {
		t.Run(name, func(t *testing.T) {
			if err := check(path); err == nil {
				t.Error("check accepted it")
			}
			var stderr bytes.Buffer
			if code := run([]string{path}, &stderr); code != 1 {
				t.Errorf("run = %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), path) {
				t.Errorf("stderr %q does not name the file", stderr.String())
			}
		})
	}
}

func TestCheckRefusesAMissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-file")
	err := check(path)
	if err == nil {
		t.Fatal("check accepted a missing path")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error %v does not say that the file does not exist", err)
	}
	var stderr bytes.Buffer
	if code := run([]string{path}, &stderr); code != 1 {
		t.Errorf("run = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), path) {
		t.Errorf("stderr %q does not name the path", stderr.String())
	}
}

func TestCheckRefusesAFolder(t *testing.T) {
	dir := t.TempDir()
	if err := check(dir); err == nil {
		t.Error("check accepted a folder")
	}
	var stderr bytes.Buffer
	if code := run([]string{dir}, &stderr); code != 1 {
		t.Errorf("run = %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Error("run said nothing about the folder")
	}
}

// The machine's own shell, when it is linked against a shared library, is the plain example
// of a file that must be refused.
func TestCheckRefusesADynamicShell(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the machine is not a Linux machine")
	}
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skipf("no /bin/sh to look at: %v", err)
	}
	f, err := elf.Open(sh)
	if err != nil {
		t.Skipf("/bin/sh is not an ELF file: %v", err)
	}
	defer func() { _ = f.Close() }()
	dynamic := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			dynamic = true
		}
	}
	if !dynamic {
		t.Skip("/bin/sh is not dynamically linked on this machine")
	}
	if err := check(sh); err == nil {
		t.Errorf("check accepted the dynamically linked %s", sh)
	}
	var stderr bytes.Buffer
	if code := run([]string{sh}, &stderr); code != 1 {
		t.Errorf("run = %d, want 1", code)
	}
}

// Hand-made headers show which rule refuses which file: each refusal is paired with a file
// that differs only in the one thing and is accepted.
func TestCheckOnHandMadeHeaders(t *testing.T) {
	load := segment{typ: elf.PT_LOAD}
	tests := []struct {
		name    string
		data    []byte
		wantErr string // empty: accepted
	}{
		{
			name: "a static executable (ET_EXEC, PT_LOAD only)",
			data: elfFile(elf.ELFOSABI_NONE, elf.ET_EXEC, load),
		},
		{
			name: "a static position-independent executable (ET_DYN, PT_LOAD only)",
			data: elfFile(elf.ELFOSABI_NONE, elf.ET_DYN, load),
		},
		{
			name: "the Linux OS ABI",
			data: elfFile(elf.ELFOSABI_LINUX, elf.ET_EXEC, load),
		},
		{
			name: "other program headers are fine",
			data: elfFile(elf.ELFOSABI_NONE, elf.ET_EXEC, load, segment{typ: elf.PT_NOTE}, segment{typ: elf.PT_GNU_STACK}),
		},
		{
			name:    "PT_INTERP asks for an interpreter",
			data:    elfFile(elf.ELFOSABI_NONE, elf.ET_EXEC, segment{typ: elf.PT_INTERP}, load),
			wantErr: "PT_INTERP",
		},
		{
			name:    "PT_DYNAMIC without PT_INTERP (a static-PIE-looking file with a dynamic section)",
			data:    elfFile(elf.ELFOSABI_NONE, elf.ET_DYN, load, segment{typ: elf.PT_DYNAMIC}),
			wantErr: "PT_DYNAMIC",
		},
		{
			name:    "PT_DYNAMIC in an ET_EXEC file",
			data:    elfFile(elf.ELFOSABI_NONE, elf.ET_EXEC, load, segment{typ: elf.PT_DYNAMIC}),
			wantErr: "PT_DYNAMIC",
		},
		{
			name:    "PT_DYNAMIC first",
			data:    elfFile(elf.ELFOSABI_NONE, elf.ET_DYN, segment{typ: elf.PT_DYNAMIC}, load),
			wantErr: "PT_DYNAMIC",
		},
		{
			name:    "PT_DYNAMIC after other headers",
			data:    elfFile(elf.ELFOSABI_NONE, elf.ET_DYN, load, segment{typ: elf.PT_NOTE}, segment{typ: elf.PT_DYNAMIC}),
			wantErr: "PT_DYNAMIC",
		},
		{
			name:    "both PT_INTERP and PT_DYNAMIC",
			data:    elfFile(elf.ELFOSABI_NONE, elf.ET_DYN, segment{typ: elf.PT_INTERP}, load, segment{typ: elf.PT_DYNAMIC}),
			wantErr: "dynamically linked",
		},
		{
			name:    "no program headers",
			data:    elfFile(elf.ELFOSABI_NONE, elf.ET_EXEC),
			wantErr: "no program headers",
		},
		{
			name:    "not an executable (relocatable object)",
			data:    elfFile(elf.ELFOSABI_NONE, elf.ET_REL, load),
			wantErr: "not an executable",
		},
		{
			name:    "not an executable (core file)",
			data:    elfFile(elf.ELFOSABI_NONE, elf.ET_CORE, load),
			wantErr: "not an executable",
		},
		{
			name:    "not a Linux file (FreeBSD OS ABI)",
			data:    elfFile(elf.ELFOSABI_FREEBSD, elf.ET_EXEC, load),
			wantErr: "not a Linux file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFile(t, "file", tt.data)
			err := check(path)
			var stderr bytes.Buffer
			code := run([]string{path}, &stderr)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("check refused it: %v", err)
				}
				if code != 0 || stderr.Len() != 0 {
					t.Errorf("run = (%d, %q), want (0, empty)", code, stderr.String())
				}
				return
			}
			if err == nil {
				t.Fatal("check accepted it")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
			if code != 1 {
				t.Errorf("run = %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr %q does not mention %q", stderr.String(), tt.wantErr)
			}
		})
	}
}

func TestRunWithAWrongNumberOfArguments(t *testing.T) {
	for name, args := range map[string][]string{
		"no argument":     nil,
		"empty list":      {},
		"two arguments":   {"a", "b"},
		"three arguments": {"a", "b", "c"},
	} {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			if code := run(args, &stderr); code != 2 {
				t.Errorf("run = %d, want 2", code)
			}
			if !strings.Contains(stderr.String(), "usage: elfcheck FILE") {
				t.Errorf("stderr = %q, want the usage", stderr.String())
			}
		})
	}
}

// A wrong command line is told apart from a file that is refused, and a file is not looked
// at when the command line is wrong.
func TestWrongUsageDoesNotLookAtTheFile(t *testing.T) {
	good := writeFile(t, "good", elfFile(elf.ELFOSABI_NONE, elf.ET_EXEC, segment{typ: elf.PT_LOAD}))
	var stderr bytes.Buffer
	if code := run([]string{good, good}, &stderr); code != 2 {
		t.Errorf("run = %d, want 2", code)
	}
}
