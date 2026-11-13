package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// childEnv makes the test binary run main() instead of the tests, so that a test can run the
// tool as a process and see its real exit code and its real standard output and error.
const childEnv = "ELFCHECK_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		main() // exits
		return
	}
	os.Exit(m.Run())
}

// usageLine is the last line of every usage error, spelled out here and not taken from main.go,
// so that a change of it is a change a test sees.
const usageLine = "usage: elfcheck --arch amd64|arm64 FILE"

// target is one machine the tool accepts: the --arch value and the ELF machine it stands for.
type target struct {
	arch    string
	machine elf.Machine
}

var (
	amd64 = target{"amd64", elf.EM_X86_64}
	arm64 = target{"arm64", elf.EM_AARCH64}

	targets = []target{amd64, arm64}
)

// segment is one program header of a hand-made ELF file.
type segment struct {
	typ elf.ProgType
}

// header is the part of an ELF file header that the tests vary.
type header struct {
	class   elf.Class
	data    elf.Data
	machine elf.Machine
	osabi   elf.OSABI
	typ     elf.Type
}

// buildELF makes the bytes of a minimal ELF file with the given header fields and program
// headers, in either class and either byte order. It has no sections.
func buildELF(h header, segs ...segment) []byte {
	var order binary.ByteOrder = binary.LittleEndian
	if h.data == elf.ELFDATA2MSB {
		order = binary.BigEndian
	}
	var b bytes.Buffer
	ident := [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(h.class), byte(h.data), byte(elf.EV_CURRENT), byte(h.osabi)}
	b.Write(ident[:])
	put := func(v any) {
		if err := binary.Write(&b, order, v); err != nil {
			panic(err)
		}
	}
	switch h.class {
	case elf.ELFCLASS64:
		const (
			ehsize    = 64
			phentsize = 56
		)
		put(uint16(h.typ))     // e_type
		put(uint16(h.machine)) // e_machine
		put(uint32(1))         // e_version
		put(uint64(0x1000))    // e_entry
		put(uint64(ehsize))    // e_phoff
		put(uint64(0))         // e_shoff
		put(uint32(0))         // e_flags
		put(uint16(ehsize))    // e_ehsize
		put(uint16(phentsize)) // e_phentsize
		put(uint16(len(segs))) // e_phnum
		put(uint16(0))         // e_shentsize
		put(uint16(0))         // e_shnum
		put(uint16(0))         // e_shstrndx
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
	case elf.ELFCLASS32:
		const (
			ehsize    = 52
			phentsize = 32
		)
		put(uint16(h.typ))     // e_type
		put(uint16(h.machine)) // e_machine
		put(uint32(1))         // e_version
		put(uint32(0x1000))    // e_entry
		put(uint32(ehsize))    // e_phoff
		put(uint32(0))         // e_shoff
		put(uint32(0))         // e_flags
		put(uint16(ehsize))    // e_ehsize
		put(uint16(phentsize)) // e_phentsize
		put(uint16(len(segs))) // e_phnum
		put(uint16(0))         // e_shentsize
		put(uint16(0))         // e_shnum
		put(uint16(0))         // e_shstrndx
		for _, s := range segs {
			put(uint32(s.typ))    // p_type
			put(uint32(0))        // p_offset
			put(uint32(0x1000))   // p_vaddr
			put(uint32(0x1000))   // p_paddr
			put(uint32(0))        // p_filesz
			put(uint32(0))        // p_memsz
			put(uint32(elf.PF_R)) // p_flags
			put(uint32(0x1000))   // p_align
		}
	default:
		panic(fmt.Sprintf("buildELF: class %v", h.class))
	}
	return b.Bytes()
}

// elfFile makes the bytes of a minimal 64-bit little-endian ELF file for the machine, with the
// given OS ABI, type and program headers.
func elfFile(machine elf.Machine, osabi elf.OSABI, typ elf.Type, segs ...segment) []byte {
	return buildELF(header{elf.ELFCLASS64, elf.ELFDATA2LSB, machine, osabi, typ}, segs...)
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// requireTool skips the test when the tool is not on PATH, unless RITUEEL_REQUIRE_TOOLS=1 is set:
// then the missing tool is a failure, so that a CI run cannot pass by skipping what it exists to
// run.
func requireTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		if os.Getenv("RITUEEL_REQUIRE_TOOLS") == "1" {
			t.Fatalf("the %s tool is not on PATH and RITUEEL_REQUIRE_TOOLS=1: %v", name, err)
		}
		t.Skipf("the %s tool is not on PATH: cannot compile a program for this test", name)
	}
	return path
}

// buildStatic compiles a tiny Go program, without cgo, for linux on the given architecture and
// returns the path of the executable. The program imports nothing and sits in its own module in a
// temporary folder, so that nothing is downloaded. The executable is only read, never run.
func buildStatic(t *testing.T, goarch string) string {
	t.Helper()
	goBin := requireTool(t, "go")
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":  "module elfcheckprobe\n\ngo 1.21\n",
		"main.go": "package main\n\nfunc main() {}\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "tiny-"+goarch)
	cmd := exec.CommandContext(t.Context(), goBin, "build", "-o", out, ".")
	cmd.Dir = dir
	// The last value of a name wins. These are the settings of the repository's recipes
	// (devbox.json), with no module download, no workspace and no cgo.
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH="+goarch,
		"GOFLAGS=-mod=readonly",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOPROXY=off",
		"GO111MODULE=on",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build (GOARCH=%s): %v\n%s", goarch, err, output)
	}
	return out
}

// processResult is what a run of the tool as a process left behind.
type processResult struct {
	stdout, stderr string
	code           int
}

// runProcess runs the tool as a process: this test binary, which runs main() when childEnv is set.
func runProcess(t *testing.T, args ...string) processResult {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], args...)
	cmd.Env = append(os.Environ(), childEnv+"=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := processResult{stdout: stdout.String(), stderr: stderr.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.code = ee.ExitCode()
	default:
		t.Fatalf("running the tool: %v", err)
	}
	return res
}

// runInProcess calls run and returns the same things as runProcess, but for the standard output,
// which run has no way to write to.
func runInProcess(args ...string) processResult {
	var stderr bytes.Buffer
	code := run(args, &stderr)
	return processResult{stderr: stderr.String(), code: code}
}

// refusal is the line the tool writes to stderr for a file it refuses.
func refusal(path, reason string) string {
	return fmt.Sprintf("elfcheck: %s: %s\n", path, reason)
}

// expectRefused checks, in the process and out of it, that the tool refuses the file with exactly
// the reason: exit code 1, one line on standard error, nothing on standard output. check is
// checked on the same file for the same reason.
func expectRefused(t *testing.T, arch, path, reason string) {
	t.Helper()
	if err := check(path, arch); err == nil {
		t.Errorf("check accepted it")
	} else if err.Error() != reason {
		t.Errorf("check error = %q, want %q", err, reason)
	}
	want := refusal(path, reason)
	if got := runInProcess("--arch", arch, path); got.code != 1 || got.stderr != want {
		t.Errorf("run = (%d, %q), want (1, %q)", got.code, got.stderr, want)
	}
	if got := runProcess(t, "--arch", arch, path); got.code != 1 || got.stderr != want || got.stdout != "" {
		t.Errorf("process = (%d, %q, stdout %q), want (1, %q, empty)", got.code, got.stderr, got.stdout, want)
	}
}

// expectAccepted checks, in the process and out of it, that the tool accepts the file: exit code
// 0 and nothing at all written.
func expectAccepted(t *testing.T, arch, path string) {
	t.Helper()
	if err := check(path, arch); err != nil {
		t.Errorf("check refused it: %v", err)
	}
	if got := runInProcess("--arch", arch, path); got.code != 0 || got.stderr != "" {
		t.Errorf("run = (%d, %q), want (0, empty)", got.code, got.stderr)
	}
	if got := runProcess(t, "--arch", arch, path); got.code != 0 || got.stderr != "" || got.stdout != "" {
		t.Errorf("process = (%d, stderr %q, stdout %q), want (0, empty, empty)", got.code, got.stderr, got.stdout)
	}
}

func TestCheckAcceptsAStaticExecutable(t *testing.T) {
	for _, tg := range targets {
		t.Run(tg.arch, func(t *testing.T) {
			path := buildStatic(t, tg.arch)
			expectAccepted(t, tg.arch, path)
		})
	}
}

// Real binaries, not only hand-made headers: a Go program built for each machine is accepted for
// its own machine and refused for the other, with the message that names both.
func TestCheckOnRealBinaries(t *testing.T) {
	const (
		amd64Refused = "built for the wrong machine: expected arm64 (EM_AARCH64), found amd64 (EM_X86_64)"
		arm64Refused = "built for the wrong machine: expected amd64 (EM_X86_64), found arm64 (EM_AARCH64)"
	)
	for _, tg := range targets {
		t.Run("built for "+tg.arch, func(t *testing.T) {
			path := buildStatic(t, tg.arch)
			f, err := elf.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			machine := f.Machine
			_ = f.Close()
			if machine != tg.machine {
				t.Fatalf("the test program for GOARCH=%s has machine %v, want %v: the build did not cross-compile", tg.arch, machine, tg.machine)
			}
			expectAccepted(t, tg.arch, path)
			other, reason := "arm64", amd64Refused
			if tg.arch == "arm64" {
				other, reason = "amd64", arm64Refused
			}
			expectRefused(t, other, path, reason)
		})
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
	for _, tg := range targets {
		for name, path := range map[string]string{"text file": text, "empty file": empty, "truncated magic": short} {
			t.Run(tg.arch+"/"+name, func(t *testing.T) {
				if err := check(path, tg.arch); err == nil {
					t.Error("check accepted it")
				}
				got := runInProcess("--arch", tg.arch, path)
				if got.code != 1 {
					t.Errorf("run = %d, want 1", got.code)
				}
				if !strings.HasPrefix(got.stderr, "elfcheck: "+path+": ") {
					t.Errorf("stderr %q does not start with the tool and the file", got.stderr)
				}
				if p := runProcess(t, "--arch", tg.arch, path); p.code != 1 || p.stdout != "" {
					t.Errorf("process = (%d, stdout %q), want (1, empty)", p.code, p.stdout)
				}
			})
		}
	}
}

func TestCheckRefusesAMissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-file")
	err := check(path, "amd64")
	if err == nil {
		t.Fatal("check accepted a missing path")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error %v does not say that the file does not exist", err)
	}
	got := runInProcess("--arch", "amd64", path)
	if got.code != 1 {
		t.Errorf("run = %d, want 1", got.code)
	}
	if !strings.Contains(got.stderr, path) {
		t.Errorf("stderr %q does not name the path", got.stderr)
	}
}

func TestCheckRefusesAFolder(t *testing.T) {
	dir := t.TempDir()
	if err := check(dir, "amd64"); err == nil {
		t.Error("check accepted a folder")
	}
	got := runInProcess("--arch", "amd64", dir)
	if got.code != 1 {
		t.Errorf("run = %d, want 1", got.code)
	}
	if got.stderr == "" {
		t.Error("run said nothing about the folder")
	}
}

// The machine's own shell, when it is linked against a shared library, is the plain example
// of a file that must be refused. It is checked for its own machine, so that what refuses it is
// the interpreter and not the machine.
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
	arch := ""
	for _, tg := range targets {
		if tg.machine == f.Machine {
			arch = tg.arch
		}
	}
	if arch == "" {
		t.Skipf("/bin/sh is built for %v, a machine the tool does not take", f.Machine)
	}
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		t.Skipf("/bin/sh is not a 64-bit little-endian file (%v, %v)", f.Class, f.Data)
	}
	if err := check(sh, arch); err == nil {
		t.Errorf("check accepted the dynamically linked %s", sh)
	} else if !strings.Contains(err.Error(), "PT_INTERP") {
		t.Errorf("error %q does not mention PT_INTERP", err)
	}
	if got := runInProcess("--arch", arch, sh); got.code != 1 {
		t.Errorf("run = %d, want 1", got.code)
	}
}

// Hand-made headers show which rule refuses which file: each refusal is paired with a file
// that differs only in the one thing and is accepted. Every case runs for both machines.
func TestCheckOnHandMadeHeaders(t *testing.T) {
	load := segment{typ: elf.PT_LOAD}
	type testCase struct {
		name    string
		segs    []segment
		osabi   elf.OSABI
		typ     elf.Type
		wantErr string // empty: accepted
	}
	tests := []testCase{
		{
			name: "a static executable (ET_EXEC, PT_LOAD only)",
			typ:  elf.ET_EXEC,
			segs: []segment{load},
		},
		{
			name: "a static position-independent executable (ET_DYN, PT_LOAD only)",
			typ:  elf.ET_DYN,
			segs: []segment{load},
		},
		{
			name:  "the Linux OS ABI",
			osabi: elf.ELFOSABI_LINUX,
			typ:   elf.ET_EXEC,
			segs:  []segment{load},
		},
		{
			name: "other program headers are fine",
			typ:  elf.ET_EXEC,
			segs: []segment{load, {typ: elf.PT_NOTE}, {typ: elf.PT_GNU_STACK}},
		},
		{
			name:    "PT_INTERP asks for an interpreter",
			typ:     elf.ET_EXEC,
			segs:    []segment{{typ: elf.PT_INTERP}, load},
			wantErr: "PT_INTERP",
		},
		{
			name:    "PT_DYNAMIC without PT_INTERP (a static-PIE-looking file with a dynamic section)",
			typ:     elf.ET_DYN,
			segs:    []segment{load, {typ: elf.PT_DYNAMIC}},
			wantErr: "PT_DYNAMIC",
		},
		{
			name:    "PT_DYNAMIC in an ET_EXEC file",
			typ:     elf.ET_EXEC,
			segs:    []segment{load, {typ: elf.PT_DYNAMIC}},
			wantErr: "PT_DYNAMIC",
		},
		{
			name:    "PT_DYNAMIC first",
			typ:     elf.ET_DYN,
			segs:    []segment{{typ: elf.PT_DYNAMIC}, load},
			wantErr: "PT_DYNAMIC",
		},
		{
			name:    "PT_DYNAMIC after other headers",
			typ:     elf.ET_DYN,
			segs:    []segment{load, {typ: elf.PT_NOTE}, {typ: elf.PT_DYNAMIC}},
			wantErr: "PT_DYNAMIC",
		},
		{
			name:    "both PT_INTERP and PT_DYNAMIC",
			typ:     elf.ET_DYN,
			segs:    []segment{{typ: elf.PT_INTERP}, load, {typ: elf.PT_DYNAMIC}},
			wantErr: "dynamically linked",
		},
		{
			name:    "no program headers",
			typ:     elf.ET_EXEC,
			wantErr: "no program headers",
		},
		{
			name:    "program headers but no PT_LOAD",
			typ:     elf.ET_EXEC,
			segs:    []segment{{typ: elf.PT_NOTE}, {typ: elf.PT_GNU_STACK}},
			wantErr: "no PT_LOAD program header",
		},
		{
			name:    "a single program header that is not PT_LOAD (position-independent)",
			typ:     elf.ET_DYN,
			segs:    []segment{{typ: elf.PT_NOTE}},
			wantErr: "no PT_LOAD program header",
		},
		{
			name:    "not an executable (relocatable object)",
			typ:     elf.ET_REL,
			segs:    []segment{load},
			wantErr: "not an executable",
		},
		{
			name:    "not an executable (core file)",
			typ:     elf.ET_CORE,
			segs:    []segment{load},
			wantErr: "not an executable",
		},
		{
			name:    "not a Linux file (FreeBSD OS ABI)",
			osabi:   elf.ELFOSABI_FREEBSD,
			typ:     elf.ET_EXEC,
			segs:    []segment{load},
			wantErr: "not a Linux file",
		},
	}
	for _, tg := range targets {
		for _, tt := range tests {
			t.Run(tg.arch+"/"+tt.name, func(t *testing.T) {
				path := writeFile(t, "file", elfFile(tg.machine, tt.osabi, tt.typ, tt.segs...))
				err := check(path, tg.arch)
				got := runInProcess("--arch", tg.arch, path)
				if tt.wantErr == "" {
					if err != nil {
						t.Errorf("check refused it: %v", err)
					}
					if got.code != 0 || got.stderr != "" {
						t.Errorf("run = (%d, %q), want (0, empty)", got.code, got.stderr)
					}
					return
				}
				if err == nil {
					t.Fatal("check accepted it")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not mention %q", err, tt.wantErr)
				}
				if got.code != 1 {
					t.Errorf("run = %d, want 1", got.code)
				}
				if !strings.Contains(got.stderr, tt.wantErr) {
					t.Errorf("stderr %q does not mention %q", got.stderr, tt.wantErr)
				}
			})
		}
	}
}

// A file that is fine in every way but its machine is refused for the other --arch, with the
// message that says both machines, and accepted for its own.
func TestCheckMachine(t *testing.T) {
	load := segment{typ: elf.PT_LOAD}
	tests := []struct {
		name    string
		machine elf.Machine
		arch    string
		reason  string // empty: accepted
	}{
		{"amd64 file, --arch amd64", elf.EM_X86_64, "amd64", ""},
		{"arm64 file, --arch arm64", elf.EM_AARCH64, "arm64", ""},
		{"amd64 file, --arch arm64", elf.EM_X86_64, "arm64", "built for the wrong machine: expected arm64 (EM_AARCH64), found amd64 (EM_X86_64)"},
		{"arm64 file, --arch amd64", elf.EM_AARCH64, "amd64", "built for the wrong machine: expected amd64 (EM_X86_64), found arm64 (EM_AARCH64)"},
		{"RISC-V file, --arch amd64", elf.EM_RISCV, "amd64", "built for the wrong machine: expected amd64 (EM_X86_64), found EM_RISCV"},
		{"RISC-V file, --arch arm64", elf.EM_RISCV, "arm64", "built for the wrong machine: expected arm64 (EM_AARCH64), found EM_RISCV"},
		{"no machine (EM_NONE), --arch amd64", elf.EM_NONE, "amd64", "built for the wrong machine: expected amd64 (EM_X86_64), found EM_NONE"},
		{"s390 file, --arch arm64", elf.EM_S390, "arm64", "built for the wrong machine: expected arm64 (EM_AARCH64), found EM_S390"},
	}
	for _, tt := range tests {
		for _, typ := range []elf.Type{elf.ET_EXEC, elf.ET_DYN} {
			t.Run(fmt.Sprintf("%s/%v", tt.name, typ), func(t *testing.T) {
				path := writeFile(t, "file", elfFile(tt.machine, elf.ELFOSABI_NONE, typ, load))
				if tt.reason == "" {
					expectAccepted(t, tt.arch, path)
					return
				}
				expectRefused(t, tt.arch, path, tt.reason)
			})
		}
	}
}

// Only 64-bit little-endian files are taken. The x32 form (32-bit class, EM_X86_64) has the
// machine of amd64 and is not an amd64 executable; a big-endian file may carry either machine.
func TestCheckClassAndByteOrder(t *testing.T) {
	load := segment{typ: elf.PT_LOAD}
	const (
		not64  = "not a 64-bit file (class ELFCLASS32)"
		notLE  = "not a little-endian file (data encoding ELFDATA2MSB)"
		goodLE = elf.ELFDATA2LSB
		goodC  = elf.ELFCLASS64
	)
	tests := []struct {
		name    string
		class   elf.Class
		data    elf.Data
		machine elf.Machine
		arch    string
		reason  string
	}{
		{"x32 (32-bit, EM_X86_64), --arch amd64", elf.ELFCLASS32, goodLE, elf.EM_X86_64, "amd64", not64},
		{"x32 (32-bit, EM_X86_64), --arch arm64", elf.ELFCLASS32, goodLE, elf.EM_X86_64, "arm64", not64},
		{"32-bit EM_386, --arch amd64", elf.ELFCLASS32, goodLE, elf.EM_386, "amd64", not64},
		{"32-bit EM_ARM, --arch arm64", elf.ELFCLASS32, goodLE, elf.EM_ARM, "arm64", not64},
		{"32-bit with the arm64 machine, --arch arm64", elf.ELFCLASS32, goodLE, elf.EM_AARCH64, "arm64", not64},
		{"32-bit RISC-V, --arch amd64", elf.ELFCLASS32, goodLE, elf.EM_RISCV, "amd64", not64},
		{"32-bit big-endian x32, --arch amd64", elf.ELFCLASS32, elf.ELFDATA2MSB, elf.EM_X86_64, "amd64", not64},
		{"big-endian, EM_X86_64, --arch amd64", goodC, elf.ELFDATA2MSB, elf.EM_X86_64, "amd64", notLE},
		{"big-endian, EM_AARCH64 (aarch64_be), --arch arm64", goodC, elf.ELFDATA2MSB, elf.EM_AARCH64, "arm64", notLE},
		{"big-endian, EM_X86_64, --arch arm64", goodC, elf.ELFDATA2MSB, elf.EM_X86_64, "arm64", notLE},
		{"big-endian, EM_AARCH64, --arch amd64", goodC, elf.ELFDATA2MSB, elf.EM_AARCH64, "amd64", notLE},
		{"big-endian RISC-V, --arch amd64", goodC, elf.ELFDATA2MSB, elf.EM_RISCV, "amd64", notLE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildELF(header{tt.class, tt.data, tt.machine, elf.ELFOSABI_NONE, elf.ET_EXEC}, load)
			path := writeFile(t, "file", data)
			expectRefused(t, tt.arch, path, tt.reason)
		})
	}
	// The same bytes with the class and the byte order the tool takes are accepted: nothing but
	// the class or the byte order is what refuses the files above.
	for _, tg := range targets {
		t.Run("control "+tg.arch, func(t *testing.T) {
			path := writeFile(t, "file", buildELF(header{goodC, goodLE, tg.machine, elf.ELFOSABI_NONE, elf.ET_EXEC}, load))
			expectAccepted(t, tg.arch, path)
		})
	}
}

// Where the answer depends on the order of the checks: the first rule that applies is the one
// the message names. The order is the OS ABI, the class, the byte order, the machine, the type,
// the program headers (none, then PT_INTERP or PT_DYNAMIC, then no PT_LOAD).
func TestCheckOrderOfRefusals(t *testing.T) {
	load := segment{typ: elf.PT_LOAD}
	note := segment{typ: elf.PT_NOTE}
	interp := segment{typ: elf.PT_INTERP}
	dynamic := segment{typ: elf.PT_DYNAMIC}
	const (
		wrongMachine = "built for the wrong machine: expected amd64 (EM_X86_64), found arm64 (EM_AARCH64)"
		notLinux     = "not a Linux file (OS ABI ELFOSABI_FREEBSD)"
		not64        = "not a 64-bit file (class ELFCLASS32)"
		notLE        = "not a little-endian file (data encoding ELFDATA2MSB)"
		notExec      = "not an executable (type ET_REL)"
		noHeaders    = "no program headers"
		noLoad       = "nothing to load: no PT_LOAD program header"
	)
	const (
		le, be = elf.ELFDATA2LSB, elf.ELFDATA2MSB
		c64    = elf.ELFCLASS64
		c32    = elf.ELFCLASS32
		none   = elf.ELFOSABI_NONE
	)
	// Every file is checked with --arch amd64. A machine of arm64 is the wrong one.
	tests := []struct {
		name string
		h    header
		segs []segment
		want string
	}{
		{"OS ABI before class, byte order and machine", header{c32, be, elf.EM_AARCH64, elf.ELFOSABI_FREEBSD, elf.ET_REL}, nil, notLinux},
		{"class before byte order and machine", header{c32, be, elf.EM_AARCH64, none, elf.ET_REL}, nil, not64},
		{"byte order before machine", header{c64, be, elf.EM_AARCH64, none, elf.ET_REL}, nil, notLE},
		{"machine before type", header{c64, le, elf.EM_AARCH64, none, elf.ET_REL}, []segment{load}, wrongMachine},
		{"machine before program headers (none)", header{c64, le, elf.EM_AARCH64, none, elf.ET_EXEC}, nil, wrongMachine},
		{"machine before PT_INTERP", header{c64, le, elf.EM_AARCH64, none, elf.ET_EXEC}, []segment{interp, load}, wrongMachine},
		{"machine before PT_DYNAMIC", header{c64, le, elf.EM_AARCH64, none, elf.ET_DYN}, []segment{load, dynamic}, wrongMachine},
		{"machine before the missing PT_LOAD", header{c64, le, elf.EM_AARCH64, none, elf.ET_EXEC}, []segment{note}, wrongMachine},
		{"type before program headers (none)", header{c64, le, elf.EM_X86_64, none, elf.ET_REL}, nil, notExec},
		{"no program headers before the missing PT_LOAD", header{c64, le, elf.EM_X86_64, none, elf.ET_EXEC}, nil, noHeaders},
		{"PT_INTERP before the missing PT_LOAD", header{c64, le, elf.EM_X86_64, none, elf.ET_EXEC}, []segment{interp}, "dynamically linked: it asks for an interpreter (PT_INTERP)"},
		{"PT_DYNAMIC before the missing PT_LOAD", header{c64, le, elf.EM_X86_64, none, elf.ET_DYN}, []segment{dynamic}, "dynamically linked: it has a dynamic section (PT_DYNAMIC)"},
		{"PT_INTERP before PT_DYNAMIC when it comes first", header{c64, le, elf.EM_X86_64, none, elf.ET_DYN}, []segment{interp, dynamic, load}, "dynamically linked: it asks for an interpreter (PT_INTERP)"},
		{"PT_DYNAMIC before PT_INTERP when it comes first", header{c64, le, elf.EM_X86_64, none, elf.ET_DYN}, []segment{dynamic, interp, load}, "dynamically linked: it has a dynamic section (PT_DYNAMIC)"},
		{"the missing PT_LOAD is the last", header{c64, le, elf.EM_X86_64, none, elf.ET_EXEC}, []segment{note}, noLoad},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFile(t, "file", buildELF(tt.h, tt.segs...))
			expectRefused(t, "amd64", path, tt.want)
		})
	}
}

// check is called by run only with an architecture that run has checked, and refuses any other
// by itself.
func TestCheckRefusesAnUnknownArchitecture(t *testing.T) {
	path := writeFile(t, "file", elfFile(elf.EM_X86_64, elf.ELFOSABI_NONE, elf.ET_EXEC, segment{typ: elf.PT_LOAD}))
	for _, arch := range []string{"", "riscv64", "386", "AMD64", "x86_64", "aarch64"} {
		t.Run(arch, func(t *testing.T) {
			err := check(path, arch)
			if err == nil {
				t.Fatal("check accepted an unknown architecture")
			}
			if want := fmt.Sprintf("unknown architecture %q", arch); err.Error() != want {
				t.Errorf("error = %q, want %q", err, want)
			}
		})
	}
}

// Every way of writing the flag that the flag package allows names the architecture.
func TestRunAcceptsTheFlagInEveryForm(t *testing.T) {
	path := writeFile(t, "file", elfFile(elf.EM_AARCH64, elf.ELFOSABI_NONE, elf.ET_EXEC, segment{typ: elf.PT_LOAD}))
	for _, args := range [][]string{
		{"--arch", "arm64", path},
		{"-arch", "arm64", path},
		{"--arch=arm64", path},
		{"-arch=arm64", path},
		{"--arch", "arm64", "--", path},
	} {
		t.Run(strings.Join(args[:len(args)-1], " "), func(t *testing.T) {
			if got := runInProcess(args...); got.code != 0 || got.stderr != "" {
				t.Errorf("run = (%d, %q), want (0, empty)", got.code, got.stderr)
			}
		})
	}
}

// A wrong command line is told apart from a file that is refused: exit 2, the reason and then the
// usage line on standard error, nothing on standard output.
func TestRunUsageErrors(t *testing.T) {
	good := writeFile(t, "good", elfFile(elf.EM_X86_64, elf.ELFOSABI_NONE, elf.ET_EXEC, segment{typ: elf.PT_LOAD}))
	missing := filepath.Join(t.TempDir(), "no-such-file")
	tests := []struct {
		name   string
		args   []string
		reason string
	}{
		{"no argument", nil, "--arch is required"},
		{"empty list", []string{}, "--arch is required"},
		{"a file and no --arch", []string{good}, "--arch is required"},
		{"two files and no --arch", []string{good, good}, "--arch is required"},
		{"the flag after the file is not read", []string{good, "--arch", "amd64"}, "--arch is required"},
		{"--arch with no value", []string{"--arch"}, "flag needs an argument: -arch"},
		{"--arch with no value after a file", []string{good, "--arch"}, "--arch is required"},
		{"unknown value", []string{"--arch", "riscv64", good}, `unknown --arch "riscv64": want amd64 or arm64`},
		{"unknown value, no file", []string{"--arch", "riscv64"}, `unknown --arch "riscv64": want amd64 or arm64`},
		{"the GOARCH name in capitals", []string{"--arch", "AMD64", good}, `unknown --arch "AMD64": want amd64 or arm64`},
		{"the uname name", []string{"--arch", "x86_64", good}, `unknown --arch "x86_64": want amd64 or arm64`},
		{"the other uname name", []string{"--arch", "aarch64", good}, `unknown --arch "aarch64": want amd64 or arm64`},
		{"an empty value", []string{"--arch", "", good}, `unknown --arch "": want amd64 or arm64`},
		{"an empty value with =", []string{"--arch=", good}, `unknown --arch "": want amd64 or arm64`},
		{"the value with a space", []string{"--arch", "amd64 ", good}, `unknown --arch "amd64 ": want amd64 or arm64`},
		{"the next flag taken as the value", []string{"--arch", "--arch", "amd64", good}, `unknown --arch "--arch": want amd64 or arm64`},
		{"the flag twice, the same value", []string{"--arch", "amd64", "--arch", "amd64", good}, `invalid value "amd64" for flag -arch: --arch given more than once`},
		{"the flag twice, two values", []string{"--arch", "amd64", "--arch", "arm64", good}, `invalid value "arm64" for flag -arch: --arch given more than once`},
		{"the flag twice, in two spellings", []string{"--arch=amd64", "-arch", "amd64", good}, `invalid value "amd64" for flag -arch: --arch given more than once`},
		{"no file", []string{"--arch", "amd64"}, "want exactly one FILE, got 0 arguments"},
		{"two files", []string{"--arch", "amd64", good, good}, "want exactly one FILE, got 2 arguments"},
		{"three files", []string{"--arch", "arm64", good, good, good}, "want exactly one FILE, got 3 arguments"},
		{"a second file that does not exist", []string{"--arch", "amd64", good, missing}, "want exactly one FILE, got 2 arguments"},
		{"an unknown flag", []string{"--foo"}, "flag provided but not defined: -foo"},
		{"an unknown flag after --arch", []string{"--arch", "amd64", "--foo", good}, "flag provided but not defined: -foo"},
		{"an unknown flag before a valid line", []string{"-x", "--arch", "amd64", good}, "flag provided but not defined: -x"},
		{"-h", []string{"-h"}, "flag: help requested"},
		{"--help", []string{"--help"}, "flag: help requested"},
		{"-h with a good line", []string{"--arch", "amd64", "-h", good}, "flag: help requested"},
		{"-help", []string{"-help"}, "flag: help requested"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := "elfcheck: " + tt.reason + "\n" + usageLine + "\n"
			if got := runInProcess(tt.args...); got.code != 2 || got.stderr != want {
				t.Errorf("run = (%d, %q), want (2, %q)", got.code, got.stderr, want)
			}
			got := runProcess(t, tt.args...)
			if got.code != 2 || got.stderr != want || got.stdout != "" {
				t.Errorf("process = (%d, stderr %q, stdout %q), want (2, %q, empty)", got.code, got.stderr, got.stdout, want)
			}
		})
	}
}

// A file is not looked at when the command line is wrong: the file below would be refused for its
// machine, and a missing one would be refused as missing, and neither is what the tool says.
func TestWrongUsageDoesNotLookAtTheFile(t *testing.T) {
	wrong := writeFile(t, "wrong", elfFile(elf.EM_AARCH64, elf.ELFOSABI_NONE, elf.ET_EXEC, segment{typ: elf.PT_LOAD}))
	missing := filepath.Join(t.TempDir(), "no-such-file")
	for name, args := range map[string][]string{
		"two files, one refused":    {"--arch", "amd64", wrong, wrong},
		"two files, none exists":    {"--arch", "amd64", missing, missing},
		"unknown value, file there": {"--arch", "x86_64", wrong},
		"unknown value, no file":    {"--arch", "x86_64", missing},
		"no --arch, file refused":   {wrong},
		"no --arch, file missing":   {missing},
		"the flag twice":            {"--arch", "amd64", "--arch", "arm64", wrong},
	} {
		t.Run(name, func(t *testing.T) {
			got := runInProcess(args...)
			if got.code != 2 {
				t.Errorf("run = %d, want 2 (stderr %q)", got.code, got.stderr)
			}
			if strings.Contains(got.stderr, "wrong machine") || strings.Contains(got.stderr, "no such file") {
				t.Errorf("stderr %q is about the file", got.stderr)
			}
			if !strings.HasSuffix(got.stderr, usageLine+"\n") {
				t.Errorf("stderr %q does not end with the usage line", got.stderr)
			}
		})
	}
}

// The three answers are three different exit codes in the process, and only a refusal or a usage
// error writes anything.
func TestProcessExitCodes(t *testing.T) {
	good := writeFile(t, "good", elfFile(elf.EM_X86_64, elf.ELFOSABI_NONE, elf.ET_EXEC, segment{typ: elf.PT_LOAD}))
	tests := []struct {
		name       string
		args       []string
		code       int
		stderrWant string
	}{
		{"a good file", []string{"--arch", "amd64", good}, 0, ""},
		{"a file for the other machine", []string{"--arch", "arm64", good}, 1, refusal(good, "built for the wrong machine: expected arm64 (EM_AARCH64), found amd64 (EM_X86_64)")},
		{"a missing file", []string{"--arch", "amd64", good + ".missing"}, 1, ""},
		{"no --arch", []string{good}, 2, "elfcheck: --arch is required\n" + usageLine + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runProcess(t, tt.args...)
			if got.code != tt.code {
				t.Errorf("exit code = %d, want %d (stderr %q)", got.code, tt.code, got.stderr)
			}
			if got.stdout != "" {
				t.Errorf("stdout = %q, want empty", got.stdout)
			}
			if tt.stderrWant != "" && got.stderr != tt.stderrWant {
				t.Errorf("stderr = %q, want %q", got.stderr, tt.stderrWant)
			}
			if (tt.code != 0) != (got.stderr != "") {
				t.Errorf("stderr = %q for exit code %d", got.stderr, got.code)
			}
		})
	}
}
