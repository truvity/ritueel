//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// The command "apply", run as the program that the release builds: the exit code, standard output
// and standard error of the whole first apply, and the one thing that only the process knows: whether
// standard input is a terminal.

// apProgram runs the program and returns what it did. stdin is the standard input of the process.
type apProgram struct {
	t   *testing.T
	exe string
	dir string // the working folder of the process
}

func (p apProgram) run(stdin any, args ...string) (code int, stdout, stderr string) {
	p.t.Helper()
	cmd := exec.CommandContext(p.t.Context(), p.exe, args...)
	cmd.Dir = p.dir
	var out, errOut bytes.Buffer
	switch in := stdin.(type) {
	case nil:
		cmd.Stdin = strings.NewReader("")
	case string:
		cmd.Stdin = strings.NewReader(in)
	case *os.File:
		cmd.Stdin = in
	default:
		p.t.Fatalf("stdin of type %T", stdin)
	}
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		p.t.Fatalf("running the program: %v", err)
	}
	return code, out.String(), errOut.String()
}

// apFirst makes a bundle of one test root, with the OpenPGP root file removed as a person does, a key
// directory beside it, and a saved plan. It returns the bundle, the key directory and the plan.
func apFirst(t *testing.T, p apProgram) (ca, keys, planPath, digest string) {
	t.Helper()
	root := t.TempDir()
	ca, keys = filepath.Join(root, "ca"), filepath.Join(root, "keys")
	if code, _, stderr := p.run(nil, "new", "--test-root", ca); code != 0 {
		t.Fatalf("new: %d %s", code, stderr)
	}
	if err := os.Remove(filepath.Join(ca, "want", "roots", "openpgp.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := p.run(nil, "--dir", ca, "apply", "--plan-only", "--key-dir", keys, "--output", "json")
	if code != 0 {
		t.Fatalf("apply --plan-only: %d %s", code, stderr)
	}
	var obj struct {
		Plan struct{ Path, SHA256, Prefix string }
	}
	if err := json.Unmarshal([]byte(stdout), &obj); err != nil || len(obj.Plan.SHA256) != 64 || obj.Plan.Prefix != obj.Plan.SHA256[:8] {
		t.Fatalf("plan: %s, %v", stdout, err)
	}
	return ca, keys, obj.Plan.Path, obj.Plan.SHA256
}

func apTreeOf(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b.WriteString(rel)
		if !d.IsDir() {
			data, _ := os.ReadFile(p)
			b.WriteString(" " + sumOf(string(data)))
		}
		b.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestProgramApplyFollowsTheScriptOfTheCommandPage(t *testing.T) {
	p := apProgram{t: t, exe: buildForCheck(t), dir: t.TempDir()}
	ca, keys, planPath, digest := apFirst(t, p)
	code, stdout, stderr := p.run(nil, "--dir", ca, "apply", planPath, "--key-dir", keys, "--confirm", digest, "--output", "json")
	if code != 0 {
		t.Fatalf("apply PLAN: exit %d, stderr %s", code, stderr)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(stdout), &obj); err != nil || strings.Count(stdout, "\n") != 1 {
		t.Fatalf("standard output is not one object: %q, %v", stdout, err)
	}
	for _, m := range []string{"output", "command", "exit_code", "outcome", "warnings", "ceremony", "plan", "record", "artifacts", "trust_sequence", "roots"} {
		if _, ok := obj[m]; !ok {
			t.Errorf("the object has no member %q: %s", m, stdout)
		}
	}
	if _, bad := obj["error"]; bad {
		t.Error("a success has an error member")
	}
	// check history accepts it, and its end line is the end that the record has.
	code, hist, _ := p.run(nil, "--dir", ca, "check", "history")
	rec := obj["record"].(map[string]any)
	if want := "history: 1 ceremony records, end " + rec["sha256"].(string)[:8] + "\n"; code != 0 || hist != want {
		t.Errorf("check history: exit %d, %q; want 0, %q", code, hist, want)
	}
	// A host accepts the list with the two pins.
	roots := obj["roots"].([]any)
	set := filepath.Dir(obj["artifacts"].([]any)[2].(map[string]any)["path"].(string))
	args := []string{"verify", "root-list", filepath.Join(ca, set, "root-list.json"), "--ca-bundle", filepath.Join(ca, set, "ca-bundle.pem")}
	for _, r := range roots {
		args = append(args, "--pin", r.(map[string]any)["x509_spki_sha256"].(string))
	}
	code, verified, stderr := p.run(nil, args...)
	if code != 0 || !strings.HasPrefix(verified, "accepted: sequence 1, 2 root keys") {
		t.Errorf("verify root-list: exit %d, %q, %s", code, verified, stderr)
	}
	// The key directory holds the keys and nothing else: the folder test-only-keys, with the two keys, and
	// the two removal authorisations beside it.
	ents, _ := os.ReadDir(keys)
	if len(ents) != 3 {
		t.Errorf("the key directory holds %d entries, want 3", len(ents))
	}
}

func TestProgramApplyWithAPipeOnStandardInputIsNotConfirmedEvenWithTheRightLine(t *testing.T) {
	p := apProgram{t: t, exe: buildForCheck(t), dir: t.TempDir()}
	ca, keys, planPath, digest := apFirst(t, p)
	before, keysBefore := apTreeOf(t, ca), apTreeOf(t, keys)
	code, stdout, stderr := p.run(digest[:8]+"\n", "--dir", ca, "apply", planPath, "--key-dir", keys)
	if code != 5 || stdout != "" || !strings.Contains(stderr, "standard input is not a terminal") {
		t.Errorf("a piped line: exit %d, stdout %q, stderr %q; want 5", code, stdout, stderr)
	}
	// A file is no terminal either.
	f := filepath.Join(t.TempDir(), "line")
	if err := os.WriteFile(f, []byte(digest[:8]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	code, _, stderr = p.run(in, "--dir", ca, "apply", planPath, "--key-dir", keys)
	if code != 5 || !strings.Contains(stderr, "not a terminal") {
		t.Errorf("a file on standard input: exit %d, stderr %q; want 5", code, stderr)
	}
	// A character device that is not a terminal counts as one for the program, and gives no line: it
	// is not a confirmation either.
	for _, dev := range []string{"/dev/null", "/dev/zero"} {
		d, err := os.Open(dev)
		if err != nil {
			continue
		}
		code, _, stderr = p.run(d, "--dir", ca, "apply", planPath, "--key-dir", keys)
		_ = d.Close()
		if code != 5 || !strings.Contains(stderr, "not confirmed") {
			t.Errorf("%s on standard input: exit %d, stderr %q; want 5", dev, code, stderr)
		}
	}
	// A closed standard input is not confirmed either.
	code, _, _ = p.run(nil, "--dir", ca, "apply", planPath, "--key-dir", keys)
	if code != 5 {
		t.Errorf("an empty standard input: exit %d, want 5", code)
	}
	if apTreeOf(t, ca) != before || apTreeOf(t, keys) != keysBefore {
		t.Error("a refused confirmation changed the bundle or the key directory")
	}
	// The same plan, confirmed by flag, still runs.
	if code, _, stderr := p.run(nil, "--dir", ca, "apply", planPath, "--key-dir", keys, "--confirm", digest); code != 0 {
		t.Errorf("the flag after the refusals: exit %d, %s", code, stderr)
	}
}

// openPty makes a pseudo terminal and returns its two ends.
func openPty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo terminal: %v", err)
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		_ = m.Close()
		t.Skipf("no pseudo terminal: %v", e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		_ = m.Close()
		t.Skipf("no pseudo terminal: %v", e)
	}
	s, err := os.OpenFile("/dev/pts/"+itoa(int(n)), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = m.Close()
		t.Skipf("no pseudo terminal: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(); _ = s.Close() })
	return m, s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}

func TestProgramApplyConfirmedByTypingAtATerminal(t *testing.T) {
	for _, upper := range []bool{false, true} {
		name := "lower case"
		if upper {
			name = "upper case"
		}
		t.Run(name, func(t *testing.T) {
			p := apProgram{t: t, exe: buildForCheck(t), dir: t.TempDir()}
			ca, keys, planPath, digest := apFirst(t, p)
			master, slave := openPty(t)
			typed := digest[:8]
			if upper {
				typed = strings.ToUpper(typed)
			}
			go func() {
				// The prompt is on standard error, which is not the terminal here; the line waits in the
				// terminal until the program reads it.
				time.Sleep(200 * time.Millisecond)
				_, _ = io.WriteString(master, typed+"\n")
			}()
			code, stdout, stderr := p.run(slave, "--dir", ca, "apply", planPath, "--key-dir", keys)
			if code != 0 {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if !strings.HasPrefix(stdout, "history: 1 ceremony records, end ") || strings.Count(stdout, "\n") != 1 {
				t.Errorf("standard output = %q, want only the end line", stdout)
			}
			if !strings.Contains(stderr, "confirmed by typing") {
				t.Errorf("standard error: %q", stderr)
			}
			rec, err := os.ReadFile(filepath.Join(ca, strings.TrimSuffix(planPath, "plan.json")+"record.json"))
			if err != nil || !strings.Contains(string(rec), `"by":"typed"`) {
				t.Errorf("the record does not say typed: %v %s", err, rec)
			}
		})
	}
	t.Run("a wrong line at a terminal", func(t *testing.T) {
		p := apProgram{t: t, exe: buildForCheck(t), dir: t.TempDir()}
		ca, keys, planPath, digest := apFirst(t, p)
		master, slave := openPty(t)
		wrong := "ffffffff"
		if strings.HasPrefix(digest, wrong) {
			wrong = "00000000"
		}
		go func() {
			time.Sleep(200 * time.Millisecond)
			_, _ = io.WriteString(master, wrong+"\n")
		}()
		before := apTreeOf(t, ca)
		code, stdout, stderr := p.run(slave, "--dir", ca, "apply", planPath, "--key-dir", keys)
		if code != 5 || stdout != "" || !strings.Contains(stderr, "not confirmed") {
			t.Errorf("exit %d, stdout %q, stderr %q; want 5", code, stdout, stderr)
		}
		if apTreeOf(t, ca) != before {
			t.Error("a wrong line changed the bundle")
		}
	})
}
