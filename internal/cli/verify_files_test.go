package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

// One rule for the files of the candidate, FILE and the .jws beside it, as the page's table says. A
// file that is not there, or cannot be read (no permission, an I/O error), is "could not check":
// exit code 1. A file that is there and is not acceptable (a link, a FIFO, a device, a folder, too
// large) is "checked and no": exit code 3 with the code malformed. The CA bundle follows the same
// rule with the code ca-bundle-mismatch, and --held keeps exit code 1 for every fault. The reader is
// the strict one: it follows no link at the file and takes a name of ASCII letters, digits, dot,
// hyphen and underscore.

func failedObject(msg string) string {
	return fmt.Sprintf(`{"output":1,"command":"verify","exit_code":1,"outcome":"failed","warnings":[],"error":%q}`+"\n", msg)
}

// vbundle finds an accepting case of the manifest and a CA bundle that goes with its candidate, by
// the manifest's own words: the bundle's sequence and its roots, which are labels of the manifest.
func (m *vmanifest) bundleScene(t *testing.T) (*vscene, []byte, string) {
	t.Helper()
	for _, c := range m.Cases {
		if c.Expect != "accept" || c.Held == nil {
			continue
		}
		data, _ := m.bytesOf(t, *c.Candidate)
		l, err := rootlist.ParseList(data)
		if err != nil {
			continue
		}
		for _, b := range m.Bundles {
			var want []string
			for _, label := range b.Roots {
				want = append(want, m.pin(t, label))
			}
			if b.Sequence == l.Sequence && slices.Equal(l.Pins(), want) {
				s := vstage(t, m, c)
				bundle, _ := os.ReadFile(filepath.Join(rootOf(t), vecDir, b.File))
				return s, bundle, b.File
			}
		}
	}
	t.Fatal("no accepting case with a held list has a CA bundle in the manifest")
	return nil, nil, ""
}

func rootOf(t testing.TB) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		if p := filepath.Dir(d); p != d {
			d = p
			continue
		}
		t.Fatal("no go.mod")
	}
}

// the four inputs of the command and what each is called in the line of an error that is a failure.
type vinput struct {
	name   string
	file   string // the name of the file in the folder of the scene
	prefix string // the start of the message of a failure
	cand   bool   // a file that follows the rule of the candidate's files: there and wrong is a refusal
	reason string // the reason code of that refusal
}

var vinputs = []vinput{
	{"FILE", "cand.json", "cannot read the root list: ", true, "malformed"},
	{"the .jws", "cand.jws", "cannot read the signature, the .jws beside the list: ", true, "malformed"},
	{"--held", "held.json", "cannot read the held list: ", false, ""},
	{"--ca-bundle", "bundle.pem", "cannot read the CA bundle: ", true, "ca-bundle-mismatch"},
}

func TestEveryFaultOfEveryInputHasItsExitCode(t *testing.T) {
	m := vloadManifest(t)
	scene, bundle, _ := m.bundleScene(t)
	goods := map[string][]byte{"cand.json": scene.candBytes, "cand.jws": scene.jwsBytes, "held.json": scene.heldBytes, "bundle.pem": bundle}
	for _, in := range vinputs {
		for _, f := range vfaults() {
			t.Run(in.name+": "+f.name, func(t *testing.T) {
				dir := t.TempDir()
				for name, data := range goods {
					if name != in.file {
						vwrite(t, dir, name, data)
					}
				}
				f.make(t, dir, in.file, goods[in.file])
				args := []string{"verify", "root-list", filepath.Join(dir, "cand.json"), "--held", filepath.Join(dir, "held.json"), "--ca-bundle", filepath.Join(dir, "bundle.pem")}
				js := vfifoGuard(t, func() result { return vrunAt(t, scene.clock, append([]string{"--output", "json"}, args...)...) })
				txt := vfifoGuard(t, func() result { return vrunAt(t, scene.clock, append([]string{"--output", "text"}, args...)...) })
				want := ExitFailure
				if in.cand {
					want = f.candidate
				}
				if js.code != want || txt.code != want {
					t.Fatalf("exit %d (json) %d (text), want %d\nstderr %q", js.code, txt.code, want, js.stderr)
				}
				if txt.stdout != "" || txt.stderr != js.stderr {
					t.Errorf("text: stdout %q stderr %q (json stderr %q)", txt.stdout, txt.stderr, js.stderr)
				}
				terminalSafe(t, js)
				if want == ExitRefused {
					detail := strings.Replace(f.detail, "%s", in.file, 1)
					if js.stdout != refusedObject(in.reason) || js.stderr != "ritueel: refused: "+in.reason+" ("+detail+")\n" {
						t.Errorf("the refusal: stdout %q stderr %q, want the detail %q", js.stdout, js.stderr, detail)
					}
					return
				}
				// A failure: the object has the member error and no reasons, and says what could not be read.
				line := strings.TrimSuffix(strings.TrimPrefix(js.stderr, "ritueel: "), "\n")
				if !strings.HasPrefix(line, in.prefix) || js.stdout != failedObject(line) || strings.Contains(line, "\n") {
					t.Errorf("the failure: stdout %q stderr %q, want a message that begins %q", js.stdout, js.stderr, in.prefix)
				}
			})
		}
	}
}

func TestAFaultOfTheInputsIsTheOneThatCountsWhenThereAreTwo(t *testing.T) {
	m := vloadManifest(t)
	scene, bundle, _ := m.bundleScene(t)
	_ = bundle
	link := func(dir, name string) {
		target := vwrite(t, t.TempDir(), "target", scene.candBytes)
		_ = os.Remove(filepath.Join(dir, name))
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatalf("cannot make a symbolic link: %v", err)
		}
	}
	run := func(t *testing.T, mutate func(dir string)) result {
		dir := t.TempDir()
		vwrite(t, dir, "cand.json", scene.candBytes)
		vwrite(t, dir, "cand.jws", scene.jwsBytes)
		vwrite(t, dir, "held.json", scene.heldBytes)
		mutate(dir)
		return vfifoGuard(t, func() result {
			return vrunAt(t, scene.clock, "--output", "json", "verify", "root-list", filepath.Join(dir, "cand.json"), "--held", filepath.Join(dir, "held.json"))
		})
	}
	for name, c := range map[string]struct {
		mutate func(dir string)
		code   ExitCode
	}{
		"FILE is missing and the .jws is a link": {func(d string) { _ = os.Remove(filepath.Join(d, "cand.json")); link(d, "cand.jws") }, ExitFailure},
		"FILE is a link and the .jws is missing": {func(d string) {
			_ = os.Remove(filepath.Join(d, "cand.json"))
			link(d, "cand.json")
			_ = os.Remove(filepath.Join(d, "cand.jws"))
		}, ExitFailure},
		"both are links": {func(d string) {
			_ = os.Remove(filepath.Join(d, "cand.json"))
			_ = os.Remove(filepath.Join(d, "cand.jws"))
			link(d, "cand.json")
			link(d, "cand.jws")
		}, ExitRefused},
		"the .jws is a link and the held list is missing": {func(d string) {
			_ = os.Remove(filepath.Join(d, "cand.jws"))
			link(d, "cand.jws")
			_ = os.Remove(filepath.Join(d, "held.json"))
		}, ExitFailure},
		"FILE is a link and the held list is a link": {func(d string) {
			_ = os.Remove(filepath.Join(d, "cand.json"))
			link(d, "cand.json")
			_ = os.Remove(filepath.Join(d, "held.json"))
			link(d, "held.json")
		}, ExitFailure},
	} {
		t.Run(name, func(t *testing.T) {
			r := run(t, c.mutate)
			if r.code != c.code {
				t.Fatalf("exit %d, want %d\nstderr %q", r.code, c.code, r.stderr)
			}
		})
	}
	t.Run("a link in a folder of the path is followed; the last folder is not", func(t *testing.T) {
		real := filepath.Join(t.TempDir(), "sub")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		vwrite(t, real, "cand.json", scene.candBytes)
		vwrite(t, real, "cand.jws", scene.jwsBytes)
		hp := vwrite(t, real, "held.json", scene.heldBytes)
		outer := t.TempDir()
		if err := os.Symlink(filepath.Dir(real), filepath.Join(outer, "current")); err != nil { // current -> the folder that holds sub
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Join(outer, "release")); err != nil { // release -> sub, itself
			t.Fatal(err)
		}
		// A link as the last folder of the path of FILE is refused by the reader (the command could not
		// open the folder); a link before the last folder is followed.
		last := vrunAt(t, scene.clock, "verify", "root-list", filepath.Join(outer, "release", "cand.json"), "--held", hp)
		if last.code != ExitFailure || !strings.HasPrefix(last.stderr, "ritueel: cannot read the root list: ") {
			t.Errorf("a link as the last folder: exit %d stderr %q", last.code, last.stderr)
		}
		followed := vrunAt(t, scene.clock, "verify", "root-list", filepath.Join(outer, "current", "sub", "cand.json"), "--held", hp)
		if followed.code != ExitOK {
			t.Errorf("a link before the last folder: exit %d stderr %q", followed.code, followed.stderr)
		}
	})
}

func TestTheSizesOfTheInputs(t *testing.T) {
	m := vloadManifest(t)
	scene, bundle, _ := m.bundleScene(t)
	pad := func(data []byte, n int) []byte {
		return append(slices.Clone(data), bytes.Repeat([]byte{' '}, n-len(data))...)
	}
	const mib8 = 8 << 20
	run := func(t *testing.T, name string, data []byte, flag string) result {
		dir := t.TempDir()
		files := map[string][]byte{"cand.json": scene.candBytes, "cand.jws": scene.jwsBytes}
		if scene.held != "" {
			files["held.json"] = scene.heldBytes
		}
		files["bundle.pem"] = bundle
		files[name] = data
		for n, d := range files {
			vwrite(t, dir, n, d)
		}
		args := []string{"--output", "json", "verify", "root-list", filepath.Join(dir, "cand.json")}
		if scene.held != "" {
			args = append(args, "--held", filepath.Join(dir, "held.json"))
		} else {
			args = append(args, scene.hostArgs()...)
		}
		args = append(args, flag, filepath.Join(dir, "bundle.pem"))
		return vrunAt(t, scene.clock, args...)
	}
	_ = run
	cases := []struct {
		name         string
		file         string
		size         int
		code         ExitCode
		reason       string // for a refusal
		stderrPrefix string
	}{
		{"FILE of 300 KiB, a list that its signature does not cover", "cand.json", 300 << 10, ExitRefused, "signature-invalid", "ritueel: refused: signature-invalid (check 3: "},
		{"FILE of exactly 8 MiB", "cand.json", mib8, ExitRefused, "signature-invalid", "ritueel: refused: signature-invalid (check 3: "},
		{"FILE of 8 MiB and one byte", "cand.json", mib8 + 1, ExitRefused, "malformed", "ritueel: refused: malformed (cand.json is longer than 8388608 bytes)"},
		{"the .jws of 300 KiB", "cand.jws", 300 << 10, ExitRefused, "malformed", "ritueel: refused: malformed (check 1: "},
		{"the .jws of exactly 8 MiB", "cand.jws", mib8, ExitRefused, "malformed", "ritueel: refused: malformed (check 1: "},
		{"the .jws of 8 MiB and one byte", "cand.jws", mib8 + 1, ExitRefused, "malformed", "ritueel: refused: malformed (cand.jws is longer than 8388608 bytes)"},
		{"the CA bundle of 300 KiB", "bundle.pem", 300 << 10, ExitRefused, "ca-bundle-mismatch", "ritueel: refused: ca-bundle-mismatch ("},
		{"the CA bundle of exactly 8 MiB", "bundle.pem", mib8, ExitRefused, "ca-bundle-mismatch", "ritueel: refused: ca-bundle-mismatch ("},
		{"the CA bundle of 8 MiB and one byte", "bundle.pem", mib8 + 1, ExitRefused, "ca-bundle-mismatch", "ritueel: refused: ca-bundle-mismatch (bundle.pem is longer than 8388608 bytes)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := map[string][]byte{"cand.json": scene.candBytes, "cand.jws": scene.jwsBytes, "bundle.pem": bundle}[c.file]
			r := run(t, c.file, pad(data, c.size), "--ca-bundle")
			if r.code != c.code || !strings.HasPrefix(r.stderr, c.stderrPrefix) || r.stdout == "" {
				t.Fatalf("exit %d, want %d\nstderr %q\nstdout %q", r.code, c.code, r.stderr, r.stdout)
			}
			if c.code == ExitRefused && !strings.Contains(r.stdout, `"reasons":["`+c.reason+`"]`) {
				t.Errorf("stdout %q", r.stdout)
			}
			terminalSafe(t, r)
		})
	}
	if scene.held != "" {
		for _, c := range []struct {
			name string
			size int
		}{{"the held list of 300 KiB", 300 << 10}, {"the held list of exactly 8 MiB", mib8}, {"the held list of 8 MiB and one byte", mib8 + 1}} {
			t.Run(c.name, func(t *testing.T) {
				r := run(t, "held.json", pad(scene.heldBytes, c.size), "--ca-bundle")
				if r.code != ExitFailure || !strings.HasPrefix(r.stderr, "ritueel: cannot read the held list: ") && !strings.HasPrefix(r.stderr, "ritueel: the held list cannot be used: ") {
					t.Fatalf("exit %d stderr %q", r.code, r.stderr)
				}
			})
		}
	}
}

func TestTheHeldListThatCannotBeUsedIsAFailure(t *testing.T) {
	m := vloadManifest(t)
	s := vstage(t, m, m.newAgainstHeld(t))
	for name, data := range map[string][]byte{
		"empty":                      nil,
		"not JSON":                   []byte("not json"),
		"a list of version 2":        bytes.Replace(s.heldBytes, []byte(`"version":1`), []byte(`"version":2`), 1),
		"a list with a member added": bytes.Replace(s.heldBytes, []byte(`"version":1`), []byte(`"version":1,"x":1`), 1),
		"a list of no root keys":     []byte(`{"version":1}`),
	} {
		t.Run(name, func(t *testing.T) {
			if len(data) > 0 && bytes.Equal(data, s.heldBytes) {
				t.Fatalf("the edit of %q changed nothing", name)
			}
			p := vwrite(t, s.dir, "bad-held.json", data)
			r := vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.cand, "--held", p)
			if r.code != ExitFailure || !strings.HasPrefix(r.stderr, "ritueel: the held list cannot be used: ") || r.stdout != failedObject(strings.TrimSuffix(strings.TrimPrefix(r.stderr, "ritueel: "), "\n")) {
				t.Fatalf("exit %d\nstdout %q\nstderr %q", r.code, r.stdout, r.stderr)
			}
		})
	}
}

func TestANameThatTheReaderDoesNotTakeIsAFailureNotARefusal(t *testing.T) {
	m := vloadManifest(t)
	s := vstage(t, m, m.newAgainstHeld(t))
	for name, file := range map[string]string{
		"a space":                  "my list.json",
		"a non-ASCII letter":       "\u00e9.json",
		"a line feed":              "a\nb.json",
		"a control character":      "a\x01b.json",
		"a backslash":              "a\\b.json",
		"an escape sequence":       "\x1b[31m.json",
		"a look-alike letter":      "l\u0456st.json",
		"a colon":                  "a:b.json",
		"a bracket":                "a(1).json",
		"a name that is not UTF-8": "a\xffb.json",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(s.dir, file)
			if err := os.WriteFile(p, s.candBytes, 0o600); err != nil {
				t.Fatalf("this file system cannot make the name: %v", err)
			}
			base := strings.TrimSuffix(file, ".json")
			vwrite(t, s.dir, base+".jws", s.jwsBytes)
			for _, mode := range []string{"text", "json"} {
				r := vrunAt(t, s.clock, "--output", mode, "verify", "root-list", p, "--held", s.held)
				if r.code != ExitFailure || !strings.HasPrefix(r.stderr, "ritueel: cannot read the root list: ") || (mode == "text" && r.stdout != "") {
					t.Fatalf("%s: exit %d stdout %q stderr %q", mode, r.code, r.stdout, r.stderr)
				}
				terminalSafe(t, r)
				// As the held list and as the bundle, too.
				h := vrunAt(t, s.clock, "--output", mode, "verify", "root-list", s.cand, "--held", p)
				if h.code != ExitFailure || !strings.HasPrefix(h.stderr, "ritueel: cannot read the held list: ") {
					t.Fatalf("held, %s: exit %d stderr %q", mode, h.code, h.stderr)
				}
				terminalSafe(t, h)
			}
		})
	}
}
