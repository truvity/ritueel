package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two faults at once, among the four inputs. The rule (the page: "Every file is read before any check
// runs"): the files are read in the order held list, FILE, .jws, CA bundle. A file that is not there
// or cannot be read, and the held list in any fault, ends the run with exit code 1 first, and the
// message is the first such file in that order. Otherwise a FILE or a .jws that is there and wrong is
// the refusal malformed, and only then a bundle that is there and wrong is ca-bundle-mismatch.

type vpair struct {
	file   string // the name of the file in the scene
	prefix string // the start of the message of a failure of that input
}

var vorder = []vpair{
	{"held.json", "cannot read the held list: "},
	{"cand.json", "cannot read the root list: "},
	{"cand.jws", "cannot read the signature, the .jws beside the list: "},
	{"bundle.pem", "cannot read the CA bundle: "},
}

func TestEveryPairOfFaultsAmongTheFourInputs(t *testing.T) {
	m := vloadManifest(t)
	scene, bundle, _ := m.bundleScene(t)
	goods := map[string][]byte{"cand.json": scene.candBytes, "cand.jws": scene.jwsBytes, "held.json": scene.heldBytes, "bundle.pem": bundle}
	missing := func(t *testing.T, dir, name string) {}
	link := func(t *testing.T, dir, name string) {
		target := vwrite(t, t.TempDir(), "target", goods[name])
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatalf("cannot make a symbolic link: %v", err)
		}
	}
	kinds := []struct {
		name string
		make func(*testing.T, string, string)
		gone bool // not there
	}{{"missing", missing, true}, {"a link", link, false}}
	ran := 0
	for i := range vorder {
		for j := i + 1; j < len(vorder); j++ {
			for _, ki := range kinds {
				for _, kj := range kinds {
					a, b := vorder[i], vorder[j]
					t.Run(a.file+" "+ki.name+" and "+b.file+" "+kj.name, func(t *testing.T) {
						ran++
						dir := t.TempDir()
						for name, data := range goods {
							if name != a.file && name != b.file {
								vwrite(t, dir, name, data)
							}
						}
						ki.make(t, dir, a.file)
						kj.make(t, dir, b.file)
						faults := map[string]bool{a.file: ki.gone, b.file: kj.gone} // file -> not there
						args := []string{"--output", "json", "verify", "root-list", filepath.Join(dir, "cand.json"), "--held", filepath.Join(dir, "held.json"), "--ca-bundle", filepath.Join(dir, "bundle.pem")}
						r := vrunAt(t, scene.clock, args...)
						// The expectation, worked out from the rule above.
						var failure string
						for _, in := range vorder {
							gone, faulty := faults[in.file]
							if faulty && (gone || in.file == "held.json") {
								failure = in.prefix
								break
							}
						}
						switch {
						case failure != "":
							line := strings.TrimSuffix(strings.TrimPrefix(r.stderr, "ritueel: "), "\n")
							if r.code != ExitFailure || !strings.HasPrefix(line, failure) || r.stdout != failedObject(line) {
								t.Fatalf("exit %d, want 1 with a message that begins %q\nstdout %q\nstderr %q", r.code, failure, r.stdout, r.stderr)
							}
						case faults["cand.json"] == false && hasKey(faults, "cand.json"), faults["cand.jws"] == false && hasKey(faults, "cand.jws"):
							if r.code != ExitRefused || r.stdout != refusedObject("malformed") || !strings.HasPrefix(r.stderr, "ritueel: refused: malformed (cand.") {
								t.Fatalf("exit %d, want 3 malformed\nstdout %q\nstderr %q", r.code, r.stdout, r.stderr)
							}
						default: // only the bundle is there and wrong
							if r.code != ExitRefused || r.stdout != refusedObject("ca-bundle-mismatch") || !strings.HasPrefix(r.stderr, "ritueel: refused: ca-bundle-mismatch (bundle.pem is a symbolic link") {
								t.Fatalf("exit %d, want 3 ca-bundle-mismatch\nstdout %q\nstderr %q", r.code, r.stdout, r.stderr)
							}
						}
						terminalSafe(t, r)
					})
				}
			}
		}
	}
	if ran != 6*4 {
		t.Fatalf("ran %d pairs, want 24", ran)
	}
}

func hasKey(m map[string]bool, k string) bool { _, ok := m[k]; return ok }

func TestTheBundleOfAListThatIsRefusedIsNotJudged(t *testing.T) {
	m := vloadManifest(t)
	c := m.refusing(t, "rollback")
	s := vstage(t, m, c)
	for name, make := range map[string]func(dir string) string{
		"a link": func(dir string) string {
			target := vwrite(t, t.TempDir(), "target", []byte("x"))
			p := filepath.Join(dir, "bundle.pem")
			if err := os.Symlink(target, p); err != nil {
				t.Fatalf("cannot make a symbolic link: %v", err)
			}
			return p
		},
		"a folder": func(dir string) string {
			p := filepath.Join(dir, "bundle.pem")
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			return p
		},
		"text that is no bundle": func(dir string) string { return vwrite(t, dir, "bundle.pem", []byte("no")) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			bs := *s
			bs.bundle = make(dir)
			r := vrunAt(t, s.clock, bs.args("json")...)
			if r.code != ExitRefused || r.stdout != refusedObject("rollback") || !strings.Contains(r.stderr, "refused: rollback (check 6") {
				t.Errorf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
			}
		})
	}
}

func TestTheBundleNameAndFolderFollowTheReader(t *testing.T) {
	m := vloadManifest(t)
	scene, bundle, _ := m.bundleScene(t)
	good := func(dir string) {
		vwrite(t, dir, "cand.json", scene.candBytes)
		vwrite(t, dir, "cand.jws", scene.jwsBytes)
		vwrite(t, dir, "held.json", scene.heldBytes)
	}
	run := func(path string) result {
		dir := filepath.Dir(scene.cand)
		_ = dir
		return vrunAt(t, scene.clock, "--output", "json", "verify", "root-list", scene.cand, "--held", scene.held, "--ca-bundle", path)
	}
	for name, file := range map[string]string{"a space": "my bundle.pem", "a non-ASCII letter": "b\u00fcndle.pem", "a line feed": "a\nb.pem", "a control character": "a\x01b.pem", "a backslash": "a\\b.pem"} {
		t.Run("a bundle named with "+name+" is a failure", func(t *testing.T) {
			p := filepath.Join(scene.dir, file)
			if err := os.WriteFile(p, bundle, 0o600); err != nil {
				t.Fatalf("this file system cannot make the name: %v", err)
			}
			r := run(p)
			if r.code != ExitFailure || !strings.HasPrefix(r.stderr, "ritueel: cannot read the CA bundle: ") {
				t.Fatalf("exit %d stderr %q", r.code, r.stderr)
			}
			terminalSafe(t, r)
		})
	}
	t.Run("a link as the last folder of the bundle's path is a failure; a link before it is followed", func(t *testing.T) {
		real := filepath.Join(t.TempDir(), "sub")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		vwrite(t, real, "bundle.pem", bundle)
		outer := t.TempDir()
		if err := os.Symlink(real, filepath.Join(outer, "release")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Dir(real), filepath.Join(outer, "current")); err != nil {
			t.Fatal(err)
		}
		if r := run(filepath.Join(outer, "release", "bundle.pem")); r.code != ExitFailure || !strings.HasPrefix(r.stderr, "ritueel: cannot read the CA bundle: ") {
			t.Errorf("last folder: exit %d stderr %q", r.code, r.stderr)
		}
		if r := run(filepath.Join(outer, "current", "sub", "bundle.pem")); r.code != ExitOK {
			t.Errorf("a link before: exit %d stderr %q", r.code, r.stderr)
		}
	})
	t.Run("a bundle and a list with the same base name in two folders are both named", func(t *testing.T) {
		// The name is the last element of the path: the list is cand.json here, and the bundle is given
		// the same name in another folder. Both entries are there, with the digests of their own bytes.
		dir := t.TempDir()
		good(dir)
		other := t.TempDir()
		same := vwrite(t, other, "cand.json", bundle)
		r := vrunAt(t, scene.clock, "--output", "json", "verify", "root-list", filepath.Join(dir, "cand.json"), "--held", filepath.Join(dir, "held.json"), "--ca-bundle", same)
		want := doneObject(vheldWarnings(t, m, scene.caseRecord, scene.clock), [2]string{"cand.json", sum(scene.candBytes)}, [2]string{"cand.jws", sum(scene.jwsBytes)}, [2]string{"cand.json", sum(bundle)})
		if r.code != ExitOK || r.stdout != want {
			t.Fatalf("exit %d\nstdout %q\nwant   %q\nstderr %q", r.code, r.stdout, want, r.stderr)
		}
	})
	t.Run("the digest of the bundle is of the bytes that were judged", func(t *testing.T) {
		dir := t.TempDir()
		good(dir)
		bp := vwrite(t, dir, "bundle.pem", bundle)
		r := vrunAt(t, scene.clock, "--output", "json", "verify", "root-list", filepath.Join(dir, "cand.json"), "--held", filepath.Join(dir, "held.json"), "--ca-bundle", bp)
		if r.code != ExitOK || !strings.Contains(r.stdout, `{"name":"bundle.pem","sha256":"`+sum(bundle)+`"}]`) {
			t.Fatalf("exit %d stdout %q", r.code, r.stdout)
		}
	})
	t.Run("a refused, a missing and a link bundle have no checked", func(t *testing.T) {
		dir := t.TempDir()
		good(dir)
		for name, p := range map[string]string{
			"a refused bundle": vwrite(t, dir, "bad.pem", []byte("# trust-sequence: 1\n")),
			"a missing bundle": filepath.Join(dir, "none.pem"),
		} {
			r := vrunAt(t, scene.clock, "--output", "json", "verify", "root-list", filepath.Join(dir, "cand.json"), "--held", filepath.Join(dir, "held.json"), "--ca-bundle", p)
			if r.code == ExitOK || strings.Contains(r.stdout, "checked") || strings.Contains(r.stdout, sum(bundle)) {
				t.Errorf("%s: exit %d stdout %q", name, r.code, r.stdout)
			}
		}
	})
}
