//go:build linux || darwin

package cli

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/testrepo"
)

// The keyring file of the newest trust set and "check request": a list that pins OpenPGP primaries gives the checker
// the primaries of the file, with no delegation and with a delegation of the type openpgp-subkey. A set with no file,
// or a file that is refused, is exit code 1 with one sentence: the request is neither accepted nor refused, and the
// command never goes on with no primaries (docs/reference/keyring-package.md, "The first form of the keyring file").

const (
	noKeyringSentence = "the newest trust set " + crqTrustSet + " pins OpenPGP primaries and holds no keyring.gpg"
	refusedSentence   = "keyring.gpg of the newest trust set " + crqTrustSet + " is refused: "
	keyringAt         = "trust/" + crqTrustSet + "/" + crqKeyringFile
)

// stoppedLine is the line of standard error of a request that is not judged for the reason given.
func stoppedLine(stem, reason string) string {
	return "ritueel: request " + stem + " is not accepted and not refused: " + reason + "\n"
}

// crqBundleWithKeyring is the bundle of a case whose keyring file is as given (nil: no file).
func crqBundleWithKeyring(t testing.TB, m crqManifest, c crqCase, keyring []byte) string {
	t.Helper()
	tree := crqBundleTree(t, m, c)
	if keyring == nil {
		delete(tree, keyringAt)
	} else {
		tree[keyringAt] = keyring
	}
	dir := t.TempDir()
	crqWrite(t, dir, tree)
	return dir
}

func TestASetThatPinsPrimariesAndHoldsNoKeyringFileStopsTheCommandWithOneSentence(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, tc := range []struct {
		id           string
		withDeleg    bool
		stopsAtFile  bool // the command reads the keyring file for this run
		wantExitCode ExitCode
	}{
		{"pgp-software-valid", true, true, ExitFailure},
		{"pgp-software-valid", false, true, ExitFailure},
		{"pgp-backsig-missing", true, true, ExitFailure},
		{"x509-software-valid", false, true, ExitFailure}, // the precedent of the roots: a bad trust set stops every run
		{"x509-csr-bad-signature", false, true, ExitFailure},
		// An x509-intermediate delegation is given no primaries, so the file is not read for it.
		{"x509-software-valid", true, false, ExitOK},
		{"x509-csr-bad-signature", true, false, ExitRefused},
	} {
		name := tc.id + "/delegation=" + map[bool]string{true: "yes", false: "no"}[tc.withDeleg]
		t.Run(name, func(t *testing.T) {
			c := m.byID(t, tc.id)
			dir := crqBundleWithKeyring(t, m, c, nil)
			before := crqSnapshot(t, dir)
			args := []string{"check", "request", c.stem(t), "--dir", dir}
			if tc.withDeleg {
				args = append(args, "--delegation", crqDelegation)
			}
			text := crqRun(t, now, args...)
			js := crqRun(t, now, append(args, "--output", "json")...)
			for _, r := range []result{text, js} {
				if r.code != tc.wantExitCode {
					t.Fatalf("exit code %d, want %d\n%s%s", int(r.code), int(tc.wantExitCode), r.stdout, r.stderr)
				}
				if tc.stopsAtFile && r.stderr != stoppedLine(c.stem(t), noKeyringSentence) {
					t.Errorf("standard error = %q, want %q", r.stderr, stoppedLine(c.stem(t), noKeyringSentence))
				}
				if !tc.stopsAtFile && strings.Contains(r.stderr, "keyring") {
					t.Errorf("standard error = %q: the keyring file was named for a run that does not read it", r.stderr)
				}
			}
			if tc.stopsAtFile {
				if text.stdout != "" {
					t.Errorf("text mode: standard output = %q, want nothing", text.stdout)
				}
				obj := object(t, js.stdout)
				wantObject(t, obj, map[string]any{"output": 1, "command": "check", "exit_code": 1, "outcome": "failed", "error": "request " + c.stem(t) + " is not accepted and not refused: " + noKeyringSentence})
				for _, k := range []string{"checks", "reasons"} {
					if _, ok := obj[k]; ok {
						t.Errorf("the object has %s: %s", k, js.stdout)
					}
				}
			}
			crqSame(t, "check request", before, crqSnapshot(t, dir))
		})
	}
}

// A keyring file that the reader refuses, or that cannot be read, is one sentence with the cause of the reader: exit
// code 1, for an OpenPGP request and for an x509 request alike, with no delegation and with an openpgp-subkey delegation.
func TestAKeyringFileThatIsRefusedStopsTheCommandWithOneSentenceAndTheCauseOfTheReader(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	a, b, z := crqKeyring(t, "a"), crqKeyring(t, "b"), crqKeyring(t, "z")
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for _, tc := range []struct {
		name string
		file []byte
		want string // in the cause
	}{
		{"b then a", cat(b, a), "out of order: certificate 1 (label A) holds the key of position 2 (label B)"},
		{"a alone", a, "missing"},
		{"z for b", cat(a, z), "not on the list"},
		{"a, b and z", cat(a, b, z), "one too many"},
		{"an empty file", []byte{}, "empty"},
		{"armour", []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"), "armour"},
		{"text", []byte("not a keyring\n"), ""},
		{"a cut file", cat(a, b)[:len(a)+len(b)-3], ""},
		{"a byte after the last packet", cat(a, b, []byte{0}), ""},
		{"a megabyte of zero bytes", make([]byte, 1<<20+1), "longer than"},
	} {
		for _, id := range []string{"pgp-software-valid", "x509-software-valid"} {
			for _, withDeleg := range []bool{true, false} {
				if id == "x509-software-valid" && withDeleg {
					continue // an x509 delegation is given no primaries: the file is not read
				}
				t.Run(tc.name+"/"+id+"/delegation="+map[bool]string{true: "yes", false: "no"}[withDeleg], func(t *testing.T) {
					c := m.byID(t, id)
					dir := crqBundleWithKeyring(t, m, c, tc.file)
					before := crqSnapshot(t, dir)
					args := []string{"check", "request", c.stem(t), "--dir", dir}
					if withDeleg {
						args = append(args, "--delegation", crqDelegation)
					}
					for _, mode := range [][]string{nil, {"--output", "json"}} {
						r := crqRun(t, now, append(args, mode...)...)
						prefix := "ritueel: request " + c.stem(t) + " is not accepted and not refused: " + refusedSentence
						if r.code != ExitFailure || !strings.HasPrefix(r.stderr, prefix) || strings.Count(r.stderr, "\n") != 1 || !onlyPrintable(r.stderr) || !strings.Contains(r.stderr, tc.want) || len(r.stderr) > 700 {
							t.Fatalf("%v: (%d, %q), want exit code 1 and one printable line that starts with %q and holds %q", mode, int(r.code), r.stderr, prefix, tc.want)
						}
						if strings.Contains(r.stdout, "accepted") && mode == nil {
							t.Errorf("standard output = %q", r.stdout)
						}
					}
					crqSame(t, "check request", before, crqSnapshot(t, dir))
				})
			}
		}
	}
}

// A keyring file that is a link, a folder, a pipe or too large for the reader of the bundle is refused, never taken
// for a missing file, and a pipe is not waited on.
func TestAKeyringFileThatIsNotAPlainFileIsRefusedAndNotTakenForAMissingOne(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	c := m.byID(t, "pgp-software-valid")
	for name, place := range map[string]func(t *testing.T, at string){
		"a link to a good file": func(t *testing.T, at string) {
			if err := os.WriteFile(filepath.Join(filepath.Dir(at), "real.gpg"), crqKeyring(t, "a", "b"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real.gpg", at); err != nil {
				t.Fatal(err)
			}
		},
		"a dangling link": func(t *testing.T, at string) {
			if err := os.Symlink("nowhere", at); err != nil {
				t.Fatal(err)
			}
		},
		"a folder": func(t *testing.T, at string) {
			if err := os.Mkdir(at, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"a pipe": func(t *testing.T, at string) {
			if err := syscall.Mkfifo(at, 0o644); err != nil {
				t.Skipf("no pipe here: %v", err)
			}
		},
		"a file over what fsx reads": func(t *testing.T, at string) {
			if err := os.WriteFile(at, make([]byte, fsx.MaxReadSize+1), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := crqBundleWithKeyring(t, m, c, nil)
			place(t, filepath.Join(dir, filepath.FromSlash(keyringAt)))
			before := crqSnapshot(t, dir)
			r := crqRun(t, now, "check", "request", c.stem(t), "--dir", dir, "--delegation", crqDelegation)
			prefix := "ritueel: request " + c.stem(t) + " is not accepted and not refused: " + refusedSentence
			if r.code != ExitFailure || !strings.HasPrefix(r.stderr, prefix) || strings.Contains(r.stderr, "holds no keyring.gpg") || !onlyPrintable(r.stderr) || strings.Count(r.stderr, "\n") != 1 {
				t.Errorf("(%d, %q), want exit code 1 and one line that starts with %q", int(r.code), r.stderr, prefix)
			}
			crqSame(t, "check request", before, crqSnapshot(t, dir))
		})
	}
}

// A list that pins no primary has no keyring file. The command asks for the primaries only when the list pins some, so
// a file in such a set is not read by it (Bundle.Primaries refuses it, for the commands that ask), and the run is
// judged with no primaries: an OpenPGP request is then not judged, and an x509 request is judged as always.
func TestAKeyringFileInASetThatPinsNoPrimaryIsNotReadByTheCommand(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, file := range [][]byte{crqKeyring(t, "a", "b"), []byte("garbage"), nil} {
		x := m.byID(t, "x509-software-valid")
		tree := crqWithTrust(crqBundleTree(t, m, x), crqTrustWithoutPrimaries(t))
		if file != nil {
			tree[keyringAt] = file
		}
		dir := t.TempDir()
		crqWrite(t, dir, tree)
		if r := crqRun(t, now, "check", "request", x.stem(t), "--dir", dir, "--delegation", crqDelegation); r.code != ExitOK || strings.Contains(r.stderr, "keyring") {
			t.Errorf("x509 request, file %q: (%d, %q), want exit code 0 and no word about a keyring", file, int(r.code), r.stderr)
		}
		p := m.byID(t, "pgp-software-valid")
		tree = crqWithTrust(crqBundleTree(t, m, p), crqTrustWithoutPrimaries(t))
		if file != nil {
			tree[keyringAt] = file
		}
		dir = t.TempDir()
		crqWrite(t, dir, tree)
		r := crqRun(t, now, "check", "request", p.stem(t), "--dir", dir, "--delegation", crqDelegation)
		if r.code != ExitFailure || !strings.Contains(r.stderr, "the newest root list pins no OpenPGP primary") || strings.Contains(r.stderr, "keyring") {
			t.Errorf("openpgp request, file %q: (%d, %q), want exit code 1 and the sentence of a list that pins none", file, int(r.code), r.stderr)
		}
	}
}

// A list that gives one fingerprint to two entries is a fault of the list that no keyring file can answer. The command
// stops with exit code 1 and says so in the same plain sentence as for every other keyring fault: the request is not
// accepted and not refused.
func TestAListThatPinsOneFingerprintTwiceStopsTheCommandWithTheSentenceOfARequestThatIsNotJudged(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "pgp-software-valid")
	tree := crqBundleTree(t, m, c)
	at := "trust/" + crqTrustSet + "/root-list.json"
	tree[at] = bytes.Replace(tree[at], []byte("c4288657012230588b51fa66e0831b9c6e084f39"), []byte("6df387de63525c9dc0ec1174bd138d2c4889b79b"), 1)
	dir := t.TempDir()
	crqWrite(t, dir, tree)
	r := crqRun(t, m.clock(t), "check", "request", c.stem(t), "--dir", dir, "--delegation", crqDelegation)
	prefix := "ritueel: request " + c.stem(t) + " is not accepted and not refused: "
	if r.code != ExitFailure || !strings.HasPrefix(r.stderr, prefix) || strings.Count(r.stderr, "\n") != 1 || !onlyPrintable(r.stderr) {
		t.Errorf("(%d, %q), want exit code 1 and one line that starts with %q", int(r.code), r.stderr, prefix)
	}
}

// A primary created after the clock of the command is a fault of the configuration: exit code 1 with the words of the
// library, and never a refusal (exit code 3).
func TestAPrimaryCreatedAfterTheClockIsExitOneAndNeverARefusal(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	late := newMemRoot(t, "A", now.AddDate(0, 0, 1), true)
	for _, id := range []string{"pgp-software-valid", "x509-software-valid"} {
		c := m.byID(t, id)
		tree := crqWithTrust(crqBundleTree(t, m, c), memTrustOf([]memRoot{late}))
		dir := t.TempDir()
		crqWrite(t, dir, tree)
		before := crqSnapshot(t, dir)
		for _, args := range [][]string{{"--delegation", crqDelegation}, nil} {
			if id == "x509-software-valid" && args != nil {
				continue // beside an x509 delegation the checker holds no primaries, so the clock does not meet one
			}
			r := crqRun(t, now, append([]string{"check", "request", c.stem(t), "--dir", dir}, args...)...)
			if r.code != ExitFailure || strings.Contains(r.stderr, "refused") || !strings.Contains(r.stderr, late.fp) || !strings.Contains(r.stderr, "after the clock") || !onlyPrintable(r.stderr) {
				t.Errorf("%s %v: (%d, %q), want exit code 1 and the words that the primary %s is after the clock", id, args, int(r.code), r.stderr, late.fp)
			}
			if r.stdout != "" {
				t.Errorf("%s %v: standard output = %q", id, args, r.stdout)
			}
		}
		crqSame(t, "check request", before, crqSnapshot(t, dir))
	}
}

// A test primary and a real primary in one keyring file, and more than 16 pinned primaries, are exit code 1 with the
// sentence of the file or the count; two real primaries are a pair of one kind.
func TestAMixOfTestAndRealPrimariesAndMoreThanSixteenAreExitOne(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	c := m.byID(t, "pgp-software-valid")
	run := func(t *testing.T, roots []memRoot) result {
		t.Helper()
		dir := t.TempDir()
		crqWrite(t, dir, crqWithTrust(crqBundleTree(t, m, c), memTrustOf(roots)))
		return crqRun(t, now, "check", "request", c.stem(t), "--dir", dir, "--delegation", crqDelegation)
	}
	t.Run("a mix", func(t *testing.T) {
		r := run(t, []memRoot{newMemRoot(t, "A", memCreated, true), newMemRoot(t, "B", memCreated, false)})
		if r.code != ExitFailure || !strings.Contains(r.stderr, "mixes test and real primaries") || !strings.Contains(r.stderr, "is refused: ") {
			t.Errorf("(%d, %q)", int(r.code), r.stderr)
		}
	})
	t.Run("two real primaries are one kind", func(t *testing.T) {
		r := run(t, []memRoot{newMemRoot(t, "A", memCreated, false), newMemRoot(t, "B", memCreated, false)})
		// The checker is made; the request is not signed by these roots, so a check refuses it or it is not complete.
		if strings.Contains(r.stderr, "keyring.gpg") || strings.Contains(r.stderr, "mixes") {
			t.Errorf("(%d, %q): a pair of one kind is refused as a file", int(r.code), r.stderr)
		}
	})
	t.Run("seventeen", func(t *testing.T) {
		r := run(t, memRoots(t, 17))
		if r.code != ExitFailure || !strings.Contains(r.stderr, "17") || !strings.Contains(r.stderr, "16") || !onlyPrintable(r.stderr) || strings.Count(r.stderr, "\n") != 1 {
			t.Errorf("(%d, %q)", int(r.code), r.stderr)
		}
		// A run that the command cannot judge is neither accepted nor refused, and says so, as every other run of this kind.
		if prefix := "ritueel: request " + c.stem(t) + " is not accepted and not refused: "; !strings.HasPrefix(r.stderr, prefix) {
			t.Errorf("standard error = %q, want it to start with %q", r.stderr, prefix)
		}
	})
	t.Run("sixteen", func(t *testing.T) {
		r := run(t, memRoots(t, 16))
		if strings.Contains(r.stderr, "16 ") && strings.Contains(r.stderr, "at most") {
			t.Errorf("(%d, %q): sixteen is the most the checks take", int(r.code), r.stderr)
		}
	})
}

// A file of the trust set that the command does not use is not read, and a run changes no byte of the bundle.
func TestTheCommandWritesNothingWhateverTheKeyringFileIs(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	c := m.byID(t, "pgp-software-valid")
	for name, file := range map[string][]byte{"good": crqKeyring(t, "a", "b"), "none": nil, "swapped": crqKeyring(t, "b", "a"), "garbage": []byte("x")} {
		dir := crqBundleWithKeyring(t, m, c, file)
		before := crqSnapshot(t, dir)
		for _, args := range [][]string{{"--delegation", crqDelegation}, nil, {"--delegation", crqDelegation, "--output", "json"}} {
			crqRun(t, now, append([]string{"check", "request", c.stem(t), "--dir", dir}, args...)...)
			crqSame(t, name+" "+strings.Join(args, " "), before, crqSnapshot(t, dir))
		}
	}
}

// The sentence that the command gave before the keyring file had a reader is gone from the code, and from the page
// that describes the command.
func TestTheOldSentenceThatSaidWhereThePrimariesAreReadFromIsNotDecidedIsGone(t *testing.T) {
	needle := "where they are read " + "from is not decided"
	root := testrepo.Root(t)
	var found []string
	for _, top := range []string{"internal", "cmd", "docs/reference/cli.md"} {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(top)), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if !strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, ".md") {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if bytes.Contains(data, []byte(needle)) {
				rel, _ := filepath.Rel(root, p)
				found = append(found, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) != 0 {
		t.Errorf("the words %q are still in %v", needle, found)
	}
}
