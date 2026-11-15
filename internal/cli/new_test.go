//go:build linux || darwin

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// "new [--test-root] DIR" through Run. The starter files are spelled out here byte for byte (the text of the
// settings is the one of docs/reference/bundle.md, record 0005 rule 20 and record 0006 rules 5 and 31); a file that
// the command writes is compared with these and never with what the program happens to make.

const newSettingsText = `# The settings of this bundle. A person writes this file; ritueel never changes it.
version: 1
name: Example                    # in the names of the root keys; 1 to 45 characters
release_address: release@example.org
policy:
  stores: [piv, openpgp-card, aws-kms]
  min_firmware: 5.7.0
  pin_policy: [once, always]
  require_name_constraints: true
  validity_months: 13
`

const newSettingsTestText = `# The settings of this bundle. A person writes this file; ritueel never changes it.
version: 1
name: Example                    # in the names of the root keys; 1 to 45 characters
release_address: release@example.org
policy:
  stores: [piv, openpgp-card, aws-kms, software]
  min_firmware: 5.7.0
  pin_policy: [once, always]
  require_name_constraints: true
  validity_months: 13
`

const newX509Text = `# One X.509 root. Its keys are made by the first apply.
version: 1
kind: x509
test: false
`

const newOpenPGPText = `# One OpenPGP root. Its keys are made by the first apply.
version: 1
kind: openpgp
test: false
`

const newX509TestText = `# One X.509 root. Its keys are made by the first apply.
version: 1
kind: x509
test: true  # set at birth; a real root never becomes a test root
`

const newOpenPGPTestText = `# One OpenPGP root. Its keys are made by the first apply.
version: 1
kind: openpgp
test: true  # set at birth; a real root never becomes a test root
`

const (
	newNotice     = "no key was made and no card was touched; edit name and release_address in ritueel.yaml before the first apply\n"
	newTestNotice = "this is a test bundle: its roots are marked TEST ONLY\n"
)

// newGolden is the three files that new writes, with ritueel.yaml last.
func newGolden(testRoot bool) [][2]string {
	if testRoot {
		return [][2]string{{"want/roots/x509.yaml", newX509TestText}, {"want/roots/openpgp.yaml", newOpenPGPTestText}, {"ritueel.yaml", newSettingsTestText}}
	}
	return [][2]string{{"want/roots/x509.yaml", newX509Text}, {"want/roots/openpgp.yaml", newOpenPGPText}, {"ritueel.yaml", newSettingsText}}
}

func sha256Of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// umaskModes are the modes that a folder made with 0755 and a file made with 0644 get under the umask of this
// process, found by making one of each.
func umaskModes(t testing.TB) (folder, file fs.FileMode) {
	t.Helper()
	d := t.TempDir()
	if err := os.Mkdir(filepath.Join(d, "f"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "g"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(d, "f"))
	if err != nil {
		t.Fatal(err)
	}
	gi, err := os.Stat(filepath.Join(d, "g"))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm(), gi.Mode().Perm()
}

// entriesOf lists everything under dir as "path" (folders end with "/") with its mode, sorted.
func entriesOf(t testing.TB, dir string) map[string]fs.FileMode {
	t.Helper()
	out := map[string]fs.FileMode{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if info.IsDir() {
			name += "/"
		}
		out[name] = info.Mode()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestNewMakesTheStarterBundleOfThePageAndNothingElse(t *testing.T) {
	folderMode, fileMode := umaskModes(t)
	for _, testRoot := range []bool{false, true} {
		name := "no test root"
		args := []string{"new"}
		if testRoot {
			name = "test root"
			args = append(args, "--test-root")
		}
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			sibling := filepath.Join(parent, "sibling")
			if err := os.WriteFile(sibling, []byte("mine"), 0o644); err != nil {
				t.Fatal(err)
			}
			beforeParent := crqSnapshot(t, parent)
			dir := filepath.Join(parent, "acme")
			text := run(t, append(args, dir)...)
			if text.code != ExitOK || text.stderr != "" {
				t.Fatalf("(%d, %q, %q)", int(text.code), text.stdout, text.stderr)
			}

			// The tree: the two folders, the three files, with the modes and the bytes of the page.
			got := entriesOf(t, dir)
			golden := newGolden(testRoot)
			if len(got) != 2+len(golden) {
				t.Errorf("the folder holds %d entries, want %d: %v", len(got), 2+len(golden), got)
			}
			for _, d := range []string{"want/", "want/roots/"} {
				if m, ok := got[d]; !ok || !m.IsDir() || m.Perm() != folderMode {
					t.Errorf("%s: %v (present %v), want a folder with the mode %v", d, m, ok, folderMode)
				}
			}
			for _, g := range golden {
				data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(g[0])))
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != g[1] {
					t.Errorf("%s =\n%s\nwant\n%s", g[0], data, g[1])
				}
				if m := got[g[0]]; !m.IsRegular() || m.Perm() != fileMode {
					t.Errorf("%s has the mode %v, want a regular file with %v", g[0], m, fileMode)
				}
			}
			// Nothing outside the folder changed, and the folders that other code makes are not made.
			afterParent := crqSnapshot(t, parent)
			var added []string
			for _, l := range afterParent {
				if !strings.HasPrefix(l, "acme") {
					continue
				}
				added = append(added, l)
			}
			if len(added) == 0 {
				t.Fatal("the folder is not in the parent")
			}
			var rest []string
			for _, l := range afterParent {
				if !strings.HasPrefix(l, "acme") {
					rest = append(rest, l)
				}
			}
			crqSame(t, "new (the entries beside the folder)", beforeParent, rest)
			for _, absent := range []string{"seen", "sealed", "roots", "requests", "history", "trust", "drills", "want/delegations", "want/cards"} {
				if _, err := os.Lstat(filepath.Join(dir, absent)); err == nil {
					t.Errorf("new made %s, which the code that writes into it makes", absent)
				}
			}

			// The text: the line of the folder, a line for each file in the form that sha256sum -c reads, and
			// the notices.
			want := "made the bundle " + dir + "\n"
			lines := strings.Split(strings.TrimSuffix(text.stdout, "\n"), "\n")
			if lines[0]+"\n" != want {
				t.Errorf("first line = %q, want %q", lines[0], strings.TrimSuffix(want, "\n"))
			}
			digests := map[string]string{}
			var order []string
			for _, l := range lines[1 : len(lines)-btoi(testRoot)-1] {
				sum, p, ok := strings.Cut(l, "  ")
				if !ok || len(sum) != 64 {
					t.Errorf("the line %q is not a digest, two spaces and a path", l)
					continue
				}
				digests[p] = sum
				order = append(order, p)
			}
			if len(order) != len(golden) {
				t.Errorf("%d file lines, want %d: %q", len(order), len(golden), text.stdout)
			}
			for _, g := range golden {
				if digests[g[0]] != sha256Of(g[1]) {
					t.Errorf("the digest of %s is %q, want %q", g[0], digests[g[0]], sha256Of(g[1]))
				}
			}
			if len(order) > 0 && order[len(order)-1] != "ritueel.yaml" {
				t.Errorf("the last file line is %q, want ritueel.yaml (the order the files were written)", order[len(order)-1])
			}
			tail := newNotice
			if testRoot {
				tail += newTestNotice
			}
			if !strings.HasSuffix(text.stdout, tail) {
				t.Errorf("the output does not end with %q: %q", tail, text.stdout)
			}
			if !testRoot && strings.Contains(text.stdout, "TEST ONLY") {
				t.Errorf("a bundle with no test root says TEST ONLY: %q", text.stdout)
			}
			if !onlyPrintable(text.stdout) {
				t.Errorf("a byte that is not printable ASCII: %q", text.stdout)
			}

			// JSON mode: the base object, with no new member.
			dir2 := filepath.Join(parent, "acme2")
			js := run(t, append([]string{"--output", "json"}, append(args, dir2)...)...)
			if js.code != ExitOK || js.stderr != "" {
				t.Fatalf("json: (%d, %q)", int(js.code), js.stderr)
			}
			wantObject(t, object(t, js.stdout), map[string]any{"output": 1, "command": "new", "exit_code": 0, "outcome": "done"})
			// The same bundle: file for file.
			crqSame(t, "the second new (the two bundles)", stripPrefix(crqSnapshot(t, dir), ""), stripPrefix(crqSnapshot(t, dir2), ""))
		})
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func stripPrefix(lines []string, prefix string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = strings.TrimPrefix(l, prefix)
	}
	sort.Strings(out)
	return out
}

// --test-root=false is the flag turned off: the same bundle as with no flag.
func TestNewWithTheFlagTurnedOffIsTheBundleWithNoFlag(t *testing.T) {
	parent := t.TempDir()
	a, b := filepath.Join(parent, "a"), filepath.Join(parent, "b")
	if r := run(t, "new", a); r.code != ExitOK {
		t.Fatal(r)
	}
	if r := run(t, "new", "--test-root=false", b); r.code != ExitOK {
		t.Fatal(r)
	}
	crqSame(t, "new --test-root=false", crqSnapshot(t, a), crqSnapshot(t, b))
}

// A parent whose name holds a line break and a letter of another script: the folder is made, and the text names it
// in printable ASCII.
func TestTheNameOfTheFolderInTheOutputIsEscaped(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "p\nqе")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Skipf("cannot make the folder: %v", err)
	}
	r := run(t, "new", filepath.Join(parent, "acme"))
	if r.code != ExitOK || !onlyPrintable(r.stdout) || !strings.Contains(r.stdout, bs+"u000aq"+bs+"u0435/acme") {
		t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(parent, "acme", "ritueel.yaml")); err != nil {
		t.Error(err)
	}
}

// ---- DIR is something that new will not write into -------------------------------------------------

func TestNewNeverWritesIntoWhatIsThere(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T, parent string) string // returns the argument
	}{
		{"a file", func(t *testing.T, parent string) string {
			p := filepath.Join(parent, "acme")
			must(t, os.WriteFile(p, []byte("mine"), 0o644))
			return p
		}},
		{"an empty folder", func(t *testing.T, parent string) string {
			p := filepath.Join(parent, "acme")
			must(t, os.Mkdir(p, 0o755))
			return p
		}},
		{"an empty folder, written with a slash at the end", func(t *testing.T, parent string) string {
			p := filepath.Join(parent, "acme")
			must(t, os.Mkdir(p, 0o755))
			return p + "/"
		}},
		{"a folder with a file in it", func(t *testing.T, parent string) string {
			p := filepath.Join(parent, "acme")
			must(t, os.Mkdir(p, 0o755))
			must(t, os.WriteFile(filepath.Join(p, "notes"), []byte("mine"), 0o644))
			return p
		}},
		{"a bundle", func(t *testing.T, parent string) string {
			p := filepath.Join(parent, "acme")
			if r := run(t, "new", p); r.code != ExitOK {
				t.Fatal(r)
			}
			return p
		}},
		{"a link to a folder", func(t *testing.T, parent string) string {
			target := filepath.Join(parent, "target")
			must(t, os.Mkdir(target, 0o755))
			p := filepath.Join(parent, "acme")
			must(t, os.Symlink(target, p))
			return p
		}},
		{"a link to nothing", func(t *testing.T, parent string) string {
			p := filepath.Join(parent, "acme")
			must(t, os.Symlink(filepath.Join(parent, "nowhere"), p))
			return p
		}},
		{"a link to a file", func(t *testing.T, parent string) string {
			target := filepath.Join(parent, "target")
			must(t, os.WriteFile(target, []byte("mine"), 0o644))
			p := filepath.Join(parent, "acme")
			must(t, os.Symlink(target, p))
			return p
		}},
		{"a leftover temporary name", func(t *testing.T, parent string) string {
			p := filepath.Join(parent, ".rt-acme")
			return p
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			arg := tc.make(t, parent)
			before := crqSnapshot(t, parent)
			text := run(t, "new", arg)
			if text.code != ExitFailure || text.stdout != "" || !strings.HasPrefix(text.stderr, "ritueel: ") {
				t.Errorf("(%d, %q, %q), want exit code 1, no standard output and one line of error", int(text.code), text.stdout, text.stderr)
			}
			if !onlyPrintable(text.stderr) || strings.Count(text.stderr, "\n") != 1 {
				t.Errorf("standard error is not one printable line: %q", text.stderr)
			}
			// The folder that was not made by this call is never reported as one to remove.
			if strings.Contains(text.stderr, "left as it is") {
				t.Errorf("the error tells the person to remove a folder that new did not make: %q", text.stderr)
			}
			js := run(t, "--output", "json", "new", arg)
			wantObject(t, object(t, js.stdout), map[string]any{"output": 1, "command": "new", "exit_code": 1, "outcome": "failed", "error": "<any>"})
			if js.code != ExitFailure {
				t.Errorf("json: exit code %d", int(js.code))
			}
			crqSame(t, "new", before, crqSnapshot(t, parent))
		})
	}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ---- where DIR is ---------------------------------------------------------------------------------

func TestNewNeedsAParentThatIsAFolderAndNotALink(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T, root string) (arg, watched string)
	}{
		{"the parent does not exist", func(t *testing.T, root string) (string, string) {
			return filepath.Join(root, "missing", "acme"), root
		}},
		{"the parent of the parent does not exist", func(t *testing.T, root string) (string, string) {
			return filepath.Join(root, "missing", "deeper", "acme"), root
		}},
		{"the parent is a file", func(t *testing.T, root string) (string, string) {
			must(t, os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o644))
			return filepath.Join(root, "file", "acme"), root
		}},
		{"the parent is a link to a folder", func(t *testing.T, root string) (string, string) {
			target := filepath.Join(root, "target")
			must(t, os.Mkdir(target, 0o755))
			must(t, os.Symlink(target, filepath.Join(root, "link")))
			return filepath.Join(root, "link", "acme"), root
		}},
		{"the parent is a link to nothing", func(t *testing.T, root string) (string, string) {
			must(t, os.Symlink(filepath.Join(root, "nowhere"), filepath.Join(root, "link")))
			return filepath.Join(root, "link", "acme"), root
		}},
		{"the path climbs", func(t *testing.T, root string) (string, string) {
			must(t, os.Mkdir(filepath.Join(root, "inner"), 0o755))
			return root + "/inner/../acme", root
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			arg, watched := tc.make(t, root)
			before := crqSnapshot(t, watched)
			r := run(t, "new", arg)
			if r.code != ExitFailure || r.stdout != "" || !onlyPrintable(r.stderr) {
				t.Errorf("(%d, %q, %q), want exit code 1", int(r.code), r.stdout, r.stderr)
			}
			crqSame(t, "new", before, crqSnapshot(t, watched))
		})
	}
}

// The last element is the name of the bundle, which goes into the names of its objects: only the letters, the
// digits, the dot, the hyphen and the underscore, and no name that a later command takes for its own.
func TestNewRefusesANameThatIsNotAFolderNameOfABundle(t *testing.T) {
	for _, name := range []string{
		"a b", "a\tb", "a\nb", "aе", "é", "a:b", "a*b", "a\"b", "a|b", "a<b", "a?b", "a\\b", "a;b", "a`b", "a$b",
		".", "..", "name.", ".rt-x", ".RT-x", ".Rt-", "CON", "con", "nul", "aux.txt", "COM1", "lpt9",
		strings.Repeat("a", 256), "a\x00b", "\x7f", "\xff",
	} {
		t.Run(strconvQuote(name), func(t *testing.T) {
			root := t.TempDir()
			before := crqSnapshot(t, root)
			r := run(t, "new", root+"/"+name)
			if r.code != ExitFailure || r.stdout != "" || !onlyPrintable(r.stderr) {
				t.Errorf("(%d, %q, %q), want exit code 1, nothing on standard output and printable text on standard error", int(r.code), r.stdout, r.stderr)
			}
			crqSame(t, "new", before, crqSnapshot(t, root))
		})
	}
	t.Run("an empty argument", func(t *testing.T) {
		r := run(t, "new", "")
		if r.code != ExitFailure && r.code != ExitUsage {
			t.Errorf("exit code %d", int(r.code))
		}
	})
}

func strconvQuote(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			b.WriteString("_")
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() > 40 {
		return b.String()[:40] + "..."
	}
	return b.String()
}

// The names that the rule accepts are made: letters, digits, dot, hyphen, underscore, and 255 bytes.
func TestNewMakesTheBundleOfAnyNameThatTheRuleAccepts(t *testing.T) {
	for _, name := range []string{"acme", "Acme", "a", "a.b", "a_b", "a-b", "1", ".hidden", strings.Repeat("a", 255)} {
		t.Run(strconvQuote(name), func(t *testing.T) {
			root := t.TempDir()
			r := run(t, "new", filepath.Join(root, name))
			if r.code != ExitOK {
				t.Fatalf("(%d, %q)", int(r.code), r.stderr)
			}
			if _, err := os.Stat(filepath.Join(root, name, "ritueel.yaml")); err != nil {
				t.Error(err)
			}
		})
	}
}

// ---- the command line -----------------------------------------------------------------------------

func TestNewTakesExactlyOneFolderAndNotTheFlagOfTheBundle(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "acme")
	other := filepath.Join(root, "other")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no argument", []string{"new"}, "DIR"},
		{"no argument, with the flag", []string{"new", "--test-root"}, "DIR"},
		{"two arguments", []string{"new", dir, other}, "DIR"},
		{"--dir after the word", []string{"new", "--dir", other, dir}, "--dir"},
		{"--dir before the word", []string{"--dir", other, "new", dir}, "--dir"},
		{"--dir with an empty value", []string{"new", "--dir", "", dir}, "--dir"},
		{"--dir with an equals sign and an empty value", []string{"new", "--dir=", dir}, "--dir"},
		{"--dir with the folder itself", []string{"new", "--dir", dir, dir}, "--dir"},
		{"--dir and no argument", []string{"new", "--dir", dir}, "DIR"},
		{"--template, which the first version does not have", []string{"new", "--template", "cloud", dir}, ""},
		{"an unknown flag", []string{"new", "--nosuch", dir}, ""},
		{"a value for the flag that has none", []string{"new", "--test-root=maybe", dir}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := crqSnapshot(t, root)
			r := run(t, tc.args...)
			if r.code != ExitUsage || r.stdout != "" || !strings.HasPrefix(r.stderr, "ritueel: ") || !strings.Contains(r.stderr, tc.want) {
				t.Errorf("(%d, %q, %q), want exit code 2, nothing on standard output and a line that holds %q", int(r.code), r.stdout, r.stderr, tc.want)
			}
			js := run(t, append([]string{"--output", "json"}, tc.args...)...)
			if js.code != ExitUsage {
				t.Errorf("json: exit code %d", int(js.code))
			}
			wantObject(t, object(t, js.stdout), map[string]any{"output": 1, "command": "new", "exit_code": 2, "outcome": "usage", "error": "<any>"})
			crqSame(t, "new", before, crqSnapshot(t, root))
		})
	}
}

// ---- new, and then the other commands -----------------------------------------------------------------

// A bundle that new made is a bundle: check history finds nothing to say, and check request opens it, finds no
// trust set (the first apply makes one) and says so. A folder that new did not finish is not one.
func TestABundleThatNewMadeIsOpenedByTheOtherCommands(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "acme")
	if r := run(t, "new", dir); r.code != ExitOK {
		t.Fatal(r)
	}
	h := run(t, "check", "history", "--dir", dir)
	if h.code != ExitOK {
		t.Errorf("check history: (%d, %q, %q)", int(h.code), h.stdout, h.stderr)
	}
	r := run(t, "check", "request", "x", "--dir", dir)
	if r.code != ExitFailure || !strings.Contains(r.stderr, "no trust set") {
		t.Errorf("check request: (%d, %q), want exit code 1 and the words no trust set", int(r.code), r.stderr)
	}

	// With no ritueel.yaml the folder is no bundle for a command that reads wanted files.
	half := filepath.Join(root, "half")
	must(t, os.Mkdir(half, 0o755))
	must(t, os.Mkdir(filepath.Join(half, "want"), 0o755))
	r = run(t, "check", "request", "x", "--dir", half)
	if r.code != ExitFailure || !strings.Contains(r.stderr, "ritueel.yaml") {
		t.Errorf("a folder with no ritueel.yaml: (%d, %q)", int(r.code), r.stderr)
	}
}

// The bundle of "new --test-root" allows the software store, and the bundle of "new" does not: a request with a
// software key is accepted in the first and refused with store-not-allowed in the second, under a delegation and a
// trust set that a person adds.
func TestOnlyTheTestBundleChecksARequestWithASoftwareKey(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	c := m.byID(t, "x509-software-valid")
	cfg := m.Configs[c.Config]
	for _, testRoot := range []bool{true, false} {
		name := "new"
		args := []string{"new"}
		if testRoot {
			name = "new --test-root"
			args = append(args, "--test-root")
		}
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "acme")
			if r := run(t, append(args, dir)...); r.code != ExitOK {
				t.Fatal(r)
			}
			crqWrite(t, dir, crqMerge(
				crqTree{"want/delegations/" + crqDelegation + ".yaml": []byte("version: 1\ntype: x509-intermediate\nroot: x509\npermitted_uri_hosts: " + crqList(cfg.PermittedURIHosts) + "\npermitted_dns_names: " + crqList(cfg.PermittedDNSNames) + "\n")},
				crqTrust(t),
				crqRequestFiles(t, c),
			))
			r := crqRun(t, now, "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir, "--output", "json")
			if testRoot {
				if r.code != ExitOK {
					t.Errorf("(%d, %q, %q), want an accepted request", int(r.code), r.stdout, r.stderr)
				}
				return
			}
			reasons, _ := stringList(object(t, r.stdout)["reasons"])
			if r.code != ExitRefused || len(reasons) != 1 || reasons[0] != "store-not-allowed" {
				t.Errorf("(%d, %q, %q), want a refusal with store-not-allowed", int(r.code), r.stdout, r.stderr)
			}
		})
	}
}
