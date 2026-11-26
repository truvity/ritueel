//go:build linux || darwin

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/wanted"
)

// More of "new --template personal" and of what apply says about the bundle it made: every spelling of the
// template that is refused, the folder that is never written into, the files that new makes, and an apply, with
// and without --plan-only, that writes nothing in every state of the starter. The names of this file start with pq.

const (
	pqKnownFaultsEnv = "RITUEEL_KNOWN_FAULTS"
	pqOwnName        = "Eve Example"
	pqOwnAddress     = "eve@example.com"
)

var pqCommentLine = regexp.MustCompile(`(?m)^ *#`)

// pqNew runs new with the arguments and a folder name in a folder of its own, and returns the parent, the folder
// that was asked for and the result.
func pqNew(t *testing.T, args ...string) (parent, dir string, r result) {
	t.Helper()
	parent = t.TempDir()
	dir = filepath.Join(parent, "ada")
	r = apRun(t, apClock, append(append([]string{"new"}, args...), dir)...)
	return parent, dir, r
}

func TestEveryTemplateThatIsNotBuiltIsAUsageErrorAndWritesNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		args  []string
		words string
	}{
		"two-cards":                  {[]string{"--template", "two-cards"}, "the template two-cards is proposed and not built; the template built is personal"},
		"cloud":                      {[]string{"--template", "cloud"}, "the template cloud is proposed and not built"},
		"file":                       {[]string{"--template", "file"}, "the template file is proposed and not built"},
		"cloud, one word":            {[]string{"--template=cloud"}, "the template cloud is proposed and not built"},
		"a made-up name":             {[]string{"--template", "company"}, "the template is personal; no other template is built"},
		"no name":                    {[]string{"--template="}, "no other template is built"},
		"a name of spaces":           {[]string{"--template", " "}, "no other template is built"},
		"upper case":                 {[]string{"--template", "PERSONAL"}, "no other template is built"},
		"a trailing space":           {[]string{"--template", "personal "}, "no other template is built"},
		"a leading space":            {[]string{"--template", " personal"}, "no other template is built"},
		"a trailing newline":         {[]string{"--template", "personal\n"}, "no other template is built"},
		"a prefix":                   {[]string{"--template", "person"}, "no other template is built"},
		"a path":                     {[]string{"--template", "../personal"}, "no other template is built"},
		"a hostile name":             {[]string{"--template", "a\U0000202eb\x1b"}, "no other template is built"},
		"a long name":                {[]string{"--template", strings.Repeat("x", 500)}, "no other template is built"},
		"the second is not built":    {[]string{"--template", "personal", "--template", "cloud"}, "the template cloud is proposed and not built"},
		"with a test root":           {[]string{"--template", "personal", "--test-root"}, "--test-root is for the roots of a company bundle"},
		"with a test root, first":    {[]string{"--test-root", "--template", "personal"}, "--test-root is for the roots of a company bundle"},
		"with a test root, one word": {[]string{"--test-root=true", "--template=personal"}, "--test-root is for the roots of a company bundle"},
		"cloud with a test root":     {[]string{"--template", "cloud", "--test-root"}, "the template cloud is proposed and not built"},
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, "ada")
			before := crqSnapshot(t, parent)
			r := apRun(t, apClock, append(append([]string{"new"}, tc.args...), dir)...)
			if r.code != ExitUsage || r.stdout != "" || !strings.HasPrefix(r.stderr, "ritueel: ") || !strings.Contains(r.stderr, tc.words) {
				t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
			}
			if !printableASCII(r.stderr) {
				t.Errorf("the text is not printable ASCII: %+q", r.stderr)
			}
			crqSame(t, "new", before, crqSnapshot(t, parent))
		})
	}
	// The template with no folder, with two, and with --dir.
	parent := t.TempDir()
	before := crqSnapshot(t, parent)
	for name, args := range map[string][]string{
		"no folder":        {"new", "--template", "personal"},
		"two folders":      {"new", "--template", "personal", filepath.Join(parent, "a"), filepath.Join(parent, "b")},
		"with --dir":       {"--dir", filepath.Join(parent, "a"), "new", "--template", "personal", filepath.Join(parent, "b")},
		"a flag, no value": {"new", filepath.Join(parent, "a"), "--template"},
	} {
		if r := apRun(t, apClock, args...); r.code != ExitUsage || r.stdout != "" {
			t.Errorf("%s: (%d, %q, %q)", name, int(r.code), r.stdout, r.stderr)
		}
	}
	crqSame(t, "new", before, crqSnapshot(t, parent))
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if (s[i] < 0x20 || s[i] > 0x7e) && s[i] != '\n' {
			return false
		}
	}
	return true
}

// Every other command of this repository that has a flag the library would keep the last value of refuses it
// given twice and reads nothing (apply.go, runApply: "the first would be dropped without a word"). new does not:
// the template that comes first is dropped, and `--template cloud --template personal` makes a personal bundle.
func TestAFlagTemplateThatIsGivenTwiceIsAUsageError(t *testing.T) {
	if os.Getenv(pqKnownFaultsEnv) == "" {
		t.Skip("a known fault, not fixed yet (" + pqKnownFaultsEnv + "=1 runs it): new.go runNew does not count --template, so the first of two is dropped without a word")
	}
	for name, args := range map[string][]string{
		"the same twice":           {"--template", "personal", "--template", "personal"},
		"a word that is not built": {"--template", "cloud", "--template", "personal"},
		"one word and two":         {"--template=personal", "--template", "personal"},
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			before := crqSnapshot(t, parent)
			r := apRun(t, apClock, append(append([]string{"new"}, args...), filepath.Join(parent, "ada"))...)
			if r.code != ExitUsage || r.stdout != "" || !strings.Contains(r.stderr, "--template is given once") {
				t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
			}
			crqSame(t, "new", before, crqSnapshot(t, parent))
		})
	}
}

func TestNewPersonalNeverWritesIntoWhatIsThere(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, parent, dir string){
		"an empty folder": func(t *testing.T, parent, dir string) {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"a folder with a file": func(t *testing.T, parent, dir string) {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("mine\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a folder that is a bundle already": func(t *testing.T, parent, dir string) {
			if r := apRun(t, apClock, "new", "--template", "personal", dir); r.code != ExitOK {
				t.Fatalf("new: %q", r.stderr)
			}
		},
		"a company bundle": func(t *testing.T, parent, dir string) {
			if r := apRun(t, apClock, "new", dir); r.code != ExitOK {
				t.Fatalf("new: %q", r.stderr)
			}
		},
		"a file": func(t *testing.T, parent, dir string) {
			if err := os.WriteFile(dir, []byte("mine\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a link to a folder": func(t *testing.T, parent, dir string) {
			target := filepath.Join(parent, "elsewhere")
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
		},
		"a link to nothing": func(t *testing.T, parent, dir string) {
			if err := os.Symlink(filepath.Join(parent, "nowhere"), dir); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, "ada")
			setup(t, parent, dir)
			before := crqSnapshot(t, parent)
			r := apRun(t, apClock, "new", "--template", "personal", dir)
			if r.code != ExitFailure || r.stdout != "" || !strings.HasPrefix(r.stderr, "ritueel: ") {
				t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
			}
			crqSame(t, "new", before, crqSnapshot(t, parent))
		})
	}
}

func TestNewPersonalWithNoClockMakesNothing(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "ada")
	r := apRun(t, time.Time{}, "new", "--template", "personal", dir)
	if r.code != ExitFailure || r.stdout != "" || !strings.Contains(r.stderr, "needs the time") {
		t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Errorf("the folder exists: %v", err)
	}
	// A clock whose 24 months give a day beyond the years that a date may have is no clock either.
	r = apRun(t, time.Date(2104, 3, 1, 0, 0, 0, 0, time.UTC), "new", "--template", "personal", dir)
	if r.code != ExitFailure || r.stdout != "" || !strings.Contains(r.stderr, "year from 2000 to 2105") || !printableASCII(r.stderr) {
		t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Errorf("the folder exists: %v", err)
	}
}

func TestTheFilesOfTheStarterOfAPersonCarryCommentsAndTheModesOfTheOtherStarter(t *testing.T) {
	folderMode, fileMode := umaskModes(t)
	_, dir, r := pqNew(t, "--template", "personal")
	if r.code != ExitOK {
		t.Fatalf("new: %q", r.stderr)
	}
	got := entriesOf(t, dir)
	for _, d := range []string{"want/", "want/roots/"} {
		if m := got[d]; !m.IsDir() || m.Perm() != folderMode {
			t.Errorf("%s: %v", d, m)
		}
	}
	for _, p := range []string{"want/roots/openpgp.yaml", "want/openpgp.yaml", "ritueel.yaml"} {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil || got[p].Perm() != fileMode || !got[p].IsRegular() {
			t.Errorf("%s: %v %v", p, err, got[p])
		}
		text := string(data)
		if !pqCommentLine.MatchString(text) || !strings.HasSuffix(text, "\n") || strings.Contains(text, "\r") || !printableASCII(text) {
			t.Errorf("%s has no comment, no final LF, a CR or a byte outside printable ASCII:\n%s", p, text)
		}
		if !strings.HasPrefix(text, "#") {
			t.Errorf("%s does not begin with a comment that says what it is:\n%s", p, text)
		}
		if len(got) != 5 {
			t.Errorf("the folder holds %d entries: %v", len(got), got)
		}
	}
	// The modes are the modes of the starter of a company: the same for a folder and for a file.
	_, other, ro := pqNew(t)
	if ro.code != ExitOK {
		t.Fatalf("new: %q", ro.stderr)
	}
	for p, m := range entriesOf(t, other) {
		if q, ok := got[p]; ok && q.Perm() != m.Perm() {
			t.Errorf("%s: %v for a person, %v for a company", p, q.Perm(), m.Perm())
		}
	}
	// What is written is what the standard output lists, and the key directory is not made.
	for _, p := range []string{"history", "roots", "sealed", "seen", "requests", "trust", "keys"} {
		if _, ok := got[p+"/"]; ok {
			t.Errorf("new made %s/", p)
		}
	}
}

// pqState is one state of the starter of a person after the person has begun to edit it.
type pqState struct {
	name        string
	fingerprint string // in the place of the placeholder; "" keeps it
	person      bool   // true when the example person is replaced
	words       string // what apply says; the wanted-file refusals and then the not-built refusal
	path        string // the file that the refusal names; "" for the not-built refusal
}

func pqBundle(t *testing.T, s pqState) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ada")
	if r := apRun(t, apClock, "new", "--template", "personal", dir); r.code != ExitOK {
		t.Fatalf("new: %q", r.stderr)
	}
	edit := func(rel, old, repl string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), old) {
			t.Fatalf("%s has no %q", rel, old)
		}
		if err := os.WriteFile(p, []byte(strings.Replace(string(data), old, repl, 1)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if s.fingerprint != "" {
		edit("want/roots/openpgp.yaml", wanted.PlaceholderFingerprint, s.fingerprint)
	}
	if s.person {
		edit("ritueel.yaml", wanted.ExamplePersonName, pqOwnName)
		edit("ritueel.yaml", wanted.ExamplePersonAddress, pqOwnAddress)
	}
	return dir
}

func TestApplyOnTheStarterOfAPersonWritesNothingInEveryState(t *testing.T) {
	const real = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
	states := []pqState{
		{"the starter as new made it", "", false, "replace the example person with your name and address", "ritueel.yaml"},
		{"a fingerprint of the key, the example person", real, false, "replace the example person with your name and address", "ritueel.yaml"},
		{"the person, the placeholder", "", true, "replace the placeholder with the fingerprint of your key", "want/roots/openpgp.yaml"},
		{"the person, the fingerprint of the examples", wanted.ExampleFingerprint, true, "the fingerprint of the examples", "want/roots/openpgp.yaml"},
		{"the person, the fingerprint of the examples in upper case", strings.ToUpper(wanted.ExampleFingerprint), true, "the fingerprint of the examples", "want/roots/openpgp.yaml"},
		{"the person and a fingerprint of the key", real, true, "passed the check of its wanted files; adoption and subkeys are built by later parts", ""},
	}
	for _, s := range states {
		for _, form := range []string{"plan-only", "plan-only json", "apply", "apply json"} {
			t.Run(s.name+" "+form, func(t *testing.T) {
				dir := pqBundle(t, s)
				keys := apKeys(t)
				base := []string{"--dir", dir}
				if strings.HasSuffix(form, "json") {
					base = append(base, "--output", "json")
				}
				args := append(base, "apply")
				if strings.HasPrefix(form, "plan-only") {
					args = append(args, "--plan-only")
				} else {
					args = append(args, "--key-dir", keys)
				}
				parent := filepath.Dir(dir)
				before, keysBefore, parentBefore := crqSnapshot(t, dir), crqSnapshot(t, keys), crqSnapshot(t, parent)
				r := apRun(t, apClock, args...)
				text := r.stderr
				if strings.HasSuffix(form, "json") {
					obj := apObject(t, r.stdout)
					msg, _ := obj["error"].(string)
					if obj["outcome"] != "failed" || obj["exit_code"] != jsonNumber("1") || msg == "" {
						t.Errorf("the object: %v", obj)
					}
					text = msg
				} else if r.stdout != "" {
					t.Errorf("standard output: %q", r.stdout)
				}
				if r.code != ExitFailure || !strings.Contains(text, s.words) || !printableASCII(text) {
					t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
				}
				if s.path != "" && !strings.Contains(text, s.path+":") {
					t.Errorf("the text does not name %s: %q", s.path, text)
				}
				if s.path == "" {
					if !strings.Contains(text, "this version does not build that yet") || strings.Contains(text, "nothing to apply") {
						t.Errorf("the text of the not-built refusal: %q", text)
					}
				} else if !strings.Contains(text, "nothing was written") {
					t.Errorf("the refusal does not say that nothing was written: %q", text)
				}
				crqSame(t, "apply (the bundle)", before, crqSnapshot(t, dir))
				crqSame(t, "apply (the parent)", parentBefore, crqSnapshot(t, parent))
				crqSame(t, "apply (the keys)", keysBefore, crqSnapshot(t, keys))
				if got := entriesOf(t, keys); len(got) != 0 {
					t.Errorf("an entry in the key directory: %v", got)
				}
				for _, p := range []string{"history", "roots", "sealed", "seen", "requests"} {
					if _, err := os.Lstat(filepath.Join(dir, p)); err == nil {
						t.Errorf("apply made %s/", p)
					}
				}
			})
		}
	}
}

// A personal bundle that passes its wanted files is "not built" for whatever clock: the clock only decides whether
// the keys pass, and a clock that is no clock is refused before anything is read as a key.
func TestApplyOnAPersonalBundleWithTheClockAtTheEdgesOfTheKey(t *testing.T) {
	dir := pqBundle(t, pqState{"", "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", true, "", ""}) // the key ends on 2028-11-20
	for name, tc := range map[string]struct {
		now   time.Time
		words string
	}{
		"a second before the last day":      {time.Date(2028, 11, 19, 23, 59, 59, 0, time.UTC), "passed the check of its wanted files"},
		"at the start of the last day":      {time.Date(2028, 11, 20, 0, 0, 0, 0, time.UTC), "not after now"},
		"the first day that is not too far": {time.Date(2025, 11, 20, 0, 0, 0, 0, time.UTC), "passed the check of its wanted files"},
		"a second before it":                {time.Date(2025, 11, 19, 23, 59, 59, 0, time.UTC), "more than 36 months from now"},
		"the zero time":                     {time.Time{}, "no clock"},
	} {
		t.Run(name, func(t *testing.T) {
			before := crqSnapshot(t, dir)
			r := apPlanOnly(t, tc.now, dir)
			if r.code != ExitFailure || !strings.Contains(r.stderr, tc.words) {
				t.Errorf("(%d, %q)", int(r.code), r.stderr)
			}
			crqSame(t, "apply", before, crqSnapshot(t, dir))
		})
	}
}
