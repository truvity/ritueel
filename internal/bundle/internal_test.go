package bundle

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/wanted"
)

// The seams of the package that a test in the package drives: create, with a file system that fails at the Nth
// call; configOf, with a hand-made value; splitDir and parseSetName.

// counter counts the calls that reach a failing file system and fails the one at failAt (0: none).
type counter struct {
	n, failAt int
	after     int // calls that came after the failure
	err       error
}

// hit counts one call and returns the injected error when it is the one to fail.
func (c *counter) hit() error {
	c.n++
	switch {
	case c.failAt == 0:
		return nil
	case c.n == c.failAt:
		return c.err
	case c.n > c.failAt:
		c.after++
	}
	return nil
}

// failFS wraps a folder: every call but Close is counted, and the one at failAt returns the error.
type failFS struct {
	inner fsx.FS
	c     *counter
}

func (f *failFS) OpenDir(name string) (fsx.FS, error) {
	if err := f.c.hit(); err != nil {
		return nil, err
	}
	child, err := f.inner.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &failFS{inner: child, c: f.c}, nil
}

func (f *failFS) Mkdir(name string, perm fs.FileMode) error {
	if err := f.c.hit(); err != nil {
		return err
	}
	return f.inner.Mkdir(name, perm)
}

func (f *failFS) CreateExcl(name string, perm fs.FileMode) (fsx.File, error) {
	if err := f.c.hit(); err != nil {
		return nil, err
	}
	file, err := f.inner.CreateExcl(name, perm)
	if err != nil {
		return nil, err
	}
	return &failFile{inner: file, c: f.c}, nil
}

func (f *failFS) RenameNoReplace(oldName, newName string) error {
	if err := f.c.hit(); err != nil {
		return err
	}
	return f.inner.RenameNoReplace(oldName, newName)
}

func (f *failFS) Sync() error {
	if err := f.c.hit(); err != nil {
		return err
	}
	return f.inner.Sync()
}

func (f *failFS) ReadFile(name string) ([]byte, error) {
	if err := f.c.hit(); err != nil {
		return nil, err
	}
	return f.inner.ReadFile(name)
}

func (f *failFS) ReadDir() ([]fs.DirEntry, error) {
	if err := f.c.hit(); err != nil {
		return nil, err
	}
	return f.inner.ReadDir()
}

func (f *failFS) Close() error { return f.inner.Close() }

type failFile struct {
	inner fsx.File
	c     *counter
}

func (f *failFile) Write(p []byte) (int, error) {
	if err := f.c.hit(); err != nil {
		return 0, err
	}
	return f.inner.Write(p)
}

func (f *failFile) Sync() error {
	if err := f.c.hit(); err != nil {
		return err
	}
	return f.inner.Sync()
}

func (f *failFile) Close() error { return f.inner.Close() }

// runCreate runs create on a new parent folder with a wrapper that fails at the call failAt, and returns the
// parent folder, the counter and the error.
func runCreate(t *testing.T, failAt int, opt StarterOptions) (string, *counter, []wanted.File, error) {
	t.Helper()
	files, err := Starter(opt)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	real, err := fsx.OpenFS(parent)
	if err != nil {
		t.Fatal(err)
	}
	c := &counter{failAt: failAt, err: errors.New("injected fault")}
	w := &fsx.Writer{FS: &failFS{inner: real, c: c}}
	cerr := create(w, filepath.Join(parent, "acme"), "acme", files)
	_ = w.Close()
	return parent, c, files, cerr
}

func TestCreateWithNoFaultMakesTheBundleInAFewCalls(t *testing.T) {
	parent, c, files, err := runCreate(t, 0, StarterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if c.n < 10 {
		t.Fatalf("only %d calls reached the file system", c.n)
	}
	for _, f := range files {
		got, err := os.ReadFile(filepath.Join(parent, "acme", filepath.FromSlash(f.Path)))
		if err != nil || string(got) != string(f.Data) {
			t.Errorf("%s: %v", f.Path, err)
		}
	}
}

// A fault at each call in turn, from the first to the last: the first error stops the writer for good, no later
// call reaches the file system, the error says what was made, ritueel.yaml is written last, and nothing outside the
// folder is touched.
func TestAFaultAtEachCallStopsTheCreateAndSaysWhatWasMade(t *testing.T) {
	for _, testRoot := range []bool{false, true} {
		_, clean, files, err := runCreate(t, 0, StarterOptions{TestRoot: testRoot})
		if err != nil {
			t.Fatal(err)
		}
		total := clean.n
		for n := 1; n <= total; n++ {
			parent, c, _, err := runCreate(t, n, StarterOptions{TestRoot: testRoot})
			if err == nil {
				t.Fatalf("a fault at call %d of %d gives no error", n, total)
			}
			var ce *CreateError
			if !errors.As(err, &ce) {
				t.Fatalf("call %d: the error is %T", n, err)
			}
			if !errors.Is(err, c.err) {
				t.Errorf("call %d: the error does not wrap the cause: %v", n, err)
			}
			if c.after != 0 {
				t.Errorf("call %d: %d calls reached the file system after the fault", n, c.after)
			}
			dir := filepath.Join(parent, "acme")
			_, statErr := os.Lstat(dir)
			exists := statErr == nil
			if ce.Made && !exists {
				t.Errorf("call %d of %d: Made is true and the folder does not exist", n, total)
			}
			// What the error lists was made, whole.
			for _, p := range ce.Written {
				full := filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(p, "/")))
				info, err := os.Stat(full)
				if err != nil {
					t.Errorf("call %d: %s is listed and is not there: %v", n, p, err)
					continue
				}
				if strings.HasSuffix(p, "/") != info.IsDir() {
					t.Errorf("call %d: %s is listed with the wrong kind", n, p)
				}
				if !info.IsDir() {
					for _, f := range files {
						if f.Path == p {
							if got, _ := os.ReadFile(full); string(got) != string(f.Data) {
								t.Errorf("call %d: %s is not whole", n, p)
							}
						}
					}
				}
			}
			// ritueel.yaml is the last file: it exists only when everything else was written.
			if _, err := os.Lstat(filepath.Join(dir, "ritueel.yaml")); err == nil {
				for _, f := range files[:len(files)-1] {
					if !slices.Contains(ce.Written, f.Path) {
						t.Errorf("call %d: ritueel.yaml exists and %s was not written first", n, f.Path)
					}
				}
			}
			if slices.Contains(ce.Written, "ritueel.yaml") && n != total {
				// Listed only when its own write finished, which is the last call or the ones before the end of it.
				for _, f := range files[:len(files)-1] {
					if !slices.Contains(ce.Written, f.Path) {
						t.Errorf("call %d: ritueel.yaml is listed and %s is not", n, f.Path)
					}
				}
			}
			// Nothing outside the folder: the parent holds the folder, or nothing.
			if ents, _ := os.ReadDir(parent); len(ents) > 1 || (len(ents) == 1 && ents[0].Name() != "acme") {
				t.Errorf("call %d: the parent holds %d entries", n, len(ents))
			}
			if !ce.Made && len(ce.Written) != 0 {
				t.Errorf("call %d: nothing is made and %v is written", n, ce.Written)
			}
			if !printableASCII(err.Error()) {
				t.Errorf("call %d: the text of the error is not printable ASCII: %q", n, err.Error())
			}
		}
		t.Logf("test root %v: %d calls, each failed in turn", testRoot, total)
	}
}

// CreateError.Made is "true when the folder itself was made by this call", and when it is false "nothing was written":
// a folder that exists because of this call, whatever stopped the call after the make, is a made folder, and the
// person has to be told to remove it.
func TestMadeIsTrueWhenTheFolderWasMadeByTheCall(t *testing.T) {
	_, clean, _, _ := runCreate(t, 0, StarterOptions{})
	for n := 1; n <= clean.n; n++ {
		parent, _, _, err := runCreate(t, n, StarterOptions{})
		var ce *CreateError
		if !errors.As(err, &ce) {
			t.Fatalf("call %d: %v", n, err)
		}
		_, statErr := os.Lstat(filepath.Join(parent, "acme"))
		if exists := statErr == nil; ce.Made != exists {
			t.Errorf("a fault at call %d of %d: Made is %v and the folder exists: %v (%v)", n, clean.n, ce.Made, exists, err)
		}
	}
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func TestCreateWritesTheRootFilesBeforeTheSettingsAndTheSettingsLast(t *testing.T) {
	files, err := Starter(StarterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if files[len(files)-1].Path != wanted.SettingsPath {
		t.Fatalf("the last starter file is %s", files[len(files)-1].Path)
	}
	// A fault at the write of ritueel.yaml's first call leaves a folder with no ritueel.yaml, with the root files.
	_, clean, _, _ := runCreate(t, 0, StarterOptions{})
	found := false
	for n := 1; n <= clean.n; n++ {
		parent, _, _, _ := runCreate(t, n, StarterOptions{})
		dir := filepath.Join(parent, "acme")
		_, e1 := os.Lstat(filepath.Join(dir, "want/roots/x509.yaml"))
		_, e2 := os.Lstat(filepath.Join(dir, "want/roots/openpgp.yaml"))
		_, e3 := os.Lstat(filepath.Join(dir, "ritueel.yaml"))
		if e1 == nil && e2 == nil && e3 != nil {
			found = true
		}
		if e3 == nil && (e1 != nil || e2 != nil) {
			t.Errorf("fault at call %d: ritueel.yaml exists and a root file does not", n)
		}
	}
	if !found {
		t.Error("no fault left a folder that holds the root files and no ritueel.yaml")
	}
}

func TestCreateOnAWriterThatIsNotOpenOrIsClosedWritesNothing(t *testing.T) {
	files, err := Starter(StarterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := create(&fsx.Writer{}, "acme", "acme", files); err == nil {
		t.Error("a writer with no folder")
	} else {
		var ce *CreateError
		if !errors.As(err, &ce) || ce.Made {
			t.Errorf("%v", err)
		}
	}
	w, err := fsx.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := create(w, "acme", "acme", files); err == nil {
		t.Error("a closed writer")
	}
}

// configOf.

func madeSettings(t *testing.T) *wanted.Settings {
	t.Helper()
	files, err := Starter(StarterOptions{TestRoot: true})
	if err != nil {
		t.Fatal(err)
	}
	s, err := wanted.ParseSettings(wanted.SettingsPath, files[len(files)-1].Data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func madeDelegation(t *testing.T, s *wanted.Settings, text string) *wanted.Delegation {
	t.Helper()
	d, err := wanted.ParseDelegation("example", []byte(text), s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

var testClock = func() time.Time { return time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC) }

func TestThePolicyReachesTheConfigurationUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name   string
		text   string
		stores []handoff.Store
		pins   []handoff.PINPolicy
		fw     string
		months int
	}{
		{"one of each", "version: 1\nname: Example\nrelease_address: a@example.org\npolicy:\n  stores: [software]\n  min_firmware: 5.7.0\n  pin_policy: [once]\n  require_name_constraints: true\n  validity_months: 1\n",
			[]handoff.Store{handoff.StoreSoftware}, []handoff.PINPolicy{handoff.PINOnce}, "5.7.0", 1},
		{"two of each", "version: 1\nname: Example\nrelease_address: a@example.org\npolicy:\n  stores: [aws-kms, piv]\n  min_firmware: 05.10.3\n  pin_policy: [always, never]\n  require_name_constraints: true\n  validity_months: 36\n",
			[]handoff.Store{handoff.StoreKMS, handoff.StorePIV}, []handoff.PINPolicy{handoff.PINAlways, handoff.PINNever}, "05.10.3", 36},
		{"all of each", "version: 1\nname: Example\nrelease_address: a@example.org\npolicy:\n  stores: [piv, openpgp-card, aws-kms, software]\n  min_firmware: 5.7.0\n  pin_policy: [never, once, always]\n  require_name_constraints: true\n  validity_months: 999999999\n",
			[]handoff.Store{handoff.StorePIV, handoff.StoreOpenPGPCard, handoff.StoreKMS, handoff.StoreSoftware}, []handoff.PINPolicy{handoff.PINNever, handoff.PINOnce, handoff.PINAlways}, "5.7.0", 999999999},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := wanted.ParseSettings(wanted.SettingsPath, []byte(tc.text))
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := configOf(s, nil, []handoff.RootRef{{}}, testClock, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(cfg.Policy.Stores, tc.stores) || !slices.Equal(cfg.Policy.PINPolicies, tc.pins) || cfg.Policy.MinFirmware != tc.fw || cfg.Policy.ValidityMonths != tc.months {
				t.Errorf("policy %+v", cfg.Policy)
			}
			if cfg.Delegation != nil {
				t.Errorf("no delegation was named and the configuration has %+v", cfg.Delegation)
			}
			if len(cfg.Roots) != 1 || cfg.Now == nil || !cfg.Now().Equal(testClock()) || cfg.Evidence != nil {
				t.Errorf("roots %v, clock set %v, evidence %v", cfg.Roots, cfg.Now != nil, cfg.Evidence)
			}
		})
	}
}

func TestTheDelegationReachesTheConfigurationWithEverythingTheChecksRead(t *testing.T) {
	s := madeSettings(t)
	const roles = "kms_read_roles:\n  \"111122223333\": arn:aws:iam::111122223333:role/a\n  \"444455556666\": arn:aws:iam::444455556666:role/b\n"
	for _, tc := range []struct {
		name string
		text string
		want handoff.Delegation
	}{
		{"x509 with both lists", "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_uri_hosts: [example.org, .example.org]\npermitted_dns_names: [example.org]\n",
			handoff.Delegation{Name: "example", Type: handoff.TypeX509, Root: "acme-tls", PermittedURIHosts: []string{"example.org", ".example.org"}, PermittedDNSNames: []string{"example.org"}}},
		{"x509 with one list and roles", "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_dns_names: [a.example.org]\n" + roles,
			handoff.Delegation{Name: "example", Type: handoff.TypeX509, Root: "acme-tls", PermittedDNSNames: []string{"a.example.org"},
				KMSReadRoles: map[string]string{"111122223333": "arn:aws:iam::111122223333:role/a", "444455556666": "arn:aws:iam::444455556666:role/b"}}},
		{"openpgp sign", "version: 1\ntype: openpgp-subkey\nroot: acme-release\ncapability: sign\n",
			handoff.Delegation{Name: "example", Type: handoff.TypeOpenPGP, Root: "acme-release", Capability: "sign"}},
		{"openpgp authenticate with roles", "version: 1\ntype: openpgp-subkey\nroot: acme-release\ncapability: authenticate\n" + roles,
			handoff.Delegation{Name: "example", Type: handoff.TypeOpenPGP, Root: "acme-release", Capability: "authenticate",
				KMSReadRoles: map[string]string{"111122223333": "arn:aws:iam::111122223333:role/a", "444455556666": "arn:aws:iam::444455556666:role/b"}}},
		{"ssh user", "version: 1\ntype: ssh-ca-key\nroot: acme-ssh\nuse: user\n", handoff.Delegation{Name: "example", Type: handoff.TypeSSH, Root: "acme-ssh", Use: "user"}},
		{"ssh host", "version: 1\ntype: ssh-ca-key\nroot: acme-ssh\nuse: host\n", handoff.Delegation{Name: "example", Type: handoff.TypeSSH, Root: "acme-ssh", Use: "host"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := madeDelegation(t, s, tc.text)
			cfg, err := configOf(s, d, []handoff.RootRef{{}}, testClock, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.Delegation
			if got == nil {
				t.Fatal("no delegation in the configuration")
			}
			if got.Name != tc.want.Name || got.Type != tc.want.Type || got.Root != tc.want.Root || got.Capability != tc.want.Capability || got.Use != tc.want.Use ||
				!slices.Equal(got.PermittedURIHosts, tc.want.PermittedURIHosts) || !slices.Equal(got.PermittedDNSNames, tc.want.PermittedDNSNames) {
				t.Errorf("delegation %+v, want %+v", *got, tc.want)
			}
			if len(got.KMSReadRoles) != len(tc.want.KMSReadRoles) {
				t.Errorf("roles %v, want %v", got.KMSReadRoles, tc.want.KMSReadRoles)
			}
			for k, v := range tc.want.KMSReadRoles {
				if got.KMSReadRoles[k] != v {
					t.Errorf("role %s: %q, want %q", k, got.KMSReadRoles[k], v)
				}
			}
			// The configuration holds copies: a change to them changes nothing in the delegation that was read.
			if len(got.PermittedURIHosts) > 0 {
				got.PermittedURIHosts[0] = "changed"
				if d.PermittedURIHosts[0] == "changed" {
					t.Error("the URI list is shared")
				}
			}
			if len(got.PermittedDNSNames) > 0 {
				got.PermittedDNSNames[0] = "changed"
				if d.PermittedDNSNames[0] == "changed" {
					t.Error("the DNS list is shared")
				}
			}
			for k := range got.KMSReadRoles {
				got.KMSReadRoles[k] = "changed"
				if d.KMSReadRoles[k] == "changed" {
					t.Error("the roles are shared")
				}
			}
		})
	}
}

func TestAHandMadeSettingsOrDelegationIsRefused(t *testing.T) {
	good := madeSettings(t)
	d := madeDelegation(t, good, "version: 1\ntype: ssh-ca-key\nroot: acme-ssh\nuse: user\n")
	byHandSettings := &wanted.Settings{Version: 1, Name: "Example", ReleaseAddress: "a@example.org", Policy: good.Policy}
	byHandDelegation := &wanted.Delegation{Name: "example", Type: wanted.TypeSSHCAKey, Root: "acme-ssh", Use: "user"}
	for name, tc := range map[string]struct {
		s *wanted.Settings
		d *wanted.Delegation
	}{
		"nil settings":                        {nil, nil},
		"zero settings":                       {&wanted.Settings{}, nil},
		"settings by hand":                    {byHandSettings, nil},
		"a zero delegation":                   {good, &wanted.Delegation{}},
		"a delegation by hand":                {good, byHandDelegation},
		"settings by hand, a good delegation": {byHandSettings, d},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := configOf(tc.s, tc.d, []handoff.RootRef{{}}, testClock, nil)
			if err == nil {
				t.Fatalf("accepted: %+v", cfg)
			}
			if cfg.Delegation != nil || len(cfg.Roots) != 0 || cfg.Now != nil {
				t.Errorf("a part of a configuration beside the error: %+v", cfg)
			}
		})
	}
}

// The OpenPGP primaries are not set: the field does not exist yet, and a configuration made from the files holds
// only what the files and the caller give.
func TestTheConfigurationHoldsOnlyWhatTheFilesAndTheCallerGive(t *testing.T) {
	s := madeSettings(t)
	cfg, err := configOf(s, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Roots != nil || cfg.Now != nil || cfg.Evidence != nil || cfg.Delegation != nil {
		t.Errorf("%+v", cfg)
	}
	// handoff.New then refuses it for what is missing: the roots and the clock.
	if _, err := handoff.New(cfg); !errors.Is(err, handoff.ErrConfig) {
		t.Errorf("New: %v", err)
	}
}

// splitDir and the set names.

func TestSplitDir(t *testing.T) {
	for _, tc := range []struct {
		dir, parent, last string
	}{
		{"acme", ".", "acme"}, {"acme/", ".", "acme"}, {"./acme", ".", "acme"}, {"/tmp/acme", "/tmp/", "acme"}, {"/tmp//acme", "/tmp/", "acme"}, {"a/b/c", "a/b/", "c"}, {"/acme", "/", "acme"}, {"a/.", ".", "a"},
	} {
		parent, last, err := splitDir(tc.dir)
		if err != nil || parent != tc.parent || last != tc.last {
			t.Errorf("splitDir(%q) = %q %q %v, want %q %q", tc.dir, parent, last, err, tc.parent, tc.last)
		}
	}
	for _, dir := range []string{"", "..", "a/..", "../a", "a/../b", "/", ".", "a b", "/tmp/a b", ".rt-abc", "con", "a\x00"} {
		if _, _, err := splitDir(dir); err == nil {
			t.Errorf("splitDir(%q) accepts", dir)
		}
	}
}

func TestParseSetName(t *testing.T) {
	for name, want := range map[string]int64{"1-00000000": 1, "7-3fa9c1d2": 7, "13-bbbbbbbb": 13, "9223372036854775807-aaaaaaaa": 9223372036854775807, "100-0123abcd": 100} {
		set, ok := parseSetName(name)
		if !ok || set.Number != want || set.Name != name {
			t.Errorf("%q: %+v %v", name, set, ok)
		}
	}
	for _, name := range []string{"", "0-aaaaaaaa", "07-aaaaaaaa", "-1-aaaaaaaa", "+7-aaaaaaaa", "7-AAAAAAAA", "7-aaaaaaa", "7-aaaaaaaaa", "7-gaaaaaaa", "7_aaaaaaaa", "7-aaaaaaaa ", " 7-aaaaaaaa",
		"7-aaaaaaaa\n", "9223372036854775808-aaaaaaaa", "99999999999999999999-aaaaaaaa", "7", "7-", "-aaaaaaaa", "a-aaaaaaaa", "7-aaaaaaaa-", "7--aaaaaaaa", "\u0667-aaaaaaaa", "7-\u0430aaaaaaa", ".rt-aaaaaaaaaaa"} {
		if set, ok := parseSetName(name); ok {
			t.Errorf("%q is a set name: %+v", name, set)
		}
	}
}

// A Bundle that holds a folder and settings that the reader did not make is no bundle.
func TestABundleWithSettingsThatTheReaderDidNotMakeIsRefused(t *testing.T) {
	real, err := fsx.OpenFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = real.Close() }()
	for name, settings := range map[string]*wanted.Settings{"nil": nil, "zero": {}, "by hand": {Version: 1, Name: "Example"}} {
		b := &Bundle{fsys: real, settings: settings}
		if err := b.usable(); !errors.Is(err, ErrBundle) {
			t.Errorf("%s: %v", name, err)
		}
		if _, _, err := b.Roots(); !errors.Is(err, ErrBundle) {
			t.Errorf("%s: Roots: %v", name, err)
		}
	}
	if err := (&Bundle{fsys: real, settings: madeSettings(t)}).usable(); err != nil {
		t.Errorf("a bundle with settings that the reader made: %v", err)
	}
}

// A fault at the last call, the flush after the rename of ritueel.yaml, leaves everything on disk: the two folders,
// the two root files and ritueel.yaml, which is listed because its rename succeeded. The error says that the bundle
// is whole and that only the flush failed, and the folder opens as a bundle.
func TestTheLastFaultListsEverythingThatWasWritten(t *testing.T) {
	_, clean, _, _ := runCreate(t, 0, StarterOptions{})
	parent, _, _, err := runCreate(t, clean.n, StarterOptions{})
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatal(err)
	}
	want := []string{"want/", "want/roots/", "want/roots/x509.yaml", "want/roots/openpgp.yaml", "ritueel.yaml"}
	if !ce.Made || !slices.Equal(ce.Written, want) {
		t.Errorf("made %v, written %v, want %v", ce.Made, ce.Written, want)
	}
	const whole = "the bundle is whole on disk but was not flushed: it may not survive a power cut"
	if !strings.Contains(err.Error(), whole) || strings.Contains(err.Error(), "things were written") {
		t.Errorf("the text of the error: %q", err)
	}
	b, oerr := Open(filepath.Join(parent, "acme"))
	if oerr != nil {
		t.Fatalf("the whole bundle does not open: %v", oerr)
	}
	_ = b.Close()
}

// Only the fault at the very last flush says that the bundle is whole. Every earlier fault says how many things
// were written in the folder, and that number is the length of the list.
func TestOnlyTheLastFlushSaysThatTheBundleIsWhole(t *testing.T) {
	_, clean, _, _ := runCreate(t, 0, StarterOptions{})
	for n := 1; n <= clean.n; n++ {
		_, _, _, err := runCreate(t, n, StarterOptions{})
		var ce *CreateError
		if !errors.As(err, &ce) {
			t.Fatalf("call %d: %v", n, err)
		}
		whole := strings.Contains(err.Error(), "whole on disk")
		if whole != (n == clean.n) {
			t.Errorf("call %d of %d: whole is %v: %s", n, clean.n, whole, err)
		}
		if !whole && ce.Made {
			if want := fmt.Sprintf("the folder was made and %d things were written in it", len(ce.Written)); !strings.Contains(err.Error(), want) {
				t.Errorf("call %d: want %q in %s", n, want, err)
			}
		}
		if !whole && !ce.Made && !strings.Contains(err.Error(), "the folder was not made") {
			t.Errorf("call %d: %s", n, err)
		}
	}
}

// existsAfter: a make or a rename that succeeded exists, and so does one whose flush failed; a fault at any earlier
// step leaves the name unmade. A fault that wraps an *fsx.Error is read through the wrap.
func TestExistsAfterTellsTheFlushFromEveryEarlierStep(t *testing.T) {
	steps := []fsx.Step{fsx.StepOpenDir, fsx.StepMkdir, fsx.StepCreate, fsx.StepWrite, fsx.StepSyncFile, fsx.StepRename, fsx.StepSyncDir, fsx.StepRead}
	for _, s := range steps {
		got := existsAfter(&fsx.Error{Step: s, Path: "x", Err: errors.New("e")})
		if want := s == fsx.StepSyncDir; got != want {
			t.Errorf("step %s: %v, want %v", s, got, want)
		}
		wrapped := fmt.Errorf("outer: %w", &fsx.Error{Step: s, Path: "x", Err: errors.New("e")})
		if got := existsAfter(wrapped); got != (s == fsx.StepSyncDir) {
			t.Errorf("wrapped step %s: %v", s, got)
		}
	}
	if !existsAfter(nil) {
		t.Error("no error: the name exists")
	}
	if existsAfter(errors.New("plain")) {
		t.Error("a plain error is not a flush")
	}
}

// The make of the folder is followed by a flush of the parent. A fault at the make leaves nothing and the error says
// so; the first fault that leaves the folder on disk is the fault at the flush, and the error then says that the
// folder was made, with nothing written in it, so that the caller tells the person to remove it.
func TestAFaultAtTheMakeAndAtTheFlushOfTheParentAreToldApart(t *testing.T) {
	for _, testRoot := range []bool{false, true} {
		opt := StarterOptions{TestRoot: testRoot}
		_, clean, _, _ := runCreate(t, 0, opt)
		first := 0
		for n := 1; n <= clean.n; n++ {
			parent, _, _, err := runCreate(t, n, opt)
			var ce *CreateError
			if !errors.As(err, &ce) {
				t.Fatalf("call %d: %v", n, err)
			}
			_, statErr := os.Lstat(filepath.Join(parent, "acme"))
			if statErr != nil {
				// Nothing is made: the first call, and only calls before the folder exists.
				if first != 0 {
					t.Fatalf("call %d: the folder is gone after call %d left it", n, first)
				}
				if ce.Made || len(ce.Written) != 0 || !strings.Contains(err.Error(), "the folder was not made") {
					t.Errorf("call %d: nothing is made and the error says: Made %v, Written %v, %q", n, ce.Made, ce.Written, err)
				}
				continue
			}
			if first == 0 {
				first = n
				ents, _ := os.ReadDir(filepath.Join(parent, "acme"))
				if len(ents) != 0 || len(ce.Written) != 0 {
					t.Errorf("call %d: the first fault that leaves the folder leaves it empty: %d entries, written %v", n, len(ents), ce.Written)
				}
				if !ce.Made || !strings.Contains(err.Error(), "the folder was made and 0 things were written in it") {
					t.Errorf("call %d: the folder exists and the error says: Made %v, %q", n, ce.Made, err)
				}
			}
		}
		if first < 2 {
			t.Errorf("test root %v: the first call that leaves the folder is call %d, want a call after the first", testRoot, first)
		}
	}
}

// CreateError.Written "lists what was made inside the folder before the stop". Everything that exists in the folder
// after a fault is listed, but the temporary files that the writer leaves under a name that starts with ".rt-" (a
// cut leaves them; nothing is deleted). A make or a rename that succeeded counts as made even when the flush after
// it failed, as it does for the folder itself.
func TestEverythingThatExistsAfterAFaultIsListedExceptTemporaryNames(t *testing.T) {
	_, clean, _, _ := runCreate(t, 0, StarterOptions{})
	for n := 1; n <= clean.n; n++ {
		parent, _, _, err := runCreate(t, n, StarterOptions{})
		var ce *CreateError
		if !errors.As(err, &ce) {
			t.Fatalf("call %d: %v", n, err)
		}
		root := filepath.Join(parent, "acme")
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
			rel, rerr := filepath.Rel(root, p)
			if werr != nil || rerr != nil || rel == "." {
				return nil
			}
			if strings.HasPrefix(d.Name(), ".rt-") {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				rel += "/"
			}
			if !slices.Contains(ce.Written, rel) {
				t.Errorf("a fault at call %d of %d: %s exists and the error does not list it (%v)", n, clean.n, rel, ce.Written)
			}
			return nil
		})
	}
}
