//go:build linux || darwin

package ceremony_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/wanted"
)

// A name that starts with ".rt-", in any case, in want/roots, want/delegations or want/cards is the
// leftover of a stopped write. Find skips it as a reader of a bundle does (record 0006, rule 45): the
// bundle gives the same answer as without it, and nothing is read from it. The names of this file
// start with ft.

const ftDelegation = "version: 1\ntype: x509-intermediate\nroot: x509\npermitted_dns_names: [example.org]\npermitted_uri_hosts: [example.org]\n"

// ftLeftovers makes, in each of the three folders of dir, a leftover of each kind, under names of
// different case.
func ftLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	var made []string
	for _, folder := range []string{"roots", "delegations", "cards"} {
		base := filepath.Join(dir, "want", folder)
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, text := range map[string]string{
			".rt-k3j9x0a1b2c":      "not a record: [",
			".rt-k3j9x0a1b2d.yaml": pfX509Real,
			".RT-X.YAML":           "version: 1\nkind: nonsense\n",
			".Rt-":                 "",
			".rT-z.yaml":           ftDelegation,
		} {
			if err := os.WriteFile(filepath.Join(base, name), []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
			made = append(made, filepath.Join(base, name))
		}
		folderLeft := filepath.Join(base, ".rt-folder")
		if err := os.MkdirAll(filepath.Join(folderLeft, "nested.yaml"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(folderLeft, "x509.yaml"), []byte(pfX509Real), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, ".RT-link.yaml")
		if err := os.Symlink("../../ritueel.yaml", link); err != nil {
			t.Fatal(err)
		}
		fifo := filepath.Join(base, ".rt-fifo")
		if err := syscall.Mkfifo(fifo, 0o644); err != nil {
			t.Fatal(err)
		}
		made = append(made, folderLeft, link, fifo)
	}
	return made
}

// ftSummary is what a Found says, as text, to compare two of them.
func ftSummary(f *ceremony.Found) string {
	if f == nil {
		return "<nil>"
	}
	var b strings.Builder
	for _, c := range f.Applies {
		fmt.Fprintf(&b, "applies %+v\n", c)
	}
	for _, l := range f.LeavesOut {
		fmt.Fprintf(&b, "leaves out %+v\n", l)
	}
	if f.Root != nil {
		fmt.Fprintf(&b, "root %s %s %v\n", f.Root.Name, f.Root.Kind, f.Root.Test)
	}
	for _, w := range f.Wanted {
		fmt.Fprintf(&b, "wanted %s %s\n", w.Path, w.SHA256)
	}
	return b.String()
}

func TestFindGivesTheSamePlanWithLeftoversInTheWantedFolders(t *testing.T) {
	files := pfFiles()
	files["want/delegations/acme-tls.yaml"] = ftDelegation
	base, err := pfFind(t, pfWrite(t, files))
	if err != nil || base.Nothing() {
		t.Fatalf("Find without leftovers = %+v, %v", base, err)
	}
	dir := pfWrite(t, files)
	made := ftLeftovers(t, dir)
	before := tree(t, dir)
	got, reads, err := efFind(t, pfOpen(t, dir))
	if err != nil {
		t.Fatalf("Find with leftovers: %v", err)
	}
	if ftSummary(got) != ftSummary(base) {
		t.Errorf("Find with leftovers:\n%s\nwithout:\n%s", ftSummary(got), ftSummary(base))
	}
	for _, p := range reads.paths {
		if strings.Contains(strings.ToLower(p), "/.rt-") {
			t.Errorf("a leftover was read: %q", p)
		}
	}
	sameTree(t, "Find", before, tree(t, dir))
	for _, p := range made {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("a leftover is gone: %v", err)
		}
	}
	// The plan that is made of it is the plan without the leftovers.
	want, err := ceremony.MakePlan(base, pfEnv())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ceremony.MakePlan(got, pfEnv())
	if err != nil {
		t.Fatal(err)
	}
	if string(plan.JSON) != string(want.JSON) || plan.SHA256 != want.SHA256 {
		t.Errorf("the plan differs:\n%s\n%s", plan.JSON, want.JSON)
	}
}

// A leftover is no root file: it does not make a second root, so a bundle of one root file and any
// number of leftovers is the first apply of that one root, and a bundle of more root files than the
// limit of reading is refused with the count of the root files and not of the leftovers.
func TestLeftoversAreNotCountedAsRootFiles(t *testing.T) {
	t.Run("one root file and more leftovers than the limit of files", func(t *testing.T) {
		files := pfFiles()
		for i := range wanted.MaxFiles + 100 {
			files[fmt.Sprintf("want/roots/.rt-%011d", i)] = pfX509Real
		}
		f, reads, err := efFind(t, pfOpen(t, pfWrite(t, files)))
		if err != nil || f.Nothing() || f.Root == nil || f.Root.Name != "x509" {
			t.Fatalf("Find = %+v, %v", f, err)
		}
		if reads.of("want/roots/x509.yaml") != 1 || reads.under("want/roots") != 1 {
			t.Errorf("the root files read are %q", reads.paths)
		}
	})
	t.Run("nine root files and leftovers are refused as nine", func(t *testing.T) {
		with := map[string]string{"ritueel.yaml": pfSettings}
		without := map[string]string{"ritueel.yaml": pfSettings}
		for i := range 9 {
			with["want/roots/"+efRootName(i)+".yaml"] = pfX509Test
			without["want/roots/"+efRootName(i)+".yaml"] = pfX509Test
		}
		for i := range 30 {
			with[fmt.Sprintf("want/roots/.rt-%011d", i)] = pfX509Test
			with[fmt.Sprintf("want/roots/.RT-%011d.yaml", i)] = pfX509Test
		}
		_, readsWith, errWith := efFind(t, pfOpen(t, pfWrite(t, with)))
		_, _, errWithout := efFind(t, pfOpen(t, pfWrite(t, without)))
		if errWith == nil || errWithout == nil || errWith.Error() != errWithout.Error() {
			t.Fatalf("Find with leftovers: %v; without: %v", errWith, errWithout)
		}
		if !strings.Contains(errWith.Error(), "9 root files") || pfKind(errWith) != "not-built" {
			t.Errorf("Find = %v (%s)", errWith, pfKind(errWith))
		}
		if readsWith.under("want/roots") != 0 {
			t.Errorf("%d root files were read", readsWith.under("want/roots"))
		}
	})
	t.Run("eight root files and leftovers are read as eight", func(t *testing.T) {
		with := map[string]string{"ritueel.yaml": pfSettings}
		for i := range 8 {
			with["want/roots/"+efRootName(i)+".yaml"] = pfX509Test
		}
		for i := range 30 {
			with[fmt.Sprintf("want/roots/.rt-%011d", i)] = "x"
		}
		_, reads, err := efFind(t, pfOpen(t, pfWrite(t, with)))
		if pfKind(err) != "not-built" || !strings.Contains(err.Error(), "8 root files") {
			t.Fatalf("Find = %v (%s)", err, pfKind(err))
		}
		if n := reads.under("want/roots"); n != 8 {
			t.Errorf("%d root files were read, want 8", n)
		}
	})
}

// A leftover does not hide a refusal: a wanted file that fails is still told, with its own path.
func TestALeftoverDoesNotHideARefusalOfFind(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		path  string
	}{
		"a root name of another form":            {map[string]string{"want/roots/BAD.yaml": pfX509Test}, "want/roots/BAD.yaml"},
		"a root that fails its check":            {map[string]string{"want/roots/bad.yaml": "version: 1\nkind: nonsense\n"}, "want/roots/bad.yaml"},
		"a delegation of a bad name":             {map[string]string{"want/delegations/BAD.yaml": ftDelegation}, "want/delegations/BAD.yaml"},
		"a delegation that fails":                {map[string]string{"want/delegations/a.yaml": "type: nonsense\n"}, "want/delegations/a.yaml"},
		"a delegation of a missing root":         {map[string]string{"want/delegations/a.yaml": "version: 1\ntype: x509-intermediate\nroot: nothing\npermitted_dns_names: [example.org]\n"}, "want/roots/nothing.yaml"},
		"a name that only looks like the prefix": {map[string]string{"want/roots/.rtx.yaml": pfX509Test}, "want/roots/.rtx.yaml"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			files := pfFiles()
			for p, text := range c.files {
				files[p] = text
			}
			dir := pfWrite(t, files)
			ftLeftovers(t, dir)
			before := tree(t, dir)
			f, err := pfFind(t, dir)
			if f != nil || err == nil || pfKind(err) != "failure" {
				t.Fatalf("Find = %+v, %v (%s)", f, err, pfKind(err))
			}
			if !strings.Contains(err.Error(), c.path) {
				t.Errorf("the error %q does not name %q", err, c.path)
			}
			if strings.Contains(strings.ToLower(err.Error()), ".rt-") && c.path != "want/roots/.rtx.yaml" {
				t.Errorf("the error names a leftover: %q", err)
			}
			if !pfPrintable(err.Error()) {
				t.Errorf("the error is not printable ASCII: %+q", err.Error())
			}
			sameTree(t, "Find", before, tree(t, dir))
		})
	}
}

// A bundle that holds nothing else than leftovers in want/roots has no root: nothing is applied.
func TestABundleWithOnlyLeftoversInTheRootsFolderHasNothingToApply(t *testing.T) {
	dir := pfWrite(t, map[string]string{"ritueel.yaml": pfSettings})
	ftLeftovers(t, dir)
	f, err := pfFind(t, dir)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if !f.Nothing() || f.Root != nil || len(f.Wanted) != 0 {
		t.Errorf("Find = %s", ftSummary(f))
	}
}
