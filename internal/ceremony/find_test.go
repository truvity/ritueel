//go:build linux || darwin

package ceremony_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/wanted"
)

// Find is the function of record 0005, rules 4 and 5 and 19: it reads the wanted files and the
// state of the bundle, writes nothing and stores nothing. In this version it knows one case, the
// first apply of a bundle that has one X.509 test root and no history.

func TestFindOfAFirstApplyBundleChangesTwoKeysOfTheRoot(t *testing.T) {
	dir := pfWrite(t, pfFiles())
	f, err := pfFind(t, dir)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if f.Nothing() {
		t.Fatal("Nothing() is true for a bundle with a root file")
	}
	wantChanges := []ceremony.Change{{Change: "create", Object: "x509/A"}, {Change: "create", Object: "x509/B"}}
	if !reflect.DeepEqual(f.Applies, wantChanges) {
		t.Errorf("Applies = %+v, want %+v", f.Applies, wantChanges)
	}
	if len(f.LeavesOut) != 0 {
		t.Errorf("LeavesOut = %+v, want none", f.LeavesOut)
	}
	if !f.Settings.Valid() || f.Settings.Name != "Example" {
		t.Errorf("Settings = %+v", f.Settings)
	}
	if f.Root == nil || !f.Root.Valid() || f.Root.Name != "x509" || f.Root.Kind != wanted.RootX509 || !f.Root.Test {
		t.Errorf("Root = %+v", f.Root)
	}
	// The wanted files are the bytes that were read, ritueel.yaml first, the root file second.
	if len(f.Wanted) != 2 {
		t.Fatalf("Wanted has %d files, want 2", len(f.Wanted))
	}
	for i, w := range []struct{ path, text string }{{"ritueel.yaml", pfSettings}, {"want/roots/x509.yaml", pfX509Test}} {
		got := f.Wanted[i]
		if got.Path != w.path || string(got.Data) != w.text || got.SHA256 != sum([]byte(w.text)) {
			t.Errorf("Wanted[%d] = %q with %d bytes and the digest %s, want %q", i, got.Path, len(got.Data), got.SHA256, w.path)
		}
	}
	if f.State == nil || f.State.Records != 0 || f.State.Newest != nil || len(f.State.Lists) != 0 || len(f.State.Unfinished) != 0 {
		t.Errorf("State = %+v, want the state of a bundle with no history", f.State)
	}
}

func TestFindWritesNothingAndChangesNothingOnTheDisk(t *testing.T) {
	dir := pfWrite(t, pfFiles())
	before := tree(t, dir)
	for range 2 {
		if _, err := pfFind(t, dir); err != nil {
			t.Fatal(err)
		}
	}
	sameTree(t, "Find", before, tree(t, dir))
}

func TestFindGivesTheSameThingTwiceAndTheBytesAreOwnCopies(t *testing.T) {
	dir := pfWrite(t, pfFiles())
	a, err := pfFind(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	a.Wanted[0].Data[0] ^= 0xff
	a.Applies[0].Object = "x509/Z"
	b, err := pfFind(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(b.Wanted[0].Data) != pfSettings || b.Applies[0].Object != "x509/A" {
		t.Errorf("a second Find was changed by the change of the first result")
	}
}

func TestFindOfABundleWithNoRootFileHasNothingToApply(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no want folder":        {"ritueel.yaml": pfSettings},
		"an empty roots folder": {"ritueel.yaml": pfSettings, "want/roots/.keep-not-a-root": ""},
	} {
		t.Run(name, func(t *testing.T) {
			dir := pfWrite(t, files)
			if name == "an empty roots folder" {
				if err := os.Remove(filepath.Join(dir, "want/roots/.keep-not-a-root")); err != nil {
					t.Fatal(err)
				}
			}
			f, err := pfFind(t, dir)
			if err != nil {
				t.Fatalf("Find: %v", err)
			}
			if !f.Nothing() || len(f.Applies) != 0 || f.Root != nil {
				t.Errorf("Found = %+v, want nothing to apply", f)
			}
		})
	}
}

func TestNothingIsTrueForANilAndAZeroFound(t *testing.T) {
	var nilFound *ceremony.Found
	if !nilFound.Nothing() || !(&ceremony.Found{}).Nothing() {
		t.Error("a nil Found and a zero Found must have nothing to apply")
	}
	if (&ceremony.Found{Applies: []ceremony.Change{{Change: "create", Object: "x509/A"}}}).Nothing() {
		t.Error("a Found with a change has something to apply")
	}
}

func TestARequestIsLeftOutWithTheReasonAndIsNeverRead(t *testing.T) {
	files := pfFiles()
	files["requests/zeta-ca/request.json"] = "\x00\xff not even text {{{"
	files["requests/acme-ca-2027/request.json"] = "garbage"
	files["requests/mid-1/other"] = ""
	dir := pfWrite(t, files)
	f, err := pfFind(t, dir)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	want := []ceremony.LeftOut{
		{Object: "requests/acme-ca-2027", Reason: pfLeftOutReason},
		{Object: "requests/mid-1", Reason: pfLeftOutReason},
		{Object: "requests/zeta-ca", Reason: pfLeftOutReason},
	}
	if !reflect.DeepEqual(f.LeavesOut, want) {
		t.Errorf("LeavesOut = %+v\nwant         %+v", f.LeavesOut, want)
	}
	if len(f.Applies) != 2 {
		t.Errorf("a request changed what is applied: %+v", f.Applies)
	}
}

func TestARequestIsLeftOutAlsoWhenThereIsNoRootFile(t *testing.T) {
	dir := pfWrite(t, map[string]string{"ritueel.yaml": pfSettings, "requests/acme-ca/request.json": "{}"})
	f, err := pfFind(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Nothing() || len(f.LeavesOut) != 1 || f.LeavesOut[0].Object != "requests/acme-ca" {
		t.Errorf("Found = %+v", f)
	}
}

func TestFindRefusesWhatThisVersionDoesNotBuildAndWritesNothing(t *testing.T) {
	// Each case is a row of the refusals of the first apply: a text that names the file and says
	// what to do, the kind of the refusal, and a folder that is the same after.
	type refusal struct {
		files map[string]string
		words []string
	}
	with := func(extra map[string]string) map[string]string {
		m := pfFiles()
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	cases := map[string]refusal{
		"an OpenPGP root file": {with(map[string]string{"want/roots/openpgp.yaml": pfOpenPGPTest}),
			[]string{"want/roots/openpgp.yaml", "openpgp", "delete that file"}},
		"an OpenPGP root file alone": {map[string]string{"ritueel.yaml": pfSettings, "want/roots/openpgp.yaml": pfOpenPGPTest},
			[]string{"want/roots/openpgp.yaml", "delete that file"}},
		"an SSH root file": {with(map[string]string{"want/roots/ssh.yaml": pfSSHTest}),
			[]string{"want/roots/ssh.yaml", "ssh", "delete that file"}},
		"a root that says test is false": {map[string]string{"ritueel.yaml": pfSettings, "want/roots/x509.yaml": pfX509Real},
			[]string{"want/roots/x509.yaml", "not a test root"}},
		"a root with no test member": {map[string]string{"ritueel.yaml": pfSettings, "want/roots/x509.yaml": pfX509NoTest},
			[]string{"want/roots/x509.yaml", "not a test root"}},
		"two X.509 root files": {with(map[string]string{"want/roots/other.yaml": pfX509Test}),
			[]string{"2 root files", "want/roots/other.yaml", "want/roots/x509.yaml"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := pfWrite(t, c.files)
			before := tree(t, dir)
			f, err := pfFind(t, dir)
			if err == nil || f != nil {
				t.Fatalf("Find = %+v, %v; want a refusal and no Found", f, err)
			}
			if k := pfKind(err); k != "not-built" {
				t.Errorf("kind = %s (%v), want not-built (exit code 1)", k, err)
			}
			if !errors.Is(err, ceremony.ErrNotBuilt) {
				t.Errorf("the error does not wrap ErrNotBuilt: %v", err)
			}
			for _, w := range c.words {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the text %q does not hold %q", err, w)
				}
			}
			if !strings.Contains(err.Error(), "nothing was written") {
				t.Errorf("the text does not say that nothing was written: %v", err)
			}
			if !pfPrintable(err.Error()) {
				t.Errorf("the text is not printable ASCII: %+q", err.Error())
			}
			sameTree(t, "Find", before, tree(t, dir))
		})
	}
}

func TestTheRefusalsOfARootFileComeInTheOrderOfTheRow(t *testing.T) {
	// openpgp or ssh first, then a root that is not a test root, then two roots of one kind. A personal bundle
	// has its own refusals: see find_personal_test.go.
	cases := []struct {
		name  string
		files map[string]string
		first string
	}{
		{"openpgp before not a test root", map[string]string{"ritueel.yaml": pfSettings, "want/roots/a.yaml": pfX509Real, "want/roots/z-openpgp.yaml": pfOpenPGPTest}, "want/roots/z-openpgp.yaml"},
		{"ssh before not a test root", map[string]string{"ritueel.yaml": pfSettings, "want/roots/a.yaml": pfX509Real, "want/roots/z-ssh.yaml": pfSSHTest}, "want/roots/z-ssh.yaml"},
		{"not a test root before two roots", map[string]string{"ritueel.yaml": pfSettings, "want/roots/a.yaml": pfX509Test, "want/roots/b.yaml": pfX509Real}, "want/roots/b.yaml"},
		{"two roots of a company bundle", map[string]string{"ritueel.yaml": pfSettings, "want/roots/a.yaml": pfX509Test, "want/roots/b.yaml": pfX509Test}, "2 root files"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := pfFind(t, pfWrite(t, c.files))
			if pfKind(err) != "not-built" || !strings.Contains(err.Error(), c.first) {
				t.Errorf("Find = %v (%s), want a refusal that names %q", err, pfKind(err), c.first)
			}
		})
	}
}

func TestAWantedFileThatFailsItsCheckIsAFailureThatNamesThePath(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		path  string
	}{
		"the settings file is missing":      {map[string]string{"want/roots/x509.yaml": pfX509Test}, "ritueel.yaml"},
		"the settings file is garbage":      {map[string]string{"ritueel.yaml": "version: 2\n"}, "ritueel.yaml"},
		"a root file fails its check":       {map[string]string{"ritueel.yaml": pfSettings, "want/roots/x509.yaml": "version: 1\nkind: nonsense\n"}, "want/roots/x509.yaml"},
		"a root file has a name it refuses": {map[string]string{"ritueel.yaml": pfSettings, "want/roots/X509.yaml": pfX509Test}, "want/roots/X509.yaml"},
		"a root file with a later member":   {map[string]string{"ritueel.yaml": pfSettings, "want/roots/x509.yaml": pfX509Test + "keys: 3\n"}, "want/roots/x509.yaml"},
		"a delegation fails its check":      {map[string]string{"ritueel.yaml": pfSettings, "want/roots/x509.yaml": pfX509Test, "want/delegations/a.yaml": "type: nonsense\n"}, "want/delegations/a.yaml"},
		"a delegation needs a missing root": {map[string]string{"ritueel.yaml": pfSettings, "want/roots/x509.yaml": pfX509Test, "want/delegations/a.yaml": "version: 1\ntype: x509-intermediate\nroot: nothing\npermitted_dns_names: [example.org]\n"}, "want/roots/nothing.yaml"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := pfWrite(t, c.files)
			before := tree(t, dir)
			f, err := pfFind(t, dir)
			if err == nil || f != nil {
				t.Fatalf("Find = %+v, %v", f, err)
			}
			if k := pfKind(err); k != "failure" {
				t.Errorf("kind = %s (%v), want a plain failure (exit code 1)", k, err)
			}
			if !strings.Contains(err.Error(), c.path) || !strings.Contains(err.Error(), "nothing was written") {
				t.Errorf("the text %q does not name %q and say that nothing was written", err, c.path)
			}
			if !pfPrintable(err.Error()) {
				t.Errorf("the text is not printable ASCII: %+q", err.Error())
			}
			sameTree(t, "Find", before, tree(t, dir))
		})
	}
}

func TestAMissingSettingsFileIsToldAsMissing(t *testing.T) {
	_, err := pfFind(t, pfWrite(t, map[string]string{"want/roots/x509.yaml": pfX509Test}))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Find = %v, want an error that wraps fs.ErrNotExist", err)
	}
}

func TestADelegationIsReadAndCheckedAndNotUsed(t *testing.T) {
	files := pfFiles()
	files["want/delegations/acme-tls.yaml"] = "version: 1\ntype: x509-intermediate\nroot: x509\npermitted_dns_names: [example.org]\npermitted_uri_hosts: [example.org]\n"
	f, err := pfFind(t, pfWrite(t, files))
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	for _, w := range f.Wanted {
		if strings.Contains(w.Path, "delegations") {
			t.Errorf("the plan would use the delegation file %s", w.Path)
		}
	}
	if len(f.Wanted) != 2 || len(f.Applies) != 2 {
		t.Errorf("Wanted %d, Applies %d", len(f.Wanted), len(f.Applies))
	}
}

func TestOtherFilesOfTheBundleAreNotRead(t *testing.T) {
	files := pfFiles()
	files["README"] = "x"
	files["want/other/thing.yaml"] = "not yaml {"
	files["notes/a.txt"] = "x"
	f, err := pfFind(t, pfWrite(t, files))
	if err != nil || len(f.Wanted) != 2 {
		t.Fatalf("Find = %+v, %v", f, err)
	}
}

// The state of the history.

// pfRecorded is a bundle that holds one finished synthetic ceremony and the wanted files of a first
// apply.
func pfRecorded(t *testing.T) *bundle {
	t.Helper()
	b := newBundle(t)
	for p, text := range pfFiles() {
		if err := os.MkdirAll(filepath.Dir(b.path(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b.path(p), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func TestAnAttemptThatIsOpenRefusesWithTheReasonAndNamesTheFolder(t *testing.T) {
	b := pfRecorded(t)
	fl := newFlow(t, b, newSpec(name1, 1, ""))
	fl.must("start")
	before := tree(t, b.dir)
	f, err := pfFind(t, b.dir)
	if f != nil || err == nil {
		t.Fatalf("Find = %+v, %v", f, err)
	}
	var refused *ceremony.RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("the error is %T (%v), want *RefusedError (exit code 3)", err, err)
	}
	if !slices.Equal(refused.Reasons, []string{"unfinished-ceremony"}) || ceremony.ReasonUnfinishedCeremony != "unfinished-ceremony" {
		t.Errorf("reasons = %q", refused.Reasons)
	}
	if !strings.Contains(err.Error(), "history/"+name1) || !strings.Contains(err.Error(), "nothing was written") {
		t.Errorf("the text %q does not name the folder history/%s", err, name1)
	}
	sameTree(t, "Find", before, tree(t, b.dir))
}

func TestAnOpenAttemptIsRefusedBeforeAnyOtherStateOfTheBundle(t *testing.T) {
	// A finished ceremony and a later one that stopped after its attempt: the reason is the open
	// attempt and never the plain text "not the first apply".
	b := pfRecorded(t)
	s1 := newSpec(name1, 1, "")
	f1 := newFlow(t, b, s1)
	f1.must("")
	s2 := newSpec(name2, 2, sum(f1.out))
	newFlow(t, b, s2).must("start")
	_, err := pfFind(t, b.dir)
	var refused *ceremony.RefusedError
	if !errors.As(err, &refused) || !slices.Equal(refused.Reasons, []string{"unfinished-ceremony"}) {
		t.Fatalf("Find = %v (%s), want the refusal of an open attempt", err, pfKind(err))
	}
	if !strings.Contains(err.Error(), "history/"+name2) || strings.Contains(err.Error(), "history/"+name1) {
		t.Errorf("the text %q must name the open folder %s and not the finished one", err, name2)
	}
}

func TestTheTextNamesThreeOpenFoldersAndCountsTheRest(t *testing.T) {
	b := pfRecorded(t)
	names := []string{"20261114T100000Z-apply", "20261114T110000Z-apply", "20261114T120000Z-apply", "20261114T130000Z-apply", "20261114T140000Z-apply"}
	for _, n := range names {
		newFlow(t, b, newSpec(n, 1, "")).must("start")
	}
	_, err := pfFind(t, b.dir)
	var refused *ceremony.RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("Find = %v (%s)", err, pfKind(err))
	}
	for _, n := range names[:3] {
		if !strings.Contains(err.Error(), "history/"+n) {
			t.Errorf("the text does not name %s: %v", n, err)
		}
	}
	for _, n := range names[3:] {
		if strings.Contains(err.Error(), n) {
			t.Errorf("the text names %s, which is beyond the first three: %v", n, err)
		}
	}
	if !strings.Contains(err.Error(), "and 2 more") {
		t.Errorf("the text does not count the two folders left: %v", err)
	}
}

func TestAFolderWithAPlanAndNoAttemptDoesNotRefuse(t *testing.T) {
	b := pfRecorded(t)
	newFlow(t, b, newSpec(name1, 1, "")).must("plan")
	f, err := pfFind(t, b.dir)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if f.Nothing() || len(f.State.Unfinished) != 0 {
		t.Errorf("Found = %+v", f)
	}
}

func TestABundleThatIsNotInTheFirstStateIsRefusedWithTheKindNotFirst(t *testing.T) {
	cases := map[string]struct {
		build func(t *testing.T, b *bundle)
		what  string
	}{
		"a ceremony record, a trust set and entries under roots": {func(t *testing.T, b *bundle) {
			newFlow(t, b, newSpec(name1, 1, "")).must("")
		}, "a ceremony record"},
		"an entry under roots only": {func(t *testing.T, b *bundle) {
			if err := os.MkdirAll(b.path("roots", "A"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "an entry under roots/"},
		"a file under roots only": {func(t *testing.T, b *bundle) {
			if err := os.MkdirAll(b.path("roots"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(b.path("roots", "stray"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "an entry under roots/"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := pfRecorded(t)
			c.build(t, b)
			before := tree(t, b.dir)
			f, err := pfFind(t, b.dir)
			if f != nil || err == nil {
				t.Fatalf("Find = %+v, %v", f, err)
			}
			if k := pfKind(err); k != "not-first" {
				t.Errorf("kind = %s (%v), want not-first (exit code 1)", k, err)
			}
			if !strings.Contains(err.Error(), c.what) || !strings.Contains(err.Error(), "nothing was written") {
				t.Errorf("the text %q does not say %q", err, c.what)
			}
			sameTree(t, "Find", before, tree(t, b.dir))
		})
	}
}

func TestAnEmptyFolderUnderRootsDoesNotMakeABundleNotFirst(t *testing.T) {
	dir := pfWrite(t, pfFiles())
	if err := os.Mkdir(filepath.Join(dir, "roots"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := pfFind(t, dir); err != nil {
		t.Errorf("Find = %v; an empty roots/ holds no entry", err)
	}
}

func TestAHistoryThatFailsItsOwnCheckIsRefusedWithTheCodesOfTheCheck(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"a link in history": func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "history"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/", filepath.Join(dir, "history", name1)); err != nil {
				t.Fatal(err)
			}
		},
		"a record that is not a record": func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "history", name1), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "history", name1, "record.json"), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a trust set that no record lists": func(t *testing.T, dir string) {
			s := newSpec(name1, 1, "")
			if err := os.MkdirAll(filepath.Join(dir, s.setName()), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, s.setName(), "root-list.json"), s.rootListText(t), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a FIFO in a trust set": func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "trust", "1-aaaaaaaa"), 0o755); err != nil {
				t.Fatal(err)
			}
			pfFIFO(t, filepath.Join(dir, "trust", "1-aaaaaaaa", "root-list.json"))
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			dir := pfWrite(t, pfFiles())
			build(t, dir)
			want := pfHistoryReasons(t, dir)
			if len(want) == 0 {
				t.Fatal("the check of the history finds nothing wrong with this bundle: the case tests nothing")
			}
			before := tree(t, dir)
			f, err := pfFind(t, dir)
			if f != nil || err == nil {
				t.Fatalf("Find = %+v, %v", f, err)
			}
			var refused *ceremony.RefusedError
			if !errors.As(err, &refused) {
				t.Fatalf("the error is %T (%v), want *RefusedError (exit code 3)", err, err)
			}
			if !slices.Equal(refused.Reasons, want) {
				t.Errorf("reasons = %q, want the codes of the check, %q", refused.Reasons, want)
			}
			if !strings.Contains(err.Error(), "nothing was written") || !pfPrintable(err.Error()) {
				t.Errorf("the text %+q", err.Error())
			}
			sameTree(t, "Find", before, tree(t, dir))
		})
	}
}

func TestARequestNameThatIsNotAPlainNameStopsTheWholeApply(t *testing.T) {
	cases := map[string]string{
		"a space":                "a b",
		"a control character":    "a\x01b",
		"not UTF-8":              "a\xffb",
		"a leftover of a stop":   ".rt-abcdef",
		"the same in upper case": ".RT-abcdef",
		"a backslash":            "a\\b",
		"a trailing dot":         "a.",
		"a Windows device name":  "con",
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			dir := pfWrite(t, pfFiles())
			if err := os.MkdirAll(filepath.Join(dir, "requests", req), 0o755); err != nil {
				t.Skipf("this system refuses the name: %v", err)
			}
			before := tree(t, dir)
			f, err := pfFind(t, dir)
			if f != nil || err == nil {
				t.Fatalf("Find = %+v, %v", f, err)
			}
			if k := pfKind(err); k != "failure" {
				t.Errorf("kind = %s, want a plain failure (exit code 1)", k)
			}
			if !pfPrintable(err.Error()) || !strings.Contains(err.Error(), "requests/") || !strings.Contains(err.Error(), "nothing was written") {
				t.Errorf("the text %+q", err.Error())
			}
			sameTree(t, "Find", before, tree(t, dir))
		})
	}
}

func TestMoreRequestNamesThanTheLimitStopTheApply(t *testing.T) {
	files := pfFiles()
	for i := 0; i <= wanted.MaxFiles; i++ {
		files[fmt.Sprintf("requests/r%04d/request.json", i)] = "{}"
	}
	f, err := pfFind(t, pfWrite(t, files))
	if f != nil || err == nil || !strings.Contains(err.Error(), fmt.Sprint(wanted.MaxFiles)) {
		t.Fatalf("Find = %+v, %v", f, err)
	}
	// Exactly the limit is accepted.
	delete(files, fmt.Sprintf("requests/r%04d/request.json", wanted.MaxFiles))
	f, err = pfFind(t, pfWrite(t, files))
	if err != nil || len(f.LeavesOut) != wanted.MaxFiles {
		t.Fatalf("Find of %d requests = %v", wanted.MaxFiles, err)
	}
}

func TestAFolderThatCannotBeListedIsAFailureAndNeverNothingFound(t *testing.T) {
	t.Run("requests is a file", func(t *testing.T) {
		files := pfFiles()
		files["requests"] = "x"
		f, err := pfFind(t, pfWrite(t, files))
		if f != nil || err == nil || !strings.Contains(err.Error(), "requests/") {
			t.Errorf("Find = %+v, %v", f, err)
		}
	})
	t.Run("requests is a link", func(t *testing.T) {
		dir := pfWrite(t, pfFiles())
		if err := os.MkdirAll(filepath.Join(dir, "elsewhere", "a"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("elsewhere", filepath.Join(dir, "requests")); err != nil {
			t.Fatal(err)
		}
		f, err := pfFind(t, dir)
		if f != nil || err == nil {
			t.Errorf("Find followed a link: %+v, %v", f, err)
		}
	})
	t.Run("roots is a file", func(t *testing.T) {
		files := pfFiles()
		files["roots"] = "x"
		f, err := pfFind(t, pfWrite(t, files))
		if f != nil || err == nil || !strings.Contains(err.Error(), "roots/") {
			t.Errorf("Find = %+v, %v", f, err)
		}
	})
	t.Run("history is a file", func(t *testing.T) {
		files := pfFiles()
		files["history"] = "x"
		f, err := pfFind(t, pfWrite(t, files))
		if f != nil || err == nil {
			t.Errorf("Find = %+v, %v", f, err)
		}
	})
	t.Run("trust is a link", func(t *testing.T) {
		dir := pfWrite(t, pfFiles())
		if err := os.Symlink("/", filepath.Join(dir, "trust")); err != nil {
			t.Fatal(err)
		}
		f, err := pfFind(t, dir)
		if f != nil || err == nil {
			t.Errorf("Find followed a link: %+v, %v", f, err)
		}
	})
}

func TestFindStopsForACancelledContextAndForNothingToRead(t *testing.T) {
	dir := pfWrite(t, pfFiles())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f, err := ceremony.Find(ctx, ceremony.FindInput{FS: pfOpen(t, dir)})
	if f != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("Find with a cancelled context = %+v, %v", f, err)
	}
	var nilCtx context.Context
	if f, err := ceremony.Find(nilCtx, ceremony.FindInput{FS: pfOpen(t, dir)}); f != nil || err == nil {
		t.Errorf("Find with no context = %+v, %v", f, err)
	}
	if f, err := ceremony.Find(context.Background(), ceremony.FindInput{}); f != nil || err == nil {
		t.Errorf("Find with no folder = %+v, %v", f, err)
	}
}

func TestFindInMemoryHandlesWhatADiskCannotHold(t *testing.T) {
	t.Run("a bundle in memory", func(t *testing.T) {
		f, err := ceremony.Find(context.Background(), ceremony.FindInput{FS: pfFS{pfMem(pfFiles())}})
		if err != nil || f.Nothing() {
			t.Fatalf("Find = %+v, %v", f, err)
		}
	})
	t.Run("a wanted file longer than the reader reads", func(t *testing.T) {
		m := pfMem(pfFiles())
		m.kids["want"].kids["roots"].kids["x509.yaml"].long = true
		f, err := ceremony.Find(context.Background(), ceremony.FindInput{FS: pfFS{m}})
		if f != nil || err == nil || !strings.Contains(err.Error(), "want/roots/x509.yaml") {
			t.Errorf("Find = %+v, %v", f, err)
		}
	})
	t.Run("a requests folder of more names than any folder holds", func(t *testing.T) {
		m := pfMem(pfFiles())
		reqs := pfNewDir()
		for i := range fsMaxDirEntries + 1 {
			reqs.kids[fmt.Sprintf("r%d", i)] = pfNewDir()
		}
		m.kids["requests"] = reqs
		f, err := ceremony.Find(context.Background(), ceremony.FindInput{FS: pfFS{m}})
		if f != nil || err == nil {
			t.Errorf("Find = %+v, %v", f, err)
		}
	})
	t.Run("a root folder of 70,000 names", func(t *testing.T) {
		m := pfMem(pfFiles())
		for i := range 70000 {
			m.put(fmt.Sprintf("want/roots/n%05d.yaml", i), &pfNode{kind: "file", data: []byte(pfX509Test)})
		}
		f, err := ceremony.Find(context.Background(), ceremony.FindInput{FS: pfFS{m}})
		if f != nil || err == nil || !strings.Contains(err.Error(), "want/roots") {
			t.Errorf("Find = %+v, %v", f, err)
		}
	})
	t.Run("a name of 255 bytes under requests", func(t *testing.T) {
		m := pfMem(pfFiles())
		m.put("requests/"+strings.Repeat("a", 255)+"/x", &pfNode{kind: "file"})
		f, err := ceremony.Find(context.Background(), ceremony.FindInput{FS: pfFS{m}})
		if err != nil || len(f.LeavesOut) != 1 {
			t.Errorf("Find = %+v, %v", f, err)
		}
		m.put("requests/"+strings.Repeat("b", 256)+"/x", &pfNode{kind: "file"})
		f, err = ceremony.Find(context.Background(), ceremony.FindInput{FS: pfFS{m}})
		if f != nil || err == nil {
			t.Errorf("a name of 256 bytes was accepted: %+v, %v", f, err)
		}
	})
}

// fsMaxDirEntries is fsx.MaxDirEntries, spelled out so that the test does not stand on the constant
// it checks.
const fsMaxDirEntries = 65536
