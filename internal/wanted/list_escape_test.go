//go:build linux || darwin

package wanted_test

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/wanted"
)

// A name that comes from a folder is shown in an error with the exact escape of package jsonset (record
// 0006, rule 46): a space as \x20, a backslash doubled, a byte that is not UTF-8 as its own \xNN, a valid
// character beyond printable ASCII as \uXXXX. So two different names never give one text. The names of this
// file start with le.

// leU is the escape \uXXXX of a character; the source of the test holds no such escape of its own.
func leU(hex string) string { return `\` + "u" + hex }

// leName is a hostile name (the file name of the entry, with ".yaml") and the way the error must show it.
type leName struct {
	name  string
	shown string
}

func leNames() []leName {
	return []leName{
		{"a b.yaml", `a\x20b.yaml`},
		{"a  b.yaml", `a\x20\x20b.yaml`},
		{" a.yaml", `\x20a.yaml`},
		{"a.yaml ", `a.yaml\x20`},
		{`a\b.yaml`, `a\\b.yaml`},
		{`a\\b.yaml`, `a\\\\b.yaml`},
		{`a\x20b.yaml`, `a\\x20b.yaml`},
		{`a\xffb.yaml`, `a\\xffb.yaml`},
		{`a\` + "u" + `00e9b.yaml`, `a\\u00e9b.yaml`},
		{"a\xffb.yaml", `a\xffb.yaml`},
		{"a\xfeb.yaml", `a\xfeb.yaml`},
		{"a\x80b.yaml", `a\x80b.yaml`},
		{"a\xc3.yaml", `a\xc3.yaml`},
		{"a\xc3b.yaml", `a\xc3b.yaml`},
		{"a\xef\xbf\xbdb.yaml", "a" + leU("fffd") + "b.yaml"},
		{"caf\xc3\xa9.yaml", "caf" + leU("00e9") + ".yaml"},
		{"a\xe2\x80\xaeb.yaml", "a" + leU("202e") + "b.yaml"},
		{"a\xf0\x9f\x98\x80b.yaml", "a" + leU("d83d") + leU("de00") + "b.yaml"},
		{"a\x01b.yaml", "a" + leU("0001") + "b.yaml"},
		{"a\nb.yaml", "a" + leU("000a") + "b.yaml"},
		{"a\tb.yaml", "a" + leU("0009") + "b.yaml"},
		{"a\x7fb.yaml", "a" + leU("007f") + "b.yaml"},
		{"a\"b.yaml", `a"b.yaml`},
		{"A.yaml", `A.yaml`},
		{"a:b.yaml", `a:b.yaml`},
	}
}

// leListers are the calls that list one folder: the five of the package, with the folder each one lists.
func leListers() []tlLister { return tlListers() }

func TestAnErrorShowsAFolderNameWithTheExactEscape(t *testing.T) {
	for _, l := range leListers() {
		for _, n := range leNames() {
			t.Run(l.name+" "+strings.ReplaceAll(n.shown, "/", "_"), func(t *testing.T) {
				_, fsys := bundleDir(t, map[string]string{l.dir + "/" + n.name: lstRootText})
				_, err := l.run(fsys, lstSettings(t))
				if err == nil {
					t.Fatalf("%s accepted the name %+q", l.name, n.name)
				}
				var we *wanted.Error
				if !errors.As(err, &we) {
					t.Fatalf("the error is %T, want *wanted.Error", err)
				}
				want := l.dir + "/" + n.shown + ":"
				if !strings.HasPrefix(err.Error(), want) {
					t.Errorf("the error is %q, want it to start with %q", err.Error(), want)
				}
				if !printable(err.Error()) {
					t.Errorf("the error is not printable ASCII: %+q", err.Error())
				}
			})
		}
	}
}

func TestTwoDifferentNamesInAFolderNeverGiveTheSameErrorTextInAnyOfTheThreeFolders(t *testing.T) {
	for _, l := range leListers() {
		t.Run(l.name, func(t *testing.T) {
			seen := map[string]string{}
			for _, n := range leNames() {
				_, fsys := bundleDir(t, map[string]string{l.dir + "/" + n.name: lstRootText})
				_, err := l.run(fsys, lstSettings(t))
				if err == nil {
					t.Fatalf("%s accepted the name %+q", l.name, n.name)
				}
				if other, ok := seen[err.Error()]; ok {
					t.Errorf("the names %+q and %+q give the same text %q", other, n.name, err.Error())
				}
				seen[err.Error()] = n.name
			}
			if len(seen) != len(leNames()) {
				t.Errorf("%d texts for %d names", len(seen), len(leNames()))
			}
		})
	}
}

// A name that a caller gives to a reader of one file (a Load or a Parse function) is shown in the same way.
func TestTheReadersOfOneFileShowAHostileNameFromACallerWithTheExactEscape(t *testing.T) {
	calls := map[string]struct {
		dir string
		run func(name string) error
	}{
		"ParseRoot": {wanted.RootsDir, func(name string) error {
			_, err := wanted.ParseRoot(name, []byte(goodRoot))
			return err
		}},
		"ParseCard": {wanted.CardsDir, func(name string) error {
			_, err := wanted.ParseCard(name, []byte(cardServerOne))
			return err
		}},
		"ParseDelegation": {wanted.DelegationsDir, func(name string) error {
			_, err := wanted.ParseDelegation(name, []byte(lstDelegation), lstSettings(t))
			return err
		}},
		"LoadRoot": {wanted.RootsDir, func(name string) error {
			_, fsys := bundleDir(t, nil)
			_, err := wanted.LoadRoot(fsys, name)
			return err
		}},
		"LoadCard": {wanted.CardsDir, func(name string) error {
			_, fsys := bundleDir(t, nil)
			_, err := wanted.LoadCard(fsys, name)
			return err
		}},
		"LoadDelegation": {wanted.DelegationsDir, func(name string) error {
			_, fsys := bundleDir(t, nil)
			_, err := wanted.LoadDelegation(fsys, name, lstSettings(t))
			return err
		}},
	}
	for call, c := range calls {
		t.Run(call, func(t *testing.T) {
			seen := map[string]string{}
			for _, n := range leNames() {
				stem := strings.TrimSuffix(n.name, ".yaml")
				shown := strings.TrimSuffix(n.shown, ".yaml")
				err := c.run(stem)
				if err == nil {
					t.Fatalf("%s accepted the name %+q", call, stem)
				}
				if want := c.dir + "/" + shown + ".yaml:"; !strings.HasPrefix(err.Error(), want) {
					t.Errorf("the error is %q, want it to start with %q", err.Error(), want)
				}
				if other, ok := seen[err.Error()]; ok {
					t.Errorf("the names %+q and %+q give the same text %q", other, stem, err.Error())
				}
				seen[err.Error()] = stem
			}
		})
	}
}

// A name that passes the check is shown as it is: the exact escape changes no text of a good name.
func TestTheTextOfAnErrorAtAGoodNameIsNotChanged(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{"want/cards/good.yaml": "version: 2\n"})
	_, err := wanted.LoadCard(fsys, "good")
	if err == nil || !strings.HasPrefix(err.Error(), "want/cards/good.yaml:") {
		t.Errorf("error = %v", err)
	}
	var we *wanted.Error
	if !errors.As(err, &we) || we.Path != "want/cards/good.yaml" {
		t.Errorf("error = %#v", err)
	}
}

// The exact escape is applied to the path only: the words of an error stay as before. An entry that is a
// folder, a link or a FIFO is named by the same shown name.
func TestAnEntryThatIsNotAFileIsNamedWithTheExactEscape(t *testing.T) {
	for _, l := range leListers() {
		t.Run(l.name, func(t *testing.T) {
			_, fsys := bundleDir(t, map[string]string{l.dir + "/a b/x.yaml": lstRootText, l.dir + "/good.yaml": lstRootText})
			_, err := l.run(fsys, lstSettings(t))
			if err == nil {
				t.Fatal("a folder in place of a file was accepted")
			}
			if want := l.dir + `/a\x20b:`; !strings.HasPrefix(err.Error(), want) {
				t.Errorf("the error is %q, want it to start with %q", err.Error(), want)
			}
		})
	}
}

// The names that every lister shows are the same set of texts in the same order: a sanity check that the
// names above are all distinct as names.
func TestTheHostileNamesAreDistinct(t *testing.T) {
	var names []string
	for _, n := range leNames() {
		names = append(names, n.name)
	}
	slices.Sort(names)
	if len(slices.Compact(names)) != len(names) {
		t.Error("two of the names of this file are equal")
	}
}

// FuzzAFolderNameIsShownExactlyAndNeverAsAnotherName: an entry of any name (no slash, no NUL) that the
// lister refuses is shown as the exact escape of its name, and two different names never give one text. The
// entries are put in the listing, so a name that a file system cannot hold is tried too.
func FuzzAFolderNameIsShownExactlyAndNeverAsAnotherName(f *testing.F) {
	for _, n := range leNames() {
		f.Add(n.name, "b.yaml")
	}
	f.Add("a\xffb.yaml", "a"+leU("fffd")+"b.yaml")
	f.Add("a b.yaml", `a\x20b.yaml`)
	f.Add("a\xc3\xa9.yaml", `a\xc3\xa9.yaml`)
	f.Fuzz(func(t *testing.T, a, b string) {
		for _, name := range []string{a, b} {
			if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || len(name) > 300 {
				return
			}
		}
		for _, folder := range []string{wanted.RootsDir, wanted.CardsDir} {
			list := func(name string) error {
				fsys := tlInjected(t, folder, func() []fs.DirEntry { return []fs.DirEntry{tlEntry{name: name}} })
				var err error
				if folder == wanted.RootsDir {
					_, err = wanted.ListRootNames(fsys)
				} else {
					_, err = wanted.ListCardNames(fsys)
				}
				return err
			}
			ea, eb := list(a), list(b)
			if ea != nil {
				if !printable(ea.Error()) || !strings.HasPrefix(ea.Error(), folder+"/"+jsonset.EscapeExact(a)+":") {
					t.Fatalf("%s: the name %+q is shown as %q", folder, a, ea.Error())
				}
			}
			if ea != nil && eb != nil && a != b && ea.Error() == eb.Error() {
				t.Fatalf("%s: the names %+q and %+q give the text %q", folder, a, b, ea.Error())
			}
		}
	})
}
