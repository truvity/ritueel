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
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// Find asks the check of the card files once, after the settings, the root files and the delegations, and
// before the history is read: a card file that fails is a wanted file that fails its check (record 0005,
// rule 19), with the exit code 1, and nothing is written. The card files are not wanted files that a plan
// uses, so they are not in the plan. The names of this file start with cf.

const (
	cfRootA = `version: 1
serial: "10000001"
kind: root
applications: [piv, fido2]
other_rows: [3]
`
	cfRootB = `version: 1
serial: "10000002"
kind: root
applications: [piv, fido2]
`
	cfDayOne = `version: 1
serial: "10000003"
kind: day-to-day
applications: [openpgp, fido2]
`
	cfBad = "version: 2\nserial: \"10000009\"\nkind: server\napplications: [piv]\n"
)

// cfCards is the three card files of a good set.
func cfCards() map[string]string {
	return map[string]string{
		"want/cards/root-a.yaml":  cfRootA,
		"want/cards/root-b.yaml":  cfRootB,
		"want/cards/day-one.yaml": cfDayOne,
	}
}

// cfWith is the files of a first-apply bundle with more files.
func cfWith(more ...map[string]string) map[string]string {
	m := pfFiles()
	for _, extra := range more {
		for k, v := range extra {
			m[k] = v
		}
	}
	return m
}

// cfProbe records the folders opened and the files read through a probing folder.
type cfProbe struct {
	opened []string
	read   []string
	onRead func(path string)
}

func (p *cfProbe) opens(prefix string) bool {
	for _, o := range p.opened {
		if o == prefix || strings.HasPrefix(o, prefix+"/") {
			return true
		}
	}
	return false
}

func (p *cfProbe) reads(prefix string) int {
	n := 0
	for _, r := range p.read {
		if strings.HasPrefix(r, prefix+"/") {
			n++
		}
	}
	return n
}

type cfFS struct {
	fsx.FS
	dir string
	p   *cfProbe
}

func (f cfFS) OpenDir(name string) (fsx.FS, error) {
	f.p.opened = append(f.p.opened, f.dir+name)
	sub, err := f.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return cfFS{FS: sub, dir: f.dir + name + "/", p: f.p}, nil
}

func (f cfFS) ReadFile(name string) ([]byte, error) {
	f.p.read = append(f.p.read, f.dir+name)
	if f.p.onRead != nil {
		f.p.onRead(f.dir + name)
	}
	return f.FS.ReadFile(name)
}

// cfFind runs Find on a probing folder over inner.
func cfFind(ctx context.Context, inner fsx.FS) (*ceremony.Found, *cfProbe, error) {
	p := &cfProbe{}
	f, err := ceremony.Find(ctx, ceremony.FindInput{FS: cfFS{FS: inner, p: p}})
	return f, p, err
}

// cfRefused checks that err is a plain failure (exit code 1) of a wanted file at path, and that it says
// nothing was written.
func cfRefused(t testing.TB, f *ceremony.Found, err error, path string) {
	t.Helper()
	if f != nil || err == nil {
		t.Fatalf("Find = %+v, %v; want a refusal and no Found", f, err)
	}
	if k := pfKind(err); k != "failure" {
		t.Errorf("kind = %s (%v), want a plain failure (exit code 1)", k, err)
	}
	if errors.Is(err, ceremony.ErrNotBuilt) || errors.Is(err, ceremony.ErrNotFirst) {
		t.Errorf("the error is the refusal of another place of the order: %v", err)
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "a wanted file is refused, and nothing was written") {
		t.Errorf("the text %q does not name %q and say that a wanted file is refused and nothing was written", err, path)
	}
	if !pfPrintable(err.Error()) {
		t.Errorf("the text is not printable ASCII: %+q", err.Error())
	}
	var we *wanted.Error
	if !errors.As(err, &we) {
		t.Errorf("the error is %T, want a *wanted.Error inside", err)
	}
}

func TestFindWithAGoodSetOfCardFilesGivesWhatItGaveBeforeAndTheCardsAreNotInThePlan(t *testing.T) {
	plain := pfMustFind(t, pfFiles())
	got := pfMustFind(t, cfWith(cfCards()))
	if !reflect.DeepEqual(got.Applies, plain.Applies) || !reflect.DeepEqual(got.LeavesOut, plain.LeavesOut) {
		t.Errorf("changes %+v / %+v, want %+v / %+v", got.Applies, got.LeavesOut, plain.Applies, plain.LeavesOut)
	}
	if len(got.Wanted) != 2 || got.Wanted[0].Path != "ritueel.yaml" || got.Wanted[1].Path != "want/roots/x509.yaml" {
		t.Fatalf("Wanted = %+v, want the settings file and the root file only", got.Wanted)
	}
	for i, w := range got.Wanted {
		if w.SHA256 != plain.Wanted[i].SHA256 || string(w.Data) != string(plain.Wanted[i].Data) {
			t.Errorf("Wanted[%d] differs from the one without card files", i)
		}
	}
	if !reflect.DeepEqual(got.State, plain.State) || got.Root.Name != plain.Root.Name || got.Settings.Name != plain.Settings.Name {
		t.Errorf("the state, the root or the settings differ")
	}
	// The plan is the golden plan, byte for byte.
	p := pfPlan(t, cfWith(cfCards()))
	if string(p.JSON) != pfGolden || p.SHA256 != pfGoldenDigest {
		t.Errorf("the plan of a bundle with card files is not the golden plan:\n%s", p.JSON)
	}
	if strings.Contains(string(p.JSON), "cards") {
		t.Errorf("the plan names a card file: %s", p.JSON)
	}
}

func TestFindWithAGoodSetWritesNothingAndReadsEachCardFileOnce(t *testing.T) {
	dir := pfWrite(t, cfWith(cfCards()))
	before := tree(t, dir)
	f, p, err := cfFind(t.Context(), pfOpen(t, dir))
	if err != nil || f.Nothing() {
		t.Fatalf("Find = %+v, %v", f, err)
	}
	sameTree(t, "Find", before, tree(t, dir))
	for path := range cfCards() {
		if n := strings.Count("\n"+strings.Join(p.read, "\n")+"\n", "\n"+path+"\n"); n != 1 {
			t.Errorf("%s was read %d times, want once", path, n)
		}
	}
}

func TestACardFileThatFailsItsCheckStopsFindAndNamesThePath(t *testing.T) {
	cases := map[string]struct {
		extra map[string]string
		path  string
	}{
		"a version that is not 1":            {map[string]string{"want/cards/bad.yaml": cfBad}, "want/cards/bad.yaml"},
		"an empty file":                      {map[string]string{"want/cards/bad.yaml": ""}, "want/cards/bad.yaml"},
		"a holder key":                       {map[string]string{"want/cards/bad.yaml": cfRootB + "holder: Example Person\n"}, "want/cards/bad.yaml"},
		"a second card with the same serial": {map[string]string{"want/cards/twin.yaml": cfRootB}, "want/cards/twin.yaml"},
		"the same number written with zeros": {map[string]string{"want/cards/twin.yaml": strings.Replace(cfRootB, "10000002", "0010000002", 1)}, "want/cards/twin.yaml"},
		"a name that is not lower case":      {map[string]string{"want/cards/Bad.yaml": cfRootB}, "want/cards/Bad.yaml"},
		"a file that is not NAME.yaml":       {map[string]string{"want/cards/bad.yml": cfRootB}, "want/cards/bad.yml"},
		"a file named for an editor backup":  {map[string]string{"want/cards/root-a.yaml~": cfRootA}, "want/cards/root-a.yaml~"},
		"a folder in the card folder":        {map[string]string{"want/cards/sub/a.yaml": cfRootA}, "want/cards/sub"},
		"a card folder that is a file":       {map[string]string{"want/cards": "x"}, "want/cards"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			files := cfWith(cfCards(), c.extra)
			if name == "a card folder that is a file" {
				files = cfWith(c.extra)
			}
			dir := pfWrite(t, files)
			before := tree(t, dir)
			f, err := pfFind(t, dir)
			cfRefused(t, f, err, c.path)
			sameTree(t, "Find", before, tree(t, dir))
			// The negative control: without the one file the same bundle is found.
			if name != "a card folder that is a file" {
				good := cfWith(cfCards())
				if _, err := pfFind(t, pfWrite(t, good)); err != nil {
					t.Errorf("the bundle without the bad file is refused: %v", err)
				}
			}
		})
	}
}

func TestACardFileThatFailsIsRefusedBeforeTheHistoryAndTheRequestsAreLooked(t *testing.T) {
	dir := pfWrite(t, cfWith(cfCards(), map[string]string{"want/cards/bad.yaml": cfBad, "requests/a/request.json": "x"}))
	f, p, err := cfFind(t.Context(), pfOpen(t, dir))
	cfRefused(t, f, err, "want/cards/bad.yaml")
	for _, folder := range []string{"history", "requests", "trust", "roots"} {
		if p.opens(folder) {
			t.Errorf("the folder %s was opened before the card files were refused: %q", folder, p.opened)
		}
	}
	if p.reads("history") != 0 || p.reads("requests") != 0 {
		t.Errorf("files were read after the refusal: %q", p.read)
	}
	// The control: the same bundle without the bad file does open the history, so the probe sees it.
	dir = pfWrite(t, cfWith(cfCards(), map[string]string{"requests/a/request.json": "x"}))
	_, p, err = cfFind(t.Context(), pfOpen(t, dir))
	if err != nil || !p.opens("history") {
		t.Errorf("Find = %v, history opened: %v", err, p.opens("history"))
	}
}

// A card file that fails is the first refusal of the order, after the three that come before it and before
// every refusal that comes after.
func TestACardFileThatFailsComesBeforeTheRefusalsOfTheHistoryAndTheState(t *testing.T) {
	bad := map[string]string{"want/cards/bad.yaml": cfBad}
	t.Run("an open attempt", func(t *testing.T) {
		b := pfRecorded(t)
		newFlow(t, b, newSpec(name1, 1, "")).must("start")
		if err := os.MkdirAll(b.path("want", "cards"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b.path("want", "cards", "bad.yaml"), []byte(cfBad), 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := pfFind(t, b.dir)
		cfRefused(t, f, err, "want/cards/bad.yaml")
		var refused *ceremony.RefusedError
		if errors.As(err, &refused) {
			t.Errorf("the refusal of an open attempt came first: %v", err)
		}
		// The control: without the bad file the attempt is the refusal.
		if err := os.Remove(b.path("want", "cards", "bad.yaml")); err != nil {
			t.Fatal(err)
		}
		if _, err := pfFind(t, b.dir); !errors.As(err, &refused) {
			t.Errorf("the control did not refuse for the open attempt: %v", err)
		}
	})
	t.Run("a bundle that is not in the first state", func(t *testing.T) {
		b := pfRecorded(t)
		newFlow(t, b, newSpec(name1, 1, "")).must("")
		if err := os.MkdirAll(b.path("want", "cards"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b.path("want", "cards", "bad.yaml"), []byte(cfBad), 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := pfFind(t, b.dir)
		cfRefused(t, f, err, "want/cards/bad.yaml")
		if err := os.Remove(b.path("want", "cards", "bad.yaml")); err != nil {
			t.Fatal(err)
		}
		if _, err := pfFind(t, b.dir); pfKind(err) != "not-first" {
			t.Errorf("the control = %v (%s), want not-first", err, pfKind(err))
		}
	})
	t.Run("a history that fails its own check", func(t *testing.T) {
		dir := pfWrite(t, cfWith(bad))
		if err := os.MkdirAll(filepath.Join(dir, "history"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/", filepath.Join(dir, "history", name1)); err != nil {
			t.Fatal(err)
		}
		f, err := pfFind(t, dir)
		cfRefused(t, f, err, "want/cards/bad.yaml")
		var refused *ceremony.RefusedError
		if errors.As(err, &refused) {
			t.Errorf("the refusal of the history came first: %v", err)
		}
	})
	t.Run("a root that is not built", func(t *testing.T) {
		files := map[string]string{"ritueel.yaml": pfSettings, "want/roots/openpgp.yaml": pfOpenPGPTest}
		f, err := pfFind(t, pfWrite(t, cfWith(files, bad)))
		cfRefused(t, f, err, "want/cards/bad.yaml")
		files["want/cards/ok.yaml"] = cfRootB
		if _, err := pfFind(t, pfWrite(t, files)); pfKind(err) != "not-built" {
			t.Errorf("the control = %v (%s), want not-built", err, pfKind(err))
		}
	})
	t.Run("more root files than are read", func(t *testing.T) {
		dir := pfWrite(t, cfWith(bad))
		for i := 1; i < 12; i++ {
			if err := os.WriteFile(filepath.Join(dir, "want", "roots", fmt.Sprintf("r%04d.yaml", i)), []byte(pfX509Test), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		f, err := pfFind(t, dir)
		cfRefused(t, f, err, "want/cards/bad.yaml")
	})
	t.Run("a request name that is not plain", func(t *testing.T) {
		f, err := pfFind(t, pfWrite(t, cfWith(bad, map[string]string{"requests/a b/x": "x"})))
		cfRefused(t, f, err, "want/cards/bad.yaml")
	})
	t.Run("a personal bundle", func(t *testing.T) {
		files := map[string]string{"ritueel.yaml": pfPersonal, "want/roots/x509.yaml": pfX509Test}
		f, err := pfFind(t, pfWrite(t, cfWith(files, bad)))
		cfRefused(t, f, err, "want/cards/bad.yaml")
	})
}

// The three refusals that come before the card files keep their place.
func TestAFileThatFailsBeforeTheCardFilesIsRefusedFirst(t *testing.T) {
	bad := map[string]string{"want/cards/bad.yaml": cfBad}
	cases := map[string]struct {
		extra map[string]string
		first string
	}{
		"the settings file":      {map[string]string{"ritueel.yaml": "version: 2\n"}, "ritueel.yaml"},
		"a root file":            {map[string]string{"want/roots/x509.yaml": "version: 1\nkind: nonsense\n"}, "want/roots/x509.yaml"},
		"a name of a root file":  {map[string]string{"want/roots/X509.yaml": pfX509Test}, "want/roots/X509.yaml"},
		"a delegation":           {map[string]string{"want/delegations/a.yaml": "type: nonsense\n"}, "want/delegations/a.yaml"},
		"a delegation of a root": {map[string]string{"want/delegations/a.yaml": "version: 1\ntype: x509-intermediate\nroot: nothing\npermitted_dns_names: [example.org]\n"}, "want/roots/nothing.yaml"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, err := pfFind(t, pfWrite(t, cfWith(bad, c.extra)))
			if f != nil || err == nil || pfKind(err) != "failure" {
				t.Fatalf("Find = %+v, %v", f, err)
			}
			if !strings.Contains(err.Error(), c.first) || strings.Contains(err.Error(), "want/cards/bad.yaml") {
				t.Errorf("the text %q must name %s and not the card file", err, c.first)
			}
		})
	}
}

func TestMoreCardFilesThanTheLimitAreRefusedWithoutReadingOne(t *testing.T) {
	files := cfWith()
	for i := range wanted.MaxCards + 1 {
		files[fmt.Sprintf("want/cards/c%04d.yaml", i)] = fmt.Sprintf("version: 1\nserial: \"%d\"\nkind: server\napplications: [piv]\n", i+1)
	}
	f, p, err := cfFind(t.Context(), pfOpen(t, pfWrite(t, files)))
	cfRefused(t, f, err, "want/cards")
	if !strings.Contains(err.Error(), "64") {
		t.Errorf("the text %q does not name the limit", err)
	}
	if n := p.reads("want/cards"); n != 0 {
		t.Errorf("%d card files were read", n)
	}
	// Exactly the limit is accepted and read once each.
	delete(files, fmt.Sprintf("want/cards/c%04d.yaml", wanted.MaxCards))
	f, p, err = cfFind(t.Context(), pfOpen(t, pfWrite(t, files)))
	if err != nil || f.Nothing() || p.reads("want/cards") != wanted.MaxCards {
		t.Errorf("Find = %+v, %v with %d reads", f, err, p.reads("want/cards"))
	}
}

func TestACanceledContextIsReturnedAsItIsAndIsNotARefusedWantedFile(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			dir := pfWrite(t, cfWith(cfCards()))
			ctx := &cfCtx{Context: t.Context()}
			p := &cfProbe{onRead: func(path string) {
				if strings.HasPrefix(path, "want/cards/") {
					ctx.err = cause // the context ends while the first card file is read
				}
			}}
			f, err := ceremony.Find(ctx, ceremony.FindInput{FS: cfFS{FS: pfOpen(t, dir), p: p}})
			if f != nil || !errors.Is(err, cause) {
				t.Fatalf("Find = %+v, %v; want %v", f, err, cause)
			}
			if strings.Contains(err.Error(), "refused") || pfKind(err) != "failure" {
				t.Errorf("the error of the context was made a refusal of a wanted file: %v", err)
			}
			var we *wanted.Error
			if errors.As(err, &we) {
				t.Errorf("the error of the context holds a wanted file fault: %v", err)
			}
			if n := p.reads("want/cards"); n != 1 {
				t.Errorf("%d card files were read after the context ended, want 1", n)
			}
			if p.opens("history") {
				t.Errorf("the history was opened after the context ended")
			}
		})
	}
}

// cfCtx is a context whose error a test sets.
type cfCtx struct {
	context.Context
	err error
}

func (c *cfCtx) Err() error {
	if c.err != nil {
		return c.err
	}
	return c.Context.Err()
}

func TestHostileCardFilesInMemoryAreRefusedAndNeverCrash(t *testing.T) {
	huge := strings.Repeat("a", 300<<10)
	cases := map[string]func(m *pfNode){
		"a file that is a link": func(m *pfNode) {
			m.put("want/cards/odd.yaml", &pfNode{kind: "link"})
		},
		"a FIFO": func(m *pfNode) {
			m.put("want/cards/odd.yaml", &pfNode{kind: "fifo"})
		},
		"a folder": func(m *pfNode) {
			m.put("want/cards/odd.yaml", pfNewDir())
		},
		"a file longer than a read": func(m *pfNode) {
			m.put("want/cards/odd.yaml", &pfNode{kind: "file", long: true})
		},
		"a file of 300 KiB": func(m *pfNode) {
			m.put("want/cards/odd.yaml", &pfNode{kind: "file", data: []byte(huge)})
		},
		"a file that cannot be read": func(m *pfNode) {
			m.put("want/cards/odd.yaml", &pfNode{kind: "file", readErr: errors.New("the disk failed")})
		},
		"a file that is gone for the system": func(m *pfNode) {
			m.put("want/cards/odd.yaml", &pfNode{kind: "file", readErr: fs.ErrNotExist})
		},
		"a name with a control code": func(m *pfNode) {
			m.put("want/cards/a\x01b.yaml", &pfNode{kind: "file", data: []byte(cfRootB)})
		},
		"a name that is not UTF-8": func(m *pfNode) {
			m.put("want/cards/a\xffb.yaml", &pfNode{kind: "file", data: []byte(cfRootB)})
		},
		"a name with a bidirectional control": func(m *pfNode) {
			m.put("want/cards/a\u202eb.yaml", &pfNode{kind: "file", data: []byte(cfRootB)})
		},
		"the card folder cannot be listed": func(m *pfNode) {
			m.kids["want"].kids["cards"] = &pfNode{kind: "dir", kids: map[string]*pfNode{}, readErr: errors.New("the disk failed")}
		},
		"a card folder of more names than any folder holds": func(m *pfNode) {
			d := pfNewDir()
			for i := range fsMaxDirEntries + 1 {
				d.kids[fmt.Sprintf("c%d.yaml", i)] = &pfNode{kind: "file"}
			}
			m.kids["want"].kids["cards"] = d
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := pfMem(cfWith(cfCards()))
			mutate(m)
			f, err := ceremony.Find(t.Context(), ceremony.FindInput{FS: pfFS{m}})
			if f != nil || err == nil {
				t.Fatalf("Find = %+v, %v; want a refusal", f, err)
			}
			if pfKind(err) != "failure" || !pfPrintable(err.Error()) || !strings.Contains(err.Error(), "want/cards") ||
				!strings.Contains(err.Error(), "nothing was written") {
				t.Errorf("error = %+q (%s)", err.Error(), pfKind(err))
			}
		})
	}
}

func TestACardFileOfTheLargestSizeIsAcceptedAndOneByteMoreIsRefused(t *testing.T) {
	pad := func(n int) string {
		text := cfRootB
		for len(text)+60 < n {
			text += "# " + strings.Repeat("x", 56) + "\n"
		}
		return text + "#" + strings.Repeat("y", n-len(text)-2) + "\n"
	}
	ok := pad(wanted.MaxBytes)
	f, err := ceremony.Find(t.Context(), ceremony.FindInput{FS: pfFS{pfMem(cfWith(map[string]string{"want/cards/big.yaml": ok}))}})
	if err != nil || f.Nothing() {
		t.Fatalf("Find of a card file of MaxBytes = %+v, %v", f, err)
	}
	f, err = ceremony.Find(t.Context(), ceremony.FindInput{FS: pfFS{pfMem(cfWith(map[string]string{"want/cards/big.yaml": pad(wanted.MaxBytes + 1)}))}})
	cfRefused(t, f, err, "want/cards/big.yaml")
}

func TestFindGivesTheSameRefusalTwiceAndWritesNothingForABadCardFile(t *testing.T) {
	dir := pfWrite(t, cfWith(cfCards(), map[string]string{"want/cards/bad.yaml": cfBad}))
	before := tree(t, dir)
	var texts []string
	for range 2 {
		_, err := pfFind(t, dir)
		if err == nil {
			t.Fatal("Find accepted a bad card file")
		}
		texts = append(texts, err.Error())
	}
	if texts[0] != texts[1] {
		t.Errorf("two runs differ:\n%s\n%s", texts[0], texts[1])
	}
	sameTree(t, "Find", before, tree(t, dir))
}
