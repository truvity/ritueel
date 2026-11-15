package cards_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/cards"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// A check that cannot run is not a pass: Inspect returns an error and no report, and Check
// returns that error as it is.

// mustFail runs Inspect and Check on a bundle and checks that both fail with a printable error and that
// Inspect returns no report. It returns the error of Inspect.
func mustFail(t testing.TB, mk func() fsx.FS) error {
	t.Helper()
	rep, err := cards.Inspect(t.Context(), mk())
	if err == nil || rep != nil {
		t.Fatalf("Inspect = %+v, %v; want an error and no report", rep, err)
	}
	if !printable(err.Error()) {
		t.Errorf("the error is not printable ASCII: %+q", err.Error())
	}
	if cerr := cards.Check(t.Context(), mk()); cerr == nil {
		t.Errorf("Check accepted what Inspect could not run on")
	}
	return err
}

func TestAFolderThatCannotBeListedAsAFolderIsAnError(t *testing.T) {
	cases := map[string]*node{
		"want/cards is a file": func() *node { n := newDir(); n.put("want/cards", &node{kind: "file", data: []byte("x")}); return n }(),
		"want/cards is a link": func() *node { n := newDir(); n.put("want/cards", &node{kind: "link"}); return n }(),
		"want is a file":       func() *node { n := newDir(); n.put("want", &node{kind: "file"}); return n }(),
		"want is a link":       func() *node { n := newDir(); n.put("want", &node{kind: "link"}); return n }(),
		"want/cards cannot be opened": func() *node {
			n := memBundle(goodSet())
			n.kids["want"].kids["cards"].err = fs.ErrPermission
			return n
		}(),
		"want/cards cannot be listed": func() *node {
			n := memBundle(goodSet())
			// The folder opens and its listing fails.
			n.kids["want"].kids["cards"] = &node{kind: "dir", err: errors.New("the disk failed"), kids: n.kids["want"].kids["cards"].kids}
			return n
		}(),
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			p := &probe{}
			err := mustFail(t, func() fsx.FS { return n.open(p) })
			if errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a fault of the folder was told as a missing folder: %v", err)
			}
			if p.readsUnder("want/cards") != 0 {
				t.Errorf("files were read: %q", p.read)
			}
		})
	}
}

func TestAnEntryThatIsNotAFileIsAnErrorBeforeAnyFileIsRead(t *testing.T) {
	for _, kind := range []string{"dir", "link", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			n := memBundle(goodSet())
			n.put("want/cards/aa-odd.yaml", &node{kind: kind, kids: map[string]*node{}})
			p := &probe{}
			err := mustFail(t, func() fsx.FS { return n.open(p) })
			if !strings.Contains(err.Error(), "want/cards/aa-odd.yaml") {
				t.Errorf("the error %q does not name the entry", err)
			}
			if len(p.read) != 0 {
				t.Errorf("files were read before the folder was judged: %q", p.read)
			}
		})
	}
	// A name that is not NAME.yaml is an error too, whatever it holds.
	for _, bad := range []string{"a.txt", "a.yml", "A.yaml", "a_b.yaml", ".yaml", "a.yaml.bak", "a.yaml~", "-a.yaml"} {
		t.Run("the name "+bad, func(t *testing.T) {
			n := memBundle(with(goodSet(), map[string]string{"want/cards/" + bad: cardRootB}))
			err := mustFail(t, func() fsx.FS { return n.open(nil) })
			if !strings.Contains(err.Error(), "want/cards/"+bad) {
				t.Errorf("the error %q does not name %q", err, bad)
			}
		})
	}
}

func TestMoreCardFilesThanTheLimitAreAnErrorAndNoFileIsRead(t *testing.T) {
	over := numbered(wanted.MaxCards + 1)
	p := &probe{}
	rep, ierr := cards.Inspect(t.Context(), memBundle(over).open(p))
	if rep != nil || ierr == nil {
		t.Fatalf("Inspect = %+v, %v", rep, ierr)
	}
	err := mustFail(t, func() fsx.FS { return memBundle(over).open(nil) })
	var we *wanted.Error
	if !errors.As(err, &we) || we.Path != "want/cards" || !strings.Contains(err.Error(), strconv.Itoa(wanted.MaxCards)) {
		t.Errorf("error = %v, want a *wanted.Error at want/cards that names %d", err, wanted.MaxCards)
	}
	if got := p.readsUnder("want/cards"); got != 0 {
		t.Errorf("%d files were read, want none: %q", got, p.read)
	}
	if got := p.count(p.listed, "want/cards"); got != 1 {
		t.Errorf("want/cards was listed %d times, want once", got)
	}
	// Bad files over the limit: still no file is read, and the count is the error, not a finding.
	bad := map[string]string{}
	for i := range wanted.MaxCards + 1 {
		bad[fmt.Sprintf("want/cards/c%04d.yaml", i)] = "version: 2\n"
	}
	p = &probe{}
	_ = mustFail(t, func() fsx.FS { return memBundle(bad).open(p) })
	if p.readsUnder("want/cards") != 0 {
		t.Errorf("files were read: %d", p.readsUnder("want/cards"))
	}
}

func TestExactlyTheLimitOfCardFilesIsReadOneByOne(t *testing.T) {
	p := &probe{}
	rep := mustInspect(t, memBundle(numbered(wanted.MaxCards)).open(p))
	if len(rep.Cards) != wanted.MaxCards || len(rep.Findings) != 0 {
		t.Fatalf("cards %d, findings %+v", len(rep.Cards), rep.Findings)
	}
	if got := p.readsUnder("want/cards"); got != wanted.MaxCards {
		t.Errorf("%d reads, want %d", got, wanted.MaxCards)
	}
}

func TestAFolderThatTheListerRefusesIsAnErrorWithNoFileRead(t *testing.T) {
	for _, n := range []int{wanted.MaxFiles, wanted.MaxFiles + 1} {
		p := &probe{}
		_ = mustFail(t, func() fsx.FS { return memBundle(numbered(n)).open(p) })
		if p.readsUnder("want/cards") != 0 {
			t.Errorf("%d names: files were read", n)
		}
	}
	// A folder with more names than any folder holds.
	big := newDir()
	cdir := newDir()
	for i := range fsx.MaxDirEntries + 1 {
		cdir.kids[fmt.Sprintf("c%05d.yaml", i)] = &node{kind: "file"}
	}
	big.put("want/cards", cdir)
	p := &probe{}
	_ = mustFail(t, func() fsx.FS { return big.open(p) })
	if len(p.read) != 0 {
		t.Errorf("files were read")
	}
}

func TestNoContextNoFileSystemAndAClosedFileSystemAreErrorsAndNeverAPanic(t *testing.T) {
	var noCtx context.Context
	var noFS fsx.FS
	good := memBundle(goodSet())
	if rep, err := cards.Inspect(noCtx, good.open(nil)); err == nil || rep != nil {
		t.Errorf("Inspect(nil context) = %+v, %v", rep, err)
	}
	if err := cards.Check(noCtx, good.open(nil)); err == nil {
		t.Error("Check(nil context) = nil")
	}
	if rep, err := cards.Inspect(t.Context(), noFS); err == nil || rep != nil {
		t.Errorf("Inspect(nil file system) = %+v, %v", rep, err)
	}
	if err := cards.Check(t.Context(), noFS); err == nil {
		t.Error("Check(nil file system) = nil")
	}
	// Both nil: still an error.
	if rep, err := cards.Inspect(noCtx, noFS); err == nil || rep != nil {
		t.Errorf("Inspect(nil, nil) = %+v, %v", rep, err)
	}
	closed := good.open(nil)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if rep, err := cards.Inspect(t.Context(), closed); err == nil || rep != nil {
		t.Errorf("Inspect(closed) = %+v, %v", rep, err)
	}
	if err := cards.Check(t.Context(), closed); err == nil {
		t.Error("Check(closed) = nil")
	}
}

func TestACanceledContextIsTheContextsErrorAndNothingIsRead(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p := &probe{}
	rep, err := cards.Inspect(ctx, memBundle(goodSet()).open(p))
	if rep != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Inspect = %+v, %v; want context.Canceled and no report", rep, err)
	}
	if len(p.opened) != 0 || len(p.read) != 0 {
		t.Errorf("the folder was touched: opened %q, read %q", p.opened, p.read)
	}
	if cerr := cards.Check(ctx, memBundle(goodSet()).open(nil)); !errors.Is(cerr, context.Canceled) {
		t.Errorf("Check = %v, want the error of the context as it is", cerr)
	}
	var we *wanted.Error
	if errors.As(err, &we) {
		t.Errorf("the error of the context was wrapped as a wanted file fault: %v", err)
	}
	// A deadline that has passed is the same.
	dctx, dcancel := context.WithTimeout(t.Context(), 0)
	defer dcancel()
	if _, err := cards.Inspect(dctx, memBundle(goodSet()).open(nil)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Inspect with a passed deadline = %v", err)
	}
}

func TestAContextThatEndsInTheMiddleStopsBeforeTheNextFile(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			ctx := &flipCtx{}
			p := &probe{onRead: func(path string) error {
				ctx.err = cause // the context ends while the first file is read
				return nil
			}}
			rep, err := cards.Inspect(ctx, memBundle(goodSet()).open(p))
			if rep != nil || !errors.Is(err, cause) {
				t.Fatalf("Inspect = %+v, %v; want %v and no report", rep, err, cause)
			}
			if len(p.read) != 1 {
				t.Errorf("%d files were read after the context ended, want 1: %q", len(p.read), p.read)
			}
		})
	}
	t.Run("after the listing and before the first file", func(t *testing.T) {
		ctx := &flipCtx{}
		p := &probe{onList: func(string) { ctx.err = context.Canceled }}
		rep, err := cards.Inspect(ctx, memBundle(goodSet()).open(p))
		if rep != nil || !errors.Is(err, context.Canceled) || len(p.read) != 0 {
			t.Errorf("Inspect = %+v, %v, reads %q", rep, err, p.read)
		}
	})
}

// causeError is the cause of a read fault that records whether anyone asked for its text.
type causeError struct {
	asked *int
	under error
}

func (e causeError) Error() string { *e.asked++; return "the text of the cause" }
func (e causeError) Unwrap() error { return e.under }

func TestAFileThatCannotBeReadIsAnErrorNotAFinding(t *testing.T) {
	boom := errors.New("the disk failed")
	cases := map[string]error{
		"a read fault":         boom,
		"a permission fault":   fs.ErrPermission,
		"a file that went":     &fs.PathError{Op: "read", Path: "x", Err: fs.ErrNotExist},
		"a link":               fmt.Errorf("%w: x", fsx.ErrLink),
		"not a regular file":   fmt.Errorf("%w: x", fsx.ErrNotRegular),
		"a closed folder":      fs.ErrClosed,
		"the read limit words": errors.New("the file is longer than the limit of a read"),
	}
	for name, cause := range cases {
		t.Run(name, func(t *testing.T) {
			asked := 0
			n := memBundle(goodSet())
			bad := cardFile("practice-one")
			p := &probe{onRead: func(path string) error {
				if path == bad {
					return causeError{asked: &asked, under: cause}
				}
				return nil
			}}
			rep, err := cards.Inspect(t.Context(), n.open(p))
			if rep != nil || err == nil {
				t.Fatalf("Inspect = %+v, %v; want an error and no report", rep, err)
			}
			if asked != 0 {
				t.Errorf("the text of the cause was asked %d times by Inspect", asked)
			}
			if !errors.Is(err, cause) {
				t.Errorf("the error %v does not wrap the cause", err)
			}
			var we *wanted.Error
			if !errors.As(err, &we) || we.Path != bad {
				t.Errorf("error = %T %v, want a *wanted.Error at %s", err, err, bad)
			}
			if !printable(err.Error()) {
				t.Errorf("not printable: %+q", err.Error())
			}
			if cerr := cards.Check(t.Context(), memBundle(goodSet()).open(&probe{onRead: p.onRead})); cerr == nil {
				t.Error("Check accepted a bundle with a file that cannot be read")
			}
		})
	}
}

func TestAFileThatWentAwayAfterTheListingIsAnError(t *testing.T) {
	n := memBundle(goodSet())
	p := &probe{onRead: func(path string) error {
		if path == cardFile("day-one") {
			delete(n.kids["want"].kids["cards"].kids, "root-a.yaml")
		}
		return nil
	}}
	rep, err := cards.Inspect(t.Context(), n.open(p))
	if rep != nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Inspect = %+v, %v; want an error that says the file is gone", rep, err)
	}
	var we *wanted.Error
	if !errors.As(err, &we) || we.Path != cardFile("root-a") {
		t.Errorf("error = %v, want a *wanted.Error at %s", err, cardFile("root-a"))
	}
	// A file that became a link after the listing.
	n = memBundle(goodSet())
	p = &probe{onRead: func(path string) error {
		if path == cardFile("day-one") {
			n.kids["want"].kids["cards"].kids["root-b.yaml"] = &node{kind: "link"}
		}
		return nil
	}}
	rep, err = cards.Inspect(t.Context(), n.open(p))
	if rep != nil || !errors.Is(err, fsx.ErrLink) {
		t.Fatalf("Inspect = %+v, %v; want an error that says a link", rep, err)
	}
}

func TestACauseThatIsTheLimitOfAReadIsAFindingAndItsTextIsNeverAsked(t *testing.T) {
	asked := 0
	n := memBundle(goodSet())
	p := &probe{onRead: func(path string) error {
		if path == cardFile("root-b") {
			return causeError{asked: &asked, under: fmt.Errorf("x: %w", fsx.ErrTooLarge)}
		}
		return nil
	}}
	rep := mustInspect(t, n.open(p))
	if asked != 0 {
		t.Errorf("the text of the cause was asked %d times", asked)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Path != cardFile("root-b") || rep.Findings[0].Code != cards.FileInvalid {
		t.Errorf("findings = %+v", rep.Findings)
	}
	if rep.Findings[0].Detail != "the file cannot be read: it is too long" {
		t.Errorf("detail = %q", rep.Findings[0].Detail)
	}
}

// hostileNames are names that a damaged or hostile stick can hold.
var hostileNames = []string{
	"a\x01b.yaml", "a\nb.yaml", "a\x00b.yaml", "a\u202eb.yaml", "a\u2066b.yaml", "a\x7fb.yaml",
	"a\xffb.yaml", "\xc3.yaml", "a\ufffdb.yaml", "caf\u00e9.yaml", "\u0430.yaml", "a b.yaml", "a\\b.yaml",
	"a/b.yaml", "..yaml", "a\tb.yaml", "\U0001f600.yaml", "A.yaml", strings.Repeat("a", 64) + ".yaml",
	strings.Repeat("\x01", 300) + ".yaml",
}

func TestAHostileNameIsAnErrorWithAPrintableTextAndNoFileRead(t *testing.T) {
	for _, name := range hostileNames {
		t.Run(fmt.Sprintf("%+q", name), func(t *testing.T) {
			n := memBundle(goodSet())
			n.kids["want"].kids["cards"].kids[name] = &node{kind: "file", data: []byte(cardRootB)}
			p := &probe{}
			rep, err := cards.Inspect(t.Context(), n.open(p))
			if err == nil || rep != nil {
				t.Fatalf("Inspect = %+v, %v", rep, err)
			}
			if !printable(err.Error()) {
				t.Errorf("the error is not printable ASCII: %+q", err.Error())
			}
			if p.readsUnder("want/cards") != 0 {
				t.Errorf("files were read: %q", p.read)
			}
		})
	}
}

// Record 0006, rule 46 and the cli page ("Machine-readable output"): a name that a reader gets from the
// list of a folder is shown with every character beyond printable ASCII written as an escape, a space
// written \x20 and every backslash doubled, so that two different names never print as the same line. The
// error of a folder that holds such a name must obey the same rule.
func TestTwoDifferentNamesInTheFolderNeverGiveTheSameErrorText(t *testing.T) {
	texts := map[string]string{}
	for _, name := range hostileNames {
		n := memBundle(nil)
		n.put("want/cards/"+name, &node{kind: "file"})
		_, err := cards.Inspect(t.Context(), n.open(nil))
		if err == nil {
			// A name with a slash is a folder in the memory bundle: not an entry of want/cards.
			continue
		}
		if other, ok := texts[err.Error()]; ok {
			t.Errorf("the names %+q and %+q give the same error text %q", other, name, err.Error())
		}
		texts[err.Error()] = name
	}
	// A space is written \x20 and a backslash is doubled.
	for name, want := range map[string]string{"a b.yaml": `want/cards/a\x20b.yaml`, "a\\b.yaml": `want/cards/a\\b.yaml`, "a\xffb.yaml": `want/cards/a\xffb.yaml`} {
		n := memBundle(nil)
		n.put("want/cards/"+name, &node{kind: "file"})
		_, err := cards.Inspect(t.Context(), n.open(nil))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the name %+q: error %v, want the path written %q", name, err, want)
		}
	}
}

func TestAFolderIsListedOnceAndEachFileIsReadOnceAndNothingElseIsTouched(t *testing.T) {
	files := with(goodSet(), map[string]string{
		"ritueel.yaml":            "x",
		"want/roots/x509.yaml":    "x",
		"want/delegations/a.yaml": "x",
		"seen/cards/a.json":       "x",
		"history/a/plan.json":     "x",
		"requests/a/request.json": "x",
		"trust/a/keys.txt":        "x",
		"cards/a.yaml":            "x",
	})
	for name, extra := range map[string]map[string]string{
		"a good set": nil,
		"with a bad file and a twin": {
			cardFile("zz-bad"):  "version: 2\n",
			cardFile("zz-twin"): cardRootB,
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := &probe{}
			n := memBundle(with(files, extra))
			mustInspect(t, n.open(p))
			if !slices.Equal(p.listed, []string{"want/cards"}) {
				t.Errorf("listed %q, want want/cards once", p.listed)
			}
			var want []string
			for path := range with(goodSet(), extra) {
				want = append(want, path)
			}
			slices.Sort(want)
			if !slices.Equal(p.read, want) {
				t.Errorf("read %q, want each card file once, in the order of the names: %q", p.read, want)
			}
			for _, o := range p.opened {
				if o != "want" && o != "want/cards" {
					t.Errorf("a folder was opened that is not on the way to want/cards: %q", o)
				}
			}
		})
	}
	// The check reads the same.
	p := &probe{}
	if err := cards.Check(t.Context(), memBundle(files).open(p)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.listed, []string{"want/cards"}) || len(p.read) != 5 {
		t.Errorf("Check listed %q and read %d files", p.listed, len(p.read))
	}
}

func TestHostileTextInAFileIsShownOnlyAsEscapes(t *testing.T) {
	texts := []string{
		"version: 1\nserial: \"1\"\nkind: \"a\u202eb\"\napplications: [piv]\n",
		"version: 1\nserial: \"1\"\nkind: \"a\\x01b\"\napplications: [piv]\n",
		"version: 1\nserial: \"1\"\nkind: \"\xff\xfe\"\napplications: [piv]\n",
		"version: 1\nserial: \"1\"\nkind: " + strings.Repeat("\u202e", 300) + "\napplications: [piv]\n",
		"version: 1\nserial: \"" + strings.Repeat("9", 5000) + "\"\nkind: root\napplications: [piv]\n",
		"version: 1\nserial: \"1\"\nkind: root\napplications: [piv]\n" + strings.Repeat("\x00", 100),
		"version: 1\nserial: \"1\"\nkind: root\napplications: [" + strings.Repeat("\u0430", 500) + "]\n",
		"version: 1\nserial: \"1\"\nkind: root\napplications: [piv]\n\u202e: 1\n",
		strings.Repeat("\u202e", 1000),
	}
	for i, text := range texts {
		rep := mustInspect(t, memBundle(map[string]string{cardFile("x"): text}).open(nil))
		if len(rep.Findings) != 1 {
			t.Errorf("text %d: findings = %+v", i, rep.Findings)
			continue
		}
		f := rep.Findings[0]
		if !printable(f.Detail) || !printable(f.Line()) || len(f.Detail) > 240 || strings.ContainsAny(f.Line(), "\r\n") {
			t.Errorf("text %d: the finding is not printable ASCII of at most 240 bytes: %+q", i, f.Line())
		}
		if err := cards.Check(t.Context(), memBundle(map[string]string{cardFile("x"): text}).open(nil)); err == nil || !printable(err.Error()) {
			t.Errorf("text %d: Check = %+q", i, err)
		}
	}
}

func TestTwoDifferentCardFileNamesNeverGiveOneFindingLine(t *testing.T) {
	files := map[string]string{}
	for _, n := range []string{"a", "a-", "a0", "a-b", "ab", "0a", "9", "a--b", "x1", "x-1"} {
		files[cardFile(n)] = "version: 2\n"
	}
	rep := mustInspect(t, memBundle(files).open(nil))
	seen := map[string]string{}
	for _, f := range rep.Findings {
		if other, ok := seen[f.Line()]; ok {
			t.Errorf("%s and %s give one line %q", other, f.Path, f.Line())
		}
		seen[f.Line()] = f.Path
	}
	if len(seen) != len(files) {
		t.Errorf("%d lines for %d files", len(seen), len(files))
	}
}
