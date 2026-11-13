package fsx_test

// The names and paths the writer refuses before it touches the file system, and the ones it
// accepts and then really writes. The rules are those of the package comment ("A name is checked
// against what the exFAT file system of a stick can hold") and of fsx.ErrInvalid. They apply to
// every element of a path and to every name of a set, except the temporary-name prefix, which
// only the last element of a path and any name of a set must not have.
//
// Every refused row holds one fault only, so that removing one rule from the writer fails the
// row of that rule and is not hidden by another rule that refuses the same name. The one pair
// that cannot be told apart is the byte limit and the UTF-16 limit: a name that has more than
// 255 UTF-16 code units has more than 255 bytes, so the UTF-16 rule never refuses a name that
// the byte rule would let through (see TestLongNamesAreRefusedByTheByteLimit).

import (
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"ritueel.id/ritueel/internal/fsx"
)

// cwdFS runs a memFS as if the working directory of the process were base: a relative path is
// made absolute under base before it reaches the memFS (which has only absolute paths). A path
// with no folder, "x", reaches the file system as "x" and as "." for its folder, as on a real one.
type cwdFS struct {
	*memFS
	base string
}

func (c cwdFS) abs(p string) string {
	if path.IsAbs(p) {
		return p
	}
	return path.Join(c.base, p)
}

func (c cwdFS) Mkdir(p string, perm fs.FileMode) error { return c.memFS.Mkdir(c.abs(p), perm) }
func (c cwdFS) CreateExcl(p string, perm fs.FileMode) (fsx.File, error) {
	return c.memFS.CreateExcl(c.abs(p), perm)
}
func (c cwdFS) RenameNoReplace(o, n string) error { return c.memFS.RenameNoReplace(c.abs(o), c.abs(n)) }
func (c cwdFS) SyncDir(p string) error            { return c.memFS.SyncDir(c.abs(p)) }

var _ fsx.FS = cwdFS{}

// nameRow is one name and the label of what it tests.
type nameRow struct{ why, name string }

func rep(s string, n int) string { return strings.Repeat(s, n) }

// utf16Len counts UTF-16 code units, as exFAT does.
func utf16Len(s string) int { return len(utf16.Encode([]rune(s))) }

// Names with the same length in bytes and in UTF-16 code units, and names that have a
// different one, at the edge of the 255 limit.
var (
	ascii255   = rep("a", 255)
	ascii256   = rep("a", 256)
	eAcute127a = rep("é", 127) + "a"  // 255 bytes, 128 UTF-16 code units
	eAcute128  = rep("é", 128)        // 256 bytes, 128 units
	euro85     = rep("€", 85)         // 255 bytes, 85 units
	euro86     = rep("€", 86)         // 258 bytes
	emoji63abc = rep("😀", 63) + "abc" // 255 bytes, 129 units
	emoji63abd = rep("😀", 63) + "abcd"
	emoji127a  = rep("😀", 127) + "a" // 255 UTF-16 code units, 509 bytes
	emoji128   = rep("😀", 128)       // 256 UTF-16 code units, 512 bytes
)

// refusedNames are single names (one element of a path, one name of a set) that the writer
// must refuse with ErrInvalid. None holds a separator and each has one fault only.
var refusedNames = []nameRow{
	// a control code, U+0000 to U+001F, anywhere in the name
	{"control U+0000 inside", "a\x00b"},
	{"control U+0000 alone", "\x00"},
	{"control U+0001 inside", "a\x01b"},
	{"control U+0001 at the end", "a\x01"},
	{"control U+0009 tab", "a\tb"},
	{"control U+000A newline", "a\nb"},
	{"control U+000D carriage return", "a\rb"},
	{"control U+001F inside", "a\x1fb"},
	{"control U+001F at the start", "\x1fa"},

	// each character of exFAT's list of invalid characters, alone (the slash is a separator
	// in a path, so it is tried as a name of a set only)
	{"quotation mark", `a"b`},
	{"asterisk", "a*b"},
	{"colon", "a:b"},
	{"less-than sign", "a<b"},
	{"greater-than sign", "a>b"},
	{"question mark", "a?b"},
	{"back slash", `a\b`},
	{"vertical bar", "a|b"},
	{"quotation mark alone", `"`},
	{"colon alone", ":"},
	{"back slash alone", `\`},
	{"a drive, C:x", "C:x"},
	{"a drive path, C:\\x", `C:\x`},

	// an end with a dot or a space
	{"trailing dot", "a."},
	{"trailing dot after an extension", "a.json."},
	{"trailing space", "a "},
	{"two trailing spaces", "a  "},
	{"a space alone", " "},
	{"dot then space at the end", "a. "},
	{"space then dot at the end", "a ."},
	{"only dots, three of them", "..."},

	// length, in bytes (the 256th byte is refused) and in UTF-16 code units
	{"256 ASCII bytes", ascii256},
	{"1000 ASCII bytes", rep("a", 1000)},
	{"128 times é, 256 bytes", eAcute128},
	{"127 times é and ab, 256 bytes", rep("é", 127) + "ab"},
	{"86 times €, 258 bytes", euro86},
	{"63 times U+1F600 and abcd, 256 bytes", emoji63abd},
	{"64 times U+1F600, 256 bytes", rep("😀", 64)},
	{"100 times U+1F600, 400 bytes and 200 UTF-16 units", rep("😀", 100)},
	{"127 times U+1F600 and a, 255 UTF-16 units and 509 bytes", emoji127a},
	{"128 times U+1F600, 256 UTF-16 units and 512 bytes", emoji128},

	// bytes that are not UTF-8
	{"a lone 0xff byte", "\xff"},
	{"0xff inside", "a\xffb"},
	{"a truncated two-byte sequence", "\xc3"},
	{"a truncated sequence inside", "a\xe2\x82b"},
	{"an overlong encoding of a slash", "\xc0\xaf"},
	{"an encoded surrogate", "\xed\xa0\x80"},
	{"a code point above U+10FFFF", "\xf4\x90\x80\x80"},
	{"invalid UTF-8 at the end of an otherwise fine name", "abc.json\x80"},
}

// refusedPathForms are paths that are refused because of their shape and not because of one
// name. Every one is refused by every method that takes a path.
var refusedPathForms = []nameRow{
	{"empty", ""},
	{"a separator alone", "/"},
	{"two separators", "//"},
	{"three separators", "///"},
	{"trailing separator", "/b/d/x/"},
	{"trailing separator, relative", "b/d/x/"},
	{"trailing separator, no folder", "x/"},
	{"two trailing separators", "/b/d/x//"},
	{"a dot as the last element", "/b/d/."},
	{"a dot as a middle element", "/b/d/./f"},
	{"a dot as the first element", "./f"},
	{"a dot alone", "."},
	{"two dots as the last element", "/b/d/.."},
	{"two dots as a middle element", "/b/d/../f"},
	{"two dots as the first element", "../f"},
	{"two dots alone", ".."},
	{"two dots after a folder", "/b/../d/f"},
	{"an empty element in the middle", "/b/d//f"},
	{"an empty element near the start", "/b//d/f"},
	{"a doubled leading separator", "//b/d/f"},
	{"an empty element in a relative path", "a//b"},
	{"a doubled leading separator and one name", "//x"},
	{"the prefix of a temporary name, the last element", "/b/d/.rt-abcdefghijk"},
	{"the prefix alone, the last element", "/b/d/.rt-"},
	{"the prefix, the last element of a relative path", ".rt-x"},
}

// nameUse is one place a name can stand in a call.
type nameUse struct {
	label string
	// do makes the call. path is the whole path given to it.
	do func(t *testing.T, w *fsx.Writer, path string) error
	// extra lists what a success leaves besides the path itself, relative to it.
	extra []string
	// check says what the path must hold after a success.
	check func(t *testing.T, img *image, at string)
}

var pathUses = []nameUse{
	{
		label: "WriteFile",
		do: func(_ *testing.T, w *fsx.Writer, p string) error {
			return w.WriteFile(p, []byte("data"), 0o600)
		},
		check: func(t *testing.T, img *image, at string) {
			t.Helper()
			if got := mustFile(t, img, at); string(got) != "data" {
				t.Fatalf("%s holds %q", at, got)
			}
		},
	},
	{
		label: "Mkdir",
		do: func(_ *testing.T, w *fsx.Writer, p string) error {
			return w.Mkdir(p, 0o700)
		},
		check: func(t *testing.T, img *image, at string) {
			t.Helper()
			if !img.isDir(at) {
				t.Fatalf("%s is not a folder", at)
			}
		},
	},
	{
		label: "CreateJournal",
		do: func(t *testing.T, w *fsx.Writer, p string) error {
			j, err := w.CreateJournal(p)
			if err != nil {
				if j != nil {
					t.Errorf("CreateJournal %q returned a journal with an error", p)
				}
				return err
			}
			if err := j.Append([]byte("one")); err != nil {
				_ = j.Close()
				return err
			}
			return j.Close()
		},
		check: func(t *testing.T, img *image, at string) {
			t.Helper()
			lines, partial, err := fsx.ReadJournal(img, at)
			if err != nil || len(lines) != 1 || string(lines[0]) != "one" || partial != nil {
				t.Fatalf("the journal %s holds %q and %q (%v)", at, lines, partial, err)
			}
		},
	},
	{
		label: "WriteSet folder",
		do: func(_ *testing.T, w *fsx.Writer, p string) error {
			return w.WriteSet(p, []fsx.NewFile{{Name: "a.json", Data: []byte("data"), Perm: 0o600}})
		},
		extra: []string{"a.json"},
		check: func(t *testing.T, img *image, at string) {
			t.Helper()
			if got := mustFile(t, img, at+"/a.json"); string(got) != "data" {
				t.Fatalf("%s/a.json holds %q", at, got)
			}
		},
	},
}

// placement is the place of a name in a path: the last element, the folder in the middle, the
// first element of a relative path, and a relative path that is the name alone.
type placement struct {
	label string
	// dirs are the folders that exist before, parents first, for the name n.
	dirs func(n string) []string
	// path is the path given, at is where it lands on the memFS.
	path, at func(n string) string
	// relative runs the writer on cwdFS with the working directory /b.
	relative bool
	// last says that n is the last element of the path (the temporary-name rule applies to it).
	last bool
}

var placements = []placement{
	{
		label: "last element",
		dirs:  func(string) []string { return []string{"/b", "/b/d"} },
		path:  func(n string) string { return "/b/d/" + n },
		at:    func(n string) string { return "/b/d/" + n },
		last:  true,
	},
	{
		label: "middle element",
		dirs:  func(n string) []string { return []string{"/b", "/b/" + n} },
		path:  func(n string) string { return "/b/" + n + "/f" },
		at:    func(n string) string { return "/b/" + n + "/f" },
	},
	{
		label:    "first element of a relative path",
		dirs:     func(n string) []string { return []string{"/b", "/b/" + n} },
		path:     func(n string) string { return n + "/f" },
		at:       func(n string) string { return "/b/" + n + "/f" },
		relative: true,
	},
	{
		label:    "relative path with no folder",
		dirs:     func(string) []string { return []string{"/b"} },
		path:     func(n string) string { return n },
		at:       func(n string) string { return "/b/" + n },
		relative: true,
		last:     true,
	},
}

func (pl placement) fsys(f *memFS) fsx.FS {
	if pl.relative {
		return cwdFS{memFS: f, base: "/b"}
	}
	return f
}

// requireRefused checks what every refused call has in common: an error that wraps ErrInvalid
// and is not a stop, no call to the file system, and a writer that goes on.
func requireRefused(t *testing.T, f *memFS, w *fsx.Writer, err error) {
	t.Helper()
	if !errors.Is(err, fsx.ErrInvalid) {
		t.Fatalf("got %v, want an error that wraps ErrInvalid", err)
	}
	var fe *fsx.Error
	if errors.As(err, &fe) {
		t.Fatalf("a refused argument is an *fsx.Error (a stop): %v", err)
	}
	if f.opCount() != 0 {
		t.Fatalf("a refused argument reached the file system: %v", f.opList())
	}
	if err := w.WriteFile("/b/d/ok.json", []byte("ok"), 0o600); err != nil {
		t.Fatalf("the writer stopped after a refused argument: %v", err)
	}
	if got := mustFile(t, f.Live(), "/b/d/ok.json"); string(got) != "ok" {
		t.Fatalf("the following write holds %q", got)
	}
	if got := f.openFiles(); got != 0 {
		t.Fatalf("%d files left open", got)
	}
}

// TestRefusedNamesInEveryElementOfEveryPath: each refused name, in the last element, in a
// folder in the middle and in the first element of a relative path, for each method that takes
// a path. The refusal is ErrInvalid, no file system call is made, and the writer goes on.
func TestRefusedNamesInEveryElementOfEveryPath(t *testing.T) {
	for _, row := range refusedNames {
		for _, use := range pathUses {
			for _, pl := range placements {
				t.Run(row.why+"/"+use.label+"/"+pl.label, func(t *testing.T) {
					f := newMemFS("/b", "/b/d")
					w := &fsx.Writer{FS: pl.fsys(f), Rand: newDetRand(1)}
					err := use.do(t, w, pl.path(row.name))
					requireRefused(t, f, w, err)
				})
			}
		}
	}
}

// TestRefusedShapesOfAPath: the paths that mean more than one thing, for each method.
func TestRefusedShapesOfAPath(t *testing.T) {
	for _, row := range refusedPathForms {
		for _, use := range pathUses {
			t.Run(row.why+"/"+use.label, func(t *testing.T) {
				f := newMemFS("/b", "/b/d")
				w := &fsx.Writer{FS: cwdFS{memFS: f, base: "/b"}, Rand: newDetRand(1)}
				err := use.do(t, w, row.name)
				requireRefused(t, f, w, err)
			})
		}
	}
}

// TestRefusedNamesOfASetFile: each refused name, and the names that are not one plain name,
// as the name of a file of a set: alone, last after a good name, and first before one.
func TestRefusedNamesOfASetFile(t *testing.T) {
	notPlain := []nameRow{
		{"empty", ""},
		{"a dot", "."},
		{"two dots", ".."},
		{"a slash inside", "a/b"},
		{"a leading slash", "/a"},
		{"a trailing slash", "a/"},
		{"a doubled slash", "a//b"},
		{"a parent and a name", "../a"},
		{"a current folder and a name", "./a"},
		{"a name and the parent", "a/.."},
		{"a slash alone", "/"},
		{"the prefix of a temporary name", ".rt-abcdefghijk"},
		{"the prefix of a temporary name, short", ".rt-x"},
		{"the prefix alone", ".rt-"},
	}
	good := fsx.NewFile{Name: "good.json", Data: []byte("x"), Perm: 0o600}
	for _, row := range slices.Concat(refusedNames, notPlain) {
		bad := fsx.NewFile{Name: row.name, Data: []byte("x"), Perm: 0o600}
		for label, files := range map[string][]fsx.NewFile{
			"alone":              {bad},
			"after a good name":  {good, bad},
			"before a good name": {bad, good},
			"between good names": {good, bad, {Name: "also-good.json", Data: []byte("x"), Perm: 0o600}},
		} {
			t.Run(row.why+"/"+label, func(t *testing.T) {
				f := newMemFS("/b", "/b/d")
				w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
				err := w.WriteSet("/b/d/s", files)
				requireRefused(t, f, w, err)
			})
		}
	}
}

// TestSetNamesThatDifferOnlyByCaseAreRefused: exFAT compares names after up-casing them, so
// two such names are one entry there. Within one set the writer refuses the pair itself.
func TestSetNamesThatDifferOnlyByCaseAreRefused(t *testing.T) {
	nf := func(n string) fsx.NewFile { return fsx.NewFile{Name: n, Data: []byte("x"), Perm: 0o600} }
	for _, c := range []struct {
		why   string
		files []fsx.NewFile
	}{
		{"the first upper, the second lower", []fsx.NewFile{nf("Keys.json"), nf("keys.json")}},
		{"the first lower, the second upper", []fsx.NewFile{nf("keys.json"), nf("Keys.json")}},
		{"all upper against all lower", []fsx.NewFile{nf("KEYS.JSON"), nf("keys.json")}},
		{"a case that differs inside", []fsx.NewFile{nf("kEys.json"), nf("keYs.json")}},
		{"not next to each other", []fsx.NewFile{nf("keys.json"), nf("root.json"), nf("KEYS.json")}},
		{"the last against the first of four", []fsx.NewFile{nf("a"), nf("b"), nf("c"), nf("A")}},
		{"a letter beyond ASCII, é and É", []fsx.NewFile{nf("é.json"), nf("É.json")}},
		{"a Cyrillic letter, к and К", []fsx.NewFile{nf("к.json"), nf("К.json")}},
		{"a Greek letter, σ and Σ", []fsx.NewFile{nf("σ"), nf("Σ")}},
		{"a pair after a good name", []fsx.NewFile{nf("good.json"), nf("Ab"), nf("aB")}},
	} {
		t.Run(c.why, func(t *testing.T) {
			f := newMemFS("/b", "/b/d")
			w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
			err := w.WriteSet("/b/d/s", c.files)
			requireRefused(t, f, w, err)
		})
	}
}

// TestSetNamesThatLookAlikeButAreNotTheSameEntryAreAccepted: the pairs that exFAT's up-casing
// keeps apart (the Kelvin sign, U+212A, is an upper-case letter that is not the upper case of
// "k"; "k" up-cases to "K"), and names that differ by more than case.
func TestSetNamesThatLookAlikeButAreNotTheSameEntryAreAccepted(t *testing.T) {
	nf := func(n string) fsx.NewFile { return fsx.NewFile{Name: n, Data: []byte("x" + n), Perm: 0o600} }
	for _, c := range []struct {
		why   string
		names []string
	}{
		{"the Kelvin sign and k", []string{"\u212a.json", "k.json"}},
		{"the Kelvin sign and K", []string{"\u212a.json", "K.json"}},
		{"names that differ by more than case", []string{"keys.json", "keys.json.bak", "key.json"}},
		{"a name and the same name in a longer form", []string{"a", "aa", "A.b"}},
		{"dot files", []string{".a", ".b", "a", "b"}},
	} {
		t.Run(c.why, func(t *testing.T) {
			f := newMemFS("/b", "/b/d")
			w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
			var files []fsx.NewFile
			for _, n := range c.names {
				files = append(files, nf(n))
			}
			if err := w.WriteSet("/b/d/s", files); err != nil {
				t.Fatalf("WriteSet: %v", err)
			}
			live := f.Live()
			for _, n := range c.names {
				if got := mustFile(t, live, "/b/d/s/"+n); string(got) != "x"+n {
					t.Fatalf("%q holds %q", n, got)
				}
			}
		})
	}
}

// acceptedNames are single names that the writer must accept and then write under exactly
// that name. A leading dot, a dot or a space inside, and ".rt" without the hyphen are not
// refused; nor is a name of 255 bytes.
var acceptedNames = []nameRow{
	{"one letter", "x"},
	{"an extension", "a.b"},
	{"a dot file", ".hidden"},
	{"a dot file with an extension", ".a.json"},
	{"two dots at the start", "..a"},
	{"two dots inside", "a..b"},
	{"a space inside", "a b"},
	{"a layout name, yaml", "ritueel.yaml"},
	{"a layout name, journal", "births.jsonl"},
	{"a layout name, record", "record.json"},
	{"a layout name, a numbered trust set", "0007-acme"},
	{"hyphens and underscores", "a-b_c"},
	{"upper case", "Keys.json"},
	{"the temporary prefix without its hyphen", ".rt"},
	{"the temporary prefix with another character", ".rt_a"},
	{"the temporary prefix not at the start", "x.rt-abcdefghijk"},
	{"rt with a hyphen and no dot", "rt-abc"},
	{"a Latin letter with an accent", "é.json"},
	{"a decomposed accent", "e\u0301.json"},
	{"Cyrillic", "ключ.json"},
	{"Chinese", "鍵"},
	{"a character beyond the BMP", "😀.json"},
	{"the Kelvin sign", "\u212a.json"},
	{"the replacement character, valid UTF-8", "\ufffd.json"},
	{"254 ASCII bytes", rep("a", 254)},
	{"255 ASCII bytes", ascii255},
	{"127 times é and a, 255 bytes", eAcute127a},
	{"85 times €, 255 bytes", euro85},
	{"63 times U+1F600 and abc, 255 bytes", emoji63abc},
	{"63 times U+1F600, 252 bytes", rep("😀", 63)},
}

// acceptedNotLast are names that are fine for a folder but not as the last element of a path
// nor as the name of a file of a set: the prefix of a temporary name.
var acceptedNotLast = []nameRow{
	{"the temporary prefix and 11 characters", ".rt-abcdefghijk"},
	{"the temporary prefix and one character", ".rt-x"},
	{"the temporary prefix alone", ".rt-"},
}

// TestAcceptedNamesAreWrittenAtExactlyThatName: each accepted name, in each place and for each
// method, makes a write that succeeds and leaves the file or the folder at exactly that name,
// and nothing else but the folders that were there before: no temporary name is left.
func TestAcceptedNamesAreWrittenAtExactlyThatName(t *testing.T) {
	for _, group := range []struct {
		rows    []nameRow
		lastToo bool
	}{
		{rows: acceptedNames, lastToo: true},
		{rows: acceptedNotLast, lastToo: false},
	} {
		for _, row := range group.rows {
			for _, use := range pathUses {
				for _, pl := range placements {
					if pl.last && !group.lastToo {
						continue
					}
					t.Run(row.why+"/"+use.label+"/"+pl.label, func(t *testing.T) {
						f := newMemFS(pl.dirs(row.name)...)
						w := &fsx.Writer{FS: pl.fsys(f), Rand: newDetRand(1)}
						if err := use.do(t, w, pl.path(row.name)); err != nil {
							t.Fatalf("got %v, want the write to succeed", err)
						}
						at := pl.at(row.name)
						use.check(t, f.Live(), at)
						want := []string{"/"}
						want = append(want, pl.dirs(row.name)...)
						want = append(want, at)
						for _, x := range use.extra {
							want = append(want, at+"/"+x)
						}
						slices.Sort(want)
						want = slices.Compact(want)
						if got := f.Live().paths(); !slices.Equal(got, want) {
							t.Fatalf("the tree holds %q, want %q", got, want)
						}
						// the stop is not set: another write goes on
						if err := w.WriteFile("/b/after.json", []byte("x"), 0o600); err != nil {
							t.Fatalf("the writer stopped: %v", err)
						}
					})
				}
			}
		}
	}
}

// TestAcceptedNamesAsTheNameOfAFileOfASet: each accepted name as a file of a set (the folder
// of the set stays plain), alone and beside another name.
func TestAcceptedNamesAsTheNameOfAFileOfASet(t *testing.T) {
	for _, row := range acceptedNames {
		t.Run(row.why, func(t *testing.T) {
			f := newMemFS("/b", "/b/d")
			w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
			files := []fsx.NewFile{
				{Name: "first.json", Data: []byte("1"), Perm: 0o600},
				{Name: row.name, Data: []byte("name " + row.name), Perm: 0o600},
				{Name: "last.json", Data: []byte("3"), Perm: 0o400},
			}
			if err := w.WriteSet("/b/d/s", files); err != nil {
				t.Fatalf("got %v, want the write to succeed", err)
			}
			want := []string{"/", "/b", "/b/d", "/b/d/s", "/b/d/s/first.json", "/b/d/s/" + row.name, "/b/d/s/last.json"}
			slices.Sort(want)
			if got := f.Live().paths(); !slices.Equal(got, want) {
				t.Fatalf("the tree holds %q, want %q", got, want)
			}
			if got := mustFile(t, f.Live(), "/b/d/s/"+row.name); string(got) != "name "+row.name {
				t.Fatalf("the file holds %q", got)
			}
		})
	}
}

// TestThePlainFormsOfAPathAreAccepted pins the forms that look like the refused ones but are
// not: "/a/b" with its leading separator, a relative path with no folder, the prefix of a
// temporary name in a folder that is not the last element, a dot file.
func TestThePlainFormsOfAPathAreAccepted(t *testing.T) {
	f := newMemFS("/b", "/b/d", "/b/.rt-dir", "/b/.hidden")
	w := &fsx.Writer{FS: cwdFS{memFS: f, base: "/b"}, Rand: newDetRand(1)}
	for _, p := range []string{"/b/d/x.json", "d/y.json", "z.json", "/b/.rt-dir/q.json", ".rt-dir/r.json", "/b/.hidden/.s", "/z"} {
		if err := w.WriteFile(p, []byte(p), 0o600); err != nil {
			t.Errorf("WriteFile %q: %v", p, err)
		}
	}
	live := f.Live()
	for p, at := range map[string]string{
		"/b/d/x.json":       "/b/d/x.json",
		"d/y.json":          "/b/d/y.json",
		"z.json":            "/b/z.json",
		"/b/.rt-dir/q.json": "/b/.rt-dir/q.json",
		".rt-dir/r.json":    "/b/.rt-dir/r.json",
		"/b/.hidden/.s":     "/b/.hidden/.s",
		"/z":                "/z",
	} {
		if got := mustFile(t, live, at); string(got) != p {
			t.Errorf("%s holds %q, want %q", at, got, p)
		}
	}
}

// TestLongNamesAreRefusedByTheByteLimit pins how the two limits meet. A name of 127 times
// U+1F600 and "a" is 255 UTF-16 code units, which exFAT holds, and 509 bytes, which a
// workstation's file system does not: the writer refuses it, because a bundle must fit both.
// 128 times U+1F600 is over both limits. A name over 255 UTF-16 code units is always over 255
// bytes, so the UTF-16 limit adds nothing that the byte limit does not refuse already.
func TestLongNamesAreRefusedByTheByteLimit(t *testing.T) {
	if got := utf16Len(emoji127a); got != 255 {
		t.Fatalf("the test name has %d UTF-16 code units, want 255", got)
	}
	if got := utf16Len(emoji128); got != 256 {
		t.Fatalf("the test name has %d UTF-16 code units, want 256", got)
	}
	if got := utf16Len(eAcute128); got != 128 {
		t.Fatalf("the test name has %d UTF-16 code units, want 128", got)
	}
	// the edge on both sides, in bytes
	for _, c := range []struct {
		name   string
		bytes  int
		accept bool
	}{
		{ascii255, 255, true},
		{ascii256, 256, false},
		{eAcute127a, 255, true},
		{eAcute128, 256, false},
		{euro85, 255, true},
		{euro86, 258, false},
		{emoji63abc, 255, true},
		{emoji63abd, 256, false},
		{emoji127a, 509, false},
		{emoji128, 512, false},
	} {
		if len(c.name) != c.bytes {
			t.Fatalf("a test name has %d bytes, want %d", len(c.name), c.bytes)
		}
		f := newMemFS("/b", "/b/d")
		w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
		err := w.WriteFile("/b/d/"+c.name, []byte("x"), 0o600)
		switch {
		case c.accept && err != nil:
			t.Errorf("a name of %d bytes and %d UTF-16 units: %v, want it accepted", len(c.name), utf16Len(c.name), err)
		case !c.accept && !errors.Is(err, fsx.ErrInvalid):
			t.Errorf("a name of %d bytes and %d UTF-16 units: %v, want ErrInvalid", len(c.name), utf16Len(c.name), err)
		}
	}
	// No name has more UTF-16 code units than bytes, so no name is over the UTF-16 limit and
	// under the byte limit. Checked over every code point class at its edge.
	for _, r := range []rune{'a', 'é', '€', '😀', 0x7f, 0x80, 0x7ff, 0x800, 0xffff, 0x10000, 0x10ffff} {
		s := string(r)
		if utf16Len(s) > len(s) {
			t.Errorf("U+%04X has %d UTF-16 code units and %d bytes", r, utf16Len(s), len(s))
		}
	}
}

// TestRefusedNameBetweenGoodWritesChangesNothing: a refusal in the middle of a run, between
// good writes, leaves the earlier files and the later writes alone.
func TestRefusedNameBetweenGoodWritesChangesNothing(t *testing.T) {
	f := newMemFS("/b", "/b/d")
	w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
	if err := w.WriteFile("/b/d/one.json", []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := f.opCount()
	for _, bad := range []string{"/b/d/two.json.", "/b/d/t:wo.json", "/b/d/" + ascii256, "/b/d\x00/x", "/b/d/\xff"} {
		if err := w.WriteFile(bad, []byte("2"), 0o600); !errors.Is(err, fsx.ErrInvalid) {
			t.Fatalf("WriteFile %q = %v, want ErrInvalid", bad, err)
		}
	}
	if f.opCount() != before {
		t.Fatalf("refused names reached the file system: %v", f.opList()[before:])
	}
	if err := w.WriteFile("/b/d/three.json", []byte("3"), 0o600); err != nil {
		t.Fatal(err)
	}
	live := f.Live()
	for p, want := range map[string]string{"/b/d/one.json": "1", "/b/d/three.json": "3"} {
		if got := mustFile(t, live, p); string(got) != want {
			t.Fatalf("%s holds %q", p, got)
		}
	}
	want := []string{"/", "/b", "/b/d", "/b/d/one.json", "/b/d/three.json"} // and no temporary name
	if got := live.paths(); !slices.Equal(got, want) {
		t.Fatalf("the tree holds %q, want %q", got, want)
	}
}
