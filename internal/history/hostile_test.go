//go:build linux || darwin

package history

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// Hostile input: everything that comes from the bundle is data from the stick. A name, a type, a
// size, the order of things. Each case runs with a time limit (runFS), so that a hang fails the
// test; and every finding, whatever the name, is printable ASCII with no line break.

func ch(r rune) string { return string(r) }

// escaped is the path part that a name must show as: printable ASCII as it is, a backslash twice,
// every other character as the escape of its UTF-16 code units, each byte that is not UTF-8 as x and
// two digits.
// It is worked out here, not taken from the package.
func escaped(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		switch {
		case r == utf8.RuneError && n == 1:
			// Each byte that is not UTF-8 is its own escape, so that it differs from U+FFFD itself.
			fmt.Fprintf(&b, `\x%02x`, s[i-n])
		case r == ' ':
			// A space is written as the escape of its byte, so that a name cannot put words in a line.
			b.WriteString(`\x20`)
		case r == 0x5c:
			// A backslash is doubled, so that a backslash in the line is always the start of an escape.
			b.WriteString(`\\`)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		case r >= 0x10000:
			hi, lo := utf16.EncodeRune(r)
			b.WriteString(uesc(hi) + uesc(lo))
		default:
			b.WriteString(uesc(r))
		}
	}
	return b.String()
}

type hostileName struct {
	label string
	name  string
	// what is the name to the check: "invalid" breaks record 0006, rule 38, and fails; "temp" starts with the
	// prefix of a temporary name and is a notice; "valid" is a valid name that is not expected.
	class string
}

func hostileNames() []hostileName {
	return []hostileName{
		{"space", "a b", "invalid"},
		{"tab", "a\tb", "invalid"},
		{"line feed", "a\nb", "invalid"},
		{"carriage return", "a\rb", "invalid"},
		{"control byte", "a\x01b", "invalid"},
		{"delete", "a\x7fb", "invalid"},
		{"escape sequence", "a\x1b[31mred\x1b[0m", "invalid"},
		{"a byte that is not UTF-8", "a\xffb", "invalid"},
		{"a cut character", "a\xc3", "invalid"},
		{"an overlong slash", "a\xc0\xafb", "invalid"},
		{"Cyrillic look-alike of a", ch(0x430) + "bc", "invalid"},
		{"Cyrillic look-alike inside", "tr" + ch(0x443) + "st", "invalid"},
		{"right to left override", "a" + ch(0x202e) + "gpj.txt", "invalid"},
		{"zero width space", "a" + ch(0x200b) + "b", "invalid"},
		{"a letter with an accent", "caf" + ch(0xe9), "invalid"},
		{"a character beyond the first plane", "a" + ch(0x1f600), "invalid"},
		{"percent", "a%2e%2eb", "invalid"},
		{"backslash", "a" + ch(0x5c) + "b", "invalid"},
		{"colon", "C:x", "invalid"},
		{"star", "a*b", "invalid"},
		{"device name CON", "CON", "invalid"},
		{"device name aux with an extension", "aux.txt", "invalid"},
		{"device name com1", "com1", "invalid"},
		{"trailing dot", "x.", "invalid"},
		{"only dots", "...", "invalid"},
		{"temporary prefix", ".rt-abcdefghijk", "temp"},
		{"temporary prefix in capitals", ".RT-abcdefghijk", "temp"},
		{"temporary prefix in two cases", ".Rt-abcdefghijk", "temp"},
		{"temporary prefix and nothing more", ".rt-", "temp"},
		{"temporary prefix and a bad name", ".rt-a b", "temp"},
		{"temporary prefix and a control byte", ".RT-\x1b[2J", "temp"},
		{"a name that only looks like the prefix", ".rtx", "valid"},
		{"the start of the prefix", ".rt", "valid"},
		{"the start of the prefix in capitals", ".RT", "valid"},
		{"a file of a desktop", ".DS_Store", "valid"},
		{"a plain name", "notes.txt", "valid"},
		{"255 bytes", strings.Repeat("a", 255), "valid"},
	}
}

func wantClass(h hostileName) Code {
	if h.class == "invalid" {
		return UnexpectedName
	}
	return UnexpectedFile
}

// entry makes a file or a folder under a hostile name, or skips the test when the disk will not
// hold the name (a system that refuses a name that is not UTF-8).
func entry(t *testing.T, b *bundle, dir, name string, folder bool) {
	t.Helper()
	p := b.dir + "/" + dir + "/" + name
	var err error
	if folder {
		if err = os.MkdirAll(p, 0o755); err == nil {
			// Something inside that would be a finding if the folder were entered.
			err = os.WriteFile(p+"/record.json", []byte("not a record"), 0o644)
			if err == nil {
				err = os.WriteFile(p+"/root-list.json", []byte("not a list"), 0o644)
			}
		}
	} else {
		err = os.WriteFile(p, []byte("x"), 0o644)
	}
	if err != nil {
		t.Skipf("this file system does not hold the name: %v", err)
	}
}

func TestHostileNameInEveryPlaceIsFoundAndShownOnlyWithEscapes(t *testing.T) {
	places := []struct {
		label string
		dir   func(r *rec) string
	}{
		{"history", func(*rec) string { return "history" }},
		{"trust", func(*rec) string { return "trust" }},
		{"ceremony folder", func(r *rec) string { return "history/" + r.folder }},
	}
	for _, pl := range places {
		for _, h := range hostileNames() {
			for _, folder := range []bool{false, true} {
				kind := "file"
				if folder {
					kind = "folder"
				}
				t.Run(pl.label+"/"+h.label+"/"+kind, func(t *testing.T) {
					if folder && h.class == "valid" {
						t.Skip("a folder with a valid name is a ceremony folder or a trust set")
					}
					b := newBundle(t)
					r := b.apply(noSet)
					dir := pl.dir(r)
					b.mkdir(dir)
					entry(t, b, dir, h.name, folder)
					rep := b.run()
					wantFindings(t, rep, []wf{{wantClass(h), dir + "/" + escaped(h.name)}})
					if rep.Records != 1 {
						t.Errorf("Records = %d, want 1: a folder with that name must not be entered", rep.Records)
					}
					// An invalid name fails the run, and a notice does not.
					if want := h.class == "invalid"; rep.Clean() == want {
						t.Errorf("Clean() = %v for a %s name", rep.Clean(), h.class)
					}
					for _, f := range rep.Findings {
						if h.class != "valid" && strings.ContainsAny(f.Line(), "\x1b\n\r\t\x00") {
							t.Errorf("a raw byte in %q", f.Line())
						}
					}
				})
			}
		}
	}
}

// What a real file system cannot hold: a name of 256 bytes and more.
func TestNamesOfMoreThan255BytesAreInvalid(t *testing.T) {
	for _, n := range []int{256, 300, 4096} {
		for _, place := range []string{"history", "trust", "ceremony"} {
			t.Run(fmt.Sprintf("%d bytes in %s", n, place), func(t *testing.T) {
				b := newBundle(t)
				r := b.apply(noSet)
				m := loadMem(t, b.dir)
				dir := map[string]string{"history": "history", "trust": "trust", "ceremony": "history/" + r.folder}[place]
				name := strings.Repeat("a", n)
				m.file(dir+"/"+name, "x")
				rep, err := runMem(t, m)
				if err != nil {
					t.Fatal(err)
				}
				wantFindings(t, rep, []wf{{UnexpectedName, dir + "/" + name}})
				if rep.Clean() {
					t.Error("clean")
				}
			})
		}
	}
	// 255 bytes is the longest name that is valid.
	b := newBundle(t)
	r := b.apply(noSet)
	m := loadMem(t, b.dir)
	m.file("history/"+r.folder+"/"+strings.Repeat("a", 255), "x")
	rep, err := runMem(t, m)
	if err != nil {
		t.Fatal(err)
	}
	wantFindings(t, rep, []wf{{UnexpectedFile, "history/" + r.folder + "/" + strings.Repeat("a", 255)}})
}

// The same names as the disk test, from a model that does not care what a disk holds, with a name
// that is a link, a FIFO or a folder: the type does not change what the name is.
func TestHostileNameOfAnyTypeIsJudgedByItsName(t *testing.T) {
	for _, h := range hostileNames() {
		for _, kind := range []string{"file", "link", "fifo", "dir"} {
			t.Run(h.label+"/"+kind, func(t *testing.T) {
				b := newBundle(t)
				r := b.apply(noSet)
				m := loadMem(t, b.dir)
				dir := "history/" + r.folder
				switch kind {
				case "dir":
					m.put(dir+"/"+h.name, &mnode{kind: "dir", kids: map[string]*mnode{"record.json": {kind: "file", data: []byte("x")}}})
				default:
					m.put(dir+"/"+h.name, &mnode{kind: kind, data: []byte("x")})
				}
				rep, err := runMem(t, m)
				if err != nil {
					t.Fatal(err)
				}
				// A name that is valid is expected in a few cases; the rest gives its class.
				if h.class != "valid" {
					wantFindings(t, rep, []wf{{wantClass(h), dir + "/" + escaped(h.name)}})
				} else {
					checkForm(t, rep)
				}
				if rep.Records != 1 {
					t.Errorf("Records = %d, want 1", rep.Records)
				}
			})
		}
	}
}

// A temporary folder holds whole files under ordinary names: it is never read as a record.
func TestTemporaryFolderIsNeverReadAsARecord(t *testing.T) {
	for _, name := range []string{".rt-abcdefghijk", ".RT-ABCDEFGHIJK", ".Rt-x"} {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			b.apply()
			// A whole ceremony folder under a temporary name, copied from a real one.
			b.mkdir("history/" + name)
			b.put("history/"+name+"/record.json", b.get("history/"+b.recs[0].folder+"/record.json"))
			b.put("history/"+name+"/transcript.txt", []byte("x"))
			// A trust set under a temporary name, with a root list that would be an anchor fault.
			b.mkdir("trust/" + name)
			b.put("trust/"+name+"/root-list.json", []byte("garbage"))
			rep, log := b.runSpied()
			wantFindings(t, rep, []wf{{UnexpectedFile, "history/" + name}, {UnexpectedFile, "trust/" + name}})
			if rep.Records != 1 {
				t.Errorf("Records = %d, want 1", rep.Records)
			}
			if !rep.Clean() {
				t.Error("a leftover temporary name is a notice and the history is clean")
			}
			for p := range log.reads {
				if strings.Contains(strings.ToLower(p), ".rt-") {
					t.Errorf("the check read %s", p)
				}
			}
			for p := range log.lists {
				if strings.Contains(strings.ToLower(p), ".rt-") {
					t.Errorf("the check listed %s", p)
				}
			}
		})
	}
}

// A record of the folder lists a path with a temporary name in it: the page does not allow it.
func TestListedPathThatMeetsATemporaryNameIsInvalid(t *testing.T) {
	b := newBundle(t)
	r := b.apply(noSet, func(r *rec) {
		r.artifacts[".rt-x/a.txt"] = []byte("x")
		r.refresh()
	})
	rep := b.run()
	has(t, rep, RecordInvalid, recordPath(r))
}

// The spelling of the page for what a record may list. Each way to leave the bundle or to name
// what is not a name gives record-invalid, and the path is never read.
func TestListedPathsThatAreNotPlainPathsMakeTheRecordInvalid(t *testing.T) {
	bad := map[string]string{
		"dot dot":                 "../x",
		"absolute":                "/etc/hosts",
		"dot dot in the middle":   "a/../../x",
		"backslash":               "a" + ch(0x5c) + "b",
		"backslash as a root":     ch(0x5c) + "x",
		"empty":                   "",
		"an empty element":        "a//b",
		"a trailing slash":        "a/",
		"a dot element":           "./a",
		"a temporary folder":      "a/.rt-x/b",
		"a temporary name":        ".RT-abcdefghijk",
		"a device name":           "aux",
		"a device name with ext":  "con.txt",
		"a trailing dot":          "x.",
		"a space":                 "a b",
		"a control byte":          "a\x01b",
		"an escape sequence":      "a\x1b[31m",
		"not UTF-8":               "a\xffb",
		"Cyrillic look-alike":     ch(0x430),
		"a name of 256 bytes":     strings.Repeat("a", 256),
		"a path of 4097 bytes":    strings.Repeat(strings.Repeat("a", 100)+"/", 41) + "a",
		"a drive":                 "C:x",
		"two slashes then a host": "//host/share",
	}
	for name, p := range bad {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			// The path is put into the bytes of the record after they are written, so that a path that
			// the writer refuses (bytes that are not UTF-8) is in the file too.
			quoted := []byte(`"` + p + `"`)
			if utf8.ValidString(p) {
				quoted = must(json.Marshal(p))
			}
			r := b.apply(noSet, func(r *rec) {
				r.record.Artifacts = []files.FileRef{{Path: "placeholder", SHA256: digestA}}
				r.recordBytes = func(c []byte) []byte {
					return bytes.Replace(c, []byte(`"placeholder"`), quoted, 1)
				}
			})
			rep, log := b.runSpied()
			has(t, rep, RecordInvalid, recordPath(r))
			if rep.Clean() {
				t.Error("clean")
			}
			for read := range log.reads {
				if !strings.HasSuffix(read, "record.json") {
					t.Errorf("the check read %q", read)
				}
			}
			checkForm(t, rep)
		})
	}
	if len(strings.Repeat(strings.Repeat("a", 100)+"/", 41)+"a") <= 4096 {
		t.Fatal("the long path is not longer than 4096 bytes")
	}
}

// Where a file is expected, something else is: a link, a FIFO, a folder, a file over 8 MiB.
func TestAnythingButAFileWhereAListedFileIsExpected(t *testing.T) {
	substitutes := map[string]func(b *bundle, rel string){
		"a link to a file of the bundle": func(b *bundle, rel string) { b.remove(rel); b.symlink("ritueel.yaml", rel) },
		"a link to a file outside": func(b *bundle, rel string) {
			outside := b.t.TempDir() + "/outside"
			if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
				b.t.Fatal(err)
			}
			b.remove(rel)
			b.symlink(outside, rel)
		},
		"a link that leads nowhere":  func(b *bundle, rel string) { b.remove(rel); b.symlink("no/such/file", rel) },
		"a link to itself":           func(b *bundle, rel string) { b.remove(rel); b.symlink(baseOf(rel), rel) },
		"a FIFO":                     func(b *bundle, rel string) { b.remove(rel); b.fifo(rel) },
		"a folder":                   func(b *bundle, rel string) { b.remove(rel); b.mkdir(rel) },
		"a folder with a file in it": func(b *bundle, rel string) { b.remove(rel); b.put(rel+"/x", []byte("x")) },
		"a file of 8 MiB and a byte": func(b *bundle, rel string) { b.remove(rel); b.sparse(rel, 8<<20+1) },
	}
	targets := []struct {
		label string
		path  func(r *rec) string
		code  Code
	}{
		{"the transcript", func(r *rec) string { return "history/" + r.folder + "/transcript.txt" }, FileDigest},
		{"the plan", func(r *rec) string { return "history/" + r.folder + "/plan.json" }, FileDigest},
		{"a wanted copy", func(r *rec) string { return "history/" + r.folder + "/wanted/ritueel.yaml" }, FileDigest},
		{"an artifact", func(r *rec) string { return "trust/" + r.set + "/keys.txt" }, FileDigest},
		{"the record", func(r *rec) string { return "history/" + r.folder + "/record.json" }, RecordInvalid},
	}
	for sub, do := range substitutes {
		for _, tg := range targets {
			t.Run(tg.label+" as "+sub, func(t *testing.T) {
				b := newBundle(t)
				r := b.apply()
				p := tg.path(r)
				do(b, p)
				rep := b.run()
				// A name that the folder expects, in another type, may also be a notice: the page says nothing.
				// A file below a listed folder that replaced a file is not listed by any record.
				ignore := []Code{UnexpectedFile, FileUnlisted}
				if tg.code == RecordInvalid {
					// A record that cannot be read is the open point about record-off-chain, and it lists nothing,
					// so its set is unlisted too.
					ignore = append(ignore, RecordOffChain, TrustSetUnlisted)
				}
				has(t, rep, tg.code, p)
				for _, f := range rep.Findings {
					expected := (f.Code == tg.code && f.Path == p) || (tg.code == RecordInvalid && f.Path == "trust/"+r.set+"/root-list.json")
					if !slicesContains(ignore, f.Code) && !expected {
						t.Errorf("another finding: %s", f.Line())
					}
				}
				if rep.Clean() {
					t.Error("clean")
				}
				checkForm(t, rep)
			})
		}
	}
}

func slicesContains(l []Code, c Code) bool {
	for _, x := range l {
		if x == c {
			return true
		}
	}
	return false
}

func baseOf(rel string) string { return rel[strings.LastIndexByte(rel, '/')+1:] }

// 8 MiB is the longest file that is read: a listed file of that size, with its digest, is whole.
func TestListedFileOfExactly8MiBIsRead(t *testing.T) {
	b := newBundle(t)
	zeros := make([]byte, 8<<20)
	b.apply(noSet, func(r *rec) {
		r.artifacts["big.bin"] = zeros
		r.refresh()
	})
	wantFindings(t, b.run(), nil)
	b.sparse("big.bin", 8<<20+1)
	has(t, b.run(), FileDigest, "big.bin")
}

func TestRecordOver8MiBIsInvalidAndOver256KiBToo(t *testing.T) {
	for name, size := range map[string]int64{"8 MiB and a byte": 8<<20 + 1, "256 KiB and a byte": 256<<10 + 1, "a gigabyte": 1 << 30} {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(noSet)
			b.sparse("history/"+r.folder+"/record.json", size)
			rep := b.run()
			has(t, rep, RecordInvalid, recordPath(r))
			if rep.Records != 1 {
				t.Errorf("Records = %d, want 1", rep.Records)
			}
		})
	}
}

// Where a folder is expected, something else is. The findings for each kind are held in
// odd_entry_test.go; these tests hold what is true of every kind: the run ends in time, nothing is
// read below the odd entry, and a file outside the bundle that the odd entry points at is not used.
func TestAnythingButAFolderWhereAFolderIsExpected(t *testing.T) {
	places := map[string]func(r *rec) string{
		"history":         func(*rec) string { return "history" },
		"trust":           func(*rec) string { return "trust" },
		"a ceremony":      func(r *rec) string { return "history/" + r.folder },
		"a trust set":     func(r *rec) string { return "trust/" + r.set },
		"the wanted copy": func(r *rec) string { return "history/" + r.folder + "/wanted" },
	}
	subs := map[string]func(b *bundle, rel string){
		"a file":                  func(b *bundle, rel string) { b.remove(rel); b.put(rel, []byte("x")) },
		"a link to a folder":      func(b *bundle, rel string) { moved(b, rel); b.symlink(movedName(rel), rel) },
		"a link to the bundle":    func(b *bundle, rel string) { b.remove(rel); b.symlink(".", rel) },
		"a link to a missing one": func(b *bundle, rel string) { b.remove(rel); b.symlink("gone", rel) },
		"a FIFO":                  func(b *bundle, rel string) { b.remove(rel); b.fifo(rel) },
	}
	for pl, path := range places {
		for sub, do := range subs {
			t.Run(pl+" as "+sub, func(t *testing.T) {
				b, r := threeRecords(t)
				p := path(r[1])
				do(b, p)
				rep, log := b.runSpiedAllowingErrors()
				if rep != nil {
					checkForm(t, rep)
				}
				for read := range log.reads {
					if strings.HasPrefix(read, p+"/") {
						t.Errorf("the check read %q, below the entry %s that is not a folder", read, p)
					}
				}
				for read := range log.lists {
					if strings.HasPrefix(read, p+"/") {
						t.Errorf("the check listed %q", read)
					}
				}
			})
		}
	}
}

// moved renames a folder to a name that a test can link to.
func moved(b *bundle, rel string) {
	b.t.Helper()
	if err := os.Rename(b.abs(rel), b.abs(movedName(rel))); err != nil {
		b.t.Fatal(err)
	}
}

func movedName(rel string) string { return rel + "-moved" }

// runSpiedAllowingErrors checks the bundle through a spy and keeps a refusal to check as a result.
func (b *bundle) runSpiedAllowingErrors() (*Report, *spyLog) {
	b.t.Helper()
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		b.t.Fatalf("OpenFS: %v", err)
	}
	defer func() { _ = root.Close() }()
	spy, log := newSpy(root)
	rep, err := runFS(b.t, spy, nil)
	if err != nil {
		if !printable(err.Error()) {
			b.t.Errorf("the text of the error is not printable ASCII: %q", err)
		}
		return nil, log
	}
	return rep, log
}

// Names that differ only in a byte that is not UTF-8, in the character U+FFFD, or in a backslash
// followed by the text of an escape, give four different lines.
func TestFoldersThatDifferOnlyInBytesThatAreNotUTF8ShowAsDifferentLines(t *testing.T) {
	b := newBundle(t)
	b.apply(noSet)
	names := []string{"a\xffb", "a\xfeb", "a" + string(rune(0xfffd)) + "b", "a" + bs + "xffb", "a\xc3", "a\xc3\xc3"}
	for _, n := range names {
		entry(t, b, "history", n, false)
	}
	rep := b.run()
	seen := map[string]string{}
	count := 0
	for _, f := range rep.Findings {
		if f.Code != UnexpectedName {
			continue
		}
		count++
		if prev, ok := seen[f.Path]; ok {
			t.Errorf("two names give the line %q (%q)", f.Line(), prev)
		}
		seen[f.Path] = f.Line()
	}
	if count != len(names) {
		t.Errorf("%d findings for %d names: %v", count, len(names), findingsOf(rep))
	}
}

const bs = string(rune(0x5c))
