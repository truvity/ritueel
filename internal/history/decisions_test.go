//go:build linux || darwin

package history

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
)

// What was decided for this check on 2026-11-14, one test group for each decision, named after what it decides.

// A name that is valid but that the check does not expect, and a leftover temporary name, are a
// notice: exit code 0, the code in warnings. A name that breaks the rule for names fails.

func TestValidNameThatTheCheckDoesNotExpectIsANotice(t *testing.T) {
	for _, place := range []string{"in history", "in trust", "in a ceremony folder"} {
		t.Run(place, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply()
			dir := map[string]string{"in history": "history", "in trust": "trust", "in a ceremony folder": "history/" + r.folder}[place]
			b.put(dir+"/notes.txt", []byte("x"))
			rep := b.run()
			wantFindings(t, rep, []wf{{UnexpectedFile, dir + "/notes.txt"}})
			wantReasons(t, rep, nil, []Code{UnexpectedFile})
			if !rep.Clean() {
				t.Error("a notice makes the history unclean")
			}
			if want := "history: 1 ceremony records, end " + r.digest[:8]; rep.EndLine() != want {
				t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
			}
		})
	}
}

func TestLeftoverTemporaryNameIsANoticeInEveryPlace(t *testing.T) {
	for _, name := range []string{".rt-abcdefghijk", ".RT-ABCDEFGHIJK"} {
		for _, place := range []string{"history", "trust", "ceremony"} {
			t.Run(place+" "+name, func(t *testing.T) {
				b := newBundle(t)
				r := b.apply()
				dir := map[string]string{"history": "history", "trust": "trust", "ceremony": "history/" + r.folder}[place]
				b.put(dir+"/"+name, []byte("x"))
				rep := b.run()
				wantFindings(t, rep, []wf{{UnexpectedFile, dir + "/" + name}})
				wantReasons(t, rep, nil, []Code{UnexpectedFile})
				if !rep.Clean() {
					t.Error("a notice makes the history unclean")
				}
			})
		}
	}
}

func TestNameThatBreaksTheRuleForNamesFailsInEveryPlace(t *testing.T) {
	for _, place := range []string{"history", "trust", "ceremony"} {
		t.Run(place, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply()
			dir := map[string]string{"history": "history", "trust": "trust", "ceremony": "history/" + r.folder}[place]
			b.put(dir+"/a b", []byte("x"))
			rep := b.run()
			wantFindings(t, rep, []wf{{UnexpectedName, dir + "/a" + bs + "x20b"}})
			wantReasons(t, rep, []Code{UnexpectedName}, nil)
			if rep.Clean() {
				t.Error("clean")
			}
		})
	}
}

func TestNamesThatThePageListsAreNotNoticed(t *testing.T) {
	b := newBundle(t)
	r := b.apply()
	base := "history/" + r.folder + "/"
	b.put(base+"births.jsonl", []byte("{}\n"))
	b.put(base+"signatures.jsonl", []byte("{}\n"))
	b.mkdir(base + "wanted/cards")
	wantFindings(t, b.run(), nil)
}

// A record that lacks a member that check history reads is record-invalid; a record that lacks
// the others passes (the page: "a record that lacks another member of the table passes this check").

func TestRecordWithoutARequiredMemberIsInvalid(t *testing.T) {
	cases := map[string]struct {
		build func(b *bundle) *rec
		drop  string
	}{
		"version":           {func(b *bundle) *rec { return b.apply(noSet) }, `"version":1`},
		"ceremony":          {func(b *bundle) *rec { return b.apply(noSet) }, `"ceremony":"`},
		"command":           {func(b *bundle) *rec { return b.apply(noSet) }, `"command":"apply"`},
		"outcome":           {func(b *bundle) *rec { return b.apply(noSet) }, `"outcome":"completed"`},
		"transcript_sha256": {func(b *bundle) *rec { return b.apply(noSet) }, `"transcript_sha256":"`},
		"artifacts":         {func(b *bundle) *rec { return b.apply(noSet) }, `"artifacts":[]`},
		"wanted of apply":   {func(b *bundle) *rec { return b.apply(noSet) }, `"wanted":[`},
		"closes of close": {func(b *bundle) *rec {
			return b.closing(b.unfinished(), noSet)
		}, `"closes":{`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			r := c.build(b)
			rewrite(b, r, func(rec []byte) []byte { return dropMember(t, rec, c.drop) })
			rep := b.run()
			has(t, rep, RecordInvalid, recordPath(r))
			lacks(t, rep, RecordVersionUnknown)
		})
	}
}

// dropMember removes the member of canonical JSON that begins with the given text, with its comma.
func dropMember(t *testing.T, doc []byte, start string) []byte {
	t.Helper()
	i := bytes.Index(doc, []byte(start))
	if i < 0 {
		t.Fatalf("%s is not in %s", start, doc)
	}
	depth, j, inString := 0, i, false
	for ; j < len(doc); j++ {
		c := doc[j]
		switch {
		case inString:
			switch c {
			case '\\':
				j++
			case '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			depth++
		case c == '}' || c == ']':
			if depth == 0 {
				goto done
			}
			depth--
		case c == ',' && depth == 0:
			goto done
		}
	}
done:
	out := append([]byte{}, doc[:i]...)
	if j < len(doc) && doc[j] == ',' {
		return append(out, doc[j+1:]...)
	}
	return append(bytes.TrimSuffix(out, []byte(",")), doc[j:]...)
}

func TestRecordWithOnlyTheMembersThatCheckHistoryReadsPasses(t *testing.T) {
	b := newBundle(t)
	b.apply(noSet, func(r *rec) {
		// Nothing but what the page's table asks for, and the members the reader needs besides.
		r.record.TrustSequence = 0
		r.record.PrevRecordSHA256 = ""
	})
	b.apply(noSet, func(r *rec) {
		r.record.TrustSequence = 0
	})
	rep := b.run()
	wantFindings(t, rep, nil)
	if !bytes.Contains(b.get("history/"+b.recs[0].folder+"/record.json"), []byte(`"version":1`)) {
		t.Fatal("the record is not what the test thinks")
	}
}

// A folder with no history folder is a bundle only with a ritueel.yaml.

func TestFolderWithNoHistoryIsABundleOnlyIfItHasAManifest(t *testing.T) {
	t.Run("no history and no manifest", func(t *testing.T) {
		dir := t.TempDir()
		rep, err := runDirErr(t, dir)
		if !errors.Is(err, ErrNotBundle) {
			t.Fatalf("err = %v, want ErrNotBundle", err)
		}
		if rep != nil {
			t.Errorf("a report comes with the error: %+v", rep)
		}
		if !strings.Contains(err.Error(), "not a bundle") || !printable(err.Error()) {
			t.Errorf("the text %q does not say that the folder is not a bundle, or is not printable ASCII", err)
		}
	})
	t.Run("no history and a manifest", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/ritueel.yaml", []byte("name: x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rep := runDir(t, dir)
		wantFindings(t, rep, nil)
		if rep.Records != 0 || rep.EndLine() != "history: 0 ceremony records" {
			t.Errorf("Records = %d, EndLine() = %q", rep.Records, rep.EndLine())
		}
	})
	t.Run("an empty history and no manifest", func(t *testing.T) {
		// A stick's copy of a bundle has the history and no wanted files.
		dir := t.TempDir()
		if err := os.Mkdir(dir+"/history", 0o755); err != nil {
			t.Fatal(err)
		}
		rep := runDir(t, dir)
		wantFindings(t, rep, nil)
		if rep.EndLine() != "history: 0 ceremony records" {
			t.Errorf("EndLine() = %q", rep.EndLine())
		}
	})
	t.Run("a history with records and no manifest", func(t *testing.T) {
		b, _ := threeRecords(t)
		b.remove("ritueel.yaml")
		rep := b.run()
		wantFindings(t, rep, nil)
		if rep.Records != 3 {
			t.Errorf("Records = %d, want 3", rep.Records)
		}
	})
	t.Run("a trust folder is not a history", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(dir+"/trust", 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := runDirErr(t, dir); !errors.Is(err, ErrNotBundle) {
			t.Errorf("err = %v, want ErrNotBundle", err)
		}
	})
}

// A listed file that is there and is not the file is file-digest; for the record it is record-invalid.
// A read that fails for another reason than "does not exist" is not a finding: the check is not done.

func TestListedFileThatCannotBeReadForAnotherReasonThanAbsenceStopsTheCheck(t *testing.T) {
	for name, cause := range map[string]error{
		"a refused permission": fs.ErrPermission,
		"an input error":       syscall.EIO,
		"too many open files":  syscall.EMFILE,
	} {
		for _, target := range []string{"history/%s/transcript.txt", "history/%s/plan.json", "history/%s/wanted/ritueel.yaml", "history/%s/record.json", "trust/%s/keys.txt", "trust/%s/root-list.json"} {
			t.Run(name+" "+target, func(t *testing.T) {
				b := newBundle(t)
				r := b.apply()
				m := loadMem(t, b.dir)
				p := strings.ReplaceAll(target, "%s", r.folder)
				if strings.HasPrefix(target, "trust") {
					p = strings.ReplaceAll(target, "%s", r.set)
				}
				m.get(p).readErr = cause
				rep, err := runMem(t, m)
				if err == nil {
					t.Fatalf("a report %v for a file that cannot be read", rep.Findings)
				}
				if rep != nil {
					t.Error("a report comes with the error")
				}
				if !errors.Is(err, cause) {
					t.Errorf("err = %v, want one that wraps %v", err, cause)
				}
				if errors.Is(err, ErrNotBundle) || errors.Is(err, ErrTooMuch) {
					t.Errorf("the error is a refusal of another kind: %v", err)
				}
			})
		}
	}
}

func TestFolderThatCannotBeListedStopsTheCheck(t *testing.T) {
	for _, dir := range []string{"history", "trust"} {
		t.Run(dir, func(t *testing.T) {
			b, _ := threeRecords(t)
			m := loadMem(t, b.dir)
			m.get(dir).readErr = fs.ErrPermission
			rep, err := runMem(t, m)
			if err == nil {
				t.Fatalf("a report %v for a folder that cannot be listed", rep.Findings)
			}
			if !errors.Is(err, fs.ErrPermission) {
				t.Errorf("err = %v, want one that wraps fs.ErrPermission", err)
			}
		})
	}
}

func TestPermissionRefusedOnTheDiskStopsTheCheck(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a process of the superuser reads a file that is refused to others")
	}
	b, r := threeRecords(t)
	p := b.abs("trust/" + r[0].set + "/keys.txt")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	rep, err := runDirErr(t, b.dir)
	if err == nil {
		t.Fatalf("a report %v for a file that is refused", rep.Findings)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("err = %v, want one that wraps fs.ErrPermission", err)
	}
}

// Only "does not exist" is file-missing.
func TestOnlyAbsenceIsFileMissing(t *testing.T) {
	b := newBundle(t)
	r := b.apply()
	m := loadMem(t, b.dir)
	m.remove("trust/" + r.set + "/keys.txt")
	rep, err := runMem(t, m)
	if err != nil {
		t.Fatal(err)
	}
	wantFindings(t, rep, []wf{{FileMissing, "trust/" + r.set + "/keys.txt"}})
}

// A listed file that is there and is not a regular file: a folder, a link, a FIFO, a file that is too long.
func TestListedFileThatIsThereAndIsNotTheFileIsFileDigestAndNeverMissing(t *testing.T) {
	for _, kind := range []string{"dir", "link", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply()
			m := loadMem(t, b.dir)
			m.put("trust/"+r.set+"/keys.txt", &mnode{kind: kind, kids: map[string]*mnode{}})
			rep, err := runMem(t, m)
			if err != nil {
				t.Fatal(err)
			}
			wantFindings(t, rep, []wf{{FileDigest, "trust/" + r.set + "/keys.txt"}})
		})
	}
	t.Run("too long", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply()
		m := loadMem(t, b.dir)
		m.put("trust/"+r.set+"/keys.txt", &mnode{kind: "file", long: true})
		rep, err := runMem(t, m)
		if err != nil {
			t.Fatal(err)
		}
		wantFindings(t, rep, []wf{{FileDigest, "trust/" + r.set + "/keys.txt"}})
	})
}
