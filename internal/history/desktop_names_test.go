//go:build linux || darwin

package history

import (
	"fmt"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// The four names that a desktop system writes beside the files of a folder are .DS_Store, Thumbs.db,
// desktop.ini and a name that starts with "._". Inside a trust set that a record lists, an entry with
// one of these names that no record lists is the finding file-unlisted, like every other entry: a
// reader of a trust set may read the whole folder, and nobody has checked the bytes of such a file.
// This holds for a regular file as much as for a link, a FIFO, a socket or a folder. Outside a trust
// set (history/, trust/ itself, a ceremony folder, wanted/) such a name is a name like any other and
// the notice unexpected-file stays.

var desktopNames = []string{".DS_Store", "Thumbs.db", "desktop.ini", "._x", "._keys.gpg", "._"}

// The places inside a trust set that the walk enters: the top, a folder, and a folder three deep.
var placesInASet = []string{"", "keyring/", "a/b/c/"}

// wantUnlisted checks a run that holds exactly the finding file-unlisted for each path, fails, shows
// the end of the untouched history, and holds no notice.
func wantUnlisted(t *testing.T, rep *Report, end string, paths ...string) {
	t.Helper()
	want := make([]wf, len(paths))
	for i, p := range paths {
		want[i] = wf{FileUnlisted, p}
	}
	wantFindings(t, rep, want)
	wantReasons(t, rep, []Code{FileUnlisted}, nil)
	wantNotCleanEndUnchanged(t, rep, end)
	for _, f := range rep.Findings {
		if !strings.HasPrefix(f.Line(), "file-unlisted "+f.Path+": ") {
			t.Errorf("the line is %q", f.Line())
		}
	}
}

func TestDesktopFileInATrustSetThatNoRecordListsIsFileUnlisted(t *testing.T) {
	for _, name := range desktopNames {
		for _, where := range placesInASet {
			for i := 0; i < 3; i++ {
				t.Run(fmt.Sprintf("%s%s in set %d", where, name, i+1), func(t *testing.T) {
					b, r := threeRecords(t)
					p := "trust/" + r[i].set + "/" + where + name
					b.put(p, []byte("x"))
					wantUnlisted(t, b.run(), r[2].digest[:8], p)
				})
			}
		}
	}
}

// What the file holds does not matter, and the file is never read: nobody has checked its bytes, and
// the check does not start now.
func TestDesktopFileInATrustSetIsFileUnlistedWhateverItHoldsAndIsNotRead(t *testing.T) {
	for name, size := range map[string]int64{"empty": 0, "one byte": 1, "just over the limit of a read": 8<<20 + 1, "a hundred MiB": 100 << 20} {
		t.Run(name, func(t *testing.T) {
			b, r := threeRecords(t)
			p := "trust/" + r[2].set + "/" + ".DS_Store"
			b.sparse(p, size)
			rep, log := b.runSpied()
			wantUnlisted(t, rep, r[2].digest[:8], p)
			if log.reads[p] != 0 {
				t.Errorf("the check read %s", p)
			}
		})
	}
}

// The text of a desktop file may say anything; the line of the finding does not show it.
func TestDesktopFileInATrustSetShowsNoByteOfItsContent(t *testing.T) {
	b, r := threeRecords(t)
	p := "trust/" + r[1].set + "/._evil.gpg"
	b.put(p, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\nEVIL\x1b[2J"))
	rep := b.run()
	wantUnlisted(t, rep, r[2].digest[:8], p)
	for _, f := range rep.Findings {
		if strings.Contains(f.Line(), "EVIL") || strings.Contains(f.Line(), "PGP") {
			t.Errorf("the line shows the content: %q", f.Line())
		}
	}
}

// There is no exception by name: a name that only looks like a desktop name, one in another case, and
// a name that has nothing to do with a desktop are the same finding.
func TestNoNameInATrustSetIsAnExceptionToFileUnlisted(t *testing.T) {
	names := []string{
		".ds_store", ".DS_STORE", "THUMBS.DB", "thumbs.db", "Desktop.ini", "DESKTOP.INI",
		"_DS_Store", ".DS_Store2", ".DS_Store.bak", "Thumbs.db.bak", "xThumbs.db", "desktop.ini2", ".DS-Store",
		"._._", ".-x", "notes.txt", "x",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			b, r := threeRecords(t)
			p := "trust/" + r[1].set + "/" + name
			b.put(p, []byte("x"))
			wantUnlisted(t, b.run(), r[2].digest[:8], p)
		})
	}
}

// A name that starts like a desktop name and breaks the rule for names is unexpected-name, and one
// that starts with the prefix of a temporary name is file-unlisted: the order of the checks of a
// name has not changed.
func TestDesktopLikeNameThatBreaksAnotherRuleKeepsItsOwnCode(t *testing.T) {
	b, r := threeRecords(t)
	set := "trust/" + r[2].set + "/"
	b.put(set+"._a b", []byte("x"))
	b.put(set+"Thumbs.db.", []byte("x"))
	b.put(set+"._.", []byte("x"))
	b.put(set+"._.rt-x", []byte("x"))
	b.put(set+".rt-.DS_Store", []byte("x"))
	rep := b.run()
	wantFindings(t, rep, []wf{
		{UnexpectedName, set + "._a" + bs + "x20b"},
		{UnexpectedName, set + "Thumbs.db."},
		{UnexpectedName, set + "._."},
		{FileUnlisted, set + "._.rt-x"},
		{FileUnlisted, set + ".rt-.DS_Store"},
	})
	wantReasons(t, rep, []Code{FileUnlisted, UnexpectedName}, nil)
}

// The same name, listed by a record, is a file like any other: no finding, and the digest is checked.
func TestDesktopFileThatARecordListsIsNotUnlisted(t *testing.T) {
	for _, name := range desktopNames {
		for _, where := range placesInASet {
			t.Run(where+name, func(t *testing.T) {
				var listed string
				b := newBundle(t)
				b.apply()
				second := b.apply(func(r *rec) {
					listed = "trust/" + r.set + "/" + where + name
					r.artifacts[listed] = []byte("bytes that a record lists")
					r.refresh()
				})
				rep := b.run()
				wantFindings(t, rep, nil)
				wantReasons(t, rep, nil, nil)
				if !rep.Clean() {
					t.Error("not clean")
				}
				if eight, _, ok := rep.End(); !ok || eight != second.digest[:8] {
					t.Errorf("End() = %q, %v", eight, ok)
				}
				// A changed file is file-digest, once, and not file-unlisted as well.
				b.put(listed, []byte("other bytes"))
				wantFindings(t, b.run(), []wf{{FileDigest, listed}})
				// A removed one is file-missing.
				b.remove(listed)
				wantFindings(t, b.run(), []wf{{FileMissing, listed}})
			})
		}
	}
}

// The record of one trust set does not list the file of another: the path is the whole name.
func TestDesktopFileListedForOneSetIsStillUnlistedInAnother(t *testing.T) {
	b := newBundle(t)
	b.apply(func(r *rec) {
		r.artifacts["trust/"+r.set+"/.DS_Store"] = []byte("listed")
		r.refresh()
	})
	second := b.apply()
	other := "trust/" + second.set + "/.DS_Store"
	b.put(other, []byte("listed"))
	rep := b.run()
	wantFindings(t, rep, []wf{{FileUnlisted, other}})
	wantNotCleanEndUnchanged(t, rep, second.digest[:8])
}

// Outside a trust set a desktop name is a name like any other: the notice, and the history stays clean.
func TestDesktopNameOutsideATrustSetIsANotice(t *testing.T) {
	for _, name := range desktopNames {
		for _, kind := range []string{"history", "trust", "ceremony folder", "wanted", "folder in wanted"} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				b, r := threeRecords(t)
				dir := map[string]string{
					"history":          "history",
					"trust":            "trust",
					"ceremony folder":  "history/" + r[1].folder,
					"wanted":           "history/" + r[1].folder + "/wanted",
					"folder in wanted": "history/" + r[1].folder + "/wanted/sub",
				}[kind]
				p := dir + "/" + name
				b.put(p, []byte("x"))
				rep := b.run()
				wantFindings(t, rep, []wf{{UnexpectedFile, p}})
				wantReasons(t, rep, nil, []Code{UnexpectedFile})
				if !rep.Clean() {
					t.Error("a notice makes the history unclean")
				}
				if eight, count, ok := rep.End(); !ok || count != 3 || eight != r[2].digest[:8] {
					t.Errorf("End() = %q, %d, %v", eight, count, ok)
				}
			})
		}
	}
}

// The wanted/ folder of a ceremony and a trust set side by side: the same name, two answers.
func TestSameDesktopNameInASetAndInTheCopiesGivesTwoAnswers(t *testing.T) {
	b, r := threeRecords(t)
	inSet := "trust/" + r[1].set + "/.DS_Store"
	inCopies := "history/" + r[1].folder + "/wanted/.DS_Store"
	b.put(inSet, []byte("x"))
	b.put(inCopies, []byte("x"))
	rep := b.run()
	wantFindings(t, rep, []wf{{FileUnlisted, inSet}, {UnexpectedFile, inCopies}})
	wantReasons(t, rep, []Code{FileUnlisted}, []Code{UnexpectedFile})
	wantNotCleanEndUnchanged(t, rep, r[2].digest[:8])
}

// A trust set that no record lists is not walked, so a desktop file in it says nothing more.
func TestDesktopFileInATrustSetThatNoRecordListsIsNotLookedAt(t *testing.T) {
	t.Run("no open attempt", func(t *testing.T) {
		b, _ := threeRecords(t)
		b.put("trust/9-3fa9c1d2/.DS_Store", []byte("x"))
		b.put("trust/9-3fa9c1d2/keyring/._x", []byte("x"))
		rep, log := b.runSpied()
		wantFindings(t, rep, []wf{{TrustSetUnlisted, "trust/9-3fa9c1d2"}})
		for p := range log.lists {
			if strings.HasPrefix(p, "trust/9-3fa9c1d2") {
				t.Errorf("the check listed %s", p)
			}
		}
	})
	t.Run("an open attempt", func(t *testing.T) {
		b, _ := threeRecords(t)
		u := b.unfinished()
		b.put("trust/"+u.set+"/.DS_Store", []byte("x"))
		b.put("trust/"+u.set+"/keyring/Thumbs.db", []byte("x"))
		rep, log := b.runSpied()
		wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(u)}})
		wantReasons(t, rep, nil, []Code{UnfinishedCeremony})
		for p := range log.lists {
			if strings.HasPrefix(p, "trust/"+u.set) {
				t.Errorf("the check listed %s", p)
			}
		}
	})
}

// A desktop name is no excuse for something that is not a regular file: a link (that leads out of the
// bundle), a FIFO, a socket and a folder are file-unlisted, as every entry of a set that no record
// lists.
func makeDesktopKind(t *testing.T, b *bundle, kind, rel string) {
	t.Helper()
	b.remove(rel)
	b.mkdir(dirOf(rel))
	switch kind {
	case "link":
		b.symlink("../../../want/evil.gpg", rel)
	case "FIFO":
		b.fifo(rel)
	case "socket":
		if err := syscall.Mknod(b.abs(rel), syscall.S_IFSOCK|0o600, 0); err != nil {
			t.Skipf("no socket here: %v", err)
		}
	}
}

func TestDesktopNameThatIsNotARegularFileInATrustSetIsFileUnlisted(t *testing.T) {
	for _, name := range desktopNames {
		for _, where := range []string{"", "keyring/"} {
			for _, kind := range []string{"link", "FIFO", "socket"} {
				t.Run(where+name+" as a "+kind, func(t *testing.T) {
					b, r := threeRecords(t)
					p := "trust/" + r[2].set + "/" + where + name
					makeDesktopKind(t, b, kind, p)
					rep, log := b.runSpied()
					wantUnlisted(t, rep, r[2].digest[:8], p)
					if log.reads[p] != 0 {
						t.Errorf("the check read %s", p)
					}
				})
			}
		}
	}
}

// A folder with one of the names is entered like any folder, and what is in it is not listed by any
// record.
func TestDesktopNameThatIsAFolderInATrustSetIsEnteredAndWhatIsInItIsFileUnlisted(t *testing.T) {
	for _, name := range desktopNames {
		t.Run(name, func(t *testing.T) {
			b, r := threeRecords(t)
			p := "trust/" + r[2].set + "/" + name + "/evil.pem"
			b.put(p, []byte("EVIL"))
			wantUnlisted(t, b.run(), r[2].digest[:8], p)
		})
	}
}

// An empty folder with a desktop name holds nothing that a reader could take: no finding.
func TestEmptyDesktopFolderInATrustSetIsNotAFinding(t *testing.T) {
	b, _ := threeRecords(t)
	b.mkdir("trust/" + b.recs[2].set + "/.DS_Store")
	wantFindings(t, b.run(), nil)
}

// A regular file and the entries that are not files, side by side: each gets the same answer.
func TestTrustSetWithDesktopNamesOfEveryKindIsFileUnlistedForEach(t *testing.T) {
	b, r := threeRecords(t)
	set := "trust/" + r[2].set + "/"
	b.symlink("/etc/passwd", set+"desktop.ini")
	b.symlink("../../../want/evil.gpg", set+"keyring/._link.gpg")
	b.fifo(set + "._fifo")
	b.put(set+".DS_Store", []byte("EVIL"))
	b.put(set+"keyring/._evil.gpg", []byte("EVIL"))
	b.put(set+"keyring/Thumbs.db", []byte("EVIL"))
	wantUnlisted(t, b.run(), r[2].digest[:8],
		set+"desktop.ini", set+"keyring/._link.gpg", set+"._fifo", set+".DS_Store", set+"keyring/._evil.gpg", set+"keyring/Thumbs.db")
}

// The walk is as deep as the longest path a record may list. A desktop file at the deepest level is
// found; a folder at the deepest level is the finding, and what is below it is not looked at one by one.
func TestDesktopFileIsFoundDownToTheDepthOfAListedPath(t *testing.T) {
	levels := files.MaxPathElements - 2
	chain := func(n int) string { return strings.TrimSuffix(strings.Repeat("d/", n), "/") }
	t.Run("a file at the deepest level", func(t *testing.T) {
		b, r := threeRecords(t)
		p := "trust/" + r[0].set + "/" + chain(levels-1) + "/.DS_Store"
		b.put(p, []byte("x"))
		wantUnlisted(t, b.run(), r[2].digest[:8], p)
	})
	t.Run("a folder at the deepest level is the finding and is not entered", func(t *testing.T) {
		b, r := threeRecords(t)
		folder := "trust/" + r[0].set + "/" + chain(levels)
		b.put(folder+"/.DS_Store", []byte("x"))
		b.put(folder+"/._x", []byte("x"))
		rep, log := b.runSpied()
		wantUnlisted(t, rep, r[2].digest[:8], folder)
		if log.lists[folder] != 0 {
			t.Error("the folder at the deepest level was entered")
		}
	})
}

// The number of findings of one code is bounded, and a desktop file counts like another: what is
// left out is counted, and the history fails.
func TestManyDesktopFilesInATrustSetAreBoundedLikeAnyOtherFinding(t *testing.T) {
	b, r := threeRecords(t)
	const extra = 7
	for i := 0; i < MaxFindingsPerCode+extra; i++ {
		b.put(fmt.Sprintf("trust/%s/._%04d", r[2].set, i), []byte("x"))
	}
	rep := b.run()
	if n := len(findingsOf(rep)); n != MaxFindingsPerCode {
		t.Errorf("%d findings, want %d", n, MaxFindingsPerCode)
	}
	if rep.Omitted != extra {
		t.Errorf("Omitted = %d, want %d", rep.Omitted, extra)
	}
	wantReasons(t, rep, []Code{FileUnlisted}, nil)
	wantNotCleanEndUnchanged(t, rep, r[2].digest[:8])
}

// Every kind of hostile name that is a file inside a listed trust set is a finding, whatever it is
// called: the name that breaks the rule for names is unexpected-name, the other names are
// file-unlisted (a temporary name too), and none is a notice.
func TestHostileFileNameInATrustSetIsNeverOnlyANotice(t *testing.T) {
	for _, h := range hostileNames() {
		t.Run(h.label, func(t *testing.T) {
			b, r := threeRecords(t)
			dir := "trust/" + r[2].set
			entry(t, b, dir, h.name, false)
			rep := b.run()
			code := FileUnlisted
			if h.class == "invalid" {
				code = UnexpectedName
			}
			wantFindings(t, rep, []wf{{code, dir + "/" + escaped(h.name)}})
			wantReasons(t, rep, []Code{code}, nil)
			if rep.Clean() {
				t.Error("clean")
			}
		})
	}
}

// A temporary name inside a finished trust set is not a leftover of any write: a set is written whole
// under a temporary name and renamed into place. It is file-unlisted, and the folder is not entered.
// In history/, trust/, a ceremony folder and the copies it stays the notice.
func TestTemporaryNameInsideATrustSetFailsAndElsewhereIsANotice(t *testing.T) {
	for _, name := range []string{".rt-abcdefghijk", ".RT-ABCDEFGHIJK", ".Rt-x", ".rt-"} {
		for _, where := range []string{"", "keyring/", "a/b/"} {
			t.Run("file "+where+name, func(t *testing.T) {
				b, r := threeRecords(t)
				p := "trust/" + r[2].set + "/" + where + name
				b.put(p, []byte("EVIL"))
				rep := b.run()
				wantFindings(t, rep, []wf{{FileUnlisted, p}})
				wantNotCleanEndUnchanged(t, rep, r[2].digest[:8])
			})
			t.Run("folder "+where+name, func(t *testing.T) {
				b, r := threeRecords(t)
				p := "trust/" + r[2].set + "/" + where + name
				b.put(p+"/evil.pem", []byte("EVIL"))
				rep, log := b.runSpied()
				// The folder is the finding; what is in it is not looked at.
				wantFindings(t, rep, []wf{{FileUnlisted, p}})
				if log.lists[p] != 0 {
					t.Error("the temporary folder was entered")
				}
			})
		}
	}
	t.Run("elsewhere it is a notice", func(t *testing.T) {
		b, r := threeRecords(t)
		var want []wf
		for _, p := range []string{
			"history/.rt-abcdefghijk",
			"trust/.rt-abcdefghijk",
			"history/" + r[0].folder + "/.rt-abcdefghijk",
			"history/" + r[0].folder + "/wanted/.rt-abcdefghijk",
		} {
			b.put(p+"/x", []byte("x"))
			want = append(want, wf{UnexpectedFile, p})
		}
		rep := b.run()
		wantFindings(t, rep, want)
		if !rep.Clean() {
			t.Error("a notice makes the history unclean")
		}
	})
}

// A trust set that a closing record lists (the leftover of a ceremony that stopped) is a listed set
// like any other: a desktop file in it that the closing record does not list is file-unlisted, and one
// that it lists is not.
func TestDesktopFileInATrustSetThatAClosingRecordListsIsJudgedLikeAnyOther(t *testing.T) {
	build := func(t *testing.T, listed bool) (*bundle, string, *rec) {
		b := newBundle(t)
		b.apply()
		stopped := b.unfinished()
		path := "trust/" + stopped.set + "/.DS_Store"
		closing := b.closing(stopped, func(r *rec) {
			listsLeftover(stopped, nil)(r)
			if listed {
				r.artifacts[path] = []byte("listed")
				r.refresh()
			}
		})
		b.put(path, []byte("listed"))
		return b, path, closing
	}
	t.Run("not listed", func(t *testing.T) {
		b, path, closing := build(t, false)
		rep := b.run()
		wantFindings(t, rep, []wf{{FileUnlisted, path}})
		wantNotCleanEndUnchanged(t, rep, closing.digest[:8])
	})
	t.Run("listed", func(t *testing.T) {
		b, _, _ := build(t, true)
		wantFindings(t, b.run(), nil)
	})
}
