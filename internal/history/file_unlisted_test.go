//go:build linux || darwin

package history

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// A file inside a trust set that no record lists is the failing finding file-unlisted; a file inside
// the folder of copies (wanted/) that its record does not list, and the names that a desktop system
// writes, are notices (the page, "The hash chain"). The tests hold the code, the path and the fact,
// and none of the words of a detail.

// Files added to a history of three records by someone who wants a wrong "clean": the
// printed end is the same as before.
func TestFileInATrustSetThatNoRecordListsFails(t *testing.T) {
	b, r := threeRecords(t)
	extra := map[string]string{
		"trust/" + r[2].set + "/ssh-ca.pub":         "a key",
		"trust/" + r[0].set + "/extra.pem":          "a certificate",
		"trust/" + r[1].set + "/sub/deep/x.pem":     "a certificate in a folder",
		"trust/" + r[1].set + "/keyring/people.gpg": "a key ring",
	}
	var want []wf
	for p, data := range extra {
		b.put(p, []byte(data))
		want = append(want, wf{FileUnlisted, p})
	}
	rep := b.run()
	// Before: exit 0, no notice, and the end line of the untouched history.
	wantFindings(t, rep, want)
	wantReasons(t, rep, []Code{FileUnlisted}, nil)
	if rep.Clean() {
		t.Error("clean")
	}
	if eight, count, ok := rep.End(); !ok || count != 3 || eight != r[2].digest[:8] {
		t.Errorf("End() = %q, %d, %v", eight, count, ok)
	}
	if !FileUnlisted.Fails() || FileUnlisted.Notice() {
		t.Error("file-unlisted does not fail")
	}
}

func TestCodeFileUnlistedComesAfterFileMissingInTheOrder(t *testing.T) {
	codes := Codes()
	var after Code
	for i, c := range codes {
		if c == FileUnlisted {
			after = codes[i-1]
		}
	}
	if after != FileMissing {
		t.Errorf("file-unlisted follows %q, want file-missing", after)
	}
}

func TestEveryKindOfEntryInATrustSetThatNoRecordListsFails(t *testing.T) {
	for _, kind := range []string{"file", "link", "fifo", "socket"} {
		t.Run(kind, func(t *testing.T) {
			b, r := threeRecords(t)
			p := "trust/" + r[1].set + "/odd"
			switch kind {
			case "file":
				b.put(p, []byte("x"))
			case "link":
				b.symlink("keys.txt", p)
			case "fifo":
				b.fifo(p)
			case "socket":
				b.mkdir("trust/" + r[1].set)
				if err := syscall.Mknod(b.abs(p), syscall.S_IFSOCK|0o600, 0); err != nil {
					t.Skipf("no socket here: %v", err)
				}
			}
			wantFindings(t, b.run(), []wf{{FileUnlisted, p}})
		})
	}
}

// The walk is as deep as the longest path a record may list, and no deeper: a folder at the last
// level is reported as it is, and the files below it are not looked at one by one.
func TestFileInATrustSetIsFoundDownToTheDepthOfAListedPath(t *testing.T) {
	// trust/<set>/ takes two elements of a path.
	levels := files.MaxPathElements - 2
	chain := func(n int) string { return strings.TrimSuffix(strings.Repeat("d/", n), "/") }
	t.Run("a file at the deepest level", func(t *testing.T) {
		b, r := threeRecords(t)
		p := "trust/" + r[0].set + "/" + chain(levels-1) + "/f"
		b.put(p, []byte("x"))
		wantFindings(t, b.run(), []wf{{FileUnlisted, p}})
	})
	t.Run("a folder at the deepest level is reported, and not entered", func(t *testing.T) {
		b, r := threeRecords(t)
		folder := "trust/" + r[0].set + "/" + chain(levels)
		b.put(folder+"/inside", []byte("x"))
		wantFindings(t, b.run(), []wf{{FileUnlisted, folder}})
	})
}

func TestAnUnlistedTrustSetIsNotWalked(t *testing.T) {
	b, _ := threeRecords(t)
	b.put("trust/9-3fa9c1d2/ssh-ca.pub", []byte("a key"))
	b.put("trust/9-3fa9c1d2/sub/x.pem", []byte("a certificate"))
	rep, log := b.runSpied()
	// It has a finding of its own, and its files would say it again.
	wantFindings(t, rep, []wf{{TrustSetUnlisted, "trust/9-3fa9c1d2"}})
	for p := range log.lists {
		if strings.HasPrefix(p, "trust/9-3fa9c1d2") {
			t.Errorf("the check listed %s", p)
		}
	}
}

func TestNamesThatADesktopWritesInATrustSetAreNotices(t *testing.T) {
	for _, name := range []string{".DS_Store", "Thumbs.db", "desktop.ini", "._keys.txt", "._x"} {
		t.Run(name, func(t *testing.T) {
			b, r := threeRecords(t)
			p := "trust/" + r[1].set + "/" + name
			b.put(p, []byte("x"))
			rep := b.run()
			wantFindings(t, rep, []wf{{UnexpectedFile, p}})
			wantReasons(t, rep, nil, []Code{UnexpectedFile})
			if !rep.Clean() {
				t.Error("a desktop file makes the history unclean")
			}
		})
	}
	t.Run("in a folder of the set", func(t *testing.T) {
		b, r := threeRecords(t)
		p := "trust/" + r[1].set + "/keyring/.DS_Store"
		b.put(p, []byte("x"))
		wantFindings(t, b.run(), []wf{{UnexpectedFile, p}})
	})
	t.Run("a name that only begins like one", func(t *testing.T) {
		b, r := threeRecords(t)
		p := "trust/" + r[1].set + "/_DS_Store"
		b.put(p, []byte("x"))
		wantFindings(t, b.run(), []wf{{FileUnlisted, p}})
	})
}

func TestNameThatBreaksTheRuleForNamesInsideATrustSetFailsAndSoDoesATemporaryName(t *testing.T) {
	b, r := threeRecords(t)
	b.put("trust/"+r[0].set+"/a b", []byte("x"))
	b.put("trust/"+r[0].set+"/.rt-abcdefghijk", []byte("x"))
	rep := b.run()
	wantFindings(t, rep, []wf{
		{UnexpectedName, "trust/" + r[0].set + "/a" + bs + "x20b"},
		{FileUnlisted, "trust/" + r[0].set + "/.rt-abcdefghijk"},
	})
}

// Copies of the wanted files: the ones the record lists are checked by their digest; the others are
// a notice.
func TestFileInTheCopiesOfAWantedFolderThatItsRecordDoesNotListIsANotice(t *testing.T) {
	b, r := threeRecords(t)
	base := "history/" + r[1].folder + "/wanted/"
	b.put(base+"other.yaml", []byte("x"))
	b.put(base+"sub/x.yaml", []byte("x"))
	rep := b.run()
	// Before: exit 0, no notice, and the end line of the untouched history.
	wantFindings(t, rep, []wf{{UnexpectedFile, base + "other.yaml"}, {UnexpectedFile, base + "sub/x.yaml"}})
	wantReasons(t, rep, nil, []Code{UnexpectedFile})
	if !rep.Clean() {
		t.Error("a notice makes the history unclean")
	}
}

func TestWantedFolderOfARecordThatCannotBeReadIsNotWalked(t *testing.T) {
	b, r := threeRecords(t)
	base := "history/" + r[1].folder
	b.put(base+"/wanted/other.yaml", []byte("x"))
	rewrite(b, r[1], func(c []byte) []byte { return append(c, []byte(" junk")...) }) // not JSON any more
	rep, log := b.runSpied()
	has(t, rep, RecordInvalid, recordPath(r[1]))
	lacks(t, rep, UnexpectedFile)
	if log.lists[base+"/wanted"] != 0 {
		t.Error("the check listed the folder of copies of a record that could not be read")
	}
}

// What the walk looks at is bounded; a bundle with more names than the limit is not checked.
func TestWalkInsideTheSetsAndTheCopiesStopsAtItsLimit(t *testing.T) {
	b, _ := threeRecords(t)
	// One bound counts every name a run looks at: the three ceremony folders of history/ and the three
	// sets of trust/, the five names of each ceremony folder, the two files of each set and the one
	// copy of each ceremony.
	const names = 3 + 3 + 3*5 + 3*2 + 3*1
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	lim := limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: MaxFindingsPerCode, walkEntries: names}
	rep, err := runFS(t, root, &lim)
	if err != nil {
		t.Fatalf("a limit of %d names, which is what the bundle holds: %v", names, err)
	}
	wantFindings(t, rep, nil)
	lim.walkEntries = names - 1
	rep, err = runFS(t, root, &lim)
	if !errors.Is(err, ErrTooMuch) || rep != nil {
		t.Fatalf("a limit of %d names: Check = %v, %v; want ErrTooMuch", names-1, rep, err)
	}
	if !printable(err.Error()) {
		t.Errorf("the text of the error is not printable ASCII: %q", err)
	}
}

func TestManyFilesInATrustSetThatNoRecordListsAreEachReported(t *testing.T) {
	// Each file is a finding of its own, up to the limit of one code.
	b := newBundle(t)
	r := b.apply()
	for i := 0; i < 50; i++ {
		b.put(fmt.Sprintf("trust/%s/f%03d.pem", r.set, i), []byte("x"))
	}
	rep := b.run()
	if n := len(findingsOf(rep)); n != 50 {
		t.Errorf("%d findings, want 50", n)
	}
}
