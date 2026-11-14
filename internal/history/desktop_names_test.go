//go:build linux || darwin

package history

import (
	"syscall"
	"testing"
)

// The four names that a desktop system writes beside the files of a folder (.DS_Store, Thumbs.db,
// desktop.ini and a name that starts with "._") are the notice unexpected-file when the entry is a
// regular file, and only then. A link, a FIFO, a socket or a folder with one of the names is not what
// a desktop writes: it is file-unlisted, like any other entry of a trust set that no record lists.
// Before, any entry that was not a folder passed as the notice, so a link to a file outside the set,
// or a FIFO, with one of these names left the history clean with the end of the untouched history.

var droppings = []string{".DS_Store", "Thumbs.db", "desktop.ini", "._x", "._keys.gpg"}

func makeDroppingKind(t *testing.T, b *bundle, kind, rel string) {
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
	for _, name := range droppings {
		for _, where := range []string{"", "keyring/"} {
			for _, kind := range []string{"link", "FIFO", "socket"} {
				t.Run(where+name+" as a "+kind, func(t *testing.T) {
					b, r := threeRecords(t)
					p := "trust/" + r[2].set + "/" + where + name
					makeDroppingKind(t, b, kind, p)
					rep := b.run()
					wantFindings(t, rep, []wf{{FileUnlisted, p}})
					wantNotCleanEndUnchanged(t, rep, r[2].digest[:8])
				})
			}
		}
	}
}

// A folder with one of the names is entered like any folder, and what is in it is not listed by any
// record.
func TestDesktopNameThatIsAFolderInATrustSetIsEnteredAndWhatIsInItIsFileUnlisted(t *testing.T) {
	for _, name := range droppings {
		t.Run(name, func(t *testing.T) {
			b, r := threeRecords(t)
			p := "trust/" + r[2].set + "/" + name + "/evil.pem"
			b.put(p, []byte("EVIL"))
			rep := b.run()
			wantFindings(t, rep, []wf{{FileUnlisted, p}})
			wantNotCleanEndUnchanged(t, rep, r[2].digest[:8])
		})
	}
}

func TestDesktopNameThatIsARegularFileInATrustSetStaysANotice(t *testing.T) {
	for _, name := range droppings {
		for _, where := range []string{"", "keyring/"} {
			t.Run(where+name, func(t *testing.T) {
				b, r := threeRecords(t)
				p := "trust/" + r[1].set + "/" + where + name
				b.put(p, []byte("x"))
				rep := b.run()
				wantFindings(t, rep, []wf{{UnexpectedFile, p}})
				if !rep.Clean() {
					t.Error("a notice makes the history unclean")
				}
			})
		}
	}
}

// The bundle of the read, in one: six entries, two of them regular files.
func TestTrustSetWithDesktopNamesOfEveryKindFailsForTheOnesThatAreNotFiles(t *testing.T) {
	b, r := threeRecords(t)
	set := "trust/" + r[2].set + "/"
	b.symlink("/etc/passwd", set+"desktop.ini")
	b.symlink("../../../want/evil.gpg", set+"keyring/._link.gpg")
	b.fifo(set + "._fifo")
	b.put(set+".DS_Store", []byte("EVIL"))
	b.put(set+"keyring/._evil.gpg", []byte("EVIL"))
	rep := b.run()
	wantFindings(t, rep, []wf{
		{FileUnlisted, set + "desktop.ini"},
		{FileUnlisted, set + "keyring/._link.gpg"},
		{FileUnlisted, set + "._fifo"},
		{UnexpectedFile, set + ".DS_Store"},
		{UnexpectedFile, set + "keyring/._evil.gpg"},
	})
	wantReasons(t, rep, []Code{FileUnlisted}, []Code{UnexpectedFile})
}

// A temporary name inside a finished trust set is not a leftover of any write: a set is written whole
// under a temporary name and renamed into place. It is file-unlisted, and the folder is not entered.
// In history/, trust/, a ceremony folder and the copies it stays the notice. Before, it was the
// notice everywhere and what was inside a temporary folder was never looked at.
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
