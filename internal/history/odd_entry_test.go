//go:build linux || darwin

package history

import (
	"syscall"
	"testing"
)

// A link, a FIFO, a socket or a device where a ceremony folder or a trust set belongs fails
// (ritueel never writes one), and a plain file with a valid name there stays a notice. The tests
// hold the code and the path, and what the history would have been before: the newest folder
// replaced was clean.

func makeOdd(t *testing.T, b *bundle, kind, rel string) {
	t.Helper()
	switch kind {
	case "dangling link":
		b.remove(rel)
		b.symlink("gone", rel)
	case "FIFO":
		b.remove(rel)
		b.fifo(rel)
	case "socket":
		b.remove(rel)
		b.mkdir(dirOf(rel))
		if err := syscall.Mknod(b.abs(rel), syscall.S_IFSOCK|0o600, 0); err != nil {
			t.Skipf("no socket here: %v", err)
		}
	}
}

var oddKinds = []string{"dangling link", "FIFO", "socket"}

// The newest ceremony folder, and its set, replaced: the two sets of the history that a removal
// leaves clean. Before: one notice each, exit 0, and the end line of the record before.
func TestLinkFIFOOrSocketInPlaceOfTheNewestFolderAndOfItsSetFails(t *testing.T) {
	for _, kind := range oddKinds {
		t.Run(kind, func(t *testing.T) {
			b, r := threeRecords(t)
			makeOdd(t, b, kind, "history/"+r[2].folder)
			makeOdd(t, b, kind, "trust/"+r[2].set)
			rep := b.run()
			wantFindings(t, rep, []wf{
				{UnexpectedName, "history/" + r[2].folder},
				{UnexpectedName, "trust/" + r[2].set},
			})
			wantReasons(t, rep, []Code{UnexpectedName}, nil)
			if rep.Clean() {
				t.Error("clean")
			}
			// What a person who keeps the end would have seen before: the end of the record before.
			if eight, count, ok := rep.End(); !ok || count != 2 || eight != r[1].digest[:8] {
				t.Errorf("End() = %q, %d, %v", eight, count, ok)
			}
		})
	}
}

func TestLinkFIFOOrSocketInPlaceOfATrustSetThatNoRecordListsFails(t *testing.T) {
	for _, kind := range oddKinds {
		t.Run(kind, func(t *testing.T) {
			b, _ := threeRecords(t)
			b.mkdir("trust/9-3fa9c1d2")
			makeOdd(t, b, kind, "trust/9-3fa9c1d2")
			wantFindings(t, b.run(), []wf{{UnexpectedName, "trust/9-3fa9c1d2"}})
		})
	}
}

func TestLinkFIFOOrSocketInHistoryAndTrustThatHoldsNoFolderFails(t *testing.T) {
	for _, kind := range oddKinds {
		t.Run(kind, func(t *testing.T) {
			b, _ := threeRecords(t)
			makeOdd(t, b, kind, "history/odd")
			makeOdd(t, b, kind, "trust/odd")
			wantFindings(t, b.run(), []wf{{UnexpectedName, "history/odd"}, {UnexpectedName, "trust/odd"}})
		})
	}
}

func TestPlainFileInPlaceOfAFolderStaysANotice(t *testing.T) {
	b, r := threeRecords(t)
	b.put("history/notes.txt", []byte("x"))
	b.put("trust/notes.txt", []byte("x"))
	rep := b.run()
	wantFindings(t, rep, []wf{{UnexpectedFile, "history/notes.txt"}, {UnexpectedFile, "trust/notes.txt"}})
	if !rep.Clean() {
		t.Error("a notice makes the history unclean")
	}
	// And a plain file where the newest folder was: the record is gone, and the set is not listed.
	b.remove("history/" + r[2].folder)
	b.put("history/"+r[2].folder, []byte("x"))
	rep = b.run()
	has(t, rep, UnexpectedFile, "history/"+r[2].folder)
}

// A link where the folder of a record in the middle of the chain belongs is a fault in any answer;
// the code is the question.
func TestLinkInPlaceOfAFolderInTheMiddleOfTheChainFailsWhateverItIsCalled(t *testing.T) {
	b, r := threeRecords(t)
	makeOdd(t, b, "dangling link", "history/"+r[1].folder)
	rep := b.run()
	has(t, rep, UnexpectedName, "history/"+r[1].folder)
	has(t, rep, ChainBroken, folderPath(r[2]))
	if rep.Clean() {
		t.Error("clean")
	}
}
