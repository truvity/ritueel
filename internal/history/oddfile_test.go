//go:build linux || darwin

package history

import (
	"syscall"
	"testing"
)

// A link, a FIFO, a socket, a device or a folder where attempt.json or a journal belongs is
// unexpected-name: ritueel writes none of them, and the file it hides is covered by no digest unless
// the record names it, and then the finding is the one of the digest. The plan and the transcript
// are always named by their record: one that is not a regular file is the notice unexpected-file
// only when no record reads it.

// makeOddFile puts an entry of a kind that is not a regular file at a path of the bundle.
func makeOddFile(t *testing.T, b *bundle, kind, rel string) {
	t.Helper()
	b.remove(rel)
	switch kind {
	case "link":
		b.symlink("ritueel.yaml", rel)
	case "FIFO":
		b.fifo(rel)
	case "socket":
		b.mkdir(dirOf(rel))
		if err := syscall.Mknod(b.abs(rel), syscall.S_IFSOCK|0o600, 0); err != nil {
			t.Skipf("no socket here: %v", err)
		}
	case "folder":
		b.mkdir(rel)
	default:
		t.Fatalf("no such kind %q", kind)
	}
}

var oddFileKinds = []string{"link", "FIFO", "socket", "folder"}

func TestAttemptOrJournalThatIsNotAFileAndNoRecordNamesIsUnexpectedName(t *testing.T) {
	for _, name := range []string{"attempt.json", "births.jsonl", "signatures.jsonl"} {
		for _, kind := range oddFileKinds {
			t.Run(name+" as a "+kind, func(t *testing.T) {
				b := newBundle(t)
				r := b.apply(noSet, withJournals)
				p := ceremonyPath(r, name)
				makeOddFile(t, b, kind, p)
				rep := b.run()
				wantFindings(t, rep, []wf{{UnexpectedName, p}})
				wantReasons(t, rep, []Code{UnexpectedName}, nil)
				if rep.Clean() {
					t.Error("clean")
				}
			})
		}
	}
}

func TestAttemptOfAnOpenCeremonyThatIsNotAFileLeavesItsSetUnlisted(t *testing.T) {
	for _, kind := range oddFileKinds {
		t.Run(kind, func(t *testing.T) {
			b := newBundle(t)
			b.apply()
			u := b.unfinished()
			p := ceremonyPath(u, "attempt.json")
			makeOddFile(t, b, kind, p)
			rep := b.run()
			wantFindings(t, rep, []wf{{TrustSetUnlisted, setPath(u)}, {UnexpectedName, p}})
		})
	}
}

func TestPlanAndTranscriptThatAreNotFilesAreOneFindingOfTheirOwnDigestOrANotice(t *testing.T) {
	for _, name := range []string{"plan.json", "transcript.txt"} {
		for _, kind := range oddFileKinds {
			t.Run(name+" as a "+kind+", named by the record", func(t *testing.T) {
				b := newBundle(t)
				r := b.apply(noSet)
				p := ceremonyPath(r, name)
				makeOddFile(t, b, kind, p)
				wantFindings(t, b.run(), []wf{{FileDigest, p}})
			})
			t.Run(name+" as a "+kind+", record unreadable", func(t *testing.T) {
				b := newBundle(t)
				r := b.apply(noSet)
				p := ceremonyPath(r, name)
				makeOddFile(t, b, kind, p)
				rewrite(b, r, func(c []byte) []byte { return append(c, []byte("junk")...) })
				rep := b.run()
				has(t, rep, UnexpectedFile, p)
				lacks(t, rep, UnexpectedName)
			})
		}
	}
}

func TestWantedThatIsNotAFolderStaysANotice(t *testing.T) {
	b := newBundle(t)
	r := b.apply(noSet)
	p := ceremonyPath(r, "wanted")
	b.remove(p)
	b.put(p, []byte("x"))
	rep := b.run()
	has(t, rep, UnexpectedFile, p)
	lacks(t, rep, UnexpectedName)
}
