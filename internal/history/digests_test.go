//go:build linux || darwin

package history

import (
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// The record of a finished ceremony names the digest of the attempt and of each journal that the
// ceremony wrote, and the check holds each file to it. A member that is absent leaves the file
// unchecked.

func ceremonyPath(r *rec, name string) string { return "history/" + r.folder + "/" + name }

func TestAttemptAndJournalsThatTheRecordNamesAreCleanWhenWhole(t *testing.T) {
	b := newBundle(t)
	b.apply()
	b.apply(namesAll)
	rep, log := b.runSpied()
	wantFindings(t, rep, nil)
	for _, name := range []string{"attempt.json", "births.jsonl", "signatures.jsonl"} {
		if n := log.reads[ceremonyPath(b.recs[1], name)]; n != 1 {
			t.Errorf("%s was read %d times, want once", name, n)
		}
	}
}

// Before: the attempt and the journals had no digest anywhere. A person who replaced or emptied
// them in a finished ceremony left the history clean, with the end line of the untouched history.
func TestJournalReplacedInAFinishedCeremonyIsNotClean(t *testing.T) {
	for _, name := range []string{files.BirthsFile, files.SignaturesFile} {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			b.apply()
			r := b.apply(namesAll)
			last := b.apply()
			b.put(ceremonyPath(r, name), []byte("not the journal\n"))
			rep := b.run()
			wantFindings(t, rep, []wf{{FileDigest, ceremonyPath(r, name)}})
			wantNotCleanEndUnchanged(t, rep, last.digest[:8])
		})
	}
}

func TestAttemptReplacedInAFinishedCeremonyIsNotClean(t *testing.T) {
	b := newBundle(t)
	b.apply()
	r := b.apply(namesAll)
	last := b.apply()
	// Another attempt of the same ceremony, written in the canonical form: not the one the record names.
	other := r.attempt
	other.Root = "another-root"
	b.put(ceremonyPath(r, "attempt.json"), must(other.Canonical()))
	rep := b.run()
	wantFindings(t, rep, []wf{{FileDigest, ceremonyPath(r, "attempt.json")}})
	wantNotCleanEndUnchanged(t, rep, last.digest[:8])
}

func TestAttemptOrJournalThatTheRecordNamesAndIsGoneIsMissing(t *testing.T) {
	for _, name := range []string{files.AttemptFile, files.BirthsFile, files.SignaturesFile} {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(namesAll)
			b.remove(ceremonyPath(r, name))
			rep := b.run()
			// Without its attempt the ceremony is still a ceremony with a record.
			wantFindings(t, rep, []wf{{FileMissing, ceremonyPath(r, name)}})
		})
	}
}

// A name that a record does not give leaves the file unchecked, as the page says.
func TestAttemptAndJournalsThatNoDigestNamesAreNotChecked(t *testing.T) {
	b := newBundle(t)
	r := b.apply(withJournals)
	b.put(ceremonyPath(r, "births.jsonl"), []byte("garbage"))
	b.put(ceremonyPath(r, "signatures.jsonl"), nil)
	b.put(ceremonyPath(r, "attempt.json"), []byte("garbage"))
	wantFindings(t, b.run(), nil)
	// Naming one of them checks that one only.
	b2 := newBundle(t)
	r2 := b2.apply(withJournals, func(r *rec) { r.record.BirthsSHA256 = files.Digest(r.extra[files.BirthsFile]) })
	b2.put(ceremonyPath(r2, "signatures.jsonl"), []byte("garbage"))
	wantFindings(t, b2.run(), nil)
	b2.put(ceremonyPath(r2, "births.jsonl"), []byte("garbage"))
	wantFindings(t, b2.run(), []wf{{FileDigest, ceremonyPath(r2, "births.jsonl")}})
}

// The wrong kind of entry is a finding of the digest, one finding, as for every listed file.
func TestAttemptOrJournalThatTheRecordNamesAndIsNotAFileIsOneFileDigest(t *testing.T) {
	for _, name := range []string{files.AttemptFile, files.BirthsFile, files.SignaturesFile} {
		for _, kind := range []string{"link", "FIFO", "socket", "folder"} {
			t.Run(name+" as a "+kind, func(t *testing.T) {
				b := newBundle(t)
				r := b.apply(namesAll)
				makeOddFile(t, b, kind, ceremonyPath(r, name))
				wantFindings(t, b.run(), []wf{{FileDigest, ceremonyPath(r, name)}})
			})
		}
	}
}

// A closing record, or a declined record, that holds a journal digest is not a record that can be
// read: it is record-invalid, it lists nothing, and it and every record after it are off the chain.
func TestClosingRecordThatHoldsAJournalDigestCannotBeRead(t *testing.T) {
	b := newBundle(t)
	b.apply()
	stopped := b.unfinished()
	closing := b.closing(stopped, func(r *rec) {
		listsLeftover(stopped, nil)(r)
		withJournals(r)
		r.record.BirthsSHA256 = files.Digest(r.extra[files.BirthsFile])
	})
	later := b.apply(noSet)
	rep := b.run()
	wantFindings(t, rep, []wf{
		{RecordInvalid, recordPath(closing)},
		{RecordOffChain, folderPath(closing)},
		{RecordOffChain, folderPath(later)},
		// The closing record lists nothing now, so the set it listed is unlisted again.
		{TrustSetUnlisted, setPath(stopped)},
	})
	if rep.Clean() {
		t.Error("clean")
	}
}

func TestDeclinedRecordThatHoldsAnAttemptOrJournalDigestCannotBeRead(t *testing.T) {
	for _, member := range []string{"attempt_sha256", "births_sha256", "signatures_sha256"} {
		t.Run(member, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(noSet, func(r *rec) {
				r.record.Outcome = files.OutcomeDeclined
				r.record.Declined = &files.Declined{Stem: "alice", Reason: "no"}
				switch member {
				case "attempt_sha256":
					r.record.AttemptSHA256 = digestA
				case "births_sha256":
					r.record.BirthsSHA256 = digestA
				default:
					r.record.SignaturesSHA256 = digestA
				}
			})
			rep := b.run()
			wantFindings(t, rep, []wf{{RecordInvalid, recordPath(r)}, {RecordOffChain, folderPath(r)}})
		})
	}
}
