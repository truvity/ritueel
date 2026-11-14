//go:build linux || darwin

package history

import (
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// A record lists what it should not: itself, a folder, the plan of another ceremony, a set that is
// not there. Each is a plain finding about that file, and the run ends.

func TestRecordThatListsItselfHasAFileThatFailsItsDigest(t *testing.T) {
	b := newBundle(t)
	r := b.apply(noSet, func(r *rec) {
		r.record.Artifacts = []files.FileRef{{Path: "history/" + r.folder + "/record.json", SHA256: digestA}}
	})
	rep := b.run()
	wantFindings(t, rep, []wf{{FileDigest, "history/" + r.folder + "/record.json"}})
}

func TestRecordThatListsAFolderHasAFileThatFailsItsDigest(t *testing.T) {
	b := newBundle(t)
	b.mkdir("trust")
	b.apply(noSet, func(r *rec) {
		r.record.Artifacts = []files.FileRef{{Path: "history", SHA256: digestA}, {Path: "trust", SHA256: digestA}}
	})
	rep := b.run()
	wantFindings(t, rep, []wf{{FileDigest, "history"}, {FileDigest, "trust"}})
}

func TestRecordThatListsTheFilesOfAnotherCeremonyChecksThemAsListed(t *testing.T) {
	b := newBundle(t)
	a := b.apply(noSet)
	other := "history/" + a.folder + "/transcript.txt"
	b.apply(noSet, func(r *rec) {
		r.record.Artifacts = []files.FileRef{{Path: other, SHA256: files.Digest(a.transcript)}}
	})
	wantFindings(t, b.run(), nil)
	b.put(other, []byte("changed"))
	rep := b.run()
	// The file fails its digest for the ceremony that owns it and for the one that lists it.
	has(t, rep, TranscriptDigest, other)
	has(t, rep, FileDigest, other)
}

func TestClosingRecordThatClosesItsOwnCeremonyReadsTheAttemptOfItsOwnFolder(t *testing.T) {
	b := newBundle(t)
	b.apply(noSet, func(r *rec) {
		r.record.Command = files.CommandClose
		r.record.Outcome = files.OutcomeClosed
		r.record.PlanSHA256 = ""
		r.record.Wanted = nil
		r.wanted = nil
		r.record.Closes = &files.Closes{Ceremony: r.folder, AttemptSHA256: files.Digest(must(r.attempt.Canonical()))}
	})
	rep := b.run()
	// The folder holds that attempt: nothing is wrong with the files.
	wantFindings(t, rep, nil)
}

func TestListedTrustSetThatIsNotThereIsOnlyMissingFiles(t *testing.T) {
	b := newBundle(t)
	b.apply(noSet, func(r *rec) {
		r.record.Artifacts = []files.FileRef{{Path: "trust/9-3fa9c1d2/root-list.json", SHA256: digestA}}
	})
	wantFindings(t, b.run(), []wf{{FileMissing, "trust/9-3fa9c1d2/root-list.json"}})
}
