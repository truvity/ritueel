package history

import (
	"testing"
)

// The keyring file of a trust set (keyring.gpg, one flat file beside the three others) is a file of the
// set like the others: the record of the ceremony that wrote the set lists it with its digest, and
// the check holds the set to the record. A set of four files with a record that lists four is clean;
// a record that lists three leaves the file unlisted; a file with another digest is told.

const keyringName = "keyring.gpg"

// withKeyringFile makes the ceremony write the keyring file into its set, and the record list it.
func withKeyringFile(data []byte) func(*rec) {
	return func(r *rec) {
		r.artifacts["trust/"+r.set+"/"+keyringName] = data
		r.refresh()
	}
}

func TestRecordThatListsTheKeyringFileIsClean(t *testing.T) {
	b := newBundle(t)
	b.apply(withKeyringFile([]byte("packets of one certificate")))
	b.apply(withKeyringFile([]byte("packets of two certificates")))
	rep := b.run()
	wantFindings(t, rep, nil)
	if !rep.Clean() {
		t.Errorf("a history whose sets hold four files is not clean: %v", findingsOf(rep))
	}
}

func TestRecordThatDoesNotListTheKeyringFileLeavesItUnlisted(t *testing.T) {
	b, r := threeRecords(t)
	p := "trust/" + r[1].set + "/" + keyringName
	b.put(p, []byte("packets of one certificate"))
	rep := b.run()
	wantFindings(t, rep, []wf{{FileUnlisted, p}})
	wantReasons(t, rep, []Code{FileUnlisted}, nil)
	if rep.Clean() || !FileUnlisted.Fails() {
		t.Error("an unlisted keyring file is not a failing finding")
	}
}

func TestKeyringFileWithAnotherDigestIsTold(t *testing.T) {
	b := newBundle(t)
	r := b.apply(withKeyringFile([]byte("packets of one certificate")))
	b.apply()
	p := "trust/" + r.set + "/" + keyringName
	b.put(p, []byte("packets of another certificate"))
	rep := b.run()
	wantFindings(t, rep, []wf{{FileDigest, p}})
	wantReasons(t, rep, []Code{FileDigest}, nil)
}

func TestKeyringFileThatIsMissingIsTold(t *testing.T) {
	b := newBundle(t)
	r := b.apply(withKeyringFile([]byte("packets of one certificate")))
	p := "trust/" + r.set + "/" + keyringName
	b.remove(p)
	rep := b.run()
	wantFindings(t, rep, []wf{{FileMissing, p}})
}
