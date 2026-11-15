//go:build linux || darwin

package history

import (
	"bytes"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// The record of a ceremony that made keys of two kinds lists the digest of each revocation signature
// and of each removal authorisation (docs/reference/ceremony-record.md, "The record"). `check history`
// reads the record with the reader of internal/ceremony/files, so a list in its form is clean and a
// list that is not in its form is record-invalid.

func revocationEntries() []files.RevocationEntry {
	return []files.RevocationEntry{
		{Label: "A", Reason: files.ReasonRootRemoval, SHA256: strings.Repeat("1", 64)},
		{Label: "A", Reason: files.ReasonCompromised, SHA256: strings.Repeat("2", 64)},
		{Label: "A", Reason: files.ReasonSuperseded, SHA256: strings.Repeat("3", 64)},
	}
}

func withRevocations(list []files.RevocationEntry) func(*rec) {
	return func(r *rec) {
		r.record.Revocations = list
		doc := &files.RootJSON{
			Version: 1, Label: "A", Store: "software", Test: true, CreatedAt: "2026-11-20T10:00:00Z",
			X509SPKISHA256: strings.Repeat("a", 64), RemovalSHA256: strings.Repeat("1", 64),
			OpenPGPFingerprint: strings.Repeat("c", 40), OpenPGPCreated: "2026-11-20T09:00:00Z",
			Revocations: map[string]string{"compromised": strings.Repeat("2", 64), "superseded": strings.Repeat("3", 64)},
		}
		r.artifacts["roots/A/root.json"] = must(doc.Canonical())
		r.refresh()
	}
}

func TestARecordWithRevocationsAndARootJSONWithAPrimaryIsClean(t *testing.T) {
	b := newBundle(t)
	b.apply(withRevocations(revocationEntries()))
	// A record after it, with none: the chain goes on.
	b.apply()
	rep := b.run()
	wantFindings(t, rep, nil)
	if !rep.Clean() {
		t.Errorf("not clean: %+v", rep.Findings)
	}
}

func TestARecordWithTheMostRevocationsIsClean(t *testing.T) {
	var list []files.RevocationEntry
	for l := 0; l < 26; l++ {
		for _, reason := range []string{"root-removal", "compromised", "superseded", "retired", "no-reason"} {
			list = append(list, files.RevocationEntry{Label: string(rune('A' + l)), Reason: reason, SHA256: strings.Repeat("4", 64)})
		}
	}
	if len(list) != files.MaxRevocations {
		t.Fatalf("%d entries", len(list))
	}
	b := newBundle(t)
	b.apply(withRevocations(list))
	wantFindings(t, b.run(), nil)
}

func TestARecordWhoseRevocationsAreMalformedIsRecordInvalid(t *testing.T) {
	good := revocationEntries()
	edit := func(f func(l []files.RevocationEntry) []files.RevocationEntry) []files.RevocationEntry {
		return f(append([]files.RevocationEntry(nil), good...))
	}
	cases := map[string][]files.RevocationEntry{
		"a label of two letters": edit(func(l []files.RevocationEntry) []files.RevocationEntry { l[0].Label = "AB"; return l }),
		"a lower-case label":     edit(func(l []files.RevocationEntry) []files.RevocationEntry { l[0].Label = "a"; return l }),
		"a bad reason":           edit(func(l []files.RevocationEntry) []files.RevocationEntry { l[1].Reason = "lost"; return l }),
		"a bad digest":           edit(func(l []files.RevocationEntry) []files.RevocationEntry { l[2].SHA256 = "abc"; return l }),
		"an empty digest":        edit(func(l []files.RevocationEntry) []files.RevocationEntry { l[2].SHA256 = ""; return l }),
		"a pair twice":           edit(func(l []files.RevocationEntry) []files.RevocationEntry { return append(l, l[1]) }),
		"131 entries": edit(func(l []files.RevocationEntry) []files.RevocationEntry {
			out := make([]files.RevocationEntry, 0, 131)
			for i := 0; i < 131; i++ {
				out = append(out, files.RevocationEntry{Label: string(rune('A' + i%26)), Reason: []string{"root-removal", "compromised", "superseded", "retired", "no-reason"}[i%5], SHA256: strings.Repeat("4", 64)})
			}
			return out
		}),
	}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(withRevocations(list))
			rep := b.run()
			has(t, rep, RecordInvalid, recordPath(r))
			if rep.Clean() {
				t.Error("clean")
			}
		})
	}
}

func TestARecordWithRevocationsOfAnotherShapeIsRecordInvalid(t *testing.T) {
	// The member is put into the bytes of the record after they were made: a list that the types of
	// the program cannot hold.
	cases := map[string]string{
		"null":                  `null`,
		"an empty list":         `[]`,
		"an object":             `{"label":"A","reason":"retired","sha256":"` + strings.Repeat("1", 64) + `"}`,
		"a string":              `"compromised"`,
		"a number":              `1`,
		"an entry with a path":  `[{"label":"A","path":"x","reason":"retired","sha256":"` + strings.Repeat("1", 64) + `"}]`,
		"an entry with no hash": `[{"label":"A","reason":"retired"}]`,
		"an entry that is null": `[null]`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(recordAs(func(c []byte) []byte {
				return bytes.Replace(c, []byte(`"transcript_sha256"`), []byte(`"revocations":`+text+`,"transcript_sha256"`), 1)
			}))
			rep := b.run()
			has(t, rep, RecordInvalid, recordPath(r))
		})
	}
}

func TestAClosingRecordWithRevocationsIsRecordInvalid(t *testing.T) {
	b := newBundle(t)
	b.apply()
	stopped := b.unfinished()
	closing := b.closing(stopped, func(r *rec) {
		for p, data := range stopped.artifacts {
			r.artifacts[p] = data
		}
		r.record.Revocations = revocationEntries()
		r.refresh()
	})
	rep := b.run()
	has(t, rep, RecordInvalid, recordPath(closing))
}
