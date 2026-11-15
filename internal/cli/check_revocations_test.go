package cli

import (
	"strings"
	"testing"
)

// "ritueel check history" on a bundle whose record lists the digests of revocation material
// (docs/reference/ceremony-record.md, "The record": revocations). The record is written as the
// ceremony that made two kinds of key writes it: the member sits between plan_sha256 and
// transcript_sha256 in the canonical order, and each entry holds label, reason and sha256.

func withRevocationList(t *testing.T, list string) (*hbundle, string) {
	t.Helper()
	b := newHB(t, 1)
	var rewritten string
	b.rewrite(t, b.recordPath(1), func(s string) string {
		rewritten = strings.Replace(s, `"transcript_sha256"`, `"revocations":`+list+`,"transcript_sha256"`, 1)
		return rewritten
	})
	return b, hbSum(rewritten)
}

func revEntries(label string) string {
	one := func(reason string, c string) string {
		return `{"label":"` + label + `","reason":"` + reason + `","sha256":"` + strings.Repeat(c, 64) + `"}`
	}
	return `[` + one("root-removal", "1") + `,` + one("compromised", "2") + `,` + one("superseded", "3") + `]`
}

func TestCheckHistoryTakesARecordWithRevocations(t *testing.T) {
	b, end := withRevocationList(t, revEntries("A"))
	r := chHist(t, b.dir)
	want := chEnd(1, end)
	if r.code != ExitOK || r.stdout != want || r.stderr != "" {
		t.Errorf("exit %d, stdout %q, stderr %q; want 0, %q and nothing", r.code, r.stdout, r.stderr, want)
	}
	chWantDone(t, chJSON(t, b.dir), []string{})
}

func TestCheckHistoryRefusesARecordWhoseRevocationsAreNotInTheirForm(t *testing.T) {
	cases := map[string]string{
		"a lower-case label":   revEntries("a"),
		"a label of two":       revEntries("AB"),
		"an empty list":        `[]`,
		"null":                 `null`,
		"an object":            `{"label":"A"}`,
		"an entry with a path": `[{"label":"A","path":"x","reason":"retired","sha256":"` + strings.Repeat("1", 64) + `"}]`,
		"a pair twice":         `[{"label":"A","reason":"retired","sha256":"` + strings.Repeat("1", 64) + `"},{"label":"A","reason":"retired","sha256":"` + strings.Repeat("2", 64) + `"}]`,
	}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			b, _ := withRevocationList(t, list)
			r := chHist(t, b.dir)
			if r.code != ExitRefused || r.stdout != "" {
				t.Fatalf("exit %d, stdout %q; want 3 and nothing on standard output", r.code, r.stdout)
			}
			if !strings.Contains(r.stderr, "record-invalid "+b.recordPath(1)) {
				t.Errorf("stderr = %q", r.stderr)
			}
			// A record that cannot be read is off the chain, and its trust set is listed by no record.
			chWantRefused(t, chJSON(t, b.dir), []string{"record-off-chain", "record-invalid", "trust-set-unlisted"}, []string{})
		})
	}
}
