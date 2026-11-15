package ceremonytest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/ceremonytest"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// The attempt names the ceremony, the digest of the plan, and the root that the plan names, and is
// the one that Made digests.
func TestTheAttemptNamesThePlanAndTheRoot(t *testing.T) {
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtAttempt})
	data := readFile(t, m.Dir, "history", m.Ceremony, "attempt.json")
	a, err := files.ReadAttempt(data)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := files.ReadPlan(readFile(t, m.Dir, "history", m.Ceremony, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != 1 || a.Ceremony != m.Ceremony || a.PlanSHA256 != m.PlanSHA256 || a.Root != plan.Root.Label || a.Root != "A" {
		t.Errorf("attempt %+v, plan root %+v, ceremony %s", a, plan.Root, m.Ceremony)
	}
	if a.StartedAt != "2026-11-20T10:00:00Z" {
		t.Errorf("started_at = %s", a.StartedAt)
	}
	if got := files.Digest(data); got != m.AttemptSHA256 {
		t.Errorf("AttemptSHA256 = %s, the digest of the file is %s", m.AttemptSHA256, got)
	}
}

// The transcript that a bundle past AtTranscript holds is the text of the run: it opens with the
// prefix of the plan, names the pin of each key that was born, and ends with the same prefix.
func TestTheTranscriptHoldsThePins(t *testing.T) {
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtTranscript})
	text := string(readFile(t, m.Dir, "history", m.Ceremony, "transcript.txt"))
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	prefix := m.PlanSHA256[:8]
	if len(lines) < 4 || lines[0] != "plan "+prefix || lines[len(lines)-1] != "done "+prefix {
		t.Errorf("the transcript is %q", text)
	}
	for _, p := range m.Pins {
		if !strings.Contains(text, p) {
			t.Errorf("the transcript does not name the pin %s", p)
		}
	}
}

// The record of the bundle at Recorded is the record of an apply that completed on a workstation,
// and holds what the run made.
func TestTheRecordIsThatOfACompletedApply(t *testing.T) {
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	data := readFile(t, m.Dir, "history", m.Ceremony, "record.json")
	rec, err := files.ReadRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Command != files.CommandApply || rec.Outcome != files.OutcomeCompleted || rec.Ceremony != m.Ceremony || rec.PlanSHA256 != m.PlanSHA256 || rec.AttemptSHA256 != m.AttemptSHA256 {
		t.Errorf("record %+v", rec)
	}
	if rec.PrevRecordSHA256 != "" || rec.TrustSequence != 1 {
		t.Errorf("the first record names %q before it and the sequence %d", rec.PrevRecordSHA256, rec.TrustSequence)
	}
	if rec.StartedAt != "2026-11-20T10:00:00Z" || rec.FinishedAt != "2026-11-20T10:05:00Z" {
		t.Errorf("started_at %s finished_at %s", rec.StartedAt, rec.FinishedAt)
	}
	if rec.BirthsSHA256 != digestOf(t, filepath.Join(m.Dir, "history", m.Ceremony, "births.jsonl")) || rec.SignaturesSHA256 != digestOf(t, filepath.Join(m.Dir, "history", m.Ceremony, "signatures.jsonl")) {
		t.Error("the record does not name the digests of the journals")
	}
	if rec.Root == nil || rec.Root.Label != "A" || rec.Root.X509 != m.Pins[0] || !rec.Root.Test {
		t.Errorf("root %+v, pins %v", rec.Root, m.Pins)
	}
	listed := map[string]bool{}
	for _, a := range rec.Artifacts {
		listed[a.Path] = true
	}
	for _, p := range []string{"roots/A/root.json", "roots/B/root.json", "trust/" + m.Set + "/root-list.json", "trust/" + m.Set + "/root-list.jws", "trust/" + m.Set + "/ca-bundle.pem"} {
		if !listed[p] {
			t.Errorf("the record does not list %s: %v", p, rec.Artifacts)
		}
	}
	if len(rec.Wanted) != 2 {
		t.Errorf("wanted = %v", rec.Wanted)
	}
	// The members that the record page gives for the first apply: where it ran, that the accepted
	// limit was shown, and how it was confirmed.
	v := jsonOf(t, data)
	if v["ran_on"] != "workstation" || v["limit_shown"] != true {
		t.Errorf("ran_on %v, limit_shown %v", v["ran_on"], v["limit_shown"])
	}
	if by := rec.Confirmation; by == nil || (by.By != "typed" && by.By != "flag") || by.At != "2026-11-20T10:00:00Z" {
		t.Errorf("confirmation %+v", rec.Confirmation)
	}
}

// The record page says that limit_shown is a member of the first apply only (record 0005, rule 20:
// the first apply prints the accepted limit). A record that More adds is the record of a later apply.
func TestARecordOfALaterApplyDoesNotSayTheLimitWasShown(t *testing.T) {
	m := ceremonytest.More(t, ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded}), 2)
	_, in := check(t, m.Dir)
	for i, c := range in.State.Chain {
		v := jsonOf(t, readFile(t, m.Dir, "history", c.Folder, "record.json"))
		_, has := v["limit_shown"]
		if i == 0 && v["limit_shown"] != true {
			t.Errorf("the first record: limit_shown = %v", v["limit_shown"])
		}
		if i > 0 && has {
			t.Errorf("record %d (%s) has limit_shown = %v: only the first apply has it", i, c.Folder, v["limit_shown"])
		}
	}
}

// A bundle that More continues is a bundle that More made: no record after the first says the limit
// was shown, however the calls are split, and the first record still does.
func TestNoRecordAfterTheFirstSaysTheLimitWasShown(t *testing.T) {
	base := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	m := ceremonytest.More(t, ceremonytest.More(t, base, 1), 2)
	_, in := check(t, m.Dir)
	if len(in.State.Chain) != 4 {
		t.Fatalf("the chain holds %d records, want 4", len(in.State.Chain))
	}
	for i, c := range in.State.Chain {
		raw := readFile(t, m.Dir, "history", c.Folder, "record.json")
		if got := strings.Contains(string(raw), `"limit_shown"`); got != (i == 0) {
			t.Errorf("record %d (%s): limit_shown present = %v", i, c.Folder, got)
		}
	}
}

// The public files that More writes have the modes of those of a real ceremony.
func TestMoreFilesHaveTheModesOfARealCeremony(t *testing.T) {
	m := ceremonytest.More(t, ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded}), 1)
	mode := func(p ...string) os.FileMode {
		t.Helper()
		fi, err := os.Stat(filepath.Join(append([]string{m.Dir}, p...)...))
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}
	_, in := check(t, m.Dir)
	first, second := in.State.Lists[0].Name, in.State.Lists[1].Name
	if a, b := mode("trust", first, "root-list.json"), mode("trust", second, "root-list.json"); a != b {
		t.Errorf("root-list.json: %v in the real set, %v in the synthetic one", a, b)
	}
	if a, b := mode("roots", "A", "root.json"), mode("roots", "C", "root.json"); a != b {
		t.Errorf("root.json: %v in the real ceremony, %v in the synthetic one", a, b)
	}
	if a, b := mode("history", in.State.Chain[0].Folder, "record.json"), mode("history", in.State.Chain[1].Folder, "record.json"); a != b {
		t.Errorf("record.json: %v, %v", a, b)
	}
	for _, name := range []string{"births.jsonl", "signatures.jsonl", "attempt.json", "plan.json", "transcript.txt"} {
		if a, b := mode("history", in.State.Chain[0].Folder, name), mode("history", in.State.Chain[1].Folder, name); a != b {
			t.Errorf("%s: %v, %v", name, a, b)
		}
	}
	if a, b := mode("trust", first), mode("trust", second); a != b {
		t.Errorf("the folder of the set: %v, %v", a, b)
	}
}

// A run that stops for a reason that no step asked for fails the test, and does not leave a bundle
// that looks like a step: here the key directory holds the key file of the first key already, and
// the store refuses to make a key where one is.
func TestARunThatStopsForAnotherReasonFailsTheTest(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "A.x509.key.pem"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, step := range []ceremonytest.Step{ceremonytest.AtFirstBirth, ceremonytest.AtBirths, ceremonytest.Recorded} {
		dir := filepath.Join(t.TempDir(), "ca")
		msg := failsWith(t, func(tb testing.TB) {
			ceremonytest.Bundle(tb, ceremonytest.Options{Step: step, Dir: dir, KeyDir: keyDir})
		})
		if msg == "" {
			t.Errorf("%s: no message", step)
		}
	}
	// A cut that is not the asked one is a fault in the same way.
	dir := filepath.Join(t.TempDir(), "ca")
	msg := failsWith(t, func(tb testing.TB) {
		ceremonytest.AfterWrites(tb, ceremonytest.Options{Dir: dir, KeyDir: keyDir}, 1000)
	})
	if !strings.Contains(msg, "not asked for") {
		t.Errorf("message %q", msg)
	}
}

// What More writes into the plan of a synthetic ceremony: the sequence, the base it follows, the
// record before it, the key it makes and the three signatures of a ceremony that adds one key.
func TestMoreWritesAPlanThatNamesTheEnd(t *testing.T) {
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	prev := digestOf(t, filepath.Join(m.Dir, "history", m.Ceremony, "record.json"))
	out := ceremonytest.More(t, m, 1)
	plan, err := files.ReadPlan(readFile(t, m.Dir, "history", out.Ceremony, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if *plan.TrustSequence != 2 || plan.BaseSequence != 1 || plan.LastRecordSHA256 != prev || plan.Command != "apply" || plan.Ceremony != out.Ceremony {
		t.Errorf("plan: sequence %d base %d last %q", *plan.TrustSequence, plan.BaseSequence, plan.LastRecordSHA256)
	}
	if plan.Root == nil || plan.Root.Label != "C" || len(plan.Signatures) != 3 || len(plan.Births) != 1 || len(plan.Applies) != 1 {
		t.Errorf("plan: root %+v, %d signatures, %d births, %d applies", plan.Root, len(plan.Signatures), len(plan.Births), len(plan.Applies))
	}
	text := string(readFile(t, m.Dir, "history", out.Ceremony, "plan.json"))
	if !strings.Contains(text, `"place":"C.x509.key.pem"`) || !strings.Contains(text, `"object":"x509/C"`) {
		t.Errorf("the plan does not name the key C: %s", text)
	}
	rec, err := files.ReadRecord(readFile(t, m.Dir, "history", out.Ceremony, "record.json"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.PrevRecordSHA256 != prev || rec.TrustSequence != 2 || rec.Root == nil || rec.Root.X509 != out.Pins[2] {
		t.Errorf("record: prev %q sequence %d root %+v", rec.PrevRecordSHA256, rec.TrustSequence, rec.Root)
	}
	// Its journals hold one birth line and three signature lines.
	if got := lines(t, filepath.Join(m.Dir, "history", out.Ceremony, "births.jsonl")); got != 1 {
		t.Errorf("births.jsonl has %d lines", got)
	}
	if got := lines(t, filepath.Join(m.Dir, "history", out.Ceremony, "signatures.jsonl")); got != 3 {
		t.Errorf("signatures.jsonl has %d lines", got)
	}
}
