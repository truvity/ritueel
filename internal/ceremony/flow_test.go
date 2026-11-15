package ceremony_test

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// canonicalFile fails unless the file is in the canonical form of RFC 8785.
func canonicalFile(t *testing.T, what string, b []byte) {
	t.Helper()
	ok, err := canonjson.IsCanonical(b)
	if err != nil || !ok {
		t.Errorf("%s is not canonical (err %v)", what, err)
	}
	if bytes.HasSuffix(b, []byte("\n")) {
		t.Errorf("%s ends with a line feed; the canonical files have none", what)
	}
}

// Two synthetic ceremonies through Folder, read back by the readers that judge each file, with
// every digest made here from the files on the disk.
func TestTwoCeremoniesThroughFolderAreRecordedAndChecked(t *testing.T) {
	b := newBundle(t)
	s1 := newSpec(name1, 1, "")
	f1 := newFlow(t, b, s1)
	f1.must("")
	rec1 := f1.out

	s2 := newSpec(name2, 2, sum(rec1))
	f2 := newFlow(t, b, s2)
	f2.must("")
	rec2 := f2.out

	for _, fl := range []*flow{f1, f2} {
		s := fl.s
		plan := fl.file("plan.json")
		p, err := files.ReadPlan(plan)
		if err != nil {
			t.Fatalf("%s: ReadPlan: %v", s.name, err)
		}
		if p.Ceremony != s.name {
			t.Errorf("plan names %q", p.Ceremony)
		}
		canonicalFile(t, s.name+"/plan.json", plan)

		attempt := fl.file("attempt.json")
		a, err := files.ReadAttempt(attempt)
		if err != nil {
			t.Fatalf("%s: ReadAttempt: %v", s.name, err)
		}
		if a.PlanSHA256 != sum(plan) || a.Ceremony != s.name || a.Version != 1 {
			t.Errorf("attempt %+v does not name the plan %s", a, sum(plan))
		}
		canonicalFile(t, s.name+"/attempt.json", attempt)

		births := bytes.Split(bytes.TrimSuffix(fl.file("births.jsonl"), []byte("\n")), []byte("\n"))
		if len(births) != 1 {
			t.Fatalf("births.jsonl holds %d lines, want 1", len(births))
		}
		bl, err := files.ReadBirthLine(births[0])
		if err != nil || bl.Label != s.label || bl.PublicKeySHA256 != s.pin {
			t.Errorf("birth line %+v, %v", bl, err)
		}
		sigs := bytes.Split(bytes.TrimSuffix(fl.file("signatures.jsonl"), []byte("\n")), []byte("\n"))
		if len(sigs) != 3 {
			t.Fatalf("signatures.jsonl holds %d lines, want 3", len(sigs))
		}
		for i, l := range sigs {
			sl, err := files.ReadSignatureLine(l)
			if err != nil || sl.N != int64(i+1) {
				t.Errorf("signature line %d: %+v, %v", i+1, sl, err)
			}
		}
		if !bytes.HasSuffix(fl.file("births.jsonl"), []byte("\n")) || !bytes.HasSuffix(fl.file("signatures.jsonl"), []byte("\n")) {
			t.Error("a journal does not end with a line feed")
		}
	}

	// The record of each ceremony lists the digests of the files as they are on the disk.
	for i, fl := range []*flow{f1, f2} {
		s := fl.s
		raw := fl.file("record.json")
		if !bytes.Equal(raw, fl.out) {
			t.Errorf("%s: the bytes returned by Record are not the bytes of record.json", s.name)
		}
		canonicalFile(t, s.name+"/record.json", raw)
		r, err := files.ReadRecord(raw)
		if err != nil {
			t.Fatalf("%s: ReadRecord: %v", s.name, err)
		}
		if r.Ceremony != s.name || r.Command != "apply" || r.Outcome != "completed" || r.Version != 1 {
			t.Errorf("%s: the head of the record is %+v", s.name, r)
		}
		if r.PlanSHA256 != sum(fl.file("plan.json")) {
			t.Errorf("%s: plan_sha256 is not the digest of plan.json", s.name)
		}
		if r.AttemptSHA256 != sum(fl.file("attempt.json")) {
			t.Errorf("%s: attempt_sha256 is not the digest of attempt.json", s.name)
		}
		if r.BirthsSHA256 != sum(fl.file("births.jsonl")) || r.SignaturesSHA256 != sum(fl.file("signatures.jsonl")) {
			t.Errorf("%s: a journal digest is not the digest of its file", s.name)
		}
		if r.TranscriptSHA256 != sum(fl.file("transcript.txt")) {
			t.Errorf("%s: transcript_sha256 is not the digest of transcript.txt", s.name)
		}
		if len(r.Wanted) != len(s.copies) {
			t.Fatalf("%s: wanted lists %d files", s.name, len(r.Wanted))
		}
		for _, w := range r.Wanted {
			if got := sum(fl.b.read("history", s.name, "wanted", filepath.FromSlash(w.Path))); got != w.SHA256 {
				t.Errorf("%s: wanted %s: digest %s, the file has %s", s.name, w.Path, w.SHA256, got)
			}
		}
		if len(r.Artifacts) != 2 {
			t.Fatalf("%s: artifacts %+v", s.name, r.Artifacts)
		}
		for _, a := range r.Artifacts {
			if got := sum(fl.b.read(filepath.FromSlash(a.Path))); got != a.SHA256 {
				t.Errorf("%s: artifact %s: digest %s, the file has %s", s.name, a.Path, a.SHA256, got)
			}
		}
		if r.Artifacts[0].Path >= r.Artifacts[1].Path {
			t.Errorf("%s: artifacts are not in path order: %+v", s.name, r.Artifacts)
		}
		if i == 0 && r.PrevRecordSHA256 != "" {
			t.Errorf("the first record has prev_record_sha256 %q", r.PrevRecordSHA256)
		}
		if i == 1 && r.PrevRecordSHA256 != sum(rec1) {
			t.Errorf("the second record has prev_record_sha256 %q, want the digest of record 1", r.PrevRecordSHA256)
		}
		if r.TrustSequence != int64(s.seq) {
			t.Errorf("%s: trust_sequence %d, want %d", s.name, r.TrustSequence, s.seq)
		}
		// What the record carries from the plan and what the caller gave.
		if r.RanOn != "workstation" || !r.LimitShown || r.Confirmation == nil || r.Confirmation.By != "flag" {
			t.Errorf("%s: the caller's members are lost: %+v", s.name, r)
		}
		if r.Root == nil || r.Root.X509 != s.pin || !r.Root.Test || !r.Root.Copyable {
			t.Errorf("%s: root is %+v", s.name, r.Root)
		}
		if r.RootReason != "the card of the year is away" {
			t.Errorf("%s: root_reason is %q", s.name, r.RootReason)
		}
		if len(r.Applied) != 1 || len(r.LeftOut) != 1 {
			t.Errorf("%s: applied %v, left_out %v", s.name, r.Applied, r.LeftOut)
		}
		if string(r.Arguments) == "" {
			t.Errorf("%s: arguments of the plan are lost", s.name)
		}
		if r.StartedAt != ts || r.FinishedAt != "2026-11-14T10:05:00Z" {
			t.Errorf("%s: times %q %q", s.name, r.StartedAt, r.FinishedAt)
		}
	}

	// signatures: the plan's own list, each with the digest of the signature, and the key that the
	// plan did not name filled in from the journal.
	r2, _ := files.ReadRecord(rec2)
	if len(r2.Signatures) != 3 {
		t.Fatalf("signatures: %v", r2.Signatures)
	}
	for i, raw := range r2.Signatures {
		m := raw.(map[string]any)
		if m["n"] != int64(i+1) {
			t.Errorf("signature %d has n %v", i+1, m["n"])
		}
		if m["signature_sha256"] != sigDigest(int64(i+1)) {
			t.Errorf("signature %d has signature_sha256 %v", i+1, m["signature_sha256"])
		}
		if m["key"] != s2.pin {
			t.Errorf("signature %d has key %v, want the key of the journal %s", i+1, m["key"], s2.pin)
		}
	}
	m0 := r2.Signatures[0].(map[string]any)
	if m0["derived"] != true || m0["serial"] != "0a0b" || m0["kind"] != "root-certificate" {
		t.Errorf("the plan's members of signature 1 were not kept: %v", m0)
	}
	if _, has := m0["tbs_sha256"]; has {
		t.Error("a derived signature got a tbs_sha256")
	}
	if m2 := r2.Signatures[2].(map[string]any); m2["tbs_sha256"] != rep('f') {
		t.Errorf("signature 3 lost its tbs_sha256: %v", m2)
	}

	// The check of the history says what the page says: two records, one end, the end is record 2.
	report := b.check()
	if !report.Clean() || len(report.Findings) != 0 {
		t.Fatalf("history.Check found %+v", report.Findings)
	}
	eight, n, ok := report.End()
	if !ok || n != 2 || eight != sum(rec2)[:8] {
		t.Errorf("end = %q, %d, %v; want %q and 2 records", eight, n, ok, sum(rec2)[:8])
	}
	if report.EndLine() != "history: 2 ceremony records, end "+sum(rec2)[:8] {
		t.Errorf("the end line is %q", report.EndLine())
	}
	if !reflect.DeepEqual(report.Ends, []string{sum(rec2)}) {
		t.Errorf("ends = %v", report.Ends)
	}
}

// The files of one ceremony folder are those the page lists, and the modes are the ones the
// code gives: the files 0644, the folders 0755, the journals 0600 (before the umask).
func TestCeremonyFolderHoldsTheSevenNamesOfThePageAndTheModes(t *testing.T) {
	b := newBundle(t)
	fl := newFlow(t, b, newSpec(name1, 1, ""))
	fl.must("")
	ents, err := os.ReadDir(b.path("history", name1))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	want := []string{"attempt.json", "births.jsonl", "plan.json", "record.json", "signatures.jsonl", "transcript.txt", "wanted"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the folder holds %v, want %v", got, want)
	}
	for _, c := range []struct {
		path string
		max  os.FileMode
	}{
		{"history", 0o755}, {"history/" + name1, 0o755}, {"history/" + name1 + "/wanted", 0o755},
		{"history/" + name1 + "/wanted/want/roots", 0o755},
		{"history/" + name1 + "/plan.json", 0o644}, {"history/" + name1 + "/wanted/ritueel.yaml", 0o644},
		{"history/" + name1 + "/attempt.json", 0o644}, {"history/" + name1 + "/transcript.txt", 0o644},
		{"history/" + name1 + "/record.json", 0o644},
		{"history/" + name1 + "/births.jsonl", 0o600}, {"history/" + name1 + "/signatures.jsonl", 0o600},
	} {
		st, err := os.Stat(b.path(filepath.FromSlash(c.path)))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&^c.max != 0 {
			t.Errorf("%s has the mode %v, more than %v", c.path, st.Mode().Perm(), c.max)
		}
		if strings.HasSuffix(c.path, ".jsonl") && st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is readable by others: %v", c.path, st.Mode().Perm())
		}
	}
	// The copies keep the paths they have in the bundle, under wanted/.
	for _, c := range fl.s.copies {
		if got := b.read("history", name1, "wanted", filepath.FromSlash(c.Path)); !bytes.Equal(got, c.Data) {
			t.Errorf("copy %s is not the bytes that were given", c.Path)
		}
	}
}

// The order the page gives: the plan and the copies, the attempt, the journals, the transcript,
// the artifacts, and the record last. A recording file system sees the files appear in that order.
func TestFilesAppearInTheOrderOfThePage(t *testing.T) {
	b := newBundle(t)
	fl := newFlow(t, b, newSpec(name1, 1, ""))
	fl.must("")
	var seen []string
	for _, e := range b.r.snapshot() {
		verb, path, _ := strings.Cut(e, " ")
		if verb == "rename" || verb == "create" || verb == "mkdir" {
			seen = append(seen, path)
		}
	}
	d := "history/" + name1 + "/"
	want := []string{
		"history", "history/" + name1, d + "plan.json", d + "wanted",
		d + "wanted/ritueel.yaml",
		d + "wanted/want", d + "wanted/want/roots", d + "wanted/want/roots/x509.yaml",
		d + "attempt.json", d + "births.jsonl", d + "signatures.jsonl",
		d + "transcript.txt",
		"roots", "trust", "roots/A", "roots/A/root.json", "trust/1-00000001",
		d + "record.json",
	}
	// The trust set is made under a temporary folder and renamed: the rename names the final path.
	var got []string
	for _, p := range seen {
		if strings.Contains(p, "/.rt-") || strings.HasPrefix(p, ".rt-") {
			continue
		}
		got = append(got, p)
	}
	// the copies are written in the order of the plan's wanted list, which is path order.
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the files appeared in this order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got[len(got)-1] != d+"record.json" {
		t.Error("the record is not the last file")
	}
}
