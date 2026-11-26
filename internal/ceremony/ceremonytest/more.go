package ceremonytest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/wanted"
)

// More adds to a bundle that has a recorded ceremony n more synthetic ceremonies: each has a
// hand-made plan that names the end of the history, a birth line, three signature lines, a root list
// of the next sequence that holds the keys of the list before and one more, the root.json of the
// new key, and a record. The keys are not real: a pin is a digest of a text, no key file is made, and
// the root list is not signed (the check of the history reads none of that). It is for tests of join
// and status that need two or more records. The bundle must be one that the check of the history
// accepts, whose order of root lists has one reading, with no open attempt. It returns a copy of m
// that names the newest ceremony; m is not changed. It fails the test on any error.
func More(t testing.TB, m *Made, n int) *Made {
	t.Helper()
	if m == nil || m.Dir == "" {
		t.Fatalf("ceremonytest: More needs a bundle made by Bundle")
	}
	if n < 1 {
		t.Fatalf("ceremonytest: More needs a number of ceremonies of at least 1, got %d", n)
	}
	out := *m
	out.Pins = slices.Clone(m.Pins)
	for range n {
		more(t, &out)
	}
	return &out
}

// synth is one hand-made ceremony.
type synth struct {
	name, label, pin string
	at               time.Time
	seq              int64
	end              string // the digest of the record before it
	copies           []wanted.File
	setName          string
	rootList         []byte
}

// more makes one more ceremony after the end of the history of m, and updates m.
func more(t testing.TB, m *Made) {
	t.Helper()
	st := stateOf(t, m.Dir)
	if st.Records < 1 || st.Newest == nil {
		t.Fatalf("ceremonytest: More needs a bundle with a recorded ceremony and a trust set")
	}
	if len(st.Unfinished) > 0 {
		t.Fatalf("ceremonytest: More needs a bundle with no open attempt, and %s is open", st.Unfinished[0])
	}
	s := &synth{end: st.End, seq: st.Newest.Number + 1}
	s.at = m.at.Add(time.Duration(st.Records) * time.Hour)
	s.name = s.at.Format("20060102T150405Z") + "-" + files.CommandApply
	s.label = nextLabel(t, m.Dir)
	sum := sha256.Sum256([]byte("ceremonytest synthetic key " + s.label + " " + s.name))
	s.pin = hex.EncodeToString(sum[:])
	for _, p := range []string{"ritueel.yaml", "want/roots/x509.yaml"} {
		data, err := os.ReadFile(filepath.Join(m.Dir, filepath.FromSlash(p)))
		if err != nil {
			t.Fatalf("ceremonytest: the wanted file %s cannot be read: %v", p, err)
		}
		s.copies = append(s.copies, wanted.File{Path: p, Data: data, SHA256: files.Digest(data)})
	}
	s.rootList = s.nextList(t, st.Newest.ListJSON)
	s.setName = fmt.Sprintf("%d-%s", s.seq, files.Digest(s.rootList)[:8])

	w, err := fsx.Open(m.Dir)
	if err != nil {
		t.Fatalf("ceremonytest: the bundle cannot be opened for writing: %v", err)
	}
	defer func() { _ = w.Close() }()
	plan, attemptSHA := s.write(t, w)

	m.Ceremony, m.PlanSHA256, m.AttemptSHA256 = s.name, plan, attemptSHA
	m.Pins = append(m.Pins, s.pin)
	m.Set = s.setName
	checkMade(t, m, st.Records+1)
}

// checkMade reads the history of the bundle after one more ceremony, and fails the test when the
// ceremony that was just made is not whole: a report with a failing finding, no State, an open
// attempt, or a count of records other than want. A later change of a rule of the check then
// shows up here, at its cause, and not in the test that uses the bundle.
func checkMade(t testing.TB, m *Made, want int) {
	t.Helper()
	fsys, err := fsx.OpenFS(m.Dir)
	if err != nil {
		t.Fatalf("ceremonytest: the bundle cannot be opened: %v", err)
	}
	defer func() { _ = fsys.Close() }()
	in, err := history.Inspect(context.Background(), fsys)
	if err != nil {
		t.Fatalf("ceremonytest: the bundle cannot be inspected: %v", err)
	}
	if failing := in.Report.Failing(); len(failing) > 0 {
		t.Fatalf("ceremonytest: the synthetic ceremony %s makes a bundle that the check of the history fails (%d failing findings, the first: %s)", m.Ceremony, len(failing), failing[0].Line())
	}
	if in.State == nil {
		t.Fatalf("ceremonytest: the synthetic ceremony %s makes a bundle with no state: %v", m.Ceremony, in.OrderErr)
	}
	if in.State.Records != want || len(in.State.Unfinished) > 0 {
		t.Fatalf("ceremonytest: the synthetic ceremony %s makes a bundle with %d records (want %d) and %d open attempts (want 0)", m.Ceremony, in.State.Records, want, len(in.State.Unfinished))
	}
}

// stateOf is the state of the history of the bundle, and fails the test when there is none.
func stateOf(t testing.TB, dir string) *history.State {
	t.Helper()
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatalf("ceremonytest: the bundle cannot be opened: %v", err)
	}
	defer func() { _ = fsys.Close() }()
	in, err := history.Inspect(context.Background(), fsys)
	if err != nil {
		t.Fatalf("ceremonytest: the bundle cannot be inspected: %v", err)
	}
	if in.State == nil {
		t.Fatalf("ceremonytest: the bundle has no state (%d findings, %v)", len(in.Report.Findings), in.OrderErr)
	}
	return in.State
}

// nextLabel is the letter after the highest label of one letter that roots/ holds.
func nextLabel(t testing.TB, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, "roots"))
	if err != nil {
		t.Fatalf("ceremonytest: roots/ cannot be listed: %v", err)
	}
	next := byte('A')
	for _, e := range ents {
		if n := e.Name(); len(n) == 1 && n[0] >= 'A' && n[0] <= 'Z' && n[0] >= next {
			next = n[0] + 1
		}
	}
	if next > 'Z' {
		t.Fatalf("ceremonytest: there is no label left after Z")
	}
	return string(next)
}

// nextList is the root list of the next sequence: the members of the list before, the keys of it and
// the new one, the next sequence and the digest of the record before.
func (s *synth) nextList(t testing.TB, prev []byte) []byte {
	t.Helper()
	var top any
	dec := json.NewDecoder(bytes.NewReader(prev))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		t.Fatalf("ceremonytest: the root list before cannot be read: %v", err)
	}
	list, ok := top.(map[string]any)
	if !ok {
		t.Fatalf("ceremonytest: the root list before is not a JSON object")
	}
	for k, v := range list {
		list[k] = integers(t, v)
	}
	roots, _ := list["roots"].([]any)
	list["roots"] = append(roots, map[string]any{"label": s.label, "x509_spki_sha256": s.pin})
	list["sequence"] = s.seq
	list["last_record_sha256"] = s.end
	b, err := canonjson.Marshal(list)
	if err != nil {
		t.Fatalf("ceremonytest: the root list cannot be written: %v", err)
	}
	return b
}

// integers turns the numbers of a decoded value into integers: the canonical form of ritueel holds
// integers only, and a number that is not one fails the test.
func integers(t testing.TB, v any) any {
	t.Helper()
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			t.Fatalf("ceremonytest: the root list before holds a number that is not an integer: %v", x)
		}
		return n
	case []any:
		for i := range x {
			x[i] = integers(t, x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = integers(t, x[k])
		}
	}
	return v
}

// planBytes is the plan of the ceremony.
func (s *synth) planBytes(t testing.TB) []byte {
	t.Helper()
	refs := make([]any, 0, len(s.copies))
	for _, c := range s.copies {
		refs = append(refs, map[string]any{"path": c.Path, "sha256": c.SHA256})
	}
	at := s.at.Format(time.RFC3339)
	m := map[string]any{
		"version":        1,
		"ceremony":       s.name,
		"command":        "apply",
		"made_at":        at,
		"ceremony_time":  at,
		"wanted":         refs,
		"applies":        []any{map[string]any{"change": "create", "object": "x509/" + s.label}},
		"root":           map[string]any{"label": s.label, "store": "software", "test": true, "copyable": true},
		"trust_sequence": s.seq,
		"base_sequence":  s.seq - 1,
		"signatures": []any{
			map[string]any{"n": 1, "kind": "root-certificate", "subject": s.label, "derived": true, "serial": "0a0b", "not_before": at, "not_after": s.at.AddDate(1, 1, 0).Format(time.RFC3339)},
			map[string]any{"n": 2, "kind": "root-removal", "subject": s.label, "derived": true},
			map[string]any{"n": 3, "kind": "root-list", "subject": s.label, "key": s.pin, "tbs_sha256": files.Digest([]byte("tbs " + s.name))},
		},
		"births":             []any{map[string]any{"label": s.label, "purpose": "x509-root", "store": "software", "place": "x509-root-" + strings.ToLower(s.label)}},
		"last_record_sha256": s.end,
	}
	b, err := canonjson.Marshal(m)
	if err != nil {
		t.Fatalf("ceremonytest: the plan cannot be written: %v", err)
	}
	return b
}

// write runs the ceremony through a folder and returns the digests of its plan and attempt.
func (s *synth) write(t testing.TB, w *fsx.Writer) (planSHA, attemptSHA string) {
	t.Helper()
	at := s.at.Format(time.RFC3339)
	plan := s.planBytes(t)
	f, err := ceremony.NewFolder(w, s.name)
	if err != nil {
		t.Fatalf("ceremonytest: %v", err)
	}
	must := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("ceremonytest: the synthetic ceremony %s stopped at %s: %v", s.name, what, err)
		}
	}
	must("the plan", f.WritePlan(plan, s.copies))
	attempt := files.Attempt{Version: files.FormatVersion, Ceremony: s.name, PlanSHA256: files.Digest(plan), Root: s.label, StartedAt: at}
	raw, err := attempt.Canonical()
	must("the attempt", err)
	tr, err := f.Start(attempt)
	must("the attempt", err)
	birth, err := (&files.BirthLine{At: at, Label: s.label, Purpose: "x509-root", Store: "software", Place: "x509-root-" + strings.ToLower(s.label), PublicKeySHA256: s.pin}).Canonical()
	must("the birth line", err)
	must("the birth journal", tr.Births().Append(birth))
	for i, kind := range []string{"root-certificate", "root-removal", "root-list"} {
		n := int64(i + 1)
		line, err := (&files.SignatureLine{At: at, N: n, Kind: kind, Key: s.pin, SignatureSHA256: files.Digest([]byte("signature " + strconv.FormatInt(n, 10) + " " + s.name))}).Canonical()
		must("a signature line", err)
		must("the journal of signatures", tr.Signatures().Append(line))
	}
	must("the end of the journals", f.End())
	con := ceremony.NewConsole(io.Discard, io.Discard)
	con.Out("synthetic ceremony %s", s.name)
	text, err := con.Transcript()
	must("the transcript", err)
	must("the transcript", f.WriteTranscript(text))

	must("roots/", mkdirIfAbsent(w, "roots"))
	must("trust/", mkdirIfAbsent(w, "trust"))
	must("the root folder", w.Mkdir("roots/"+s.label, 0o755))
	must("root.json", w.WriteFile("roots/"+s.label+"/root.json", []byte(`{"label":"`+s.label+`"}`), 0o644))
	must("the trust set", w.WriteSet("trust/"+s.setName, []fsx.NewFile{{Name: "root-list.json", Data: s.rootList, Perm: 0o644}}))
	// limit_shown is for the first apply only (the record page), so a later ceremony leaves it out.
	_, err = f.Record(ceremony.RecordIn{
		Command: files.CommandApply, Outcome: files.OutcomeCompleted, PrevRecordSHA256: s.end,
		StartedAt: at, FinishedAt: s.at.Add(5 * time.Minute).Format(time.RFC3339),
		Root:         &files.PlanRoot{Label: s.label, Store: "software", X509: s.pin, Test: true, Copyable: true},
		Confirmation: &files.Confirmation{By: "flag", At: at},
		RanOn:        ceremony.RanOnWorkstation,
		Artifacts:    []string{"roots/" + s.label + "/root.json", "trust/" + s.setName + "/root-list.json"},
	})
	must("the record", err)
	return files.Digest(plan), files.Digest(raw)
}

// mkdirIfAbsent makes the folder when it is not there: the writer stops for good at a name that
// exists, so the folder is looked at first.
func mkdirIfAbsent(w *fsx.Writer, name string) error {
	_, err := fsx.ReadDir(w.FS, name)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return w.Mkdir(name, 0o755)
	}
	return err
}
