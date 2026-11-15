package ceremony

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// birthLineBytes is a canonical line of the birth journal, with its line feed.
func birthLineBytes(t testing.TB, label, purpose, store, place string) []byte {
	t.Helper()
	b, err := (&files.BirthLine{
		At: "2026-11-14T10:00:00Z", Label: label, Purpose: purpose, Store: store, Place: place,
		PublicKeySHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// FuzzBirthsAgainstThePlan feeds the comparison of the birth journal with the births of a plan
// with any list of births (as JSON) and any bytes of a journal. The laws: it never panics; every
// refusal is of kind ErrDiskMismatch; and an accepted journal has one line for each birth, in
// the order of the plan, each line read by the reader of the journal, no pair of label and purpose
// twice (a label may be born twice, once for each purpose), and in each member that the birth gives (label, purpose, store, place) the very text of the line.
func FuzzBirthsAgainstThePlan(f *testing.F) {
	a := birthLineBytes(f, "A", "x509-root", "software", "A.x509.key.pem")
	b := birthLineBytes(f, "B", "x509-root", "kms", "arn:aws:kms:eu-west-1:1:key/b")
	plan := func(s string) []byte { return []byte(s) }
	f.Add(plan(`[{"label":"A","purpose":"x509-root","store":"software","place":"A.x509.key.pem"}]`), a)
	f.Add(plan(`[{"label":"A"},{"label":"B","store":"kms"}]`), append(append([]byte{}, a...), b...))
	f.Add(plan(`[{"label":"A"},{"label":"B"}]`), append(append([]byte{}, b...), a...))
	f.Add(plan(`[]`), []byte(nil))
	f.Add(plan(`[]`), a)
	f.Add(plan(`[5]`), a)
	f.Add(plan(`["A"]`), a)
	f.Add(plan(`[{"label":5}]`), a)
	f.Add(plan(`[{"purpose":"x509-root"}]`), a)
	f.Add(plan(`[{"label":"A","store":7}]`), a)
	f.Add(plan(`[{"label":"A"},{"label":"A"}]`), append(append([]byte{}, a...), a...))
	p := birthLineBytes(f, "A", "openpgp-primary", "software", "A.openpgp.key.asc")
	f.Add(plan(`[{"label":"A","purpose":"x509-root"},{"label":"A","purpose":"openpgp-primary"}]`), append(append([]byte{}, a...), p...))
	f.Add(plan(`[{"label":"A","purpose":"openpgp-primary"},{"label":"A","purpose":"x509-root"}]`), append(append([]byte{}, a...), p...))
	f.Add(plan(`[{"label":"A","purpose":"openpgp-primary"},{"label":"A","purpose":"openpgp-primary"}]`), append(append([]byte{}, p...), p...))
	f.Add(plan(`[{"label":"A","place":null}]`), a)
	f.Fuzz(func(t *testing.T, planJSON, journal []byte) {
		var births []any
		if json.Unmarshal(planJSON, &births) != nil {
			return
		}
		lines, ok := journalLines(journal)
		if !ok {
			return
		}
		r := &recordReader{op: "record"}
		err := r.births(&files.Plan{Births: births}, lines)
		if err != nil {
			if !errors.Is(err, ErrDiskMismatch) {
				t.Fatalf("a refusal of kind %v: %v", err, err)
			}
			return
		}
		if len(lines) != len(births) {
			t.Fatalf("%d lines accepted for %d births", len(lines), len(births))
		}
		seen := map[[2]string]bool{}
		for i, raw := range lines {
			l, rerr := files.ReadBirthLine(raw)
			if rerr != nil {
				t.Fatalf("line %d accepted and its reader refuses it: %v", i, rerr)
			}
			if seen[[2]string{l.Label, l.Purpose}] {
				t.Fatalf("the key %s for the purpose %s accepted twice", l.Label, l.Purpose)
			}
			seen[[2]string{l.Label, l.Purpose}] = true
			m, isMap := births[i].(map[string]any)
			if !isMap {
				t.Fatalf("birth %d is not an object and was accepted", i)
			}
			if _, has := m["label"].(string); !has {
				t.Fatalf("birth %d has no label and was accepted", i)
			}
			for name, got := range map[string]string{"label": l.Label, "purpose": l.Purpose, "store": l.Store, "place": l.Place} {
				if v, has := m[name]; has {
					if s, _ := v.(string); s != got {
						t.Fatalf("birth %d: %s %v of the plan accepted for %q of the line", i, name, v, got)
					}
				}
			}
		}
	})
}

// FuzzRecordArtifactPaths feeds the judgement of the artifact paths of a record with any list of
// paths (one for each line of the input), over a bundle that holds a few files. The laws: it never
// panics; an accepted list has no two paths that are equal when the letters are lower-cased, no
// path that fails the rule for paths of the bundle or is under history/, the digests of the
// files that are there, and stands in the byte order of the path text.
func FuzzRecordArtifactPaths(f *testing.F) {
	dir := f.TempDir()
	for p, text := range map[string]string{"a": "1", "b/c": "2", "b/d": "3", "x-y": "4", "Q/z.json": "5"} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			f.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			f.Fatal(err)
		}
	}
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		f.Fatal(err)
	}
	w := &fsx.Writer{FS: fsys}
	f.Cleanup(func() { _ = w.Close() })
	folder, err := NewFolder(w, "20261114T100000Z-apply")
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"a", "a\nb/c", "b/d\nb/c\nx-y", "a\nA", "Q/z.json\nq/z.json", "b/c\nb/c", "history/x", "History/x", "", "a\n\nb/c", "../a", "b/c\nB/d\nx-y\nb/D"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		paths := strings.Split(string(in), "\n")
		if len(paths) > maxArtifacts+1 {
			return
		}
		r := &recordReader{f: folder, op: "record"}
		var rec files.Record
		if err := r.artifacts(paths, &rec); err != nil {
			return
		}
		seen := map[string]bool{}
		for _, p := range paths {
			if files.CheckPath(p) != nil {
				t.Fatalf("accepted the path %q that the rule refuses", p)
			}
			if strings.HasPrefix(strings.ToLower(p), "history/") {
				t.Fatalf("accepted %q under history/", p)
			}
			if seen[strings.ToLower(p)] {
				t.Fatalf("accepted two paths that are one when the case is dropped: %q", p)
			}
			seen[strings.ToLower(p)] = true
		}
		if len(rec.Artifacts) != len(paths) {
			t.Fatalf("%d artifacts for %d paths", len(rec.Artifacts), len(paths))
		}
		for i, a := range rec.Artifacts {
			if i > 0 && rec.Artifacts[i-1].Path >= a.Path {
				t.Fatalf("artifacts out of byte order: %q then %q", rec.Artifacts[i-1].Path, a.Path)
			}
			b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(a.Path)))
			if err != nil {
				t.Fatalf("an artifact that is not there was accepted: %v", err)
			}
			if a.SHA256 != files.Digest(b) {
				t.Fatalf("the digest of %q is not the digest of the file", a.Path)
			}
		}
	})
}

var (
	x509Form    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	openPGPForm = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// FuzzRecordInRoot feeds the check of the two fingerprints of the root with any two texts. The
// laws: it never panics, and the root is accepted exactly when each fingerprint is empty or of the
// form of the page (64 lower-case hexadecimal digits for X.509, 40 for OpenPGP); a refusal is of
// kind ErrInvalidInput.
func FuzzRecordInRoot(f *testing.F) {
	f.Add(strings.Repeat("a", 64), strings.Repeat("b", 40))
	f.Add("", "")
	f.Add(strings.Repeat("a", 63), "")
	f.Add("", strings.Repeat("b", 41))
	f.Add(strings.Repeat("A", 64), strings.Repeat("B", 40))
	f.Add(strings.Repeat("g", 64), strings.Repeat("/", 40))
	f.Add(strings.Repeat("a", 64)+"\n", strings.Repeat("b", 40)+"\n")
	f.Fuzz(func(t *testing.T, x509, openpgp string) {
		in := RecordIn{
			Command: files.CommandApply, Outcome: files.OutcomeCompleted,
			Root: &files.PlanRoot{Label: "A", X509: x509, OpenPGP: openpgp},
		}
		err := checkRecordIn("record", in)
		want := (x509 == "" || x509Form.MatchString(x509)) && (openpgp == "" || openPGPForm.MatchString(openpgp))
		if (err == nil) != want {
			t.Fatalf("x509 %q, openpgp %q: error %v, want accepted: %v", x509, openpgp, err, want)
		}
		if err != nil && !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("a refusal of the wrong kind: %v", err)
		}
	})
}
