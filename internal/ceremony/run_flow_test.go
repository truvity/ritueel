//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	bundlepkg "ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/rootlist"
)

// The whole run of the first apply of a software test root through Run, as a person or a script sees
// it: what is written, in which form, what is printed, and what the readers on main say.

// rtWholeTree is every entry that a whole first apply leaves in the bundle, for the plan name and the
// trust set folder given.
func rtWholeTree(name, set string) []string {
	h := "history/" + name
	out := []string{
		"history", h, h + "/attempt.json", h + "/births.jsonl", h + "/plan.json", h + "/record.json",
		h + "/signatures.jsonl", h + "/transcript.txt", h + "/wanted", h + "/wanted/ritueel.yaml",
		h + "/wanted/want", h + "/wanted/want/roots", h + "/wanted/want/roots/x509.yaml",
		"ritueel.yaml", "want", "want/roots", "want/roots/x509.yaml",
		"roots", "roots/A", "roots/A/root.json", "roots/B", "roots/B/root.json",
		"trust", set, set + "/ca-bundle.pem", set + "/root-list.json", set + "/root-list.jws",
	}
	slices.Sort(out)
	return out
}

func TestADirectApplyWithTheFlagWritesTheFilesOfTheFirstApplyAndNoOther(t *testing.T) {
	r := rtNew(t)
	done, p := r.mustDirect()
	if got, want := rtNames(r.tree()), rtWholeTree(p.Name, done.TrustSet); !slices.Equal(got, want) {
		t.Errorf("the bundle holds\n%q\nwant\n%q", got, want)
	}
	keys := rtNames(r.keyTree())
	if want := []string{"A.removal.jws", "B.removal.jws", "test-only-keys", mkKeyFile("A"), mkKeyFile("B")}; !slices.Equal(keys, want) {
		t.Errorf("the key directory holds %q, want %q", keys, want)
	}
	for _, k := range keys {
		st, err := os.Stat(filepath.Join(r.keyDir, k))
		if k == "test-only-keys" {
			if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
				t.Errorf("%s: %v %v, want a folder that nobody but the owner can enter", k, st, err)
			}
			continue
		}
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s: %v %v, want a regular file that nobody but the owner can read", k, st, err)
		}
	}
	// A folder or a file that the run wrote gives its owner the bits the bundle page asks for, and no
	// other person can change it.
	for p := range r.tree() {
		st, err := os.Lstat(filepath.Join(r.bundleDir, p))
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case st.IsDir() && st.Mode().Perm()&0o700 != 0o700:
			t.Errorf("%s: mode %v lacks the owner's read, write and search bits", p, st.Mode())
		case st.Mode().IsRegular() && st.Mode().Perm()&0o400 == 0:
			t.Errorf("%s: mode %v lacks the owner's read bit", p, st.Mode())
		case st.Mode().Perm()&0o022 != 0:
			t.Errorf("%s: mode %v can be changed by someone else", p, st.Mode())
		case !st.IsDir() && !st.Mode().IsRegular():
			t.Errorf("%s: is not a folder or a regular file", p)
		}
	}
}

func TestTheDoneOfARunHoldsWhatWasReadBackFromTheDisk(t *testing.T) {
	r := rtNew(t)
	done, p := r.mustDirect()
	rec, raw := r.record(p.Name)
	if done.Ceremony != p.Name || done.RecordPath != "history/"+p.Name+"/record.json" {
		t.Errorf("Ceremony %q, RecordPath %q", done.Ceremony, done.RecordPath)
	}
	if done.RecordSHA256 != rtHexSum(raw) || done.End != done.RecordSHA256 {
		t.Errorf("RecordSHA256 %q, End %q, want the digest %q of record.json", done.RecordSHA256, done.End, rtHexSum(raw))
	}
	if done.Records != 1 || done.TrustSequence != 1 || rec.TrustSequence != 1 {
		t.Errorf("Records %d, TrustSequence %d (record %d), want 1, 1", done.Records, done.TrustSequence, rec.TrustSequence)
	}
	if want := "history: 1 ceremony records, end " + done.End[:8]; done.EndLine != want {
		t.Errorf("EndLine %q, want %q", done.EndLine, want)
	}
	list := r.b.read(filepath.FromSlash(done.TrustSet), "root-list.json")
	if want := "trust/1-" + rtHexSum(list)[:8]; done.TrustSet != want {
		t.Errorf("TrustSet %q, want %q: the number and the first eight characters of the digest of root-list.json", done.TrustSet, want)
	}
	if len(done.Artifacts) != 5 || len(rec.Artifacts) != 5 {
		t.Fatalf("%d artifacts (record %d), want 5", len(done.Artifacts), len(rec.Artifacts))
	}
	for i, a := range done.Artifacts {
		if a != rec.Artifacts[i] {
			t.Errorf("artifact %d: %+v, the record lists %+v", i, a, rec.Artifacts[i])
		}
		if got := rtHexSum(r.b.read(filepath.FromSlash(a.Path))); got != a.SHA256 {
			t.Errorf("%s: the digest is %s, the file has %s", a.Path, a.SHA256, got)
		}
	}
	paths := make([]string, 0, 5)
	for _, a := range done.Artifacts {
		paths = append(paths, a.Path)
	}
	want := []string{"roots/A/root.json", "roots/B/root.json", done.TrustSet + "/ca-bundle.pem", done.TrustSet + "/root-list.json", done.TrustSet + "/root-list.jws"}
	if !slices.Equal(paths, want) {
		t.Errorf("artifacts %q, want %q (path order)", paths, want)
	}
	if len(done.Roots) != 2 {
		t.Fatalf("%d roots", len(done.Roots))
	}
	for i, root := range done.Roots {
		label := string(rune('A' + i))
		if root.Label != label || root.Store != "software" || !root.Test || len(root.X509SPKISHA256) != 64 || root.NotAfter != "2029-11-20T10:00:00Z" {
			t.Errorf("root %d = %+v", i, root)
		}
	}
	if done.Roots[0].X509SPKISHA256 == done.Roots[1].X509SPKISHA256 {
		t.Error("the two roots have one pin")
	}
}

func TestTheRecordOfTheFirstApplyHasTheMembersOfThePageAndNoOther(t *testing.T) {
	r := rtNew(t)
	done, p := r.mustDirect()
	rec, raw := r.record(p.Name)
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range members {
		got = append(got, k)
	}
	slices.Sort(got)
	want := []string{"applied", "artifacts", "attempt_sha256", "births_sha256", "ceremony", "command", "confirmation", "finished_at", "limit_shown", "outcome", "plan_sha256", "ran_on", "root", "signatures", "signatures_sha256", "started_at", "transcript_sha256", "trust_sequence", "version", "wanted"}
	if !slices.Equal(got, want) {
		t.Errorf("the record has the members %q, want %q (no backend, no warnings, no arguments, no prev_record_sha256)", got, want)
	}
	if rec.Version != 1 || rec.Ceremony != p.Name || rec.Command != files.CommandApply || rec.Outcome != files.OutcomeCompleted || rec.PlanSHA256 != p.SHA256 {
		t.Errorf("record head %+v", rec)
	}
	if rec.PrevRecordSHA256 != "" {
		t.Errorf("prev_record_sha256 = %q in the first record of a history", rec.PrevRecordSHA256)
	}
	if rec.Root == nil || rec.Root.Label != "A" || rec.Root.Store != "software" || rec.Root.X509 != done.Roots[0].X509SPKISHA256 || !rec.Root.Test || !rec.Root.Copyable || rec.Root.OpenPGP != "" {
		t.Errorf("root = %+v, want the key A: software, its pin, test and copyable, no OpenPGP", rec.Root)
	}
	if rec.RanOn != "workstation" || !rec.LimitShown {
		t.Errorf("ran_on %q, limit_shown %v", rec.RanOn, rec.LimitShown)
	}
	if rec.Confirmation == nil || rec.Confirmation.By != "flag" {
		t.Errorf("confirmation = %+v, want by flag", rec.Confirmation)
	}
	started, e1 := time.Parse(time.RFC3339, rec.StartedAt)
	finished, e2 := time.Parse(time.RFC3339, rec.FinishedAt)
	confirmed, e3 := time.Parse(time.RFC3339, rec.Confirmation.At)
	if e1 != nil || e2 != nil || e3 != nil || confirmed.After(started) || !finished.After(started) {
		t.Errorf("times: confirmed %q, started %q, finished %q: want confirmed <= started < finished", rec.Confirmation.At, rec.StartedAt, rec.FinishedAt)
	}
	for _, c := range []struct {
		name, file, got string
	}{
		{"attempt_sha256", "attempt.json", rec.AttemptSHA256},
		{"births_sha256", "births.jsonl", rec.BirthsSHA256},
		{"signatures_sha256", "signatures.jsonl", rec.SignaturesSHA256},
		{"transcript_sha256", "transcript.txt", rec.TranscriptSHA256},
	} {
		if want := rtHexSum(r.b.read("history", p.Name, c.file)); c.got != want {
			t.Errorf("%s = %s, the digest of %s on disk is %s", c.name, c.got, c.file, want)
		}
	}
	// wanted and applied are the plan's lists; each signature of the plan carries its digest.
	if len(rec.Wanted) != 2 || rec.Wanted[0].Path != "ritueel.yaml" || rec.Wanted[1].Path != "want/roots/x509.yaml" {
		t.Errorf("wanted = %+v", rec.Wanted)
	}
	for _, w := range rec.Wanted {
		if got := rtHexSum(r.b.read("history", p.Name, "wanted", filepath.FromSlash(w.Path))); got != w.SHA256 {
			t.Errorf("wanted %s: %s, the copy has %s", w.Path, w.SHA256, got)
		}
	}
	if len(rec.Applied) != 2 || len(rec.Signatures) != 5 {
		t.Errorf("%d applied, %d signatures, want 2 and 5", len(rec.Applied), len(rec.Signatures))
	}
	var sigs []map[string]any
	if err := json.Unmarshal(members["signatures"], &sigs); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(r.b.read("history", p.Name, "signatures.jsonl"), []byte("\n")), []byte("\n"))
	for i, s := range sigs {
		line, err := files.ReadSignatureLine(lines[i])
		if err != nil {
			t.Fatal(err)
		}
		if s["signature_sha256"] != line.SignatureSHA256 || s["kind"] != line.Kind || int64(s["n"].(float64)) != line.N {
			t.Errorf("signature %d of the record: %v, the journal has %+v", i+1, s, line)
		}
		if k, _ := s["key"].(string); k != line.Key {
			t.Errorf("signature %d: key %q, the journal has %q", i+1, k, line.Key)
		}
	}
}

func TestTheJournalsOfARunHaveOneLinePerKeyAndPerSignatureInOrder(t *testing.T) {
	r := rtNew(t)
	done, p := r.mustDirect()
	births := bytes.Split(bytes.TrimSuffix(r.b.read("history", p.Name, "births.jsonl"), []byte("\n")), []byte("\n"))
	if len(births) != 2 {
		t.Fatalf("%d birth lines", len(births))
	}
	for i, l := range births {
		b, err := files.ReadBirthLine(l)
		if err != nil {
			t.Fatal(err)
		}
		label := string(rune('A' + i))
		if b.Label != label || b.Place != "x509-root-"+strings.ToLower(label) || b.Store != "software" || b.Purpose != "x509-root" || b.PublicKeySHA256 != done.Roots[i].X509SPKISHA256 {
			t.Errorf("birth line %d = %+v", i, b)
		}
	}
	sigs := bytes.Split(bytes.TrimSuffix(r.b.read("history", p.Name, "signatures.jsonl"), []byte("\n")), []byte("\n"))
	kinds := []string{"root-certificate", "root-removal", "root-certificate", "root-removal", "root-list"}
	if len(sigs) != len(kinds) {
		t.Fatalf("%d signature lines", len(sigs))
	}
	for i, l := range sigs {
		s, err := files.ReadSignatureLine(l)
		if err != nil || s.N != int64(i+1) || s.Kind != kinds[i] {
			t.Errorf("signature line %d: %+v, %v, want n %d kind %s", i, s, err, i+1, kinds[i])
		}
	}
	// The attempt names the plan and the label that signs.
	at, err := files.ReadAttempt(r.b.read("history", p.Name, "attempt.json"))
	if err != nil || at.Ceremony != p.Name || at.PlanSHA256 != p.SHA256 || at.Root != "A" {
		t.Errorf("attempt = %+v, %v", at, err)
	}
}

func TestTheCheckOfTheHistoryAcceptsWhatARunWroteAndItsEndIsTheRecord(t *testing.T) {
	r := rtNew(t)
	done, _ := r.mustDirect()
	rep, err := history.Check(context.Background(), r.b.raw)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Clean() || len(rep.Findings) != 0 || rep.Records != 1 {
		t.Fatalf("history.Check: findings %+v, %d records", rep.Findings, rep.Records)
	}
	eight, n, ok := rep.End()
	if !ok || n != 1 || eight != done.RecordSHA256[:8] {
		t.Errorf("End = %q, %d, %v; want %q, 1", eight, n, ok, done.RecordSHA256[:8])
	}
}

func TestTheTrustSetOfARunIsAcceptedByTheReadersOfAHostAndTheBundle(t *testing.T) {
	r := rtNew(t)
	done, _ := r.mustDirect()
	pins := []string{done.Roots[0].X509SPKISHA256, done.Roots[1].X509SPKISHA256}
	trust, err := rootlist.PinTrust(pins)
	if err != nil {
		t.Fatal(err)
	}
	set := filepath.FromSlash(done.TrustSet)
	listJSON, listJWS := r.b.read(set, "root-list.json"), r.b.read(set, "root-list.jws")
	v := rootlist.Verify(rootlist.Signed{JSON: listJSON, JWS: listJWS}, trust, pfClock.Add(time.Hour))
	if !v.Accepted || v.List == nil || v.List.Sequence != 1 || len(v.List.Roots) != 2 {
		t.Fatalf("the host does not accept the list: %+v", v)
	}
	if bv := rootlist.VerifyCABundle(r.b.read(set, "ca-bundle.pem"), v.List); !bv.Accepted {
		t.Fatalf("the CA bundle is not accepted: %+v", bv)
	}
	b, err := bundlepkg.Open(r.bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	roots, bset, err := b.Roots()
	if err != nil || len(roots) != 2 || bset.Number != 1 || "trust/"+bset.Name != done.TrustSet {
		t.Fatalf("Roots() = %d roots in %+v, %v; want the two roots of the set that the run wrote", len(roots), bset, err)
	}
	certs := rtBundleCerts(t, r.b.read(set, "ca-bundle.pem"))
	for i := range roots {
		if !bytes.Equal(roots[i].Subject, certs[i].RawSubject) {
			t.Errorf("root %d of the bundle is not the certificate %d of the CA bundle", i, i)
		}
	}
}

func TestTheRootJSONOfEachKeyIsTheOneThePageDescribes(t *testing.T) {
	r := rtNew(t)
	done, _ := r.mustDirect()
	for i, root := range done.Roots {
		raw := r.b.read("roots", root.Label, "root.json")
		rj, err := files.ReadRootJSON(raw)
		if err != nil {
			t.Fatalf("%s: %v", root.Label, err)
		}
		if rj.Label != root.Label || rj.Store != "software" || !rj.Test || rj.X509SPKISHA256 != done.Roots[i].X509SPKISHA256 || rj.CreatedAt != "2026-11-20T10:00:00Z" {
			t.Errorf("root.json of %s = %+v", root.Label, rj)
		}
		removal, err := os.ReadFile(filepath.Join(r.keyDir, root.Label+".removal.jws"))
		if err != nil {
			t.Fatal(err)
		}
		if rj.RemovalSHA256 != rtHexSum(removal) {
			t.Errorf("removal_sha256 of %s is %s, the file has %s", root.Label, rj.RemovalSHA256, rtHexSum(removal))
		}
	}
}

func TestStandardOutputHoldsTheEndLineOnlyAndTheSummaryGoesToStandardError(t *testing.T) {
	r := rtNew(t)
	done, _ := r.mustDirect()
	if got, want := r.stdout.String(), done.EndLine+"\n"; got != want {
		t.Errorf("standard output = %q, want %q", got, want)
	}
	errText := r.stderr.String()
	for _, w := range []string{"plan digest ", "limit: ", "is recorded", "TEST ONLY", done.RecordSHA256, done.TrustSet, "copy them to a safe place"} {
		if !strings.Contains(errText, w) {
			t.Errorf("standard error does not say %q", w)
		}
	}
	if strings.Contains(errText, done.EndLine) {
		t.Error("the end line is on standard error")
	}
	if !pfPrintable(strings.ReplaceAll(errText+r.stdout.String(), "\n", "")) {
		t.Error("an output line is not printable ASCII")
	}
}

func TestTheTranscriptHoldsWhatWasPrintedBeforeTheRecordAndItsDigestIsInTheRecord(t *testing.T) {
	r := rtNew(t)
	done, p := r.mustDirect()
	tr := r.transcript(p.Name)
	rec, _ := r.record(p.Name)
	if rtHexSum([]byte(tr)) != rec.TranscriptSHA256 {
		t.Error("transcript_sha256 is not the digest of transcript.txt")
	}
	lines := strings.Split(strings.TrimSuffix(tr, "\n"), "\n")
	index := func(prefix string) int {
		for i, l := range lines {
			if strings.HasPrefix(l, prefix) {
				return i
			}
		}
		return -1
	}
	first := index("ceremony " + p.Name)
	limit, digest, conf := index("limit: "), index("plan digest "), index("confirmed with --confirm")
	pinA, pinB := index("root key A: x509 pin "+done.Roots[0].X509SPKISHA256), index("root key B: x509 pin "+done.Roots[1].X509SPKISHA256)
	checked, writes := index("checked: "), index("writes: ")
	order := []int{first, limit, digest, conf, pinA, pinB, checked, writes}
	if first != 0 || slices.Contains(order, -1) || !slices.IsSorted(order) {
		t.Errorf("the transcript lines are out of order or missing: %v\n%s", order, tr)
	}
	if writes != len(lines)-1 {
		t.Errorf("the transcript ends at line %d of %d: it must end with the last line printed before the record", writes+1, len(lines))
	}
	// What was printed after the record is not in it.
	for _, not := range []string{"is recorded", "history: 1 ceremony records", "copy them to a safe place"} {
		if strings.Contains(tr, not) {
			t.Errorf("the transcript holds a line of the summary: %q", not)
		}
	}
	if !strings.Contains(tr, "TEST ONLY") {
		t.Error("the transcript does not hold the accepted limit")
	}
}

func TestTheFingerprintsOfBothKeysAreShownBeforeTheFirstSignatureIsMade(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	var order []string
	r.open = func(keyDir, bundleDir string) (ceremony.RootStore, error) {
		st, err := ceremony.NewSoftwareStore(keyDir, bundleDir)
		if err != nil {
			return nil, err
		}
		return &rtOrderStore{RootStore: st, note: func(e string) {
			order = append(order, e+" after "+rtItoa(strings.Count(r.stderr.String(), "x509 pin ")))
		}}, nil
	}
	if _, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p))); err != nil {
		t.Fatal(err)
	}
	// SaveRemoval is the first act of a signature that the store sees. By then both pin lines are printed.
	if len(order) == 0 || order[0] != "save-removal after 2" {
		t.Errorf("order = %q: both pin lines must be printed (2) before the first signature is saved", order)
	}
}

func TestTheCommonNameOfEachRootIsTheNameOfTheBundleInTheCopyOfTheSettings(t *testing.T) {
	r := rtNew(t)
	done, _ := r.mustDirect()
	var names []string
	for _, c := range rtBundleCerts(t, r.b.read(filepath.FromSlash(done.TrustSet), "ca-bundle.pem")) {
		names = append(names, c.Subject.CommonName)
	}
	if want := []string{"Example Root A (TEST ONLY)", "Example Root B (TEST ONLY)"}; !slices.Equal(names, want) {
		t.Errorf("the certificates are %q, want %q", names, want)
	}
}

func TestNothingOfARunIsLeftOpenWhenItEndsWell(t *testing.T) {
	r := rtNew(t)
	r.mustDirect()
	// No temporary name stays behind and no entry is a link.
	err := filepath.WalkDir(r.bundleDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".rt-") {
			t.Errorf("a temporary name is left: %s", p)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			t.Errorf("a link is left: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
