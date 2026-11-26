//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	bundlepkg "ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/verifier"
)

// The first apply of a software test root as one synthetic ceremony through the folder of a
// ceremony (Folder): the plan, the attempt, MakeRoots with the journals of the folder, the end, the
// transcript, the artifacts that MakeRoots returns, and the record. What the run writes is what the
// readers on main judge.

// mkCeremony is one such ceremony, finished.
type mkCeremony struct {
	run    *mkRun
	made   *ceremony.Made
	w      *fsx.Writer
	folder *ceremony.Folder
	record []byte
}

func mkRunCeremony(t *testing.T) *mkCeremony {
	t.Helper()
	r := newMkRun(t)
	w, err := fsx.Open(r.bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	c := &mkCeremony{run: r, w: w}
	c.folder, err = ceremony.NewFolder(w, r.plan.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.folder.WritePlan(r.plan.JSON, r.found.Wanted); err != nil {
		t.Fatalf("WritePlan: %v", err)
	}
	tr, err := c.folder.Start(files.Attempt{Version: 1, Ceremony: r.plan.Name, PlanSHA256: r.plan.SHA256, Root: "A", StartedAt: "2026-11-20T10:00:00Z"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	in := r.in()
	in.Trace = tr
	r.console.Out("plan %s", r.plan.Prefix)
	c.made, err = ceremony.MakeRoots(context.Background(), in)
	if err != nil {
		t.Fatalf("MakeRoots: %v", err)
	}
	if err := c.folder.End(); err != nil {
		t.Fatalf("End: %v", err)
	}
	r.console.Out("done %s", r.plan.Prefix)
	text, err := r.console.Transcript()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.folder.WriteTranscript(text); err != nil {
		t.Fatalf("WriteTranscript: %v", err)
	}
	for _, d := range []string{"roots", "trust"} {
		if err := w.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range c.made.Roots {
		if err := w.Mkdir("roots/"+root.Label, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := w.WriteFile(root.RootJSONPath, root.RootJSON, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.made.Set.Write(w, c.made.TrustSetDir()); err != nil {
		t.Fatalf("Set.Write: %v", err)
	}
	rec := c.made.Record
	c.record, err = c.folder.Record(ceremony.RecordIn{
		Command: files.CommandApply, Outcome: files.OutcomeCompleted,
		StartedAt: "2026-11-20T10:00:00Z", FinishedAt: "2026-11-20T10:05:00Z",
		Root: &rec, Confirmation: &files.Confirmation{By: "flag", At: "2026-11-20T10:00:00Z"},
		RanOn: ceremony.RanOnWorkstation, LimitShown: true, Artifacts: c.made.Artifacts(),
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	return c
}

func TestAWholeCeremonyOfTheFirstApplyIsCleanForTheCheckOfTheHistory(t *testing.T) {
	c := mkRunCeremony(t)
	rep, err := history.Check(context.Background(), pfOpen(t, c.run.bundleDir))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Clean() || len(rep.Findings) != 0 {
		t.Fatalf("the check finds %+v", rep.Findings)
	}
	if rep.Records != 1 {
		t.Errorf("%d records, want 1", rep.Records)
	}
	sum := sha256.Sum256(c.record)
	eight, n, ok := rep.End()
	if !ok || n != 1 || eight != hex.EncodeToString(sum[:])[:8] {
		t.Errorf("the end is %q (%d, %v), want the first eight characters of the digest of record.json", eight, n, ok)
	}
}

func TestTheRecordOfTheCeremonyHoldsTheRootOfThePlanWithTheFingerprintOfTheKeyThatSigned(t *testing.T) {
	c := mkRunCeremony(t)
	rec, err := files.ReadRecord(c.record)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if ok, err := canonjson.IsCanonical(c.record); err != nil || !ok {
		t.Errorf("record.json is not canonical: %v", err)
	}
	if rec.Root == nil || *rec.Root != c.made.Record {
		t.Fatalf("the record's root is %+v, want %+v", rec.Root, c.made.Record)
	}
	if rec.Root.X509 != c.made.Roots[0].Pin || !rec.Root.Test || !rec.Root.Copyable || rec.Root.Label != "A" || rec.Root.Store != "software" || rec.Root.OpenPGP != "" {
		t.Errorf("the root of the record is %+v", rec.Root)
	}
	// Every artifact of the ceremony is listed, with the digest of the bytes on the disk.
	var paths []string
	for _, a := range rec.Artifacts {
		paths = append(paths, a.Path)
		b, err := os.ReadFile(filepath.Join(c.run.bundleDir, filepath.FromSlash(a.Path)))
		if err != nil {
			t.Fatal(err)
		}
		if got := mkSHA(b); got != a.SHA256 {
			t.Errorf("%s: the record has %s, the file %s", a.Path, a.SHA256, got)
		}
	}
	if !slices.Equal(paths, c.made.Artifacts()) {
		t.Errorf("the record lists %v, the run made %v", paths, c.made.Artifacts())
	}
}

func mkSHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestTheFilesOfTheBundleAreTheOnesOfThePageAndNoOther(t *testing.T) {
	c := mkRunCeremony(t)
	var got []string
	err := filepath.WalkDir(c.run.bundleDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(c.run.bundleDir, p)
		got = append(got, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h := "history/" + c.run.plan.Name + "/"
	set := c.made.TrustSetDir()
	want := []string{
		"ritueel.yaml", "want/roots/x509.yaml",
		h + "plan.json", h + "wanted/ritueel.yaml", h + "wanted/want/roots/x509.yaml", h + "attempt.json",
		h + "births.jsonl", h + "signatures.jsonl", h + "transcript.txt", h + "record.json",
		"roots/A/root.json", "roots/B/root.json",
		set + "/ca-bundle.pem", set + "/root-list.json", set + "/root-list.jws",
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("the bundle holds\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestNoSecretIsInAnyFileOfTheBundleOrTheTranscriptAndTheKeyFilesHoldIt(t *testing.T) {
	c := mkRunCeremony(t)
	keyDir := c.run.keyDir
	var blob []byte
	err := filepath.WalkDir(c.run.bundleDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		blob = append(blob, b...)
		blob = append(blob, '\n')
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	tr, _ := c.run.console.Transcript()
	blob = append(blob, tr...)
	mkWantNoScalar(t, "the files of the bundle and the transcript", blob, keyDir)
	// The opposite for the key directory: the key file holds the scalar.
	for _, l := range []string{"A", "B"} {
		d := mkScalar(t, keyDir, l)
		b, _ := os.ReadFile(filepath.Join(keyDir, mkKeyFile(l)))
		if len(b) == 0 || !bytes.Contains(b, d) {
			t.Errorf("the key file of %s does not hold the scalar", l)
		}
	}
}

func TestTheJournalsOfTheFolderHoldTheLinesOfTheRunInTheOrderOfThePlan(t *testing.T) {
	c := mkRunCeremony(t)
	h := filepath.Join(c.run.bundleDir, "history", c.run.plan.Name)
	births, err := os.ReadFile(filepath.Join(h, "births.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(births, []byte("\n")), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("births.jsonl holds %d lines", len(lines))
	}
	for i, l := range lines {
		b, err := files.ReadBirthLine(l)
		if err != nil || b.Label != string(rune('A'+i)) || b.Place != "x509-root-"+strings.ToLower(b.Label) || b.Store != "software" || b.Purpose != "x509-root" || b.PublicKeySHA256 != c.made.Roots[i].Pin {
			t.Errorf("birth line %d: %+v, %v", i+1, b, err)
		}
	}
	sigs, err := os.ReadFile(filepath.Join(h, "signatures.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	slines := bytes.Split(bytes.TrimSuffix(sigs, []byte("\n")), []byte("\n"))
	if len(slines) != 5 {
		t.Fatalf("signatures.jsonl holds %d lines", len(slines))
	}
	wantKinds := []string{"root-certificate", "root-removal", "root-certificate", "root-removal", "root-list"}
	wantKeys := []string{c.made.Roots[0].Pin, c.made.Roots[0].Pin, c.made.Roots[1].Pin, c.made.Roots[1].Pin, c.made.Roots[0].Pin}
	for i, l := range slines {
		s, err := files.ReadSignatureLine(l)
		if err != nil || s.N != int64(i+1) || s.Kind != wantKinds[i] || s.Key != wantKeys[i] {
			t.Errorf("signature line %d: %+v, %v", i+1, s, err)
		}
	}
	// The journal that was judged in the run is the journal that is on the disk.
	if err := ceremony.CheckJournals(c.run.plan, map[string]string{"A": c.made.Roots[0].Pin, "B": c.made.Roots[1].Pin},
		ceremony.JournalRead{Lines: lines}, ceremony.JournalRead{Lines: slines}); err != nil {
		t.Errorf("CheckJournals on the files: %v", err)
	}
}

func TestTheTrustSetOfTheCeremonyIsReadByTheReadersOfTheHost(t *testing.T) {
	c := mkRunCeremony(t)
	dir := filepath.Join(c.run.bundleDir, filepath.FromSlash(c.made.TrustSetDir()))
	listJSON, _ := os.ReadFile(filepath.Join(dir, "root-list.json"))
	listJWS, _ := os.ReadFile(filepath.Join(dir, "root-list.jws"))
	ca, _ := os.ReadFile(filepath.Join(dir, "ca-bundle.pem"))
	trust, err := rootlist.PinTrust([]string{c.made.Roots[0].Pin, c.made.Roots[1].Pin})
	if err != nil {
		t.Fatal(err)
	}
	v := rootlist.Verify(rootlist.Signed{JSON: listJSON, JWS: listJWS}, trust, pfClock)
	if !v.Accepted || v.Again || v.Wayback {
		t.Fatalf("the list is refused: %+v", v)
	}
	if bv := rootlist.VerifyCABundle(ca, v.List); !bv.Accepted {
		t.Errorf("the CA bundle is refused: %+v", bv)
	}
	b, err := bundlepkg.Open(c.run.bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	roots, set, err := b.Roots()
	if err != nil {
		t.Fatalf("Roots: %v", err)
	}
	if len(roots) != 2 || set.Number != 1 || "trust/"+set.Name != c.made.TrustSetDir() {
		t.Errorf("Roots = %d roots in %+v", len(roots), set)
	}
	for i, root := range roots {
		cert, err := x509.ParseCertificate(c.made.Roots[i].Certificate)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(root.Subject, cert.RawSubject) {
			t.Errorf("root %d: the subject is not that of the certificate", i)
		}
	}
}

func TestOpenSSLAcceptsEachRootCertificateAgainstTheCABundleAndNoOther(t *testing.T) {
	c := mkRunCeremony(t)
	ca := c.made.Set.CABundle()
	at := pfClock.Add(24 * 3600 * 1e9)
	for _, root := range c.made.Roots {
		if err := verifier.OpenSSLVerify(t, ca, root.Certificate, at); err != nil {
			t.Errorf("%s: %v", root.Label, err)
		}
	}
	// A certificate of a key that is not in the bundle is refused by the same bundle.
	stranger := mkCertSpec{Name: "Example", Label: "A"}.build()
	if err := verifier.OpenSSLVerify(t, ca, stranger.DER, at); err == nil {
		t.Error("a certificate of another key is accepted against the CA bundle")
	}
	// A certificate that is outside its validity is refused too.
	if err := verifier.OpenSSLVerify(t, ca, c.made.Roots[0].Certificate, mkAddMonths(pfClock, 37)); err == nil {
		t.Error("a certificate is accepted 37 months after the ceremony")
	}
	// What OpenSSL reads from the certificate is what the page says.
	text := verifier.OpenSSLText(t, c.made.Roots[0].Certificate)
	for _, want := range []string{
		"Subject: CN=Example Root A (TEST ONLY)", "Issuer: CN=Example Root A (TEST ONLY)",
		"CA:TRUE", "Certificate Sign, CRL Sign", "Signature Algorithm: ecdsa-with-SHA384", "Version: 3 (0x2)",
		"Public Key Algorithm: id-ecPublicKey", "ASN1 OID: secp384r1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("OpenSSL does not show %q:\n%s", want, text)
		}
	}
	for _, not := range []string{"Name Constraints", "Authority Key Identifier", "Digital Signature", "Extended Key Usage", "Path Length"} {
		if strings.Contains(text, not) {
			t.Errorf("OpenSSL shows %q", not)
		}
	}
	// notBefore and notAfter are the ceremony time and 36 calendar months later.
	if !strings.Contains(text, "Not Before: Nov 20 10:00:00 2026 GMT") || !strings.Contains(text, "Not After : Nov 20 10:00:00 2029 GMT") {
		t.Errorf("the validity is not the page's:\n%s", text)
	}
}

func TestTwoCeremoniesCannotShareAKeyDirectory(t *testing.T) {
	// The second first-apply into a key directory that holds the keys of the first is refused before a
	// key is made (the key files are never replaced).
	c := mkRunCeremony(t)
	second, err := ceremony.NewSoftwareStore(c.run.keyDir, c.run.bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	in := c.run.in()
	in.Store = second
	in.Trace = newMkTrace(&mkLog{})
	made, err := ceremony.MakeRoots(context.Background(), in)
	if made != nil || mkBackendReason(err) != "key-exists" {
		t.Fatalf("MakeRoots = %v, %v; want key-exists", made, err)
	}
}

func TestTheDigestOfEachSignatureLineIsTheDigestOfTheSignatureThatWasMade(t *testing.T) {
	// A line holds a digest of the signature and not the signature (the page of the journal). For a
	// certificate the signature is the one in the certificate, the DER value of ECDSA; for a removal
	// authorisation and the list it is the 96 bytes of r and s that the JWS carries.
	c := mkRunCeremony(t)
	h := filepath.Join(c.run.bundleDir, "history", c.run.plan.Name)
	raw, err := os.ReadFile(filepath.Join(h, "signatures.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
	if len(lines) != 5 {
		t.Fatalf("%d lines", len(lines))
	}
	want := make([]string, 5)
	for i := range c.made.Roots {
		cert, err := x509.ParseCertificate(c.made.Roots[i].Certificate)
		if err != nil {
			t.Fatal(err)
		}
		want[2*i] = mkSHA(cert.Signature)
		text, err := os.ReadFile(filepath.Join(c.run.keyDir, c.made.Roots[i].Label+".removal.jws"))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := base64.RawURLEncoding.DecodeString(strings.Split(string(text), ".")[2])
		if err != nil || len(sig) != 96 {
			t.Fatalf("the removal signature: %d bytes, %v", len(sig), err)
		}
		want[2*i+1] = mkSHA(sig)
	}
	var jwsDoc struct {
		Signatures []struct {
			Signature string `json:"signature"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(c.made.Set.ListJWS(), &jwsDoc); err != nil || len(jwsDoc.Signatures) != 1 {
		t.Fatalf("the list signature file: %v", err)
	}
	listSig, err := base64.RawURLEncoding.DecodeString(jwsDoc.Signatures[0].Signature)
	if err != nil || len(listSig) != 96 {
		t.Fatalf("the list signature: %d bytes, %v", len(listSig), err)
	}
	want[4] = mkSHA(listSig)
	for i, l := range lines {
		sl, err := files.ReadSignatureLine(l)
		if err != nil {
			t.Fatal(err)
		}
		if sl.SignatureSHA256 != want[i] {
			t.Errorf("line %d (%s): the digest is %s, the signature has %s", i+1, sl.Kind, sl.SignatureSHA256, want[i])
		}
	}
}
