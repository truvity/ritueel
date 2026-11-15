package ceremony_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// A synthetic ceremony of keys of two kinds: each label has an X.509 key and an OpenPGP primary, so
// the plan has two births for each label, and signatures of the kinds root-certificate, root-removal,
// primary-self-signature and primary-revocation (one for each reason), then the root list. The
// bytes of every file are made here from fixed text, never by the code under test: the digests are
// those of the page (a packet for a revocation, the text for a removal authorisation).

const (
	tkPurposeX509 = "x509-root"
	tkPurposePGP  = "openpgp-primary"
	tkCreated     = "2026-11-14T09:00:00Z"
)

// tkOpts shapes one synthetic ceremony.
type tkOpts struct {
	// labels are the labels that the ceremony makes, in order; "A" when empty.
	labels []string
	// reasons are the reasons of the revocation signatures of each primary; the two always made
	// when empty.
	reasons []string
	// noPrimaries makes an X.509-only ceremony: no primary, no revocation, one removal for each label.
	noPrimaries bool
	// noSelfSignature leaves out the plan's self-signature of each primary.
	noSelfSignature bool
	// rootJSON edits the root.json of a label before it is written; nil keeps it.
	rootJSON func(label string, r *files.RootJSON)
	// skipRootJSON leaves out the root.json of these labels.
	skipRootJSON map[string]bool
	// rootJSONBytes replaces the bytes of the root.json of a label.
	rootJSONBytes map[string][]byte
	// twoSelfSignatures gives each primary a second self-signature in the plan and the journal.
	twoSelfSignatures bool
	// planEdit edits the plan after the signatures and the births were made.
	planEdit func(m map[string]any)
}

// tk is one synthetic ceremony that stands before Record.
type tk struct {
	t  testing.TB
	b  *bundle
	fl *flow
	o  tkOpts
	// labels in the order of the plan.
	labels  []string
	reasons []string
	// per label: the pin of the X.509 key, the fingerprint of the primary, the digest of the public
	// key of the primary in its birth line.
	pin, fpr, pgpKey map[string]string
	// badDisk is set by a test that changed the disk so that the good input is refused too.
	badDisk bool
}

func tkSum(parts ...string) string { return sum([]byte(strings.Join(parts, " "))) }

// packet is the digest of the revocation signature packet of a label and a reason.
func (k *tk) packet(label, reason string) string { return tkSum("packet", label, reason) }

// removal is the digest of the text of the removal authorisation of a label.
func (k *tk) removal(label string) string { return tkSum("jws", label) }

func (k *tk) hasPrimary() bool { return !k.o.noPrimaries }

// newTK builds the ceremony up to the record: the plan, the attempt, the journals, the transcript
// and the artifacts are on the disk.
func newTK(t testing.TB, o tkOpts) *tk {
	t.Helper()
	k, err := tryTK(t, o, 0)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// tryTK is newTK on a bundle whose writer fails its failAt-th changing call (0 never fails). It
// returns the first error, with the ceremony as far as it came.
func tryTK(t testing.TB, o tkOpts, failAt int) (*tk, error) {
	t.Helper()
	k := &tk{t: t, o: o, pin: map[string]string{}, fpr: map[string]string{}, pgpKey: map[string]string{}}
	k.labels = o.labels
	if len(k.labels) == 0 {
		k.labels = []string{"A"}
	}
	k.reasons = o.reasons
	if len(k.reasons) == 0 {
		k.reasons = []string{files.ReasonCompromised, files.ReasonSuperseded}
	}
	for i, l := range k.labels {
		k.pin[l] = rep(byte('a' + i))
		k.fpr[l] = strings.Repeat(string(rune('1'+i)), 40)
		k.pgpKey[l] = rep(byte('5' + i))
	}
	s := newSpec(name1, 1, "")
	s.label, s.pin = k.labels[0], k.pin[k.labels[0]]
	s.edit = func(m map[string]any) {
		var births, sigs []any
		n := 0
		sig := func(kind, subject string, extra map[string]any) {
			n++
			e := map[string]any{"n": n, "kind": kind, "subject": subject}
			for a, b := range extra {
				e[a] = b
			}
			sigs = append(sigs, e)
		}
		for _, l := range k.labels {
			births = append(births, map[string]any{"label": l, "purpose": tkPurposeX509, "store": "software", "place": l + ".x509.key.pem"})
			if k.hasPrimary() {
				births = append(births, map[string]any{"label": l, "purpose": tkPurposePGP, "store": "software", "place": l + ".openpgp.key.asc", "creation_time": tkCreated})
			}
			sig("root-certificate", l, map[string]any{"derived": true, "serial": "0a0b", "not_before": ts, "not_after": "2027-11-14T10:00:00Z"})
			sig("root-removal", l, map[string]any{"derived": true})
			if k.hasPrimary() {
				if !o.noSelfSignature {
					sig("primary-self-signature", l, map[string]any{"derived": true})
					if o.twoSelfSignatures {
						sig("primary-self-signature", l, map[string]any{"derived": true})
					}
				}
				for _, r := range k.reasons {
					sig("primary-revocation", l, map[string]any{"derived": true, "reason": r})
				}
			}
		}
		sig("root-list", k.labels[0], map[string]any{"key": k.pin[k.labels[0]], "tbs_sha256": rep('f')})
		m["births"], m["signatures"] = births, sigs
		if o.planEdit != nil {
			o.planEdit(m)
		}
	}
	var b *bundle
	if failAt > 0 {
		b = newBundleFailing(t, failAt)
	} else {
		b = newBundle(t)
	}
	fl := newFlow(t, b, s)
	k.b, k.fl = b, fl
	steps := []func() error{
		func() error { return fl.step("plan") },
		func() error { return fl.step("start") },
		k.writeJournals,
		func() error { return fl.step("end") },
		func() error { return fl.step("transcript") },
		k.writeArtifacts,
	}
	for _, st := range steps {
		if err := st(); err != nil {
			return k, err
		}
	}
	return k, nil
}

func (k *tk) writeJournals() error {
	births := k.fl.tr.Births()
	for _, l := range k.labels {
		line := &files.BirthLine{At: ts, Label: l, Purpose: tkPurposeX509, Store: "software", Place: l + ".x509.key.pem", PublicKeySHA256: k.pin[l]}
		if err := k.appendBirth(births, line); err != nil {
			return err
		}
		if k.hasPrimary() {
			if err := k.appendBirth(births, &files.BirthLine{At: ts, Label: l, Purpose: tkPurposePGP, Store: "software", Place: l + ".openpgp.key.asc", PublicKeySHA256: k.pgpKey[l]}); err != nil {
				return err
			}
		}
	}
	sigs := k.fl.tr.Signatures()
	n := int64(0)
	add := func(kind, key, digest string) error {
		n++
		b, err := (&files.SignatureLine{At: ts, N: n, Kind: kind, Key: key, SignatureSHA256: digest}).Canonical()
		if err != nil {
			k.t.Fatal(err)
		}
		return sigs.Append(b)
	}
	for _, l := range k.labels {
		steps := []struct{ kind, key, digest string }{
			{"root-certificate", k.pin[l], tkSum("cert", l)},
			{"root-removal", k.pin[l], tkSum("removal-signature", l)},
		}
		if k.hasPrimary() {
			if !k.o.noSelfSignature {
				steps = append(steps, struct{ kind, key, digest string }{"primary-self-signature", k.fpr[l], tkSum("self", l)})
				if k.o.twoSelfSignatures {
					steps = append(steps, struct{ kind, key, digest string }{"primary-self-signature", k.fpr[l], tkSum("self again", l)})
				}
			}
			for _, r := range k.reasons {
				steps = append(steps, struct{ kind, key, digest string }{"primary-revocation", k.fpr[l], k.packet(l, r)})
			}
		}
		for _, st := range steps {
			if err := add(st.kind, st.key, st.digest); err != nil {
				return err
			}
		}
	}
	return add("root-list", k.pin[k.labels[0]], tkSum("list"))
}

func (k *tk) appendBirth(j ceremony.Journal, l *files.BirthLine) error {
	k.t.Helper()
	b, err := l.Canonical()
	if err != nil {
		k.t.Fatal(err)
	}
	return j.Append(b)
}

// rootJSONOf is the root.json of a label as the ceremony would write it.
func (k *tk) rootJSONOf(label string) *files.RootJSON {
	r := &files.RootJSON{
		Version: 1, Label: label, Store: "software", Test: true, CreatedAt: "2026-11-20T10:00:00Z",
		X509SPKISHA256: k.pin[label], RemovalSHA256: k.removal(label),
	}
	if k.hasPrimary() {
		r.OpenPGPFingerprint, r.OpenPGPCreated = k.fpr[label], tkCreated
		r.Revocations = map[string]string{}
		for _, reason := range k.reasons {
			r.Revocations[reason] = k.packet(label, reason)
		}
	}
	return r
}

func (k *tk) rootJSONPath(label string) string { return "roots/" + label + "/root.json" }

func (k *tk) artifactPaths() []string {
	var out []string
	for _, l := range k.labels {
		if !k.o.skipRootJSON[l] {
			out = append(out, k.rootJSONPath(l))
		}
	}
	return append(out, k.fl.s.setName()+"/root-list.json")
}

func (k *tk) writeArtifacts() error {
	t, w := k.t, k.b.w
	for _, d := range []string{"roots", "trust"} {
		if err := w.Mkdir(d, 0o755); err != nil {
			return err
		}
	}
	for _, l := range k.labels {
		if k.o.skipRootJSON[l] {
			continue
		}
		r := k.rootJSONOf(l)
		if k.o.rootJSON != nil {
			k.o.rootJSON(l, r)
		}
		data, ok := k.o.rootJSONBytes[l]
		if !ok {
			var err error
			if data, err = r.Canonical(); err != nil {
				t.Fatalf("root.json of %s: %v", l, err)
			}
		}
		if err := w.Mkdir("roots/"+l, 0o755); err != nil {
			return err
		}
		if err := w.WriteFile(k.rootJSONPath(l), data, 0o644); err != nil {
			return err
		}
	}
	s := k.fl.s
	return w.WriteSet(s.setName(), []fsx.NewFile{{Name: "root-list.json", Data: s.rootListText(t), Perm: 0o644}})
}

// wantRevocations are the entries that the plan makes: for each label, in the order of its
// signatures, the removal authorisation and then each reason.
func (k *tk) wantRevocations() []files.RevocationEntry {
	var out []files.RevocationEntry
	for _, l := range k.labels {
		out = append(out, files.RevocationEntry{Label: l, Reason: files.ReasonRootRemoval, SHA256: k.removal(l)})
		if k.hasPrimary() {
			for _, r := range k.reasons {
				out = append(out, files.RevocationEntry{Label: l, Reason: r, SHA256: k.packet(l, r)})
			}
		}
	}
	return out
}

// recordIn is the input of the record that the plan asks for.
func (k *tk) recordIn() ceremony.RecordIn {
	root := &files.PlanRoot{Label: k.labels[0], Store: "software", X509: k.pin[k.labels[0]], Test: true, Copyable: true}
	if k.hasPrimary() {
		root.OpenPGP = k.fpr[k.labels[0]]
	}
	return ceremony.RecordIn{
		Command: files.CommandApply, Outcome: files.OutcomeCompleted,
		StartedAt: ts, FinishedAt: "2026-11-14T10:05:00Z",
		Root: root, Confirmation: &files.Confirmation{By: "flag", At: ts},
		RanOn: ceremony.RanOnWorkstation, LimitShown: true,
		Artifacts:   k.artifactPaths(),
		Revocations: k.wantRevocations(),
	}
}

// record calls Folder.Record with the input after edit changed it.
func (k *tk) record(edit func(*ceremony.RecordIn)) ([]byte, error) {
	in := k.recordIn()
	if edit != nil {
		edit(&in)
	}
	return k.fl.f.Record(in)
}

// refuses calls Record with the input after edit, requires that it is refused with the kind and
// the words, that nothing reached the disk and that the folder is not stopped, and then calls
// Record again with the good input, which must be accepted: a refusal leaves the folder in the
// state in which the right call works.
func (k *tk) refuses(edit func(*ceremony.RecordIn), kind error, words ...string) {
	k.t.Helper()
	before := tree(k.t, k.b.dir)
	mark := k.b.r.mark()
	out, err := k.record(edit)
	if err == nil {
		k.t.Fatalf("a record was written: %s", out)
	}
	if out != nil {
		k.t.Errorf("Record returned bytes with its error: %s", out)
	}
	if kind != nil {
		wantKind(k.t, err, kind)
	} else {
		wantKind(k.t, err)
	}
	if errors.Is(err, ceremony.ErrFolderStopped) {
		k.t.Error("a refusal stopped the folder")
	}
	for _, w := range words {
		if !strings.Contains(err.Error(), w) {
			k.t.Errorf("the reason %q does not hold %q", err, w)
		}
	}
	if got := k.b.r.since(mark); len(got) != 0 {
		k.t.Errorf("a refused record reached the file system: %v", got)
	}
	sameTree(k.t, "a refused Record", before, tree(k.t, k.b.dir))
	if _, err := os.Lstat(k.b.path("history", name1, "record.json")); !os.IsNotExist(err) {
		k.t.Errorf("record.json exists: %v", err)
	}
	if k.badDisk || k.o.rootJSONBytes != nil || k.o.rootJSON != nil || k.o.skipRootJSON != nil {
		return
	}
	if _, err := k.record(nil); err != nil {
		k.t.Fatalf("the good record after the refusal: %v", err)
	}
}
