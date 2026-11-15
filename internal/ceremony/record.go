package ceremony

import (
	"bytes"
	"maps"
	"slices"
	"strings"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/jsonset"
)

// The words of the member ran_on of a record: where the ceremony ran (record 0005, rule 3; the
// names are Proposed on the page).
const (
	// RanOnWorkstation is a ceremony that ran on a workstation, with its attempt in files.
	RanOnWorkstation = "workstation"
	// RanOnOfflineSystem is a ceremony that ran on the offline system of the stick.
	RanOnOfflineSystem = "offline-system"
)

const (
	// maxArtifacts is the most artifacts that one record lists.
	maxArtifacts = 1000
	// maxFolderBytes is the most bytes that [Folder.Record] reads in all: the plan, the copies,
	// the attempt, the journals, the transcript and the artifacts. [Folder.WritePlan] and
	// [Folder.Adopt] take at most this many bytes of copies: one limit for both.
	maxFolderBytes = 256 << 20
)

// RecordIn is what the engine knows of the ceremony when it asks for the record. It holds no
// digest: [Folder.Record] takes every digest from the bytes it reads back from the disk, and takes
// what the plan says (the wanted files, what it applies and leaves out, the trust sequence) from
// the plan.json that it reads back. A zero RecordIn is refused.
type RecordIn struct {
	// Command is the command of the ceremony: [files.CommandApply]. The record of a closing
	// ceremony is not written yet.
	Command string
	// Outcome is the outcome: [files.OutcomeCompleted].
	Outcome string
	// PrevRecordSHA256 is the digest of the ceremony record before this one in the chain, and ""
	// for the first. It must be the plan's last_record_sha256: a plan is made against the end of
	// the history, and a ceremony that ends elsewhere is not the ceremony that was planned.
	PrevRecordSHA256 string
	// StartedAt is when the attempt was written; left out of the record when "".
	StartedAt string
	// FinishedAt is when the record is written; left out of the record when "".
	FinishedAt string
	// Root is the root key that signed, with the fingerprints that are known now; nil leaves it out.
	Root *files.PlanRoot
	// Confirmation is how and when the plan was confirmed; nil leaves it out.
	Confirmation *files.Confirmation
	// RanOn is [RanOnWorkstation] or [RanOnOfflineSystem]; "" leaves the member out.
	RanOn string
	// LimitShown is true when the accepted limit was printed in this run.
	LimitShown bool
	// Artifacts are the paths in the bundle of every file the ceremony wrote other than its own
	// folder: the root.json of each key, the files of the trust set, the answers. Each is read
	// back from the disk and listed with its digest, in the byte order of the path text. Nothing
	// under history/ is an artifact, and two paths that differ only in the case of letters are
	// refused, wherever they stand in the list.
	Artifacts []string
}

// Record writes record.json, the last file of the ceremony folder, and returns its bytes (the
// canonical form, with no line feed at the end). It reads back from the disk, once each, plan.json,
// every copy under wanted/, attempt.json, the two journals, transcript.txt and every artifact, and
// takes every digest from the bytes it read: the record says what is on the disk. It refuses (and
// writes nothing) when
//
//   - a file is missing, is a link or not a regular file, or is longer than fsx.MaxReadSize;
//   - plan.json is not the plan the folder holds, or the attempt does not name it, or a copy does
//     not have the digest that the plan lists;
//   - a journal ends in a half line or holds a line that its reader refuses, or the lines of the
//     journal of signatures are not those of the plan's signatures, one for each, in the order of n,
//     of the same kind and the same key;
//   - the transcript breaks the rules of the page;
//   - a journal of births does not hold one line for each birth of the plan, in the order of the
//     plan, with the label, purpose, store and place that the plan gives;
//   - an artifact path is not a plain path of the bundle, is under history/, is given twice or
//     twice in letters of another case, or the artifacts are more than 1,000;
//   - the root names a fingerprint that is not of the form of the page: 64 lower-case hexadecimal
//     digits for an X.509 key, 40 for an OpenPGP key;
//   - the plan names requests (the record of an answer is not written yet) or the input is not as
//     [RecordIn] says.
//
// The record it writes has the member signature_sha256 in each signature of the plan, and the key
// that signed in each signature the plan did not name it for. The artifacts stand in the byte
// order of the path text. It is read back with [files.ReadRecord] before it is written and after.
//
// Record can return an error while record.json is on disk: the file is renamed into place, and a
// cut at the flush of the folder after the rename is an error of the call although the file is
// there. A caller that gets an error from Record looks at the folder before it says that there is
// no record.
func (f *Folder) Record(in RecordIn) ([]byte, error) {
	if f == nil {
		return nil, newError("record", ErrOutOfOrder, nil, "the folder was not made by NewFolder")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	const op = "record"
	if err := f.begin(op, stateTranscribed); err != nil {
		return nil, err
	}
	if err := checkRecordIn(op, in); err != nil {
		return nil, err
	}
	rd := &recordReader{f: f, op: op}
	rec, err := rd.build(in)
	if err != nil {
		return nil, err
	}
	b, err := rec.Canonical()
	if err != nil {
		return nil, newError(op, ErrInvalidInput, err, "the record cannot be written")
	}
	if err := f.checkRecordBytes(op, b); err != nil {
		return nil, err
	}
	if err := f.w.WriteFile(f.dir()+"/"+files.RecordFile, b, fileMode); err != nil {
		return nil, f.stop(op, err, "record.json could not be written")
	}
	if err := f.verifyFile(op, files.RecordFile, b); err != nil {
		return nil, err
	}
	f.state = stateRecorded
	return slices.Clone(b), nil
}

// checkRecordBytes reads the bytes of a record with the reader that judges it and requires the
// canonical form and the folder's name.
func (f *Folder) checkRecordBytes(op string, b []byte) error {
	r, err := files.ReadRecord(b)
	if err != nil {
		return newError(op, ErrInvalidInput, err, "the record is refused by its reader")
	}
	if ok, err := canonjson.IsCanonical(b); err != nil || !ok {
		return newError(op, ErrInvalidInput, err, "the record is not in the canonical form of RFC 8785")
	}
	if r.Ceremony != f.name {
		return newError(op, ErrInvalidInput, nil, "the record is of another ceremony than its folder")
	}
	return nil
}

// checkRecordIn judges the part of the input that needs no file.
func checkRecordIn(op string, in RecordIn) error {
	if in.Command != files.CommandApply || in.Outcome != files.OutcomeCompleted {
		return newError(op, ErrInvalidInput, nil, "this version writes the record of a completed apply only")
	}
	if in.PrevRecordSHA256 != "" && !files.IsDigest(in.PrevRecordSHA256) {
		return newError(op, ErrInvalidInput, nil, "prev_record_sha256 is not a SHA-256 digest of 64 lower-case hexadecimal characters")
	}
	if in.StartedAt != "" && files.CheckTime(in.StartedAt) != nil {
		return newError(op, ErrInvalidInput, nil, "started_at is not a time of the form YYYY-MM-DDThh:mm:ssZ")
	}
	if in.FinishedAt != "" && files.CheckTime(in.FinishedAt) != nil {
		return newError(op, ErrInvalidInput, nil, "finished_at is not a time of the form YYYY-MM-DDThh:mm:ssZ")
	}
	if in.RanOn != "" && in.RanOn != RanOnWorkstation && in.RanOn != RanOnOfflineSystem {
		return newError(op, ErrInvalidInput, nil, "ran_on is %s, not one of the two words the page gives", jsonset.Quote(in.RanOn))
	}
	if in.Root != nil {
		if in.Root.X509 != "" && !files.IsDigest(in.Root.X509) {
			return newError(op, ErrInvalidInput, nil, "the X.509 fingerprint of the root is not 64 lower-case hexadecimal digits")
		}
		if in.Root.OpenPGP != "" && !isLowerHex(in.Root.OpenPGP, 40) {
			return newError(op, ErrInvalidInput, nil, "the OpenPGP fingerprint of the root is not 40 lower-case hexadecimal digits")
		}
	}
	if len(in.Artifacts) > maxArtifacts {
		return newError(op, ErrInvalidInput, nil, "%d artifacts are more than the %d that a record lists", len(in.Artifacts), maxArtifacts)
	}
	return nil
}

// isLowerHex reports whether s is n lower-case hexadecimal digits.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// recordReader reads the files of the folder once each and keeps the total it read.
type recordReader struct {
	f     *Folder
	op    string
	total int
}

// read reads the file at path (relative to the bundle) once, through fsx, and counts it.
func (r *recordReader) read(path string, what string) ([]byte, error) {
	b, err := fsx.ReadFile(r.f.w.FS, path)
	if err != nil {
		return nil, newError(r.op, nil, err, "%s cannot be read", what)
	}
	r.total += len(b)
	if r.total > maxFolderBytes {
		return nil, newError(r.op, ErrInvalidInput, nil, "the files of the record are more than %d bytes in all", maxFolderBytes)
	}
	return b, nil
}

func (r *recordReader) mismatch(format string, args ...any) error {
	return newError(r.op, ErrDiskMismatch, nil, format, args...)
}

// build reads everything and makes the record.
func (r *recordReader) build(in RecordIn) (*files.Record, error) {
	f := r.f
	dir := f.dir() + "/"
	planBytes, err := r.read(dir+files.PlanFile, "plan.json")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(planBytes, f.plan) {
		return nil, r.mismatch("plan.json on disk is not the plan of the folder")
	}
	p, err := f.checkPlan(r.op, planBytes)
	if err != nil {
		return nil, err
	}
	if len(p.Requests) > 0 {
		return nil, newError(r.op, ErrInvalidInput, nil, "the plan answers requests; the record of an answer is not written yet")
	}
	if in.PrevRecordSHA256 != p.LastRecordSHA256 {
		return nil, newError(r.op, ErrInvalidInput, nil, "the record follows another record than the one the plan was made against")
	}
	rec := &files.Record{
		Version:          files.FormatVersion,
		Ceremony:         f.name,
		Command:          in.Command,
		Outcome:          in.Outcome,
		PlanSHA256:       files.Digest(planBytes),
		PrevRecordSHA256: in.PrevRecordSHA256,
		StartedAt:        in.StartedAt,
		FinishedAt:       in.FinishedAt,
		RootReason:       p.RootReason,
		RanOn:            in.RanOn,
		LimitShown:       in.LimitShown,
		Arguments:        p.Arguments,
		Applied:          p.Applies,
		LeftOut:          p.LeavesOut,
	}
	if in.Root != nil {
		root := *in.Root
		rec.Root = &root
	}
	if in.Confirmation != nil {
		c := *in.Confirmation
		rec.Confirmation = &c
	}
	if p.TrustSequence != nil {
		rec.TrustSequence = *p.TrustSequence
	}
	if err := r.attempt(rec); err != nil {
		return nil, err
	}
	if err := r.copies(p, rec); err != nil {
		return nil, err
	}
	if err := r.journals(p, rec); err != nil {
		return nil, err
	}
	tb, err := r.read(dir+files.TranscriptFile, "transcript.txt")
	if err != nil {
		return nil, err
	}
	if err := checkTranscript(tb); err != nil {
		return nil, newError(r.op, ErrDiskMismatch, err, "transcript.txt on disk breaks the rules of the page")
	}
	rec.TranscriptSHA256 = files.Digest(tb)
	if err := r.artifacts(in.Artifacts, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// attempt reads attempt.json: it must be the attempt of this ceremony and name the plan.
func (r *recordReader) attempt(rec *files.Record) error {
	b, err := r.read(r.f.dir()+"/"+files.AttemptFile, "attempt.json")
	if err != nil {
		return err
	}
	a, err := files.ReadAttempt(b)
	if err != nil {
		return newError(r.op, ErrDiskMismatch, err, "attempt.json on disk is refused by its reader")
	}
	if ok, err := canonjson.IsCanonical(b); err != nil || !ok {
		return newError(r.op, ErrDiskMismatch, err, "attempt.json on disk is not in the canonical form")
	}
	if a.Ceremony != r.f.name || a.PlanSHA256 != rec.PlanSHA256 {
		return r.mismatch("attempt.json on disk does not name this ceremony and this plan")
	}
	rec.AttemptSHA256 = files.Digest(b)
	return nil
}

// copies reads each copy under wanted/ and requires the digest the plan lists. The record's wanted
// list is the plan's.
func (r *recordReader) copies(p *files.Plan, rec *files.Record) error {
	base := r.f.dir() + "/" + files.WantedDir + "/"
	rec.Wanted = make([]files.FileRef, 0, len(p.Wanted))
	for _, w := range p.Wanted {
		b, err := r.read(base+w.Path, "a copy of a wanted file")
		if err != nil {
			return err
		}
		d := files.Digest(b)
		if d != w.SHA256 {
			return r.mismatch("the copy %s on disk does not have the digest that the plan lists", jsonset.Quote(w.Path))
		}
		rec.Wanted = append(rec.Wanted, files.FileRef{Path: w.Path, SHA256: d})
	}
	return nil
}

// journals reads the two journals, judges every line and fills the digests and the signatures.
func (r *recordReader) journals(p *files.Plan, rec *files.Record) error {
	dir := r.f.dir() + "/"
	bb, err := r.read(dir+files.BirthsFile, "births.jsonl")
	if err != nil {
		return err
	}
	lines, ok := journalLines(bb)
	if !ok {
		return r.mismatch("births.jsonl ends in a half line, holds an empty line, or is longer than %d lines", MaxJournalLines)
	}
	if err := r.births(p, lines); err != nil {
		return err
	}
	rec.BirthsSHA256 = files.Digest(bb)
	sb, err := r.read(dir+files.SignaturesFile, "signatures.jsonl")
	if err != nil {
		return err
	}
	slines, ok := journalLines(sb)
	if !ok {
		return r.mismatch("signatures.jsonl ends in a half line, holds an empty line, or is longer than %d lines", MaxJournalLines)
	}
	sigs, err := r.signatures(p, slines)
	if err != nil {
		return err
	}
	rec.Signatures = sigs
	rec.SignaturesSHA256 = files.Digest(sb)
	return nil
}

// births compares the lines of the birth journal with the births of the plan: one line for each
// birth of the plan, in the order of the plan, with the same value in each of the members label,
// purpose, store and place that the plan gives. A missing line, a line too many and a line for a
// label that the plan does not list are an error. The plan always names the label of a birth.
func (r *recordReader) births(p *files.Plan, lines [][]byte) error {
	if len(lines) != len(p.Births) {
		return r.mismatch("births.jsonl holds %d lines and the plan lists %d births", len(lines), len(p.Births))
	}
	seen := make(map[string]bool, len(lines))
	for i, raw := range lines {
		l, err := files.ReadBirthLine(raw)
		if err != nil {
			return newError(r.op, ErrDiskMismatch, err, "a line of births.jsonl is refused by its reader")
		}
		if seen[l.Label] {
			return r.mismatch("births.jsonl holds the key %s twice", l.Label)
		}
		seen[l.Label] = true
		planned, ok := p.Births[i].(map[string]any)
		if !ok {
			return r.mismatch("birth %d of the plan is not an object", i+1)
		}
		if _, has := planned["label"].(string); !has {
			return r.mismatch("birth %d of the plan names no label", i+1)
		}
		for _, m := range []struct{ name, got string }{
			{"label", l.Label}, {"purpose", l.Purpose}, {"store", l.Store}, {"place", l.Place},
		} {
			v, has := planned[m.name]
			if !has {
				continue
			}
			if s, _ := v.(string); s != m.got {
				return r.mismatch("birth %d: the %s of the journal is not the %s of the plan", i+1, m.name, m.name)
			}
		}
	}
	return nil
}

// signatures makes the record's list: the plan's signatures, each with the digest of the signature
// that was made and, when the plan did not name it (a key born in the ceremony), the key that signed.
// The journal must hold one line for each, in the order of n, of the same kind.
func (r *recordReader) signatures(p *files.Plan, lines [][]byte) ([]any, error) {
	if len(lines) != len(p.Signatures) {
		return nil, r.mismatch("signatures.jsonl holds %d lines and the plan lists %d signatures", len(lines), len(p.Signatures))
	}
	out := make([]any, 0, len(p.Signatures))
	for i, raw := range lines {
		l, err := files.ReadSignatureLine(raw)
		if err != nil {
			return nil, newError(r.op, ErrDiskMismatch, err, "a line of signatures.jsonl is refused by its reader")
		}
		planned, ok := p.Signatures[i].(map[string]any)
		if !ok {
			return nil, r.mismatch("signature %d of the plan is not an object", i+1)
		}
		if n, _ := planned["n"].(int64); n != int64(i)+1 || l.N != int64(i)+1 {
			return nil, r.mismatch("signature %d: the numbers of the plan and of the journal are not %d", i+1, i+1)
		}
		if kind, _ := planned["kind"].(string); kind != l.Kind {
			return nil, r.mismatch("signature %d: the kind of the journal is not the kind of the plan", i+1)
		}
		m := maps.Clone(planned)
		if key, has := m["key"]; has {
			if k, _ := key.(string); k != l.Key {
				return nil, r.mismatch("signature %d: the key of the journal is not the key of the plan", i+1)
			}
		} else {
			m["key"] = l.Key
		}
		m["signature_sha256"] = l.SignatureSHA256
		out = append(out, m)
	}
	return out, nil
}

// artifacts reads each artifact once and lists it with its digest, in the byte order of the path text.
// Every path is judged, with a set of the paths in lower case, before the first file is read.
func (r *recordReader) artifacts(paths []string, rec *files.Record) error {
	sorted := slices.Clone(paths)
	slices.Sort(sorted)
	own := historyDir + "/"
	rec.Artifacts = make([]files.FileRef, 0, len(sorted))
	lower := make(map[string]string, len(sorted))
	for _, p := range sorted {
		if err := files.CheckPath(p); err != nil {
			return newError(r.op, ErrInvalidInput, nil, "the artifact path %s %s", jsonset.Quote(p), err)
		}
		if strings.HasPrefix(strings.ToLower(p), own) {
			return newError(r.op, ErrInvalidInput, nil, "the artifact %s is under history/; the files of a ceremony folder are not artifacts", jsonset.Quote(p))
		}
		key := strings.ToLower(p)
		if first, dup := lower[key]; dup {
			if first == p {
				return newError(r.op, ErrInvalidInput, nil, "the artifact %s is given twice", jsonset.Quote(p))
			}
			return newError(r.op, ErrInvalidInput, nil, "the artifacts %s and %s differ only in the case of letters", jsonset.Quote(first), jsonset.Quote(p))
		}
		lower[key] = p
	}
	for _, p := range sorted {
		b, err := r.read(p, "an artifact")
		if err != nil {
			return err
		}
		rec.Artifacts = append(rec.Artifacts, files.FileRef{Path: p, SHA256: files.Digest(b)})
	}
	return nil
}
