package ceremony_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/wanted"
)

// sum is the SHA-256 of b in lower-case hexadecimal, made here and not by the code under test.
func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func rep(c byte) string { return strings.Repeat(string(c), 64) }

const (
	name1 = "20261114T100000Z-apply"
	name2 = "20261114T110000Z-apply"
	ts    = "2026-11-14T10:00:00Z"
)

// errCut is the error that the failing file system returns at the cut.
var errCut = errors.New("test: the write was cut")

// rec records the changing calls that reach the file system and fails the Nth of them.
type rec struct {
	mu     sync.Mutex
	events []string
	count  int
	failAt int
	failed bool
	// corruptAt is the nth write of file data (1 is the first) that reaches the disk with its
	// first byte changed, and writes counts them; 0 changes nothing.
	corruptAt int
	writes    int
	// hook, when it is set, is called at each changing call before the call is made, with the
	// number of the call (1 is the first) and its description; it runs on the goroutine of the
	// caller, outside the lock of rec.
	hook func(n int, desc string)
	// openHook, when it is set, is called at each OpenDir of the file system before the call is
	// made, with the path of the folder; it runs on the goroutine of the caller.
	openHook func(path string)
}

// corrupt reports whether this write of data is the one that is changed.
func (r *rec) corrupt() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes++
	return r.corruptAt > 0 && r.writes == r.corruptAt
}

// op records one changing call. It returns errCut at the call that failAt names.
func (r *rec) op(desc string) error {
	if h := r.hook; h != nil {
		r.mu.Lock()
		n := r.count + 1
		r.mu.Unlock()
		h(n, desc)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	r.events = append(r.events, desc)
	if r.failAt > 0 && r.count == r.failAt && !r.failed {
		r.failed = true
		return errCut
	}
	return nil
}

func (r *rec) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func (r *rec) mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func (r *rec) since(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events[n:]...)
}

// spyFS wraps a folder of the real file system and reports every changing call to rec.
type spyFS struct {
	in   fsx.FS
	r    *rec
	path string
}

func (s *spyFS) at(name string) string {
	if s.path == "" {
		return name
	}
	return s.path + "/" + name
}

func (s *spyFS) OpenDir(name string) (fsx.FS, error) {
	if h := s.r.openHook; h != nil {
		h(s.at(name))
	}
	d, err := s.in.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &spyFS{in: d, r: s.r, path: s.at(name)}, nil
}

func (s *spyFS) Mkdir(name string, perm fs.FileMode) error {
	if err := s.r.op("mkdir " + s.at(name)); err != nil {
		return err
	}
	return s.in.Mkdir(name, perm)
}

func (s *spyFS) CreateExcl(name string, perm fs.FileMode) (fsx.File, error) {
	tmp := strings.HasPrefix(strings.ToLower(name), ".rt-")
	label := "create "
	if tmp {
		label = "create-tmp "
	}
	if err := s.r.op(label + s.at(name)); err != nil {
		return nil, err
	}
	f, err := s.in.CreateExcl(name, perm)
	if err != nil {
		return nil, err
	}
	shown := s.at(name)
	if tmp {
		shown = s.path + "/(tmp)"
	}
	return &spyFile{File: f, r: s.r, path: shown}, nil
}

func (s *spyFS) RenameNoReplace(oldName, newName string) error {
	if err := s.r.op("rename " + s.at(newName)); err != nil {
		return err
	}
	return s.in.RenameNoReplace(oldName, newName)
}

func (s *spyFS) Sync() error {
	if err := s.r.op("sync-dir " + s.path); err != nil {
		return err
	}
	return s.in.Sync()
}

func (s *spyFS) ReadFile(name string) ([]byte, error) { return s.in.ReadFile(name) }
func (s *spyFS) ReadDir() ([]fs.DirEntry, error)      { return s.in.ReadDir() }
func (s *spyFS) Close() error                         { return s.in.Close() }

type spyFile struct {
	fsx.File
	r    *rec
	path string
}

// Write fails by writing the first half and returning errCut, as a cut leaves a part of a file.
func (f *spyFile) Write(p []byte) (int, error) {
	if err := f.r.op("write " + f.path); err != nil {
		n, _ := f.File.Write(p[:len(p)/2])
		return n, err
	}
	if f.r.corrupt() && len(p) > 0 {
		q := append([]byte(nil), p...)
		q[0] ^= 1
		return f.File.Write(q)
	}
	return f.File.Write(p)
}

func (f *spyFile) Sync() error {
	if err := f.r.op("sync-file " + f.path); err != nil {
		return err
	}
	return f.File.Sync()
}

// bundle is a folder with ritueel.yaml at its root, a writer over it that goes through the
// recording file system, and a second, plain handle to read it back with.
type bundle struct {
	t   *testing.T
	dir string
	w   *fsx.Writer
	r   *rec
	raw fsx.FS
}

func newBundle(t *testing.T) *bundle {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ritueel.yaml"), []byte(manifestText), 0o644); err != nil {
		t.Fatal(err)
	}
	return openBundle(t, dir, 0)
}

// openBundle opens dir with a new writer; the Nth changing call of that writer fails when failAt
// is N.
func openBundle(t *testing.T, dir string, failAt int) *bundle {
	t.Helper()
	inner, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := &rec{failAt: failAt}
	w := &fsx.Writer{FS: &spyFS{in: inner, r: r}}
	raw, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = w.Close()
		_ = raw.Close()
	})
	return &bundle{t: t, dir: dir, w: w, r: r, raw: raw}
}

// check runs the check of the history on the folder, with a handle that the writer does not own.
func (b *bundle) check() *history.Report {
	b.t.Helper()
	rep, err := history.Check(context.Background(), b.raw)
	if err != nil {
		b.t.Fatalf("history.Check: %v", err)
	}
	return rep
}

func (b *bundle) path(parts ...string) string {
	return filepath.Join(append([]string{b.dir}, parts...)...)
}

func (b *bundle) read(parts ...string) []byte {
	b.t.Helper()
	data, err := os.ReadFile(b.path(parts...))
	if err != nil {
		b.t.Fatal(err)
	}
	return data
}

const manifestText = "version: 1\nname: acme\n"

// tree describes every entry under dir: its kind and, for a file, the digest of its bytes.
func tree(t testing.TB, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			out[rel] = "link"
		case d.IsDir():
			out[rel] = "dir"
		case d.Type().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[rel] = "file " + sum(b)
		default:
			out[rel] = "other"
		}
		return nil
	})
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	return out
}

// sameTree fails when the two trees differ.
func sameTree(t testing.TB, what string, before, after map[string]string) {
	t.Helper()
	if diff := treeDiff(before, after); diff != "" {
		t.Errorf("%s changed the folder:\n%s", what, diff)
	}
}

func treeDiff(before, after map[string]string) string {
	var lines []string
	for k, v := range before {
		if w, ok := after[k]; !ok {
			lines = append(lines, "- "+k)
		} else if w != v {
			lines = append(lines, "~ "+k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			lines = append(lines, "+ "+k)
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// spec is one synthetic ceremony: the plan it holds and the lines it writes.
type spec struct {
	name   string
	last   string // last_record_sha256 of the plan; "" for the first ceremony
	seq    int    // trust_sequence of the plan
	label  string // the label of the key that this ceremony adds
	pin    string
	copies []wanted.File
	edit   func(map[string]any)
}

func newSpec(name string, seq int, last string) *spec {
	label := string(rune('A' + seq - 1))
	return &spec{
		name: name, last: last, seq: seq, label: label, pin: rep(byte('a' + seq - 1)),
		copies: []wanted.File{
			wantedFile("ritueel.yaml", "version: 1\nname: acme\n"),
			wantedFile("want/roots/x509.yaml", "version: 1\nkind: x509\ntest: true\n"),
		},
	}
}

func wantedFile(path, text string) wanted.File {
	return wanted.File{Path: path, Data: []byte(text), SHA256: sum([]byte(text))}
}

// planMap is the plan as a map: the members that the page lists, with the signatures that this
// ceremony makes: the certificate and the removal of its key (derived: no key, no tbs digest), and
// the root list, signed by a key that the plan names.
func (s *spec) planMap() map[string]any {
	refs := make([]any, 0, len(s.copies))
	paths := make([]string, 0, len(s.copies))
	byPath := map[string]wanted.File{}
	for _, c := range s.copies {
		paths = append(paths, c.Path)
		byPath[c.Path] = c
	}
	sort.Strings(paths)
	for _, p := range paths {
		refs = append(refs, map[string]any{"path": p, "sha256": sum(byPath[p].Data)})
	}
	m := map[string]any{
		"version":        1,
		"ceremony":       s.name,
		"command":        "apply",
		"arguments":      map[string]any{"with": []any{"acme-card"}},
		"made_at":        ts,
		"ceremony_time":  ts,
		"wanted":         refs,
		"applies":        []any{map[string]any{"change": "create", "object": "x509/" + s.label}},
		"leaves_out":     []any{map[string]any{"object": "requests/none", "reason": "nothing asked"}},
		"root":           map[string]any{"label": s.label, "store": "software", "test": true, "copyable": true},
		"root_reason":    "the card of the year is away",
		"trust_sequence": s.seq,
		"signatures": []any{
			map[string]any{"n": 1, "kind": "root-certificate", "subject": s.label, "derived": true, "serial": "0a0b", "not_before": ts, "not_after": "2027-11-14T10:00:00Z"},
			map[string]any{"n": 2, "kind": "root-removal", "subject": s.label, "derived": true},
			map[string]any{"n": 3, "kind": "root-list", "subject": s.label, "key": s.pin, "tbs_sha256": rep('f')},
		},
		"births": []any{map[string]any{"label": s.label, "purpose": "x509-root", "store": "software", "place": s.label + ".x509.key.pem"}},
	}
	if s.last != "" {
		m["last_record_sha256"] = s.last
	}
	if s.seq > 1 {
		m["base_sequence"] = s.seq - 1
	}
	if s.edit != nil {
		s.edit(m)
	}
	return m
}

func (s *spec) plan(t testing.TB) []byte {
	t.Helper()
	b, err := canonjson.Marshal(s.planMap())
	if err != nil {
		t.Fatalf("canonjson.Marshal: %v", err)
	}
	return b
}

func (s *spec) attempt(t testing.TB, plan []byte) files.Attempt {
	return files.Attempt{Version: 1, Ceremony: s.name, PlanSHA256: sum(plan), Root: s.label, StartedAt: ts}
}

func birthBytes(t testing.TB, label, pin string) []byte {
	t.Helper()
	b, err := (&files.BirthLine{At: ts, Label: label, Purpose: "x509-root", Store: "software", Place: label + ".x509.key.pem", PublicKeySHA256: pin}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rawSigBytes is a signature line of any number n, also one that the writer of the lines refuses.
func rawSigBytes(t testing.TB, n int64) []byte {
	t.Helper()
	return []byte(strings.Replace(string(sigBytes(t, 1, "root-list", rep('a'))), `"n":1,`, fmt.Sprintf(`"n":%d,`, n), 1))
}

// sigDigest is the digest that the test gives to the signature n: 64 hexadecimal digits that
// differ for 16 numbers in a row.
func sigDigest(n int64) string { return rep("0123456789abcdef"[n%16]) }

func sigBytes(t testing.TB, n int64, kind, key string) []byte {
	t.Helper()
	b, err := (&files.SignatureLine{At: ts, N: n, Kind: kind, Key: key, SignatureSHA256: sigDigest(n)}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rootListText is a root list as the check of the history reads it: the sequence, the anchor and
// the one key that the ceremony adds.
func (s *spec) rootListText(t testing.TB) []byte {
	m := map[string]any{
		"sequence": s.seq,
		"roots":    []any{map[string]any{"label": s.label, "x509_spki_sha256": s.pin}},
	}
	if s.last != "" {
		m["last_record_sha256"] = s.last
	}
	b, err := canonjson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (s *spec) setName() string { return fmt.Sprintf("trust/%d-%08d", s.seq, s.seq) }

// artifactPaths are the files that this ceremony writes outside its own folder.
func (s *spec) artifactPaths() []string {
	return []string{"roots/" + s.label + "/root.json", s.setName() + "/root-list.json"}
}

// flow runs one synthetic ceremony through a Folder, step by step.
type flow struct {
	t   *testing.T
	b   *bundle
	s   *spec
	f   *ceremony.Folder
	tr  ceremony.Trace
	con *ceremony.Console
	out []byte // record.json, when it was written
	in  func(*ceremony.RecordIn)
	// next is the index in stages of the next stage that run makes.
	next int
}

func newFlow(t *testing.T, b *bundle, s *spec) *flow {
	t.Helper()
	f, err := ceremony.NewFolder(b.w, s.name)
	if err != nil {
		t.Fatal(err)
	}
	return &flow{t: t, b: b, s: s, f: f, con: ceremony.NewConsole(io.Discard, io.Discard)}
}

// stage names, in the order of a ceremony.
var stages = []string{"plan", "start", "births", "signatures", "end", "transcript", "artifacts", "record"}

func (fl *flow) step(name string) error {
	s := fl.s
	switch name {
	case "plan":
		return fl.f.WritePlan(s.plan(fl.t), s.copies)
	case "start":
		var err error
		fl.tr, err = fl.f.Start(s.attempt(fl.t, s.plan(fl.t)))
		return err
	case "births":
		fl.con.Out("plan %s", s.name)
		return fl.tr.Births().Append(birthBytes(fl.t, s.label, s.pin))
	case "signatures":
		fl.con.Err("keys are born; now the signatures")
		if err := fl.tr.Signatures().Append(sigBytes(fl.t, 1, "root-certificate", s.pin)); err != nil {
			return err
		}
		if err := fl.tr.Signatures().Append(sigBytes(fl.t, 2, "root-removal", s.pin)); err != nil {
			return err
		}
		return fl.tr.Signatures().Append(sigBytes(fl.t, 3, "root-list", s.pin))
	case "end":
		return fl.f.End()
	case "transcript":
		fl.con.Out("done: %s", s.name)
		text, err := fl.con.Transcript()
		if err != nil {
			return err
		}
		return fl.f.WriteTranscript(text)
	case "artifacts":
		return fl.writeArtifacts()
	case "record":
		in := ceremony.RecordIn{
			Command: files.CommandApply, Outcome: files.OutcomeCompleted, PrevRecordSHA256: s.last,
			StartedAt: ts, FinishedAt: "2026-11-14T10:05:00Z",
			Root:         &files.PlanRoot{Label: s.label, Store: "software", X509: s.pin, Test: true, Copyable: true},
			Confirmation: &files.Confirmation{By: "flag", At: ts},
			RanOn:        ceremony.RanOnWorkstation, LimitShown: true,
			Artifacts: s.artifactPaths(),
		}
		if fl.in != nil {
			fl.in(&in)
		}
		var err error
		fl.out, err = fl.f.Record(in)
		return err
	}
	panic("unknown stage " + name)
}

// writeArtifacts writes what the engine writes between the transcript and the record: the
// root.json of the key, and the trust set, which is made last.
func (fl *flow) writeArtifacts() error {
	w, s := fl.b.w, fl.s
	for _, d := range []string{"roots", "trust"} {
		if _, err := fsx.ReadDir(w.FS, d); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := w.Mkdir(d, 0o755); err != nil {
				return err
			}
		}
	}
	if err := w.Mkdir("roots/"+s.label, 0o755); err != nil {
		return err
	}
	if err := w.WriteFile("roots/"+s.label+"/root.json", []byte(`{"label":"`+s.label+`"}`), 0o644); err != nil {
		return err
	}
	return w.WriteSet(s.setName(), []fsx.NewFile{{Name: "root-list.json", Data: s.rootListText(fl.t), Perm: 0o644}})
}

// run does the stages that follow the last one it did, up to and including last; "" is all of
// them. It stops at the first error, says which stage failed, and makes that stage again at the
// next call.
func (fl *flow) run(last string) error {
	for fl.next < len(stages) {
		st := stages[fl.next]
		if err := fl.step(st); err != nil {
			return fmt.Errorf("stage %s: %w", st, err)
		}
		fl.next++
		if st == last {
			break
		}
	}
	return nil
}

// skipTo makes the next run begin at the stage name: the caller did the stages before it by hand.
func (fl *flow) skipTo(name string) {
	for i, st := range stages {
		if st == name {
			fl.next = i
			return
		}
	}
	panic("unknown stage " + name)
}

func (fl *flow) must(last string) {
	fl.t.Helper()
	if err := fl.run(last); err != nil {
		fl.t.Fatal(err)
	}
}

// folderPath is the path of a file of the ceremony folder.
func (fl *flow) file(name string) []byte {
	fl.t.Helper()
	return fl.b.read("history", fl.s.name, name)
}

func codes(cs []history.Code) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = string(c)
	}
	return out
}
