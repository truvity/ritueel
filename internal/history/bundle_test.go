//go:build linux || darwin

package history

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// The tests of this package build a bundle in a temporary folder from a description: ceremonies in
// order, what each one lists, the trust sets they write, and optionally a ceremony that stopped.
// Every JSON file of the bundle is written with the Canonical method of its own type. A second,
// independent way to build the clean bundle is in handmade_test.go.

// runLimit is how long one check may take in a test. A check that does not return is a failed test,
// not a run that hangs.
const runLimit = 60 * time.Second

func ptr[T any](v T) *T { return &v }

var (
	digestA = strings.Repeat("a", 64)
	digestB = strings.Repeat("b", 64)
)

// bundle is a bundle on disk in a temporary folder.
type bundle struct {
	t    testing.TB
	dir  string
	recs []*rec
	end  string // the digest of the newest record that was written
	made int    // the ceremonies made so far, with a record or not
	mem  *mnode // when set, the bundle is kept in memory and dir is empty
}

// rec is one ceremony folder, in memory first and on disk after write.
type rec struct {
	b      *bundle
	n      int
	kind   string // "apply", "close" or "unfinished"
	folder string
	set    string // the name of the trust set it writes

	plan    files.Plan
	attempt files.Attempt
	record  files.Record

	wanted     map[string][]byte // under wanted/ of the ceremony folder
	transcript []byte            // nil: no transcript.txt
	extra      map[string][]byte // other files of the ceremony folder, by name (the journals)
	artifacts  map[string][]byte // bundle path -> bytes, every file the record lists besides the transcript, the plan and the wanted copies
	closed     *rec              // the ceremony a closing record closes

	noRecord    bool
	noPlan      bool
	noAttempt   bool
	rawPlan     []byte
	rawAttempt  []byte
	recordBytes func(canonical []byte) []byte

	planBytes    []byte
	attemptBytes []byte
	digest       string // of record.json as written; "" for a ceremony with no record
}

func newBundle(t testing.TB) *bundle {
	t.Helper()
	b := &bundle{t: t, dir: t.TempDir()}
	b.put("ritueel.yaml", []byte("name: test\n"))
	b.mkdir("history")
	return b
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func refsOf(m map[string][]byte) []files.FileRef {
	out := make([]files.FileRef, 0, len(m))
	for p, data := range m {
		out = append(out, files.FileRef{Path: p, SHA256: files.Digest(data)})
	}
	slices.SortFunc(out, func(a, b files.FileRef) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// rootListBytes is the root list of a trust set: the one member the check reads, and a version.
func rootListBytes(last string) []byte {
	m := map[string]any{"version": 1}
	if last != "" {
		m["last_record_sha256"] = last
	}
	return must(canonjson.Marshal(m))
}

// apply adds the ceremony folder of a ceremony of a plan, with a record, and a trust set.
func (b *bundle) apply(opts ...func(*rec)) *rec { return b.add("apply", nil, opts) }

// unfinished adds a ceremony folder with a plan, an attempt and a trust set, and no record.
func (b *bundle) unfinished(opts ...func(*rec)) *rec { return b.add("unfinished", nil, opts) }

// closing adds a closing record for the attempt of a ceremony that stopped.
func (b *bundle) closing(of *rec, opts ...func(*rec)) *rec { return b.add("close", of, opts) }

func (b *bundle) add(kind string, of *rec, opts []func(*rec)) *rec {
	b.t.Helper()
	b.made++
	n := b.made
	r := &rec{b: b, n: n, kind: kind, closed: of}
	word := "apply"
	if kind == "close" {
		word = "close"
	}
	r.folder = fmt.Sprintf("2026%04dT100000Z-%s", n, word)
	r.set = fmt.Sprintf("%d-%08x", n, 0x3fa9c1d2+uint32(n))
	r.artifacts = map[string][]byte{}
	r.plan = files.Plan{Version: 1, Command: files.CommandApply, LastRecordSHA256: b.end, TrustSequence: ptr(int64(n))}
	r.attempt = files.Attempt{Version: 1}
	switch kind {
	case "close":
		r.record = files.Record{Version: 1, Command: files.CommandClose, Outcome: files.OutcomeClosed, PrevRecordSHA256: b.end}
		r.transcript = []byte(fmt.Sprintf("closing %d\n", n))
		r.noPlan, r.noAttempt = true, true
	default:
		r.wanted = map[string][]byte{"ritueel.yaml": []byte(fmt.Sprintf("name: bundle %d\n", n))}
		r.artifacts["trust/"+r.set+"/root-list.json"] = rootListBytes(b.end)
		r.artifacts["trust/"+r.set+"/keys.txt"] = []byte(fmt.Sprintf("keys of set %d\n", n))
		r.record = files.Record{Version: 1, Command: files.CommandApply, Outcome: files.OutcomeCompleted, PrevRecordSHA256: b.end, TrustSequence: int64(n)}
		if kind == "unfinished" {
			r.noRecord = true
		} else {
			r.transcript = []byte(fmt.Sprintf("ceremony %d\n", n))
		}
	}
	r.refresh()
	for _, o := range opts {
		o(r)
	}
	r.write()
	b.recs = append(b.recs, r)
	return r
}

// refresh makes the digests of the plan, the attempt and the record agree with the content: the
// state of a ceremony that nobody touched. A test that changes content and calls refresh keeps the
// bundle whole; a test that changes content and does not has made a fault.
func (r *rec) refresh() {
	r.plan.Ceremony = r.folder
	r.attempt.Ceremony = r.folder
	r.record.Ceremony = r.folder
	r.record.Artifacts = refsOf(r.artifacts)
	if r.transcript != nil {
		r.record.TranscriptSHA256 = files.Digest(r.transcript)
	}
	if r.kind == "close" {
		r.record.Closes = &files.Closes{Ceremony: r.closed.folder, AttemptSHA256: files.Digest(r.closed.attemptBytes), Reason: "the run stopped"}
		return
	}
	r.plan.Wanted = refsOf(r.wanted)
	r.planBytes = must(r.plan.Canonical())
	r.attempt.PlanSHA256 = files.Digest(r.planBytes)
	r.attemptBytes = must(r.attempt.Canonical())
	r.record.PlanSHA256 = files.Digest(r.planBytes)
	r.record.Wanted = refsOf(r.wanted)
}

// write puts the ceremony folder and the files it lists on disk.
func (r *rec) write() {
	b := r.b
	b.t.Helper()
	base := "history/" + r.folder + "/"
	b.mkdir("history/" + r.folder)
	if r.kind != "close" {
		if !r.noPlan {
			data := r.rawPlan
			if data == nil {
				data = must(r.plan.Canonical())
			}
			r.planBytes = data
			b.put(base+files.PlanFile, data)
		}
		if !r.noAttempt {
			data := r.rawAttempt
			if data == nil {
				data = must(r.attempt.Canonical())
			}
			r.attemptBytes = data
			b.put(base+files.AttemptFile, data)
		}
	}
	for p, data := range r.wanted {
		b.put(base+files.WantedDir+"/"+p, data)
	}
	if r.transcript != nil {
		b.put(base+files.TranscriptFile, r.transcript)
	}
	for name, data := range r.extra {
		b.put(base+name, data)
	}
	for p, data := range r.artifacts {
		b.put(p, data)
	}
	if r.noRecord {
		return
	}
	data := must(r.record.Canonical())
	if r.recordBytes != nil {
		data = r.recordBytes(data)
	}
	b.put(base+files.RecordFile, data)
	r.digest = files.Digest(data)
	b.end = r.digest
}

// Options for add.

// noSet leaves the trust set out: the record lists no artifact.
func noSet(r *rec) {
	r.artifacts = map[string][]byte{}
	r.refresh()
}

// prev changes what the record says about its predecessor, and the anchor of the root list of its
// own trust set with it: the list names the record before the ceremony, as the record does. A test
// that wants the two to differ changes the list on its own.
func prev(d string) func(*rec) {
	return func(r *rec) {
		r.record.PrevRecordSHA256 = d
		if p := "trust/" + r.set + "/root-list.json"; r.artifacts[p] != nil {
			r.artifacts[p] = rootListBytes(d)
			r.refresh()
		}
	}
}

// recordAs changes the bytes of record.json after they were made.
func recordAs(f func([]byte) []byte) func(*rec) {
	return func(r *rec) { r.recordBytes = f }
}

// Files of the bundle on disk.

func (b *bundle) abs(rel string) string { return filepath.Join(b.dir, filepath.FromSlash(rel)) }

func (b *bundle) mkdir(rel string) {
	b.t.Helper()
	if b.mem != nil {
		if rel != "." && b.mem.get(rel) == nil {
			b.mem.put(rel, &mnode{kind: "dir", kids: map[string]*mnode{}})
		}
		return
	}
	if err := os.MkdirAll(b.abs(rel), 0o755); err != nil {
		b.t.Fatal(err)
	}
}

func (b *bundle) put(rel string, data []byte) {
	b.t.Helper()
	if b.mem != nil {
		b.mem.put(rel, &mnode{kind: "file", data: data})
		return
	}
	b.mkdir(dirOf(rel))
	if err := os.WriteFile(b.abs(rel), data, 0o644); err != nil {
		b.t.Fatal(err)
	}
}

func (b *bundle) get(rel string) []byte {
	b.t.Helper()
	data, err := os.ReadFile(b.abs(rel))
	if err != nil {
		b.t.Fatal(err)
	}
	return data
}

func (b *bundle) remove(rel string) {
	b.t.Helper()
	if err := os.RemoveAll(b.abs(rel)); err != nil {
		b.t.Fatal(err)
	}
}

func (b *bundle) symlink(target, rel string) {
	b.t.Helper()
	b.mkdir(dirOf(rel))
	if err := os.Symlink(target, b.abs(rel)); err != nil {
		b.t.Fatal(err)
	}
}

func (b *bundle) fifo(rel string) {
	b.t.Helper()
	b.mkdir(dirOf(rel))
	if err := syscall.Mkfifo(b.abs(rel), 0o600); err != nil {
		b.t.Skipf("no FIFO here: %v", err)
	}
}

// sparse makes a file of the given size that holds zero bytes and costs no disk.
func (b *bundle) sparse(rel string, size int64) {
	b.t.Helper()
	b.mkdir(dirOf(rel))
	f, err := os.Create(b.abs(rel))
	if err != nil {
		b.t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		b.t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.t.Fatal(err)
	}
}

// dirOf is the folder part of a "/" separated path of a bundle.
func dirOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return "."
	}
	return p[:i]
}

// Running a check.

// run checks the bundle and fails the test when the check does not finish with a report.
func (b *bundle) run() *Report {
	b.t.Helper()
	return runDir(b.t, b.dir)
}

func runDir(t testing.TB, dir string) *Report {
	t.Helper()
	rep, err := runDirErr(t, dir)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return rep
}

func runDirErr(t testing.TB, dir string) (*Report, error) {
	t.Helper()
	root, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatalf("OpenFS: %v", err)
	}
	defer func() { _ = root.Close() }()
	return runFS(t, root, nil)
}

// runFS runs the check on fsys, with the limits of the package or those given, and fails the test
// when it does not return in time (a FIFO that is waited on, a loop).
func runFS(t testing.TB, fsys fsx.FS, lim *limits) (*Report, error) {
	t.Helper()
	type result struct {
		rep *Report
		err error
	}
	ch := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), runLimit)
	defer cancel()
	go func() {
		var r result
		if lim == nil {
			r.rep, r.err = Check(ctx, fsys)
		} else {
			r.rep, r.err = check(ctx, fsys, *lim)
		}
		ch <- r
	}()
	select {
	case r := <-ch:
		return r.rep, r.err
	case <-time.After(runLimit + 10*time.Second):
		t.Fatalf("Check did not return within %v", runLimit)
		return nil, nil
	}
}

// Findings.

// wf is a finding as a test says it: the code and the path.
type wf struct {
	code Code
	path string
}

func (w wf) String() string { return string(w.code) + " " + w.path }

func findingsOf(rep *Report, ignore ...Code) []wf {
	var out []wf
	for _, f := range rep.Findings {
		if !slices.Contains(ignore, f.Code) {
			out = append(out, wf{f.Code, f.Path})
		}
	}
	return out
}

func sortWF(l []wf) []wf {
	l = slices.Clone(l)
	slices.SortFunc(l, func(a, b wf) int { return strings.Compare(a.String(), b.String()) })
	return l
}

// wantFindings fails when the findings, apart from those of the ignored codes, are not exactly want.
// It also checks the form of every finding, the ignored ones too.
func wantFindings(t testing.TB, rep *Report, want []wf, ignore ...Code) {
	t.Helper()
	got := sortWF(findingsOf(rep, ignore...))
	want = sortWF(want)
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got %v\nwant %v", got, want)
	}
	checkForm(t, rep)
}

// wantReasons fails when the reasons and the warnings, apart from the ignored codes, are not those.
func wantReasons(t testing.TB, rep *Report, reasons, warnings []Code, ignore ...Code) {
	t.Helper()
	drop := func(l []Code) []Code {
		var out []Code
		for _, c := range l {
			if !slices.Contains(ignore, c) {
				out = append(out, c)
			}
		}
		return out
	}
	if got := drop(rep.Reasons()); !slices.Equal(got, reasons) {
		t.Errorf("Reasons() = %v, want %v", got, reasons)
	}
	if got := drop(rep.Warnings()); !slices.Equal(got, warnings) {
		t.Errorf("Warnings() = %v, want %v", got, warnings)
	}
}

// printable reports whether s is only printable ASCII, with no line break.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// checkForm checks every finding against the form of the page: the line is "code path: detail",
// all of it printable ASCII, with no line break, and the detail says something.
func checkForm(t testing.TB, rep *Report) {
	t.Helper()
	for _, f := range rep.Findings {
		line := f.Line()
		if !slices.Contains(Codes(), f.Code) {
			t.Errorf("a finding has the code %q, which is not one of the page", f.Code)
		}
		if f.Path == "" || f.Detail == "" {
			t.Errorf("finding %q has an empty path or detail", line)
		}
		if want := string(f.Code) + " " + f.Path + ": " + f.Detail; line != want {
			t.Errorf("Line() = %q, want %q", line, want)
		}
		if !printable(line) || !printable(f.Path) || !printable(f.Detail) {
			t.Errorf("finding %+v is not printable ASCII: %q", f, line)
		}
		if strings.ContainsAny(line, "\r\n") {
			t.Errorf("the line holds a line break: %q", line)
		}
	}
}

// The spy: a wrapper of fsx.FS that counts the calls.

var errSpyRefused = errors.New("the spy refuses a call that changes the bundle")

type spyLog struct {
	mu      sync.Mutex
	reads   map[string]int
	lists   map[string]int
	opens   map[string]int
	changes []string
}

func (l *spyLog) count(m *map[string]int, key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if *m == nil {
		*m = map[string]int{}
	}
	(*m)[key]++
}

func (l *spyLog) change(call string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.changes = append(l.changes, call)
}

// spyFS counts every read and every listing by the path from the root, and refuses (and records)
// every call that would change something. It hands out wrapped handles from OpenDir, so that the
// walk of fsx.ReadFile is seen.
type spyFS struct {
	fsx.FS
	log  *spyLog
	here string
}

func newSpy(inner fsx.FS) (*spyFS, *spyLog) {
	l := &spyLog{}
	return &spyFS{FS: inner, log: l}, l
}

func (s *spyFS) at(name string) string {
	if s.here == "" {
		return name
	}
	return s.here + "/" + name
}

func (s *spyFS) OpenDir(name string) (fsx.FS, error) {
	s.log.count(&s.log.opens, s.at(name))
	d, err := s.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &spyFS{FS: d, log: s.log, here: s.at(name)}, nil
}

func (s *spyFS) ReadFile(name string) ([]byte, error) {
	s.log.count(&s.log.reads, s.at(name))
	return s.FS.ReadFile(name)
}

func (s *spyFS) ReadDir() ([]fs.DirEntry, error) {
	key := s.here
	if key == "" {
		key = "."
	}
	s.log.count(&s.log.lists, key)
	return s.FS.ReadDir()
}

func (s *spyFS) Mkdir(name string, perm fs.FileMode) error {
	s.log.change("Mkdir " + s.at(name))
	return errSpyRefused
}

func (s *spyFS) CreateExcl(name string, perm fs.FileMode) (fsx.File, error) {
	s.log.change("CreateExcl " + s.at(name))
	return nil, errSpyRefused
}

func (s *spyFS) RenameNoReplace(oldName, newName string) error {
	s.log.change("RenameNoReplace " + s.at(oldName) + " " + s.at(newName))
	return errSpyRefused
}

func (s *spyFS) Sync() error {
	s.log.change("Sync " + s.here)
	return errSpyRefused
}

// runSpied checks the bundle through a spy.
func (b *bundle) runSpied() (*Report, *spyLog) {
	b.t.Helper()
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		b.t.Fatalf("OpenFS: %v", err)
	}
	defer func() { _ = root.Close() }()
	spy, log := newSpy(root)
	rep, err := runFS(b.t, spy, nil)
	if err != nil {
		b.t.Fatalf("Check: %v", err)
	}
	return rep, log
}

// has fails the test when the report holds no finding of that code at that path.
func has(t testing.TB, rep *Report, code Code, path string) {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Code == code && f.Path == path {
			return
		}
	}
	t.Errorf("no finding %s %s in %v", code, path, findingsOf(rep))
}

// lacks fails the test when the report holds a finding of that code.
func lacks(t testing.TB, rep *Report, code Code) {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Code == code {
			t.Errorf("a finding %s: %q", code, f.Line())
			return
		}
	}
}

// detail returns the detail of the finding of that code at that path, or "".
func detail(rep *Report, code Code, path string) string {
	for _, f := range rep.Findings {
		if f.Code == code && f.Path == path {
			return f.Detail
		}
	}
	return ""
}

// threeRecords is the clean bundle of three records that write a trust set each.
func threeRecords(t *testing.T) (*bundle, [3]*rec) {
	t.Helper()
	b := newBundle(t)
	var r [3]*rec
	for i := range r {
		r[i] = b.apply()
	}
	return b, r
}

// rewrite changes the bytes of a record.json that is already on disk, as an edit after the fact.
func rewrite(b *bundle, r *rec, f func([]byte) []byte) {
	b.t.Helper()
	b.put("history/"+r.folder+"/record.json", f(b.get("history/"+r.folder+"/record.json")))
}

// folderName gives the ceremony folder another name. The record, the plan and the attempt say it.
func folderName(name string) func(*rec) {
	return func(r *rec) {
		r.folder = name
		r.refresh()
	}
}

// setName gives the trust set that the ceremony writes another name.
func setName(name string) func(*rec) {
	return func(r *rec) {
		files := map[string][]byte{}
		for p, data := range r.artifacts {
			files["trust/"+name+"/"+p[strings.LastIndexByte(p, '/')+1:]] = data
		}
		r.set = name
		r.artifacts = files
		r.refresh()
	}
}

// renameDir moves a folder or a file of the bundle.
func renameDir(b *bundle, from, to string) error { return os.Rename(b.abs(from), b.abs(to)) }

// namesAttempt makes the record name the digest of attempt.json.
func namesAttempt(r *rec) {
	r.record.AttemptSHA256 = files.Digest(must(r.attempt.Canonical()))
}

// withJournals writes the two journals into the ceremony folder.
func withJournals(r *rec) {
	if r.extra == nil {
		r.extra = map[string][]byte{}
	}
	r.extra[files.BirthsFile] = []byte("{\"label\":\"a\"}\n")
	r.extra[files.SignaturesFile] = []byte("{\"n\":1}\n")
}

// namesJournals writes the journals and makes the record name their digests.
func namesJournals(r *rec) {
	withJournals(r)
	r.record.BirthsSHA256 = files.Digest(r.extra[files.BirthsFile])
	r.record.SignaturesSHA256 = files.Digest(r.extra[files.SignaturesFile])
}

// namesAll makes the record name the attempt and both journals.
func namesAll(r *rec) {
	namesAttempt(r)
	namesJournals(r)
}
