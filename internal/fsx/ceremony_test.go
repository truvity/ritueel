package fsx_test

// A small ceremony written through a bundleWriter, and the oracle that says what a cut may
// leave. The oracle is the test: a writer that the oracle cannot tell from a wrong writer
// proves nothing, so cut_test.go runs it against both.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

const (
	bundle   = "/b"
	cerDir   = "/b/history/20261113-apply"
	trustSet = "/b/trust/0007-acme"
)

type journal interface {
	Append(line []byte) error
	Close() error
}

// bundleWriter is the surface of fsx.Writer that a ceremony uses. The real writer and each
// deliberately wrong writer implement it over the same fsx.FS.
type bundleWriter interface {
	Mkdir(path string, perm fs.FileMode) error
	WriteFile(path string, data []byte, perm fs.FileMode) error
	WriteSet(finalDir string, files []fsx.NewFile) error
	CreateJournal(path string) (journal, error)
}

type realWriter struct{ *fsx.Writer }

// leakChecked says that the oracle of the open handles applies to this writer: it is the real
// one, and the wrong writers open handles as they please.
func (realWriter) leakChecked() bool { return true }

func (r realWriter) CreateJournal(p string) (journal, error) {
	j, err := r.Writer.CreateJournal(p)
	if err != nil {
		return nil, err
	}
	return j, nil
}

// intent is what the ceremony means to write: the only names and contents that may stand at a
// final name.
type intent struct {
	dirs     map[string]bool
	files    map[string][]byte
	journals map[string][][]byte
	sets     map[string][]string // a set's folder to its file names
}

type fileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type recordJSON struct {
	Transcript fileRef   `json:"transcript"`
	Artifacts  []fileRef `json:"artifacts"`
	Trust      []fileRef `json:"trust"`
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fill makes n deterministic bytes (some artifacts are longer than one sector).
func fill(seed string, n int) []byte {
	out := make([]byte, 0, n)
	h := sha256.Sum256([]byte(seed))
	for len(out) < n {
		out = append(out, h[:]...)
		h = sha256.Sum256(h[:])
	}
	return out[:n]
}

func journalContent(lines [][]byte) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func newIntent() *intent {
	in := &intent{
		dirs:     map[string]bool{"/b": true, "/b/history": true, "/b/sealed": true, "/b/trust": true, cerDir: true},
		files:    map[string][]byte{},
		journals: map[string][][]byte{},
		sets:     map[string][]string{},
	}
	in.files[cerDir+"/plan.json"] = []byte(`{"version":1,"ceremony":"20261113-apply","trust_sequence":7}`)
	in.files[cerDir+"/attempt.json"] = []byte(`{"version":1,"ceremony":"20261113-apply","root":"acme","started_at":"2026-11-13T10:00:00Z"}`)
	in.journals[cerDir+"/births.jsonl"] = [][]byte{
		[]byte(`{"n":1,"key":"` + digest([]byte("k1")) + `"}`),
		[]byte(`{"n":2,"key":"` + digest([]byte("k2")) + `"}`),
		[]byte(`{"n":3,"key":"` + digest([]byte("k3")) + `"}`),
	}
	in.journals[cerDir+"/signatures.jsonl"] = [][]byte{
		[]byte(`{"n":1,"sig":"` + digest([]byte("s1")) + `"}`),
		[]byte(`{"n":2,"sig":"` + digest([]byte("s2")) + `"}`),
		[]byte(`{"n":3,"sig":"` + digest([]byte("s3")) + `"}`),
	}
	in.files["/b/sealed/a1.bin"] = fill("a1", 90)
	in.files["/b/sealed/a2.bin"] = fill("a2", 700)
	in.files["/b/sealed/a3.bin"] = fill("a3", 1500)
	in.sets[trustSet] = []string{"keys.json", "root.json"}
	in.files[trustSet+"/keys.json"] = []byte(`{"keys":["k1","k2","k3"]}`)
	in.files[trustSet+"/root.json"] = fill("root", 600)
	in.files[cerDir+"/transcript.txt"] = []byte("line one\nline two\n")

	rec := recordJSON{Transcript: fileRef{cerDir + "/transcript.txt", digest(in.files[cerDir+"/transcript.txt"])}}
	for _, p := range []string{"/b/sealed/a1.bin", "/b/sealed/a2.bin", "/b/sealed/a3.bin"} {
		rec.Artifacts = append(rec.Artifacts, fileRef{p, digest(in.files[p])})
	}
	for _, n := range in.sets[trustSet] {
		rec.Trust = append(rec.Trust, fileRef{trustSet + "/" + n, digest(in.files[trustSet+"/"+n])})
	}
	b, err := json.Marshal(rec)
	if err != nil {
		panic(err)
	}
	in.files[cerDir+"/record.json"] = b
	return in
}

// An ack is a call that returned nil: what it promised must stand after any cut that comes
// later, under every policy (a flushed effect is in every image).
type ack struct {
	After int // the number of file system calls made when the call returned
	Kind  string
	Path  string
	Lines int // kind "line": the journal holds at least this many whole lines
}

// run writes the ceremony. Each step is one call (a journal step is several).
type run struct {
	t    testing.TB
	fs   *memFS
	w    bundleWriter
	in   *intent
	acks []ack
}

// rel is the path the writer is given for a path of the intent: relative to the root.
func rel(p string) string { return strings.TrimPrefix(p, "/") }

// checkOpen is the oracle of the handles, after a call of the real writer has returned: the
// root, and the file of each journal that is still open, and nothing else.
func (r *run) checkOpen(journals int) {
	r.t.Helper()
	if c, ok := r.w.(interface{ leakChecked() bool }); !ok || !c.leakChecked() {
		return
	}
	d, f := r.fs.handles()
	if d != 1 || f != journals {
		r.t.Fatalf("after the call the writer holds %d folders and %d files open (%s), want the root and %d journals", d, f, r.fs.describeOpen(), journals)
	}
	if v := r.fs.violationList(); len(v) > 0 {
		r.t.Fatalf("the writer made calls that no correct caller makes: %q", v)
	}
}

var defaultOrder = []string{"mkdir", "plan", "attempt", "births", "sigs", "artifacts", "trust", "transcript", "record"}

func (r *run) ack(kind, p string, lines int) {
	r.acks = append(r.acks, ack{After: r.fs.opCount(), Kind: kind, Path: p, Lines: lines})
}

func (r *run) file(p string) error {
	if err := r.w.WriteFile(rel(p), r.in.files[p], 0o600); err != nil {
		return err
	}
	r.ack("file", p, 0)
	r.checkOpen(0)
	return nil
}

func (r *run) journal(p string) error {
	j, err := r.w.CreateJournal(rel(p))
	if err != nil {
		return err
	}
	r.ack("journal", p, 0)
	r.checkOpen(1)
	for i, l := range r.in.journals[p] {
		if err := j.Append(l); err != nil {
			_ = j.Close()
			return err
		}
		r.ack("line", p, i+1)
		r.checkOpen(1)
	}
	if err := j.Close(); err != nil {
		return err
	}
	r.checkOpen(0)
	return nil
}

func (r *run) step(name string) error {
	switch name {
	case "mkdir":
		if err := r.w.Mkdir(rel(cerDir), 0o700); err != nil {
			return err
		}
		r.ack("dir", cerDir, 0)
		r.checkOpen(0)
		return nil
	case "plan":
		return r.file(cerDir + "/plan.json")
	case "attempt":
		return r.file(cerDir + "/attempt.json")
	case "births":
		return r.journal(cerDir + "/births.jsonl")
	case "sigs":
		return r.journal(cerDir + "/signatures.jsonl")
	case "artifacts":
		for _, n := range []string{"a1", "a2", "a3"} {
			if err := r.file("/b/sealed/" + n + ".bin"); err != nil {
				return err
			}
		}
		return nil
	case "trust":
		var set []fsx.NewFile
		for _, n := range r.in.sets[trustSet] {
			set = append(set, fsx.NewFile{Name: n, Data: r.in.files[trustSet+"/"+n], Perm: 0o600})
		}
		if err := r.w.WriteSet(rel(trustSet), set); err != nil {
			return err
		}
		r.ack("set", trustSet, 0)
		r.checkOpen(0)
		return nil
	case "transcript":
		return r.file(cerDir + "/transcript.txt")
	case "record":
		return r.file(cerDir + "/record.json")
	}
	panic("unknown step " + name)
}

// runCeremony runs the steps in the order given on a fresh memFS and returns the run. The
// run must end without an error: every wrong writer here is wrong about order, not about
// failing.
func runCeremony(t testing.TB, mk func(*memFS) bundleWriter, order []string) *run {
	t.Helper()
	f := newMemFS("b", "b/history", "b/sealed", "b/trust")
	r := &run{t: t, fs: f, w: mk(f), in: newIntent()}
	for _, name := range order {
		if err := r.step(name); err != nil {
			t.Fatalf("step %s: %v", name, err)
		}
	}
	if c, ok := r.w.(interface{ Close() error }); ok {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if d, fl := f.handles(); d != 0 || fl != 0 {
			t.Fatalf("after Close of the writer %d folders and %d files are open (%s)", d, fl, f.describeOpen())
		}
	}
	return r
}

// realMaker is the real writer over the file system, with random parts that repeat from run
// to run.
func realMaker(f *memFS) bundleWriter {
	return realWriter{&fsx.Writer{FS: f.Root(), Rand: newDetRand(1)}}
}

// ---- the oracle -------------------------------------------------------------------------

var tempShape = regexp.MustCompile(`^\.rt-[a-z0-9]{11}$`)

// oracle returns every way the image breaks what a cut may leave. An empty result means that
// the image is one a checker would not call broken.
//
// A cut may leave: a file at a final name that is whole or absent (a journal may also be a
// prefix of its content, because it is created at its final name and grows); anything at a
// temporary name; a set folder at its final name only when every file is in it; a record only
// when every file it lists is there with its digest; and, for every call that returned, what
// the call promised.
func oracle(img *image, in *intent, acks []ack, cut int, sawPartial *int) []string {
	var bad []string
	add := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }

	for _, p := range img.paths() {
		if p == "/" {
			continue
		}
		temp := false
		for _, e := range strings.Split(p[1:], "/") {
			if strings.HasPrefix(e, fsx.TempPrefix) {
				temp = true
				if !tempShape.MatchString(e) {
					add("%s: a temporary name of the wrong shape %q (want .rt- and 11 of a-z0-9)", p, e)
				}
			}
		}
		if temp {
			continue
		}
		nd := img.nodes[p]
		if nd.dir() {
			if !in.dirs[p] && in.sets[p] == nil {
				add("%s: a folder at a name that is not a final name%s", p, leak(path.Base(p), in))
			}
			continue
		}
		if want, ok := in.files[p]; ok {
			if !bytes.Equal(nd.data, want) {
				add("%s: a file at its final name holds %d bytes that are not its content (%d bytes intended)", p, len(nd.data), len(want))
			}
			continue
		}
		if lines, ok := in.journals[p]; ok {
			want := journalContent(lines)
			if !bytes.HasPrefix(want, nd.data) {
				add("%s: a journal that is not a prefix of its intended content", p)
			}
			whole, partial, err := img.readJournal(p)
			if err != nil {
				add("%s: ReadJournal: %v", p, err)
				continue
			}
			var back []byte
			for _, l := range whole {
				back = append(back, l...)
				back = append(back, '\n')
			}
			back = append(back, partial...)
			if !bytes.Equal(back, nd.data) {
				add("%s: ReadJournal's lines and partial do not add up to the file", p)
			}
			if len(nd.data) > 0 && nd.data[len(nd.data)-1] != '\n' && partial == nil {
				add("%s: a torn last line is not reported as partial", p)
			}
			if (len(nd.data) == 0 || nd.data[len(nd.data)-1] == '\n') && partial != nil {
				add("%s: a journal that ends in a newline reports a partial line", p)
			}
			if partial != nil && sawPartial != nil {
				*sawPartial++
			}
			continue
		}
		add("%s: a file at a name that is not a final name%s", p, leak(path.Base(p), in))
	}

	for dir, names := range in.sets {
		if !img.isDir(dir) {
			continue
		}
		for _, n := range names {
			b, ok := img.file(dir + "/" + n)
			if !ok {
				add("%s: a set at its final name without %s", dir, n)
			} else if !bytes.Equal(b, in.files[dir+"/"+n]) {
				add("%s: a set at its final name with a short or wrong %s", dir, n)
			}
		}
	}

	if raw, ok := img.file(cerDir + "/record.json"); ok {
		var rec recordJSON
		if err := json.Unmarshal(raw, &rec); err != nil {
			add("record.json does not parse: %v", err)
		} else {
			listed := append([]fileRef{rec.Transcript}, rec.Artifacts...)
			listed = append(listed, rec.Trust...)
			for _, l := range listed {
				b, ok := img.file(l.Path)
				switch {
				case !ok:
					add("record.json exists and lists %s, which is missing", l.Path)
				case digest(b) != l.SHA256:
					add("record.json exists and lists %s, which fails its digest", l.Path)
				}
			}
		}
	}

	for _, a := range acks {
		if a.After > cut {
			continue
		}
		switch a.Kind {
		case "dir":
			if !img.isDir(a.Path) {
				add("a call that returned (#%d) made folder %s, and it is not there", a.After, a.Path)
			}
		case "file":
			if b, ok := img.file(a.Path); !ok || !bytes.Equal(b, in.files[a.Path]) {
				add("a call that returned (#%d) wrote %s, and it is %s", a.After, a.Path, describe(img, a.Path))
			}
		case "set":
			for _, n := range in.sets[a.Path] {
				if b, ok := img.file(a.Path + "/" + n); !ok || !bytes.Equal(b, in.files[a.Path+"/"+n]) {
					add("a call that returned (#%d) wrote set %s, and %s is %s", a.After, a.Path, n, describe(img, a.Path+"/"+n))
				}
			}
		case "journal":
			if _, ok := img.file(a.Path); !ok {
				add("a call that returned (#%d) created journal %s, and it is not there", a.After, a.Path)
			}
		case "line":
			whole, _, err := img.readJournal(a.Path)
			if err != nil || len(whole) < a.Lines {
				add("an Append that returned (#%d) made line %d of %s whole, and the journal has %d whole lines (%v)", a.After, a.Lines, a.Path, len(whole), err)
				continue
			}
			for i := 0; i < a.Lines; i++ {
				if !bytes.Equal(whole[i], in.journals[a.Path][i]) {
					add("line %d of %s differs from what Append was given", i+1, a.Path)
				}
			}
		}
	}
	return bad
}

func describe(img *image, p string) string {
	b, ok := img.file(p)
	if !ok {
		return "absent"
	}
	return fmt.Sprintf("%d bytes of another content", len(b))
}

// leak says when a name that is not a final name carries one, which is what a temporary name
// must never do (record 0006, rule 32).
func leak(name string, in *intent) string {
	var all []string
	for p := range in.files {
		all = append(all, path.Base(p))
	}
	for p := range in.journals {
		all = append(all, path.Base(p))
	}
	for _, f := range all {
		if f != name && strings.Contains(name, f) {
			return fmt.Sprintf(" (the name carries the final name %q)", f)
		}
	}
	return ""
}

// ---- one pass over every cut ---------------------------------------------------------------

type verdict struct {
	Cut   int
	Op    string
	Pol   policy
	Msgs  []string
	After string // the op that the cut follows
}

type sweep struct {
	Ops        int
	Images     int
	Failures   []verdict
	PartialSaw int
}

// policiesUnderTest are the flushed-only policy, the everything-survives policy and 12 seeds.
func policiesUnderTest() []policy { return policies(12) }

func sweepCuts(r *run) sweep {
	ops := r.fs.opList()
	s := sweep{Ops: len(ops)}
	for n := 0; n <= len(ops); n++ {
		for _, p := range policiesUnderTest() {
			img := r.fs.CrashAfter(n, p)
			s.Images++
			if msgs := oracle(img, r.in, r.acks, n, &s.PartialSaw); len(msgs) > 0 {
				v := verdict{Cut: n, Pol: p, Msgs: msgs, After: "(before the first call)"}
				if n > 0 {
					v.After = ops[n-1].String()
				}
				s.Failures = append(s.Failures, v)
			}
		}
	}
	return s
}

func (s sweep) table(limit int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d images broken; first %d:\n", len(s.Failures), s.Images, min(limit, len(s.Failures)))
	for i, v := range s.Failures {
		if i == limit {
			break
		}
		fmt.Fprintf(&b, "  cut after call %3d  policy %-8v  after %s\n", v.Cut, v.Pol, v.After)
		for _, m := range v.Msgs {
			fmt.Fprintf(&b, "      %s\n", m)
		}
	}
	return b.String()
}

// byKind returns the policy kinds that caught something, with the first cut of each.
func (s sweep) byKind() map[string]verdict {
	out := map[string]verdict{}
	for _, v := range s.Failures {
		if _, ok := out[v.Pol.kind]; !ok {
			out[v.Pol.kind] = v
		}
	}
	return out
}

func (s sweep) kinds() []string {
	k := s.byKind()
	out := make([]string, 0, len(k))
	for name := range k {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// readJournal reads the journal at the "/"-rooted path p of the image through the package's reader.
func (img *image) readJournal(p string) (lines [][]byte, partial []byte, err error) {
	root := img.root()
	defer func() { _ = root.Close() }()
	return fsx.ReadJournal(root, rel(p))
}
