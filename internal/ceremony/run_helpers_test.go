//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// Helpers of the tests of Run, the whole first apply of a software test root. The names of this file
// start with rt.

// rtBuf is a stream that keeps what it is given, safe for several goroutines.
type rtBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *rtBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *rtBuf) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// rtReader is a standard input that counts its reads.
type rtReader struct {
	mu    sync.Mutex
	r     io.Reader
	reads int
	bytes int
}

func (r *rtReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.mu.Lock()
	r.reads++
	r.bytes += n
	r.mu.Unlock()
	return n, err
}

func (r *rtReader) taken() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bytes
}

func (r *rtReader) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reads
}

// rt is one prepared run: a bundle that holds the first-apply files, a key directory beside it, a
// writer through the recording file system, and the streams of the run.
type rt struct {
	t         *testing.T
	root      string
	bundleDir string
	keyDir    string
	b         *bundle
	stderr    *rtBuf
	stdout    *rtBuf
	console   *ceremony.Console
	stdin     *rtReader
	term      bool
	clockMu   sync.Mutex
	clockN    int
	clockAt   time.Time
	open      func(keyDir, bundleDir string) (ceremony.RootStore, error)
}

// rtOpt changes a run before it starts.
type rtOpt func(*rtSetup)

type rtSetup struct {
	failAt int
	files  map[string]string
}

func rtFailAt(n int) rtOpt { return func(s *rtSetup) { s.failAt = n } }

// rtNew makes the run: the bundle folder "ca" with the files of a first apply, and the key
// directory "keys" beside it.
func rtNew(t *testing.T, opts ...rtOpt) *rt {
	t.Helper()
	s := &rtSetup{files: pfFiles()}
	for _, o := range opts {
		o(s)
	}
	r := &rt{t: t, clockAt: pfClock.Add(time.Second)}
	r.root = t.TempDir()
	r.bundleDir = filepath.Join(r.root, "ca")
	r.keyDir = filepath.Join(r.root, "keys")
	for _, d := range []string{r.bundleDir, r.keyDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for p, text := range s.files {
		full := filepath.Join(r.bundleDir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r.b = openBundle(t, r.bundleDir, s.failAt)
	r.stderr, r.stdout = &rtBuf{}, &rtBuf{}
	r.console = ceremony.NewConsole(r.stderr, r.stdout)
	return r
}

// now is the clock of the run: one second more at each call, from one second after the plan.
func (r *rt) now() time.Time {
	r.clockMu.Lock()
	defer r.clockMu.Unlock()
	r.clockN++
	return r.clockAt.Add(time.Duration(r.clockN) * time.Second)
}

// env is the Env of the run.
func (r *rt) env() ceremony.Env {
	e := ceremony.Env{Now: r.now, Rand: &pfCounter{}, Self: pfSelf, Out: r.console, InIsTerminal: r.term}
	if r.stdin != nil {
		e.In = r.stdin
	}
	return e
}

// find runs Find on the bundle through the writer of the run.
func (r *rt) find() *ceremony.Found {
	r.t.Helper()
	f, err := ceremony.Find(context.Background(), ceremony.FindInput{FS: r.b.w.FS})
	if err != nil {
		r.t.Fatalf("Find: %v", err)
	}
	return f
}

// plan makes the plan of the bundle with the fixed clock.
func (r *rt) plan() (*ceremony.PlanOut, *ceremony.Found) {
	r.t.Helper()
	f := r.find()
	p, err := ceremony.MakePlan(f, pfEnv())
	if err != nil {
		r.t.Fatalf("MakePlan: %v", err)
	}
	return p, f
}

// typed sets the standard input to a terminal that holds text.
func (r *rt) typed(text string) *rt {
	r.stdin = &rtReader{r: strings.NewReader(text)}
	r.term = true
	return r
}

// in is the RunIn of a direct apply of the plan.
func (r *rt) in(p *ceremony.PlanOut, f *ceremony.Found, c ceremony.Confirm) ceremony.RunIn {
	return ceremony.RunIn{
		Writer: r.b.w, Env: r.env(), Plan: p, Wanted: f.Wanted,
		KeyDir: r.keyDir, BundleDir: r.bundleDir, Confirm: c, OpenStore: r.open,
	}
}

// savedIn is the RunIn of apply PLAN: the plan is read from its folder.
func (r *rt) savedIn(p *ceremony.PlanOut, c ceremony.Confirm) ceremony.RunIn {
	return ceremony.RunIn{
		Writer: r.b.w, Env: r.env(), Plan: p, Saved: true,
		KeyDir: r.keyDir, BundleDir: r.bundleDir, Confirm: c, OpenStore: r.open,
	}
}

// flag is the confirmation of a script for the plan.
func rtFlag(p *ceremony.PlanOut) ceremony.Confirm {
	return ceremony.Confirm{Flag: true, Digest: p.SHA256}
}

// direct runs a direct apply with the flag confirmation.
func (r *rt) direct() (*ceremony.Done, error) {
	r.t.Helper()
	p, f := r.plan()
	return ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
}

// mustDirect runs a direct apply and fails the test when it does not end well.
func (r *rt) mustDirect() (*ceremony.Done, *ceremony.PlanOut) {
	r.t.Helper()
	p, f := r.plan()
	done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
	if err != nil {
		r.t.Fatalf("Run: %v", err)
	}
	return done, p
}

// savePlan writes the plan folder, as apply --plan-only does, and returns the plan as apply PLAN
// reads it back.
func (r *rt) savePlan() *ceremony.PlanOut {
	r.t.Helper()
	p, f := r.plan()
	folder, err := ceremony.NewFolder(r.b.w, p.Name)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := folder.WritePlan(p.JSON, f.Wanted); err != nil {
		r.t.Fatalf("WritePlan: %v", err)
	}
	saved, err := ceremony.ReadSavedPlan(r.b.w.FS, "history/"+p.Name+"/plan.json")
	if err != nil {
		r.t.Fatalf("ReadSavedPlan: %v", err)
	}
	return saved
}

// tree is the entries of the bundle folder.
func (r *rt) tree() map[string]string { return tree(r.t, r.bundleDir) }

// keyTree is the entries of the key directory.
func (r *rt) keyTree() map[string]string { return tree(r.t, r.keyDir) }

// transcript is the transcript.txt of the ceremony.
func (r *rt) transcript(name string) string {
	r.t.Helper()
	return string(r.b.read("history", name, "transcript.txt"))
}

// rtKinds says the kind of an error of Run.
func rtKind(err error) string {
	if _, ok := rtStopped(err); ok {
		// A fault after the first write is a failure whatever its cause is (exit code 1).
		return "stopped"
	}
	return pfKind(err)
}

// rtHexSum is the digest of bytes.
func rtHexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// rtNames are the sorted paths of a tree.
func rtNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rtStopped returns the *StoppedError inside err.
func rtStopped(err error) (*ceremony.StoppedError, bool) {
	var s *ceremony.StoppedError
	ok := errors.As(err, &s)
	return s, ok
}

// rtReadRecord reads the record of the ceremony from the bundle.
func (r *rt) record(name string) (*files.Record, []byte) {
	r.t.Helper()
	b := r.b.read("history", name, "record.json")
	rec, err := files.ReadRecord(b)
	if err != nil {
		r.t.Fatalf("ReadRecord: %v", err)
	}
	return rec, b
}

// rtOrderStore wraps a RootStore and reports the acts that follow the births.
type rtOrderStore struct {
	ceremony.RootStore
	note func(string)
}

func (s *rtOrderStore) SaveRemoval(label string, jws []byte) error {
	s.note("save-removal")
	return s.RootStore.SaveRemoval(label, jws)
}

// rtItoa is the text of a number.
func rtItoa(n int) string { return strconv.Itoa(n) }

// rtBundleCerts parses the certificates of a CA bundle in the order of the file.
func rtBundleCerts(t testing.TB, data []byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return out
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

// rtOtherEnv is the Env of a plan with other serials than the golden plan.
func rtOtherEnv() ceremony.Env {
	e := pfEnv()
	e.Rand = &pfCounter{n: 100}
	return e
}

// buildinfoProgram is the description of a program, as Env.Self returns it.
type buildinfoProgram = buildinfo.Program

// rtSelf is an Env.Self that describes another program.
func rtSelf(version, osArch, sum string) func() (buildinfo.Program, error) {
	return func() (buildinfo.Program, error) {
		return buildinfo.Program{Version: version, OSArch: osArch, SHA256: sum}, nil
	}
}

// rtFixed is a clock that always shows the second after the ceremony time of the golden plan.
func rtFixed() time.Time { return pfClock.Add(time.Second) }
