//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/keystore"
)

// Helpers of the tests of the birth of a software test root (RootStore, MakeRoots and the checks of
// its artifacts). The names of this file start with mk.

// mkLog is an ordered list of events that the fakes of a test write to: calls of the store, lines of
// the two journals, and lines of the console. It is safe for several goroutines.
type mkLog struct {
	mu sync.Mutex
	ev []string
}

func (l *mkLog) add(format string, args ...any) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, fmt.Sprintf(format, args...))
}

func (l *mkLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ev...)
}

// index is the position of the first event with the prefix, or -1.
func (l *mkLog) index(prefix string) int {
	for i, e := range l.all() {
		if strings.HasPrefix(e, prefix) {
			return i
		}
	}
	return -1
}

// count is the number of events with the prefix.
func (l *mkLog) count(prefix string) int {
	n := 0
	for _, e := range l.all() {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

// mkLineWriter is a stream of the console that logs each line it is given.
type mkLineWriter struct {
	log    *mkLog
	prefix string
	buf    bytes.Buffer
	mu     sync.Mutex
}

func (w *mkLineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		i := bytes.IndexByte(w.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		w.log.add("%s%s", w.prefix, w.buf.Next(i + 1)[:i])
	}
	return len(p), nil
}

// mkJournal is a journal that keeps its lines and writes an event for each. It fails the call
// number failAt (counted from 1), when failAt is not zero.
type mkJournal struct {
	log    *mkLog
	name   string
	failAt int
	panics bool

	mu    sync.Mutex
	lines [][]byte
	calls int
}

func (j *mkJournal) Append(line []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.calls++
	if j.panics {
		panic("journal panics")
	}
	if j.failAt != 0 && j.calls == j.failAt {
		return errors.New("test: the journal refuses the line")
	}
	j.lines = append(j.lines, append([]byte(nil), line...))
	j.log.add("%s-line %s", j.name, mkLineWhat(j.name, line))
	return nil
}

// mkLineWhat says what a journal line is: the label of a birth, the number and kind of a signature.
func mkLineWhat(name string, line []byte) string {
	if name == "births" {
		if l, err := files.ReadBirthLine(line); err == nil {
			return l.Label
		}
		return "?"
	}
	if l, err := files.ReadSignatureLine(line); err == nil {
		return fmt.Sprintf("%d %s", l.N, l.Kind)
	}
	return "?"
}

// mkTrace is a Trace over two memory journals.
type mkTrace struct {
	births, sigs *mkJournal
}

func newMkTrace(log *mkLog) *mkTrace {
	return &mkTrace{births: &mkJournal{log: log, name: "births"}, sigs: &mkJournal{log: log, name: "signatures"}}
}

func (t *mkTrace) Births() ceremony.Journal     { return t.births }
func (t *mkTrace) Signatures() ceremony.Journal { return t.sigs }

// mkStore wraps a RootStore, writes an event for each call, and fails or lies when asked to.
type mkStore struct {
	inner ceremony.RootStore
	log   *mkLog

	refuseErr error
	failBirth map[string]error
	// keyAndErr makes the key of the label and returns it together with this error, as a store that
	// has broken its contract does.
	keyAndErr    map[string]error
	failRemoval  map[string]error
	panicOn      string // "refuse", "birth", "saveremoval", "readremoval", "kind", "place"
	nilKeyFor    string
	typedNilFor  string
	wrapKey      func(label string, k keystore.Key) keystore.Key
	readRemoval  func(label string, real []byte) []byte
	kindOverride keystore.Kind
	copyOverride *bool
	placeFor     map[string]string
	afterBirth   func(label string)
	readErr      error

	mu    sync.Mutex
	keys  []*mkKey
	birth int
}

func (s *mkStore) Kind() keystore.Kind {
	if s.panicOn == "kind" {
		panic("store panics")
	}
	if s.kindOverride != "" {
		return s.kindOverride
	}
	return s.inner.Kind()
}

func (s *mkStore) Copyable() bool {
	if s.copyOverride != nil {
		return *s.copyOverride
	}
	return s.inner.Copyable()
}

func (s *mkStore) Place(label string) string {
	if s.panicOn == "place" {
		panic("store panics")
	}
	if p, ok := s.placeFor[label]; ok {
		return p
	}
	return s.inner.Place(label)
}

func (s *mkStore) Refuse(ctx context.Context) error {
	s.log.add("refuse")
	if s.panicOn == "refuse" {
		panic("store panics")
	}
	if s.refuseErr != nil {
		return s.refuseErr
	}
	return s.inner.Refuse(ctx)
}

// Start is forwarded and not logged: it is not one of the acts that the tests of the order watch.
func (s *mkStore) Start(ctx context.Context, labels []string) error {
	return s.inner.Start(ctx, labels)
}

func (s *mkStore) Birth(ctx context.Context, label string) (keystore.Key, error) {
	s.log.add("birth %s", label)
	if s.panicOn == "birth" {
		panic("store panics")
	}
	if err := s.failBirth[label]; err != nil {
		return nil, err
	}
	if s.nilKeyFor == label {
		return nil, nil
	}
	if s.typedNilFor == label {
		var k *mkKey
		return k, nil
	}
	k, err := s.inner.Birth(ctx, label)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.birth++
	s.mu.Unlock()
	if s.afterBirth != nil {
		defer s.afterBirth(label)
	}
	if err := s.keyAndErr[label]; err != nil {
		mk := &mkKey{Key: k, label: label, log: s.log}
		s.mu.Lock()
		s.keys = append(s.keys, mk)
		s.mu.Unlock()
		return mk, err
	}
	if s.wrapKey != nil {
		w := s.wrapKey(label, k)
		if mk, ok := w.(*mkKey); ok {
			s.mu.Lock()
			s.keys = append(s.keys, mk)
			s.mu.Unlock()
		}
		return w, nil
	}
	mk := &mkKey{Key: k, label: label, log: s.log}
	s.mu.Lock()
	s.keys = append(s.keys, mk)
	s.mu.Unlock()
	return mk, nil
}

func (s *mkStore) SaveRemoval(label string, jws []byte) error {
	s.log.add("save-removal %s", label)
	if s.panicOn == "saveremoval" {
		panic("store panics")
	}
	if err := s.failRemoval[label]; err != nil {
		return err
	}
	return s.inner.SaveRemoval(label, jws)
}

func (s *mkStore) ReadRemoval(ctx context.Context, label string) ([]byte, error) {
	s.log.add("read-removal %s", label)
	if s.panicOn == "readremoval" {
		panic("store panics")
	}
	if s.readErr != nil {
		return nil, s.readErr
	}
	b, err := s.inner.ReadRemoval(ctx, label)
	if err != nil {
		return nil, err
	}
	if s.readRemoval != nil {
		return s.readRemoval(label, b), nil
	}
	return b, nil
}

func (s *mkStore) Close() error { s.log.add("store-close"); return s.inner.Close() }

// mkKey wraps a key of the store: it counts and logs the signatures and the closes, and can
// change what it says about itself.
type mkKey struct {
	keystore.Key
	label string
	log   *mkLog

	pub     crypto.PublicKey
	signFn  func(r io.Reader, digest []byte, o crypto.SignerOpts) ([]byte, error)
	kind    keystore.Kind
	copyOv  *bool
	panicOn string // "sign", "public", "close"

	mu     sync.Mutex
	signs  int
	closes int
}

func (k *mkKey) Public() crypto.PublicKey {
	if k.panicOn == "public" {
		panic("key panics")
	}
	if k.pub != nil {
		return k.pub
	}
	return k.Key.Public()
}

func (k *mkKey) Sign(r io.Reader, digest []byte, o crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	k.signs++
	k.mu.Unlock()
	k.log.add("sign %s", k.label)
	if k.panicOn == "sign" {
		panic("key panics")
	}
	if k.signFn != nil {
		return k.signFn(r, digest, o)
	}
	return k.Key.Sign(r, digest, o)
}

func (k *mkKey) Kind() keystore.Kind {
	if k.kind != "" {
		return k.kind
	}
	return k.Key.Kind()
}

func (k *mkKey) Copyable() bool {
	if k.copyOv != nil {
		return *k.copyOv
	}
	return k.Key.Copyable()
}

func (k *mkKey) Close() error {
	k.mu.Lock()
	k.closes++
	k.mu.Unlock()
	if k.panicOn == "close" {
		panic("key panics")
	}
	return k.Key.Close()
}

func (k *mkKey) closed() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.closes
}

// mkRun is one prepared run of MakeRoots: a bundle on the disk, a key directory beside it, the plan
// of the first apply, a recording store and trace, and a console whose lines go to the log.
type mkRun struct {
	t         *testing.T
	root      string
	bundleDir string
	keyDir    string
	found     *ceremony.Found
	plan      *ceremony.PlanOut
	log       *mkLog
	store     *mkStore
	trace     *mkTrace
	console   *ceremony.Console
	stderr    *mkLineWriter
	stdout    *mkLineWriter
	env       ceremony.Env
	clockN    int
	clockMu   sync.Mutex
}

// newMkRun makes the run. The bundle is the first-apply bundle of the tests of the plan, the key
// directory is empty and beside it, and the store is open on it and has not been asked to refuse.
func newMkRun(t *testing.T) *mkRun {
	t.Helper()
	r := &mkRun{t: t, log: &mkLog{}}
	r.root = t.TempDir()
	r.bundleDir = filepath.Join(r.root, "ca")
	r.keyDir = filepath.Join(r.root, "keys")
	for _, d := range []string{r.bundleDir, r.keyDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for p, text := range pfFiles() {
		full := filepath.Join(r.bundleDir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f, err := pfFind(t, r.bundleDir)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	r.found = f
	plan, err := ceremony.MakePlan(f, pfEnv())
	if err != nil {
		t.Fatalf("MakePlan: %v", err)
	}
	r.plan = plan
	inner, err := ceremony.NewSoftwareStore(r.keyDir, r.bundleDir)
	if err != nil {
		t.Fatalf("NewSoftwareStore: %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	r.store = &mkStore{inner: inner, log: r.log}
	r.trace = newMkTrace(r.log)
	r.stderr = &mkLineWriter{log: r.log, prefix: "console: "}
	r.stdout = &mkLineWriter{log: r.log, prefix: "console-out: "}
	r.console = ceremony.NewConsole(r.stderr, r.stdout)
	r.env = ceremony.Env{Now: r.now, Out: r.console}
	return r
}

// now is the clock of the journals: the ceremony time of the plan, and one second more at each call.
func (r *mkRun) now() time.Time {
	r.clockMu.Lock()
	defer r.clockMu.Unlock()
	r.clockN++
	return pfClock.Add(time.Duration(r.clockN) * time.Second)
}

// in is the input of MakeRoots as the run holds it.
func (r *mkRun) in() ceremony.MakeIn {
	return ceremony.MakeIn{
		Env: r.env, Store: r.store, Plan: r.plan, Settings: r.found.Settings, Root: r.found.Root, Trace: r.trace,
	}
}

// make runs MakeRoots with the input of the run.
func (r *mkRun) make() (*ceremony.Made, error) {
	r.t.Helper()
	return ceremony.MakeRoots(context.Background(), r.in())
}

// mustMake runs MakeRoots and fails the test when it is refused.
func (r *mkRun) mustMake() *ceremony.Made {
	r.t.Helper()
	m, err := r.make()
	if err != nil {
		r.t.Fatalf("MakeRoots: %v", err)
	}
	return m
}

// keyFiles are the names of the files in the key directory, sorted: the removal authorisations, and the
// files in the folder test-only-keys under the name test-only-keys/<file>. The folder itself is not listed.
func (r *mkRun) keyFiles() []string {
	r.t.Helper()
	ents, err := os.ReadDir(r.keyDir)
	if err != nil {
		r.t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if e.Name() != "test-only-keys" {
			out = append(out, e.Name())
			continue
		}
		inner, err := os.ReadDir(filepath.Join(r.keyDir, e.Name()))
		if err != nil {
			r.t.Fatal(err)
		}
		for _, f := range inner {
			out = append(out, e.Name()+"/"+f.Name())
		}
	}
	return out
}

// mkKeyFile is the name of the key file of a label under the key directory, as the key driver keeps it:
// test-only-keys/x509-root-<label in lower case>.p8.
func mkKeyFile(label string) string {
	return "test-only-keys/x509-root-" + strings.ToLower(label) + ".p8"
}

// mkCache makes one good ceremony once per test binary would be cheaper, but a test that changes
// nothing may share it: mkGood returns a fresh run that has been made.
func mkGood(t *testing.T) (*mkRun, *ceremony.Made) {
	t.Helper()
	r := newMkRun(t)
	return r, r.mustMake()
}

// mkScalar reads the private scalar of the key file of a label in the key directory.
func mkScalar(t testing.TB, keyDir, label string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(keyDir, mkKeyFile(label)))
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		t.Fatalf("the key file does not parse: %v", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("the key file holds a %T", k)
	}
	raw, err := ec.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// mkAs says which kind of fault an error is, in words that a test can compare.
func mkAs[T error](err error) (T, bool) {
	var target T
	ok := errors.As(err, &target)
	return target, ok
}

// mkBackendReason returns the reason of a *BackendError, or "".
func mkBackendReason(err error) string {
	if b, ok := mkAs[*ceremony.BackendError](err); ok && len(b.Reasons) == 1 {
		return b.Reasons[0]
	}
	return ""
}

// mkWantArtifactError fails the test unless err is an *ArtifactError that names the member.
func mkWantArtifactError(t testing.TB, err error, artifact, member string) {
	t.Helper()
	ae, ok := mkAs[*ceremony.ArtifactError](err)
	if !ok {
		t.Fatalf("the error is %T (%v), want *ArtifactError for %s %s", err, err, artifact, member)
	}
	if !strings.HasPrefix(ae.Artifact, artifact) || ae.Member != member {
		t.Fatalf("the error names %q / %q, want %q / %q: %v", ae.Artifact, ae.Member, artifact, member, err)
	}
	if !pfPrintable(err.Error()) {
		t.Errorf("the text %+q is not printable ASCII", err.Error())
	}
}

// errorsAs is errors.As for a target pointer of any error type.
func errorsAs[T error](err error, target *T) bool { return errors.As(err, target) }

// x509ParseCertificate parses a certificate of the tests.
func x509ParseCertificate(der []byte) (*x509.Certificate, error) { return x509.ParseCertificate(der) }

// bigInt is a big integer of a small number.
func bigInt(n int64) *big.Int { return big.NewInt(n) }
