package software

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
)

// The passphrases of the tests are made-up text.
const (
	testPass  = "plover quartz-lamp hedgerow tumbles"
	testPass2 = "marmot zephyr-kettle anvil drifts"
)

// lowWork lowers the work factor that is written and the lowest that is read to 10 for one test, so
// that the tests that do not show the cost of scrypt do not pay for it. A test that calls it is not
// parallel. The production values are 18 and 18 (see TestTheProductionWorkFactorsAre18And22).
func lowWork(t testing.TB) {
	t.Helper()
	written, lowest := workFactorWritten, workFactorLowest
	workFactorWritten, workFactorLowest = 10, 10
	t.Cleanup(func() { workFactorWritten, workFactorLowest = written, lowest })
}

// passSource is a PassphraseSource that records what it is asked and keeps the slices that it gave,
// so that a test can look at them after the call.
type passSource struct {
	mu    sync.Mutex
	def   string                 // the passphrase of every key that has no entry in by
	by    map[Purpose]string     // the passphrase of one key
	err   error                  // returned instead of a passphrase when set
	raw   func(p Purpose) []byte // when set, the slice that is returned (it may be nil, short, anything)
	hook  func(ctx context.Context, p Purpose)
	asked []Purpose
	given [][]byte
}

func newPassSource(def string) *passSource { return &passSource{def: def} }

func (s *passSource) Passphrase(ctx context.Context, p Purpose) ([]byte, error) {
	s.mu.Lock()
	s.asked = append(s.asked, p)
	hook, err, raw := s.hook, s.err, s.raw
	pass := s.def
	if v, ok := s.by[p]; ok {
		pass = v
	}
	s.mu.Unlock()
	if hook != nil {
		hook(ctx, p)
	}
	var out []byte
	if raw != nil {
		out = raw(p)
	} else {
		out = []byte(pass)
	}
	s.mu.Lock()
	s.given = append(s.given, out)
	s.mu.Unlock()
	if err != nil {
		return out, err
	}
	return out, nil
}

func (s *passSource) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.asked)
}

func (s *passSource) purposes() []Purpose {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Purpose(nil), s.asked...)
}

// allZero reports whether every byte of b is zero (and b is not empty).
func allZero(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// openPassStore opens a Store in ModePassphrase on a new bundle and key folder.
func openPassStore(t testing.TB, src PassphraseSource) (s *Store, bundle, keys string) {
	t.Helper()
	bundle, keys = newBundle(t)
	s, err := Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase, Passphrases: src})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, bundle, keys
}

// recAge is a format that holds an ageFormat and counts the calls that reach it: the three methods
// of secretFormat and the two of format. The Store picks the passphrase path by the type
// secretFormat, so a wrapper has to forward all of them.
type recAge struct {
	inner    ageFormat
	inspects int
	wraps    int
	unwraps  int
	plain    int
}

func (f *recAge) wrap(kind FileKind, payload []byte) ([]byte, error) {
	f.plain++
	return f.inner.wrap(kind, payload)
}

func (f *recAge) unwrap(kind FileKind, file []byte) ([]byte, error) {
	f.plain++
	return f.inner.unwrap(kind, file)
}

func (f *recAge) inspect(file []byte) error {
	f.inspects++
	return f.inner.inspect(file)
}

func (f *recAge) wrapWith(pass []byte, kind FileKind, payload []byte) ([]byte, error) {
	f.wraps++
	return f.inner.wrapWith(pass, kind, payload)
}

func (f *recAge) unwrapWith(pass []byte, kind FileKind, file []byte) ([]byte, error) {
	f.unwraps++
	return f.inner.unwrapWith(pass, kind, file)
}

var (
	_ format       = (*recAge)(nil)
	_ secretFormat = (*recAge)(nil)
)

// recordAge puts a recording age format in a passphrase Store.
func recordAge(t testing.TB, s *Store) *recAge {
	t.Helper()
	if _, ok := s.format.(ageFormat); !ok {
		t.Fatalf("the format of the store is %T, not an ageFormat", s.format)
	}
	f := &recAge{}
	s.format = f
	return f
}

// The hand-built header of an age file: the version line, the stanzas, a MAC line that is made up,
// and then a payload that is made up. The reader refuses on the stanzas before it looks at the MAC,
// so a header that is refused needs neither.
const ageVersionLine = "age-encryption.org/v1\n"

var saltOf16 = bytes.Repeat([]byte{7}, 16)

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

// stanzaText is one stanza as the format writes it: the line with the type and the arguments, and
// the body in lines of 64 characters, the last one shorter (an empty one when the body ends a line).
func stanzaText(typ string, args []string, body []byte) string {
	var b strings.Builder
	b.WriteString("-> " + typ)
	for _, a := range args {
		b.WriteString(" " + a)
	}
	b.WriteString("\n")
	enc := b64(body)
	for len(enc) >= 64 {
		b.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	b.WriteString(enc + "\n")
	return b.String()
}

// scryptBody is a body of the length that a scrypt stanza has.
func scryptBody() []byte { return bytes.Repeat([]byte{9}, scryptBodyLen) }

// goodArgs is the arguments of a scrypt stanza with a work factor.
func goodArgs(wf string) []string { return []string{b64(saltOf16), wf} }

// headerOf is a whole header and a payload that is made up, for the stanzas of the text.
func headerOf(stanzas ...string) []byte {
	var b strings.Builder
	b.WriteString(ageVersionLine)
	for _, s := range stanzas {
		b.WriteString(s)
	}
	b.WriteString("--- " + b64(bytes.Repeat([]byte{1}, 32)) + "\n")
	b.Write(bytes.Repeat([]byte{2}, 64))
	return []byte(b.String())
}

// scryptStanza is the stanza of a good passphrase file with the given work factor text.
func scryptStanza(wf string) string { return stanzaText("scrypt", goodArgs(wf), scryptBody()) }

// stanzaOf is the same as a value that the library hands to an identity.
func stanzaOf(typ string, args []string, body []byte) *age.Stanza {
	return &age.Stanza{Type: typ, Args: args, Body: body}
}

// stubIdentity counts the calls and gives the answer of a passphrase that does not match.
type stubIdentity struct{ calls int }

func (s *stubIdentity) Unwrap([]*age.Stanza) ([]byte, error) {
	s.calls++
	return nil, age.ErrIncorrectIdentity
}

// headerLen is the length of the header of an age file: the version line, the stanzas and the
// MAC line with its line end.
func headerLen(t testing.TB, file []byte) int {
	t.Helper()
	i := bytes.Index(file, []byte("\n--- "))
	if i < 0 {
		t.Fatal("no MAC line in the file")
	}
	j := bytes.IndexByte(file[i+1:], '\n')
	if j < 0 {
		t.Fatal("the MAC line has no end")
	}
	return i + 1 + j + 1
}

// libraryFile is a file that the library itself writes for a passphrase at a work factor, with
// the payload: the writer that is not ours.
func libraryFile(t testing.TB, pass string, wf int, payload []byte) []byte {
	t.Helper()
	rcp, err := age.NewScryptRecipient(pass)
	if err != nil {
		t.Fatal(err)
	}
	rcp.SetWorkFactor(wf)
	var out bytes.Buffer
	w, err := age.Encrypt(&out, rcp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// libraryOpen is the reader that is not ours: the library with the passphrase and no limit of ours.
func libraryOpen(t testing.TB, pass string, file []byte) ([]byte, error) {
	t.Helper()
	id, err := age.NewScryptIdentity(pass)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(file), id)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// wantRefusal checks that err wraps the sentinel, gives the code, and holds neither the passphrase
// nor any of the strings in text.
func wantRefusal(t testing.TB, err, sentinel error, code string, text ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %v", sentinel)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("the error is %v, want %v", err, sentinel)
	}
	if Code(err) != code {
		t.Errorf("the code is %q, want %q", Code(err), code)
	}
	for _, s := range text {
		if s != "" && strings.Contains(err.Error(), s) {
			t.Errorf("the error holds %q: %v", s, err)
		}
	}
}
