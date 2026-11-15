package ceremony

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/trustset"
	"ritueel.id/ritueel/internal/wanted"
)

// The folders of the bundle that the artifacts of a first apply stand in (docs/reference/bundle.md,
// "The layout").
const (
	// rootsDir holds roots/<label>/root.json.
	rootsDir = "roots"
	// trustDir holds the trust sets, trust/<number>-<8 characters>/.
	trustDir = "trust"
)

// rootKind is one kind of root that the engine can make. The table [rootKinds] has one kind, the
// X.509 root; the OpenPGP root comes later, and a kind that is not in the table is refused in Find
// as not built. A kind makes the keys of a plan, the artifacts of its first apply, and checks each
// artifact by code that did not make it.
type rootKind interface {
	// Make is the births, the signatures and the checks of one root: it asks the store for each key,
	// writes the lines of the two journals, makes the artifacts and judges each one. It writes no
	// file of the bundle.
	Make(ctx context.Context, in MakeIn) (*Made, error)
}

// rootKinds is the one table of kinds that the engine can make.
var rootKinds = map[wanted.RootKind]rootKind{
	wanted.RootX509: x509Kind{},
}

// MakeIn is what [MakeRoots] needs. Every member is required: a zero MakeIn makes nothing.
type MakeIn struct {
	// Env gives the clock for the lines of the journals and the console on which the fingerprints
	// are shown. The serials and the times are the plan's, and the clock is not read for them.
	Env Env
	// Store is where the keys are born and kept.
	Store RootStore
	// Plan is the plan, as [ReadPlanOut] or [MakePlan] returned it: the one typed reading that the
	// person confirmed.
	Plan *PlanOut
	// Settings is ritueel.yaml, which gives the name in the common name of a root.
	Settings *wanted.Settings
	// Root is the wanted root file the plan used.
	Root *wanted.Root
	// Trace is where the lines of the two journals are written.
	Trace Trace
}

// MadeRoot is one root key of a first apply, with the public artifacts made for it.
type MadeRoot struct {
	// Label is the label of the key.
	Label string
	// Pin is the pin of the key: the SHA-256 of its DER SubjectPublicKeyInfo.
	Pin string
	// Place is the place of the key in its store, as the plan gives it.
	Place string
	// Certificate is the DER of its root certificate. It is in ca-bundle.pem and in no file of
	// its own.
	Certificate []byte
	// RemovalSHA256 is the SHA-256 of its removal authorisation, which is kept in the key store
	// and not in the bundle.
	RemovalSHA256 string
	// RootJSONPath is the path of its root.json in the bundle, roots/<label>/root.json.
	RootJSONPath string
	// RootJSON is the bytes of its root.json: the canonical form, the file that is written.
	RootJSON []byte
}

// Made is what [MakeRoots] returns: the artifacts of the first apply, each judged by the seven checks of artifacts.go, ready
// to be written by the caller in the order of the run. Nothing in it is a secret.
type Made struct {
	// Roots are the keys, in label order.
	Roots []MadeRoot
	// Set is the first trust set: root-list.json, root-list.jws and ca-bundle.pem.
	Set *trustset.Set
	// Record is the root of the ceremony record: the plan's root with the X.509 pin of the key that
	// signed, a test root that can be copied.
	Record files.PlanRoot
	// Checked names the checks that passed, in this fixed order: "root-certificate", "removal-authorisation",
	// "root-list", "ca-bundle", "root-json", "plan" and "journals". The plan against the born keys runs
	// first, so that no later step reads the list of born keys before it is known to be whole.
	Checked []string
}

// TrustSetDir is the folder of the trust set in the bundle, trust/<number>-<8 characters>. It is ""
// for a Made that holds no set.
func (m *Made) TrustSetDir() string {
	if m == nil || m.Set == nil || m.Set.Name() == "" {
		return ""
	}
	return trustDir + "/" + m.Set.Name()
}

// Artifacts are the paths in the bundle of the files that the ceremony writes besides its own
// folder, in the byte order of the path text: the root.json of each key and the files of the trust
// set, whose names are those of the set. The key files are not in the bundle and are not listed.
func (m *Made) Artifacts() []string {
	if m == nil {
		return nil
	}
	var out []string
	for _, r := range m.Roots {
		out = append(out, r.RootJSONPath)
	}
	if dir := m.TrustSetDir(); dir != "" {
		for _, f := range m.Set.Files() {
			out = append(out, dir+"/"+f.Name)
		}
	}
	slices.Sort(out)
	return out
}

// MakeError is a fault of the making of the keys and the artifacts: the step, and what is wrong. Its
// text is made once, in printable ASCII, and the cause stays reachable with errors.Is and
// errors.As. An [*ArtifactError] and a [*BackendError] are returned as they are, and are not wrapped.
type MakeError struct {
	// Step is the step: "input", "births", "fingerprints", "signatures", "list" or "checks".
	Step string
	// Reason says what is wrong, with the text of the cause after it.
	Reason string
	err    error
}

// Error says the step and the reason.
func (e *MakeError) Error() string {
	if e == nil {
		return "make: no error"
	}
	return "make " + e.Step + ": " + e.Reason
}

// Unwrap returns the cause.
func (e *MakeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// makeErr makes a MakeError. The text of the cause is taken once.
func makeErr(step string, cause error, format string, args ...any) *MakeError {
	reason := fmt.Sprintf(format, args...)
	if t := causeText(cause); t != "" {
		reason += ": " + t
	}
	return &MakeError{Step: step, Reason: reason, err: cause}
}

// guard calls fn and turns a panic of it into an error: a store, a key or a trace that panics is the
// fault of that one, and the engine goes on to refuse and does not crash.
func guard(what string, fn func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("ceremony: the %s panicked", what)
		}
	}()
	return fn()
}

// isNilValue reports whether v is nil or holds a nil pointer, map, slice, function or channel.
func isNilValue(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// MakeRoots makes the keys and the artifacts of the first apply of the root that the plan names, with
// the kind of root that its wanted file has: the births, the signatures, and the seven checks of artifacts.go. It
// is the births, the signatures and the checks of the run, and it writes no file of the bundle: the caller writes the
// artifacts in the order of the run, from the bytes that the returned [Made] holds. It runs [RootStore.Refuse]
// first and checks the plan against the store before the first key is made. After each key is born it
// writes one line of the birth journal; after the last it prints the fingerprint of each key; after each
// signature it writes one line of the journal of signatures; and it checks every artifact before it
// returns it. A fault is an error and no Made comes with it. The keys are closed before it returns.
// What a fault leaves is what the order leaves: the key files and the lines that were written stay,
// and nothing is deleted.
func MakeRoots(ctx context.Context, in MakeIn) (*Made, error) {
	if ctx == nil {
		return nil, makeErr("input", nil, "there is no context")
	}
	if in.Root == nil || !in.Root.Valid() {
		return nil, makeErr("input", nil, "the wanted root file was not read by its reader")
	}
	kind, ok := rootKinds[in.Root.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: a root of the kind %s", ErrNotBuilt, string(in.Root.Kind))
	}
	return kind.Make(ctx, in)
}

// tapTrace is a [Trace] that keeps the lines that its journals accepted, so that the journals can be
// judged by [CheckJournals] before anything else is written.
type tapTrace struct {
	births, signatures *tapJournal
}

// newTap wraps the journals of a trace. It returns an error for a trace that holds no journal.
func newTap(tr Trace) (*tapTrace, error) {
	if isNilValue(tr) {
		return nil, errors.New("there is no trace")
	}
	var b, s Journal
	if err := guard("trace", func() error { b, s = tr.Births(), tr.Signatures(); return nil }); err != nil {
		return nil, err
	}
	if isNilValue(b) || isNilValue(s) {
		return nil, errors.New("the trace holds no journal")
	}
	return &tapTrace{births: &tapJournal{inner: b}, signatures: &tapJournal{inner: s}}, nil
}

// tapJournal appends to a journal and keeps a copy of each line that it accepted.
type tapJournal struct {
	inner Journal
	mu    sync.Mutex
	lines [][]byte
}

// Append writes the line to the journal and, when the journal accepted it, keeps a copy.
func (t *tapJournal) Append(line []byte) error {
	own := slices.Clone(line)
	if err := guard("journal", func() error { return t.inner.Append(own) }); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = append(t.lines, own)
	return nil
}

// read returns the lines that were accepted, as a journal read with no half line.
func (t *tapJournal) read() JournalRead {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := JournalRead{}
	for _, l := range t.lines {
		out.Lines = append(out.Lines, slices.Clone(l))
	}
	return out
}
