package ceremony

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"ritueel.id/ritueel/internal/keydir"
	"ritueel.id/ritueel/internal/keystore"
	"ritueel.id/ritueel/internal/keystore/atoomsoftware"
	"ritueel.id/ritueel/internal/keystore/port"
)

// RootStore is the place where the keys of one root are born and kept. One implementation now, the
// software driver of atoom for a test root, reached through the key port ([NewSoftwareStore]). A store of the
// cloud and a store of cards are further implementations; nothing else in the engine changes
// (docs/reference/ceremony-record.md, "The plan": births name the store and the place of each key).
//
// A RootStore is used by one ceremony at a time. Every method of a nil or zero value returns an
// error, and none makes a key.
type RootStore interface {
	// Kind is the kind of the keys that the store makes: the word that the plan gives as the store of
	// a birth.
	Kind() keystore.Kind
	// Copyable is true when a key of the store can be copied: a key file can.
	Copyable() bool
	// Place is the name that the plan and the journal give for the key of a label: the purpose of the key,
	// x509-root- and the label in lower case, never a path and the same for every store. It is "" for a
	// label that is not one upper-case letter.
	Place(label string) string
	// Refuse is every refusal that needs no key: the key directory, and what stands in it already. A
	// store makes no key before Refuse has returned nil.
	Refuse(ctx context.Context) error
	// Start starts the key store for the keys of the labels: for the software driver, the folder of its keys is
	// made in the key directory and the driver is linked in the process. It is called after the person
	// confirmed the plan and before the attempt is written, so that nothing is made before the
	// confirmation. It makes no key. A second call with the same labels does nothing. A store that is not started
	// when the first key is asked for is started then, for every label.
	Start(ctx context.Context, labels []string) error
	// Birth makes the key of a label in the store and reads it back. The caller writes the journal line
	// only after Birth returned. The caller closes the key. The store is started first.
	Birth(ctx context.Context, label string) (keystore.Key, error)
	// SaveRemoval stores the removal authorisation of a label in the key directory and reads it back.
	SaveRemoval(label string, jws []byte) error
	// ReadRemoval returns the removal authorisation of a label as it is stored, so that a check can
	// compare the stored file with the text that was made.
	ReadRemoval(ctx context.Context, label string) ([]byte, error)
	// Close releases the store: the in-process link is stopped and the key directory is released. A second
	// Close does nothing.
	Close() error
}

// errNoStore is the fault of a store that was not made by its constructor.
var errNoStore = errors.New("ceremony: the key store was not made by NewSoftwareStore")

// purposePrefix begins the purpose, and so the place, of the X.509 key of a root.
const purposePrefix = purposeX509Root + "-"

// purposeOf is the purpose of the key of a label: x509-root- and the label in lower case, a name that
// the key port accepts (1 to 64 characters of a-z, 0-9 and a hyphen). It is "" for a label that is not
// one upper-case letter.
func purposeOf(label string) string {
	if len(label) != 1 || label[0] < 'A' || label[0] > 'Z' {
		return ""
	}
	return purposePrefix + strings.ToLower(label)
}

// softwareStore is the [RootStore] over the key port, with the software driver of atom linked in the
// process for a test root. The key directory is the one that [CheckKeyDir] judges ([RootStore.Refuse]
// calls that one function), and the store opens the folder that was checked. The keys are in the folder
// test-only-keys of the key directory, which the driver owns; the removal authorisations are ritueel's
// own files beside that folder.
type softwareStore struct {
	keyDir, bundleDir string

	mu      sync.Mutex
	dir     *keydir.Dir
	link    *atoomsoftware.Link
	labels  []string
	refused bool
	started bool
	closed  bool
}

// NewSoftwareStore opens the key directory of a software test root. keyDir must exist, be a folder, not be
// the bundle folder or inside it, and not be inside the work tree of a repository that holds the bundle;
// a refusal is a [*BackendError] (exit code 4) with the reason code key-dir, as [CheckKeyDir] gives it for
// the same folder. bundleDir is required. The store makes nothing in the key directory before
// [RootStore.Start], and no key before [RootStore.Refuse] has returned nil.
func NewSoftwareStore(keyDir, bundleDir string) (RootStore, error) {
	if keyDir == "" || bundleDir == "" {
		return nil, errors.New("ceremony: the key directory and the bundle folder are both needed for a software store")
	}
	if _, ok := port.Lookup(storeSoftware); !ok {
		return nil, port.ErrUnknownStore
	}
	d, err := keydir.Open(keyDir, bundleDir)
	if err != nil {
		return nil, keyDirError(err)
	}
	return &softwareStore{keyDir: keyDir, bundleDir: bundleDir, dir: d}, nil
}

// use returns the open store, or the reason it cannot be used. The caller holds the lock.
func (s *softwareStore) use() error {
	if s == nil || s.dir == nil {
		return errNoStore
	}
	if s.closed {
		return errors.New("ceremony: the key store is closed")
	}
	return nil
}

// Kind is the kind of the software store, from the table of the key port.
func (s *softwareStore) Kind() keystore.Kind {
	info, _ := port.Lookup(storeSoftware)
	return info.Kind
}

// Copyable is true: a key file can be copied. It comes from the table of the key port.
func (s *softwareStore) Copyable() bool {
	info, _ := port.Lookup(storeSoftware)
	return info.Copyable
}

// Place is the purpose of the key of a label, x509-root-<label in lower case>.
func (s *softwareStore) Place(label string) string { return purposeOf(label) }

// Refuse runs [CheckKeyDir] on the key directory: the folder, and what stands in it. A refusal is a
// [*BackendError]. After a nil return the store may make keys. Only the last answer counts: a call
// forgets an earlier nil first, so a call that refuses, for any reason, leaves the store refusing
// every Birth and SaveRemoval until a later call returns nil. After [RootStore.Start] the folder of the
// test keys is this store's own and is not a use of the key directory.
func (s *softwareStore) Refuse(ctx context.Context) error {
	if s == nil {
		return errNoStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refused = false
	if ctx == nil {
		return errors.New("ceremony: there is no context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.use(); err != nil {
		return err
	}
	if err := checkKeyDir(s.keyDir, s.bundleDir, s.started); err != nil {
		return err
	}
	s.refused = true
	return nil
}

// Start makes the folder test-only-keys in the key directory and links the software driver of atom in the
// process, with one purpose for each label. It needs [RootStore.Refuse] to have returned nil. It asks the
// store what it is, and a store that the table of the key port does not hold is refused. It makes no key.
func (s *softwareStore) Start(ctx context.Context, labels []string) error {
	if ctx == nil {
		return errors.New("ceremony: there is no context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil {
		return errNoStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.start(ctx, labels)
}

// start is [RootStore.Start]. The caller holds the lock.
func (s *softwareStore) start(ctx context.Context, labels []string) error {
	if err := s.use(); err != nil {
		return err
	}
	if s.started {
		if slices.Equal(s.labels, labels) {
			return nil
		}
		return errors.New("ceremony: the key store was started for other labels")
	}
	if !s.refused {
		return errors.New("ceremony: the key directory was not refused or accepted yet, so the key store is not started")
	}
	if len(labels) == 0 {
		return errors.New("ceremony: the key store needs at least one label")
	}
	purposes := make([]string, len(labels))
	for i, l := range labels {
		if purposes[i] = purposeOf(l); purposes[i] == "" || slices.Contains(labels[:i], l) {
			return errors.New("ceremony: the labels are not different upper-case letters")
		}
	}
	link, err := atoomsoftware.Open(s.dir.Path(), purposes)
	if err != nil {
		return starterError(err)
	}
	info, err := port.Describe(ctx, link.Client())
	if err != nil || info.Store != storeSoftware {
		_ = link.Close()
		if err == nil {
			err = port.ErrUnknownStore
		}
		return fmt.Errorf("the key store did not say that it is the software store, and no key was made: %w", err)
	}
	s.link, s.labels, s.started = link, slices.Clone(labels), true
	return nil
}

// allLabels are the labels A to Z, the labels that a store started by its first birth declares.
func allLabels() []string {
	out := make([]string, 0, 26)
	for c := 'A'; c <= 'Z'; c++ {
		out = append(out, string(c))
	}
	return out
}

// Birth makes an ECDSA P-384 key in the store (the key must be absent, the store must say that it made
// it, the public key must read back and a signature must verify: see [port.Birth]). It makes no key before
// [RootStore.Refuse] returned nil. A store that was not started is started here for every label. A key that exists is never adopted, and the
// refusal is a [*BackendError] with the reason key-exists. An error returns no key.
func (s *softwareStore) Birth(ctx context.Context, label string) (keystore.Key, error) {
	if ctx == nil {
		return nil, errors.New("ceremony: there is no context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errNoStore
	}
	name := purposeOf(label)
	if name == "" {
		return nil, errors.New("ceremony: the label is not one upper-case letter")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.use(); err != nil {
		return nil, err
	}
	if !s.refused {
		return nil, errors.New("ceremony: the key directory was not refused or accepted yet, so no key is made")
	}
	if !s.started {
		// A caller that did not start the store (a run starts it, for the labels of its plan, before the
		// attempt) has it started here, for every label.
		if err := s.start(ctx, allLabels()); err != nil {
			return nil, err
		}
	}
	if !slices.Contains(s.labels, label) {
		return nil, errors.New("ceremony: the key store was not started for this label, so no key is made")
	}
	k, err := port.Birth(ctx, s.link.Client(), name)
	if err != nil {
		return nil, birthError(err)
	}
	return k, nil
}

// SaveRemoval stores the removal authorisation of a label as <label>.removal.jws in the key directory,
// beside the folder of the keys.
func (s *softwareStore) SaveRemoval(label string, jws []byte) error {
	if s == nil {
		return errNoStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.use(); err != nil {
		return err
	}
	if !s.refused {
		return errors.New("ceremony: the key directory was not refused or accepted yet, so nothing is stored")
	}
	if err := s.dir.SaveRemoval(label, jws); err != nil {
		return fileError(err)
	}
	return nil
}

// ReadRemoval returns the removal authorisation of a label from its file.
func (s *softwareStore) ReadRemoval(ctx context.Context, label string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("ceremony: there is no context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errNoStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.use(); err != nil {
		return nil, err
	}
	b, err := s.dir.ReadRemoval(label)
	if err != nil {
		return nil, fileError(err)
	}
	return b, nil
}

// Close stops the in-process link and releases the key directory. The folder of the keys and the files
// stay.
func (s *softwareStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var first error
	if s.link != nil {
		first = s.link.Close()
	}
	if s.dir != nil {
		if err := s.dir.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// starterError turns a fault of the start of the driver into the error that a command maps. A folder of
// the test keys that stands already is the refusal key-exists, and a state folder that the driver refuses
// is the refusal key-dir, the key directory that is not fit; any other fault is an ordinary error. No
// text holds a path.
func starterError(err error) error {
	switch {
	case errors.Is(err, atoomsoftware.ErrFolderExists):
		return &BackendError{Reasons: []string{ReasonKeyExists}, Msg: keyDirUsedText + "; nothing was written"}
	case errors.Is(err, atoomsoftware.ErrStateRefused):
		return &BackendError{Reasons: []string{ReasonKeyDir}, Msg: err.Error() + "; no key was made"}
	}
	return fmt.Errorf("the key store could not be started, and no key was made: %w", err)
}

// birthError turns a fault of a birth into the error that a command maps: a key that exists already is the
// refusal key-exists, and any other fault is an ordinary error, never a success.
func birthError(err error) error {
	if errors.Is(err, port.ErrKeyExists) {
		return &BackendError{Reasons: []string{ReasonKeyExists}, Msg: "a key of this purpose exists already in the key store, and an existing key is never adopted; use an empty key directory"}
	}
	return err
}
