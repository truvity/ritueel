package ceremony

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"sync"

	"ritueel.id/ritueel/internal/keystore"
	"ritueel.id/ritueel/internal/keystore/software"
)

// RootStore is the place where the keys of one root are born and kept. One implementation now, the
// software store in its TEST ONLY mode ([NewSoftwareStore]). A store of the cloud, the passphrase mode
// and a store of cards are further implementations; nothing else in the engine changes
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
	// Place is the name that the plan and the journal give for the key of a label: the name of the key
	// file for a software store, never a path. It is "" for a label that is not one upper-case letter.
	Place(label string) string
	// Refuse is every refusal that needs no key: the key directory, and key files that exist
	// already. A store makes no key before Refuse has returned nil.
	Refuse(ctx context.Context) error
	// Birth makes the key of a label, saves it where it lives and reads it back. The caller writes the
	// journal line only after Birth returned. The caller closes the key.
	Birth(ctx context.Context, label string) (keystore.Key, error)
	// SaveRemoval stores the removal authorisation of a label next to the key and reads it back.
	SaveRemoval(label string, jws []byte) error
	// ReadRemoval returns the removal authorisation of a label as it is stored, so that a check can
	// compare the stored file with the text that was made.
	ReadRemoval(ctx context.Context, label string) ([]byte, error)
	// Close releases the store. A second Close does nothing.
	Close() error
}

// errNoStore is the fault of a store that was not made by its constructor.
var errNoStore = errors.New("ceremony: the key store was not made by NewSoftwareStore")

// softwareStore is the [RootStore] over the software store in its TEST ONLY mode. The key directory
// is the one that [CheckKeyDir] judges ([RootStore.Refuse] calls that one function), and the store of
// the library opens the folder that was checked.
type softwareStore struct {
	keyDir, bundleDir string

	mu      sync.Mutex
	st      *software.Store
	refused bool
	closed  bool
}

// NewSoftwareStore opens the key directory of a software test root: ModeTest of the software store,
// which writes plain key files marked TEST ONLY. keyDir must exist, be a folder, not be the bundle
// folder or inside it, and not be inside the work tree of a repository that holds the bundle; a
// refusal is a [*BackendError] (exit code 4) with the reason code of the key store, key-dir, as
// [CheckKeyDir] gives it for the same folder. bundleDir is required. The store makes no key before [RootStore.Refuse] has returned nil.
func NewSoftwareStore(keyDir, bundleDir string) (RootStore, error) {
	if keyDir == "" || bundleDir == "" {
		return nil, errors.New("ceremony: the key directory and the bundle folder are both needed for a software store")
	}
	st, err := software.Open(software.Config{KeyDir: keyDir, BundleDir: bundleDir, Mode: software.ModeTest})
	if err != nil {
		return nil, keyDirError(err)
	}
	return &softwareStore{keyDir: keyDir, bundleDir: bundleDir, st: st}, nil
}

// use returns the open store, or the reason it cannot be used. The caller holds the lock.
func (s *softwareStore) use() (*software.Store, error) {
	if s == nil || s.st == nil {
		return nil, errNoStore
	}
	if s.closed {
		return nil, errors.New("ceremony: the key store is closed")
	}
	return s.st, nil
}

// Kind is [keystore.KindSoftware].
func (s *softwareStore) Kind() keystore.Kind { return keystore.KindSoftware }

// Copyable is true: a key file can be copied.
func (s *softwareStore) Copyable() bool { return true }

// Place is the name of the key file of a label, <label>.x509.key.pem.
func (s *softwareStore) Place(label string) string {
	if len(label) != 1 || label[0] < 'A' || label[0] > 'Z' {
		return ""
	}
	return label + keyFileSuffix
}

// Refuse runs [CheckKeyDir] on the key directory: the folder, and the key files that stand in it. A
// refusal is a [*BackendError]. After a nil return the store may make keys. Only the last answer
// counts: a call forgets an earlier nil first, so a call that refuses, for any reason, leaves the
// store refusing every Birth and SaveRemoval until a later call returns nil.
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
	if _, err := s.use(); err != nil {
		return err
	}
	if err := CheckKeyDir(s.keyDir, s.bundleDir); err != nil {
		return err
	}
	s.refused = true
	return nil
}

// Birth makes an ECDSA P-384 key in memory, writes it to the key file of the label (the store writes
// the file, reads it back and compares the key) and opens the file again to compare the public key.
// It makes no key before [RootStore.Refuse] returned nil. A file that exists is never replaced, and
// the refusal is a [*BackendError] with the reason key-exists. An error returns no key, and a key
// that was made and could not be saved is closed.
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
	if s.Place(label) == "" {
		return nil, errors.New("ceremony: the label is not one upper-case letter")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.use()
	if err != nil {
		return nil, err
	}
	if !s.refused {
		return nil, errors.New("ceremony: the key directory was not refused or accepted yet, so no key is made")
	}
	k, err := software.Generate()
	if err != nil {
		return nil, keyStoreError(err)
	}
	if err := st.SaveX509(label, k); err != nil {
		_ = k.Close()
		return nil, keyStoreError(err)
	}
	if !k.Saved() {
		_ = k.Close()
		return nil, errors.New("ceremony: the key was written and is not marked as saved, so it is not used")
	}
	back, err := st.OpenX509(ctx, label)
	if err != nil {
		_ = k.Close()
		return nil, keyStoreError(err)
	}
	defer func() { _ = back.Close() }()
	pub, ok := k.Public().(*ecdsa.PublicKey)
	got, ok2 := back.Public().(*ecdsa.PublicKey)
	if !ok || !ok2 || pub == nil || got == nil || !pub.Equal(got) {
		_ = k.Close()
		return nil, errors.New("ceremony: the key file does not read back as the key that was made")
	}
	return k, nil
}

// SaveRemoval stores the removal authorisation of a label as <label>.removal.jws next to the key.
func (s *softwareStore) SaveRemoval(label string, jws []byte) error {
	if s == nil {
		return errNoStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.use()
	if err != nil {
		return err
	}
	if !s.refused {
		return errors.New("ceremony: the key directory was not refused or accepted yet, so nothing is stored")
	}
	if err := st.SaveRemoval(label, jws); err != nil {
		return keyStoreError(err)
	}
	return nil
}

// ReadRemoval returns the removal authorisation of a label from its file.
func (s *softwareStore) ReadRemoval(ctx context.Context, label string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("ceremony: there is no context")
	}
	if s == nil {
		return nil, errNoStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.use()
	if err != nil {
		return nil, err
	}
	b, err := st.ReadRemoval(ctx, label)
	if err != nil {
		return nil, keyStoreError(err)
	}
	return b, nil
}

// Close releases the key directory.
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
	if s.st == nil {
		return nil
	}
	return s.st.Close()
}

// keyStoreError turns a fault of the software store into the error that a command maps: a refusal
// that has a reason code is a [*BackendError], and any other is an ordinary error with the text of
// the store, which holds fixed words and no path and no key.
func keyStoreError(err error) error {
	if code := software.Code(err); code != "" {
		return &BackendError{Reasons: []string{code}, Msg: err.Error()}
	}
	return err
}
