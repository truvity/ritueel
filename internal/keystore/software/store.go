package software

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/openpgp"
)

// Mode says how the key files of one root are protected. The zero value is invalid and refused:
// a store that was left at its zero value never means the weakest mode.
type Mode int

const (
	// ModeTest is no encryption: the root is a TEST ONLY root (record 0005, rule 26). The caller
	// takes it from the bundle's root.json (`test`) and from the plan, never from a file.
	ModeTest Mode = iota + 1
	// ModePassphrase is an age file with one scrypt recipient (record 0002, rules 22 and 28), for
	// a root that is not a test root and a holder without cards. It needs a [PassphraseSource].
	ModePassphrase
)

// PassphraseSource gives the passphrase of one key. It is the plug of the passphrase mode: the
// store calls it once for each key that a call saves or opens (an X.509 key, an OpenPGP primary),
// never twice for the same key in one call, and never keeps what it returns. A Config for a test
// root must not set it. [ReaderSource] reads the passphrases from a reader, one line each; a
// prompt at a terminal is the caller's to build.
type PassphraseSource interface {
	// Passphrase returns the passphrase of the key that p names. The bytes are the store's to
	// clear after use; the slice must be a copy that the source does not keep.
	Passphrase(ctx context.Context, p Purpose) ([]byte, error)
}

// Config opens a [Store]. BundleDir is required: a Config without it is refused, so the check of
// the key directory cannot be left out by leaving a field empty. A field that is set for a mode
// that ignores it hides a mistake and is refused.
type Config struct {
	// KeyDir is the key directory, outside the bundle ([CheckKeyDir]).
	KeyDir string
	// BundleDir is the bundle folder that the key directory must not be in.
	BundleDir string
	// Mode says how the files are protected; the zero value is refused.
	Mode Mode
	// Passphrases gives the passphrases of the passphrase mode, which needs it. A test root must
	// leave it nil.
	Passphrases PassphraseSource
}

// fileWriter is what a Store needs to write: the two methods of *fsx.Writer that it calls. A test
// in this package replaces it to record a write and to make one fail.
type fileWriter interface {
	WriteFile(path string, data []byte, perm fs.FileMode) error
	Close() error
}

// Store writes and reads the key files of one bundle in one key directory. It is safe for several
// goroutines; calls run one at a time. After its writer stopped (the first write error, record
// 0006, rule 33) every call that writes returns that error and writes nothing.
//
// A Store never signs, and it cannot tell that a root is a test root: the caller gives the mode.
// A key that [Store.OpenX509] or [Store.OpenOpenPGP] returns must be compared by the caller with
// the pin or the fingerprint in the trust set before it signs; and a copy of an older key file
// that opens fine is not detected here. A caller that makes a new key for a certificate that
// anyone will rely on calls SaveX509 or SaveOpenPGP before it signs with the key for that
// certificate (the OpenPGP self-signature that makes the certificate comes first), and writes its
// birth journal line only after that call returned. The caller closes each key with Key.Close
// when the ceremony ends.
type Store struct {
	mu     sync.Mutex
	mode   Mode
	fsys   fsx.FS           // the key directory, for reads
	w      fileWriter       // the writer of the same folder
	format format           // wraps and unwraps the payload of a file; set by Open
	source PassphraseSource // the passphrases of a passphrase root; nil for a test root
	closed bool
	stop   error // the first error of the writer; set once
}

// Open checks the key directory ([CheckKeyDir]), opens the resolved folder that was checked with
// fsx (which refuses a link as the last element), and returns the Store. The mode and the owner
// of the folder are not checked or changed: on exFAT they mean nothing, and a mode of 0700 is
// the holder's duty.
//
// A zero Mode, an empty BundleDir, a ModeTest with a source set and a ModePassphrase with none (a
// nil interface or a nil pointer in it) are an [ErrParams]. The way that a card opens a key file
// (passkeys and a recovery key) is not built, and there is no Mode for it.
func Open(cfg Config) (*Store, error) {
	switch cfg.Mode {
	case ModeTest:
		if cfg.Passphrases != nil {
			return nil, refuse(ErrParams, "a test root has no passphrase and the source is set")
		}
	case ModePassphrase:
		if nilSource(cfg.Passphrases) {
			return nil, refuse(ErrParams, "a passphrase root needs a source of passphrases")
		}
	default:
		return nil, refuse(ErrParams, "no mode is set; the way that cards open a key file is not built")
	}
	if cfg.BundleDir == "" {
		return nil, refuse(ErrParams, "the bundle folder is empty")
	}
	dir, err := checkKeyDir(os.Stat, cfg.KeyDir, cfg.BundleDir)
	if err != nil {
		return nil, err
	}
	checked, err := os.Stat(dir)
	if err != nil {
		return nil, refuse(ErrKeyDir, "the key directory cannot be looked at")
	}
	w, err := fsx.Open(dir)
	if err != nil {
		if errors.Is(err, fsx.ErrLink) {
			return nil, refuse(ErrKeyDir, "the key directory is a link")
		}
		return nil, refuse(ErrKeyDir, "the key directory cannot be opened")
	}
	if err := stillTheCheckedFolder(os.Stat, dir, cfg.BundleDir, checked); err != nil {
		_ = w.Close()
		return nil, err
	}
	st := &Store{mode: cfg.Mode, fsys: w.FS, w: w, format: plainFormat{}}
	if cfg.Mode == ModePassphrase {
		st.format, st.source = ageFormat{}, cfg.Passphrases
	}
	return st, nil
}

// nilSource reports whether a source is nil: a nil interface, or a nil pointer, map, function or
// channel inside one, which would panic when it is called.
func nilSource(src PassphraseSource) bool {
	if src == nil {
		return true
	}
	switch v := reflect.ValueOf(src); v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Chan, reflect.Slice, reflect.Interface:
		return v.IsNil()
	}
	return false
}

// stillTheCheckedFolder is the look after the open: a link put into a parent of the key directory
// between the check and the open of the folder is followed by the open (fsx refuses a link only at
// the last element), so the path is resolved and checked again, and the folder that it gives must
// be the same file as the one that was checked, by os.SameFile, at the same resolved path.
func stillTheCheckedFolder(stat statFunc, dir, bundleDir string, checked fs.FileInfo) error {
	again, err := checkKeyDir(stat, dir, bundleDir)
	if err != nil {
		return err
	}
	now, err := stat(again)
	if err != nil || again != dir || !os.SameFile(checked, now) {
		return refuse(ErrKeyDir, "the key directory is not the folder that was checked")
	}
	return nil
}

// Close releases the key directory. A second Close does nothing. Every other call after it is an
// [ErrParams].
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.w == nil {
		return nil
	}
	if err := s.w.Close(); err != nil {
		return errors.New("software: the key directory could not be released")
	}
	return nil
}

// begin checks that the Store was made by Open and is not closed. The caller holds the lock.
func (s *Store) begin() error {
	if s == nil || s.fsys == nil || s.w == nil || s.format == nil || s.mode == 0 {
		return refuse(ErrParams, "the store was not made by Open")
	}
	if s.closed {
		return refuse(ErrParams, "the store is closed")
	}
	return nil
}

// HasKeyFiles says whether the key directory holds any key file of either mode: the first `apply`
// refuses a directory that has one. A name that is not a valid file name, or that starts with the
// temporary prefix of the writer, is skipped, and a folder, a link or any other entry that is
// not a regular file is not a key file.
func (s *Store) HasKeyFiles() (bool, error) {
	if s == nil {
		return false, refuse(ErrParams, "the store was not made by Open")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		return false, err
	}
	names, err := s.keyFileNames()
	if err != nil {
		return false, err
	}
	return len(names) > 0, nil
}

// keyFileNames lists the regular files of the key directory that have the name of a key file of
// either mode, with the mode.
func (s *Store) keyFileNames() (map[string]Mode, error) {
	ents, err := s.entries()
	if err != nil {
		return nil, err
	}
	return keyFilesOf(ents), nil
}

// entries lists the key directory: every name in it, of any kind.
func (s *Store) entries() ([]fs.DirEntry, error) {
	ents, err := fsx.ReadDir(s.fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("%w: the key directory could not be listed: %w", ErrKeyDir, err)
	}
	return ents, nil
}

// keyFilesOf picks the regular files with the name of a key file out of a listing.
func keyFilesOf(ents []fs.DirEntry) map[string]Mode {
	out := map[string]Mode{}
	for _, e := range ents {
		name := e.Name()
		m, ok := isKeyFileName(name)
		if ok && e.Type().IsRegular() {
			out[name] = m
		}
	}
	return out
}

// SaveX509 writes the X.509 key of a root as PKCS#8, PEM-armoured as PRIVATE KEY, after the
// marker line of a test root, to `<label>.x509.key.pem`.
func (s *Store) SaveX509(label string, k *Key) error {
	if !labelOK(label) {
		return errLabel
	}
	return s.save(FileX509, label, "", k, encodeX509, parseX509)
}

// SaveOpenPGP writes the primary of a root as the transferable secret key of the page (RFC 9580,
// section 10.2, S2K usage 0), ASCII-armoured with the header `Comment: TEST ONLY`, to
// `<label>.openpgp.key.asc`. cert is the public certificate that openpgp.NewPrimary made; its
// primary must be the public key of k, else the call is an [ErrParams]. The creation time is the
// one in the certificate.
func (s *Store) SaveOpenPGP(label string, k *Key, cert []byte) error {
	if !labelOK(label) {
		return errLabel
	}
	return s.save(FileOpenPGP, label, "", k, func(priv *ecdsa.PrivateKey) ([]byte, error) {
		secret, err := openpgp.SecretKey(cert, priv)
		if err != nil {
			return nil, fmt.Errorf("%w: the certificate and the key do not make a secret key: %w", ErrParams, err)
		}
		return secret, nil
	}, func(payload []byte) (*ecdsa.PrivateKey, error) {
		priv, _, cert2, err := parseOpenPGP(payload)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(cert2, cert) {
			wipe(priv)
			return nil, refuse(ErrKeyFile, "the file does not read back with the certificate that was given")
		}
		return priv, nil
	})
}

// save is the write of a file that holds a private key: make the payload, wrap it, write it, read
// it back, parse it with the code that Open uses and compare it with the key.
func (s *Store) save(kind FileKind, label, reason string, k *Key,
	build func(priv *ecdsa.PrivateKey) ([]byte, error), parse func(payload []byte) (*ecdsa.PrivateKey, error),
) error {
	if s == nil {
		return refuse(ErrParams, "the store was not made by Open")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop != nil {
		return s.stop
	}
	if err := s.begin(); err != nil {
		return err
	}
	var payload []byte
	if err := k.withPrivate(func(priv *ecdsa.PrivateKey) (err error) {
		payload, err = build(priv)
		return err
	}); err != nil {
		return err
	}
	defer func() { clear(payload) }()
	pub := k.publicCopy()
	return s.write(kind, label, reason, payload, func(inner []byte) error {
		priv, err := parse(inner)
		if err != nil {
			return err
		}
		defer wipe(priv)
		return sameKey(pub, priv)
	}, k.markSaved)
}

// sameKey checks that a key read back is the key that was given: the same public key, and a
// SHA-384 digest signed with the key read back verifies with the given public key.
func sameKey(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) error {
	if pub == nil || !pub.Equal(&priv.PublicKey) {
		return refuse(ErrKeyFile, "the key read back is not the key that was given")
	}
	digest := make([]byte, digestLen)
	if _, err := rand.Read(digest); err != nil {
		return errors.New("software: no random bytes for the check of the key read back")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil || !ecdsa.VerifyASN1(pub, digest, sig) {
		return refuse(ErrKeyFile, "the key read back does not sign what the given key verifies")
	}
	return nil
}

// SaveRevocation writes one OpenPGP key revocation signature packet (version 4, type 0x20, at
// most 1 KiB) for a reason, which is one of compromised, superseded, retired and no-reason: the
// packet armoured as PGP SIGNATURE with the header `Comment: TEST ONLY`, to
// `<label>.revocation.<reason>.asc`.
func (s *Store) SaveRevocation(label, reason string, sig []byte) error {
	if !labelOK(label) {
		return errLabel
	}
	if !reasonOK(reason) {
		return refuse(ErrParams, "the reason is not one of compromised, superseded, retired, no-reason")
	}
	if len(sig) > maxRevocationSize {
		return refuse(ErrParams, "the revocation signature is longer than 1 KiB")
	}
	if err := checkRevocation(sig); err != nil {
		return refuse(ErrParams, "the revocation signature is not one version 4 key revocation packet")
	}
	return s.saveText(FileRevocation, label, reason, sig)
}

// SaveRemoval writes the compact JWS of a removal authorisation (three Base64url parts, two dots,
// at most 4 KiB) to `<label>.removal.jws`. Its content is checked by the code that makes and uses
// it, not here.
func (s *Store) SaveRemoval(label string, jws []byte) error {
	if !labelOK(label) {
		return errLabel
	}
	if err := checkRemoval(jws); err != nil {
		return refuse(ErrParams, "the removal authorisation is not a compact JWS of at most 4 KiB")
	}
	return s.saveText(FileRemoval, label, "", jws)
}

// saveText writes a file that holds no private key and reads it back: the payload must come out
// of the file as it went in.
func (s *Store) saveText(kind FileKind, label, reason string, payload []byte) error {
	if s == nil {
		return refuse(ErrParams, "the store was not made by Open")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop != nil {
		return s.stop
	}
	if err := s.begin(); err != nil {
		return err
	}
	return s.write(kind, label, reason, payload, func(got []byte) error {
		if !bytes.Equal(got, payload) {
			return refuse(ErrKeyFile, "the file does not read back as it was given")
		}
		return nil
	}, nil)
}

// write wraps the payload and writes the file, reads it back, unwraps it and checks the payload
// that came out with verify. done is called when the whole has passed. The caller holds the lock
// and has checked the store. A passphrase root asks its source once, after the name has been
// looked at and before the payload is encrypted, and uses that passphrase for the read back too.
// The mode and the format of the store must agree before the name is looked at, the source is
// asked or a byte is encrypted: a passphrase mode has the age format and the test mode the plain
// one, so a store that was put together wrongly writes nothing and never puts a plain file under
// an .age name. A file of the other mode in the folder is still an ErrWrongMode first.
func (s *Store) write(kind FileKind, label, reason string, payload []byte, verify func(payload []byte) error, done func()) error {
	sf, secret := s.format.(secretFormat)
	name := fileName(s.mode, label, kind, reason)
	if name == "" || fsx.CheckName(name) != nil {
		return refuse(ErrParams, "the file name is not valid")
	}
	before, err := s.entries()
	if err != nil {
		return err
	}
	if err := noOtherMode(s.mode, keyFilesOf(before)); err != nil {
		return err
	}
	if !modeAndFormatAgree(s.mode, secret) {
		return refuse(ErrParams, "the mode of the store and its file format do not agree")
	}
	// The name is looked at before a byte of the key goes to the disk: a writer that meets a file
	// of that name has already made, flushed and closed a whole temporary file with the new key.
	for _, e := range before {
		if e.Name() == name {
			s.stop = fmt.Errorf("%w: the file %s stands there: %w", ErrKeyExists, name, fs.ErrExist)
			return s.stop
		}
	}
	if len(payload) > MaxKeyFileSize {
		return refuse(ErrKeyFile, "the key file would be longer than %d bytes", MaxKeyFileSize)
	}
	var pass []byte
	if secret {
		if pass, err = s.passphrase(context.Background(), Purpose{Label: label, File: kind}); err != nil {
			return err
		}
		defer clear(pass)
	}
	var file []byte
	if secret {
		file, err = sf.wrapWith(pass, kind, payload)
	} else {
		file, err = s.format.wrap(kind, payload)
	}
	if err != nil {
		return err
	}
	defer clear(file)
	if len(file) > MaxKeyFileSize {
		return refuse(ErrKeyFile, "the key file would be longer than %d bytes", MaxKeyFileSize)
	}
	if err := s.w.WriteFile(name, file, keyFilePerm); err != nil {
		left := s.leftover(kind, before)
		if errors.Is(err, fs.ErrExist) {
			s.stop = fmt.Errorf("%w: the file %s stands there%s: %w", ErrKeyExists, name, left, err)
		} else {
			s.stop = fmt.Errorf("software: the file %s was not written whole%s: %w", name, left, err)
		}
		return s.stop
	}
	back, err := fsx.ReadFile(s.fsys, name)
	if err != nil {
		return fmt.Errorf("%w: the file %s was written and cannot be read back: %w", ErrKeyFile, name, err)
	}
	defer clear(back)
	if !bytes.Equal(back, file) {
		return fmt.Errorf("%w: the file %s was written and does not read back as it was written", ErrKeyFile, name)
	}
	if err := s.verifyBack(sf, pass, kind, back, verify); err != nil {
		return fmt.Errorf("the file %s was written and failed its check: %w", name, err)
	}
	if done != nil {
		done()
	}
	return nil
}

// modeAndFormatAgree says whether the mode of a store fits the format that it holds: the
// passphrase mode needs a format with a passphrase (an age file) and the test mode a plain one. No
// other mode is built.
func modeAndFormatAgree(mode Mode, secret bool) bool {
	switch mode {
	case ModePassphrase:
		return secret
	case ModeTest:
		return !secret
	}
	return false
}

// verifyBack unwraps the file that was read back and hands the payload to verify. A passphrase
// root opens it with the passphrase that wrote it.
func (s *Store) verifyBack(sf secretFormat, pass []byte, kind FileKind, back []byte, verify func(payload []byte) error) error {
	var inner []byte
	var err error
	if sf != nil {
		inner, err = sf.unwrapWith(pass, kind, back)
	} else {
		inner, err = s.format.unwrap(kind, back)
	}
	if err != nil {
		return err
	}
	defer clear(inner)
	return verify(inner)
}

// passphrase asks the source for the passphrase of one key and checks it with [CheckPassphrase].
// The slice that comes back is the caller's to clear. It is cleared here on every path that
// returns an error.
func (s *Store) passphrase(ctx context.Context, p Purpose) ([]byte, error) {
	if s.source == nil {
		return nil, refuse(ErrParams, "a passphrase root has no source of passphrases")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pass, err := s.source.Passphrase(ctx, p)
	if err != nil {
		clear(pass)
		return nil, fmt.Errorf("software: the source of passphrases gave none: %w", err)
	}
	if err := CheckPassphrase(pass); err != nil {
		clear(pass)
		return nil, err
	}
	return pass, nil
}

// leftover says which temporary file of the writer a failed write may have left in the key
// directory, so that the caller can tell the person to look at it and remove it: nothing is
// deleted here (record 0006, rule 33). It lists the folder again and names every temporary name
// that the listing before the write did not hold. A file that holds a key is the case that
// matters; the other kinds of file hold no key and say nothing.
func (s *Store) leftover(kind FileKind, before []fs.DirEntry) string {
	if kind != FileX509 && kind != FileOpenPGP {
		return ""
	}
	had := map[string]bool{}
	for _, e := range before {
		had[e.Name()] = true
	}
	now, err := s.entries()
	if err != nil {
		return "; a temporary file (a name that starts with " + fsx.TempPrefix + ") may hold the key: remove it"
	}
	var names []string
	for _, e := range now {
		n := e.Name()
		if had[n] || !strings.HasPrefix(strings.ToLower(n), fsx.TempPrefix) {
			continue
		}
		names = append(names, strconv.QuoteToASCII(n))
	}
	if len(names) == 0 {
		return ""
	}
	return "; the temporary file " + strings.Join(names, ", ") + " may hold the key: remove it"
}

// noOtherMode refuses a write into a folder that holds a key file of the other mode: a real root
// never becomes a test root and a test root never becomes a real one (record 0005, rule 26).
func noOtherMode(mode Mode, names map[string]Mode) error {
	for _, m := range names {
		if m != mode {
			return refuse(ErrWrongMode, "the key directory holds a key file of the other mode")
		}
	}
	return nil
}

// OpenX509 opens the X.509 key of a root. The key that it returns must be compared by the caller
// with the pin in the trust set before it signs.
func (s *Store) OpenX509(ctx context.Context, label string) (*Key, error) {
	if !labelOK(label) {
		return nil, errLabel
	}
	payload, err := s.read(ctx, FileX509, label, "")
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	priv, err := parseX509(payload)
	if err != nil {
		return nil, err
	}
	return fromPrivate(priv), nil
}

// OpenPGPKey is a primary opened from its key file: the key, the creation time that fixes the
// fingerprint (docs/reference/bundle.md, root.json `openpgp_created`) and the public certificate.
type OpenPGPKey struct {
	Key     *Key
	Created time.Time
	Cert    []byte // the public certificate: key packet, user ID, self-signature
}

// OpenOpenPGP opens the primary of a root. The fingerprint of the certificate that it returns must
// be compared by the caller with the one in the trust set before the key signs.
func (s *Store) OpenOpenPGP(ctx context.Context, label string) (*OpenPGPKey, error) {
	if !labelOK(label) {
		return nil, errLabel
	}
	payload, err := s.read(ctx, FileOpenPGP, label, "")
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	priv, created, cert, err := parseOpenPGP(payload)
	if err != nil {
		return nil, err
	}
	return &OpenPGPKey{Key: fromPrivate(priv), Created: created, Cert: cert}, nil
}

// ReadRevocation returns the revocation signature packet of a label and a reason.
func (s *Store) ReadRevocation(ctx context.Context, label, reason string) ([]byte, error) {
	if !labelOK(label) {
		return nil, errLabel
	}
	if !reasonOK(reason) {
		return nil, refuse(ErrParams, "the reason is not one of compromised, superseded, retired, no-reason")
	}
	payload, err := s.read(ctx, FileRevocation, label, reason)
	if err != nil {
		return nil, err
	}
	if err := checkRevocation(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// ReadRemoval returns the compact JWS of the removal authorisation of a label.
func (s *Store) ReadRemoval(ctx context.Context, label string) ([]byte, error) {
	if !labelOK(label) {
		return nil, errLabel
	}
	payload, err := s.read(ctx, FileRemoval, label, "")
	if err != nil {
		return nil, err
	}
	if err := checkRemoval(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// read returns the payload of a key file. The order is fixed: the context, the store, the file
// of the store's own mode (a file of the other mode is an [ErrWrongMode] and is never parsed),
// the size (before any parse), and then the unwrapping of the mode's format.
func (s *Store) read(ctx context.Context, kind FileKind, label, reason string) ([]byte, error) {
	if ctx == nil {
		return nil, refuse(ErrParams, "the context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, refuse(ErrParams, "the store was not made by Open")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		return nil, err
	}
	name := fileName(s.mode, label, kind, reason)
	if name == "" || fsx.CheckName(name) != nil {
		return nil, refuse(ErrParams, "the file name is not valid")
	}
	file, err := fsx.ReadFile(s.fsys, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if other := fileName(otherMode(s.mode), label, kind, reason); s.exists(other) {
				return nil, refuse(ErrWrongMode, "the key file of the label is a file of the other mode")
			}
		}
		return nil, fmt.Errorf("%w: the file %s cannot be read: %w", ErrKeyFile, name, err)
	}
	defer clear(file)
	if len(file) > MaxKeyFileSize {
		return nil, refuse(ErrKeyFile, "the key file is longer than %d bytes", MaxKeyFileSize)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sf, secret := s.format.(secretFormat)
	if !secret {
		return s.format.unwrap(kind, file)
	}
	// The header is looked at before the passphrase is asked: a file that is refused costs no
	// prompt and no scrypt.
	if err := sf.inspect(file); err != nil {
		return nil, err
	}
	pass, err := s.passphrase(ctx, Purpose{Label: label, File: kind})
	if err != nil {
		return nil, err
	}
	defer clear(pass)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return sf.unwrapWith(pass, kind, file)
}

// exists reports whether the key directory lists a name. It never reads the file.
func (s *Store) exists(name string) bool {
	names, err := s.keyFileNames()
	if err != nil {
		return false
	}
	_, ok := names[name]
	return ok
}

// otherMode is the mode that is not m.
func otherMode(m Mode) Mode {
	if m == ModeTest {
		return ModePassphrase
	}
	return ModeTest
}

// errLabel is the refusal of a label that is not one upper-case ASCII letter. The text does not
// repeat the label.
var errLabel = refuse(ErrParams, "the label is not one upper-case letter A to Z")
