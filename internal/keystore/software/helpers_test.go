package software

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/openpgp"
)

// The moments of the test certificates: the creation time of the primary and a ceremony time.
var (
	testCreated  = time.Unix(1767225600, 0).UTC() // 2026-01-01
	testCeremony = time.Unix(1794744000, 0).UTC() // 2026-11-15 12:00:00 UTC
)

// newBundle makes two folders under t.TempDir(): a bundle folder with a ritueel.yaml and an empty
// history folder, and a key folder beside it. Both are the real file system.
func newBundle(t testing.TB) (bundle, keys string) {
	t.Helper()
	root := t.TempDir()
	if insideWorkTree(root) {
		t.Skip("the temporary folder is inside a work tree: the tests of the key folder need one that is not")
	}
	bundle = filepath.Join(root, "bundle")
	keys = filepath.Join(root, "keys")
	for _, d := range []string{bundle, filepath.Join(bundle, "history"), keys} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bundle, "ritueel.yaml"), []byte("name: Example Test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundle, keys
}

// insideWorkTree says whether dir or a folder above it holds a .git entry. It is written here, apart
// from the function under test, so that a fault in that function cannot make a test skip itself.
func insideWorkTree(dir string) bool {
	for cur := dir; ; cur = filepath.Dir(cur) {
		if _, err := os.Lstat(filepath.Join(cur, ".git")); err == nil {
			return true
		}
		if filepath.Dir(cur) == cur {
			return false
		}
	}
}

// openStore opens a Store in ModeTest on a new bundle and key folder and closes it at the end.
func openStore(t testing.TB) (s *Store, bundle, keys string) {
	t.Helper()
	bundle, keys = newBundle(t)
	s, err := Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModeTest})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, bundle, keys
}

func mustGenerate(t testing.TB) *Key {
	t.Helper()
	k, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { _ = k.Close() })
	return k
}

// scalarBytes is a copy of the 48 bytes of the scalar of a key.
func scalarBytes(t testing.TB, k *Key) []byte {
	t.Helper()
	var out []byte
	err := k.withPrivate(func(priv *ecdsa.PrivateKey) error {
		b, err := priv.Bytes()
		out = bytes.Clone(b)
		return err
	})
	if err != nil {
		t.Fatalf("the scalar of the key: %v", err)
	}
	return out
}

func mustUserID(t testing.TB) string {
	t.Helper()
	uid, err := openpgp.UserID("Example Test", "A", "release@example.org", true)
	if err != nil {
		t.Fatal(err)
	}
	return uid
}

// certFor makes the public certificate of a primary whose key is k, with the signer of the
// package under test.
func certFor(t testing.TB, k *Key) []byte {
	t.Helper()
	uid := mustUserID(t)
	cert, err := openpgp.NewPrimary(rand.Reader, openpgp.PrimaryParams{
		Key: k, CreationTime: testCreated, CeremonyTime: testCeremony,
		ExpiresAt: testCeremony.AddDate(3, 0, 0), UserID: uid,
	})
	if err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	return cert
}

// A canary is one form that a leak of a secret could take.
type canary struct {
	name string
	text []byte
}

// canaries is a set of forms of the secrets of a test.
type canaries []canary

// find returns the name of the first canary that data holds, or "".
func (c canaries) find(data []byte) string {
	for _, f := range c {
		if len(f.text) > 0 && bytes.Contains(data, f.text) {
			return f.name
		}
	}
	return ""
}

// findText is find for a string.
func (c canaries) findText(s string) string { return c.find([]byte(s)) }

func (c canaries) with(more canaries) canaries { return append(append(canaries{}, c...), more...) }

// keysOf returns every form of the secret of a key that a leak could take: the 48 bytes of the
// scalar, its hex in both cases, its Base64 in the four forms, its decimal text, the DER of the
// PKCS#8 and its Base64, each 24-character window of the PEM body that no other key shares (the
// part of a PKCS#8 that every P-384 key has is not a secret), and, when the certificate is given,
// the packet bytes of the secret key with their Base64 and hex.
func keysOf(t testing.TB, k *Key, cert []byte) canaries {
	t.Helper()
	d := scalarBytes(t, k)
	var out canaries
	add := func(name string, b []byte) { out = append(out, canary{name, bytes.Clone(b)}) }
	add("scalar", d)
	add("scalar hex", []byte(hex.EncodeToString(d)))
	add("scalar HEX", []byte(strings.ToUpper(hex.EncodeToString(d))))
	for _, enc := range []struct {
		name string
		e    *base64.Encoding
	}{{"std", base64.StdEncoding}, {"url", base64.URLEncoding}, {"std raw", base64.RawStdEncoding}, {"url raw", base64.RawURLEncoding}} {
		add("scalar base64 "+enc.name, []byte(enc.e.EncodeToString(d)))
	}
	add("scalar decimal", []byte(new(big.Int).SetBytes(d).String()))

	var der []byte
	if err := k.withPrivate(func(priv *ecdsa.PrivateKey) (err error) {
		der, err = x509.MarshalPKCS8PrivateKey(priv)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	add("pkcs8 der", der)
	body := base64.StdEncoding.EncodeToString(der)
	add("pkcs8 base64", []byte(body))
	other := mustGenerate(t)
	var otherDER []byte
	if err := other.withPrivate(func(priv *ecdsa.PrivateKey) (err error) {
		otherDER, err = x509.MarshalPKCS8PrivateKey(priv)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	otherBody := base64.StdEncoding.EncodeToString(otherDER)
	for i := 0; i+24 <= len(body); i++ {
		w := body[i : i+24]
		if !strings.Contains(otherBody, w) {
			add("pem window", []byte(w))
		}
	}
	if cert != nil {
		var secret []byte
		if err := k.withPrivate(func(priv *ecdsa.PrivateKey) (err error) {
			secret, err = openpgp.SecretKey(cert, priv)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		// the first packet: the header, the public part, S2K usage, the scalar, the checksum
		n := 2 + 111 + 1 + 2 + 48 + 2
		if len(secret) < n {
			t.Fatal("the secret key is shorter than its first packet")
		}
		first := secret[:n]
		add("secret packet", first)
		add("secret packet base64", []byte(base64.StdEncoding.EncodeToString(first)))
		add("secret packet hex", []byte(hex.EncodeToString(first)))
		// the secret part of the packet alone, with the public key packet left out
		add("secret material", secret[2+111:n])
	}
	return out
}

// A recording writer sees every call that a Store makes to the writer of its key folder and, when
// it has an inner writer, passes the call on.
type recordedWrite struct {
	name string
	data []byte
	perm fs.FileMode
}

type recWriter struct {
	mu     sync.Mutex
	inner  fileWriter
	writes []recordedWrite
	closes int
}

func (r *recWriter) WriteFile(path string, data []byte, perm fs.FileMode) error {
	r.mu.Lock()
	r.writes = append(r.writes, recordedWrite{path, bytes.Clone(data), perm})
	r.mu.Unlock()
	if r.inner == nil {
		return nil
	}
	return r.inner.WriteFile(path, data, perm)
}

func (r *recWriter) Close() error {
	r.mu.Lock()
	r.closes++
	r.mu.Unlock()
	if r.inner == nil {
		return nil
	}
	return r.inner.Close()
}

func (r *recWriter) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.writes)
}

// record puts a recording writer in front of the writer of the Store and returns it.
func record(s *Store) *recWriter {
	r := &recWriter{inner: s.w}
	s.w = r
	return r
}

// recFormat is a format that records what the Store hands to it and passes the call on.
type recFormat struct {
	inner   format
	wraps   int
	unwraps int
	lastLen int
}

func (f *recFormat) wrap(kind FileKind, payload []byte) ([]byte, error) {
	f.wraps++
	return f.inner.wrap(kind, payload)
}

func (f *recFormat) unwrap(kind FileKind, file []byte) ([]byte, error) {
	f.unwraps++
	f.lastLen = len(file)
	return f.inner.unwrap(kind, file)
}

// recordFormat puts a recording format in the Store.
func recordFormat(s *Store) *recFormat {
	f := &recFormat{inner: s.format}
	s.format = f
	return f
}

// An injected fault: the file system of a writer that fails at one step. The folder is the real
// one, so the file that a stopped write leaves is really there.
var errInjected = errors.New("an injected fault")

type faultFS struct {
	fsx.FS
	at fsx.Step
}

func (f faultFS) CreateExcl(name string, perm fs.FileMode) (fsx.File, error) {
	if f.at == fsx.StepCreate {
		return nil, errInjected
	}
	file, err := f.FS.CreateExcl(name, perm)
	if err != nil {
		return nil, err
	}
	return faultFile{File: file, at: f.at}, nil
}

func (f faultFS) RenameNoReplace(oldName, newName string) error {
	if f.at == fsx.StepRename {
		return errInjected
	}
	return f.FS.RenameNoReplace(oldName, newName)
}

func (f faultFS) Sync() error {
	if f.at == fsx.StepSyncDir {
		return errInjected
	}
	return f.FS.Sync()
}

type faultFile struct {
	fsx.File
	at fsx.Step
}

func (f faultFile) Write(p []byte) (int, error) {
	if f.at == fsx.StepWrite {
		n, _ := f.File.Write(p[:len(p)/2])
		return n, errInjected
	}
	return f.File.Write(p)
}

func (f faultFile) Sync() error {
	if f.at == fsx.StepSyncFile {
		return errInjected
	}
	return f.File.Sync()
}

// failAt makes the writer of the Store fail at one step, on the real folder of the Store.
func failAt(t testing.TB, s *Store, keys string, step fsx.Step) {
	t.Helper()
	real, err := fsx.OpenFS(keys)
	if err != nil {
		t.Fatal(err)
	}
	w := &fsx.Writer{FS: faultFS{FS: real, at: step}}
	t.Cleanup(func() { _ = w.Close() })
	s.w = w
}

// staticFS is a folder that holds the files it is given and writes nothing: the file system of
// the fuzz targets, which must not touch a disk.
type staticFS struct {
	files map[string][]byte
}

var errStatic = errors.New("static file system")

func (s staticFS) OpenDir(string) (fsx.FS, error)                   { return nil, errStatic }
func (s staticFS) Mkdir(string, fs.FileMode) error                  { return errStatic }
func (s staticFS) CreateExcl(string, fs.FileMode) (fsx.File, error) { return nil, errStatic }
func (s staticFS) RenameNoReplace(string, string) error             { return errStatic }
func (s staticFS) Sync() error                                      { return nil }
func (s staticFS) Close() error                                     { return nil }

func (s staticFS) ReadFile(name string) ([]byte, error) {
	b, ok := s.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
	}
	return bytes.Clone(b), nil
}

func (s staticFS) ReadDir() ([]fs.DirEntry, error) {
	var out []fs.DirEntry
	for name, b := range s.files {
		out = append(out, fs.FileInfoToDirEntry(staticInfo{name: name, size: int64(len(b))}))
	}
	return out, nil
}

type staticInfo struct {
	name string
	size int64
}

func (i staticInfo) Name() string       { return i.name }
func (i staticInfo) Size() int64        { return i.size }
func (i staticInfo) Mode() fs.FileMode  { return 0o600 }
func (i staticInfo) ModTime() time.Time { return time.Time{} }
func (i staticInfo) IsDir() bool        { return false }
func (i staticInfo) Sys() any           { return nil }

// refuseWriter fails the test when anything is written.
type refuseWriter struct{ t testing.TB }

func (r refuseWriter) WriteFile(path string, _ []byte, _ fs.FileMode) error {
	r.t.Errorf("a read wrote the file %q", path)
	return errors.New("not allowed")
}
func (r refuseWriter) Close() error { return nil }

// staticStore is a Store in ModeTest over files that are held in memory.
func staticStore(t testing.TB, files map[string][]byte) *Store {
	t.Helper()
	return &Store{mode: ModeTest, fsys: staticFS{files: files}, w: refuseWriter{t}, format: plainFormat{}}
}

// writeKeyFile puts bytes in the key folder under a name, as a hostile or damaged folder would.
func writeKeyFile(t testing.TB, keys, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(keys, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readKeyFile(t testing.TB, keys, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(keys, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dirNames lists the names in a folder.
func dirNames(t testing.TB, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// pemOf returns the PKCS#8 PEM block of a key, as the Store writes it.
func pemOf(t testing.TB, k *Key) []byte {
	t.Helper()
	var out []byte
	if err := k.withPrivate(func(priv *ecdsa.PrivateKey) (err error) {
		out, err = encodeX509(priv)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// x509File is the exact file of a test root's X.509 key.
func x509File(t testing.TB, k *Key) []byte {
	t.Helper()
	return append([]byte(testMarker+"\n"), pemOf(t, k)...)
}

// derOf returns the PKCS#8 DER of a private key.
func derOf(t testing.TB, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// pemFile writes a PEM block of a type with the given DER, in the form of the page.
func pemFile(blockType string, der []byte) []byte {
	return append([]byte(testMarker+"\n"), pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})...)
}

// samePublic reports whether two keys have the same public key.
func samePublic(a, b *Key) bool {
	pa, pb := a.publicCopy(), b.publicCopy()
	return pa != nil && pb != nil && pa.Equal(pb)
}

// bg is a context for the calls that take one.
// armourLine is a begin or end line of an armour or PEM block ("BEGIN", "PRIVATE KEY"). It is built
// from parts so that no file of the repository holds a private key marker as one string.
func armourLine(word, label string) string { return "-----" + word + " " + label + "-----" }

func bg() context.Context { return context.Background() }

// keyP384 makes a plain P-384 private key that the package did not make.
func keyP384(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
