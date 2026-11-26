//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/keystore"
)

// The software store of a test root, as a RootStore (internal/ceremony/rootstore.go): the place where
// the keys of one root are born and kept. It makes no key before Refuse has returned nil, never
// replaces a key file, and says refusals with the reason codes of the key store.

// mkStoreCase is a bundle folder and an empty key directory beside it.
func mkStoreCase(t *testing.T) (root, bundle, keys string) {
	t.Helper()
	root = t.TempDir()
	bundle = filepath.Join(root, "ca")
	keys = filepath.Join(root, "keys")
	for _, d := range []string{bundle, keys} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root, bundle, keys
}

func mkOpenStore(t *testing.T, keys, bundle string) ceremony.RootStore {
	t.Helper()
	s, err := ceremony.NewSoftwareStore(keys, bundle)
	if err != nil {
		t.Fatalf("NewSoftwareStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestTheSoftwareStoreSaysWhatItIs(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	if s.Kind() != keystore.KindSoftware || s.Kind() != "software" {
		t.Errorf("Kind = %q, want software", s.Kind())
	}
	if !s.Copyable() {
		t.Error("a key file can be copied, and the store says it cannot")
	}
}

func TestThePlaceOfAKeyIsItsPurposeAndNeverAPath(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	for _, l := range []string{"A", "B", "M", "Z"} {
		if got, want := s.Place(l), "x509-root-"+strings.ToLower(l); got != want {
			t.Errorf("Place(%q) = %q, want %q", l, got, want)
		}
	}
	for _, l := range []string{"", "a", "AB", "1", "-", " ", "A ", "\x00", "A\n", "Ä", "../A", "A/", "\\", "AA", "z"} {
		if got := s.Place(l); got != "" {
			t.Errorf("Place(%+q) = %q, want no place", l, got)
		}
	}
}

func TestAStoreRefusesAKeyDirectoryThatBreaksTheRulesWithTheReasonKeyDir(t *testing.T) {
	root, bundle, _ := mkStoreCase(t)
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(bundle, "keys")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(filepath.Join(work, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(work, "bundle"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(work, "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ keys, bundle string }{
		"the key directory does not exist":                             {filepath.Join(root, "none"), bundle},
		"the key directory is a file":                                  {file, bundle},
		"the key directory is the bundle":                              {bundle, bundle},
		"inside the bundle":                                            {inside, bundle},
		"inside the work tree of the repository that holds the bundle": {filepath.Join(work, "keys"), filepath.Join(work, "bundle")},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := ceremony.NewSoftwareStore(tc.keys, tc.bundle)
			if s != nil {
				_ = s.Close()
				t.Fatalf("a store is made")
			}
			if got := mkBackendReason(err); got != "key-dir" {
				t.Fatalf("NewSoftwareStore: %v (reason %q), want a *BackendError with key-dir", err, got)
			}
			// The same verdict as the check that needs no store.
			cerr := ceremony.CheckKeyDir(tc.keys, tc.bundle)
			if mkBackendReason(cerr) != "key-dir" {
				t.Fatalf("CheckKeyDir gives %v for the same folders", cerr)
			}
		})
	}
}

func TestAStoreNeedsBothFolders(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	for _, tc := range []struct{ keys, bundle string }{{"", bundle}, {keys, ""}, {"", ""}} {
		s, err := ceremony.NewSoftwareStore(tc.keys, tc.bundle)
		if s != nil || err == nil {
			t.Errorf("NewSoftwareStore(%q, %q) = %v, %v", tc.keys, tc.bundle, s, err)
		}
	}
}

func TestNoKeyIsMadeBeforeRefuseHasReturnedNil(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	if k, err := s.Birth(context.Background(), "A"); err == nil || k != nil {
		t.Fatalf("Birth before Refuse gives %v, %v", k, err)
	}
	// A text that the store would take after Refuse: three parts of the alphabet of a compact JWS.
	text := []byte("eyJhbGciOiJFUzM4NCJ9.eyJ2IjoxfQ.c2ln")
	if err := s.SaveRemoval("A", text); err == nil {
		t.Fatal("SaveRemoval before Refuse is accepted")
	}
	ents, _ := os.ReadDir(keys)
	if len(ents) != 0 {
		t.Fatalf("a file was written before Refuse: %v", ents)
	}
}

func TestABirthWritesTheKeyFileAndTheStoreReadsItBackAsTheSameKey(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	ctx := context.Background()
	if err := s.Refuse(ctx); err != nil {
		t.Fatalf("Refuse: %v", err)
	}
	k, err := s.Birth(ctx, "A")
	if err != nil {
		t.Fatalf("Birth: %v", err)
	}
	defer func() { _ = k.Close() }()
	if k.Kind() != keystore.KindSoftware || !k.Copyable() {
		t.Errorf("the key says %q, copyable %v", k.Kind(), k.Copyable())
	}
	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		t.Fatalf("the key is %T", k.Public())
	}
	file := filepath.Join(keys, mkKeyFile("A"))
	st, err := os.Stat(file)
	if err != nil {
		t.Fatalf("no key file: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("the key file has the mode %o, want 600", st.Mode().Perm())
	}
	folder, err := os.Stat(filepath.Join(keys, "test-only-keys"))
	if err != nil || !folder.IsDir() || folder.Mode().Perm() != 0o700 {
		t.Errorf("the folder test-only-keys: %v, %v; want a folder of the mode 700", folder, err)
	}
	der, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	// An independent read of the key file gives the same public key.
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("the key file is not a PKCS#8 private key: %v", err)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !pub.Equal(&priv.PublicKey) {
		t.Error("the key file holds another key than the key that Birth returned")
	}
	// No file but the key file: the removal authorisation is saved by its own call.
	ents, _ := os.ReadDir(keys)
	if len(ents) != 1 {
		t.Errorf("the key directory holds %d files after one birth", len(ents))
	}
}

func TestABirthOfALabelThatIsNotOneLetterMakesNoKey(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	ctx := context.Background()
	if err := s.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"", "a", "AB", "1", "..", "A/B", "\x00"} {
		if k, err := s.Birth(ctx, l); err == nil || k != nil {
			t.Errorf("Birth(%+q) = %v, %v", l, k, err)
		}
	}
	if ents, _ := os.ReadDir(keys); len(ents) != 0 {
		t.Errorf("a file was written: %v", ents)
	}
}

func TestAKeyFileIsNeverReplaced(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	ctx := context.Background()
	if err := s.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	k, err := s.Birth(ctx, "A")
	if err != nil {
		t.Fatal(err)
	}
	_ = k.Close()
	before, err := os.ReadFile(filepath.Join(keys, mkKeyFile("A")))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := s.Birth(ctx, "A")
	if k2 != nil || mkBackendReason(err) != "key-exists" {
		t.Fatalf("a second Birth of A: %v, %v; want key-exists", k2, err)
	}
	after, _ := os.ReadFile(filepath.Join(keys, mkKeyFile("A")))
	if !bytes.Equal(before, after) {
		t.Fatal("the key file was changed")
	}
}

func TestRefuseSeesKeyFilesThatStandInTheDirectory(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	if err := os.WriteFile(filepath.Join(keys, "C.x509.key.pem"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := mkOpenStore(t, keys, bundle)
	err := s.Refuse(context.Background())
	if got := mkBackendReason(err); got != "key-exists" {
		t.Fatalf("Refuse: %v (reason %q), want key-exists", err, got)
	}
	// And no key is made after a refusal.
	if k, err := s.Birth(context.Background(), "A"); k != nil || err == nil {
		t.Fatalf("Birth after a refusal gives %v, %v", k, err)
	}
	if _, err := os.Stat(filepath.Join(keys, mkKeyFile("A"))); err == nil {
		t.Fatal("a key file was made after Refuse refused")
	}
}

func TestAKeyFileThatAppearsAfterAnAcceptedRefuseMakesTheNextRefuseRefuseAndNoKeyIsMade(t *testing.T) {
	// "A store makes no key before Refuse has returned nil": the last answer of Refuse is the one
	// that counts. A key file that came into the folder after an earlier acceptance is refused by
	// the next Refuse, and the store then makes no key.
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	ctx := context.Background()
	if err := s.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "C.x509.key.pem"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Refuse(ctx); mkBackendReason(err) != "key-exists" {
		t.Fatalf("Refuse: %v", err)
	}
	if k, err := s.Birth(ctx, "A"); err == nil {
		_ = k.Close()
		t.Fatal("a key is made after the last Refuse refused")
	}
	if _, err := os.Stat(filepath.Join(keys, mkKeyFile("A"))); err == nil {
		t.Fatal("a key file is written after the last Refuse refused")
	}
}

func TestAContextThatIsNilOrDoneIsRefusedByEveryCallThatTakesOne(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	var nilCtx context.Context //nolint:staticcheck
	if err := s.Refuse(nilCtx); err == nil {
		t.Error("Refuse(nil) is accepted")
	}
	if err := s.Refuse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k, err := s.Birth(nilCtx, "A"); err == nil || k != nil {
		t.Error("Birth(nil) is accepted")
	}
	if _, err := s.ReadRemoval(nilCtx, "A"); err == nil {
		t.Error("ReadRemoval(nil) is accepted")
	}
	done, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Refuse(done); !errors.Is(err, context.Canceled) {
		t.Errorf("Refuse(done) = %v", err)
	}
	if k, err := s.Birth(done, "A"); !errors.Is(err, context.Canceled) || k != nil {
		t.Errorf("Birth(done) = %v, %v", k, err)
	}
	if ents, _ := os.ReadDir(keys); len(ents) != 0 {
		t.Errorf("a file was written: %v", ents)
	}
}

func TestTheRemovalAuthorisationIsStoredNextToTheKeyAndReadBackAsItWas(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	ctx := context.Background()
	if err := s.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	k, err := s.Birth(ctx, "A")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = k.Close() }()
	text := []byte("eyJhbGciOiJFUzM4NCJ9.eyJ2IjoxfQ.c2ln")
	if err := s.SaveRemoval("A", text); err != nil {
		t.Fatalf("SaveRemoval: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(keys, "A.removal.jws"))
	if err != nil || !bytes.Equal(got, text) {
		t.Fatalf("the file holds %q, %v", got, err)
	}
	back, err := s.ReadRemoval(ctx, "A")
	if err != nil || !bytes.Equal(back, text) {
		t.Fatalf("ReadRemoval = %q, %v", back, err)
	}
	// It is never replaced either.
	err = s.SaveRemoval("A", text)
	if mkBackendReason(err) != "key-exists" {
		t.Fatalf("a second SaveRemoval: %v, want key-exists", err)
	}
	// A label that has none.
	if _, err := s.ReadRemoval(ctx, "B"); err == nil {
		t.Error("ReadRemoval of a label with no file succeeds")
	}
	if _, err := s.ReadRemoval(ctx, "ab"); err == nil {
		t.Error("ReadRemoval of a bad label succeeds")
	}
}

func TestARemovalTextThatIsNotACompactJWSIsRefusedAndNothingIsWritten(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	if err := s.Refuse(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string][]byte{
		"empty":         nil,
		"no dots":       []byte("abc"),
		"a line feed":   []byte("a.b.c\n"),
		"a space":       []byte("a.b .c"),
		"not ASCII":     []byte("a.b.\xc3\xa9"),
		"too long":      append([]byte("a.b."), bytes.Repeat([]byte("c"), 5000)...),
		"four parts":    []byte("a.b.c.d"),
		"a path in it":  []byte("a.b./c"),
		"padding in it": []byte("a.b.c=="),
	} {
		if err := s.SaveRemoval("A", text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if ents, _ := os.ReadDir(keys); len(ents) != 0 {
		t.Errorf("a file was written: %v", ents)
	}
}

func TestAClosedStoreMakesNothingAndASecondCloseIsNil(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s, err := ceremony.NewSoftwareStore(keys, bundle)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("a second Close: %v", err)
	}
	if err := s.Refuse(ctx); err == nil {
		t.Error("Refuse on a closed store succeeds")
	}
	if k, err := s.Birth(ctx, "A"); err == nil || k != nil {
		t.Error("Birth on a closed store succeeds")
	}
	if err := s.SaveRemoval("A", []byte("a.b.c")); err == nil {
		t.Error("SaveRemoval on a closed store succeeds")
	}
	if _, err := s.ReadRemoval(ctx, "A"); err == nil {
		t.Error("ReadRemoval on a closed store succeeds")
	}
	if ents, _ := os.ReadDir(keys); len(ents) != 0 {
		t.Errorf("a file was written: %v", ents)
	}
}

func TestTwoGoroutinesBirthingOneLabelMakeOneKeyAndRefuseTheOther(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	ctx := context.Background()
	if err := s.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 4)
	oks := make([]bool, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			k, err := s.Birth(ctx, "A")
			errs[i], oks[i] = err, k != nil
			if k != nil {
				_ = k.Close()
			}
		}()
	}
	close(start)
	wg.Wait()
	made := 0
	for i := range errs {
		if oks[i] {
			made++
			if errs[i] != nil {
				t.Errorf("a key and an error: %v", errs[i])
			}
		} else if mkBackendReason(errs[i]) != "key-exists" {
			t.Errorf("a refused Birth gives %v, want key-exists", errs[i])
		}
	}
	if made != 1 {
		t.Fatalf("%d keys were made for one label, want 1", made)
	}
	if ents, _ := os.ReadDir(keys); len(ents) != 1 {
		t.Errorf("the directory holds %d files", len(ents))
	}
}

func TestTwoGoroutinesBirthingTwoLabelsMakeTwoKeys(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	ctx := context.Background()
	if err := s.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, l := range []string{"A", "B"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			k, err := s.Birth(ctx, l)
			if err != nil {
				t.Errorf("Birth(%s): %v", l, err)
				return
			}
			_ = k.Close()
		}()
	}
	close(start)
	wg.Wait()
	inner, _ := os.ReadDir(filepath.Join(keys, "test-only-keys"))
	var names []string
	for _, e := range inner {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"x509-root-a.p8", "x509-root-b.p8"}) {
		t.Errorf("the folder test-only-keys holds %v", names)
	}
}

// mkWithin runs fn and fails the test when it does not return in time: a pipe where a file belongs
// must not stop the store.
func mkWithin(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatalf("%s did not return", what)
	}
}

func TestAPipeOrALinkInThePlaceOfAFileIsRefusedAndDoesNotStopTheStore(t *testing.T) {
	for _, kind := range []string{"fifo", "link", "folder"} {
		for _, name := range []string{"test-only-keys", "A.removal.jws"} {
			t.Run(kind+" "+name, func(t *testing.T) {
				root, bundle, keys := mkStoreCase(t)
				path := filepath.Join(keys, name)
				switch kind {
				case "fifo":
					if err := syscall.Mkfifo(path, 0o600); err != nil {
						t.Fatal(err)
					}
				case "link":
					if err := os.Symlink(filepath.Join(root, "elsewhere"), path); err != nil {
						t.Fatal(err)
					}
				case "folder":
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				s := mkOpenStore(t, keys, bundle)
				ctx := context.Background()
				mkWithin(t, "Refuse, Birth, SaveRemoval and ReadRemoval", func() {
					// A folder or a link or a pipe with the name of a key file is not a key file for the check, and the
					// store refuses to write over it or to read it; whichever is the answer, it is an answer.
					if err := s.Refuse(ctx); err != nil {
						return
					}
					if k, err := s.Birth(ctx, "A"); err == nil {
						if name == "test-only-keys" {
							t.Errorf("a key is born beside a %s with the name of the key folder", kind)
						}
						_ = k.Close()
					}
					_ = s.SaveRemoval("A", []byte("a.b.c"))
					if b, err := s.ReadRemoval(ctx, "A"); err == nil && name == "A.removal.jws" {
						t.Errorf("a removal authorisation is read from a %s: %q", kind, b)
					}
				})
			})
		}
	}
}
