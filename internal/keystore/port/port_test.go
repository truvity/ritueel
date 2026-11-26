package port_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	"github.com/truvity/atoom/common/refusal"
	keyv1alpha1 "github.com/truvity/atoom/key/gen/atoom/key/v1alpha1"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
	"github.com/truvity/atoom/key/keyid"
	"github.com/truvity/atoom/key/signer"

	"ritueel.id/ritueel/internal/keystore"
	"ritueel.id/ritueel/internal/keystore/atoomsoftware"
	"ritueel.id/ritueel/internal/keystore/port"
)

// The key of a purpose through the key port: the table of the stores that ritueel knows, and the four steps
// of a birth. The steps are tried one at a time against a scripted store, a struct that answers the
// four calls the package makes and fails the test on any other; the whole path is tried against the
// software driver of atom, linked in the process.

const purposeName = "x509-root-a"

// scripted is a key-port client that answers Capabilities, PublicKey, Ensure and Sign from a script. Any other
// call of the port is a call that the package under test must not make: the nil client inside panics.
type scripted struct {
	keyv1alpha1connect.KeyStoreServiceClient

	// The store that Capabilities names and the algorithm that it declares for the purpose.
	store, algorithm string
	curve            elliptic.Curve
	// exists says that the key is there before the first call; else PublicKey answers "absent" until Ensure.
	exists bool
	// What the calls answer; the zero value is a store that behaves.
	publicKeyErr    error  // every PublicKey call
	ensureErr       error  // Ensure
	notCreated      bool   // Ensure answers created = false
	ensureSPKI      []byte // Ensure gives this key instead of the key that it made
	emptySPKI       bool   // Ensure gives no key
	readBack        []byte // the first PublicKey after Ensure gives this key
	laterPublic     []byte // the second and later PublicKey after Ensure give this key
	readBackErr     error  // the first PublicKey after Ensure fails
	signErr         error
	signOtherDigest bool // the signature is a good signature of another digest
	signOtherKeyID  bool // the answer of Sign names another key

	mu       sync.Mutex
	priv     *ecdsa.PrivateKey
	spki     []byte
	ensured  bool
	afterEns int
	calls    []string
}

func newScripted(t *testing.T) *scripted {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &scripted{store: "software", algorithm: "ES384", curve: elliptic.P384(), priv: priv, spki: mustSPKI(t, &priv.PublicKey)}
}

func mustSPKI(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// otherKey is the SubjectPublicKeyInfo of a new P-384 key.
func otherKey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return mustSPKI(t, &priv.PublicKey)
}

func (s *scripted) log(call string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call)
}

func (s *scripted) count(call string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if c == call {
			n++
		}
	}
	return n
}

func (s *scripted) Capabilities(context.Context, *connect.Request[keyv1alpha1.CapabilitiesRequest]) (*connect.Response[keyv1alpha1.CapabilitiesResponse], error) {
	s.log("Capabilities")
	return connect.NewResponse(&keyv1alpha1.CapabilitiesResponse{
		Store:      s.store,
		Algorithms: []string{"ES384"},
		Purposes:   []*keyv1alpha1.PurposeInfo{{Name: purposeName, Algorithm: s.algorithm, Operations: []string{"sign"}}},
	}), nil
}

func (s *scripted) PublicKey(_ context.Context, req *connect.Request[keyv1alpha1.PublicKeyRequest]) (*connect.Response[keyv1alpha1.PublicKeyResponse], error) {
	s.log("PublicKey")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.publicKeyErr != nil {
		return nil, s.publicKeyErr
	}
	if req.Msg.GetPurpose() != purposeName {
		return nil, refusal.New(connect.CodeInvalidArgument, "purpose", "purpose")
	}
	if !s.exists && !s.ensured {
		return nil, refusal.New(connect.CodeNotFound, "absent", "purpose")
	}
	spki := s.spki
	if s.ensured {
		s.afterEns++
		switch {
		case s.afterEns == 1 && s.readBackErr != nil:
			return nil, s.readBackErr
		case s.afterEns == 1 && s.readBack != nil:
			spki = s.readBack
		case s.afterEns >= 2 && s.laterPublic != nil:
			spki = s.laterPublic
		}
	}
	return connect.NewResponse(&keyv1alpha1.PublicKeyResponse{SpkiDer: spki, KeyId: keyid.Software(spki)}), nil
}

func (s *scripted) Ensure(_ context.Context, _ *connect.Request[keyv1alpha1.EnsureRequest]) (*connect.Response[keyv1alpha1.EnsureResponse], error) {
	s.log("Ensure")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ensureErr != nil {
		return nil, s.ensureErr
	}
	s.ensured = true
	spki := s.spki
	if s.ensureSPKI != nil {
		spki = s.ensureSPKI
	}
	if s.emptySPKI {
		spki = nil
	}
	return connect.NewResponse(&keyv1alpha1.EnsureResponse{SpkiDer: spki, Created: !s.notCreated}), nil
}

func (s *scripted) Sign(_ context.Context, req *connect.Request[keyv1alpha1.SignRequest]) (*connect.Response[keyv1alpha1.SignResponse], error) {
	s.log("Sign")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signErr != nil {
		return nil, s.signErr
	}
	digest := req.Msg.GetDigest()
	if s.signOtherDigest {
		other := sha512.Sum384([]byte("not what was asked"))
		digest = other[:]
	}
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, digest)
	if err != nil {
		return nil, err
	}
	id := keyid.Software(s.spki)
	if s.signOtherKeyID {
		id = keyid.Software([]byte("another key"))
	}
	return connect.NewResponse(&keyv1alpha1.SignResponse{SignatureDer: sig, KeyId: id}), nil
}

// A scripted store that behaves gives the key, and the four steps happened in order and once each.
func TestBirthThroughAStoreThatBehavesGivesTheKeyAfterTheFourStepsInOrder(t *testing.T) {
	s := newScripted(t)
	k, err := port.Birth(context.Background(), s, purposeName)
	if err != nil {
		t.Fatalf("Birth: %v", err)
	}
	defer func() { _ = k.Close() }()
	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&s.priv.PublicKey) || pub.Curve != elliptic.P384() {
		t.Fatalf("the key is %T %v, want the key that the store made", k.Public(), k.Public())
	}
	// Step 1 asks whether the key is there, step 2 makes it, step 3 reads it back, and the signer of atom
	// asks what the store serves and reads the key a last time, then the self-test signs once.
	want := []string{"PublicKey", "Ensure", "PublicKey", "Capabilities", "Capabilities", "PublicKey", "Sign"}
	s.mu.Lock()
	got := slices.Clone(s.calls)
	s.mu.Unlock()
	if !slices.Equal(got, want) {
		t.Errorf("the calls were %v, want %v", got, want)
	}
}

// Each step fails on its own. The key that a store made stays in it: no call deletes anything (the
// scripted store has no such call, and a call it does not answer would panic).
func TestEachStepOfABirthFailsOnItsOwnAndGivesNoKey(t *testing.T) {
	boom := connect.NewError(connect.CodeUnavailable, errors.New("test: the store is gone"))
	cases := []struct {
		name    string
		edit    func(t *testing.T, s *scripted)
		is      []error // errors.Is must hold for each
		isNot   []error
		ensured int // calls of Ensure
		signed  int // calls of Sign
		textHas string
	}{
		{name: "step 1: the key exists already", edit: func(_ *testing.T, s *scripted) { s.exists = true },
			is: []error{port.ErrKeyExists}, ensured: 0},
		{name: "step 1: the store cannot say whether the key exists", edit: func(_ *testing.T, s *scripted) { s.publicKeyErr = boom },
			isNot: []error{port.ErrKeyExists, port.ErrBirth}, ensured: 0, textHas: "PublicKey"},
		{name: "step 1: a refusal that is not 'absent' is not taken for absent", edit: func(_ *testing.T, s *scripted) {
			s.publicKeyErr = refusal.New(connect.CodeNotFound, "purpose", "purpose")
		}, isNot: []error{port.ErrKeyExists, port.ErrBirth}, ensured: 0, textHas: "PublicKey"},
		{name: "step 1: 'absent' with another code is not taken for absent", edit: func(_ *testing.T, s *scripted) {
			s.publicKeyErr = refusal.New(connect.CodeFailedPrecondition, "absent", "purpose")
		}, isNot: []error{port.ErrKeyExists, port.ErrBirth}, ensured: 0, textHas: "PublicKey"},
		{name: "step 2: Ensure fails", edit: func(_ *testing.T, s *scripted) { s.ensureErr = boom },
			isNot: []error{port.ErrKeyExists, port.ErrBirth}, ensured: 1, textHas: "Ensure"},
		{name: "step 2: Ensure says that it did not make the key", edit: func(_ *testing.T, s *scripted) { s.notCreated = true },
			is: []error{port.ErrKeyExists}, ensured: 1},
		{name: "step 3: Ensure gives no public key", edit: func(_ *testing.T, s *scripted) { s.emptySPKI = true },
			is: []error{port.ErrBirth}, ensured: 1},
		{name: "step 3: the public key that reads back is another key", edit: func(t *testing.T, s *scripted) { s.readBack = otherKey(t) },
			is: []error{port.ErrBirth}, ensured: 1, textHas: "does not read back"},
		{name: "step 3: the public key cannot be read back", edit: func(_ *testing.T, s *scripted) { s.readBackErr = boom },
			isNot: []error{port.ErrBirth}, ensured: 1, textHas: "PublicKey"},
		{name: "step 3: the key of the signer is another key than the one that was read back", edit: func(t *testing.T, s *scripted) { s.laterPublic = otherKey(t) },
			is: []error{port.ErrBirth}, ensured: 1, textHas: "key of the signer"},
		{name: "step 4: the store cannot sign", edit: func(_ *testing.T, s *scripted) { s.signErr = boom },
			is: []error{port.ErrBirth}, ensured: 1, signed: 1, textHas: "could not sign"},
		{name: "step 4: the signature is of another digest and does not verify", edit: func(_ *testing.T, s *scripted) { s.signOtherDigest = true },
			is: []error{port.ErrBirth, signer.ErrVerify}, ensured: 1, signed: 1},
		{name: "step 4: the answer to Sign names another key", edit: func(_ *testing.T, s *scripted) { s.signOtherKeyID = true },
			is: []error{port.ErrBirth, signer.ErrKeyChanged}, ensured: 1, signed: 1},
		{name: "the purpose is not an ES384 key", edit: func(t *testing.T, s *scripted) {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			s.algorithm, s.priv, s.spki = "ES256", priv, mustSPKI(t, &priv.PublicKey)
		}, is: []error{port.ErrAlgorithm}, ensured: 1},
		{name: "the store is not one that ritueel knows", edit: func(_ *testing.T, s *scripted) { s.store = "aws-kms" },
			is: []error{port.ErrUnknownStore}, ensured: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newScripted(t)
			c.edit(t, s)
			k, err := port.Birth(context.Background(), s, purposeName)
			if k != nil || err == nil {
				if k != nil {
					_ = k.Close()
				}
				t.Fatalf("Birth = %v, %v; want no key and an error", k, err)
			}
			for _, want := range c.is {
				if !errors.Is(err, want) {
					t.Errorf("the error %q is not %q", err, want)
				}
			}
			for _, not := range c.isNot {
				if errors.Is(err, not) {
					t.Errorf("the error %q is %q", err, not)
				}
			}
			if c.textHas != "" && !strings.Contains(err.Error(), c.textHas) {
				t.Errorf("the error %q does not say %q", err, c.textHas)
			}
			if got := s.count("Ensure"); got != c.ensured {
				t.Errorf("Ensure was called %d times, want %d", got, c.ensured)
			}
			if got := s.count("Sign"); got != c.signed {
				t.Errorf("Sign was called %d times, want %d", got, c.signed)
			}
		})
	}
}

// A store that the table does not hold is refused before a key is made. The table is asked after the
// key was made today (Birth asks it when it opens the key, which is its third step), so this test says
// what the package should do and does not pass yet.
func TestBirthInAStoreThatTheTableDoesNotHoldMakesNoKey(t *testing.T) {
	s := newScripted(t)
	s.store = "aws-kms"
	if k, err := port.Birth(context.Background(), s, purposeName); k != nil || !errors.Is(err, port.ErrUnknownStore) {
		t.Fatalf("Birth = %v, %v; want ErrUnknownStore", k, err)
	}
	if n := s.count("Ensure"); n != 0 {
		t.Errorf("a key was made in a store that the table does not hold: Ensure was called %d times", n)
	}
}

func TestDescribeAnswersTheEntryOfTheTableAndRefusesAStoreThatIsNotInIt(t *testing.T) {
	s := newScripted(t)
	info, err := port.Describe(context.Background(), s)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if info.Store != "software" || info.Kind != keystore.KindSoftware || !info.Copyable || !slices.Equal(info.Warnings, []string{keystore.WarningSoftwareCopyable}) {
		t.Errorf("Describe = %+v", info)
	}
	for _, name := range []string{"aws-kms", "yubikey-piv", "", "Software", "software "} {
		s.store = name
		if _, err := port.Describe(context.Background(), s); !errors.Is(err, port.ErrUnknownStore) {
			t.Errorf("Describe of the store %q = %v, want ErrUnknownStore", name, err)
		}
		if _, ok := port.Lookup(name); ok {
			t.Errorf("Lookup(%q) knows the store", name)
		}
	}
	// A store that cannot be asked is a failure and not an unknown store.
	failing := newScripted(t)
	failing.store = "software"
	if _, err := port.Describe(context.Background(), failingCapabilities{failing}); err == nil || errors.Is(err, port.ErrUnknownStore) {
		t.Errorf("Describe of a store that cannot be asked = %v", err)
	}
	if _, err := port.Describe(nil, s); err == nil { //nolint:staticcheck // the nil context is the case
		t.Error("Describe takes no context")
	}
	if _, err := port.Describe(context.Background(), nil); err == nil {
		t.Error("Describe takes no client")
	}
}

type failingCapabilities struct{ *scripted }

func (failingCapabilities) Capabilities(context.Context, *connect.Request[keyv1alpha1.CapabilitiesRequest]) (*connect.Response[keyv1alpha1.CapabilitiesResponse], error) {
	return nil, connect.NewError(connect.CodeUnavailable, errors.New("test: down"))
}

func TestLookupGivesACopyOfTheWarnings(t *testing.T) {
	a, ok := port.Lookup("software")
	if !ok || len(a.Warnings) == 0 {
		t.Fatalf("Lookup(software) = %+v, %v", a, ok)
	}
	a.Warnings[0] = "changed"
	if b, _ := port.Lookup("software"); b.Warnings[0] != keystore.WarningSoftwareCopyable {
		t.Errorf("a change of the answer changed the table: %v", b.Warnings)
	}
}

func TestBirthTakesAContextAndAClient(t *testing.T) {
	if k, err := port.Birth(nil, newScripted(t), purposeName); k != nil || err == nil { //nolint:staticcheck // the nil context is the case
		t.Errorf("Birth without a context = %v, %v", k, err)
	}
	if k, err := port.Birth(context.Background(), nil, purposeName); k != nil || err == nil {
		t.Errorf("Birth without a client = %v, %v", k, err)
	}
}

// The software driver of atom, linked in the process: the key is made, kept in its file, read back, and
// the kind, copyable and warnings are those of the table.
func TestBirthThroughTheSoftwareDriverMakesTheKeyOnceAndSignsAndRefusesAnExistingKey(t *testing.T) {
	dir := t.TempDir()
	link, err := atoomsoftware.Open(dir, []string{purposeName, "x509-root-b"})
	if err != nil {
		t.Fatalf("atoomsoftware.Open: %v", err)
	}
	t.Cleanup(func() { _ = link.Close() })
	ctx := context.Background()

	k, err := port.Birth(ctx, link.Client(), purposeName)
	if err != nil {
		t.Fatalf("Birth: %v", err)
	}
	if k.Kind() != keystore.KindSoftware || k.Kind() != "software" || !k.Copyable() || !slices.Equal(k.Warnings(), []string{keystore.WarningSoftwareCopyable}) {
		t.Errorf("kind %q, copyable %v, warnings %v", k.Kind(), k.Copyable(), k.Warnings())
	}
	// A change of the warnings that the key gave does not change the key's answer.
	w := k.Warnings()
	w[0] = "changed"
	if k.Warnings()[0] != keystore.WarningSoftwareCopyable {
		t.Error("a change of the answer changed the warnings of the key")
	}
	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		t.Fatalf("the key is %T", k.Public())
	}

	// It signs a SHA-384 digest, and the signature verifies with the public key.
	digest := sha512.Sum384([]byte("a message"))
	sig, err := k.Sign(rand.Reader, digest[:], crypto.SHA384)
	if err != nil || !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatalf("Sign: %v; verifies %v", err, err == nil && ecdsa.VerifyASN1(pub, digest[:], sig))
	}
	// It signs nothing else: the wrong hash and the wrong length are refused.
	if _, err := k.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Error("a signature with the options of SHA-256 for an ES384 key")
	}
	short := sha256.Sum256([]byte("a message"))
	if _, err := k.Sign(rand.Reader, short[:], crypto.SHA384); err == nil {
		t.Error("a signature over a digest of the wrong length")
	}

	// The key is in the file of the driver, and the file holds the private key that goes with the public one.
	file := filepath.Join(dir, "test-only-keys", purposeName+".p8")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("no key file: %v", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(before)
	if err != nil {
		t.Fatalf("the key file is not a PKCS#8 key: %v", err)
	}
	if priv, ok := parsed.(*ecdsa.PrivateKey); !ok || !priv.PublicKey.Equal(pub) {
		t.Error("the key file holds another key than the key that Birth gave")
	}

	// A second Birth of the purpose is refused as an existing key, never adopted, and the file stays as it was.
	k2, err := port.Birth(ctx, link.Client(), purposeName)
	if k2 != nil || !errors.Is(err, port.ErrKeyExists) {
		t.Fatalf("a second Birth = %v, %v; want ErrKeyExists", k2, err)
	}
	after, err := os.ReadFile(file)
	if err != nil || string(before) != string(after) {
		t.Errorf("the key file changed after a refused Birth: %v", err)
	}
	// The other purpose is another key.
	kb, err := port.Birth(ctx, link.Client(), "x509-root-b")
	if err != nil {
		t.Fatalf("Birth of the second purpose: %v", err)
	}
	defer func() { _ = kb.Close() }()
	if kb.Public().(*ecdsa.PublicKey).Equal(pub) {
		t.Error("two purposes have one key")
	}

	// NewKey opens the key of an existing purpose and gives the same public key.
	again, err := port.NewKey(ctx, link.Client(), purposeName)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if !again.Public().(*ecdsa.PublicKey).Equal(pub) {
		t.Error("NewKey gives another key")
	}
	_ = again.Close()

	// After Close the key signs nothing, a second Close is nil, and the store is still there for another key.
	if err := k.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := k.Sign(rand.Reader, digest[:], crypto.SHA384); !errors.Is(err, port.ErrClosed) {
		t.Errorf("a signature after Close: %v, want ErrClosed", err)
	}
	if err := k.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
	if _, err := kb.Sign(rand.Reader, digest[:], crypto.SHA384); err != nil {
		t.Errorf("the close of one key stopped another: %v", err)
	}

	// A purpose that the driver does not declare is refused by the driver; no file is made for it.
	if k3, err := port.Birth(ctx, link.Client(), "x509-root-c"); k3 != nil || err == nil {
		t.Errorf("Birth of an undeclared purpose = %v, %v", k3, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "test-only-keys", "x509-root-c.p8")); err == nil {
		t.Error("a key file of a purpose that was not declared")
	}

	// A driver that was stopped answers nothing.
	if err := link.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := kb.Sign(rand.Reader, digest[:], crypto.SHA384); err == nil {
		t.Error("a signature through a link that was closed")
	}
}

func TestNewKeyOfAPurposeWithNoKeyIsRefused(t *testing.T) {
	link, err := atoomsoftware.Open(t.TempDir(), []string{purposeName})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = link.Close() })
	if k, err := port.NewKey(context.Background(), link.Client(), purposeName); k != nil || err == nil {
		t.Errorf("NewKey of a purpose with no key = %v, %v", k, err)
	}
}
