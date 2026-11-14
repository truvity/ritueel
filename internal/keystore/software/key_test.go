package software

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/keystore"
)

func digest48() []byte {
	d := sha512.Sum384([]byte("example message of the tests"))
	return d[:]
}

func TestGenerateTwiceGivesTwoDifferentKeysOnP384WithAPointOnTheCurve(t *testing.T) {
	a, b := mustGenerate(t), mustGenerate(t)
	pa, ok := a.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public is a %T", a.Public())
	}
	pb := b.Public().(*ecdsa.PublicKey)
	if pa.Equal(pb) {
		t.Error("two keys have the same public key")
	}
	if bytes.Equal(scalarBytes(t, a), scalarBytes(t, b)) {
		t.Error("two keys have the same scalar")
	}
	for i, p := range []*ecdsa.PublicKey{pa, pb} {
		if p.Curve != elliptic.P384() {
			t.Errorf("key %d is on %v, want P-384", i, p.Curve.Params().Name)
		}
		raw, err := p.Bytes()
		if err != nil || len(raw) != pointLen {
			t.Errorf("key %d: point of %d bytes (%v), want %d", i, len(raw), err, pointLen)
		}
		if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), raw); err != nil {
			t.Errorf("key %d: the point is not on the curve: %v", i, err)
		}
	}
	if got := len(scalarBytes(t, a)); got != scalarLen {
		t.Errorf("scalar of %d bytes, want %d", got, scalarLen)
	}
}

func TestGenerateWritesNothingAndSavesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("TMPDIR", dir)
	k := mustGenerate(t)
	if k.Saved() {
		t.Error("a new key is Saved")
	}
	if names := dirNames(t, dir); len(names) != 0 {
		t.Errorf("Generate wrote %v", names)
	}
}

func TestSignOfADigestOf48BytesVerifiesWithThePublicKeyAndIsDER(t *testing.T) {
	k := mustGenerate(t)
	pub := k.Public().(*ecdsa.PublicKey)
	for i := 0; i < 20; i++ {
		d := sha512.Sum384(fmt.Appendf(nil, "message %d", i))
		sig, err := k.Sign(rand.Reader, d[:], crypto.SHA384)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !ecdsa.VerifyASN1(pub, d[:], sig) {
			t.Fatalf("signature %d does not verify", i)
		}
		if sig[0] != 0x30 {
			t.Errorf("the signature does not start like a DER sequence: % x", sig[:2])
		}
	}
}

type fixedOpts crypto.Hash

func (o fixedOpts) HashFunc() crypto.Hash { return crypto.Hash(o) }

// panicOpts is the typed nil whose method panics: a nil pointer inside the interface.
type panicOpts struct{ h crypto.Hash }

func (o *panicOpts) HashFunc() crypto.Hash { return o.h }

func TestSignAcceptsTheRandomSourceAsNilAndAsAnyReaderAndTheHashAsAnyOptsThatSaySHA384(t *testing.T) {
	k := mustGenerate(t)
	pub := k.Public().(*ecdsa.PublicKey)
	d := digest48()
	for name, opts := range map[string]crypto.SignerOpts{
		"crypto.SHA384":     crypto.SHA384,
		"an opts value":     fixedOpts(crypto.SHA384),
		"a non-nil pointer": &panicOpts{h: crypto.SHA384},
	} {
		for _, rnd := range []interface{ Read([]byte) (int, error) }{nil, rand.Reader, bytes.NewReader(nil)} {
			sig, err := k.Sign(rnd, d, opts)
			if err != nil || !ecdsa.VerifyASN1(pub, d, sig) {
				t.Errorf("%s with reader %T: %v", name, rnd, err)
			}
		}
	}
}

func TestSignRefusesAnythingButASHA384DigestOf48BytesAndNeverPanics(t *testing.T) {
	k := mustGenerate(t)
	closed := mustGenerate(t)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	good := digest48()
	short := sha256.Sum256(good)
	long := sha512.Sum512(good)
	cases := []struct {
		name   string
		key    *Key
		digest []byte
		opts   crypto.SignerOpts
	}{
		{"a digest of 32 bytes", k, short[:], crypto.SHA384},
		{"a digest of 64 bytes", k, long[:], crypto.SHA384},
		{"a digest of 47 bytes", k, good[:47], crypto.SHA384},
		{"a digest of 49 bytes", k, append(bytes.Clone(good), 0), crypto.SHA384},
		{"an empty digest", k, []byte{}, crypto.SHA384},
		{"a nil digest", k, nil, crypto.SHA384},
		{"SHA-256 options", k, good, crypto.SHA256},
		{"SHA-512 options", k, good, crypto.SHA512},
		{"SHA-384 as a 512 value", k, good, crypto.SHA3_384},
		{"hash 0 options", k, good, crypto.Hash(0)},
		{"nil options", k, good, nil},
		{"typed nil options", k, good, (*panicOpts)(nil)},
		{"options of a hash that does not exist", k, good, fixedOpts(200)},
		{"a closed key", closed, good, crypto.SHA384},
		{"a nil key", nil, good, crypto.SHA384},
		{"a zero key", &Key{}, good, crypto.SHA384},
		{"a key with an empty state", &Key{s: &keyState{}}, good, crypto.SHA384},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			sig, err := c.key.Sign(nil, c.digest, c.opts)
			if err == nil {
				t.Fatal("signed")
			}
			if sig != nil {
				t.Error("a refusal returned bytes")
			}
			if !errors.Is(err, ErrParams) {
				t.Errorf("the error does not wrap ErrParams: %v", err)
			}
		})
	}
}

// A signature that the key itself would not verify is never returned (record 0002, rule 14).
func TestASignatureThatTheKeyWouldNotVerifyIsNeverReturned(t *testing.T) {
	d := digest48()
	tampers := map[string]func(sig []byte) []byte{
		"the last byte changed": func(s []byte) []byte { s = bytes.Clone(s); s[len(s)-1] ^= 1; return s },
		"the first number changed": func(s []byte) []byte {
			s = bytes.Clone(s)
			s[5] ^= 0x80
			return s
		},
		"cut by one byte":       func(s []byte) []byte { return s[:len(s)-1] },
		"one byte added":        func(s []byte) []byte { return append(bytes.Clone(s), 0) },
		"empty":                 func([]byte) []byte { return []byte{} },
		"nil":                   func([]byte) []byte { return nil },
		"bytes that are no DER": func([]byte) []byte { return bytes.Repeat([]byte{7}, 96) },
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			k := mustGenerate(t)
			k.s.tamper = tamper
			sig, err := k.Sign(nil, d, crypto.SHA384)
			if err == nil || sig != nil {
				t.Fatalf("returned %d bytes and %v", len(sig), err)
			}
			if !errors.Is(err, errSignature) {
				t.Errorf("the error is not errSignature: %v", err)
			}
		})
	}
	t.Run("a hook that changes nothing is the control", func(t *testing.T) {
		k := mustGenerate(t)
		k.s.tamper = func(s []byte) []byte { return s }
		if sig, err := k.Sign(nil, d, crypto.SHA384); err != nil || sig == nil {
			t.Fatalf("a good signature is refused: %v", err)
		}
	})
}

// scribble changes the coordinates of a public key that a caller got, as a careless caller could.
func scribble(p *ecdsa.PublicKey) {
	//nolint:staticcheck // the coordinates are changed on purpose
	p.X.SetInt64(0)
	//nolint:staticcheck // the coordinates are changed on purpose
	p.Y.SetInt64(1)
}

// sharesNumbers reports whether two public keys hold the same big.Int objects.
func sharesNumbers(a, b *ecdsa.PublicKey) bool {
	//nolint:staticcheck // the coordinates are compared by identity on purpose
	return a.X == b.X || a.Y == b.Y
}

func TestPublicReturnsACopyOnEveryCall(t *testing.T) {
	k := mustGenerate(t)
	first := k.Public().(*ecdsa.PublicKey)
	want, err := first.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	scribble(first)
	second := k.Public().(*ecdsa.PublicKey)
	if first == second {
		t.Error("two calls return one pointer")
	}
	got, err := second.Bytes()
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("the key changed when a caller changed its copy: %v", err)
	}
	pk := k.Public().(*ecdsa.PublicKey)
	if sharesNumbers(pk, second) {
		t.Error("two copies share their numbers")
	}
	d := digest48()
	sig, err := k.Sign(nil, d, crypto.SHA384)
	if err != nil || !ecdsa.VerifyASN1(second, d, sig) {
		t.Errorf("the key signs no more after its copy was changed: %v", err)
	}
}

func TestPublicOfAClosedNilOrZeroKeyIsNil(t *testing.T) {
	closed := mustGenerate(t)
	_ = closed.Close()
	for name, k := range map[string]*Key{"closed": closed, "nil": nil, "zero": {}, "empty state": {s: &keyState{}}} {
		if p := k.Public(); p != nil {
			t.Errorf("%s: Public is %v, want an untyped nil", name, p)
		}
	}
}

func TestCloseTwiceIsNilAndLeavesNoScalarAndTheKeySignsNoMore(t *testing.T) {
	k := mustGenerate(t)
	pub := k.Public()
	if pub == nil {
		t.Fatal("no public key")
	}
	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	if err := k.Close(); err != nil {
		t.Errorf("the second Close returned %v", err)
	}
	priv := k.s.priv
	//nolint:staticcheck // the test looks at the numbers that Close is to clear
	if priv.D.Sign() != 0 || priv.X.Sign() != 0 || priv.Y.Sign() != 0 {
		t.Error("a number of the key object is not zero after Close")
	}
	if _, err := k.Sign(nil, digest48(), crypto.SHA384); !errors.Is(err, ErrParams) {
		t.Errorf("Sign after Close: %v", err)
	}
	if k.Public() != nil {
		t.Error("Public after Close is not nil")
	}
}

func TestCloseClearsEveryWordOfTheScalar(t *testing.T) {
	k := mustGenerate(t)
	//nolint:staticcheck // the test looks at the words that Close is to clear
	words := k.s.priv.D.Bits()
	if len(words) == 0 {
		t.Fatal("no words")
	}
	nonzero := false
	for _, w := range words {
		nonzero = nonzero || w != 0
	}
	if !nonzero {
		t.Fatal("the scalar is zero before Close")
	}
	_ = k.Close()
	for i, w := range words {
		if w != 0 {
			t.Errorf("word %d of the scalar is %#x after Close", i, w)
		}
	}
}

func TestCloseOfANilAndOfAZeroKeyIsNil(t *testing.T) {
	var nilKey *Key
	if err := nilKey.Close(); err != nil {
		t.Errorf("nil: %v", err)
	}
	if err := (&Key{}).Close(); err != nil {
		t.Errorf("zero: %v", err)
	}
	if err := (&Key{s: &keyState{}}).Close(); err != nil {
		t.Errorf("empty state: %v", err)
	}
}

func TestCloseLeavesSavedAsItWas(t *testing.T) {
	s, _, _ := openStore(t)
	saved := mustGenerate(t)
	if err := s.SaveX509("A", saved); err != nil {
		t.Fatal(err)
	}
	unsaved := mustGenerate(t)
	_ = saved.Close()
	_ = unsaved.Close()
	if !saved.Saved() {
		t.Error("Close made a saved key not saved")
	}
	if unsaved.Saved() {
		t.Error("Close made a key saved")
	}
}

func TestSavedOfANilAndAZeroKeyIsFalse(t *testing.T) {
	var nilKey *Key
	if nilKey.Saved() || (&Key{}).Saved() {
		t.Error("Saved is true for a key that is not there")
	}
	nilKey.markSaved()
	(&Key{}).markSaved()
}

// Sign and Close at once: each Sign answers with a signature that verifies or with ErrParams,
// whichever comes first. No order is assumed.
func TestSignAndCloseAtOnceGiveASignatureThatVerifiesOrAnErrorWhicheverComesFirst(t *testing.T) {
	k := mustGenerate(t)
	pub := k.Public().(*ecdsa.PublicKey)
	d := digest48()
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := k.Sign(nil, d, crypto.SHA384)
			switch {
			case err == nil && !ecdsa.VerifyASN1(pub, d, sig):
				errs <- "a signature that does not verify"
			case err != nil && (!errors.Is(err, ErrParams) || sig != nil):
				errs <- "an error that is not ErrParams, or bytes with an error"
			}
		}()
		if i == 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := k.Close(); err != nil {
					errs <- "Close: " + err.Error()
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if _, err := k.Sign(nil, d, crypto.SHA384); !errors.Is(err, ErrParams) {
		t.Errorf("a Sign after Close and after the others: %v", err)
	}
}

func TestAKeyPrintsAsAFixedTextUnderEveryVerbAndMarshalsToNothing(t *testing.T) {
	k := mustGenerate(t)
	cert := certFor(t, k)
	secrets := keysOf(t, k, cert)
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%p", "%T", "%10v", "%-40s", "%.3s", "%08x"}
	type holder struct {
		K     *Key
		Value Key
		Slice []*Key
		Map   map[string]*Key
	}
	h := holder{K: k, Value: *k, Slice: []*Key{k}, Map: map[string]*Key{"k": k}}
	for _, verb := range verbs {
		for name, v := range map[string]any{"pointer": k, "value": *k, "struct": h, "pointer to struct": &h, "slice": []*Key{k, k}, "error wrap": fmt.Errorf("sign: %w", errors.New("x")), "key in an error": fmt.Errorf("sign %v: %w", k, errors.New("x"))} {
			out := fmt.Sprintf(verb, v)
			if f := secrets.findText(out); f != "" {
				t.Errorf("%s of a %s holds a canary (%s)", verb, name, f)
			}
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		if got := fmt.Sprintf(verb, k); got != keyText {
			t.Errorf("%s of *Key is %q, want %q", verb, got, keyText)
		}
		if got := fmt.Sprintf(verb, *k); got != keyText {
			t.Errorf("%s of Key is %q, want %q", verb, got, keyText)
		}
	}
	if got := fmt.Sprint(k, *k); got != keyText+" "+keyText {
		t.Errorf("Sprint is %q", got)
	}
	for name, v := range map[string]any{"pointer": k, "value": *k, "struct": h} {
		out, err := json.Marshal(v)
		if err != nil {
			continue // an error is as good as nothing
		}
		if f := secrets.find(out); f != "" {
			t.Errorf("json of a %s holds a canary (%s)", name, f)
		}
	}
	//nolint:staticcheck // that the key marshals to nothing is the case under test
	if out, err := json.Marshal(k); err != nil || string(out) != "{}" {
		t.Errorf("json.Marshal gives %q (%v), want {}", out, err)
	}
	if out, err := json.MarshalIndent(h, "", " "); err == nil {
		if f := secrets.find(out); f != "" {
			t.Errorf("indented json holds a canary (%s)", f)
		}
	}
	var nilKey *Key
	// A nil pointer prints as fmt prints every nil pointer; a zero key prints the fixed text.
	if got := fmt.Sprintf("%v %+v", nilKey, &Key{}); got != "<nil> "+keyText {
		t.Errorf("a nil and a zero key print %q", got)
	}
}

func TestAKeyIsAKeystoreKeyOfKindSoftwareThatCanBeCopiedWithOneWarning(t *testing.T) {
	var k keystore.Key = mustGenerate(t)
	if k.Kind() != keystore.KindSoftware || k.Kind() != "software" {
		t.Errorf("Kind is %q", k.Kind())
	}
	if !k.Copyable() {
		t.Error("a software key is not copyable")
	}
	w := k.Warnings()
	if len(w) != 1 || w[0] != "software-copyable" {
		t.Errorf("Warnings is %q", w)
	}
	if keystore.WarningSoftwareCopyable != "software-copyable" {
		t.Errorf("the constant is %q", keystore.WarningSoftwareCopyable)
	}
	w[0] = "changed"
	if got := k.Warnings(); got[0] != "software-copyable" {
		t.Error("Warnings shares its list between calls")
	}
	var nilKey *Key
	if nilKey.Kind() != keystore.KindSoftware || !nilKey.Copyable() || len(nilKey.Warnings()) != 1 {
		t.Error("a nil key answers differently")
	}
}

// The flag of a closed key decides, not only what Close did to the numbers.
func TestAKeyThatIsMarkedClosedGivesNoPublicKeyAndNoSignatureWhateverItsNumbersAre(t *testing.T) {
	k := mustGenerate(t)
	k.s.closed = true
	if k.Public() != nil {
		t.Error("Public of a key marked closed is not nil")
	}
	if sig, err := k.Sign(nil, digest48(), crypto.SHA384); sig != nil || !errors.Is(err, ErrParams) {
		t.Errorf("Sign: %v", err)
	}
	if k.publicCopy() != nil {
		t.Error("publicCopy is not nil")
	}
}
