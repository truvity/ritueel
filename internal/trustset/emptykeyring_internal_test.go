package trustset

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// One reading of a keyring that is not nil, in the whole package: it is a keyring held, also with
// zero bytes. No exported call can make that state, so these tests build the set and the draft by
// hand.

// emptySets returns a set of each kind with a keyring of zero bytes that is not nil, and its
// counterpart with a keyring that is nil.
func emptySets(t testing.TB) (pins, none *Set, pinsNil, noneNil *Set) {
	t.Helper()
	f := newMFixture(t, true)
	good, err := f.draft.Sign([]Signer{f.a.signer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bare, err := f.bare.Sign([]Signer{f.a.signer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	with := func(s *Set, keyring []byte) *Set {
		c := *s
		c.keyring = keyring
		return &c
	}
	return with(good, []byte{}), with(bare, []byte{}), with(good, nil), with(bare, nil)
}

// hasKeyring reads the keyring that is not nil as held: it never agrees with a list that pins none,
// and an empty file does not agree with a list that pins primaries either.
func TestHasKeyringReadsAKeyringThatIsNotNilAsHeld(t *testing.T) {
	pins, none, pinsNil, noneNil := emptySets(t)
	f := newMFixture(t, true)
	full, err := f.draft.Sign([]Signer{f.a.signer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	oneByte := *none
	oneByte.keyring = []byte{0xC6}
	cases := []struct {
		name        string
		set         *Set
		has, agrees bool
	}{
		{"a list that pins none and a nil keyring", noneNil, false, true},
		{"a list that pins primaries and a nil keyring", pinsNil, false, false},
		{"a list that pins none and an empty keyring", none, true, false},
		{"a list that pins primaries and an empty keyring", pins, true, false},
		{"a list that pins none and a keyring of a byte", &oneByte, true, false},
		{"a list that pins primaries and its keyring", full, true, true},
	}
	for _, c := range cases {
		has, ok := c.set.hasKeyring()
		if has != c.has || ok != c.agrees {
			t.Errorf("%s: hasKeyring = %v, %v; want %v, %v", c.name, has, ok, c.has, c.agrees)
		}
	}
	// A list that cannot be read agrees with nothing, for a nil keyring and for an empty one.
	for _, keyring := range [][]byte{nil, {}, {0xC6}} {
		s := *none
		s.listJSON, s.keyring = []byte("{"), keyring
		if has, ok := s.hasKeyring(); has || ok {
			t.Errorf("a list that is not a list, keyring %v: hasKeyring = %v, %v", keyring, has, ok)
		}
	}
}

// A set with a keyring of zero bytes that is not nil, with a list that pins none and with a list that
// pins primaries, has no files and is not written: Write is the ErrParams "the set has no files", and
// nothing is on the disk. The accessor gives the keyring as it is held, an empty value that is not nil.
func TestASetWithAnEmptyKeyringThatIsNotNilHasNoFilesAndWritesNothing(t *testing.T) {
	pins, none, _, noneNil := emptySets(t)
	if len(noneNil.Files()) != 3 {
		t.Fatalf("the control set has %d files", len(noneNil.Files()))
	}
	for name, s := range map[string]*Set{"a list that pins none": none, "a list that pins primaries": pins} {
		t.Run(name, func(t *testing.T) {
			if s.Files() != nil {
				t.Fatalf("%d files", len(s.Files()))
			}
			if got := s.Keyring(); got == nil || len(got) != 0 {
				t.Errorf("Keyring = %#v, want an empty value that is not nil", got)
			}
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "trust"), 0o755); err != nil {
				t.Fatal(err)
			}
			w, err := fsx.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = w.Close() }()
			err = s.Write(w, "trust/1-00000000")
			if !errors.Is(err, ErrParams) || !strings.Contains(err.Error(), "the set has no files") {
				t.Errorf("Write: %v", err)
			}
			if ents, _ := os.ReadDir(filepath.Join(dir, "trust")); len(ents) != 0 {
				t.Errorf("trust/ holds %d entries", len(ents))
			}
		})
	}
	// The accessor of a nil keyring still gives nil.
	if noneNil.Keyring() != nil {
		t.Error("a nil keyring is not nil")
	}
}

// A draft with a keyring of zero bytes that is not nil: the self-check refuses it (a keyring is held,
// and it is no keyring file), whether the list pins primaries or not, and the accessors read it as held:
// an empty value that is not nil, and the digest of zero bytes. The draft with a nil keyring gives
// nil and an empty digest.
func TestADraftWithAnEmptyKeyringThatIsNotNilIsOneReading(t *testing.T) {
	const emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	f := newMFixture(t, true)
	for name, d := range map[string]*Draft{
		"a list that pins primaries": withKeyring(f.draft, []byte{}),
		"a list that pins none":      withKeyring(f.bare, []byte{}),
	} {
		t.Run(name, func(t *testing.T) {
			sg := &tally{Signer: f.a.signer}
			set, err := d.Sign([]Signer{sg}, nil)
			if set != nil {
				t.Fatal("a set came with the error")
			}
			kindSelf(t, err)
			if got := d.Keyring(); got == nil || len(got) != 0 {
				t.Errorf("Keyring = %#v, want an empty value that is not nil", got)
			}
			if got := d.KeyringSHA256(); got != emptyDigest {
				t.Errorf("KeyringSHA256 = %q, want the digest of zero bytes", got)
			}
		})
	}
	// The texts say which fault it is.
	_, err := withKeyring(f.draft, []byte{}).Sign([]Signer{f.a.signer}, nil)
	if text := kindSelf(t, err); !strings.Contains(text, "the file is empty") {
		t.Errorf("a list that pins primaries: %v", text)
	}
	_, err = withKeyring(f.bare, []byte{}).Sign([]Signer{f.a.signer}, nil)
	if text := kindSelf(t, err); !strings.Contains(text, "pins no OpenPGP primary") {
		t.Errorf("a list that pins none: %v", text)
	}
	// A draft with a nil keyring: a list that pins none signs, a list that pins primaries is refused.
	nilBare := withKeyring(f.bare, nil)
	if nilBare.Keyring() != nil || nilBare.KeyringSHA256() != "" {
		t.Error("a nil keyring gives a keyring or a digest")
	}
	if _, err := nilBare.Sign([]Signer{f.a.signer}, nil); err != nil {
		t.Errorf("no keyring for a list that pins none: %v", err)
	}
	_, err = withKeyring(f.draft, nil).Sign([]Signer{f.a.signer}, nil)
	if text := kindSelf(t, err); !strings.Contains(text, "holds no keyring file") {
		t.Errorf("a list that pins primaries and no keyring: %v", text)
	}
}

// The reading follows the keyring of a draft into the set that Sign makes: a set whose keyring is the
// copy of a keyring held keeps what is held, nil stays nil.
func TestSignKeepsWhatIsHeldAndNilStaysNil(t *testing.T) {
	f := newMFixture(t, false)
	set, err := f.draft.Sign([]Signer{f.a.signer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if set.keyring == nil || !bytes.Equal(set.keyring, f.draft.keyring) {
		t.Error("the set does not hold the keyring of the draft")
	}
	bare, err := f.bare.Sign([]Signer{f.a.signer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bare.keyring != nil {
		t.Errorf("a set with no keyring holds %#v", bare.keyring)
	}
}
