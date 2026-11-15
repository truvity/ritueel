package trustset

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/rootlist"
)

// The checks of the keyring file that only a draft or a set made by hand can reach: the self-check of
// Sign, which asks the reader of the keyring file again with the entries of the list that the reader
// of the page accepted, and the set whose keyring file does not fit its list.

// ipgp is one OpenPGP primary made in memory for these tests.
type ipgp struct {
	label string
	cert  []byte
	print string
}

var (
	iCreated  = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	iCeremony = time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
)

func newIPrimary(t testing.TB, label string) ipgp {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := openpgp.UserID("Example Test", label, "root@example.org", true)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := openpgp.NewPrimary(rand.Reader, openpgp.PrimaryParams{
		Key: key, CreationTime: iCreated, CeremonyTime: iCeremony, ExpiresAt: iCeremony.AddDate(3, 0, 0), UserID: uid,
	})
	if err != nil {
		t.Fatal(err)
	}
	print, err := openpgp.Fingerprint(&key.PublicKey, iCreated)
	if err != nil {
		t.Fatal(err)
	}
	return ipgp{label: label, cert: cert, print: print}
}

// kFixture is a first list of A and B with their primaries, and the list of A alone.
type kFixture struct {
	a, b, c ikey
	pa, pb  ipgp
	pc      ipgp
	d       *Draft // A and B, with the keyring file
	bare    *Draft // A and B, no fingerprints, no keyring file
	onlyA   *Draft // A, with its keyring file
}

func newKFixture(t testing.TB) *kFixture {
	t.Helper()
	f := &kFixture{
		a: newIKey(t, "A", 0), b: newIKey(t, "B", 0), c: newIKey(t, "C", 0),
		pa: newIPrimary(t, "A"), pb: newIPrimary(t, "B"), pc: newIPrimary(t, "C"),
	}
	certs := map[string][]byte{"A": f.a.cert.Raw, "B": f.b.cert.Raw}
	var err error
	f.d, err = NewDraft(Input{
		Sequence: 1, SignedAt: iAt,
		Roots:               []Root{{Label: "A", X509SPKISHA256: f.a.pin, OpenPGPFingerprint: f.pa.print}, {Label: "B", X509SPKISHA256: f.b.pin, OpenPGPFingerprint: f.pb.print}},
		Certificates:        certs,
		OpenPGPCertificates: map[string][]byte{"A": f.pa.cert, "B": f.pb.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.bare, err = NewDraft(Input{
		Sequence: 1, SignedAt: iAt,
		Roots:        []Root{{Label: "A", X509SPKISHA256: f.a.pin}, {Label: "B", X509SPKISHA256: f.b.pin}},
		Certificates: certs,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.onlyA, err = NewDraft(Input{
		Sequence: 1, SignedAt: iAt,
		Roots:               []Root{{Label: "A", X509SPKISHA256: f.a.pin, OpenPGPFingerprint: f.pa.print}},
		Certificates:        map[string][]byte{"A": f.a.cert.Raw},
		OpenPGPCertificates: map[string][]byte{"A": f.pa.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// withKeyring is a copy of the draft that holds another keyring file, as a draft made by hand would.
func withKeyring(d *Draft, keyring []byte) *Draft {
	c := *d
	c.keyring = keyring
	if keyring != nil {
		c.keyringSHA = hexSHA256(keyring)
	}
	return &c
}

// kindSelf checks that err is an ErrSelf and nothing else, and returns its text.
func kindSelf(t *testing.T, err error) string {
	t.Helper()
	kindOfSelf(t, err)
	return err.Error()
}

// The negative control: the draft as NewDraft made it signs, and the self-check accepts it.
func TestSelfCheckKeyringAcceptsWhatNewDraftMade(t *testing.T) {
	f := newKFixture(t)
	set, err := f.d.Sign([]Signer{f.a.signer}, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(set.Keyring(), slices.Concat(f.pa.cert, f.pb.cert)) {
		t.Error("the set holds another keyring file")
	}
	list, err := rootlist.ParseList(f.d.listJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.selfCheckKeyring(list); err != nil {
		t.Errorf("selfCheckKeyring: %v", err)
	}
	// A list that pins nothing and a draft with no file agree as well.
	bareList, err := rootlist.ParseList(f.bare.listJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.bare.selfCheckKeyring(bareList); err != nil {
		t.Errorf("selfCheckKeyring of a list that pins nothing: %v", err)
	}
}

// A keyring file that does not fit the list that was signed is an ErrSelf and no set. The file is
// made by hand into the draft, which NewDraft would never make.
func TestSignRefusesAKeyringFileThatDoesNotFitTheList(t *testing.T) {
	f := newKFixture(t)
	both := slices.Concat(f.pa.cert, f.pb.cert)
	cases := []struct {
		name    string
		draft   *Draft
		signers []Signer
		want    string
	}{
		{"a keyring file of other primaries", withKeyring(f.d, slices.Concat(f.pa.cert, f.pc.cert)), []Signer{f.a.signer}, "not on the list"},
		{"a swapped pair", withKeyring(f.d, slices.Concat(f.pb.cert, f.pa.cert)), []Signer{f.a.signer}, "out of order"},
		{"one certificate too few", withKeyring(f.d, f.pa.cert), []Signer{f.a.signer}, "missing"},
		{"one certificate too many", withKeyring(f.d, slices.Concat(both, f.pc.cert)), []Signer{f.a.signer}, "one too many"},
		{"a file that stops short", withKeyring(f.d, both[:len(both)-1]), []Signer{f.a.signer}, "refuses the keyring file"},
		{"an empty file that is not nil", withKeyring(f.d, []byte{}), []Signer{f.a.signer}, "the file is empty"},
		{"an armoured file", withKeyring(f.d, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")), []Signer{f.a.signer}, "armoured"},
		{"no file for a list that pins primaries", withKeyring(f.d, nil), []Signer{f.a.signer}, "holds no keyring file"},
		{"a file for a list that pins none", withKeyring(f.bare, both), []Signer{f.a.signer}, "pins no OpenPGP primary"},
		{"a file of A for the list of A and a file of B and A for A", withKeyring(f.onlyA, slices.Concat(f.pa.cert, f.pb.cert)), []Signer{f.a.signer}, "one too many"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := tc.draft.Sign(tc.signers, nil)
			if set != nil {
				t.Fatal("a set came with the error")
			}
			text := kindSelf(t, err)
			if !strings.Contains(text, tc.want) {
				t.Errorf("the text does not say %q: %v", tc.want, err)
			}
			// The files of the list and of the bundle were accepted; the fault is the keyring's alone.
			if strings.Contains(text, "reason ") {
				t.Errorf("the keyring fault is told as a fault of the list: %v", err)
			}
		})
	}
}

// The self-check asks the reader with the entries of the list that the reader of the page accepted,
// whatever the draft was made from: the list holds A only, so a file of A and B has one certificate
// too many, and the list that holds A and B takes the same file.
func TestSelfCheckKeyringUsesTheEntriesOfTheAcceptedList(t *testing.T) {
	f := newKFixture(t)
	both := withKeyring(f.d, slices.Concat(f.pa.cert, f.pb.cert))
	listA, err := rootlist.ParseList(f.onlyA.listJSON)
	if err != nil {
		t.Fatal(err)
	}
	listAB, err := rootlist.ParseList(f.d.listJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := both.selfCheckKeyring(listAB); err != nil {
		t.Errorf("the list of A and B: %v", err)
	}
	text := kindSelf(t, both.selfCheckKeyring(listA))
	if !strings.Contains(text, "one too many") {
		t.Errorf("the list of A: %v", text)
	}
	// A list with no entry at all, as a list of no fingerprint.
	empty := &rootlist.List{}
	kindSelf(t, both.selfCheckKeyring(empty))
	if err := withKeyring(f.d, nil).selfCheckKeyring(empty); err != nil {
		t.Errorf("no file and no entry: %v", err)
	}
}

// The text of a fault that the keyring file makes in the self-check shows no byte of the file.
func TestSelfCheckKeyringTextShowsNoByteOfTheFile(t *testing.T) {
	f := newKFixture(t)
	hostile := bytes.Clone(slices.Concat(f.pa.cert, f.pb.cert))
	hostile[len(hostile)/2] ^= 0xff
	_, err := withKeyring(f.d, hostile).Sign([]Signer{f.a.signer}, nil)
	text := kindSelf(t, err)
	if len(text) > 600 {
		t.Errorf("the text is %d bytes long", len(text))
	}
}

// A zero draft and a draft that no NewDraft made have no keyring file and refuse to sign.
func TestZeroDraftHasNoKeyringFile(t *testing.T) {
	var d Draft
	if d.Keyring() != nil || d.KeyringSHA256() != "" {
		t.Error("a zero draft gives a keyring file")
	}
	if _, err := d.Sign(nil, nil); !errors.Is(err, ErrParams) {
		t.Errorf("Sign of a zero draft: %v", err)
	}
	// A draft that holds a keyring file and nothing else is not valid: the accessors still give nothing.
	k := &Draft{keyring: []byte{1}, keyringSHA: "x"}
	if k.Keyring() != nil || k.KeyringSHA256() != "" {
		t.Error("an invalid draft gives its keyring file")
	}
}

// signedSet is a set of a draft, for the tests of a set that does not fit its list.
func signedSet(t *testing.T, f *kFixture, d *Draft) *Set {
	t.Helper()
	set, err := d.Sign([]Signer{f.a.signer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// A forged set (a zero set; a list that pins primaries and no keyring file; a keyring file and a list
// that pins none; a list that cannot be read) has no files and is not written, and the file system is
// as it was.
func TestForgedSetHasNoFilesAndWritesNothing(t *testing.T) {
	f := newKFixture(t)
	good := signedSet(t, f, f.d)
	bare := signedSet(t, f, f.bare)
	if len(good.Files()) != 4 || len(bare.Files()) != 3 {
		t.Fatalf("%d and %d files", len(good.Files()), len(bare.Files()))
	}
	forge := func(from *Set, change func(*Set)) *Set {
		c := *from
		c.keyring = slices.Clone(from.keyring)
		c.listJSON = slices.Clone(from.listJSON)
		change(&c)
		return &c
	}
	cases := map[string]*Set{
		"fingerprints and no keyring file":   forge(good, func(s *Set) { s.keyring = nil }),
		"fingerprints and an empty file":     forge(good, func(s *Set) { s.keyring = []byte{} }),
		"a keyring file and no fingerprints": forge(bare, func(s *Set) { s.keyring = []byte{0xC6, 0x00} }),
		"a list that is not a list":          forge(good, func(s *Set) { s.listJSON = []byte("{") }),
		"a list of text":                     forge(good, func(s *Set) { s.listJSON = []byte("not json") }),
		"a list that pins none and a file":   forge(good, func(s *Set) { s.listJSON = bare.listJSON }),
		"a list that pins and the bare set":  forge(bare, func(s *Set) { s.listJSON = good.listJSON }),
		"a list with an unknown key": forge(good, func(s *Set) {
			s.listJSON = bytes.ReplaceAll(s.listJSON, []byte(`"openpgp_fingerprint"`), []byte(`"openpgp_fingerprinx"`))
		}),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if s.Files() != nil {
				t.Fatal("a set that does not fit its list has files")
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
			// The accessors say what the set holds and nothing more.
			if got := s.Keyring(); !bytes.Equal(got, s.keyring) && s.keyring != nil {
				t.Error("Keyring differs from the field")
			}
		})
	}
}

// A set that fits its list gives the files as before, and a set that Sign made from a draft with a
// keyring file shares no memory with it.
func TestSetKeyringSharesNoMemoryWithTheDraft(t *testing.T) {
	f := newKFixture(t)
	set := signedSet(t, f, f.d)
	if &set.keyring[0] == &f.d.keyring[0] {
		t.Error("the set shares the keyring file with the draft")
	}
	set.keyring[0] ^= 0xff
	if f.d.keyring[0] == set.keyring[0] {
		t.Error("changing the set changed the draft")
	}
}

// FuzzSelfCheckKeyring: the bytes are the keyring file of a draft made by hand. Sign gives a set or
// an ErrSelf and nothing else, never panics, and a set comes only for a file that the reader of the
// keyring file accepts with the entries of the list; the set then holds the bytes as they are.
func FuzzSelfCheckKeyring(f *testing.F) {
	fx := newKFixture(f)
	both := slices.Concat(fx.pa.cert, fx.pb.cert)
	f.Add(both)
	f.Add(slices.Concat(fx.pb.cert, fx.pa.cert))
	f.Add(fx.pa.cert)
	f.Add(both[:len(both)-1])
	f.Add(append(slices.Clone(both), 0))
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
	f.Add(bytes.Repeat([]byte{0xC6}, 100))
	entries := []openpgp.KeyringEntry{{Label: "A", Fingerprint: fx.pa.print}, {Label: "B", Fingerprint: fx.pb.print}}
	f.Fuzz(func(t *testing.T, data []byte) {
		d := withKeyring(fx.d, bytes.Clone(data))
		if data == nil {
			d = withKeyring(fx.d, []byte{})
		}
		set, err := d.Sign([]Signer{fx.a.signer}, nil)
		_, rerr := openpgp.ReadKeyring(bytes.Clone(data), entries)
		if err != nil {
			if set != nil {
				t.Fatal("a set with an error")
			}
			kindOfSelf(t, err)
			if rerr == nil {
				// The reader accepts the file: Sign may refuse it only for the test mark of the
				// primaries, which differs from the mark of the X.509 roots of the draft.
				keys, _ := openpgp.ReadKeyring(bytes.Clone(data), entries)
				if len(keys) == 0 || keys[0].TestMark() == fx.d.testRoots {
					t.Fatalf("the reader accepts the file with the mark of the roots and Sign refuses it: %v", err)
				}
				if !strings.Contains(err.Error(), "does not fit the CA bundle") {
					t.Fatalf("a refusal for the mark does not say so: %v", err)
				}
			}
			return
		}
		if rerr != nil {
			t.Fatalf("Sign takes a file that the reader refuses: %v", rerr)
		}
		if keys, _ := openpgp.ReadKeyring(bytes.Clone(data), entries); len(keys) == 0 || keys[0].TestMark() != fx.d.testRoots {
			t.Fatal("Sign takes a file whose primaries carry another test mark than the roots")
		}
		if !bytes.Equal(set.Keyring(), data) || len(set.Files()) != 4 {
			t.Fatal("the set does not hold the file as it is")
		}
	})
}
