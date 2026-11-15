package trustset

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/rootlist"
)

// The checks that only a draft made by hand can reach: the self-check of Sign, which asks the reader
// of the keyring file again and compares the test mark of its primaries with the test mark of the
// X.509 roots that NewDraft read.

const (
	markRootsTest     = "the X.509 roots are test roots and the OpenPGP primaries are not"
	markPrimariesTest = "the OpenPGP primaries are test primaries and the X.509 roots are not"
)

var markSerial int64

// newMarkedKey is a root key like newIKey, whose common name carries the test mark or none does.
func newMarkedKey(t testing.TB, label string, test bool) ikey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	markSerial++
	name := "Example Test Root " + label
	if test {
		name += " (TEST ONLY)"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9000 + markSerial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewKeySigner(label, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return ikey{label: label, cert: cert, key: key, pin: jws.Pin(cert), signer: s}
}

// newMarkedPrimary is newIPrimary with the mark of the user ID given.
func newMarkedPrimary(t testing.TB, label string, test bool) ipgp {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := openpgp.UserID("Example Test", label, "root@example.org", test)
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

// mFixture is a first list of A and B with a keyring file, all of one mark.
type mFixture struct {
	a, b   ikey
	pa, pb ipgp
	draft  *Draft
	bare   *Draft // the same roots, no fingerprint, no keyring file
	test   bool
}

func newMFixture(t testing.TB, test bool) *mFixture {
	t.Helper()
	f := &mFixture{test: test}
	f.a, f.b = newMarkedKey(t, "A", test), newMarkedKey(t, "B", test)
	f.pa, f.pb = newMarkedPrimary(t, "A", test), newMarkedPrimary(t, "B", test)
	certs := map[string][]byte{"A": f.a.cert.Raw, "B": f.b.cert.Raw}
	var err error
	f.draft, err = NewDraft(Input{
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
	return f
}

// tally is a Signer that counts how many times it was asked.
type tally struct {
	Signer
	mu sync.Mutex
	n  int
}

func (s *tally) SignES384(input []byte) ([]byte, error) {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
	return s.Signer.SignES384(input)
}

func (s *tally) asked() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// NewDraft keeps the mark of the X.509 roots, for a list with a keyring file and for one without.
func TestNewDraftKeepsTheMarkOfTheRoots(t *testing.T) {
	for _, test := range []bool{true, false} {
		f := newMFixture(t, test)
		if f.draft.testRoots != test || f.bare.testRoots != test {
			t.Errorf("test=%v: the draft keeps %v, the one with no keyring %v", test, f.draft.testRoots, f.bare.testRoots)
		}
		if f.draft.Keyring() == nil || f.bare.Keyring() != nil {
			t.Errorf("test=%v: the keyring files are not as expected", test)
		}
	}
	var zero Draft
	if zero.testRoots {
		t.Error("a zero draft holds the test mark")
	}
}

// The negative control: a draft that NewDraft made signs, and its self-check accepts the keyring file,
// for both marks. The keyring file and the roots carry one mark.
func TestSelfCheckAcceptsAKeyringOfTheMarkOfTheRoots(t *testing.T) {
	for _, test := range []bool{true, false} {
		f := newMFixture(t, test)
		sg := &tally{Signer: f.a.signer}
		set, err := f.draft.Sign([]Signer{sg}, nil)
		if err != nil {
			t.Fatalf("test=%v: %v", test, err)
		}
		if len(set.Files()) != 4 || sg.asked() != 1 {
			t.Errorf("test=%v: %d files, asked %d times", test, len(set.Files()), sg.asked())
		}
		list, err := rootlist.ParseList(f.draft.listJSON)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.draft.selfCheckKeyring(list); err != nil {
			t.Errorf("test=%v: selfCheckKeyring: %v", test, err)
		}
	}
}

// A draft made by hand whose keyring file has the other test mark than the X.509 roots is an ErrSelf in
// Sign, told as a fault of the keyring file, and no set comes. The file fits the list: the reader
// accepts it, and the mark is the only fault. The signer of the first list was asked once, which is
// what Sign does before the check, and the check asks nobody.
func TestSignRefusesAKeyringFileOfAnotherMarkThanTheRoots(t *testing.T) {
	cases := []struct {
		name     string
		filesAre bool // the primaries (and the file the draft holds) are test primaries
		want     string
	}{
		{"test primaries, roots said to be real", true, markPrimariesTest},
		{"real primaries, roots said to be test", false, markRootsTest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newMFixture(t, c.filesAre)
			d := *f.draft
			d.testRoots = !c.filesAre
			sg := &tally{Signer: f.a.signer}
			set, err := d.Sign([]Signer{sg}, nil)
			if set != nil {
				t.Fatal("a set came with the error")
			}
			text := kindSelf(t, err)
			if !strings.Contains(text, "the keyring file does not fit the CA bundle: "+c.want) {
				t.Errorf("the text does not say it: %v", err)
			}
			if strings.Contains(text, "reason ") {
				t.Errorf("a fault of the keyring is told as a fault of the list: %v", err)
			}
			if sg.asked() != 1 {
				t.Errorf("the signer was asked %d times, want 1", sg.asked())
			}
			// The self-check alone says the same, and it does not read its own files again.
			list, perr := rootlist.ParseList(d.listJSON)
			if perr != nil {
				t.Fatal(perr)
			}
			if got := kindSelf(t, d.selfCheckKeyring(list)); !strings.Contains(got, c.want) {
				t.Errorf("selfCheckKeyring: %v", got)
			}
		})
	}
}

// A draft whose list pins no primary has no keyring file to compare, whatever mark the draft says its
// roots have.
func TestSelfCheckWithNoKeyringComparesNoMark(t *testing.T) {
	for _, test := range []bool{true, false} {
		f := newMFixture(t, test)
		d := *f.bare
		d.testRoots = !test
		if _, err := d.Sign([]Signer{f.a.signer}, nil); err != nil {
			t.Errorf("test=%v: %v", test, err)
		}
	}
}

// A keyring file that the reader refuses is told by the reader, before the marks are compared, and a
// file whose primaries are not the list's too.
func TestSelfCheckTellsTheReadersFaultBeforeTheMarks(t *testing.T) {
	f := newMFixture(t, true)
	other := newMarkedPrimary(t, "A", false)
	for name, file := range map[string][]byte{
		"a file that stops short": f.draft.keyring[:len(f.draft.keyring)-1],
		"another primary":         slices.Concat(other.cert, f.pb.cert),
		"an armoured file":        []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"),
	} {
		t.Run(name, func(t *testing.T) {
			d := withKeyring(f.draft, file)
			d.testRoots = false // the marks differ as well
			_, err := d.Sign([]Signer{f.a.signer}, nil)
			text := kindSelf(t, err)
			if strings.Contains(text, "does not fit the CA bundle") {
				t.Errorf("told as a difference of marks: %v", err)
			}
		})
	}
}

// markDifference: the four pairs, and the sentence names the test family.
func TestMarkDifferenceSaysWhichFamilyIsTheTestOne(t *testing.T) {
	for _, c := range []struct {
		roots, primaries bool
		want             string
	}{
		{false, false, ""},
		{true, true, ""},
		{true, false, markRootsTest},
		{false, true, markPrimariesTest},
	} {
		if got := markDifference(c.roots, c.primaries); got != c.want {
			t.Errorf("roots %v primaries %v: %q, want %q", c.roots, c.primaries, got, c.want)
		}
	}
}

// The self-check works on a copy of the keyring file and leaves the draft as it was, for a refusal too.
func TestSelfCheckOfAMarkDifferenceChangesNothing(t *testing.T) {
	f := newMFixture(t, true)
	d := *f.draft
	d.testRoots = false
	before := bytes.Clone(d.keyring)
	if _, err := d.Sign([]Signer{f.a.signer}, nil); err == nil {
		t.Fatal("no error")
	}
	if !bytes.Equal(before, d.keyring) || d.testRoots {
		t.Error("the draft changed")
	}
}

// keyringOf with the mark of the roots: the file comes back for the same mark, for test and for real,
// and nothing comes back with a refusal for the other, which is an ErrParams that names the test family.
func TestKeyringOfGivesNoBytesWithAMarkDifference(t *testing.T) {
	for _, test := range []bool{true, false} {
		f := newMFixture(t, test)
		roots := []Root{
			{Label: "A", X509SPKISHA256: f.a.pin, OpenPGPFingerprint: f.pa.print},
			{Label: "B", X509SPKISHA256: f.b.pin, OpenPGPFingerprint: f.pb.print},
		}
		certs := map[string][]byte{"A": f.pa.cert, "B": f.pb.cert}
		file, err := keyringOf(roots, certs, test)
		if err != nil || !bytes.Equal(file, slices.Concat(f.pa.cert, f.pb.cert)) {
			t.Errorf("test=%v, the mark of the roots: %d bytes, %v", test, len(file), err)
		}
		file, err = keyringOf(roots, certs, !test)
		if file != nil {
			t.Errorf("test=%v: %d bytes come with the refusal", test, len(file))
		}
		// Primaries of one mark with roots said to carry the other: test primaries with real roots, or
		// the reverse.
		want := markRootsTest
		if test {
			want = markPrimariesTest
		}
		if err == nil || !errors.Is(err, ErrParams) || !strings.HasSuffix(err.Error(), ": "+want) {
			t.Errorf("test=%v, the other mark: %v", test, err)
		}
	}
	// A list that pins no primary has no file whatever the mark: the answer is nil and no error.
	f := newMFixture(t, true)
	for _, test := range []bool{true, false} {
		if file, err := keyringOf([]Root{{Label: "A", X509SPKISHA256: f.a.pin}}, nil, test); file != nil || err != nil {
			t.Errorf("no fingerprint, test=%v: %v, %v", test, file, err)
		}
	}
}

// marshalCABundle says whether the roots are test roots, false with an error and no bytes, and the
// bytes are those of MarshalCABundle.
func TestMarshalCABundleSaysTheMarkOfTheRoots(t *testing.T) {
	for _, test := range []bool{true, false} {
		f := newMFixture(t, test)
		roots := []Root{{Label: "A", X509SPKISHA256: f.a.pin}, {Label: "B", X509SPKISHA256: f.b.pin}}
		ders := [][]byte{f.a.cert.Raw, f.b.cert.Raw}
		out, mark, err := marshalCABundle(1, roots, ders)
		if err != nil || mark != test {
			t.Fatalf("test=%v: mark %v, error %v", test, mark, err)
		}
		plain, err := MarshalCABundle(1, roots, ders)
		if err != nil || !bytes.Equal(out, plain) {
			t.Errorf("test=%v: MarshalCABundle gives other bytes: %v", test, err)
		}
		// A fault gives false and no bytes: the sequence, a count that does not fit, a certificate that
		// is not the root's.
		for name, call := range map[string]func() ([]byte, bool, error){
			"the sequence":        func() ([]byte, bool, error) { return marshalCABundle(0, roots, ders) },
			"too few":             func() ([]byte, bool, error) { return marshalCABundle(1, roots, ders[:1]) },
			"another certificate": func() ([]byte, bool, error) { return marshalCABundle(1, roots, [][]byte{ders[1], ders[0]}) },
			"no roots":            func() ([]byte, bool, error) { return marshalCABundle(1, nil, nil) },
		} {
			out, mark, err := call()
			if err == nil || out != nil || mark {
				t.Errorf("test=%v, %s: %d bytes, mark %v, error %v", test, name, len(out), mark, err)
			}
		}
	}
	// A mix of test and real roots is a fault, and says false.
	a, b := newMarkedKey(t, "A", true), newMarkedKey(t, "B", false)
	out, mark, err := marshalCABundle(1, []Root{{Label: "A", X509SPKISHA256: a.pin}, {Label: "B", X509SPKISHA256: b.pin}}, [][]byte{a.cert.Raw, b.cert.Raw})
	if err == nil || out != nil || mark {
		t.Errorf("a mix: %d bytes, mark %v, error %v", len(out), mark, err)
	}
}
