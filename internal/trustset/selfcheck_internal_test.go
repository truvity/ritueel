package trustset

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/history"
)

// The self-check (Draft.selfCheck) asks the reader of the page about the builder's own output. The
// builder cannot make a file the reader refuses, so these tests reach ErrSelf by changing the file,
// or the draft, between the signing and the check.

var iAt = time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)

// iFixture is a first list of A and B and a renewal of it, both signed, made with ikeys.
type iFixture struct {
	a, b    ikey
	first   *Draft
	second  *Draft
	firstS  *Set
	secondS *Set
}

func newIFixture(t *testing.T) *iFixture {
	t.Helper()
	f := &iFixture{a: newIKey(t, "A", 0), b: newIKey(t, "B", 0)}
	roots := []Root{{Label: "A", X509SPKISHA256: f.a.pin}, {Label: "B", X509SPKISHA256: f.b.pin}}
	certs := map[string][]byte{"A": f.a.cert.Raw, "B": f.b.cert.Raw}
	var err error
	f.first, err = NewDraft(Input{Sequence: 1, SignedAt: iAt, Roots: roots, Certificates: certs})
	if err != nil {
		t.Fatal(err)
	}
	f.firstS, err = f.first.Sign([]Signer{f.a.signer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.second, err = NewDraft(Input{
		Sequence: 2, SignedAt: iAt.Add(time.Hour), Roots: roots, Certificates: certs,
		LastRecordSHA256: strings.Repeat("ab", 32), Previous: f.firstS.listJSON,
		Earlier: []history.RootList{{Name: "1", Keys: []history.RootKey{{Label: "A", Pin: f.a.pin}, {Label: "B", Pin: f.b.pin}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.secondS, err = f.second.Sign([]Signer{f.b.signer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSelfCheckAcceptsWhatSignMade(t *testing.T) {
	f := newIFixture(t)
	if err := f.first.selfCheck(f.firstS.listJWS); err != nil {
		t.Errorf("first: %v", err)
	}
	if err := f.second.selfCheck(f.secondS.listJWS); err != nil {
		t.Errorf("second: %v", err)
	}
}

// wantSelf checks an ErrSelf with the reason and the check number in the text.
func wantSelf(t *testing.T, err error) string {
	t.Helper()
	kindOfSelf(t, err)
	text := err.Error()
	if !strings.Contains(text, "reason ") || !strings.Contains(text, "check ") {
		t.Errorf("the text has no reason code and check number: %v", err)
	}
	return text
}

func kindOfSelf(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("no error")
	}
	if !errors.Is(err, ErrSelf) || errors.Is(err, ErrParams) || errors.Is(err, ErrSign) || errors.Is(err, ErrSigners) || errors.Is(err, ErrReturns) {
		t.Fatalf("not only ErrSelf: %v", err)
	}
	for i := 0; i < len(err.Error()); i++ {
		if c := err.Error()[i]; c < 0x20 || c > 0x7e {
			t.Fatalf("not printable: %+q", err.Error())
		}
	}
}

func TestSelfCheckRefusesAChangedSignatureFile(t *testing.T) {
	f := newIFixture(t)
	var doc struct {
		Signatures []struct {
			Protected string `json:"protected"`
			Signature string `json:"signature"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(f.secondS.listJWS, &doc); err != nil {
		t.Fatal(err)
	}
	remake := func(mutate func()) []byte {
		mutate()
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	t.Run("one byte of the file changed", func(t *testing.T) {
		file := bytes.Clone(f.secondS.listJWS)
		i := bytes.Index(file, []byte(`"signature":"`)) + len(`"signature":"`)
		if file[i] == 'A' {
			file[i] = 'B'
		} else {
			file[i] = 'A'
		}
		wantSelf(t, f.second.selfCheck(file))
	})
	t.Run("a signature that is not the list's", func(t *testing.T) {
		other := bytes.Clone(f.firstS.listJWS)
		wantSelf(t, f.second.selfCheck(other))
	})
	t.Run("no signatures", func(t *testing.T) {
		wantSelf(t, f.second.selfCheck([]byte(`{"signatures":[]}`)))
	})
	t.Run("not a file", func(t *testing.T) {
		for _, junk := range []string{"", "x", "{}", "null", strings.Repeat("{", 1000)} {
			wantSelf(t, f.second.selfCheck([]byte(junk)))
		}
	})
	t.Run("a header that is not the page's", func(t *testing.T) {
		out := remake(func() {
			raw, _ := base64.RawURLEncoding.DecodeString(doc.Signatures[0].Protected)
			raw = bytes.Replace(raw, []byte("root-list+json"), []byte("root-list+jsoX"), 1)
			doc.Signatures[0].Protected = base64.RawURLEncoding.EncodeToString(raw)
		})
		wantSelf(t, f.second.selfCheck(out))
	})
}

// A list that needs more signatures than the file has: the file of the renewal is read against a
// draft that is an add (every key signs).
func TestSelfCheckRefusesAFileWithASignatureTooFew(t *testing.T) {
	f := newIFixture(t)
	c := newIKey(t, "C", 0)
	roots := []Root{{Label: "A", X509SPKISHA256: f.a.pin}, {Label: "B", X509SPKISHA256: f.b.pin}, {Label: "C", X509SPKISHA256: c.pin}}
	d, err := NewDraft(Input{
		Sequence: 2, SignedAt: iAt.Add(time.Hour), Roots: roots,
		Certificates:     map[string][]byte{"A": f.a.cert.Raw, "B": f.b.cert.Raw, "C": c.cert.Raw},
		LastRecordSHA256: strings.Repeat("ab", 32), Previous: f.firstS.listJSON,
		Earlier: []history.RootList{{Name: "1", Keys: []history.RootKey{{Label: "A", Pin: f.a.pin}, {Label: "B", Pin: f.b.pin}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind() != KindAdd {
		t.Fatalf("Kind = %v", d.Kind())
	}
	set, err := d.Sign([]Signer{f.a.signer, f.b.signer, c.signer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.selfCheck(set.listJWS); err != nil {
		t.Fatal(err)
	}
	// Take the signatures of A and B only: C's is missing.
	var doc struct {
		Signatures []map[string]string `json:"signatures"`
	}
	if err := json.Unmarshal(set.listJWS, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Signatures = doc.Signatures[:2]
	out, _ := json.Marshal(doc)
	text := wantSelf(t, d.selfCheck(out))
	if !strings.Contains(text, "check ") {
		t.Error(text)
	}
}

// A draft whose previous list is the list itself: the list is the held list again, which brings
// nothing new, and the builder never makes it.
func TestSelfCheckRefusesTheHeldListAgain(t *testing.T) {
	f := newIFixture(t)
	d := *f.second
	d.previous = d.listJSON
	err := d.selfCheck(f.secondS.listJWS)
	kindOfSelf(t, err)
}

// A list with a lower sequence than the held one is the way back, which the builder never writes.
func TestSelfCheckRefusesTheWayBack(t *testing.T) {
	f := newIFixture(t)
	d := *f.first
	d.kind = KindRenewal
	d.previous = f.secondS.listJSON
	kindOfSelf(t, d.selfCheck(f.firstS.listJWS))
}

// The clock of the check is the signing time: a draft whose signing time is later than the list's
// has an expired list (check 11), one whose signing time is earlier has a list from the future
// (check 5).
func TestSelfCheckClockIsTheSigningTime(t *testing.T) {
	f := newIFixture(t)
	late := *f.second
	late.signedAt = late.signedAt.AddDate(1, 2, 0)
	wantSelf(t, late.selfCheck(f.secondS.listJWS))
	early := *f.second
	early.signedAt = early.signedAt.Add(-time.Second)
	wantSelf(t, early.selfCheck(f.secondS.listJWS))
	exact := *f.second
	if err := exact.selfCheck(f.secondS.listJWS); err != nil {
		t.Errorf("the clock at the signing time: %v", err)
	}
}

// The trust of the check: a previous list that cannot be read, and a first list with no pins.
func TestSelfCheckTrustThatCannotBeMade(t *testing.T) {
	f := newIFixture(t)
	d := *f.second
	d.previous = []byte("garbage")
	kindOfSelf(t, d.selfCheck(f.secondS.listJWS))
	e := *f.first
	e.pins = nil
	kindOfSelf(t, e.selfCheck(f.firstS.listJWS))
	g := *f.first
	g.pins = []string{"x"}
	kindOfSelf(t, g.selfCheck(f.firstS.listJWS))
}

// The CA bundle is judged against the list that the reader accepted.
func TestSelfCheckRefusesACABundleThatIsNotTheLists(t *testing.T) {
	f := newIFixture(t)
	d := *f.second
	d.caBundle = bytes.Replace(d.caBundle, []byte("# trust-sequence: 2"), []byte("# trust-sequence: 3"), 1)
	wantSelfNoCheck(t, d.selfCheck(f.secondS.listJWS))
	e := *f.second
	e.caBundle = f.first.caBundle
	kindOfSelf(t, e.selfCheck(f.secondS.listJWS))
	h := *f.second
	h.caBundle = nil
	kindOfSelf(t, h.selfCheck(f.secondS.listJWS))
}

func wantSelfNoCheck(t *testing.T, err error) string {
	t.Helper()
	kindOfSelf(t, err)
	return err.Error()
}

// The self-check works on copies: the draft's bytes are the same after it ran, whatever the check
// does with what it is given.
func TestSelfCheckDoesNotChangeTheDraft(t *testing.T) {
	f := newIFixture(t)
	before := bytes.Clone(f.second.listJSON)
	prev := bytes.Clone(f.second.previous)
	bundle := bytes.Clone(f.second.caBundle)
	jwsFile := bytes.Clone(f.secondS.listJWS)
	_ = f.second.selfCheck(jwsFile)
	if !bytes.Equal(before, f.second.listJSON) || !bytes.Equal(prev, f.second.previous) || !bytes.Equal(bundle, f.second.caBundle) || !bytes.Equal(jwsFile, f.secondS.listJWS) {
		t.Error("the self-check changed what it was given")
	}
}

// A list that the reader accepts only by the way back (its sequence is lower than the held list's and
// it names every key it removes) is not what the builder makes: the verdict says Wayback, and the
// self-check refuses it.
func TestSelfCheckRefusesAListAcceptedByTheWayBack(t *testing.T) {
	f := newIFixture(t)
	removal, err := NewRemoval(f.a.signer)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDraft(Input{
		Sequence: 2, SignedAt: iAt.Add(time.Hour),
		Roots:            []Root{{Label: "B", X509SPKISHA256: f.b.pin}},
		Certificates:     map[string][]byte{"B": f.b.cert.Raw},
		Departures:       []Departure{{X509SPKISHA256: f.a.pin, Leave: LeaveRevoked, Authorisation: removal}},
		LastRecordSHA256: strings.Repeat("ab", 32), Previous: f.firstS.listJSON,
		Earlier: []history.RootList{{Name: "1", Keys: []history.RootKey{{Label: "A", Pin: f.a.pin}, {Label: "B", Pin: f.b.pin}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	set, err := d.Sign([]Signer{f.b.signer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The host holds a list of sequence 5 with the keys A and B: the revoke list of sequence 2 is
	// taken by the way back.
	held, err := MarshalList(ListSpec{
		Sequence: 5, SignedAt: iAt.Add(-time.Hour), LastRecordSHA256: strings.Repeat("cd", 32),
		Roots: []Root{{Label: "A", X509SPKISHA256: f.a.pin}, {Label: "B", X509SPKISHA256: f.b.pin}},
	})
	if err != nil {
		t.Fatal(err)
	}
	other := *d
	other.previous = held
	text := wantSelf(t, other.selfCheck(set.listJWS))
	_ = text
	// Against its own previous list it is accepted.
	if err := d.selfCheck(set.listJWS); err != nil {
		t.Errorf("against its previous list: %v", err)
	}
}

// A Set shares no memory with the Draft it came from.
func TestSetSharesNoMemoryWithTheDraft(t *testing.T) {
	f := newIFixture(t)
	s, d := f.secondS, f.second
	if &s.listJSON[0] == &d.listJSON[0] || &s.caBundle[0] == &d.caBundle[0] {
		t.Error("the set holds the draft's own bytes")
	}
}

// When the self-check refuses, Sign returns ErrSelf and no set. The draft is changed after NewDraft
// (its previous list is the list itself), which the public calls cannot do.
func TestSignReturnsNoSetWhenTheSelfCheckRefuses(t *testing.T) {
	f := newIFixture(t)
	d := *f.second
	d.previous = d.listJSON
	set, err := d.Sign([]Signer{f.b.signer}, nil)
	if set != nil {
		t.Fatal("a set came with the error")
	}
	kindOfSelf(t, err)
}
