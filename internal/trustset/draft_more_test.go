package trustset_test

import (
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/trustset"
)

// The bounds of the input are checked before the first entry is read: 27 roots with a bad label
// each are refused for their number and not for the first label.
func TestBoundsAreCheckedBeforeTheEntriesAreRead(t *testing.T) {
	c := newChain(t)
	in := c.input(next{labels: []string{"A", "B"}})
	for i := 0; i < 25; i++ { // 27 roots in all: one more than the list may hold
		in.Roots = append(in.Roots, trustset.Root{Label: "bad label", X509SPKISHA256: "x"})
	}
	refuses(t, in, "a list holds at most 26 root keys and 27 root keys are given")
	in = c.input(next{labels: []string{"A", "B"}})
	in.Certificates = map[string][]byte{}
	for i := 0; i < 27; i++ {
		in.Certificates[strings.Repeat("a", i+1)] = nil
	}
	refuses(t, in, "a list holds at most 26 root keys and 27 certificates are given")
	// 26 roots and 26 certificates are within the bound.
	labels := make([]string, 26)
	for i := range labels {
		labels[i] = string(rune('A' + i))
	}
	if _, err := trustset.NewDraft(newChain(t).input(next{labels: labels})); err != nil {
		t.Errorf("26 roots: %v", err)
	}
}

// Every stored authorisation is judged, not the first one only.
func TestEveryStoredAuthorisationIsJudged(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B", "C"}})
	a, b := revoke(t, "A"), revoke(t, "B")
	wrongA := a
	wrongA.Authorisation = b.Authorisation // B's authorisation under A's pin
	wrongB := b
	wrongB.Authorisation = a.Authorisation
	refuses(t, c.input(next{labels: []string{"C"}, deps: []trustset.Departure{wrongA, b}}), "stored authorisation of root key A")
	refuses(t, c.input(next{labels: []string{"C"}, deps: []trustset.Departure{a, wrongB}}), "stored authorisation of root key B")
	refuses(t, c.input(next{labels: []string{"C"}, deps: []trustset.Departure{wrongB, a}}), "stored authorisation of root key B")
	if _, err := c.draft(next{labels: []string{"C"}, deps: []trustset.Departure{a, b}}); err != nil {
		t.Errorf("both right: %v", err)
	}
}

// A previous list whose roots are not in label order (the reader does not enforce the order): the
// labels that the draft reports are in label order whatever the order of the list it replaces.
func TestPreviousListInAnotherOrder(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B", "C"}})
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(c.last().ListJSON(), &doc); err != nil {
		t.Fatal(err)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(doc["roots"], &entries); err != nil {
		t.Fatal(err)
	}
	slices.Reverse(entries)
	doc["roots"], _ = json.Marshal(entries)
	reversed, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	in := c.input(next{labels: []string{"C"}, deps: []trustset.Departure{revokeLost(t, "B"), revokeLost(t, "A")}})
	in.Previous = reversed
	d, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatalf("a previous list in another order: %v", err)
	}
	if !slices.Equal(d.Unnamed(), []string{"A", "B"}) || !slices.Equal(d.Required(), []string{"A", "B", "C"}) {
		t.Errorf("Unnamed %v, Required %v", d.Unnamed(), d.Required())
	}
	set, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(set.Signers(), []string{"A", "B", "C"}) {
		t.Errorf("Signers %v", set.Signers())
	}
}

// The most departures: 25 keys of a list of 26 retire, and every one of the 26 signs. A 26th
// departure is for a key that does not leave, and that is what is told.
func TestTwentyFiveKeysRetireAtOnce(t *testing.T) {
	labels := make([]string, 26)
	for i := range labels {
		labels[i] = string(rune('A' + i))
	}
	c := newChain(t)
	c.add(next{labels: labels})
	var deps []trustset.Departure
	for _, l := range labels[1:] {
		deps = append(deps, retire(t, l))
	}
	d, err := c.draft(next{labels: labels[:1], deps: deps})
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind() != trustset.KindRetire || !slices.Equal(d.Required(), labels) {
		t.Errorf("kind %v, Required %v", d.Kind(), d.Required())
	}
	set, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	mustAccept(t, set, c.last().ListJSON(), firstCeremony.Add(time.Hour))
	// A 26th departure, for the key that stays.
	deps = append(deps, retire(t, "A"))
	refuses(t, c.input(next{labels: labels[:1], deps: deps}), "not removed")
	deps = append(deps, retire(t, "Z"))
	refuses(t, c.input(next{labels: labels[:1], deps: deps}), "at most 26 departures")
}

// An authorisation of exactly MaxBytes is judged by the reader of the page, one byte more is over the
// limit.
func TestAuthorisationAtTheLimit(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	for _, tc := range []struct {
		n    int
		want string
	}{{trustset.MaxBytes - 1, "stored authorisation"}, {trustset.MaxBytes, "stored authorisation"}, {trustset.MaxBytes + 1, "longer than"}} {
		dep := trustset.Departure{X509SPKISHA256: newRoot(t, "A", true).Pin, Leave: trustset.LeaveRevoked, Authorisation: strings.Repeat("a", tc.n)}
		refuses(t, c.input(next{labels: []string{"B"}, deps: []trustset.Departure{dep}}), tc.want)
	}
}

// Signers that share one buffer for what they return: the file holds each signature as it was
// returned, not the bytes that a later signer wrote over it.
func TestSignersThatShareTheirOutputBuffer(t *testing.T) {
	c, d := addDraft(t)
	var mu sync.Mutex
	shared := make([]byte, 96)
	mk := func(l string) *scriptedSigner {
		s := counting(newRoot(t, l, true).signer(t))
		inner := s.inner
		s.sign = func(in []byte) ([]byte, error) {
			sig, err := inner.SignES384(in)
			mu.Lock()
			copy(shared, sig)
			mu.Unlock()
			return shared, err
		}
		return s
	}
	set, err := d.Sign([]trustset.Signer{mk("A"), mk("B"), mk("C")}, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mustAccept(t, set, c.last().ListJSON(), firstCeremony.Add(time.Hour))
}
