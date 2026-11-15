package trustset_test

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/keystore/software"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// This file holds the helpers of the tests of Draft, Sign and Set: a chain of lists made in memory
// with the draft itself, the way a bundle grows. Every key is a software key, no card is touched.

// firstCeremony is the signing time of the first list of a chain; each next list is an hour later.
var firstCeremony = time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)

// link is one list of a chain after it was signed.
type link struct {
	roots  []trustset.Root
	set    *trustset.Set
	draft  *trustset.Draft
	signed time.Time
}

// chain is the lists of one bundle in the order of the history.
type chain struct {
	t     testing.TB
	links []link
}

func newChain(t testing.TB) *chain { return &chain{t: t} }

// next describes the next list of a chain.
type next struct {
	labels  []string // the labels of the roots of the new list
	noPrint bool     // the entries have no OpenPGP fingerprint
	deps    []trustset.Departure
	at      time.Time // zero: an hour after the last list
	change  func(*trustset.Input)
}

// rootsOf returns the entries of the roots with the given labels, as made keys.
func rootsOf(t testing.TB, noPrint bool, labels ...string) []trustset.Root {
	t.Helper()
	out := make([]trustset.Root, 0, len(labels))
	for _, l := range labels {
		out = append(out, newRoot(t, l, true).entry(!noPrint))
	}
	return out
}

// certsOf returns the DER of the current certificate of each label.
func certsOf(t testing.TB, labels ...string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte, len(labels))
	for _, l := range labels {
		out[l] = slices.Clone(newRoot(t, l, true).DER)
	}
	return out
}

// earlier returns the root lists of the chain for Input.Earlier, with names that are hostile on
// purpose: a control character and a backslash, to show that no error prints one.
func (c *chain) earlier() []history.RootList {
	out := make([]history.RootList, 0, len(c.links))
	for i, l := range c.links {
		out = append(out, historyList("trust/\x1b[31m\\u0041-"+string(rune('a'+i%26)), l.roots))
	}
	return out
}

// historyList turns the entries of a list into a root list of the history reader.
func historyList(name string, roots []trustset.Root) history.RootList {
	keys := make([]history.RootKey, len(roots))
	for i, r := range roots {
		keys[i] = history.RootKey{Label: r.Label, Pin: r.X509SPKISHA256, Fingerprint: r.OpenPGPFingerprint}
	}
	return history.RootList{Name: name, Keys: keys}
}

// lastRecord is a made-up digest of the end of the history.
func lastRecord(n int) string { return hexOf(fmt.Sprintf("end of the history before list %d", n)) }

// input is the Input for the next list.
func (c *chain) input(n next) trustset.Input {
	c.t.Helper()
	seq := int64(len(c.links) + 1)
	at := n.at
	if at.IsZero() {
		at = firstCeremony.Add(time.Duration(seq-1) * time.Hour)
	}
	in := trustset.Input{
		Sequence:     seq,
		SignedAt:     at,
		Roots:        rootsOf(c.t, n.noPrint, n.labels...),
		Certificates: certsOf(c.t, n.labels...),
		Departures:   slices.Clone(n.deps),
	}
	in.OpenPGPCertificates = certificatesOfRoots(in.Roots)
	if seq > 1 {
		in.LastRecordSHA256 = lastRecord(int(seq))
		in.Previous = c.links[len(c.links)-1].set.ListJSON()
		in.Earlier = c.earlier()
	}
	if n.change != nil {
		n.change(&in)
	}
	return in
}

// draft builds the draft of the next list.
func (c *chain) draft(n next) (*trustset.Draft, error) {
	c.t.Helper()
	return trustset.NewDraft(c.input(n))
}

// signersFor makes the signers that the draft needs: every label of Required and the first of
// OneOf, each wrapped in a counter. extra and drop adjust the labels.
func signersFor(t testing.TB, d *trustset.Draft, extra []string, drop []string) []*scriptedSigner {
	t.Helper()
	labels := slices.Clone(d.Required())
	if len(d.OneOf()) > 0 {
		labels = append(labels, d.OneOf()[0])
	}
	labels = append(labels, extra...)
	labels = slices.DeleteFunc(labels, func(l string) bool { return slices.Contains(drop, l) })
	out := make([]*scriptedSigner, 0, len(labels))
	for _, l := range labels {
		out = append(out, counting(newRoot(t, l, true).signer(t)))
	}
	return out
}

// asSigners turns counting signers into the list of the interface type that Sign takes.
func asSigners(in []*scriptedSigner) []trustset.Signer {
	out := make([]trustset.Signer, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// calls returns how many times each signer was asked.
func calls(in []*scriptedSigner) []int {
	out := make([]int, len(in))
	for i, s := range in {
		out[i] = s.count()
	}
	return out
}

// zeroCalls fails the test when any signer was asked.
func zeroCalls(t testing.TB, in []*scriptedSigner) {
	t.Helper()
	for i, s := range in {
		if s.count() != 0 {
			t.Fatalf("signer %d (%s) was asked %d times, want 0", i, s.Label(), s.count())
		}
	}
}

// add builds the next list, signs it with the signers it needs and adds it to the chain.
func (c *chain) add(n next) *trustset.Set {
	c.t.Helper()
	d, err := c.draft(n)
	if err != nil {
		c.t.Fatalf("NewDraft for list %d: %v", len(c.links)+1, err)
	}
	set, err := d.Sign(asSigners(signersFor(c.t, d, nil, nil)), nil)
	if err != nil {
		c.t.Fatalf("Sign for list %d: %v", len(c.links)+1, err)
	}
	in := c.input(n)
	c.links = append(c.links, link{roots: sortedRoots(in.Roots), set: set, draft: d, signed: in.SignedAt})
	return set
}

// sortedRoots returns the entries in label order.
func sortedRoots(in []trustset.Root) []trustset.Root {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b trustset.Root) int { return strings.Compare(a.Label, b.Label) })
	return out
}

// last is the newest set of the chain.
func (c *chain) last() *trustset.Set { return c.links[len(c.links)-1].set }

// retire is the departure of a retired key.
func retire(t testing.TB, label string) trustset.Departure {
	return trustset.Departure{X509SPKISHA256: newRoot(t, label, true).Pin, Leave: trustset.LeaveRetired}
}

// revoke is the departure of a revoked key with its stored authorisation.
func revoke(t testing.TB, label string) trustset.Departure {
	r := newRoot(t, label, true)
	return trustset.Departure{X509SPKISHA256: r.Pin, Leave: trustset.LeaveRevoked, Authorisation: r.removal(t)}
}

// revokeLost is the departure of a revoked key whose authorisation is lost.
func revokeLost(t testing.TB, label string) trustset.Departure {
	return trustset.Departure{X509SPKISHA256: newRoot(t, label, true).Pin, Leave: trustset.LeaveRevoked}
}

// verify asks the reader of the page, as a host does, about a set: against the previous list when
// there is one, against the pins of the list when there is none, with the clock at the signing time.
func verify(t testing.TB, set *trustset.Set, previous []byte, at time.Time) rootlist.Verdict {
	t.Helper()
	var trust rootlist.Trust
	var err error
	if previous == nil {
		list, perr := rootlist.ParseList(set.ListJSON())
		if perr != nil {
			t.Fatalf("ParseList: %v", perr)
		}
		trust, err = rootlist.PinTrust(list.Pins())
	} else {
		var held *rootlist.Held
		held, err = rootlist.ParseHeld(previous)
		if err == nil {
			trust = rootlist.HeldTrust(held)
		}
	}
	if err != nil {
		t.Fatalf("the trust: %v", err)
	}
	return rootlist.Verify(rootlist.Signed{JSON: set.ListJSON(), JWS: set.ListJWS()}, trust, at)
}

// mustAccept fails the test unless the reader accepts the set and its CA bundle.
func mustAccept(t testing.TB, set *trustset.Set, previous []byte, at time.Time) *rootlist.List {
	t.Helper()
	v := verify(t, set, previous, at)
	if !v.Accepted || v.Again || v.Wayback {
		t.Fatalf("the reader refuses the set: %+v", v)
	}
	if cv := rootlist.VerifyCABundle(set.CABundle(), v.List); !cv.Accepted {
		t.Fatalf("the reader refuses the CA bundle: %+v", cv)
	}
	return v.List
}

// kidsOf returns the kid of each signature of a root-list.jws, in the order of the file.
func kidsOf(t testing.TB, file []byte) []string {
	t.Helper()
	g, err := jws.ParseGeneral(file, rootlist.ListTyp)
	if err != nil {
		t.Fatalf("ParseGeneral: %v", err)
	}
	out := make([]string, len(g.Signatures))
	for i, s := range g.Signatures {
		out[i] = s.Header.Kid
	}
	return out
}

// wantOnly checks that err wraps want and no other kind of the package, and that its text is
// printable ASCII and short.
func wantOnly(t testing.TB, err, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %v", want)
	}
	all := []error{trustset.ErrParams, trustset.ErrSign, trustset.ErrSigners, trustset.ErrReturns, trustset.ErrSelf}
	if !slices.ContainsFunc(all, func(e error) bool { return errors.Is(e, want) }) {
		t.Fatalf("%v is not a kind of the package", want)
	}
	for _, k := range all {
		if errors.Is(k, want) {
			if !errors.Is(err, k) {
				t.Fatalf("error %q does not wrap %v", err, want)
			}
			continue
		}
		if errors.Is(err, k) {
			t.Fatalf("error %q wraps %v as well as %v", err, k, want)
		}
	}
	if !printable(err.Error()) {
		t.Fatalf("the text of the error is not printable ASCII: %+q", err.Error())
	}
	if len(err.Error()) > 600 {
		t.Fatalf("the text of the error is %d bytes long", len(err.Error()))
	}
}

// bundleCerts returns the DER of each certificate of a CA bundle, in the order of the file.
func bundleCerts(t testing.TB, data []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return out
		}
		out = append(out, block.Bytes)
	}
}

// newRootVariant returns another key that carries the same label as newRoot(label) does: a holder
// who wants the place of a key that left makes a new key, which must not take the old label.
func newRootVariant(t testing.TB, label, variant string) *testRoot {
	t.Helper()
	name := label + "-test-" + variant
	rootsMu.Lock()
	defer rootsMu.Unlock()
	if r, ok := roots[name]; ok {
		return r
	}
	key, err := software.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	r := &testRoot{Label: label, Key: key, Test: true}
	r.DER = rootCertificate(t, key, label, true)
	r.Cert, err = x509.ParseCertificate(r.DER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	r.Pin = jws.Pin(r.Cert)
	r.makePrimary(t)
	roots[name] = r
	return r
}

// previousOf is the bytes of a root-list.json of the given sequence with the given entries: what a
// caller reads from the previous trust set. The list is not signed; NewDraft reads it and nothing
// more.
func previousOf(t testing.TB, sequence int64, at time.Time, entries []trustset.Root) []byte {
	t.Helper()
	spec := trustset.ListSpec{Sequence: sequence, SignedAt: at, Roots: entries}
	if sequence > 1 {
		spec.LastRecordSHA256 = lastRecord(int(sequence))
	}
	data, err := trustset.MarshalList(spec)
	if err != nil {
		t.Fatalf("MarshalList: %v", err)
	}
	return data
}

// refuses fails the test unless NewDraft refuses the input with ErrParams and a text that holds
// want, and returns no draft.
func refuses(t testing.TB, in trustset.Input, want string) {
	t.Helper()
	d, err := trustset.NewDraft(in)
	if d != nil {
		t.Fatalf("a draft came with the error %v", err)
	}
	wantOnly(t, err, trustset.ErrParams)
	if want != "" && !strings.Contains(err.Error(), want) {
		t.Fatalf("the error %q does not hold %q", err, want)
	}
}
