package trustset_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/trustset"
)

// digestOf is the SHA-256 of the bytes in lower-case hexadecimal, computed here and not by the
// package, so the tests below do not repeat what they check.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ofEveryKind returns one signed draft of every kind of list, each from its own chain.
func ofEveryKind(t *testing.T) map[string]*chain {
	t.Helper()
	out := map[string]*chain{}
	build := func(name string, steps []next, last next) {
		c := newChain(t)
		for _, s := range steps {
			c.add(s)
		}
		c.add(last)
		out[name] = c
	}
	ab := next{labels: []string{"A", "B"}}
	abc := next{labels: []string{"A", "B", "C"}}
	build("first", nil, ab)
	build("renewal", []next{ab}, ab)
	build("add", []next{ab}, abc)
	build("retire", []next{ab, abc}, next{labels: []string{"A", "B"}, deps: []trustset.Departure{retire(t, "C")}})
	build("revoke", []next{ab, abc}, next{labels: []string{"B", "C"}, deps: []trustset.Departure{revoke(t, "A")}})
	build("revoke without the authorisation", []next{ab}, next{labels: []string{"B"}, deps: []trustset.Departure{revokeLost(t, "A")}})
	return out
}

// The name of a draft and of its set is the function SetName for the sequence and the SHA-256 of
// root-list.json, for every kind of list: its number, a hyphen and the first eight characters of
// that digest.
func TestTheNameOfADraftAndOfItsSetIsTheNameOfTheList(t *testing.T) {
	for kind, c := range ofEveryKind(t) {
		t.Run(kind, func(t *testing.T) {
			l := c.links[len(c.links)-1]
			digest := digestOf(l.draft.ListJSON())
			want, err := trustset.SetName(l.draft.Sequence(), digest)
			if err != nil {
				t.Fatal(err)
			}
			if got := l.draft.SetName(); got != want {
				t.Errorf("Draft.SetName = %q, want %q", got, want)
			}
			if got := l.set.Name(); got != want {
				t.Errorf("Set.Name = %q, want %q", got, want)
			}
			// The shape: the number in plain digits, a hyphen, eight characters of the digest.
			wantText := strconv.FormatInt(l.draft.Sequence(), 10) + "-" + digest[:8]
			if want != wantText {
				t.Errorf("SetName = %q, want %q", want, wantText)
			}
			if !bundleSpelling.MatchString(want) {
				t.Errorf("%q is not the spelling that internal/bundle reads", want)
			}
			if err := fsx.CheckName(want); err != nil {
				t.Errorf("fsx.CheckName(%q): %v", want, err)
			}
			// The digest is the one the draft names for the list, and the one of the set's file.
			if digest != l.draft.ListSHA256() || digest != digestOf(l.set.ListJSON()) {
				t.Error("the digest of the list differs between the draft and the set")
			}
		})
	}
}

// The name is the name of root-list.json and of nothing else: not the CA bundle, not the signature
// file, and not the signers. The same draft signed twice, and signed by the other key of a one-of
// group, gives one name; the bytes of the signature file differ, the name does not.
func TestTheNameDependsOnTheListAndOnNothingElse(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	d, err := c.draft(next{labels: []string{"A", "B"}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	other := []trustset.Signer{counting(newRoot(t, "B", true).signer(t))}
	second, err := d.Sign(other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.ListJWS(), second.ListJWS()) {
		t.Fatal("the two sets have one signature file, so the test shows nothing")
	}
	if first.Name() != second.Name() || first.Name() != d.SetName() {
		t.Errorf("names: %q, %q, %q", first.Name(), second.Name(), d.SetName())
	}
	// The name is built from the list: not from the CA bundle, and not from the signature file.
	for _, other := range [][]byte{d.CABundle(), first.ListJWS(), second.ListJWS(), []byte("x")} {
		if digestOf(other)[:8] == digestOf(d.ListJSON())[:8] {
			t.Fatal("the files have one digest prefix, so the test shows nothing")
		}
		if strings.HasSuffix(d.SetName(), digestOf(other)[:8]) {
			t.Errorf("the name %q is the digest of another file", d.SetName())
		}
	}
	// Another list of the same number is another name.
	e, err := c.draft(next{labels: []string{"A", "B", "C"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.Sequence() != d.Sequence() || e.SetName() == d.SetName() {
		t.Errorf("two lists of number %d are named %q and %q", d.Sequence(), d.SetName(), e.SetName())
	}
	// The same list again is the same name.
	again, err := c.draft(next{labels: []string{"A", "B"}})
	if err != nil {
		t.Fatal(err)
	}
	if again.SetName() != d.SetName() {
		t.Errorf("the same list is named %q and %q", d.SetName(), again.SetName())
	}
}

// A nil and a zero value give the empty text, and no call panics.
func TestNameOfANilAndOfAZeroValue(t *testing.T) {
	var nd *trustset.Draft
	var ns *trustset.Set
	for name, got := range map[string]string{
		"nil draft":  nd.SetName(),
		"zero draft": (&trustset.Draft{}).SetName(),
		"nil set":    ns.Name(),
		"zero set":   (&trustset.Set{}).Name(),
	} {
		if got != "" {
			t.Errorf("%s: name %q, want the empty text", name, got)
		}
	}
}

// The name that a Set gives is the folder that bundle.Open reads: written under trust/ with Name,
// the newest set is that folder, for each list of a chain.
func TestTheNameOfASetIsTheFolderTheBundleReads(t *testing.T) {
	c := threeSets(t)
	dir := filepath.Join(t.TempDir(), "acme")
	if _, err := bundle.Create(dir, bundle.StarterOptions{TestRoot: true}); err != nil {
		t.Fatal(err)
	}
	w, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if err := w.Mkdir(bundle.TrustDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i, l := range c.links {
		name := l.set.Name()
		if name != l.draft.SetName() {
			t.Fatalf("list %d: Set.Name %q, Draft.SetName %q", i+1, name, l.draft.SetName())
		}
		if err := l.set.Write(w, bundle.TrustDir+"/"+name); err != nil {
			t.Fatalf("Write %d: %v", i+1, err)
		}
		b, err := bundle.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		_, set, err := b.Roots()
		_ = b.Close()
		if err != nil {
			t.Fatalf("Roots after set %d: %v", i+1, err)
		}
		if set.Name != name || set.Number != int64(i+1) {
			t.Errorf("the newest set is %+v, want %s", set, name)
		}
	}
}

// Both methods are safe for several goroutines and always give one answer.
func TestTheNameIsStable(t *testing.T) {
	c := newChain(t)
	set := c.add(next{labels: []string{"A", "B"}})
	d := c.links[0].draft
	want := d.SetName()
	for i := 0; i < 50; i++ {
		if d.SetName() != want || set.Name() != want {
			t.Fatal("the name changed between two calls")
		}
	}
}
