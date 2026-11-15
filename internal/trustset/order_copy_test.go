package trustset_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/trustset"
)

// This file holds the tests of the order of the checks of NewDraft (a key that came back is told
// before a label that is reused), of the copy of the previous list, and of the kinds of error that
// the comments of errors.go name.

// leftTwice is a bundle of three lists: A, B and C; then A and B (C retired); then B (A retired).
// The key C and the key A both left, and the label C was held by a key that is not A.
func leftTwice(t *testing.T, noPrint bool) *chain {
	t.Helper()
	return chainOf(t, noPrint,
		next{labels: []string{"A", "B", "C"}},
		next{labels: []string{"A", "B"}, deps: []trustset.Departure{retire(t, "C")}},
		next{labels: []string{"B"}, deps: []trustset.Departure{retire(t, "A")}})
}

// putUnderLabel gives the entry with the label the pin, the fingerprint and the certificate of a key.
func putUnderLabel(label string, pin, print string, der []byte) func(*trustset.Input) {
	return func(in *trustset.Input) {
		for i := range in.Roots {
			if in.Roots[i].Label == label {
				in.Roots[i].X509SPKISHA256 = pin
				in.Roots[i].OpenPGPFingerprint = print
			}
		}
		in.Certificates[label] = der
	}
}

// A text that tells a return does not tell a reused label as well: the reason is one.
func noLabelReuseText(t *testing.T, err error) {
	t.Helper()
	if strings.Contains(err.Error(), "was held by another root key") || strings.Contains(err.Error(), "never reused") {
		t.Errorf("a return is told as a reused label: %v", err)
	}
}

// A key that left, under the label of another key that left, is a return: by its fingerprint, by its
// pin and by both.
func TestAReturningKeyUnderAnOldLabelIsToldAsAReturnInEveryWay(t *testing.T) {
	a := newRoot(t, "A", true)
	t.Run("by its pin", func(t *testing.T) {
		c := leftTwice(t, true)
		d, err := c.draft(next{labels: []string{"B", "C"}, noPrint: true, change: putUnderLabel("C", a.Pin, "", a.DER)})
		if d != nil {
			t.Fatal("a draft came with the error")
		}
		wantReturn(t, err, []string{"C"}, "by its pin")
		noLabelReuseText(t, err)
	})
	t.Run("by its fingerprint, under a new pin", func(t *testing.T) {
		c := leftTwice(t, false)
		fresh := newRootVariant(t, "C", "fresh")
		d, err := c.draft(next{labels: []string{"B", "C"}, change: putUnderLabel("C", fresh.Pin, a.Print, fresh.DER)})
		if d != nil {
			t.Fatal("a draft came with the error")
		}
		wantReturn(t, err, []string{"C"}, "by its fingerprint")
		noLabelReuseText(t, err)
	})
	t.Run("by its pin and by its fingerprint", func(t *testing.T) {
		c := leftTwice(t, false)
		d, err := c.draft(next{labels: []string{"B", "C"}, change: putUnderLabel("C", a.Pin, a.Print, a.DER)})
		if d != nil {
			t.Fatal("a draft came with the error")
		}
		wantReturn(t, err, []string{"C"}, "by its pin and by its fingerprint")
		noLabelReuseText(t, err)
	})
	t.Run("a key that was revoked", func(t *testing.T) {
		c := chainOf(t, true,
			next{labels: []string{"A", "B", "C"}},
			next{labels: []string{"A", "B"}, deps: []trustset.Departure{retire(t, "C")}},
			next{labels: []string{"B"}, deps: []trustset.Departure{revoke(t, "A")}})
		_, err := c.draft(next{labels: []string{"B", "C"}, noPrint: true, change: putUnderLabel("C", a.Pin, "", a.DER)})
		wantReturn(t, err, []string{"C"}, "by its pin")
		noLabelReuseText(t, err)
	})
	t.Run("the key under its own old label is the same answer", func(t *testing.T) {
		c := leftTwice(t, true)
		_, err := c.draft(next{labels: []string{"A", "B"}, noPrint: true})
		wantReturn(t, err, []string{"A"}, "by its pin")
	})
}

// A list that brings back one key and gives a new key a label of another key is told as a return:
// the check of the returns runs first, so the answer is root-returns for the key that came back.
func TestAReturnAndAReusedLabelInOneListAreToldAsAReturn(t *testing.T) {
	c := leftTwice(t, true)
	fresh := newRootVariant(t, "C", "fresh")
	_, err := c.draft(next{labels: []string{"A", "B", "C"}, noPrint: true, change: putUnderLabel("C", fresh.Pin, "", fresh.DER)})
	wantReturn(t, err, []string{"A"}, "by its pin")
	noLabelReuseText(t, err)
	if strings.Contains(err.Error(), "root key C comes back") {
		t.Errorf("the new key is told as a return: %v", err)
	}
}

// The controls of the order. A new key under an old label of another key, and no key that came back,
// is still a reused label (ErrParams). A list that is not one of the five kinds is told as that, before a
// return and before a reused label.
func TestTheOrderOfTheChecksOfReturnsLabelsAndShape(t *testing.T) {
	t.Run("a new key under an old label is a reused label", func(t *testing.T) {
		c := leftTwice(t, true)
		fresh := newRootVariant(t, "C", "fresh")
		d, err := c.draft(next{labels: []string{"B", "C"}, noPrint: true, change: putUnderLabel("C", fresh.Pin, "", fresh.DER)})
		if d != nil {
			t.Fatal("a draft came with the error")
		}
		wantOnly(t, err, trustset.ErrParams)
		if !strings.Contains(err.Error(), "label C was held by another root key") {
			t.Errorf("the reason is not a reused label: %v", err)
		}
	})
	t.Run("an added key and a removed key, with a return and a reused label, is told as the shape", func(t *testing.T) {
		c := leftTwice(t, true)
		a := newRoot(t, "A", true)
		// The list {B} gives way to a list that drops B and holds the pin of A under the label C.
		d, err := c.draft(next{labels: []string{"C"}, noPrint: true, deps: []trustset.Departure{retire(t, "B")}, change: putUnderLabel("C", a.Pin, "", a.DER)})
		if d != nil {
			t.Fatal("a draft came with the error")
		}
		wantOnly(t, err, trustset.ErrParams)
		if errors.Is(err, trustset.ErrReturns) {
			t.Error("told as a return")
		}
		if strings.Contains(err.Error(), "was held by another root key") || strings.Contains(err.Error(), "comes back") {
			t.Errorf("the shape of the change is not told first: %v", err)
		}
	})
	t.Run("a kept key under its label is neither", func(t *testing.T) {
		c := leftTwice(t, true)
		if _, err := c.draft(next{labels: []string{"B"}, noPrint: true}); err != nil {
			t.Errorf("a renewal: %v", err)
		}
	})
}

// NewDraft reads one copy of Previous, made first, and the draft holds that copy: whatever the
// caller does to those bytes after the call changes neither the draft nor its signature.
func TestNewDraftKeepsTheCopyOfPreviousThatItChecked(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	in := c.input(next{labels: []string{"A", "B"}})
	original := bytes.Clone(in.Previous)
	d, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	// The caller wipes every byte of Previous after the call.
	for i := range in.Previous {
		in.Previous[i] = 0xff
	}
	set, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatalf("Sign after Previous was wiped: %v", err)
	}
	mustAccept(t, set, original, firstCeremony.Add(time.Hour))
	// A draft made after the wipe reads the wiped bytes and is refused: the draft above did not.
	refuses(t, in, "")
}

// The caller's Input is left as it was: the same bytes at the same place, after a draft and after a
// refusal.
func TestNewDraftLeavesPreviousOfTheCallerAlone(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	for _, n := range []struct {
		name string
		next next
		ok   bool
	}{
		{"a draft", next{labels: []string{"A", "B"}}, true},
		{"a refusal", next{labels: []string{"A", "B"}, change: func(in *trustset.Input) { in.Sequence = 9 }}, false},
		{"a time before the previous list", next{labels: []string{"A", "B"}, at: firstCeremony.Add(-time.Hour)}, false},
	} {
		in := c.input(n.next)
		before := bytes.Clone(in.Previous)
		head := &in.Previous[0]
		length := len(in.Previous)
		_, err := trustset.NewDraft(in)
		if (err == nil) != n.ok {
			t.Fatalf("%s: %v", n.name, err)
		}
		if !bytes.Equal(in.Previous, before) || &in.Previous[0] != head || len(in.Previous) != length {
			t.Errorf("%s: the Previous of the caller changed", n.name)
		}
	}
}

// Two drafts from one input are independent of each other and of the input: the second is made from
// bytes that the caller changed in between, and the first is not touched.
func TestTwoDraftsFromOnePreviousAreIndependent(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	in := c.input(next{labels: []string{"A", "B"}})
	original := bytes.Clone(in.Previous)
	first, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Previous[len(in.Previous)/2] ^= 0x01
	if second, err := trustset.NewDraft(in); err == nil || second != nil {
		t.Fatalf("a draft from a changed Previous: %v", err)
	}
	in.Previous = original
	third, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.ListJSON(), third.ListJSON()) || first.SetName() != third.SetName() {
		t.Error("two drafts of one input differ")
	}
	set, err := first.Sign(asSigners(signersFor(t, first, nil, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	mustAccept(t, set, original, firstCeremony.Add(time.Hour))
}

// A Previous that is a part of a larger buffer: the bytes after its end are not a part of the copy,
// and the bytes of the buffer that the caller changes after the call change nothing.
func TestAPreviousThatIsAPartOfALargerBuffer(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	in := c.input(next{labels: []string{"A", "B"}})
	original := bytes.Clone(in.Previous)
	buf := append(bytes.Clone(in.Previous), []byte(" trailing bytes that the list does not hold")...)
	in.Previous = buf[:len(original):len(buf)]
	d, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := range buf {
		buf[i] = 'x'
	}
	set, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mustAccept(t, set, original, firstCeremony.Add(time.Hour))
}

// A first list has no previous list: nil is what it takes, and nil stays what the draft holds (the
// first list signs and the reader accepts it with no held list).
func TestAFirstListKeepsNoPrevious(t *testing.T) {
	c := newChain(t)
	in := c.input(next{labels: []string{"A", "B"}})
	if in.Previous != nil {
		t.Fatal("the first input has a Previous")
	}
	d, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	set, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	mustAccept(t, set, nil, firstCeremony)
	in.Previous = []byte{}
	refuses(t, in, "")
}

// The kinds of error as the comments of errors.go give them: a nil or an empty draft, set or writer is
// ErrParams; a nil signer, or a signer with no usable certificate, is ErrSigners and not ErrParams;
// a signer that fails and a function after that fails are ErrSign. The kind that a set the reader
// refuses is given is ErrSelf and is tested in the self-check.
func TestTheKindsOfErrorsAsTheCommentsSayThem(t *testing.T) {
	c := newChain(t)
	set := c.add(next{labels: []string{"A", "B"}})
	d, err := c.draft(next{labels: []string{"A", "B"}})
	if err != nil {
		t.Fatal(err)
	}
	w, _ := setDir(t)
	var nilDraft *trustset.Draft
	var nilSet *trustset.Set
	if _, err := nilDraft.Sign(nil, nil); err == nil {
		t.Error("a nil draft signed")
	} else {
		wantOnly(t, err, trustset.ErrParams)
	}
	wantOnly(t, nilSet.Write(w, "trust/1-00000000"), trustset.ErrParams)
	wantOnly(t, set.Write(nil, "trust/1-00000000"), trustset.ErrParams)

	good := signersFor(t, d, nil, nil)
	wantSigners := func(name string, signers []trustset.Signer) {
		t.Helper()
		got, err := d.Sign(signers, nil)
		if got != nil {
			t.Errorf("%s: a set came with the error", name)
		}
		wantOnly(t, err, trustset.ErrSigners)
	}
	wantSigners("a nil signer", []trustset.Signer{nil})
	noCert := &scriptedSigner{inner: good[0], cert: func() *x509.Certificate { return nil }}
	wantSigners("a signer with no certificate", []trustset.Signer{noCert})
	if good[0].count() != 0 {
		t.Error("a key was asked before the signers were judged")
	}

	failing := &scriptedSigner{inner: good[0], sign: func([]byte) ([]byte, error) { return nil, errors.New("the card is gone") }}
	_, err = d.Sign([]trustset.Signer{failing}, nil)
	wantOnly(t, err, trustset.ErrSign)
	_, err = d.Sign([]trustset.Signer{good[0]}, func(trustset.Signed) error { return errors.New("no") })
	wantOnly(t, err, trustset.ErrSign)
	_, err = d.Sign([]trustset.Signer{good[0]}, func(trustset.Signed) error { panic("no") })
	wantOnly(t, err, trustset.ErrSign)
}

// A name taken from a set is the folder a Write makes in a writer that sits on a bundle: the folder
// exists and holds the three files, under the name the draft told before the signature.
func TestTheDraftTellsTheFolderBeforeTheSignature(t *testing.T) {
	c := newChain(t)
	d, err := c.draft(next{labels: []string{"A", "B"}})
	if err != nil {
		t.Fatal(err)
	}
	told := d.SetName()
	set, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	w, dir := setDir(t)
	if err := set.Write(w, "trust/"+told); err != nil {
		t.Fatal(err)
	}
	if set.Name() != told {
		t.Errorf("the set is named %q, the draft told %q", set.Name(), told)
	}
	ents, err := os.ReadDir(filepath.Join(dir, "trust", told))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	// The list pins OpenPGP primaries, so the folder holds the keyring file as well.
	want := append(trustset.FileNames(), trustset.KeyringFile)
	if len(names) != len(want) {
		t.Fatalf("the folder holds %v, want %v", names, want)
	}
	for _, n := range want {
		if _, err := os.Stat(filepath.Join(dir, "trust", told, n)); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}
