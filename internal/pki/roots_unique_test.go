package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/asn1"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// The roots of a bundle against each other. The contract keeps a request from taking the key or the name of "any root key of the bundle",
// so a name is one root's and a key is one root's: a list that holds one name with two keys, or one key under two names, would make the rule
// about a request mean two things. The package therefore refuses such a list with ErrParams, in IntermediateTBS and in SignIntermediate,
// before any check of the request and before the signer is touched. A root listed twice with the same bytes of its subject and the same
// key is one root: it passes, and counts once.

const (
	sameKeyWords  = "same key"
	sameNameWords = "same name"
)

// rootsRefusedBothWays gives the list to IntermediateTBS and to SignIntermediate and asks for the same refusal from both: ErrParams, no check,
// no body, no signature, the signer not called, and the list unchanged.
func rootsRefusedBothWays(t *testing.T, b rootSet, csr *testCSR, roots []pki.RootRef, words string) {
	t.Helper()
	before := snapshotRoots(roots)
	p := b.a.interParams(csr)
	p.Roots = roots
	tbs, err := pki.IntermediateTBS(p)
	refused(t, err, pki.ErrParams)
	if pki.CheckOf(err) != pki.CheckNone {
		t.Errorf("check %q for a parameter", pki.CheckOf(err))
	}
	if tbs != nil {
		t.Error("a body came with the error")
	}
	said := false
	for _, w := range strings.Split(words, "|") {
		said = said || strings.Contains(err.Error(), w)
	}
	if !said {
		t.Errorf("the text does not say %q: %v", words, err)
	}
	honest, herr := pki.IntermediateTBS(b.params(t, csr))
	if herr != nil {
		t.Fatal(herr)
	}
	s := &opaqueSigner{key: b.a.key}
	sig, serr := pki.SignIntermediate(nil, s, p, honest)
	refused(t, serr, pki.ErrParams)
	if sig != nil || s.calls != 0 || pki.CheckOf(serr) != pki.CheckNone || serr.Error() != err.Error() {
		t.Errorf("SignIntermediate: signature %v, %d calls, check %q, %v", sig != nil, s.calls, pki.CheckOf(serr), serr)
	}
	if !sameRoots(before, roots) {
		t.Error("the list was changed by the call")
	}
}

func TestTwoRootsOfOneNameOrOneKeyAreRefused(t *testing.T) {
	b := newBundle(t)
	csr := goodRequest(t)
	nameB := b.b.parsed.Subject.CommonName // "Beta Root B (TEST ONLY)"
	other := newKey(t)
	third := newKey(t)
	capsB := buildRoot(t, func(p *pki.RootParams) { p.Name = "BETA"; p.Label = "B" }) // the name of B in capitals, a key of its own
	if same, err := pki.SameName(capsB.parsed.RawSubject, b.b.parsed.RawSubject); err != nil || !same || bytes.Equal(capsB.parsed.RawSubject, b.b.parsed.RawSubject) {
		t.Fatalf("the name BETA is not another spelling of the name of B: %v, %v", same, err)
	}
	nameD := cnName(tUTF8, "Delta Root D (TEST ONLY)")
	rows := []struct {
		name  string
		extra []pki.RootRef
		words string
	}{
		// One key under two names.
		// The name of B is B's, and the key of C is C's: the entry clashes twice, and which clash is told depends on the place of the entry.
		{"the name of B with the key of C", []pki.RootRef{{Subject: b.b.parsed.RawSubject, Key: &b.c.key.PublicKey}}, sameKeyWords + "|" + sameNameWords},
		{"a new name with the key of C", []pki.RootRef{{Subject: nameD, Key: &b.c.key.PublicKey}}, sameKeyWords},
		{"a new name with the key of the issuer", []pki.RootRef{{Subject: nameD, Key: &b.a.key.PublicKey}}, sameKeyWords},
		{"the name of B in capitals with the key of B", []pki.RootRef{{Subject: capsB.parsed.RawSubject, Key: &b.b.key.PublicKey}}, sameKeyWords},
		{"the name of B as a PrintableString with the key of B", []pki.RootRef{{Subject: cnName(tPrintable, nameB), Key: &b.b.key.PublicKey}}, sameKeyWords},
		{"the name of B in lower case with the key of B", []pki.RootRef{{Subject: cnName(tUTF8, strings.ToLower(nameB)), Key: &b.b.key.PublicKey}}, sameKeyWords},
		{"two new names with one new key", []pki.RootRef{{Subject: nameD, Key: &other.PublicKey}, {Subject: cnName(tUTF8, "Echo Root E (TEST ONLY)"), Key: &other.PublicKey}}, sameKeyWords},
		// One name with two keys.
		{"the name of B with a new key", []pki.RootRef{{Subject: b.b.parsed.RawSubject, Key: &other.PublicKey}}, sameNameWords},
		{"the name of the issuer with a new key", []pki.RootRef{{Subject: b.a.parsed.RawSubject, Key: &other.PublicKey}}, sameNameWords},
		{"the name of B in capitals with a key of its own", []pki.RootRef{capsB.ref()}, sameNameWords},
		{"the name of B as a PrintableString with a new key", []pki.RootRef{{Subject: cnName(tPrintable, nameB), Key: &other.PublicKey}}, sameNameWords},
		{"the name of B as a PrintableString in capitals with a new key", []pki.RootRef{{Subject: cnName(tPrintable, strings.ToUpper(nameB)), Key: &other.PublicKey}}, sameNameWords},
		{"a new name with two keys", []pki.RootRef{{Subject: nameD, Key: &other.PublicKey}, {Subject: nameD, Key: &third.PublicKey}}, sameNameWords},
		{"a new name with two keys, one name in capitals", []pki.RootRef{{Subject: nameD, Key: &other.PublicKey}, {Subject: cnName(tUTF8, strings.ToUpper("Delta Root D (TEST ONLY)")), Key: &third.PublicKey}}, sameNameWords},
		// A root that is listed again and then clashes.
		{"B again, then the name of B with a new key", []pki.RootRef{b.b.ref(), {Subject: b.b.parsed.RawSubject, Key: &other.PublicKey}}, sameNameWords},
		{"B again, then the key of B under a new name", []pki.RootRef{b.b.ref(), {Subject: nameD, Key: &b.b.key.PublicKey}}, sameKeyWords},
		{"a new root twice and then its name with another key", []pki.RootRef{{Subject: nameD, Key: &other.PublicKey}, {Subject: nameD, Key: &other.PublicKey}, {Subject: nameD, Key: &third.PublicKey}}, sameNameWords},
	}
	places := []struct {
		name string
		put  func(base, extra []pki.RootRef) []pki.RootRef
	}{
		{"after the roots", func(base, extra []pki.RootRef) []pki.RootRef {
			return append(append([]pki.RootRef(nil), base...), extra...)
		}},
		{"before the roots", func(base, extra []pki.RootRef) []pki.RootRef {
			return append(append([]pki.RootRef(nil), extra...), base...)
		}},
		{"between the issuer and the others", func(base, extra []pki.RootRef) []pki.RootRef {
			return append(append(append([]pki.RootRef(nil), base[:1]...), extra...), base[1:]...)
		}},
	}
	base := []pki.RootRef{b.a.ref(), b.b.ref(), b.c.ref()}
	for _, r := range rows {
		for _, pl := range places {
			t.Run(r.name+", "+pl.name, func(t *testing.T) {
				rootsRefusedBothWays(t, b, csr, pl.put(base, r.extra), r.words)
			})
		}
	}
	t.Run("the list that holds only the clash and the issuer", func(t *testing.T) {
		rootsRefusedBothWays(t, b, csr, []pki.RootRef{b.a.ref(), {Subject: b.a.parsed.RawSubject, Key: &other.PublicKey}}, sameNameWords)
		rootsRefusedBothWays(t, b, csr, []pki.RootRef{b.a.ref(), {Subject: nameD, Key: &b.a.key.PublicKey}}, sameKeyWords)
	})
	t.Run("a list with a clash is refused before the request is read", func(t *testing.T) {
		bad := copyCSR(csr)
		bad.Version = []byte{0x02, 0x01, 0x07}
		p := b.a.interParams(bad)
		p.Roots = append(append([]pki.RootRef(nil), base...), pki.RootRef{Subject: b.b.parsed.RawSubject, Key: &other.PublicKey})
		_, err := pki.IntermediateTBS(p)
		refused(t, err, pki.ErrParams)
		if pki.CheckOf(err) != pki.CheckNone {
			t.Errorf("check %q: %v", pki.CheckOf(err), err)
		}
	})
	t.Run("a clash that is no name is the fault of the name first", func(t *testing.T) {
		// A root whose subject is not a name is refused for that, whatever its key is.
		p := b.a.interParams(csr)
		p.Roots = append(append([]pki.RootRef(nil), base...), pki.RootRef{Subject: []byte{0x04, 0x01, 0x00}, Key: &b.b.key.PublicKey})
		_, err := pki.IntermediateTBS(p)
		refused(t, err, pki.ErrParams)
		if !strings.Contains(err.Error(), "not a name") {
			t.Errorf("the text does not say that the subject is not a name: %v", err)
		}
	})
}

// A root that is listed twice with the same subject bytes and the same key is one root: the list is accepted and the body is the body of
// the list without it; a request for it is still refused as a request for a root.
func TestARootListedTwiceIsOneRoot(t *testing.T) {
	b := newBundle(t)
	csr := goodRequest(t)
	baseline, err := pki.IntermediateTBS(b.params(t, csr))
	if err != nil {
		t.Fatal(err)
	}
	copyOf := func(r *testRoot) pki.RootRef {
		return pki.RootRef{Subject: append([]byte(nil), r.parsed.RawSubject...), Key: ownKey(t, &r.key.PublicKey)}
	}
	rows := []struct {
		name  string
		roots []pki.RootRef
	}{
		{"B again", []pki.RootRef{b.a.ref(), b.b.ref(), b.c.ref(), b.b.ref()}},
		{"B again, next to B", []pki.RootRef{b.a.ref(), b.b.ref(), b.b.ref(), b.c.ref()}},
		{"B again, before B", []pki.RootRef{b.b.ref(), b.a.ref(), b.b.ref(), b.c.ref()}},
		{"the issuer again", []pki.RootRef{b.a.ref(), b.b.ref(), b.c.ref(), b.a.ref()}},
		{"the issuer three times", []pki.RootRef{b.a.ref(), b.a.ref(), b.a.ref(), b.b.ref(), b.c.ref()}},
		{"B and C again", []pki.RootRef{b.a.ref(), b.b.ref(), b.c.ref(), b.c.ref(), b.b.ref()}},
		{"B again as another copy of the same bytes and the same key", []pki.RootRef{b.a.ref(), b.b.ref(), b.c.ref(), copyOf(b.b)}},
		{"the issuer again as another copy", []pki.RootRef{b.a.ref(), b.b.ref(), b.c.ref(), copyOf(b.a)}},
		{"two lists joined, each with the issuer", append([]pki.RootRef{b.a.ref(), b.b.ref()}, b.a.ref(), b.c.ref())},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p := b.a.interParams(csr)
			p.Roots = r.roots
			tbs, err := pki.IntermediateTBS(p)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !bytes.Equal(tbs, baseline) {
				t.Error("the body is not the body of the list without the repeated root")
			}
			sig, err := pki.SignIntermediate(nil, b.a.key, p, tbs)
			if err != nil {
				t.Fatalf("SignIntermediate: %v", err)
			}
			if _, err := pki.Assemble(tbs, sig, &b.a.key.PublicKey); err != nil {
				t.Fatal(err)
			}
			// It counts once: a request for the key of the repeated root, or for its name, is still the refusal of a request for a root.
			for _, name := range []string{"key of B", "name of B", "key of C", "name of C"} {
				c := copyCSR(csr)
				switch name {
				case "key of B":
					c.Key, c.RawSubjectPublicKeyInfo = b.b.key, nil
				case "key of C":
					c.Key, c.RawSubjectPublicKeyInfo = b.c.key, nil
				case "name of B":
					c.RawSubject = b.b.parsed.RawSubject
				case "name of C":
					c.RawSubject = b.c.parsed.RawSubject
				}
				p.CSR = c.DER()
				if _, err := pki.IntermediateTBS(p); pki.CheckOf(err) != pki.CheckPolicy || !strings.Contains(err.Error(), "a root of the bundle") {
					t.Errorf("a request for the %s: %v", name, err)
				}
			}
		})
	}
	// The same subject bytes and the same key, and one root that only looks the same: the bytes differ, and then the roots are two names of
	// one key (refused) and not one root listed twice.
	t.Run("B again with its name written in capitals is not the same entry", func(t *testing.T) {
		p := b.a.interParams(csr)
		p.Roots = []pki.RootRef{b.a.ref(), b.b.ref(), {Subject: cnName(tUTF8, strings.ToUpper(b.b.parsed.Subject.CommonName)), Key: &b.b.key.PublicKey}}
		_, err := pki.IntermediateTBS(p)
		refused(t, err, pki.ErrParams)
	})
}

// A long list: a thousand roots with a name and a key each are accepted, a root listed again at the end is accepted, and a clash with the
// first root is found at the end of the list.
func TestAListOfAThousandRootsIsJudgedWholeAndAtOnce(t *testing.T) {
	b := newBundle(t)
	csr := goodRequest(t)
	roots := []pki.RootRef{b.a.ref()}
	keys := []*ecdsa.PrivateKey{b.a.key}
	for i := 1; i < 1000; i++ {
		k := newKey(t)
		keys = append(keys, k)
		roots = append(roots, pki.RootRef{Subject: cnName(tUTF8, "Many Root "+itoa(i)+" (TEST ONLY)"), Key: &k.PublicKey})
	}
	p := b.a.interParams(csr)
	p.Roots = roots
	if _, err := pki.IntermediateTBS(p); err != nil {
		t.Fatalf("a thousand distinct roots: %v", err)
	}
	p.Roots = append(append([]pki.RootRef(nil), roots...), roots[1], roots[999], roots[0])
	if _, err := pki.IntermediateTBS(p); err != nil {
		t.Fatalf("a thousand roots and three of them again: %v", err)
	}
	other := newKey(t)
	rootsRefusedBothWays(t, b, csr, append(append([]pki.RootRef(nil), roots...), pki.RootRef{Subject: roots[1].Subject, Key: &other.PublicKey}), sameNameWords)
	rootsRefusedBothWays(t, b, csr, append(append([]pki.RootRef(nil), roots...), pki.RootRef{Subject: cnName(tUTF8, "Last Root (TEST ONLY)"), Key: &keys[998].PublicKey}), sameKeyWords)
	// A request for the key of the last root of the long list is still refused.
	c := copyCSR(csr)
	c.Key, c.RawSubjectPublicKeyInfo = keys[999], nil
	p = b.a.interParams(c)
	p.Roots = roots
	if _, err := pki.IntermediateTBS(p); pki.CheckOf(err) != pki.CheckPolicy {
		t.Errorf("a request for the key of the thousandth root: %v", err)
	}
}

// The names that the list compares are the names that SameName compares: for every pair of names of the table of SameName that can be
// roots, two roots with those names and two keys are refused for their name exactly when SameName says the names are the same.
func TestTheNamesOfTheRootsAreComparedAsSameNameCompares(t *testing.T) {
	b := newBundle(t)
	csr := goodRequest(t)
	k1, k2 := newKey(t), newKey(t)
	var names [][]byte
	seen := map[string]bool{}
	ou := mustOID(asn1.ObjectIdentifier{2, 5, 4, 11})
	own := [][]byte{
		cnName(tUTF8, "Alpha x"), cnName(tUTF8, "ALPHA X"), cnName(tPrintable, "alpha x"), cnName(tUTF8, "Alpha y"), cnName(tUTF8, "Alpha  x"),
		nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme"))), rdn(atv(oidAttrCN, str(tUTF8, "root")))),
		nameOf(rdn(atv(oidAttrO, str(tPrintable, "ACME"))), rdn(atv(oidAttrCN, str(tUTF8, "Root")))),
		nameOf(rdn(atv(oidAttrCN, str(tUTF8, "root"))), rdn(atv(oidAttrO, str(tUTF8, "acme")))),
		nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme")), atv(oidAttrCN, str(tUTF8, "root")))),
		nameOf(rdn(atv(oidAttrO, str(tUTF8, "ACME")), atv(oidAttrCN, str(tPrintable, "ROOT")))),
		nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme")), atv(ou, str(tUTF8, "root")))),
		nameOf(rdn(atv(oidAttrDC, str(tIA5, "example"))), rdn(atv(oidAttrDC, str(tIA5, "org")))),
		nameOf(rdn(atv(oidAttrDC, str(tIA5, "EXAMPLE"))), rdn(atv(oidAttrDC, str(tIA5, "ORG")))),
		nameOf(rdn(atv(oidAttrDC, str(tIA5, "org"))), rdn(atv(oidAttrDC, str(tIA5, "example")))),
		nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme"))), rdn(atv(ou, str(tUTF8, "a"))), rdn(atv(oidAttrCN, str(tUTF8, "root")))),
		nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme"))), rdn(atv(ou, str(tUTF8, "A"))), rdn(atv(oidAttrCN, str(tPrintable, "ROOT")))),
	}
	// Two names that are two names, and that run into one text if the attributes of a relative name were written one after the other
	// with nothing between: the text of the first attribute ends with what the type of the second begins with. A name is compared as
	// its attributes are, so the two are two roots.
	oidP, oidQ1, oidQ2 := mustOID(asn1.ObjectIdentifier{1, 2, 3, 4, 5}), mustOID(asn1.ObjectIdentifier{1, 2, 5, 4, 7}), mustOID(asn1.ObjectIdentifier{2, 5, 4, 7})
	runIntoOne := [][]byte{
		nameOf(rdn(atv(oidP, str(tUTF8, "t")), atv(oidQ1, str(tUTF8, "x")))),
		nameOf(rdn(atv(oidP, str(tUTF8, "t1.")), atv(oidQ2, str(tUTF8, "x")))),
	}
	if same, err := pki.SameName(runIntoOne[0], runIntoOne[1]); err != nil || same {
		t.Fatalf("the two names that run into one text are the same name: %v, %v", same, err)
	}
	own = append(own, runIntoOne...)
	pool := append([][]byte(nil), own...)
	for _, r := range sameNameRows() {
		pool = append(pool, r.issuer, r.subj)
	}
	{
		for _, n := range pool {
			if seen[string(n)] {
				continue
			}
			seen[string(n)] = true
			// A name that cannot be a root (the text rule of a root's name) is left out: the list is refused for that and not for a clash.
			p := b.a.interParams(csr)
			p.Roots = []pki.RootRef{b.a.ref(), {Subject: n, Key: &k1.PublicKey}}
			if _, err := pki.IntermediateTBS(p); err != nil {
				continue
			}
			names = append(names, n)
		}
	}
	if len(names) < 27 {
		t.Fatalf("only %d names can be roots", len(names))
	}
	same, different := 0, 0
	for _, a := range names {
		for _, c := range names {
			want, err := pki.SameName(a, c)
			if err != nil {
				t.Fatal(err)
			}
			p := b.a.interParams(csr)
			p.Roots = []pki.RootRef{b.a.ref(), {Subject: a, Key: &k1.PublicKey}, {Subject: c, Key: &k2.PublicKey}}
			_, err = pki.IntermediateTBS(p)
			if want {
				same++
				if err == nil || !strings.Contains(err.Error(), sameNameWords) {
					t.Errorf("SameName(%x, %x) is true and the list is not refused for it: %v", a, c, err)
				}
				continue
			}
			different++
			if err != nil {
				t.Errorf("SameName(%x, %x) is false and the list is refused: %v", a, c, err)
			}
		}
	}
	t.Logf("%d names, %d ordered pairs: %d the same name, %d different", len(names), len(names)*len(names), same, different)
	if same < 60 || different < 400 {
		t.Errorf("the set is too small: %d same, %d different", same, different)
	}
}
