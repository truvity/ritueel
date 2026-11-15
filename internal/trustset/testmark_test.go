package trustset_test

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/trustset"
)

// The test mark of the X.509 roots and the test mark of the OpenPGP primaries of a list agree: a list
// never mixes test roots and real roots (docs/reference/root-list.md), and a test root and a real
// root are never mixed, as for the CA bundle (docs/reference/keyring-package.md). NewDraft refuses a
// difference as an ErrParams that says which family is the test one.

const (
	rootsAreTest     = "the X.509 roots are test roots and the OpenPGP primaries are not"
	primariesAreTest = "the OpenPGP primaries are test primaries and the X.509 roots are not"
)

// labelsTo returns the labels A, B, ... for n roots.
func labelsTo(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = string(rune('A' + i))
	}
	return out
}

// crossInput is a first list of the labels whose X.509 roots have the mark xTest and whose OpenPGP
// primaries have the mark pTest. The pins and the fingerprints are those of the made keys, so the
// list and the certificates fit one another: the marks are the only fault, when they differ.
func crossInput(t testing.TB, xTest, pTest bool, labels ...string) trustset.Input {
	t.Helper()
	in := trustset.Input{
		Sequence:            1,
		SignedAt:            firstCeremony,
		Certificates:        map[string][]byte{},
		OpenPGPCertificates: map[string][]byte{},
	}
	for _, l := range labels {
		x, p := newRoot(t, l, xTest), newRoot(t, l, pTest)
		in.Roots = append(in.Roots, trustset.Root{Label: l, X509SPKISHA256: x.Pin, OpenPGPFingerprint: p.Print})
		in.Certificates[l] = slices.Clone(x.DER)
		in.OpenPGPCertificates[l] = slices.Clone(p.PGP)
	}
	return in
}

// signFirst signs a first list with one key of the family given, which a first list needs.
func signFirst(t testing.TB, d *trustset.Draft, test bool) (*trustset.Set, *scriptedSigner) {
	t.Helper()
	if len(d.OneOf()) == 0 {
		t.Fatal("no OneOf label")
	}
	s := counting(newRoot(t, d.OneOf()[0], test).signer(t))
	set, err := d.Sign([]trustset.Signer{s}, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return set, s
}

// Test X.509 roots with real primaries, and real X.509 roots with test primaries, are refused, for
// one root and for several up to the most a list holds. The sentence names the test family, and it
// is the only fault of the input.
func TestNewDraftRefusesRootsAndPrimariesOfAnotherMark(t *testing.T) {
	for _, n := range []int{1, 2, 3, 26} {
		labels := labelsTo(n)
		t.Run(fmt.Sprintf("test roots, real primaries, %d roots", n), func(t *testing.T) {
			refusesCerts(t, crossInput(t, true, false, labels...), rootsAreTest)
		})
		t.Run(fmt.Sprintf("real roots, test primaries, %d roots", n), func(t *testing.T) {
			refusesCerts(t, crossInput(t, false, true, labels...), primariesAreTest)
		})
	}
}

// The sentence of the one family is not the sentence of the other, and it is the whole reason that
// the error gives.
func TestTheSentenceOfAMarkDifferenceNamesTheTestFamilyAndOnlyIt(t *testing.T) {
	_, err := trustset.NewDraft(crossInput(t, true, false, "A", "B"))
	wantOnly(t, err, trustset.ErrParams)
	if !strings.HasSuffix(err.Error(), ": "+rootsAreTest) || strings.Contains(err.Error(), "primaries are test") {
		t.Errorf("test roots, real primaries: %v", err)
	}
	_, err = trustset.NewDraft(crossInput(t, false, true, "A", "B"))
	wantOnly(t, err, trustset.ErrParams)
	if !strings.HasSuffix(err.Error(), ": "+primariesAreTest) || strings.Contains(err.Error(), "roots are test") {
		t.Errorf("real roots, test primaries: %v", err)
	}
	if strings.Contains(err.Error(), "TEST ONLY") {
		t.Errorf("the error shows the mark as written: %v", err)
	}
}

// The same mark in both families is accepted, for test and for real, for one root and for several,
// and the draft holds the certificates joined in the order of the list. The file that comes out is
// read by the reader of the keyring file, and the mark that the primaries tell is the mark of the
// roots.
func TestNewDraftTakesTheSameMarkInBothFamilies(t *testing.T) {
	for _, test := range []bool{true, false} {
		for _, n := range []int{1, 2, 3, 26} {
			t.Run(fmt.Sprintf("test=%v %d roots", test, n), func(t *testing.T) {
				labels := labelsTo(n)
				in := crossInput(t, test, test, labels...)
				d, err := trustset.NewDraft(in)
				if err != nil {
					t.Fatalf("NewDraft: %v", err)
				}
				var want []byte
				var entries []openpgp.KeyringEntry
				for _, l := range labels {
					want = append(want, newRoot(t, l, test).PGP...)
					entries = append(entries, openpgp.KeyringEntry{Label: l, Fingerprint: newRoot(t, l, test).Print})
				}
				if !bytes.Equal(d.Keyring(), want) {
					t.Error("the keyring file is not the certificates in the order of the list")
				}
				keys, err := openpgp.ReadKeyring(d.Keyring(), entries)
				if err != nil {
					t.Fatalf("ReadKeyring: %v", err)
				}
				for i, k := range keys {
					if k.TestMark() != test {
						t.Errorf("primary %d: TestMark = %v, the roots are test = %v", i, k.TestMark(), test)
					}
				}
				set, s := signFirst(t, d, test)
				if len(set.Files()) != 4 || !bytes.Equal(set.Keyring(), want) {
					t.Errorf("the set has %d files or another keyring file", len(set.Files()))
				}
				if s.count() != 1 {
					t.Errorf("the signer was asked %d times", s.count())
				}
				mustAccept(t, set, nil, in.SignedAt)
			})
		}
	}
}

// A draft with no keyring file has nothing to compare: test roots and real roots, with no
// fingerprint, give a draft with no keyring file, as before.
func TestNewDraftWithNoKeyringHasNoMarkToCompare(t *testing.T) {
	for _, test := range []bool{true, false} {
		in := crossInput(t, test, test, "A", "B")
		for i := range in.Roots {
			in.Roots[i].OpenPGPFingerprint = ""
		}
		in.OpenPGPCertificates = nil
		d, err := trustset.NewDraft(in)
		if err != nil {
			t.Fatalf("test=%v: %v", test, err)
		}
		if d.Keyring() != nil || d.KeyringSHA256() != "" {
			t.Errorf("test=%v: a keyring file for a list that pins no primary", test)
		}
		set, _ := signFirst(t, d, test)
		if len(set.Files()) != 3 || set.Keyring() != nil {
			t.Errorf("test=%v: %d files", test, len(set.Files()))
		}
		// Certificates for a list that pins no primary stay refused for what they are, not for a mark.
		for _, pTest := range []bool{true, false} {
			extra := in
			extra.Certificates = in.Certificates
			extra.OpenPGPCertificates = map[string][]byte{"A": newRoot(t, "A", pTest).PGP, "B": newRoot(t, "B", pTest).PGP}
			_, err := trustset.NewDraft(extra)
			wantOnly(t, err, trustset.ErrParams)
			if strings.Contains(err.Error(), "test roots") || strings.Contains(err.Error(), "test primaries") {
				t.Errorf("test=%v primaries test=%v: told as a mark difference: %v", test, pTest, err)
			}
		}
	}
}

// The comparison is the last step of the keyring: a fault that was told before stays told first, so
// the order and the kinds of the earlier checks are the same as before. Each input here also has the
// other mark in the primaries.
func TestAMarkDifferenceIsToldAfterTheEarlierFaults(t *testing.T) {
	mark := []string{rootsAreTest, primariesAreTest}
	cases := []struct {
		name   string
		xTest  bool
		pTest  bool
		mutate func(in *trustset.Input)
		want   string
	}{
		{"the sequence", true, false, func(in *trustset.Input) { in.Sequence = 0 }, "sequence"},
		{"a missing X.509 certificate", true, false, func(in *trustset.Input) { delete(in.Certificates, "B") }, "there are 1 certificates for 2 roots"},
		{"a keyring file that is armoured", true, false, func(in *trustset.Input) {
			in.OpenPGPCertificates["A"] = []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
		}, "armoured"},
		{"a keyring file that is armoured, reverse", false, true, func(in *trustset.Input) {
			in.OpenPGPCertificates["A"] = []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
		}, "armoured"},
		{"a primary that the list does not pin", true, false, func(in *trustset.Input) {
			in.OpenPGPCertificates["A"] = newRoot(t, "C", false).PGP
		}, "not on the list"},
		{"a missing OpenPGP certificate", false, true, func(in *trustset.Input) { delete(in.OpenPGPCertificates, "B") }, "OpenPGP certificates for 2 roots"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := crossInput(t, c.xTest, c.pTest, "A", "B")
			c.mutate(&in)
			d, err := trustset.NewDraft(in)
			if d != nil {
				t.Fatal("a draft")
			}
			wantOnly(t, err, trustset.ErrParams)
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("%q does not hold %q", err, c.want)
			}
			for _, m := range mark {
				if strings.Contains(err.Error(), m) {
					t.Errorf("told as a mark difference: %v", err)
				}
			}
		})
	}
}

// A mix inside one family is told by the check of that family, before the two marks are compared: test
// roots and real roots in the CA bundle, and test and real primaries in the keyring file.
func TestAMixInsideOneFamilyIsToldByItsOwnCheck(t *testing.T) {
	// X.509: A is a test root, B is real; the primaries are all real.
	in := crossInput(t, false, false, "A", "B")
	in.Certificates["A"] = slices.Clone(newRoot(t, "A", true).DER)
	in.Roots[0].X509SPKISHA256 = newRoot(t, "A", true).Pin
	d, err := trustset.NewDraft(in)
	if d != nil {
		t.Fatal("a draft")
	}
	wantOnly(t, err, trustset.ErrParams)
	if !strings.Contains(err.Error(), "mix test roots and real roots") {
		t.Errorf("a mix of roots: %v", err)
	}
	// OpenPGP: A is a test primary, B is real; the X.509 roots are all test roots.
	in = crossInput(t, true, true, "A", "B")
	in.OpenPGPCertificates["B"] = slices.Clone(newRoot(t, "B", false).PGP)
	in.Roots[1].OpenPGPFingerprint = newRoot(t, "B", false).Print
	d, err = trustset.NewDraft(in)
	if d != nil {
		t.Fatal("a draft")
	}
	wantOnly(t, err, trustset.ErrParams)
	if !strings.Contains(err.Error(), "mixes test and real primaries") || strings.Contains(err.Error(), rootsAreTest) {
		t.Errorf("a mix of primaries: %v", err)
	}
}

// A refusal gives no draft, so no signer is asked: the nil draft refuses to sign, whatever the
// signers.
func TestNoSignerIsAskedForAMarkDifference(t *testing.T) {
	for _, in := range []trustset.Input{crossInput(t, true, false, "A", "B"), crossInput(t, false, true, "A", "B")} {
		d, err := trustset.NewDraft(in)
		if d != nil || err == nil {
			t.Fatalf("draft %v, error %v", d, err)
		}
		signers := []*scriptedSigner{counting(newRoot(t, "A", true).signer(t)), counting(newRoot(t, "A", false).signer(t))}
		set, err := d.Sign(asSigners(signers), nil)
		if set != nil {
			t.Error("a set")
		}
		wantOnly(t, err, trustset.ErrParams)
		zeroCalls(t, signers)
	}
}

// A second list of a bundle is held to the same rule. The pin is the pin of the key, so a root
// certificate re-issued over the same key under a name with the other mark keeps the pin: the renewal
// whose certificates are now real and whose primaries are still test primaries is refused, and the
// same renewal with the same mark is accepted.
func TestARenewalIsHeldToTheSameMark(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	if _, err := c.draft(next{labels: []string{"A", "B"}}); err != nil {
		t.Fatalf("a renewal with the same mark: %v", err)
	}
	in := c.input(next{labels: []string{"A", "B"}})
	for _, l := range []string{"A", "B"} {
		in.Certificates[l] = rootCertificate(t, newRoot(t, l, true).Key, l, false)
	}
	refuses(t, in, primariesAreTest)
	// The other way: the primaries are the ones that are held, and no certificate is test any more.
	in = c.input(next{labels: []string{"A", "B"}})
	for _, l := range []string{"A", "B"} {
		in.Certificates[l] = rootCertificate(t, newRoot(t, l, true).Key, l, true)
	}
	if _, err := trustset.NewDraft(in); err != nil {
		t.Errorf("certificates re-issued with the same mark: %v", err)
	}
}

// Hostile bytes where a keyring file stands, with roots and fingerprints of the other mark than the
// bytes: size, counts, wrong types (a certificate of the X.509 side where a
// primary stands), bytes that are not UTF-8, and a user ID that spells the mark in another place.
// Every one is refused with an ErrParams that is short, printable and shows none of the bytes, and
// no draft comes.
func TestHostileBytesAreRefusedOnTheMarkPath(t *testing.T) {
	real, test := newRoot(t, "A", false), newRoot(t, "A", true)
	long := bytes.Repeat([]byte{0xC6, 0x00}, 1<<20)
	cases := map[string][]byte{
		"nil":                        nil,
		"empty":                      {},
		"one byte":                   {0xC6},
		"zeros":                      make([]byte, 4096),
		"over the limit":             long,
		"all ones":                   bytes.Repeat([]byte{0xff}, 70000),
		"an X.509 certificate":       test.DER,
		"the same certificate twice": slices.Concat(real.PGP, real.PGP),
		"not UTF-8 in the user ID":   bytes.Replace(real.PGP, []byte("root@"), []byte{0xff, 0xfe, 0xc0, 0x80, '@'}, 1),
		"the mark in the user ID":    bytes.Replace(real.PGP, []byte(" <root@"), []byte("(TEST ONLY) <root@"), 1),
		"a link as text":             []byte("../../etc/passwd"),
		"armour":                     []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"),
	}
	for name, file := range cases {
		for _, xTest := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, test roots %v", name, xTest), func(t *testing.T) {
				in := crossInput(t, xTest, !xTest, "A", "B")
				in.OpenPGPCertificates["A"] = file
				d, err := trustset.NewDraft(in)
				if d != nil {
					t.Fatal("a draft")
				}
				wantOnly(t, err, trustset.ErrParams)
			})
		}
	}
}
