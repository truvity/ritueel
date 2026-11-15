package trustset_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/trustset"
)

// FuzzKeyringCertificates: the bytes are the certificate of A and the certificate of B. NewDraft
// gives a draft or an ErrParams and never panics; an error gives no draft; a draft holds the two
// certificates joined, as they are, and the reader of the keyring file and another reader read them
// again.
func FuzzKeyringCertificates(f *testing.F) {
	a, b := newRoot(f, "A", true), newRoot(f, "B", true)
	f.Add(a.PGP, b.PGP)
	f.Add(b.PGP, a.PGP)
	f.Add(a.PGP, a.PGP)
	f.Add(a.PGP, []byte{})
	f.Add([]byte{}, b.PGP)
	f.Add(a.PGP[:len(a.PGP)-1], b.PGP)
	f.Add(a.PGP, append(slices.Clone(b.PGP), 0xC6, 0x00))
	f.Add(withSubkey(a.PGP), b.PGP)
	f.Add(slices.Concat(a.PGP, b.PGP), []byte{})
	f.Add([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----"), b.PGP)
	f.Fuzz(func(t *testing.T, ca, cb []byte) {
		in := keyringInput(t, "A", "B")
		in.OpenPGPCertificates = map[string][]byte{"A": ca, "B": cb}
		d, err := trustset.NewDraft(in)
		if err != nil {
			if d != nil {
				t.Fatal("a draft comes with an error")
			}
			wantOnly(t, err, trustset.ErrParams)
			return
		}
		want := slices.Concat(ca, cb)
		if !bytes.Equal(d.Keyring(), want) {
			t.Fatal("the draft does not hold the certificates as they are")
		}
		if d.KeyringSHA256() != hexOf(string(want)) {
			t.Fatal("the digest is not the digest of the file")
		}
		if _, err := openpgp.ReadKeyring(d.Keyring(), entriesOf(t, "A", "B")); err != nil {
			t.Fatalf("the reader refuses the file of a draft: %v", err)
		}
		if got := readByGoCrypto(t, d.Keyring()); !slices.Equal(got, fingerprintsOf(t, "A", "B")) {
			t.Fatalf("another reader reads %v", got)
		}
	})
}

// FuzzKeyringEdits: the bytes are a list of edits of the two valid certificates: change a byte,
// delete a range, insert a byte, repeat a packet, cut the end. Whatever comes out is refused or taken
// as it is; the certificate of A with a change that the reader cannot see stays a certificate that
// the reader accepts.
func FuzzKeyringEdits(f *testing.F) {
	a, b := newRoot(f, "A", true), newRoot(f, "B", true)
	packets := [2][][]byte{packetsOf(f, a.PGP), packetsOf(f, b.PGP)}
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0x10, 0xff})
	f.Add([]byte{1, 0, 5, 3})
	f.Add([]byte{2, 1, 7, 1})
	f.Add([]byte{3, 0, 2, 0})
	f.Add([]byte{4, 1, 9, 0})
	f.Add([]byte{0, 1, 0, 0x01, 4, 0, 3, 0})
	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 64 {
			ops = ops[:64]
		}
		certs := [2][]byte{slices.Clone(a.PGP), slices.Clone(b.PGP)}
		for len(ops) >= 4 {
			kind, which, pos, val := ops[0]%5, ops[1]%2, int(ops[2]), ops[3]
			ops = ops[4:]
			c := certs[which]
			if len(c) == 0 {
				continue
			}
			pos %= len(c)
			switch kind {
			case 0:
				c[pos] ^= val
			case 1:
				end := min(len(c), pos+int(val%32))
				c = slices.Delete(c, pos, end)
			case 2:
				c = slices.Insert(c, pos, val)
			case 3:
				// A packet of the valid certificate is repeated at the end.
				c = append(c, packets[which][int(val)%len(packets[which])]...)
			case 4:
				c = c[:pos]
			}
			certs[which] = c
		}
		in := keyringInput(t, "A", "B")
		in.OpenPGPCertificates = map[string][]byte{"A": certs[0], "B": certs[1]}
		d, err := trustset.NewDraft(in)
		if err != nil {
			if d != nil {
				t.Fatal("a draft comes with an error")
			}
			wantOnly(t, err, trustset.ErrParams)
			return
		}
		if !bytes.Equal(d.Keyring(), slices.Concat(certs[0], certs[1])) {
			t.Fatal("the draft does not hold the certificates as they are")
		}
		if _, err := openpgp.ReadKeyring(d.Keyring(), entriesOf(t, "A", "B")); err != nil {
			t.Fatalf("the reader refuses the file of a draft: %v", err)
		}
	})
}

// FuzzKeyringMark: the bytes are the certificate of A and the certificate of B, the X.509 roots are
// test roots or real roots, and the list pins the fingerprints of the test primaries or of the real
// ones. NewDraft gives a draft or an ErrParams and never panics. A draft comes only when the reader of
// the keyring file accepts the file and the mark of its primaries is the mark of the X.509 roots; a
// file that the reader accepts with the other mark is refused with the sentence that names the test
// family.
func FuzzKeyringMark(f *testing.F) {
	for _, xTest := range []bool{true, false} {
		for _, pTest := range []bool{true, false} {
			a, b := newRoot(f, "A", pTest), newRoot(f, "B", pTest)
			f.Add(a.PGP, b.PGP, xTest, pTest)
			f.Add(a.PGP, b.PGP, xTest, !pTest)
			f.Add(b.PGP, a.PGP, xTest, pTest)
			f.Add(a.PGP, newRoot(f, "B", !pTest).PGP, xTest, pTest)
			f.Add(a.PGP[:len(a.PGP)-1], b.PGP, xTest, pTest)
		}
	}
	f.Fuzz(func(t *testing.T, ca, cb []byte, xTest, pTest bool) {
		in := crossInput(t, xTest, pTest, "A", "B")
		in.OpenPGPCertificates = map[string][]byte{"A": ca, "B": cb}
		entries := entriesOfMark(t, pTest, "A", "B")
		keys, rerr := openpgp.ReadKeyring(slices.Concat(ca, cb), entries)
		d, err := trustset.NewDraft(in)
		if err != nil {
			if d != nil {
				t.Fatal("a draft comes with an error")
			}
			wantOnly(t, err, trustset.ErrParams)
			if rerr == nil && keys[0].TestMark() != xTest {
				want := rootsAreTest
				if keys[0].TestMark() {
					want = primariesAreTest
				}
				if !strings.HasSuffix(err.Error(), ": "+want) {
					t.Fatalf("the mark differs and the error does not say so: %v", err)
				}
			}
			return
		}
		if rerr != nil {
			t.Fatalf("a draft for a file that the reader refuses: %v", rerr)
		}
		for i, k := range keys {
			if k.TestMark() != xTest {
				t.Fatalf("a draft whose primary %d has the mark %v and whose roots have %v", i, k.TestMark(), xTest)
			}
		}
		if !bytes.Equal(d.Keyring(), slices.Concat(ca, cb)) {
			t.Fatal("the draft does not hold the certificates as they are")
		}
	})
}

// entriesOfMark returns the entries that the reader of the keyring file is asked with, for the primaries
// of the given mark of the labels given.
func entriesOfMark(t testing.TB, test bool, labels ...string) []openpgp.KeyringEntry {
	t.Helper()
	out := make([]openpgp.KeyringEntry, 0, len(labels))
	for _, l := range labels {
		out = append(out, openpgp.KeyringEntry{Label: l, Fingerprint: newRoot(t, l, test).Print})
	}
	return out
}
