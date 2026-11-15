package trustset_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"

	"ritueel.id/ritueel/internal/keystore/software"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/trustset"
)

// This file holds the helpers of the tests of the keyring file of a trust set.

// keyringInput is the input of a first list of the given labels, with the certificates of the real
// OpenPGP primaries of the test roots.
func keyringInput(t testing.TB, labels ...string) trustset.Input {
	t.Helper()
	return newChain(t).input(next{labels: labels})
}

// joined returns the certificates of the test roots with the given labels, one after the other, in
// the order given.
func joined(t testing.TB, labels ...string) []byte {
	t.Helper()
	var out []byte
	for _, l := range labels {
		out = append(out, newRoot(t, l, true).PGP...)
	}
	return out
}

// entriesOf returns the entries that the reader of the keyring file is asked with, for the test
// roots with the given labels, in the order given.
func entriesOf(t testing.TB, labels ...string) []openpgp.KeyringEntry {
	t.Helper()
	out := make([]openpgp.KeyringEntry, 0, len(labels))
	for _, l := range labels {
		out = append(out, openpgp.KeyringEntry{Label: l, Fingerprint: newRoot(t, l, true).Print})
	}
	return out
}

// packetsOf splits a file of OpenPGP packets in the new format with the length forms of one, two and
// five octets into its packets, each with its header. It fails the test for anything else.
func packetsOf(t testing.TB, file []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(file) > 0 {
		if len(file) < 2 || file[0]&0xC0 != 0xC0 {
			t.Fatalf("a packet at %d bytes from the end is not in the new format", len(file))
		}
		var head, n int
		switch l := int(file[1]); {
		case l < 192:
			head, n = 2, l
		case l < 224:
			head, n = 3, (l-192)<<8+int(file[2])+192
		case l == 255:
			head, n = 6, int(file[2])<<24|int(file[3])<<16|int(file[4])<<8|int(file[5])
		default:
			t.Fatalf("a partial length %d", l)
		}
		if head+n > len(file) {
			t.Fatalf("a packet of %d bytes is cut", head+n)
		}
		out = append(out, file[:head+n])
		file = file[head+n:]
	}
	return out
}

// tagOf is the tag of a packet in the new format.
func tagOf(packet []byte) byte { return packet[0] & 0x3F }

// primaryOf makes a new primary for the label, with the given test mark, and returns its
// certificate and its fingerprint. The X.509 key of the label is not touched.
func primaryOf(t testing.TB, label string, test bool) (cert []byte, print string, key *software.Key) {
	t.Helper()
	r := &testRoot{Label: label, Test: test}
	r.makePrimary(t)
	return r.PGP, r.Print, r.PGPKey
}

// readByGoCrypto reads a keyring file with the reader of go-crypto, which did not make it, and
// returns the fingerprint of each primary key in the order of the file.
func readByGoCrypto(t testing.TB, file []byte) []string {
	t.Helper()
	list, err := pgp.ReadKeyRing(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("go-crypto does not read the keyring file: %v", err)
	}
	var out []string
	for _, e := range list {
		out = append(out, hex.EncodeToString(e.PrimaryKey.Fingerprint))
	}
	return out
}

// fingerprintsOf returns the fingerprints of the test roots with the given labels.
func fingerprintsOf(t testing.TB, labels ...string) []string {
	t.Helper()
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		out = append(out, newRoot(t, l, true).Print)
	}
	return out
}

// extension returns one more certification of the primary of a test root, made at a later ceremony
// time, as ExtendPrimary makes it.
func extension(t testing.TB, r *testRoot, hours int) []byte {
	t.Helper()
	p := r.primaryParams(t, ceremony.Add(time.Duration(hours)*time.Hour))
	sig, err := openpgp.ExtendPrimary(rand.Reader, p)
	if err != nil {
		t.Fatalf("ExtendPrimary: %v", err)
	}
	return sig
}
