package openpgp_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// SigningBasis: the read-only description of what later signatures are made from.

func TestQASigningBasisIsTheSnapshotFieldByField(t *testing.T) {
	n := 0
	for _, f := range qaExports(t) {
		k, err := openpgp.ReadForeignKey(f.file)
		if err != nil {
			continue
		}
		n++
		if d := openpgp.BasisAgainstSnapshot(k); len(d) != 0 {
			t.Errorf("%s: the basis is not the snapshot: %v", f.name, d)
		}
		kc, err := qaReadCert(k.Certificate())
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		if !reflect.DeepEqual(k.SigningBasis(), kc.SigningBasis()) {
			t.Errorf("%s: the basis of the certificate is not the basis of the export:\n%+v\n%+v", f.name, k.SigningBasis(), kc.SigningBasis())
		}
		if d := openpgp.BasisAgainstSnapshot(kc); len(d) != 0 {
			t.Errorf("%s: the basis of the certificate is not its snapshot: %v", f.name, d)
		}
	}
	if n < 150 {
		t.Errorf("only %d keys", n)
	}
	// a key that nothing read has an empty basis
	var nilKey *openpgp.ForeignKey
	if !reflect.DeepEqual(nilKey.SigningBasis(), openpgp.ForeignBasis{}) || !reflect.DeepEqual((&openpgp.ForeignKey{}).SigningBasis(), openpgp.ForeignBasis{}) {
		t.Error("the basis of a key that nothing read is not empty")
	}
}

// What SigningBasis returns shares nothing with the key: every slice is changed in place, then emptied, and the
// key says the same when it is asked again.
func TestQASigningBasisSharesNothingWithTheKey(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, shape := range []string{"rich", "plain"} {
			file := b.plain
			if shape == "rich" {
				file = fkRichOf(t, b, false, true).file
			}
			k := fkRead(t, file)
			want := k.SigningBasis()
			snap := openpgp.SnapshotOf(k)
			if len(want.UserIDs) == 0 || (shape == "rich" && len(want.Subkeys) == 0) {
				t.Fatalf("%s: the basis has %d user IDs and %d subkeys", shape, len(want.UserIDs), len(want.Subkeys))
			}
			for round := 0; round < 2; round++ {
				got := k.SigningBasis()
				qaScramble(reflect.ValueOf(&got), 1)
				for i := range got.UserIDs {
					got.UserIDs[i] = openpgp.ForeignBasisUserID{Text: "scribble"}
				}
				for i := range got.Subkeys {
					got.Subkeys[i] = openpgp.ForeignBasisSubkey{Fingerprint: "scribble"}
				}
				got.UserIDs, got.Subkeys = got.UserIDs[:0], nil
				if again := k.SigningBasis(); !reflect.DeepEqual(again, want) {
					t.Fatalf("%s: the basis changed after a caller changed the one it was given", shape)
				}
				if !reflect.DeepEqual(openpgp.SnapshotOf(k), snap) {
					t.Fatalf("%s: the snapshot changed after a caller changed the basis", shape)
				}
			}
			// two calls give two bases that share no slice: an element of one is not an element of the other
			a, c := k.SigningBasis(), k.SigningBasis()
			if len(a.UserIDs) > 0 && &a.UserIDs[0] == &c.UserIDs[0] {
				t.Error("two bases share their list of user IDs")
			}
			if len(a.Subkeys) > 0 && &a.Subkeys[0] == &c.Subkeys[0] {
				t.Error("two bases share their list of subkeys")
			}
		}
	})
}

// The basis marks what a ceremony must show: the weak source, the tie, the text that a re-signing may cover, the
// primary user ID, and the algorithm of each subkey.
func TestQASigningBasisSaysWhatACeremonyMustShow(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	const A, B = "Alpha Person <alpha@example.org>", "Bravo\nPerson <bravo@example.org>"
	file := qaFile(t, b, nil,
		qaUserBlock{A, [][]byte{qaUserSig(t, w, A, 0x13, 8, 1000), qaUserSig(t, w, A, 0x13, 2, 1100)}},
		qaUserBlock{B, [][]byte{qaUserSig(t, w, B, 0x13, 8, 1000, fkSubpacket(25, false, 1)), qaUserSig(t, w, B, 0x13, 8, 1000, fkSubpacket(25, false, 1), fkSubpacket(27, false, 2))}})
	got := fkRead(t, file).SigningBasis()
	if len(got.UserIDs) != 2 {
		t.Fatalf("%+v", got)
	}
	a, bb := got.UserIDs[0], got.UserIDs[1] // sorted by text: "Alpha" before "Bravo"
	if a.Text != A || !a.Weak || !a.AnyStrong || a.Tied || !a.TextOK || a.IsPrimary {
		t.Errorf("the user ID with a SHA-1 source: %+v", a)
	}
	if bb.Text != B || bb.Weak || !bb.Tied || bb.TextOK || !bb.IsPrimary || !bb.Primary {
		t.Errorf("the user ID that is tied, has a text that may not be covered and is flagged: %+v", bb)
	}
	// a subkey: the algorithm is the one of its packet
	enc, _, _ := fkDonors(t)
	sb := fkRead(t, w.file(t, fkParts{subSigs: [][]byte{w.sign(t, "sub", 0x18, w.areas(1000, fkSubpacket(27, false, 0x0C)), nil, 8, sha256.New, enc[3].pub.Body)}})).SigningBasis().Subkeys
	if len(sb) != 1 || sb[0].Algorithm.ID != 18 || len(sb[0].Fingerprint) != 40 || sb[0].Fingerprint != strings.ToLower(sb[0].Fingerprint) {
		t.Errorf("the subkey of the basis: %+v", sb)
	}
	if _, err := hex.DecodeString(sb[0].Fingerprint); err != nil {
		t.Errorf("the fingerprint is not hexadecimal: %v", err)
	}
}

// ParseHeldDigest takes 64 lower-case hexadecimal digits and nothing else.
//
// That a HeldDigest cannot be made outside the package without ParseHeldDigest is a fact of the compiler, and no
// test says it: its one field is unexported, so another package can only write the zero value, which
// ReadForeignCertificate refuses.
func TestQAParseHeldDigest(t *testing.T) {
	good := strings.Repeat("ab", 32)
	d, err := openpgp.ParseHeldDigest(good)
	if err != nil || d.String() != good {
		t.Fatalf("the good digest: %v %q", err, d.String())
	}
	sum := sha256.Sum256([]byte("x"))
	if d, err := openpgp.ParseHeldDigest(hex.EncodeToString(sum[:])); err != nil || d.String() != hex.EncodeToString(sum[:]) {
		t.Errorf("the digest of a text: %v", err)
	}
	for name, text := range map[string]string{
		"empty":                   "",
		"upper case":              strings.ToUpper(good),
		"one upper-case digit":    "A" + good[1:],
		"63 digits":               good[:63],
		"65 digits":               good + "a",
		"a prefix":                "sha256:" + good,
		"a prefix of 0x":          "0x" + good[2:],
		"a space in front":        " " + good,
		"a space behind":          good + " ",
		"a line break behind":     good + "\n",
		"a space inside":          good[:32] + " " + good[33:],
		"a g":                     "g" + good[1:],
		"a non-ASCII digit":       "١" + good[2:],
		"the zero digest":         strings.Repeat("0", 64),
		"a NUL":                   "\x00" + good[1:],
		"two digests":             good + good,
		"a colon between pairs":   strings.Repeat("ab:", 21) + "ab",
		"64 bytes of a wide rune": strings.Repeat("é", 32),
	} {
		d, err := openpgp.ParseHeldDigest(text)
		if err == nil || !errors.Is(err, openpgp.ErrParams) || d.String() != "" {
			t.Errorf("%s: %q: %v, %q", name, text, err, d.String())
			continue
		}
		if strings.Contains(err.Error(), "abab") {
			t.Errorf("%s: the text of the error holds the digest: %v", name, err)
		}
	}
	// the zero value is no digest: the reader refuses it before it looks at the certificate
	var zero openpgp.HeldDigest
	if zero.String() != "" {
		t.Errorf("the zero digest says %q", zero.String())
	}
	cert := fkRead(t, fkNamed(t, "ed25519").plain).Certificate()
	k, err := openpgp.ReadForeignCertificate(cert, zero)
	if k != nil || !errors.Is(err, openpgp.ErrParams) || errors.Is(err, openpgp.ErrForeignKey) {
		t.Errorf("the zero digest: %v", err)
	}
	// and for every input, so that it is no digest that a certificate is compared with
	for _, in := range [][]byte{nil, {1}, make([]byte, openpgp.MaxForeignKeyBytes+1)} {
		if _, err := openpgp.ReadForeignCertificate(in, zero); !errors.Is(err, openpgp.ErrParams) {
			t.Errorf("the zero digest and an input of %d bytes: %v", len(in), err)
		}
	}
}

// The certificate is copied before it is hashed and the copy is what is parsed. A slice that another goroutine
// changes during the call cannot give a key whose bytes are not the ones that were hashed: the outcome is the
// key of the original certificate, or the refusal of the digest, and never another refusal that a parse of
// changed bytes would give. The writer changes a byte of the caller's slice back and forth as fast as it goes.
//
// What this shows, and what it does not: the writer and the copy read and write the same memory, which is the
// caller's fault and which the race detector reports in the caller; so the test is skipped under the detector,
// which can only show that our own code makes no other access to the caller's slice than the one copy.
func TestQAACertificateThatChangesDuringTheReadIsNeverParsedAsOtherThanItWasHashed(t *testing.T) {
	if qaRaceEnabled {
		t.Skip("the caller's slice is written and read at once: the detector reports that, in the caller")
	}
	b := fkNamed(t, "ed25519")
	cert := fkRead(t, b.plain).Certificate()
	want := fkDigestOf(cert)
	in := bytes.Clone(cert)
	// the byte is the last of the signature of the user ID: a change of it is a signature that does not verify
	at := len(in) / 2
	stop, done := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			mu.Lock()
			in[at] ^= 0x40
			mu.Unlock()
		}
	}()
	ok, digest, other := 0, 0, 0
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		k, err := openpgp.ReadForeignCertificate(in, want)
		switch {
		case err == nil:
			if !bytes.Equal(k.Certificate(), cert) {
				t.Fatal("a key that is not the certificate that was hashed")
			}
			ok++
		case errors.Is(err, openpgp.ErrAdoptedCertificate) && strings.Contains(err.Error(), "SHA-256"):
			digest++
		default:
			other++
			t.Errorf("a refusal that is not the one of the digest: %v", err)
			if other > 3 {
				t.FailNow()
			}
		}
	}
	close(stop)
	<-done
	t.Logf("the caller's slice changed during %d reads: %d keys, %d refusals of the digest, %d other", ok+digest+other, ok, digest, other)
	if ok == 0 || digest == 0 {
		t.Errorf("the writer and the reader did not meet: %d keys, %d digests", ok, digest)
	}
}
