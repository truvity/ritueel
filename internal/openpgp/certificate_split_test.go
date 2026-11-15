package openpgp_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// SplitCertificate reads the framing of one certificate of the first form (docs/reference/keyring-package.md,
// "The first form of the keyring file"): one Public-Key packet, one User ID packet and one to
// 256 Signature packets, and nothing else. It parses no key and verifies nothing. The tests give it
// the certificates that the builders write, the certificate files of the hand-off, and frames that
// are not the form, some of them with packets that are not keys at all, because the reader must
// refuse or accept by the frame alone.

// splitSafely is SplitCertificate that reports a panic as a failure of the test.
func splitSafely(t testing.TB, what string, in []byte) (c *openpgp.Certificate, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: SplitCertificate panicked: %v", what, r)
			c, err = nil, errors.New("panic")
		}
	}()
	return openpgp.SplitCertificate(in)
}

// assertSplit splits a certificate that must be accepted, and checks the parts against the tests' own
// reader: tags 6, 13 and 2 or more, each part one whole packet, and the three kinds joined are the
// input.
func assertSplit(t testing.TB, what string, in []byte) *openpgp.Certificate {
	t.Helper()
	before := bytes.Clone(in)
	c, err := splitSafely(t, what, in)
	if err != nil || c == nil {
		t.Fatalf("%s: SplitCertificate = %v, %v; want a certificate", what, c, err)
	}
	if !bytes.Equal(in, before) {
		t.Errorf("%s: SplitCertificate changed its input", what)
	}
	if len(c.Signatures) < 1 || len(c.Signatures) > openpgp.MaxCertifications {
		t.Errorf("%s: %d signatures", what, len(c.Signatures))
	}
	whole := [][]byte{c.Key, c.UserID}
	whole = append(whole, c.Signatures...)
	if !bytes.Equal(bytes.Join(whole, nil), in) {
		t.Errorf("%s: the parts joined are not the input", what)
	}
	for i, part := range whole {
		tag, _, rest, ok := softPacket(part)
		want := byte(tagSignature)
		switch i {
		case 0:
			want = tagPublicKey
		case 1:
			want = tagUserID
		}
		if !ok || len(rest) != 0 || tag != want {
			t.Errorf("%s: part %d is not one whole packet of tag %d (tag %d, whole %v, %d bytes after)", what, i, want, tag, ok, len(rest))
		}
	}
	return c
}

// assertCertificateRefused splits bytes that must be refused: an ErrCertificateForm and no other
// kind of this package, no Certificate, and a text that is one short line with no byte of the input.
func assertCertificateRefused(t testing.TB, what string, in []byte) {
	t.Helper()
	before := bytes.Clone(in)
	c, err := splitSafely(t, what, in)
	if err == nil {
		t.Errorf("%s: no error, want an ErrCertificateForm", what)
		return
	}
	if c != nil {
		t.Errorf("%s: a certificate was returned with the error %v", what, err)
	}
	if !errors.Is(err, openpgp.ErrCertificateForm) {
		t.Errorf("%s: error = %v, want an ErrCertificateForm", what, err)
	}
	for _, other := range []error{openpgp.ErrKeyring, openpgp.ErrKeyringForm, openpgp.ErrSignatureFile, openpgp.ErrRevocation,
		openpgp.ErrRevocationReason, openpgp.ErrParams, openpgp.ErrAnswer, openpgp.ErrRequest} {
		if errors.Is(err, other) {
			t.Errorf("%s: error %v is also %v", what, err, other)
		}
	}
	if !bytes.Equal(in, before) {
		t.Errorf("%s: SplitCertificate changed its input", what)
	}
	checkErrorText(t, what, err)
}

// fakePacket is a packet of a tag with a body of n bytes that no key reader would accept.
func fakePacket(tag byte, n int) []byte { return wrap(tag, bytes.Repeat([]byte{0x5A}, n)) }

// fakeCertificate is a certificate by frame only: a key, a user ID and count signatures.
func fakeCertificate(count int) []byte {
	parts := [][]byte{fakePacket(tagPublicKey, 100), fakePacket(tagUserID, 30)}
	for range count {
		parts = append(parts, fakePacket(tagSignature, 60))
	}
	return cat(parts...)
}

func TestSplitCertificateSplitsTheCertificateThatNewPrimaryWrites(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	cert := m.cert(t)
	c := assertSplit(t, "NewPrimary", cert)
	if len(c.Signatures) != 1 {
		t.Fatalf("%d signatures, want 1", len(c.Signatures))
	}
	ps := splitPackets(t, cert)
	if !bytes.Equal(c.Key, ps[0].Raw) || !bytes.Equal(c.UserID, ps[1].Raw) || !bytes.Equal(c.Signatures[0], ps[2].Raw) {
		t.Error("a part is not the packet that the tests' own reader finds")
	}
	if !bytes.Equal(c.Key, m.keyPacket()) {
		t.Error("the key part is not the key packet of the primary")
	}
	if !bytes.Equal(c.UserID, m.uidPacket()) {
		t.Error("the user ID part is not the user ID packet of the primary")
	}
}

func TestSplitCertificateKeepsEverySignatureThatExtendPrimaryAdds(t *testing.T) {
	m := newKeyringPrimary(t, "B", true)
	cert := m.cert(t)
	second := m.extension(t, ceremony.AddDate(0, 1, 0))
	third := m.extension(t, ceremony.AddDate(0, 2, 0))
	c := assertSplit(t, "three self-signatures", cat(cert, second, third))
	if len(c.Signatures) != 3 {
		t.Fatalf("%d signatures, want 3", len(c.Signatures))
	}
	if !bytes.Equal(c.Signatures[1], second) || !bytes.Equal(c.Signatures[2], third) {
		t.Error("the signatures are not in the order that they stand")
	}
}

func TestSplitCertificateReadsTheCertificateFilesOfTheHandOff(t *testing.T) {
	for _, name := range []string{"test-primary-a.pgp", "test-primary-b.pgp", "test-primary-z.pgp"} {
		t.Run(name, func(t *testing.T) {
			file := vector(t, "pki", name)
			c := assertSplit(t, name, file)
			if got := splitPackets(t, c.Key); len(got) != 1 || got[0].HeaderLen != 6 {
				t.Errorf("the key packet of the vector has the header length %d, the test expects the five-octet form (6 bytes with the tag)", got[0].HeaderLen)
			}
			// The file reads as a keyring too, so the two readers agree on what it holds.
			if got := ringFingerprints(t, file); len(got) != 1 {
				t.Errorf("go-crypto reads %d primaries from the vector", len(got))
			}
		})
	}
}

// The same certificate in each header form of RFC 9580, section 4.2 is accepted, and each part keeps
// the header that it had.
func TestSplitCertificateReadsEveryHeaderForm(t *testing.T) {
	cert := newKeyringPrimary(t, "A", true).cert(t)
	for _, form := range []string{"new1", "new2", "new5", "old1", "old2", "old4"} {
		t.Run(form, func(t *testing.T) {
			again := repack(t, cert, form)
			c := assertSplit(t, form, again)
			ps := splitPackets(t, again)
			if !bytes.Equal(c.Key, ps[0].Raw) || !bytes.Equal(c.UserID, ps[1].Raw) || !bytes.Equal(c.Signatures[0], ps[2].Raw) {
				t.Error("a part lost or changed its header")
			}
		})
	}
	t.Run("a different form for each packet", func(t *testing.T) {
		ps := splitPackets(t, cert)
		key, _ := packetIn("old4", tagPublicKey, ps[0].Body)
		uid, _ := packetIn("new5", tagUserID, ps[1].Body)
		sig, _ := packetIn("old2", tagSignature, ps[2].Body)
		c := assertSplit(t, "mixed", cat(key, uid, sig))
		if !bytes.Equal(c.Key, key) || !bytes.Equal(c.UserID, uid) || !bytes.Equal(c.Signatures[0], sig) {
			t.Error("a part is not the packet as it stood")
		}
	})
}

func TestSplitCertificateRefusesWhatIsNotTheFirstForm(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	cert := m.cert(t)
	ps := splitPackets(t, cert)
	key, uid, sig := ps[0].Raw, ps[1].Raw, ps[2].Raw
	other := newKeyringPrimary(t, "B", true)
	subkey := wrap(tagSubkey, keyBody(&other.key.PublicKey, created))
	cases := []struct {
		name string
		in   []byte
	}{
		{"a key packet only", key},
		{"a key and a user ID, no signature", cat(key, uid)},
		{"a signature only", sig},
		{"a user ID first", cat(uid, key, sig)},
		{"a signature before the user ID", cat(key, sig, uid)},
		{"a signature first", cat(sig, key, uid)},
		{"a second key packet", cat(key, uid, sig, key)},
		{"a second certificate", cat(cert, cert)},
		{"a subkey after the signature", cat(cert, subkey)},
		{"a subkey between the user ID and the signature", cat(key, uid, subkey, sig)},
		{"a subkey instead of the key", cat(subkey, uid, sig)},
		{"a subkey in place of the user ID", cat(key, subkey, sig)},
		{"a second user ID after the signature", cat(cert, uid)},
		{"a second user ID before the signature", cat(key, uid, uid, sig)},
		{"a trailing zero byte", cat(cert, []byte{0})},
		{"a trailing line end", cat(cert, []byte("\n"))},
		{"a trailing two bytes that are not a packet", cat(cert, []byte{0x01, 0x02})},
		{"a byte before", cat([]byte{0}, cert)},
		{"a secret key packet first", cat(fakePacket(5, 100), uid, sig)},
		{"a user attribute", cat(key, uid, fakePacket(17, 10), sig)},
		{"a trust packet", cat(key, uid, sig, fakePacket(12, 3))},
		{"a marker packet", cat(fakePacket(10, 3), key, uid, sig)},
		{"a packet of tag 0", cat(key, uid, sig, fakePacket(0, 5))},
		{"a packet of tag 63", cat(key, uid, sig, fakePacket(63, 5))},
		{"a literal data packet", cat(key, uid, fakePacket(11, 5))},
		{"a message that is armoured", []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n")},
		{"the empty input", []byte{}},
		{"a nil input", nil},
		{"one byte", []byte{0xC6}},
		{"a header with no length", []byte{0xC6, 0xFF}},
		{"zeros", make([]byte, 64)},
		{"a packet with a first bit of zero", cat([]byte{0x46, 0x01, 0x00}, uid, sig)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { assertCertificateRefused(t, c.name, c.in) })
	}
}

// Every cut of a certificate that is not whole at its end is refused, and so is every cut that
// leaves fewer than three packets.
// The text of a refusal says what is wrong, so that a person who reads it knows which part is missing.
func TestSplitCertificateSaysWhatIsMissing(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	ps := splitPackets(t, m.cert(t))
	for _, c := range []struct {
		name string
		in   []byte
		word string
	}{
		{"an empty input", []byte{}, "empty"},
		{"a nil input", nil, "empty"},
		{"a key and nothing else", ps[0].Raw, "User ID"},
		{"a key and a user ID", cat(ps[0].Raw, ps[1].Raw), "signature"},
		{"a subkey first", cat(wrap(tagSubkey, ps[0].Body), ps[1].Raw, ps[2].Raw), "Public-Key"},
		{"no user ID in the second place", cat(ps[0].Raw, ps[2].Raw, ps[2].Raw), "User ID"},
		{"a key and a user ID and a key", cat(ps[0].Raw, ps[1].Raw, ps[0].Raw), "Signature"},
	} {
		_, err := openpgp.SplitCertificate(c.in)
		if err == nil || !strings.Contains(err.Error(), c.word) {
			t.Errorf("%s: the refusal is %v, want a text that holds %q", c.name, err, c.word)
		}
	}
}

func TestSplitCertificateRefusesEveryCutOfACertificate(t *testing.T) {
	cert := newKeyringPrimary(t, "A", true).cert(t)
	for n := 0; n < len(cert); n++ {
		assertCertificateRefused(t, fmt.Sprintf("the first %d of %d bytes", n, len(cert)), cert[:n])
	}
}

func TestSplitCertificateRefusesAPartialAndAnIndeterminateLength(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	ps := splitPackets(t, m.cert(t))
	key, uid, sig := ps[0].Raw, ps[1].Raw, ps[2].Raw
	for name, in := range map[string][]byte{
		"a partial length on the key":            cat([]byte{0xC0 | tagPublicKey, 0xE0}, ps[0].Body, uid, sig),
		"a partial length on the user ID":        cat(key, []byte{0xC0 | tagUserID, 0xE0}, ps[1].Body, sig),
		"a partial length on a signature":        cat(key, uid, []byte{0xC0 | tagSignature, 0xE0}, ps[2].Body),
		"the last partial length":                cat(key, uid, []byte{0xC0 | tagSignature, 0xFE}, ps[2].Body),
		"an indeterminate length on the key":     cat([]byte{0x80 | tagPublicKey<<2 | 3}, ps[0].Body, uid, sig),
		"an indeterminate length on the user ID": cat(key, []byte{0x80 | tagUserID<<2 | 3}, ps[1].Body, sig),
		"an indeterminate length on a signature": cat(key, uid, []byte{0x80 | tagSignature<<2 | 3}, ps[2].Body),
		"a five-octet length past the input":     cat(key, uid, []byte{0xC0 | tagSignature, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF}, ps[2].Body),
		"a four-octet old length past the input": cat(key, uid, []byte{0x80 | tagSignature<<2 | 2, 0xFF, 0xFF, 0xFF, 0xFF}, ps[2].Body),
		"a two-octet length of one more":         cat(key, uid, []byte{0xC0 | tagSignature, 0xC0, byte(len(ps[2].Body) - 192 + 1)}, ps[2].Body),
	} {
		assertCertificateRefused(t, name, in)
	}
}

func TestSplitCertificateAcceptsAtTheLimitsAndRefusesPastThem(t *testing.T) {
	t.Run("256 signatures are accepted", func(t *testing.T) {
		c := assertSplit(t, "256", fakeCertificate(openpgp.MaxCertifications))
		if len(c.Signatures) != 256 {
			t.Errorf("%d signatures, want 256", len(c.Signatures))
		}
	})
	t.Run("257 signatures are refused", func(t *testing.T) {
		assertCertificateRefused(t, "257", fakeCertificate(openpgp.MaxCertifications+1))
	})
	t.Run("1000 signatures are refused", func(t *testing.T) {
		assertCertificateRefused(t, "1000", fakeCertificate(1000))
	})
	// The size is checked against MaxKeyringBytes: a user ID padded so that the whole is exactly 1 MiB
	// is accepted, one byte more is refused before a packet is read.
	pad := func(total int) []byte {
		head := cat(fakePacket(tagPublicKey, 100), fakePacket(tagSignature, 60))
		// the user ID packet has a five-octet length: 6 bytes of header
		body := total - len(head) - 6
		return cat(fakePacket(tagPublicKey, 100), wrapLong(tagUserID, bytes.Repeat([]byte{0x41}, body)), fakePacket(tagSignature, 60))
	}
	t.Run("exactly 1 MiB is accepted", func(t *testing.T) {
		in := pad(openpgp.MaxKeyringBytes)
		if len(in) != openpgp.MaxKeyringBytes {
			t.Fatalf("the test input is %d bytes", len(in))
		}
		assertSplit(t, "1 MiB", in)
	})
	t.Run("1 MiB and one byte is refused", func(t *testing.T) {
		in := pad(openpgp.MaxKeyringBytes + 1)
		if len(in) != openpgp.MaxKeyringBytes+1 {
			t.Fatalf("the test input is %d bytes", len(in))
		}
		assertCertificateRefused(t, "1 MiB and one", in)
		if _, err := openpgp.SplitCertificate(in); err == nil || !strings.Contains(err.Error(), "longer than") {
			t.Errorf("the refusal of a long input is %v, want one that says the input is longer than a limit (the size is checked first)", err)
		}
	})
	t.Run("a long input of no packets is refused by its size", func(t *testing.T) {
		in := bytes.Repeat([]byte{0xFF}, openpgp.MaxKeyringBytes+1)
		assertCertificateRefused(t, "long", in)
		if _, err := openpgp.SplitCertificate(in); err == nil || !strings.Contains(err.Error(), "longer than") {
			t.Errorf("the refusal is %v, want one about the size", err)
		}
	})
}

// A refusal at a count is a refusal of the form and says so, not of the bytes: the text names a
// position and a tag, and no byte of the input.
func TestSplitCertificateErrorsNameNoByteOfTheInput(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	cert := m.cert(t)
	ps := splitPackets(t, cert)
	secretish := []byte("Example Test Release Root A")
	if !bytes.Contains(cert, secretish) {
		t.Fatal("the user ID text is not in the certificate: the test does not look for what it means to")
	}
	for name, in := range map[string][]byte{
		"a subkey":            cat(cert, wrap(tagSubkey, ps[1].Body)),
		"a second user ID":    cat(cert, ps[1].Raw),
		"a trailing byte":     cat(cert, []byte{1}),
		"a missing signature": cat(ps[0].Raw, ps[1].Raw),
		"a cut":               cert[:len(cert)-3],
	} {
		_, err := openpgp.SplitCertificate(in)
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		text := err.Error()
		for _, bad := range []string{"Example", "release@", "example.org", "TEST ONLY"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s: the text %q holds %q from the input", name, text, bad)
			}
		}
		checkErrorText(t, name, err)
	}
}

func TestSplitCertificateReturnsCopies(t *testing.T) {
	cert := newKeyringPrimary(t, "A", true).cert(t)
	in := bytes.Clone(cert)
	c, err := openpgp.SplitCertificate(in)
	if err != nil {
		t.Fatal(err)
	}
	// Changing the result changes nothing of the input.
	clear(c.Key)
	clear(c.UserID)
	for _, s := range c.Signatures {
		clear(s)
	}
	if !bytes.Equal(in, cert) {
		t.Error("changing the result changed the input")
	}
	// Changing the input after the call changes nothing of a new result.
	c2, err := openpgp.SplitCertificate(in)
	if err != nil {
		t.Fatal(err)
	}
	keep := bytes.Clone(c2.Key)
	clear(in)
	if !bytes.Equal(c2.Key, keep) {
		t.Error("changing the input changed the result")
	}
	// The three kinds do not share a backing array: appending to one does not reach the next.
	c3, err := openpgp.SplitCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	userBefore := bytes.Clone(c3.UserID)
	c3.Key = append(c3.Key[:len(c3.Key)], 9, 9, 9, 9)
	if !bytes.Equal(c3.UserID, userBefore) {
		t.Error("the key part shares memory with the user ID part")
	}
}

func TestSplitCertificateGivesTheSameAnswerTwice(t *testing.T) {
	cert := cat(newKeyringPrimary(t, "A", true).cert(t))
	a, errA := openpgp.SplitCertificate(cert)
	b, errB := openpgp.SplitCertificate(cert)
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	if !bytes.Equal(a.Key, b.Key) || !bytes.Equal(a.UserID, b.UserID) || len(a.Signatures) != len(b.Signatures) {
		t.Error("two calls on the same bytes give two answers")
	}
}

// The three walks over the packets of one certificate (SecretKey, ReadKeyring and SplitCertificate)
// agree on what the frame of a certificate of one signature is. SplitCertificate takes no more than the
// frame, so it accepts what the others refuse for the key or a signature; but where the
// difference is only the frame, all three give the same answer.
func TestTheThreeWalksOverACertificateAgreeOnTheFrame(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	good := m.cert(t)
	ps := splitPackets(t, good)
	key, uid, sig := ps[0].Raw, ps[1].Raw, ps[2].Raw
	other := newKeyringPrimary(t, "B", true)
	subkey := wrap(tagSubkey, keyBody(&other.key.PublicKey, created))
	second := m.extension(t, ceremony.AddDate(0, 1, 0))
	cases := []struct {
		name string
		in   []byte
		// one says that the frame holds exactly one signature, which is what SecretKey takes
		one bool
		ok  bool
	}{
		{"the certificate", good, true, true},
		{"the certificate in the old format", repack(t, good, "old2"), true, true},
		{"the certificate with five-octet lengths", repack(t, good, "new5"), true, true},
		{"two self-signatures", cat(good, second), false, true},
		{"no signature", cat(key, uid), true, false},
		{"a subkey after", cat(good, subkey), true, false},
		{"a second user ID", cat(good, uid), true, false},
		{"a trailing byte", cat(good, []byte{0}), true, false},
		{"the user ID first", cat(uid, key, sig), true, false},
		{"a cut", good[:len(good)-1], true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, splitErr := openpgp.SplitCertificate(c.in)
			if (splitErr == nil) != c.ok {
				t.Errorf("SplitCertificate accepts: %v, want %v (%v)", splitErr == nil, c.ok, splitErr)
			}
			_, ringErr := openpgp.ReadKeyring(c.in, []openpgp.KeyringEntry{m.entry()})
			if (ringErr == nil) != c.ok {
				t.Errorf("ReadKeyring accepts: %v, want %v (%v)", ringErr == nil, c.ok, ringErr)
			}
			if c.one {
				_, secretErr := openpgp.SecretKey(c.in, m.key)
				// SecretKey needs the key packet in the shortest form too, which is stricter than the frame:
				// it may refuse a certificate in another header form, and it must not accept one that the frame refuses.
				if secretErr == nil && !c.ok {
					t.Error("SecretKey accepts a certificate that the frame refuses")
				}
			}
		})
	}
}

// 257 valid certifications are a certificate that ReadKeyring refuses by count, as SplitCertificate does;
// 256 are accepted by both.
func TestSplitCertificateAndReadKeyringAgreeOnTheCountOfCertifications(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	sigs := make([][]byte, 0, openpgp.MaxCertifications+1)
	for range openpgp.MaxCertifications + 1 {
		sigs = append(sigs, m.extension(t, ceremony))
	}
	for _, n := range []int{openpgp.MaxCertifications, openpgp.MaxCertifications + 1} {
		in := m.assemble(sigs[:n]...)
		_, splitErr := openpgp.SplitCertificate(in)
		_, ringErr := openpgp.ReadKeyring(in, []openpgp.KeyringEntry{m.entry()})
		if (splitErr == nil) != (n == openpgp.MaxCertifications) || (ringErr == nil) != (n == openpgp.MaxCertifications) {
			t.Errorf("%d certifications: SplitCertificate error %v, ReadKeyring error %v; want both to accept exactly %d", n, splitErr, ringErr, openpgp.MaxCertifications)
		}
	}
}
