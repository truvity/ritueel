package openpgp_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// ReadForeignCertificate accepts a certificate only when the reader would write it as it stands. The
// accepted case is the certificate of every key of the kit; each refusal changes one thing in it.

// fkReadCertificate reads a certificate against its own SHA-256, which is how a test that is not about the
// digest reads one.
func fkReadCertificate(cert []byte) (*openpgp.ForeignKey, error) {
	return openpgp.ReadForeignCertificate(cert, fkDigest(cert))
}

// fkDigest is the digest of a certificate as a record would hold it. A test makes it from the bytes it has
// just made; the code under test cannot.
func fkDigest(cert []byte) openpgp.HeldDigest {
	sum := sha256.Sum256(cert)
	d, err := openpgp.ParseHeldDigest(hex.EncodeToString(sum[:]))
	if err != nil {
		panic(err)
	}
	return d
}

// fkCertParts is the certificate of a template as its packets.
func fkCertParts(t testing.TB, b *fkBase) []fkPacket {
	t.Helper()
	return fkSplit(t, fkRead(t, b.plain).Certificate())
}

// fkCertRefused reads a certificate that must be refused with ErrAdoptedCertificate and, as every
// refusal of a certificate is, with ErrForeignKey, and returns no key.
func fkCertRefused(t testing.TB, what string, cert []byte, b *fkBase, kinds ...error) error {
	t.Helper()
	k, err := fkReadCertificate(cert)
	if err == nil {
		t.Errorf("%s: the certificate was read, want a refusal", what)
		return nil
	}
	if k != nil {
		t.Errorf("%s: a key is returned with the error %v", what, err)
	}
	if !errors.Is(err, openpgp.ErrForeignKey) {
		t.Errorf("%s: %v is not an ErrForeignKey", what, err)
	}
	for _, kind := range kinds {
		if !errors.Is(err, kind) {
			t.Errorf("%s: %v is not the kind %v", what, err, kind)
		}
	}
	fkCheckText(t, what, err, b)
	return err
}

func TestReadForeignCertificateAcceptsTheCertificateOfAnExport(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		export := fkRead(t, b.plain)
		cert := export.Certificate()
		k, err := fkReadCertificate(cert)
		if err != nil {
			t.Fatalf("ReadForeignCertificate: %v", err)
		}
		if !bytes.Equal(k.Certificate(), cert) {
			t.Error("the certificate of the key is not the input")
		}
		// the view is the export's, but for what only a file with a secret has
		if k.Primary.Fingerprint != export.Primary.Fingerprint || k.Primary.Algorithm != export.Primary.Algorithm ||
			!k.Primary.Created.Equal(export.Primary.Created) || k.Primary.Revoked != export.Primary.Revoked {
			t.Errorf("the primary of the certificate is %+v, the export's is %+v", k.Primary, export.Primary)
		}
		if len(k.UserIDs) != len(export.UserIDs) || len(k.Subkeys) != len(export.Subkeys) || len(k.KeySignatures) != len(export.KeySignatures) {
			t.Errorf("the view of the certificate has %d user IDs, %d subkeys and %d key signatures, the export's %d, %d and %d",
				len(k.UserIDs), len(k.Subkeys), len(k.KeySignatures), len(export.UserIDs), len(export.Subkeys), len(export.KeySignatures))
		}
		for i, s := range k.Subkeys {
			if !s.InCertificate || s.Form != openpgp.SubkeyPublic || s.Fingerprint != export.Subkeys[i].Fingerprint {
				t.Errorf("subkey %d of the certificate: %+v", i, s)
			}
		}
		if k.OtherKeySignatures != 0 || k.OtherKeyRevocations != 0 || k.DuplicatesDropped != 0 || k.UnreadableRevocations != 0 || k.UserAttributesLeftOut != 0 {
			t.Errorf("the counts of what is left out are not zero in a certificate: %+v", k)
		}
		for i, u := range k.UserIDs {
			if u.Certifications != 0 || u.OtherSignatures != 0 || u.OtherRevocations != 0 || u.UnreadableRevocations != 0 {
				t.Errorf("user ID %d of the certificate has counts of what is left out: %+v", i, u)
			}
		}
		// a key with no secret: no state, no cipher, nothing to open, a wipe that clears nothing
		if k.Primary.Secret != 0 || k.Primary.Secret.String() == "unprotected" || k.Primary.Cipher != "" {
			t.Errorf("a certificate has a secret state: %q %q", k.Primary.Secret, k.Primary.Cipher)
		}
		s, err := k.OpenSecret(nil)
		if s != nil || !errors.Is(err, openpgp.ErrParams) {
			t.Errorf("OpenSecret of a certificate: %v, %v", s, err)
		}
		k.Wipe()
		// the export reads no certificate as an export: a public key packet has no secret
		if _, err := openpgp.ReadForeignKey(cert); !errors.Is(err, openpgp.ErrForeignNoSecret) {
			t.Errorf("ReadForeignKey of a certificate: %v", err)
		}
	})
}

func TestReadForeignCertificateRefusesWhatTheReaderWouldNotWrite(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		ps := fkCertParts(t, b)
		if len(ps) < 4 || ps[0].Tag != 6 || ps[1].Tag != 13 || ps[2].Tag != 2 {
			t.Fatalf("the certificate of the template is not a primary, a user ID, a signature and a subkey")
		}
		join := func(parts ...[]fkPacket) []byte {
			var all []fkPacket
			for _, p := range parts {
				all = append(all, p...)
			}
			return fkJoin(all...)
		}
		one := func(p fkPacket) []fkPacket { return []fkPacket{p} }
		sigBody := ps[2].Body

		// a copy of the self-signature with an unhashed subpacket more, which no signature covers
		extra := bytes.Clone(sigBody)
		hl := int(extra[4])<<8 | int(extra[5])
		ul := int(extra[6+hl])<<8 | int(extra[7+hl])
		note := fkSubpacket(26, false, []byte("https://example.org/policy")...)
		withExtra := slices.Concat(extra[:6+hl], []byte{byte((ul + len(note)) >> 8), byte(ul + len(note))}, extra[8+hl:8+hl+ul], note, extra[8+hl+ul:])

		// the signature of another key on the user ID of the primary
		_, _, other := fkDonors(t)
		foreign := fkSplit(t, b.certSig(t, other, b.ent.PrimaryKey, fkUser, fkSigSpec{Typ: gpacket.SigTypeGenericCert}))

		// the secret subkey packet of the export
		var secretSub fkPacket
		for _, p := range fkSplit(t, b.plain) {
			if p.Tag == 7 {
				secretSub = p
				break
			}
		}
		badSub := bytes.Clone(ps[len(ps)-1].Body)
		badSub[len(badSub)-1] ^= 1

		cases := []struct {
			name  string
			cert  []byte
			kinds []error
		}{
			{"a trust packet", join(ps[:1], one(fkPacket{12, []byte{1, 2}}), ps[1:]), []error{openpgp.ErrAdoptedCertificate}},
			{"a marker packet", join(one(fkPacket{10, []byte("PGP")}), ps), []error{openpgp.ErrAdoptedCertificate}},
			{"a header that is not the shortest", slices.Concat(wrapLong(6, ps[0].Body), fkJoin(ps[1:]...)), []error{openpgp.ErrAdoptedCertificate}},
			{"an old format header", slices.Concat(fkJoin(ps[0]), []byte{0x80 | 13<<2, byte(len(ps[1].Body))}, ps[1].Body, fkJoin(ps[2:]...)), []error{openpgp.ErrAdoptedCertificate}},
			{"the export, with its secret key packet", b.plain, []error{openpgp.ErrAdoptedCertificate}},
			{"a secret subkey packet", join(ps, one(secretSub)), []error{openpgp.ErrAdoptedCertificate}},
			{"an unhashed subpacket that the reader does not write", join(ps[:2], one(fkPacket{2, withExtra}), ps[3:]), []error{openpgp.ErrAdoptedCertificate}},
			{"a signature of another key", join(ps[:3], foreign, ps[3:]), []error{openpgp.ErrAdoptedCertificate}},
			{"a user ID twice", join(ps[:3], ps[1:3], ps[3:]), []error{openpgp.ErrAdoptedCertificate}},
			{"a user ID with no signature", join(ps[:3], one(fkPacket{13, []byte("Nobody <nobody@example.org>")}), ps[3:]), []error{openpgp.ErrAdoptedCertificate}},
			{"a subkey whose binding does not verify", join(ps[:len(ps)-1], one(fkPacket{2, badSub})), []error{openpgp.ErrAdoptedCertificate}},
			{"a subkey with no signature", join(ps, one(fkPacket{14, ps[3].Body})), []error{openpgp.ErrAdoptedCertificate}},
			{"a user ID after a subkey", join(ps[:3], ps[3:5], ps[1:3], ps[5:]), []error{openpgp.ErrForeignForm}},
			{"a second primary", slices.Concat(fkJoin(ps...), fkJoin(ps...)), []error{openpgp.ErrForeignPrimaries}},
			{"only the primary", fkJoin(ps[0]), []error{openpgp.ErrForeignSelfSignature}},
			{"a self-signature that does not verify", join(ps[:2], one(fkPacket{2, func() []byte { s := bytes.Clone(sigBody); s[len(s)-1] ^= 1; return s }()}), ps[3:]), []error{openpgp.ErrForeignSelfSignature}},
			{"a signature first", fkJoin(ps[2]), []error{openpgp.ErrAdoptedCertificate}},
			{"a certificate cut short", fkJoin(ps...)[:len(fkJoin(ps...))-1], []error{openpgp.ErrForeignForm}},
			{"a certificate with a byte after it", append(fkJoin(ps...), 0), []error{openpgp.ErrForeignForm}},
			{"armour", fkArmour(t, fkJoin(ps...), "PGP PUBLIC KEY BLOCK", nil), []error{openpgp.ErrForeignForm}},
			{"nothing", nil, []error{openpgp.ErrForeignForm}},
			{"more bytes than the limit", make([]byte, openpgp.MaxForeignKeyBytes+1), []error{openpgp.ErrForeignLimit}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				_ = fkCertRefused(t, c.name, c.cert, b, c.kinds...)
			})
		}
	})
}

// The limits of the reader are held before any signature is verified, as they are for an export.
func TestReadForeignCertificateHoldsTheLimitsBeforeAnyVerification(t *testing.T) {
	b := fkNamed(t, "ed25519")
	ps := fkCertParts(t, b)
	sig := fkJoin(ps[2])

	// more packets than MaxForeignPackets
	many := append(fkJoin(ps[:2]...), bytes.Repeat(sig, openpgp.MaxForeignPackets)...)
	_ = fkCertRefused(t, "more packets than the limit", many, b, openpgp.ErrForeignLimit)

	// more signatures that the primary has to answer for than MaxForeignClaimedSignatures, spread so that
	// no component has more than MaxForeignSignatures
	var claimed []byte
	claimed = append(claimed, fkJoin(ps[0])...)
	for i := 0; i < 3; i++ {
		claimed = append(claimed, fkJoin(fkPacket{13, []byte{byte('A' + i)}})...)
		claimed = append(claimed, bytes.Repeat(sig, 700)...)
	}
	_ = fkCertRefused(t, "more claimed signatures than the limit", claimed, b, openpgp.ErrForeignLimit)

	// more user IDs than MaxForeignUserIDs
	var ids []byte
	ids = append(ids, fkJoin(ps[0])...)
	for i := 0; i <= openpgp.MaxForeignUserIDs; i++ {
		ids = append(ids, fkJoin(fkPacket{13, []byte{byte('A' + i)}})...)
	}
	_ = fkCertRefused(t, "more user IDs than the limit", ids, b, openpgp.ErrForeignLimit)

	// a user ID packet longer than MaxForeignUserIDBytes
	long := slices.Concat(fkJoin(ps[0]), fkJoin(fkPacket{13, make([]byte, openpgp.MaxForeignUserIDBytes+1)}))
	_ = fkCertRefused(t, "a user ID longer than the limit", long, b, openpgp.ErrForeignLimit)
}

// The certificate is read only against the digest that the caller holds, and the digest is compared before
// anything is parsed: a certificate with a newest self-signature taken out is a certificate that the reader
// would write, and only the digest tells it from the whole one.
func TestReadForeignCertificateIsReadOnlyAgainstItsDigest(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		export := fkRead(t, fkRichOf(t, b, false, true).file)
		cert := export.Certificate()
		digest := fkDigest(cert)
		if _, err := openpgp.ReadForeignCertificate(cert, digest); err != nil {
			t.Fatalf("the certificate against its digest: %v", err)
		}

		// the same certificate with a key revocation of the primary taken out is still a fixpoint, and it
		// is refused against the digest of the whole one
		ps := fkSplit(t, cert)
		var cut []fkPacket
		taken := 0
		for _, p := range ps {
			if p.Tag == 2 && len(cut) > 0 && taken == 0 && cut[len(cut)-1].Tag == 6 {
				taken++ // a signature right after the primary: a key signature
				continue
			}
			cut = append(cut, p)
		}
		if taken == 0 {
			t.Fatal("the rich certificate has no signature on the key")
		}
		short := fkJoin(cut...)
		if _, err := fkReadCertificate(short); err != nil {
			t.Fatalf("the certificate with a signature of the key taken out is not read against its own digest: %v", err)
		}
		k, err := openpgp.ReadForeignCertificate(short, digest)
		if k != nil || !errors.Is(err, openpgp.ErrAdoptedCertificate) {
			t.Errorf("a shortened certificate against the digest of the whole one: %v", err)
		}

		// the digest is compared before anything is parsed: a mismatch of garbage is an
		// ErrAdoptedCertificate and not a fault of the packets
		_, err = openpgp.ReadForeignCertificate([]byte{1, 2, 3}, digest)
		if !errors.Is(err, openpgp.ErrAdoptedCertificate) {
			t.Errorf("garbage against a digest: %v", err)
		}
		if _, err = openpgp.ReadForeignCertificate(cert, openpgp.HeldDigest{}); !errors.Is(err, openpgp.ErrParams) {
			t.Errorf("a certificate against no digest: %v", err)
		}
	})
}

// A held digest is made only from the text of a record: 64 lower-case hexadecimal digits.
func TestParseHeldDigest(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	d, err := openpgp.ParseHeldDigest(good)
	if err != nil || d.String() != good {
		t.Fatalf("a digest of 64 lower-case digits: %q, %v", d.String(), err)
	}
	if (openpgp.HeldDigest{}).String() != "" {
		t.Error("the zero digest has a text")
	}
	for name, text := range map[string]string{
		"empty":       "",
		"upper case":  strings.ToUpper(good),
		"one short":   good[1:],
		"one long":    good + "0",
		"not hex":     good[:63] + "g",
		"a space":     good[:63] + " ",
		"a newline":   good + "\n",
		"a prefix":    "sha256:" + good,
		"zeros":       strings.Repeat("0", 64),
		"a wide hexa": strings.Repeat("\uff10", 64),
	} {
		d, err := openpgp.ParseHeldDigest(text)
		if err == nil || !errors.Is(err, openpgp.ErrParams) || d != (openpgp.HeldDigest{}) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "0123456789") {
			t.Errorf("%s: the error holds the text: %v", name, err)
		}
	}
}
