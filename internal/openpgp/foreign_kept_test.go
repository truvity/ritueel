package openpgp_test

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/verifier"
)

// What the certificate keeps. The rich file is a real-looking key: several user IDs (one revoked, one with
// only a SHA-1 self-signature), a photograph with a valid self-signature, a direct-key signature, a key
// revocation, a signing subkey with its back-signature, encryption subkeys, an expired subkey, a revoked
// subkey and a stub. The certificate is read by go-crypto as a key ring and must hold what a person needs,
// and what the reader loses must be what has no signature of the primary.

func TestForeignCertificateKeepsWhatAPersonNeeds(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, protected := range []bool{false, true} {
			name := "unprotected"
			if protected {
				name = "protected"
			}
			t.Run(name, func(t *testing.T) {
				r := fkRichKept(t, b, protected)
				k := fkRead(t, r.file)
				secrets := append(slices.Clone(r.numbers), r.regions...)
				ps := fkCertProperty(t, "the rich key", k, secrets...)

				ents, err := pgp.ReadKeyRing(bytes.NewReader(k.Certificate()))
				if err != nil || len(ents) != 1 {
					t.Fatalf("go-crypto does not read the certificate as a key ring: %v (%d keys)", err, len(ents))
				}
				e := ents[0]
				if hex.EncodeToString(e.PrimaryKey.Fingerprint) != k.Primary.Fingerprint {
					t.Error("another primary")
				}
				// exactly the user IDs that have a valid self-signature
				want := map[string]bool{}
				for _, u := range k.UserIDs {
					if u.Valid {
						want[u.Text] = true
					}
				}
				got := map[string]bool{}
				for n := range e.Identities {
					got[n] = true
				}
				if len(got) != len(want) {
					t.Errorf("the user IDs of the key ring are %v, those with a valid self-signature %v", got, want)
				}
				for n := range want {
					if !got[n] {
						t.Errorf("the user ID %q is not in the key ring", n)
					}
				}
				// exactly the subkeys that have a valid binding, with their fingerprints, in order
				var wantSubs []string
				for _, s := range k.Subkeys {
					if s.InCertificate {
						wantSubs = append(wantSubs, s.Fingerprint)
					}
				}
				var gotSubs []string
				for _, s := range e.Subkeys {
					gotSubs = append(gotSubs, hex.EncodeToString(s.PublicKey.Fingerprint))
				}
				if !slices.Equal(gotSubs, wantSubs) {
					t.Errorf("the subkeys of the key ring %v, those with a binding %v", gotSubs, wantSubs)
				}
				// the revocations: the key's, the subkey's, and the back-signature of the signing subkey
				if len(e.Revocations) != 1 {
					t.Errorf("%d key revocations in the key ring, want the 1 of the primary", len(e.Revocations))
				}
				revoked, backed := 0, 0
				for _, s := range e.Subkeys {
					fp := hex.EncodeToString(s.PublicKey.Fingerprint)
					if len(s.Revocations) > 0 && fp == hex.EncodeToString(r.donor["revoked"].pair.pub.Fingerprint) {
						revoked++
					}
					if fp == hex.EncodeToString(r.donor["backsig"].pair.pub.Fingerprint) && s.Sig != nil && s.Sig.EmbeddedSignature != nil {
						backed++
					}
				}
				if revoked != 1 {
					t.Errorf("the revocation of the revoked subkey is not in the key ring")
				}
				if backed != 1 {
					t.Errorf("the back-signature of the signing subkey is not in the key ring")
				}
				// the photograph, with its self-signature that verified (fkCertProperty verified it)
				if n := len(fkCertTagsOf(ps, 17)); n != 1 || k.UserAttributes != 2 || k.UserAttributesLeftOut != 1 {
					t.Errorf("%d photographs in the certificate, %d in the file, %d left out; want 1, 2 and 1", n, k.UserAttributes, k.UserAttributesLeftOut)
				}
				// the direct-key signature and the key revocation are written, and a SHA-1 only user ID is kept
				types := map[byte]int{}
				for _, p := range ps[1:] {
					if p.tag == 2 {
						types[p.body[1]]++
					}
				}
				if types[0x1F] != 1 || types[0x20] != 1 {
					t.Errorf("signatures of the key in the certificate: %v", types)
				}
				if !slices.Contains(fkCertUsers(ps), r.uidText["weak"]) {
					t.Error("the user ID with only a SHA-1 self-signature is not in the certificate")
				}
				if slices.Contains(fkCertUsers(ps), r.uidText["tampered"]) || slices.Contains(fkCertUsers(ps), r.uidText["bare"]) {
					t.Error("a user ID with no valid self-signature is in the certificate")
				}
			})
		}
	})
}

// The certificate of a key is read by the tools that verify signatures: a message that the signing subkey
// signed now is accepted by gpgv and by sqv with only the certificate that the reader wrote.
func TestForeignCertificateIsReadByGpgvAndSqv(t *testing.T) {
	msg := []byte("the release of example.org version 1.2.3\n")
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		file := b.file(t, fkProt{Pass: fkPass})
		k := fkRead(t, file)
		cert := k.Certificate()
		now := time.Now().UTC().Truncate(time.Second)
		cfg := *b.cfg
		cfg.Time = func() time.Time { return now.Add(-time.Hour) }
		var sig bytes.Buffer
		if err := pgp.DetachSign(&sig, b.ent, bytes.NewReader(msg), &cfg); err != nil {
			t.Fatalf("sign the message: %v", err)
		}
		if err := verifier.GPGVVerify(t, cert, sig.Bytes(), msg, k.Primary.Fingerprint); err != nil {
			t.Errorf("gpgv: %v", err)
		}
		if err := verifier.SQVVerify(t, cert, sig.Bytes(), msg, k.Primary.Fingerprint, now); err != nil {
			t.Errorf("sqv: %v", err)
		}
	})
}

var _ = openpgp.ErrForeignKey
