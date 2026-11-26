package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	gecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// J. Two fuzz targets. The seeds are made in code from keys that go-crypto writes at run time: no
// file of a key is committed. The checks hold for every input: no panic (the reader recovers one and
// says so in its text, and that text is a failure here), a refusal or a key, never both, and the
// certificate of a key is whole packets with no secret in it.

// fkFuzzSeeds are files that the targets start from.
func fkFuzzSeeds(f *testing.F) [][]byte {
	var out [][]byte
	for _, b := range fkBases(f) {
		for _, prot := range []fkProt{{}, {Pass: fkPass}} {
			file := b.file(f, prot)
			out = append(out, file, fkArmourKey(f, file))
		}
	}
	return out
}

// fkDecoded is the packets of a file that may be armoured, or nil if the file is not whole packets.
func fkDecoded(in []byte) []byte {
	if !bytes.HasPrefix(in, []byte("-----BEGIN")) {
		return in
	}
	blk, err := armor.Decode(bytes.NewReader(in))
	if err != nil {
		return nil
	}
	out, err := io.ReadAll(blk.Body)
	if err != nil {
		return nil
	}
	return out
}

// fkSamePublic tells whether a key is the key of a public key packet that go-crypto read.
func fkSamePublic(s crypto.Signer, pk *gpacket.PublicKey) bool {
	switch want := pk.PublicKey.(type) {
	case *rsa.PublicKey:
		got, ok := s.Public().(*rsa.PublicKey)
		return ok && got.N.Cmp(want.N) == 0 && got.E == want.E
	case *eddsa.PublicKey:
		got, ok := s.Public().(ed25519.PublicKey)
		return ok && bytes.Equal(got, want.X)
	case *gecdsa.PublicKey:
		got, ok := s.Public().(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		raw, err := got.Bytes()
		wantRaw := append([]byte{4}, want.X.FillBytes(make([]byte, 48))...)
		wantRaw = append(wantRaw, want.Y.FillBytes(make([]byte, 48))...)
		return err == nil && bytes.Equal(raw, wantRaw)
	}
	return false
}

// fkPlainText holds an error text to what a person can read.
func fkPlainText(t *testing.T, err error) {
	t.Helper()
	text := err.Error()
	if strings.Contains(text, "could not be read") {
		t.Fatalf("the reader recovered a panic: %v", err)
	}
	if len(text) > 600 {
		t.Fatalf("the text of the error is %d bytes", len(text))
	}
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] > 0x7E {
			t.Fatalf("the text of the error holds the byte %#x: %q", text[i], text)
		}
	}
}

func FuzzForeignReadKey(f *testing.F) {
	seeds := fkFuzzSeeds(f)
	for _, s := range seeds {
		f.Add(s)
	}
	for _, b := range fkBases(f) {
		for _, protected := range []bool{false, true} {
			f.Add(fkRichOf(f, b, protected, true).file)
			if b.name != "rsa4096" {
				f.Add(fkRichOf(f, b, protected, false).file)
			}
		}
	}
	// secret subkeys in every form, and the subkeys of a stretched length field
	for _, c := range fkCraftedSeeds(f) {
		f.Add(c)
	}
	for _, a := range append(fkReviewerAttacks(f), fkRelabelledAttacks(f)...) {
		f.Add(a.file)
	}
	f.Add([]byte{})
	f.Add([]byte{0xC5, 0xE0})
	f.Add([]byte{0x80 | 5<<2 | 3})
	f.Add(append([]byte("-----BEGIN "+fkPrivateBlock()+"-----\n\n"), "AAAA\n-----END "+fkPrivateBlock()+"-----\n"...))
	f.Fuzz(func(t *testing.T, in []byte) {
		before := bytes.Clone(in)
		k, err := openpgp.ReadForeignKey(in)
		if !bytes.Equal(in, before) {
			t.Fatal("ReadForeignKey changed its input")
		}
		if err != nil {
			if k != nil {
				t.Fatalf("a key is returned with the error %v", err)
			}
			if !errors.Is(err, openpgp.ErrForeignKey) {
				t.Fatalf("an error that is not an ErrForeignKey: %v", err)
			}
			fkPlainText(t, err)
			return
		}
		if k == nil {
			t.Fatal("no key and no error")
		}
		if len(k.UserIDs) > openpgp.MaxForeignUserIDs || len(k.Subkeys) > openpgp.MaxForeignSubkeys {
			t.Fatalf("%d user IDs and %d subkeys are more than the limits", len(k.UserIDs), len(k.Subkeys))
		}
		if len(k.Primary.Fingerprint) != 40 || k.Primary.KeyID != k.Primary.Fingerprint[24:] {
			t.Fatalf("fingerprint %q and key ID %q", k.Primary.Fingerprint, k.Primary.KeyID)
		}
		if (k.Primary.Secret != openpgp.SecretUnprotected && k.Primary.Secret != openpgp.SecretProtected) ||
			(k.Primary.Secret == openpgp.SecretProtected) != (k.Primary.Cipher != "") {
			t.Fatalf("secret %v with cipher %q", k.Primary.Secret, k.Primary.Cipher)
		}
		valid := 0
		for _, u := range k.UserIDs {
			if u.Valid {
				valid++
			}
		}
		if valid == 0 {
			t.Fatal("a key with no user ID that has a valid self-signature")
		}

		// The certificate: whole packets, the primary first, no secret packet, a copy.
		cert := k.Certificate()
		ctags, cbodies, ok := softPackets(cert)
		if !ok || len(ctags) == 0 || ctags[0] != 6 {
			t.Fatalf("the certificate is not whole packets that start with a public key")
		}
		pk, err := gpacket.Read(bytes.NewReader(wrap(6, cbodies[0])))
		if err != nil {
			t.Fatalf("go-crypto does not read the primary of the certificate: %v", err)
		}
		if got, ok := pk.(*gpacket.PublicKey); !ok || hexOf(got.Fingerprint) != k.Primary.Fingerprint {
			t.Fatalf("the primary of the certificate is not the primary of the key")
		}
		for _, tag := range ctags {
			if tag == 5 || tag == 7 || tag == 10 || tag == 12 {
				t.Fatalf("the certificate holds a packet of tag %d", tag)
			}
		}
		cert[0] ^= 0xFF
		if bytes.Equal(cert, k.Certificate()) {
			t.Fatal("Certificate does not return a copy")
		}
		cert = k.Certificate()

		// no secret region of the input is in the certificate, unless a packet that is copied holds it
		if packets := fkDecoded(in); packets != nil {
			tags, bodies, ok := softPackets(packets)
			if !ok {
				t.Fatal("the reader takes a file that is not whole packets")
			}
			var kept []byte
			for i, tag := range tags {
				if tag != 5 && tag != 7 && tag != 10 && tag != 12 {
					kept = append(kept, bodies[i]...)
				}
			}
			next := 0
			for i, tag := range tags {
				if tag != 5 && tag != 7 && tag != 6 && tag != 14 {
					continue
				}
				if next >= len(cbodies) {
					break
				}
				// the key packets of the certificate are those of the file, in order, but a subkey
				// of an algorithm that is not delimited is only possible public
				cb := cbodies[next]
				next++
				for next < len(ctags) && ctags[next] != 6 && ctags[next] != 14 {
					next++
				}
				if tag == 5 || tag == 7 {
					if !bytes.HasPrefix(bodies[i], cb) {
						t.Fatalf("a key packet of the certificate is not the public part of the secret key packet")
					}
					region := bodies[i][len(cb):]
					if len(region) >= 8 && bytes.Contains(cert, region) && !bytes.Contains(kept, region) {
						t.Fatalf("the certificate holds the secret region of a key packet")
					}
					// and no run of it beyond its first two bytes, unless the public part or a packet
					// that is copied holds the same run
					if len(region) > 2 {
						if where, bad := fkLeaksExcept(cert, append(bytes.Clone(kept), bodies[i][:len(cb)]...), region[2:]); bad {
							t.Fatalf("the certificate holds a run of the secret region of a key packet (%s)", where)
						}
					}
				}
			}
		}

		// OpenSecret on whatever the file is: a key that matches, or a named error, and no panic
		for _, pass := range [][]byte{nil, []byte(fkPass), []byte("not it")} {
			s, err := k.OpenSecret(pass)
			if err != nil {
				if s != nil {
					t.Fatal("a key with an error")
				}
				if !errors.Is(err, openpgp.ErrWrongPassphrase) && !errors.Is(err, openpgp.ErrForeignSecret) {
					t.Fatalf("OpenSecret: an error of no kind that is named: %v", err)
				}
				fkPlainText(t, err)
				continue
			}
			if !fkSamePublic(s.Signer(), pk.(*gpacket.PublicKey)) {
				t.Fatal("OpenSecret returned a key that is not the key of the file")
			}
			s.Wipe()
		}
		k.Wipe()
		if s, err := k.OpenSecret(nil); s != nil || !errors.Is(err, openpgp.ErrParams) {
			t.Fatalf("OpenSecret after the wipe: %v", err)
		}
	})
}

func FuzzForeignOpenSecret(f *testing.F) {
	for _, s := range fkFuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		k, err := openpgp.ReadForeignKey(in)
		if err != nil {
			fkPlainText(t, err)
			return
		}
		pk, err := gpacket.Read(bytes.NewReader(wrap(6, softBody(t, k.Certificate()))))
		if err != nil {
			t.Fatalf("go-crypto does not read the primary: %v", err)
		}
		s, err := k.OpenSecret([]byte(fkPass))
		if err != nil {
			if s != nil {
				t.Fatal("a key with an error")
			}
			if !errors.Is(err, openpgp.ErrWrongPassphrase) && !errors.Is(err, openpgp.ErrForeignSecret) {
				t.Fatalf("an error of no kind that is named: %v", err)
			}
			fkPlainText(t, err)
			return
		}
		if !fkSamePublic(s.Signer(), pk.(*gpacket.PublicKey)) {
			t.Fatal("the key that opened is not the public key of the file")
		}
		// it signs, and the signature verifies with the public key of go-crypto
		fkSignAndVerifyQuiet(t, s.Signer(), pk.(*gpacket.PublicKey))
		s.Wipe()
	})
}

// softBody is the body of the first packet of a certificate.
func softBody(t *testing.T, cert []byte) []byte {
	t.Helper()
	tag, body, _, ok := softPacket(cert)
	if !ok || tag != 6 {
		t.Fatal("the certificate does not start with a public key packet")
	}
	return body
}

// fkSignAndVerifyQuiet is fkSignAndVerify for the fuzz target.
func fkSignAndVerifyQuiet(t *testing.T, s crypto.Signer, pk *gpacket.PublicKey) {
	t.Helper()
	d := sha256.Sum256([]byte("fuzz"))
	switch s.Public().(type) {
	case *rsa.PublicKey:
		sig, err := s.Sign(rand.Reader, d[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("the key does not sign: %v", err)
		}
		if rsa.VerifyPKCS1v15(pk.PublicKey.(*rsa.PublicKey), crypto.SHA256, d[:], sig) != nil {
			t.Fatal("the signature does not verify")
		}
	case ed25519.PublicKey:
		sig, err := s.Sign(rand.Reader, d[:], crypto.Hash(0))
		if err != nil || !ed25519.Verify(ed25519.PublicKey(pk.PublicKey.(*eddsa.PublicKey).X), d[:], sig) {
			t.Fatalf("the key does not sign a signature that verifies: %v", err)
		}
	case *ecdsa.PublicKey:
		sig, err := s.Sign(rand.Reader, d[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("the key does not sign: %v", err)
		}
		if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), d[:], sig) {
			t.Fatal("the signature does not verify")
		}
	}
}

// fkLeaksExcept is fkLeaks for the fuzz targets: a run of twelve bytes of the data that is in hay and not
// in except, where the run is not a run of one or two values (a block of zeros stands in many packets).
func fkLeaksExcept(hay, except, data []byte) (string, bool) {
	const w = 12
	for j := 0; j+w <= len(data); j++ {
		run := data[j : j+w]
		seen := map[byte]bool{}
		for _, c := range run {
			seen[c] = true
		}
		if len(seen) < 4 {
			continue
		}
		if bytes.Contains(hay, run) && !bytes.Contains(except, run) {
			return fmt.Sprintf("offset %d", j), true
		}
	}
	return "", false
}

// fkCraftedSeeds are files with a secret subkey whose public part has a length field that claims more
// than it has, and the same subkeys as they are, for each algorithm.
func fkCraftedSeeds(f *testing.F) [][]byte {
	b := fkNamed(f, "ed25519")
	enc, sig, _ := fkDonors(f)
	var out [][]byte
	for _, usage := range []byte{0, 254, 255} {
		for _, s := range []fkSubSecret{
			fkRSASub(f, 3, usage), fkRSASub(f, 257, usage), fkRSASub(f, 65537, usage),
			fkFakeSub(f, 17, usage), fkFakeSub(f, 16, usage),
			fkRealSub(f, "ECDH", enc[0].pub, enc[0].sec, usage, 6, 33, true),
			fkRealSub(f, "EdDSA", sig[0].pub, sig[0].sec, usage, 6, 33, false),
		} {
			out = append(out, s.bound(f, b, s.body))
			for _, k := range []int{1, 3, 8} {
				out = append(out, s.bound(f, b, s.stretch(s.last, k)))
			}
		}
	}
	return out
}

// The third target: a valid file with a secret subkey, of which only the bytes of the public part of the
// subkey packet are mutated (its version, time, algorithm and length fields and numbers). Whatever the
// reader makes of it, the certificate holds no run of the secret area that follows, except a run that the
// public part itself holds.
func FuzzForeignSubkeyPublicPart(f *testing.F) {
	b := fkNamed(f, "ed25519")
	enc, sig, _ := fkDonors(f)
	var areas, pubs [][]byte
	var bindings []fkPacket
	for _, usage := range []byte{0, 254, 255} {
		for _, s := range []fkSubSecret{
			fkRSASub(f, 3, usage), fkRSASub(f, 17, usage), fkRSASub(f, 257, usage), fkRSASub(f, 65537, usage),
			fkFakeSub(f, 17, usage), fkFakeSub(f, 16, usage),
			fkRealSub(f, "ECDH", enc[0].pub, enc[0].sec, usage, 6, 33, true),
			fkRealSub(f, "EdDSA", sig[0].pub, sig[0].sec, usage, 6, 33, false),
		} {
			bindings = append(bindings, fkBinding(f, b, s.body[:s.pubLen]))
			areas = append(areas, bytes.Clone(s.area()))
			pubs = append(pubs, bytes.Clone(s.body[:s.pubLen]))
		}
	}
	for i := range areas {
		f.Add(pubs[i], uint8(i))
		// the length field at the end raised by one to eight bytes
		for _, k := range []int{1, 2, 3, 8} {
			p := bytes.Clone(pubs[i])
			if len(p) > 8 {
				// the last MPI header: found from its end by the caller of the seed, not known here, so the
				// header of the first number is stretched too
				bits := int(p[6])<<8 | int(p[7]) + 8*k
				p[6], p[7] = byte(bits>>8), byte(bits)
			}
			f.Add(p, uint8(i))
		}
	}
	head := fkTemplateHead(f, b.file(f, fkProt{}))
	f.Fuzz(func(t *testing.T, pub []byte, sel uint8) {
		area := areas[int(sel)%len(areas)]
		body := append(bytes.Clone(pub), area...)
		file := fkJoin(append(slicesClone(head), fkPacket{7, body}, bindings[int(sel)%len(areas)])...)
		k, err := openpgp.ReadForeignKey(file)
		if err != nil {
			if k != nil || !errors.Is(err, openpgp.ErrForeignKey) {
				t.Fatalf("an error that is not a refusal of the file, or a key with it: %v", err)
			}
			fkPlainText(t, err)
			return
		}
		cert := k.Certificate()
		ctags, bodies, ok := softPackets(cert)
		if !ok {
			t.Fatal("the certificate is not whole packets")
		}
		for i, tag := range ctags {
			if tag == 14 && len(k.Subkeys) == 1 && k.Subkeys[0].Form != openpgp.SubkeyPublic {
				sub := bodies[i]
				if !bytes.HasPrefix(body, sub) {
					t.Fatal("the subkey of the certificate is not the start of the secret subkey packet")
				}
				if len(sub) > len(pub)+2 {
					t.Fatalf("the subkey of the certificate takes %d bytes of the secret area", len(sub)-len(pub))
				}
			}
		}
		if len(area) > 2 {
			if where, bad := fkLeaksExcept(cert, pub, area[2:]); bad {
				t.Fatalf("the certificate holds a run of the secret area (%s)", where)
			}
		}
	})
}
