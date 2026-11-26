package openpgp_test

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// F. Every refusal of ReadForeignKey, with its kind, its parent kind, no key, and a text that names
// the case and holds no byte of a secret, no passphrase and no user ID. H is the same check of every
// text here: each case runs with an unprotected and with a protected file.

// fkCase is a refusal: the file is made from a template and a protection.
type fkCase struct {
	name  string
	file  func(t testing.TB, b *fkBase, prot fkProt) []byte
	kinds []error
	words []string
}

// fkRefuse runs the cases on every template, unprotected and protected.
func fkRefuse(t *testing.T, cases []fkCase) {
	t.Helper()
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, protected := range []bool{false, true} {
			prot := fkProt{}
			if protected {
				prot = fkProt{Pass: fkPass}
			}
			for _, c := range cases {
				name := c.name
				if protected {
					name += " (protected)"
				}
				t.Run(name, func(t *testing.T) {
					file := c.file(t, b, prot)
					err := fkRefused(t, c.name, file, b, c.kinds...)
					if err == nil {
						return
					}
					for _, w := range c.words {
						if !strings.Contains(err.Error(), w) {
							t.Errorf("the text %q does not say %q", err, w)
						}
					}
				})
			}
		}
	})
}

// fkMutate reads the packets of a file, changes them and joins them again.
func fkMutate(f func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket) func(testing.TB, *fkBase, fkProt) []byte {
	return func(t testing.TB, b *fkBase, prot fkProt) []byte {
		t.Helper()
		return fkJoin(f(t, b, fkSplit(t, b.file(t, prot)))...)
	}
}

// fkPrimaryRegion rewrites the secret part of the primary: the public part stays.
func fkPrimaryRegion(region func(t testing.TB) []byte) func(testing.TB, *fkBase, fkProt) []byte {
	return fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
		ps[0] = fkPacket{5, append(bytes.Clone(b.pubBody(t)), region(t)...)}
		return ps
	})
}

// fkProtected writes a protected region of the form that is claimed and not checked: it is of the
// right length, with random bytes.
func fkProtected(t testing.TB, cipher, s2kType, hash byte) []byte {
	t.Helper()
	r := []byte{254, cipher, s2kType, hash}
	return append(r, fkRandom(t, 8+1+16+40)...)
}

func TestForeignRefusesEveryFaultOfThePrimary(t *testing.T) {
	version := func(v byte) func(testing.TB, *fkBase, fkProt) []byte {
		return fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			ps[0].Body = bytes.Clone(ps[0].Body)
			ps[0].Body[0] = v
			return ps
		})
	}
	gnu := func(usage, mode byte, serial []byte) func(testing.TB) []byte {
		return func(testing.TB) []byte { return fkStubRegion(usage, mode, serial) }
	}
	fkRefuse(t, []fkCase{
		{"version 2", version(2), []error{openpgp.ErrForeignVersion}, []string{"version 2"}},
		{"version 3", version(3), []error{openpgp.ErrForeignVersion}, []string{"version 3", "MD5"}},
		{"version 5", version(5), []error{openpgp.ErrForeignVersion}, []string{"version 5"}},
		{"version 6", version(6), []error{openpgp.ErrForeignVersion}, []string{"version 6"}},
		{"version 7", version(7), []error{openpgp.ErrForeignVersion}, []string{"not known (7)"}},
		{"version 0", version(0), []error{openpgp.ErrForeignVersion}, []string{"not known (0)"}},
		{"a public key packet", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			ps[0] = fkPacket{6, b.pubBody(t)}
			return ps
		}), []error{openpgp.ErrForeignNoSecret}, []string{"public key packet"}},
		{"a GNU dummy, usage 255", fkPrimaryRegion(gnu(255, 1, nil)), []error{openpgp.ErrForeignNoSecret}, []string{"dummy"}},
		{"a GNU dummy, usage 254", fkPrimaryRegion(gnu(254, 1, nil)), []error{openpgp.ErrForeignNoSecret}, []string{"dummy"}},
		{"a GNU card with a serial number, usage 255", fkPrimaryRegion(gnu(255, 2, fkSerial)), []error{openpgp.ErrForeignNoSecret}, []string{"card"}},
		{"a GNU card with a serial number, usage 254", fkPrimaryRegion(gnu(254, 2, fkSerial)), []error{openpgp.ErrForeignNoSecret}, []string{"card"}},
		{"a GNU extension of another mode", fkPrimaryRegion(gnu(255, 3, nil)), []error{openpgp.ErrForeignNoSecret}, []string{"mode 3"}},
		{"a private S2K type that is not GNU", fkPrimaryRegion(func(testing.TB) []byte { return []byte{255, 0, 101, 2, 'X', 'Y', 'Z', 1} }), []error{openpgp.ErrForeignProtection}, []string{"private S2K"}},
		{"no secret part at all", fkPrimaryRegion(func(testing.TB) []byte { return nil }), []error{openpgp.ErrForeignForm}, []string{"no secret part"}},
		{"an unprotected secret that is cut short", fkPrimaryRegion(func(testing.TB) []byte { return []byte{0, 0, 1, 2, 3} }), []error{openpgp.ErrForeignForm}, nil},
		{"a protection cut short after the usage octet", fkPrimaryRegion(func(testing.TB) []byte { return []byte{254, 9} }), []error{openpgp.ErrForeignForm}, nil},
		{"usage 255", fkPrimaryRegion(func(t testing.TB) []byte { r := fkProtected(t, 7, 3, 2); r[0] = 255; return r }), []error{openpgp.ErrForeignProtection}, []string{"255"}},
		{"usage 253, an AEAD form", fkPrimaryRegion(func(t testing.TB) []byte { r := fkProtected(t, 7, 3, 2); r[0] = 253; return r }), []error{openpgp.ErrForeignProtection}, []string{"253"}},
		{"usage 7, a cipher number", fkPrimaryRegion(func(t testing.TB) []byte { r := fkProtected(t, 7, 3, 2); r[0] = 7; return r }), []error{openpgp.ErrForeignProtection}, []string{"cipher number", "MD5"}},
		{"cipher CAST5", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 3, 3, 2) }), []error{openpgp.ErrForeignProtection}, []string{"CAST5"}},
		{"cipher Triple-DES", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 2, 3, 2) }), []error{openpgp.ErrForeignProtection}, []string{"TripleDES"}},
		{"cipher IDEA", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 1, 3, 2) }), []error{openpgp.ErrForeignProtection}, []string{"IDEA"}},
		{"cipher Blowfish", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 4, 3, 2) }), []error{openpgp.ErrForeignProtection}, []string{"Blowfish"}},
		{"cipher Twofish", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 10, 3, 2) }), []error{openpgp.ErrForeignProtection}, []string{"Twofish"}},
		{"cipher Camellia", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 13, 3, 2) }), []error{openpgp.ErrForeignProtection}, []string{"Camellia-256"}},
		{"cipher 0", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 0, 3, 2) }), []error{openpgp.ErrForeignProtection}, []string{"no cipher"}},
		{"cipher 99", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 99, 3, 2) }), []error{openpgp.ErrForeignProtection}, []string{"99"}},
		{"simple S2K", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 7, 0, 2) }), []error{openpgp.ErrForeignProtection}, []string{"simple S2K"}},
		{"salted S2K without iteration", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 7, 1, 2) }), []error{openpgp.ErrForeignProtection}, []string{"salted S2K"}},
		{"Argon2", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 9, 4, 2) }), []error{openpgp.ErrForeignProtection}, []string{"Argon2"}},
		{"an S2K type that is not known", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 9, 7, 2) }), []error{openpgp.ErrForeignProtection}, []string{"type 7"}},
		{"S2K hash MD5", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 9, 3, 1) }), []error{openpgp.ErrForeignProtection}, []string{"MD5"}},
		{"S2K hash RIPEMD-160", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 9, 3, 3) }), []error{openpgp.ErrForeignProtection}, []string{"RIPEMD-160"}},
		{"S2K hash SHA3-256", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 9, 3, 12) }), []error{openpgp.ErrForeignProtection}, []string{"SHA3-256"}},
		{"S2K hash that is not known", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 9, 3, 99) }), []error{openpgp.ErrForeignProtection}, []string{"99"}},
		{"a protection cut short in the S2K", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 9, 3, 8)[:20] }), []error{openpgp.ErrForeignForm}, []string{"cut short"}},
		{"a ciphertext shorter than its check and a number", fkPrimaryRegion(func(t testing.TB) []byte { return fkProtected(t, 9, 3, 8)[:13+16+22] }), []error{openpgp.ErrForeignForm}, []string{"shorter than"}},
		{"two primaries, a second secret key", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			return append(ps, ps[0])
		}), []error{openpgp.ErrForeignPrimaries}, []string{"second primary"}},
		{"two primaries, a public key packet after the user ID", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			return append(append([]fkPacket{}, ps[:2]...), append([]fkPacket{{6, b.pubBody(t)}}, ps[2:]...)...)
		}), []error{openpgp.ErrForeignPrimaries}, nil},
		{"two primaries in a row", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			return append([]fkPacket{ps[0]}, ps...)
		}), []error{openpgp.ErrForeignPrimaries}, nil},
		{"the primary has bytes missing before its algorithm", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			ps[0].Body = ps[0].Body[:5]
			return ps
		}), []error{openpgp.ErrForeignForm}, []string{"cut short"}},
		{"the primary has an algorithm that is not known", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			ps[0].Body = bytes.Clone(ps[0].Body)
			ps[0].Body[5] = 99
			return ps
		}), []error{openpgp.ErrForeignAlgorithm}, []string{"99"}},
	})
}

// fkHandPrimary is a file that starts with a primary of an algorithm the reader refuses, with the
// public numbers given and no more: the refusal comes before anything else of the file is read.
func fkHandPrimary(alg byte, params ...[]byte) func(testing.TB, *fkBase, fkProt) []byte {
	return func(t testing.TB, b *fkBase, prot fkProt) []byte {
		t.Helper()
		body := append([]byte{4, 0x65, 0x53, 0xF1, 0x00, alg}, bytes.Join(params, nil)...)
		body = append(body, 0, 1, 2, 3, 4, 5, 6, 7)
		ps := fkSplit(t, b.file(t, prot))
		return fkJoin(append([]fkPacket{{5, body}}, ps[1:]...)...)
	}
}

// fkBig is the public number of a refused key: n bytes with the top bit set.
func fkBig(t testing.TB, n int) []byte {
	b := fkRandom(t, n)
	b[0] |= 0x80
	return fkMPI(b)
}

var fkOtherFiles sync.Map

// fkOther is the file of a primary that go-crypto writes and the reader refuses.
func fkOther(algo gpacket.PublicKeyAlgorithm, curve gpacket.Curve, bits int) func(testing.TB, *fkBase, fkProt) []byte {
	return func(t testing.TB, b *fkBase, prot fkProt) []byte {
		t.Helper()
		key := string(rune(algo)) + string(curve) + string(rune(bits))
		if f, ok := fkOtherFiles.Load(key); ok {
			return f.([]byte)
		}
		cfg := fkConfig(algo, curve, bits)
		e, err := pgp.NewEntity("Quokka Tester", "", "quokka@example.org", cfg)
		if err != nil {
			t.Skipf("go-crypto does not make this key: %v", err)
		}
		var buf bytes.Buffer
		if err := e.SerializePrivateWithoutSigning(&buf, cfg); err != nil {
			t.Fatal(err)
		}
		fkOtherFiles.Store(key, buf.Bytes())
		return buf.Bytes()
	}
}

func TestForeignRefusesPrimariesOfOtherAlgorithms(t *testing.T) {
	p256 := []byte{8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	p384 := []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x22}
	cv25519 := []byte{10, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}
	ed25519 := []byte{9, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}
	bp256 := []byte{9, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07}
	e65537 := []byte{0, 17, 1, 0, 1}
	point := func(t testing.TB, first byte, n int) []byte {
		return fkMPI(append([]byte{first}, fkRandom(t, n)...))
	}
	fkRefuse(t, []fkCase{
		{"RSA 2048", fkOther(gpacket.PubKeyAlgoRSA, "", 2048), []error{openpgp.ErrForeignAlgorithm}, []string{"RSA 2048"}},
		{"RSA 3072", fkOther(gpacket.PubKeyAlgoRSA, "", 3072), []error{openpgp.ErrForeignAlgorithm}, []string{"RSA 3072"}},
		{"ECDSA P-256", fkOther(gpacket.PubKeyAlgoECDSA, gpacket.CurveNistP256, 0), []error{openpgp.ErrForeignAlgorithm}, []string{"ECDSA P-256"}},
		{"ECDSA P-521", fkOther(gpacket.PubKeyAlgoECDSA, gpacket.CurveNistP521, 0), []error{openpgp.ErrForeignAlgorithm}, []string{"ECDSA P-521"}},
		{"native Ed25519", fkOther(gpacket.PubKeyAlgoEd25519, "", 0), []error{openpgp.ErrForeignAlgorithm}, []string{"Ed25519 (native)"}},
		{"RSA 4097", func(t testing.TB, b *fkBase, p fkProt) []byte {
			n := append([]byte{1}, fkRandom(t, 512)...)
			return fkHandPrimary(1, fkMPI(n), e65537)(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"RSA 4097"}},
		{"RSA 4095", func(t testing.TB, b *fkBase, p fkProt) []byte {
			n := fkRandom(t, 512)
			n[0] = 0x40 | n[0]&0x3F
			return fkHandPrimary(1, fkMPI(n), e65537)(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"RSA 4095"}},
		{"RSA encrypt-only", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(2, fkBig(t, 512), e65537)(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"RSA 4096"}},
		{"DSA 2048", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(17, fkBig(t, 256), fkBig(t, 32), fkBig(t, 256), fkBig(t, 256))(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"DSA 2048"}},
		{"ElGamal", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(16, fkBig(t, 256), fkBig(t, 1), fkBig(t, 256))(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"ElGamal 2048"}},
		{"ECDH", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(18, cv25519, point(t, 0x40, 32), []byte{3, 1, 8, 7})(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"ECDH Curve25519"}},
		{"EdDSA on another curve", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(22, cv25519, point(t, 0x40, 32))(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"Curve25519", "does not go with the algorithm"}},
		{"ECDSA on a Brainpool curve", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(19, bp256, point(t, 4, 64))(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"brainpoolP256r1"}},
		{"ECDSA on a curve that is not named", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(19, []byte{3, 1, 2, 3}, point(t, 4, 64))(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"not one that this reader knows"}},
		{"ECDSA P-256 as written by hand", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(19, p256, point(t, 4, 64))(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"ECDSA P-256"}},
		{"X25519 as a primary", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(25, fkRandom(t, 32))(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"X25519"}},
		{"Ed448 as a primary", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(28, fkRandom(t, 57))(t, b, p)
		}, []error{openpgp.ErrForeignAlgorithm}, []string{"Ed448"}},
		{"a P-384 point that is not on the curve", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(19, p384, point(t, 4, 96))(t, b, p)
		}, []error{openpgp.ErrForeignForm}, []string{"not a point"}},
		{"an Ed25519 key that is not 0x40 and 32 bytes", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(22, ed25519, point(t, 0x40, 31))(t, b, p)
		}, []error{openpgp.ErrForeignForm}, []string{"length or the form of its curve"}},
		{"an Ed25519 key with another prefix", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(22, ed25519, point(t, 0x41, 32))(t, b, p)
		}, []error{openpgp.ErrForeignForm}, []string{"length or the form of its curve"}},
		{"an RSA modulus that is not in the form of the standard", func(t testing.TB, b *fkBase, p fkProt) []byte {
			n := fkRandom(t, 512)
			n[0] = 0x7F // 4095 bits, written as 4096
			return fkHandPrimary(1, append([]byte{0x10, 0x00}, n...), e65537)(t, b, p)
		}, []error{openpgp.ErrForeignForm}, []string{"not well formed"}},
		{"a P-384 key cut short in its point", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkHandPrimary(19, p384)(t, b, p)
		}, []error{openpgp.ErrForeignForm}, nil},
	})
}

// A genuine version 6 key, as go-crypto writes it, is refused by its version.
func TestForeignRefusesAGenuineVersion6Key(t *testing.T) {
	cfg := fkConfig(gpacket.PubKeyAlgoEd25519, "", 0)
	cfg.V6Keys = true
	e, err := pgp.NewEntity("Quokka Tester", "", "quokka@example.org", cfg)
	if err != nil {
		t.Skipf("go-crypto does not make a version 6 key: %v", err)
	}
	var buf bytes.Buffer
	if err := e.SerializePrivateWithoutSigning(&buf, cfg); err != nil {
		t.Fatal(err)
	}
	err = fkRefused(t, "version 6", buf.Bytes(), nil, openpgp.ErrForeignVersion)
	if err != nil && !strings.Contains(err.Error(), "version 6") {
		t.Errorf("the text does not name the version: %v", err)
	}
}

func TestForeignRefusesPacketsThatDoNotBelong(t *testing.T) {
	var cases []fkCase
	for _, tag := range []byte{0, 1, 3, 4, 8, 9, 11, 15, 16, 18, 19, 20, 21, 22, 40, 63} {
		cases = append(cases,
			fkCase{"tag " + string(rune('0'+tag/10)) + string(rune('0'+tag%10)) + " after the key", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
				return append(ps, fkPacket{tag, []byte{1, 2, 3}})
			}), []error{openpgp.ErrForeignPacket}, []string{"tag"}},
			fkCase{"tag " + string(rune('0'+tag/10)) + string(rune('0'+tag%10)) + " first", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
				return append([]fkPacket{{tag, []byte{1, 2, 3}}}, ps...)
			}), []error{openpgp.ErrForeignPacket}, []string{"tag"}},
			fkCase{"tag " + string(rune('0'+tag/10)) + string(rune('0'+tag%10)) + " between the user ID and its signature", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
				return append(append(append([]fkPacket{}, ps[:2]...), fkPacket{tag, []byte{1, 2, 3}}), ps[2:]...)
			}), []error{openpgp.ErrForeignPacket}, []string{"tag"}},
		)
	}
	fkRefuse(t, cases)
}

func TestForeignRefusesPacketsOutOfOrder(t *testing.T) {
	enc, _, _ := fkDonors(t)
	fkRefuse(t, []fkCase{
		{"a signature first", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			return append([]fkPacket{ps[2]}, ps...)
		}), []error{openpgp.ErrForeignForm}, []string{"starts with"}},
		{"a user ID first", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			return append([]fkPacket{ps[1]}, ps...)
		}), []error{openpgp.ErrForeignForm}, []string{"starts with"}},
		{"a secret subkey first", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			return append([]fkPacket{ps[3]}, ps...)
		}), []error{openpgp.ErrForeignForm}, []string{"subkey"}},
		{"a public subkey first", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			return append([]fkPacket{enc[0].pub}, ps...)
		}), []error{openpgp.ErrForeignForm}, []string{"subkey"}},
		{"a user attribute first", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			return append([]fkPacket{fkAttribute(t, 10)}, ps...)
		}), []error{openpgp.ErrForeignForm}, []string{"starts with"}},
		{"a user ID after a subkey", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			return append(append([]fkPacket{}, ps[:5]...), append([]fkPacket{ps[1]}, ps[5:]...)...)
		}), []error{openpgp.ErrForeignForm}, []string{"user ID follows a subkey"}},
		{"a user attribute after a subkey", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			return append(ps, fkAttribute(t, 10))
		}), []error{openpgp.ErrForeignForm}, []string{"user attribute follows a subkey"}},
		{"the user ID before the primary signature", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			return append([]fkPacket{ps[0]}, ps[2], ps[1])
		}), []error{openpgp.ErrForeignSelfSignature}, nil},
		{"only trust and marker packets", func(t testing.TB, b *fkBase, p fkProt) []byte {
			return fkJoin(fkPacket{12, []byte{1}}, fkPacket{10, []byte("PGP")})
		}, []error{openpgp.ErrForeignForm}, []string{"no key packet"}},
		{"a subkey with no secret part", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			ps[3] = fkPacket{7, enc[0].pub.Body}
			return ps
		}), []error{openpgp.ErrForeignForm}, []string{"no secret part"}},
		{"a public subkey with bytes after its public part", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			ps[3] = fkPacket{14, append(bytes.Clone(enc[0].pub.Body), 1, 2, 3)}
			return ps
		}), []error{openpgp.ErrForeignForm}, []string{"after its public part"}},
		{"a subkey cut short", fkMutate(func(t testing.TB, b *fkBase, ps []fkPacket) []fkPacket {
			ps[3] = fkPacket{14, enc[0].pub.Body[:5]}
			return ps
		}), []error{openpgp.ErrForeignForm}, []string{"cut short"}},
	})
}

func TestForeignRefusesEmptyAndTinyFiles(t *testing.T) {
	for _, in := range [][]byte{nil, {}, {0}, {0x80}, {0xC5}, {0xC5, 0}, {0x85, 0}, {'-'}, []byte("hello"), {0xFF, 0xFF, 0xFF}} {
		_ = fkRefused(t, "a tiny file", in, nil, openpgp.ErrForeignForm)
	}
}

// G. The header forms and the packets that are skipped.

// fkView is what a key shows in its exported fields, for a comparison of two reads.
type fkView struct {
	Primary    openpgp.ForeignPrimary
	UserIDs    []openpgp.ForeignUserID
	Subkeys    []openpgp.ForeignSubkey
	KeySigs    []openpgp.ForeignSignature
	Other      int
	Attrs      int
	AttrsBytes int
	Unreadable int
}

func fkViewOf(k *openpgp.ForeignKey) fkView {
	return fkView{k.Primary, k.UserIDs, k.Subkeys, k.KeySignatures, k.OtherKeySignatures, k.UserAttributes, k.UserAttributeBytes, k.UnreadableRevocations}
}

func TestForeignHeaderFormsGiveTheSameKey(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		r := fkRichOf(t, b, true, false)
		want := fkViewOf(fkRead(t, r.file))
		for _, form := range []string{"old1", "old2", "old4", "new5", "new2", "new1"} {
			t.Run(form, func(t *testing.T) {
				file := fkRepackAll(t, r.file, form)
				if form != "new1" && form != "new2" && bytes.Equal(file, r.file) {
					t.Fatalf("the file is unchanged by the form %s", form)
				}
				k := fkRead(t, file)
				if got := fkViewOf(k); !fkDeepEqual(got, want) {
					t.Errorf("the key differs from the key of the new-format file:\n%+v\n%+v", got, want)
				}
				s, err := k.OpenSecret([]byte(fkPass))
				if err != nil {
					t.Fatalf("OpenSecret: %v", err)
				}
				fkSignAndVerify(t, s.Signer(), fkCertPublic(t, k.Certificate()))
				// the armour of the same bytes
				ka := fkRead(t, fkArmourKey(t, file))
				if !bytes.Equal(ka.Certificate(), k.Certificate()) || !fkDeepEqual(fkViewOf(ka), want) {
					t.Error("the armoured file gives another key")
				}
			})
		}
	})
}

func TestForeignSkipsTrustAndMarkerPackets(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		r := fkRichOf(t, b, false, true)
		plain := fkRead(t, r.file)
		ps := fkSplit(t, r.file)
		trust := fkPacket{12, []byte{0x01, 0x02, 0x03}}
		marker := fkPacket{10, []byte("PGP")}
		for _, place := range []string{"first", "after the primary", "after the user ID", "after a signature", "after a subkey", "last", "everywhere"} {
			t.Run(place, func(t *testing.T) {
				var out []fkPacket
				add := func(i int) bool {
					if i < 0 {
						return place == "first" || place == "everywhere"
					}
					switch place {
					case "first":
						return false
					case "after the primary":
						return i == 0
					case "after the user ID":
						return ps[i].Tag == 13
					case "after a signature":
						return ps[i].Tag == 2
					case "after a subkey":
						return ps[i].Tag == 7 || ps[i].Tag == 14
					case "last":
						return i == len(ps)-1
					}
					return true
				}
				if add(-1) {
					out = append(out, marker, trust)
				}
				for i, p := range ps {
					out = append(out, p)
					if add(i) {
						out = append(out, trust, marker)
					}
				}
				for _, form := range []string{"new", "old"} {
					file := fkJoin(out...)
					if form == "old" {
						file = nil
						for _, p := range out {
							if p.Tag < 16 {
								file = append(file, oldHeader(p.Tag, p.Body)...)
							} else {
								file = append(file, wrap(p.Tag, p.Body)...)
							}
						}
					}
					k := fkRead(t, file)
					if !fkDeepEqual(fkViewOf(k), fkViewOf(plain)) {
						t.Errorf("%s: a skipped packet changed the key", form)
					}
					cert := splitPackets(t, k.Certificate())
					for _, p := range cert {
						if p.Tag == 12 || p.Tag == 10 {
							t.Errorf("%s: the certificate holds a packet of tag %d", form, p.Tag)
						}
					}
					if form == "new" && !bytes.Equal(k.Certificate(), plain.Certificate()) {
						t.Error("the certificate differs from the certificate of the file with no skipped packet")
					}
				}
			})
		}
	})
}

// Partial and indeterminate lengths are refused by name, wherever they stand.
func TestForeignRefusesPartialAndIndeterminateLengths(t *testing.T) {
	b := fkNamed(t, "ed25519")
	file := b.file(t, fkProt{})
	ps := fkSplit(t, file)
	for _, first := range []byte{224, 225, 239, 254} {
		for place := 0; place < len(ps); place++ {
			// the packet at place gets a partial header: its first length octet, then its body
			var out []byte
			for i, p := range ps {
				if i == place {
					out = append(out, 0xC0|p.Tag, first)
					out = append(out, p.Body...)
					continue
				}
				out = append(out, wrap(p.Tag, p.Body)...)
			}
			err := fkRefused(t, "a partial length", out, b, openpgp.ErrForeignForm)
			if err != nil && !strings.Contains(err.Error(), "partial body length") {
				t.Errorf("place %d, octet %d: the text does not say partial: %v", place, first, err)
			}
		}
	}
	for place := 0; place < len(ps); place++ {
		var out []byte
		for i, p := range ps {
			if i == place && p.Tag < 16 {
				out = append(out, 0x80|p.Tag<<2|3)
				out = append(out, p.Body...)
				continue
			}
			out = append(out, wrap(p.Tag, p.Body)...)
		}
		if place < len(ps) && ps[place].Tag >= 16 {
			continue
		}
		err := fkRefused(t, "an indeterminate length", out, b, openpgp.ErrForeignForm)
		if err != nil && !strings.Contains(err.Error(), "indeterminate length") {
			t.Errorf("place %d: the text does not say indeterminate: %v", place, err)
		}
	}
}

// The text of a refusal of a length names the limit when the length is too large, and the cut when the
// length runs past the end.
func TestForeignRefusesLengthsPastTheFile(t *testing.T) {
	b := fkNamed(t, "ed25519")
	ps := fkSplit(t, b.file(t, fkProt{}))
	rest := fkJoin(ps[1:]...)
	for _, c := range []struct {
		name   string
		header []byte
		kind   error
		word   string
	}{
		{"five octets, the largest", []byte{0xC5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, openpgp.ErrForeignLimit, "MaxForeignPacketBytes"},
		{"five octets, one past the limit", []byte{0xC5, 0xFF, 0, 0x10, 0, 1}, openpgp.ErrForeignLimit, "MaxForeignPacketBytes"},
		{"old format, four octets, the largest", []byte{0x80 | 5<<2 | 2, 0xFF, 0xFF, 0xFF, 0xFF}, openpgp.ErrForeignLimit, "MaxForeignPacketBytes"},
		{"five octets, past the end of the file", []byte{0xC5, 0xFF, 0, 0, 0x7F, 0xFF}, openpgp.ErrForeignForm, "cut short"},
		{"old format, two octets, past the end", []byte{0x80 | 5<<2 | 1, 0xFF, 0xFF}, openpgp.ErrForeignForm, "cut short"},
		{"two octets of length, cut in the length", []byte{0xC5, 0xC0}, openpgp.ErrForeignForm, "cut short"},
		{"five octets of length, cut in the length", []byte{0xC5, 0xFF, 0, 0}, openpgp.ErrForeignForm, "cut short"},
		{"old format, two octets, cut in the length", []byte{0x80 | 5<<2 | 1, 0}, openpgp.ErrForeignForm, "cut short"},
		{"old format, four octets, cut in the length", []byte{0x80 | 5<<2 | 2, 0, 0}, openpgp.ErrForeignForm, "cut short"},
	} {
		in := append(bytes.Clone(c.header), rest...)
		if strings.Contains(c.name, "cut in the length") {
			in = c.header // the file ends in the length
		}
		err := fkRefused(t, c.name, in, b, c.kind)
		if err != nil && !strings.Contains(err.Error(), c.word) {
			t.Errorf("%s: the text %q does not say %q", c.name, err, c.word)
		}
	}
}
