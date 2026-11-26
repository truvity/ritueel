package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/sha1" //nolint:gosec // SHA-1 signatures are the cases
	"crypto/sha256"
	"hash"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// A binding is written only when it is complete; a revocation without an issuer that does not verify is
// counted with those of other keys; and every certificate that is written is read by the library (the
// property helper holds that for every file here).

// fkBackBy is a back-signature (type 0x19) over the primary and the subkey over, made by the key of signer:
// a back-signature of the right form that the subkey's own key did not make when signer is another.
func fkBackBy(t testing.TB, b *fkBase, signer, over fkDonorKey, at int) []byte {
	t.Helper()
	id := signer.pair.pub.KeyId
	sg := &gpacket.Signature{Version: 4, SigType: gpacket.SigTypePrimaryKeyBinding, PubKeyAlgo: signer.pair.pub.PubKeyAlgo,
		Hash: crypto.SHA256, CreationTime: fkSigAt(at), IssuerKeyId: &id}
	if err := sg.CrossSignKey(over.pair.pub, b.ent.PrimaryKey, signer.pair.priv, b.cfg); err != nil {
		t.Fatal(err)
	}
	return fkSplit(t, fkSerializeSig(t, sg))[0].Body
}

func TestForeignBindingCompleteness(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	enc, sig, _ := fkDonors(t)
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	d, other := sig[0], sig[1]
	good := fkSplit(t, fkSerializeSig(t, b.backSig(t, d, fkSigAt(1000))))[0].Body
	bad := bytes.Clone(good)
	bad[len(bad)-1] ^= 1
	byOther := fkBackBy(t, b, other, d, 1000)

	type back struct {
		unhashed []byte // embedded signature in the unhashed area
		hashed   []byte // and in the hashed area
	}
	bind := func(key fkDonorKey, at int, flags byte, bk back) fkPacket {
		extra := [][]byte{}
		if flags != 0 {
			extra = append(extra, fkSubpacket(27, false, flags))
		}
		if bk.hashed != nil {
			extra = append(extra, fkSubpacket(32, false, bk.hashed...))
		}
		var un []byte
		if bk.unhashed != nil {
			un = fkSubpacket(32, false, bk.unhashed...)
		}
		return fkPacket{2, w.sign(t, "sub", 0x18, w.areas(at, extra...), un, 8, sha256.New, key.pub.Body)}
	}
	cases := []struct {
		name       string
		key        fkDonorKey
		sigs       []fkPacket
		in         bool
		incomplete bool
		written    int // bindings written for the subkey when it is in
	}{
		{"signing, with a back-signature in the unhashed area", d, []fkPacket{bind(d, 1000, 0x02, back{unhashed: good})}, true, false, 1},
		{"signing, with a back-signature in the hashed area", d, []fkPacket{bind(d, 1000, 0x02, back{hashed: good})}, true, false, 1},
		{"signing, with none", d, []fkPacket{bind(d, 1000, 0x02, back{})}, false, true, 0},
		{"signing, with a back-signature that does not verify", d, []fkPacket{bind(d, 1000, 0x02, back{unhashed: bad})}, false, true, 0},
		{"signing, with a back-signature made by another subkey", d, []fkPacket{bind(d, 1000, 0x02, back{unhashed: byOther})}, false, true, 0},
		{"signing, with a back-signature of another subkey in the hashed area", d, []fkPacket{bind(d, 1000, 0x02, back{hashed: byOther})}, false, true, 0},
		{"certify, with none", d, []fkPacket{bind(d, 1000, 0x01, back{})}, false, true, 0},
		{"certify, with a back-signature", d, []fkPacket{bind(d, 1000, 0x01, back{unhashed: good})}, true, false, 1},
		{"certify and sign, with none", d, []fkPacket{bind(d, 1000, 0x03, back{})}, false, true, 0},
		{"encryption only, with none", enc[0], []fkPacket{bind(enc[0], 1000, 0x0C, back{})}, true, false, 1},
		{"a signing key with no key flags at all", d, []fkPacket{bind(d, 1000, 0, back{})}, true, false, 1},
		{"two bindings, the complete one first", d, []fkPacket{bind(d, 1000, 0x02, back{unhashed: good}), bind(d, 1100, 0x02, back{})}, true, false, 1},
		{"two bindings, the incomplete one first", d, []fkPacket{bind(d, 1100, 0x02, back{}), bind(d, 1000, 0x02, back{unhashed: good})}, true, false, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			file := fkJoin(append(append(slicesClone(head), c.key.packet(t, fkAsSecret)), c.sigs...)...)
			k := fkRead(t, file)
			ps := fkCertProperty(t, c.name, k)
			s := k.Subkeys[0]
			if s.InCertificate != c.in || s.IncompleteBinding != c.incomplete {
				t.Errorf("in certificate %v, incomplete %v, want %v and %v: %+v", s.InCertificate, s.IncompleteBinding, c.in, c.incomplete, s)
			}
			if s.Fingerprint != hexOf(c.key.pair.pub.Fingerprint) {
				t.Errorf("the fingerprint is %q: a subkey whose binding verifies keeps it", s.Fingerprint)
			}
			sigs := 0
			subs := 0
			for _, p := range ps {
				if p.tag == 14 {
					subs++
				} else if p.tag == 2 && subs > 0 {
					sigs++
				}
			}
			if sigs != c.written || subs != map[bool]int{true: 1, false: 0}[c.in] {
				t.Errorf("%d subkeys and %d bindings in the certificate, want %d bindings", subs, sigs, c.written)
			}
			if len(c.sigs) == 2 && c.in && !s.Bound {
				t.Error("the subkey is not bound although one binding is complete")
			}
		})
	}
}

// A revocation that names no issuer and does not verify may be a designated revoker's with the issuer
// stripped: it is counted with the revocations of other keys. One that names no issuer and verifies is the
// primary's, and is not.
func TestForeignRevocationsWithoutAnIssuer(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	enc, _, _ := fkDonors(t)
	created := fkSubpacket(2, false, fkU32(uint32(fkAt(1200).Unix()))...)
	flip := func(body []byte) []byte {
		c := bytes.Clone(body)
		c[len(c)-1] ^= 1
		return c
	}
	bind := fkBinding(t, b, enc[0].pub.Body)
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	files := map[string]func(rev []byte) []byte{
		"key":    func(rev []byte) []byte { return fkJoin(head[0], fkPacket{2, rev}, head[1], head[2]) },
		"user":   func(rev []byte) []byte { return fkJoin(head[0], head[1], head[2], fkPacket{2, rev}) },
		"subkey": func(rev []byte) []byte { return fkJoin(head[0], head[1], head[2], enc[0].pub, bind, fkPacket{2, rev}) },
	}
	typ := map[string]byte{"key": 0x20, "user": 0x30, "subkey": 0x28}
	kind := map[string]string{"key": "key", "user": "user", "subkey": "sub"}
	for name, mk := range files {
		target := []byte(fkUser)
		if name == "subkey" {
			target = enc[0].pub.Body
		}
		rev := w.sign(t, kind[name], typ[name], created, nil, 8, sha256.New, target) // no issuer at all, and it verifies
		count := func(k *openpgp.ForeignKey) (other, otherRev int) {
			switch name {
			case "key":
				return k.OtherKeySignatures, k.OtherKeyRevocations
			case "user":
				return k.UserIDs[0].OtherSignatures, k.UserIDs[0].OtherRevocations
			}
			return k.Subkeys[0].OtherSignatures, k.Subkeys[0].OtherRevocations
		}
		t.Run(name+", does not verify", func(t *testing.T) {
			k := fkRead(t, mk(flip(rev)))
			_ = fkCertProperty(t, name, k)
			if o, r := count(k); o != 1 || r != 1 {
				t.Errorf("other signatures %d and revocations %d, want 1 and 1", o, r)
			}
			if k.Primary.Revoked || (name == "user" && k.UserIDs[0].Revoked) || (name == "subkey" && k.Subkeys[0].Revoked) {
				t.Error("a revocation that does not verify revokes")
			}
		})
		t.Run(name+", verifies with the primary", func(t *testing.T) {
			k := fkRead(t, mk(rev))
			_ = fkCertProperty(t, name, k)
			if o, r := count(k); o != 0 || r != 0 {
				t.Errorf("a revocation of the primary is counted as another key's: %d, %d", o, r)
			}
			revoked := k.Primary.Revoked
			switch name {
			case "user":
				revoked = k.UserIDs[0].Revoked
			case "subkey":
				revoked = k.Subkeys[0].Revoked
			}
			if !revoked {
				t.Error("a revocation with no issuer that verifies does not revoke")
			}
		})
	}
}

// The certificate that is written is read by the library for every sibling that one side could accept and the
// other refuse: SHA-1 where it is the only signature and beside a strong one, revocations and direct-key
// signatures with SHA-1, a reason, a critical subpacket that the reader does not write, and a binding of a
// signing subkey with its revocation. fkCertProperty reads each certificate with the library.
func TestForeignEveryCertificateIsReadByTheLibrary(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	enc, sig, _ := fkDonors(t)
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	flags := fkSubpacket(27, false, 3)
	type hs struct {
		id byte
		f  func() hash.Hash
	}
	strong, weak := hs{8, sha256.New}, hs{2, sha1.New}
	user := func(h hs, typ byte, at int, extra ...[]byte) fkPacket {
		return fkPacket{2, w.sign(t, "user", typ, w.areas(at, append([][]byte{flags}, extra...)...), nil, h.id, h.f, []byte(fkUser))}
	}
	key := func(h hs, typ byte, at int, extra ...[]byte) fkPacket {
		return fkPacket{2, w.sign(t, "key", typ, w.areas(at, extra...), nil, h.id, h.f, nil)}
	}
	subOf := func(d fkDonorKey, h hs, typ byte, at int, extra ...[]byte) fkPacket {
		return fkPacket{2, w.sign(t, "sub", typ, w.areas(at, extra...), nil, h.id, h.f, d.pub.Body)}
	}
	reason := func(c byte) []byte { return fkReasonSub(c) }
	crit := fkSubpacket(100, true, 1)
	back := fkSplit(t, fkSerializeSig(t, b.backSig(t, sig[0], fkSigAt(1000))))[0].Body
	signBind := func(h hs, at int) fkPacket {
		return fkPacket{2, w.sign(t, "sub", 0x18, w.areas(at, fkSubpacket(27, false, 0x02)), fkSubpacket(32, false, back...), h.id, h.f, sig[0].pub.Body)}
	}
	sub := func(d fkDonorKey, sigs ...fkPacket) []fkPacket { return append([]fkPacket{d.pub}, sigs...) }
	base := []fkPacket{head[0], head[1]}
	cat := func(parts ...[]fkPacket) []byte {
		var ps []fkPacket
		for _, p := range parts {
			ps = append(ps, p...)
		}
		return fkJoin(ps...)
	}
	cases := map[string][]byte{
		"SHA-1 is the only self-signature":                            cat(base, []fkPacket{user(weak, 0x13, 1000)}),
		"SHA-1 beside a strong self-signature":                        cat(base, []fkPacket{user(weak, 0x13, 1000), user(strong, 0x13, 1100)}),
		"a SHA-1 certification revocation":                            cat(base, []fkPacket{user(strong, 0x13, 1000), user(weak, 0x30, 1100, reason(32))}),
		"a SHA-1 certification revocation with no reason":             cat(base, []fkPacket{user(strong, 0x13, 1000), user(weak, 0x30, 1100)}),
		"a SHA-1 direct-key signature":                                cat(base[:1], []fkPacket{key(weak, 0x1F, 900, flags)}, base[1:], []fkPacket{head[2]}),
		"a SHA-1 key revocation":                                      cat(base[:1], []fkPacket{key(weak, 0x20, 1500, reason(2))}, base[1:], []fkPacket{head[2]}),
		"a key revocation with a critical subpacket":                  cat(base[:1], []fkPacket{key(strong, 0x20, 1500, crit)}, base[1:], []fkPacket{head[2]}),
		"a SHA-1 binding":                                             cat(base, []fkPacket{head[2]}, sub(enc[0], subOf(enc[0], weak, 0x18, 1000, fkSubpacket(27, false, 0x0C)))),
		"a SHA-1 binding and a strong one":                            cat(base, []fkPacket{head[2]}, sub(enc[0], subOf(enc[0], weak, 0x18, 1000), subOf(enc[0], strong, 0x18, 1100))),
		"a binding and a SHA-1 subkey revocation":                     cat(base, []fkPacket{head[2]}, sub(enc[0], subOf(enc[0], strong, 0x18, 1000), subOf(enc[0], weak, 0x28, 1100, reason(3)))),
		"a binding and a strong subkey revocation":                    cat(base, []fkPacket{head[2]}, sub(enc[0], subOf(enc[0], strong, 0x18, 1000), subOf(enc[0], strong, 0x28, 1100, reason(2)))),
		"a binding and a revocation with a critical subpacket":        cat(base, []fkPacket{head[2]}, sub(enc[0], subOf(enc[0], strong, 0x18, 1000), subOf(enc[0], strong, 0x28, 1100, crit))),
		"a binding and a revocation that is older":                    cat(base, []fkPacket{head[2]}, sub(enc[0], subOf(enc[0], strong, 0x18, 1100), subOf(enc[0], strong, 0x28, 1000, reason(3)))),
		"a binding and a revocation with no reason":                   cat(base, []fkPacket{head[2]}, sub(enc[0], subOf(enc[0], strong, 0x18, 1000), subOf(enc[0], strong, 0x28, 1100))),
		"a signing subkey with its back-signature and a revocation":   cat(base, []fkPacket{head[2]}, sub(sig[0], signBind(strong, 1000), subOf(sig[0], strong, 0x28, 1100, reason(3)))),
		"a signing subkey with a SHA-1 binding with a back-signature": cat(base, []fkPacket{head[2]}, sub(sig[0], signBind(weak, 1000))),
		"a signing subkey with a SHA-1 revocation":                    cat(base, []fkPacket{head[2]}, sub(sig[0], signBind(strong, 1000), subOf(sig[0], weak, 0x28, 1100, reason(2)))),
	}
	for name, file := range cases {
		t.Run(name, func(t *testing.T) {
			k := fkRead(t, file)
			_ = fkCertProperty(t, name, k)
		})
	}
}

// A user attribute whose body is not a sequence of subpackets is left out even when the primary signed it, and
// counted once in UserAttributesLeftOut. The certificate that is written holds no attribute packet and stays
// readable by the library.
func TestForeignCertificateOfAMalformedAttribute(t *testing.T) {
	b := fkNamed(t, "ed25519")
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	body := []byte("not subpackets of an image")
	file := fkJoin(head[0], head[1], head[2], fkPacket{17, body}, fkPacket{2, fkAttrSig(t, b, body, 1000)})
	k := fkRead(t, file)
	if k.UserAttributesLeftOut != 1 {
		t.Fatalf("the malformed attribute must be left out and counted once: the count is %d", k.UserAttributesLeftOut)
	}
	if _, err := pgp.ReadKeyRing(bytes.NewReader(k.Certificate())); err != nil {
		t.Fatalf("the library must read the certificate when a malformed attribute is left out: %v", err)
	}
	ps, err := fkWalkCertificate(k.Certificate())
	if err != nil {
		t.Fatalf("the certificate does not walk: %v", err)
	}
	if n := len(fkCertTagsOf(ps, 17)); n != 0 {
		t.Errorf("the certificate holds %d user attribute packets, want none", n)
	}
}
