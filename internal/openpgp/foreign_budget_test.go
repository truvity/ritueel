package openpgp_test

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The work budgets, the back-signature rule, the duplicates, and the counts of what the certificate leaves
// out: each from a file built to produce it.

// fkAttrSig is a certification of the attribute body by the primary of the Ed25519 template.
func fkAttrSig(t testing.TB, b *fkBase, body []byte, at int) []byte {
	w := fkWriter{b}
	return w.sign(t, "attr", 0x13, w.areas(at), nil, 8, sha256.New, body)
}

// MaxForeignHashedBytes: a file whose checks hash just under 512 MiB is read, and one that hashes more is
// refused by name. The cost of a check is charged before it is done: two passes over the data that the
// signature covers (the hash tag, and the library's verification), so a photograph of the largest size
// with 255 self-signatures is just under the budget and 256 is just over. The signatures are the same
// bytes, which the certificate writes once.
func TestForeignHashedBytesBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("hashes about half a gigabyte")
	}
	b := fkNamed(t, "ed25519")
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	// a photograph that is one image subpacket of the largest size, as the library reads it
	n := openpgp.MaxForeignPacketBytes - 6
	photo := fkPacket{17, append([]byte{0xFF, byte((n + 1) >> 24), byte((n + 1) >> 16), byte((n + 1) >> 8), byte(n + 1), 1}, make([]byte, n)...)}
	sig := fkPacket{2, fkAttrSig(t, b, photo.Body, 1000)}
	build := func(n int) []byte {
		ps := []fkPacket{head[0], head[1], head[2], photo}
		for i := 0; i < n; i++ {
			ps = append(ps, sig)
		}
		return fkJoin(ps...)
	}
	start := time.Now()
	k, err := openpgp.ReadForeignKey(build(255))
	if err != nil {
		t.Fatalf("255 signatures over a photograph of 1 MiB (just under the budget): %v", err)
	}
	if k.UserAttributes != 1 || k.UserAttributesLeftOut != 0 || k.DuplicatesDropped != 254 {
		t.Errorf("attributes %d, left out %d, duplicates %d", k.UserAttributes, k.UserAttributesLeftOut, k.DuplicatesDropped)
	}
	_ = fkCertProperty(t, "the photograph", k)
	err = fkRefused(t, "256 signatures over a photograph", build(256), b, openpgp.ErrForeignLimit)
	if err != nil && !strings.Contains(err.Error(), "MaxForeignHashedBytes") {
		t.Errorf("the text does not name the budget: %v", err)
	}
	t.Logf("both files took %v", time.Since(start))
	// an ordinary key uses a small part: a photograph of 1 MiB with thirty self-signatures, a tenth of it
	if _, err := openpgp.ReadForeignKey(build(30)); err != nil {
		t.Errorf("thirty self-signatures on a photograph: %v", err)
	}
}

// MaxForeignVerifications: a binding of an encryption subkey costs three (its signature, and the strict
// pass of two), the self-signature of the user ID one. A file of 1365 distinct bindings costs 4096 and is
// read; one more binding costs 4099 and is refused by name. The bindings differ in their creation
// time, because identical ones are charged each and merged only in the output.
func TestForeignVerificationsBudget(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	enc, _, _ := fkDonors(t)
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	build := func(n int) []byte {
		ps := []fkPacket{head[0], head[1], head[2], enc[0].pub}
		for i := 0; i < n; i++ {
			if i == (n+1)/2 {
				ps = append(ps, enc[1].pub)
			}
			d := enc[0]
			if i >= (n+1)/2 {
				d = enc[1]
			}
			ps = append(ps, fkPacket{2, w.sign(t, "sub", 0x18, w.areas(1000+i, fkSubpacket(27, false, 0x0C)), nil, 8, sha256.New, d.pub.Body)})
		}
		return fkJoin(ps...)
	}
	start := time.Now()
	k, err := openpgp.ReadForeignKey(build(1365))
	if err != nil {
		t.Fatalf("1365 bindings (4096 verifications): %v", err)
	}
	if !k.Subkeys[0].InCertificate || !k.Subkeys[1].InCertificate {
		t.Error("the subkeys are not in the certificate")
	}
	_ = fkCertProperty(t, "the bindings", k)
	err = fkRefused(t, "1366 bindings", build(1366), b, openpgp.ErrForeignLimit)
	if err != nil && !strings.Contains(err.Error(), "MaxForeignVerifications") {
		t.Errorf("the text does not name the budget: %v", err)
	}
	t.Logf("both files took %v", time.Since(start))
	// the rich key: fkRichKept has this many signatures that the primary made, and a binding costs three
	r := fkRichKept(t, b, false)
	signatures := 0
	rk := fkRead(t, r.file)
	for _, u := range rk.UserIDs {
		signatures += len(u.Signatures)
	}
	for _, s := range rk.Subkeys {
		signatures += 3 * len(s.Signatures)
	}
	signatures += len(rk.KeySignatures)
	if signatures > openpgp.MaxForeignVerifications/10 {
		t.Errorf("the rich key costs about %d verifications, a tenth of the budget is %d", signatures, openpgp.MaxForeignVerifications/10)
	}
	t.Logf("the rich key costs at most %d of %d verifications", signatures, openpgp.MaxForeignVerifications)
	// the doc comment's key of twenty years: 15 user IDs x 20 self-signatures and 30 subkeys x 20 bindings of
	// three each (the encryption subkeys here; a signing subkey adds the check of its back-signature) is 300
	// + 1800 = 2100 for these, and below the budget with the revocations and direct-key signatures
	if 15*20+30*20*3 > openpgp.MaxForeignVerifications {
		t.Error("the key of twenty years of the doc comment is over the budget")
	}
}

// 2. The back-signature of a binding: only the first embedded signature of its unhashed area is tried.
func TestForeignBackSignatureRule(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	_, sig, _ := fkDonors(t)
	d := sig[0]
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	back := fkSplit(t, fkSerializeSig(t, b.backSig(t, d, fkSigAt(1000))))[0].Body
	garbage := bytes.Clone(back)
	garbage[len(garbage)-1] ^= 1
	bind := func(at int, embedded ...[]byte) fkPacket {
		var un []byte
		for _, e := range embedded {
			un = append(un, fkSubpacket(32, false, e...)...)
		}
		return fkPacket{2, w.sign(t, "sub", 0x18, w.areas(at, fkSubpacket(27, false, 0x02)), un, 8, sha256.New, d.pub.Body)}
	}
	file := func(sigs ...fkPacket) []byte {
		return fkJoin(append(append(slicesClone(head), d.pub), sigs...)...)
	}
	embeddedIn := func(ps []fkCP) int {
		n := 0
		for _, p := range ps {
			if p.tag != 2 {
				continue
			}
			if _, _, un, ok := fkSigAreasOf(p.body); ok {
				sps, _ := fkReadSubpackets(un)
				for _, sp := range sps {
					if sp.typ == 32 {
						n++
					}
				}
			}
		}
		return n
	}
	t.Run("one good back-signature", func(t *testing.T) {
		k := fkRead(t, file(bind(1000, back)))
		ps := fkCertProperty(t, "one good", k)
		if !k.Subkeys[0].InCertificate || !k.Subkeys[0].Bound || embeddedIn(ps) != 1 {
			t.Errorf("in certificate %v, bound %v, %d back-signatures written, want true, true and 1", k.Subkeys[0].InCertificate, k.Subkeys[0].Bound, embeddedIn(ps))
		}
		if _, err := pgpRead(k.Certificate()); err != nil {
			t.Errorf("go-crypto does not read the certificate: %v", err)
		}
	})
	t.Run("one garbage back-signature: left out, incomplete, fingerprint kept", func(t *testing.T) {
		k := fkRead(t, file(bind(1000, garbage)))
		ps := fkCertProperty(t, "one garbage", k)
		// the binding is not complete: it is not written, the subkey is left out with its fingerprint, and
		// the certificate is one that the library reads
		s := k.Subkeys[0]
		if s.InCertificate || s.Bound || !s.IncompleteBinding || s.Fingerprint != hexOf(d.pair.pub.Fingerprint) || embeddedIn(ps) != 0 || len(fkCertTagsOf(ps, 14)) != 0 {
			t.Errorf("%+v", s)
		}
	})
	// go-crypto refuses a signature with two embedded signatures, so the rule that only the first is tried
	// is not reached: the binding is unreadable, and a subkey that has no other binding is left out
	for name, emb := range map[string][][]byte{
		"a good one first and garbage after":  {back, garbage, garbage},
		"garbage first and a good one second": {garbage, back},
		"two good ones":                       {back, back},
	} {
		t.Run(name+": the binding is unreadable and the subkey is left out", func(t *testing.T) {
			k := fkRead(t, file(bind(1000, emb...)))
			ps := fkCertProperty(t, name, k)
			s := k.Subkeys[0]
			if s.InCertificate || s.Bound || len(s.Signatures) != 1 || s.Signatures[0].Status != openpgp.SignatureUnreadable || len(fkCertTagsOf(ps, 14)) != 0 {
				t.Errorf("%+v", s)
			}
		})
	}
	t.Run("the same binding many times", func(t *testing.T) {
		one := bind(1000, back)
		ps := []fkPacket{}
		for i := 0; i < 500; i++ {
			ps = append(ps, one)
		}
		start := time.Now()
		k := fkRead(t, file(ps...))
		took := time.Since(start)
		cp := fkCertProperty(t, "repeated", k)
		if embeddedIn(cp) != 1 || k.DuplicatesDropped != 499 {
			t.Errorf("%d back-signatures written, %d duplicates dropped", embeddedIn(cp), k.DuplicatesDropped)
		}
		if took > 20*time.Second {
			t.Errorf("500 repeated bindings took %v", took)
		}
		// 500 distinct bindings with the same back-signature: the back-signature is judged once per subkey
		var many []fkPacket
		for i := 0; i < 500; i++ {
			many = append(many, bind(1000+i, back))
		}
		start = time.Now()
		k = fkRead(t, file(many...))
		t.Logf("500 distinct bindings with one back-signature: %v", time.Since(start))
		if _, err := fkWalkCertificate(k.Certificate()); err != nil {
			t.Error(err)
		}
	})
}

func pgpRead(cert []byte) (pgp.EntityList, error) { return pgp.ReadKeyRing(bytes.NewReader(cert)) }

// 3. Duplicates are merged into the first occurrence and counted.
func TestForeignDuplicatesAreDropped(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	enc, _, _ := fkDonors(t)
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	self := func(at int, flags byte) fkPacket {
		return fkPacket{2, w.userSig(t, 0x13, w.areas(at, fkSubpacket(27, false, flags)), nil)}
	}
	count := func(ps []fkCP, tag byte) int { return len(fkCertTagsOf(ps, tag)) }

	t.Run("the same user ID twice, with the same signature", func(t *testing.T) {
		k := fkRead(t, fkJoin(head[0], head[1], head[2], head[1], head[2]))
		ps := fkCertProperty(t, "uid twice", k)
		if count(ps, 13) != 1 || count(ps, 2) != 1 || k.DuplicatesDropped != 2 {
			t.Errorf("%d user IDs, %d signatures, %d duplicates", count(ps, 13), count(ps, 2), k.DuplicatesDropped)
		}
	})
	t.Run("two different valid self-signatures are both kept", func(t *testing.T) {
		k := fkRead(t, fkJoin(head[0], head[1], self(1000, 3), self(1100, 1)))
		ps := fkCertProperty(t, "two signatures", k)
		if count(ps, 13) != 1 || count(ps, 2) != 2 || k.DuplicatesDropped != 0 {
			t.Errorf("%d user IDs, %d signatures, %d duplicates", count(ps, 13), count(ps, 2), k.DuplicatesDropped)
		}
	})
	t.Run("the same user ID twice, with different signatures: merged", func(t *testing.T) {
		k := fkRead(t, fkJoin(head[0], head[1], self(1000, 3), head[1], self(1100, 1)))
		ps := fkCertProperty(t, "uid twice, two signatures", k)
		if count(ps, 13) != 1 || count(ps, 2) != 2 || k.DuplicatesDropped != 1 {
			t.Errorf("%d user IDs, %d signatures, %d duplicates", count(ps, 13), count(ps, 2), k.DuplicatesDropped)
		}
	})
	t.Run("a user ID whose first occurrence has no good signature", func(t *testing.T) {
		k := fkRead(t, fkJoin(head[0], head[1], head[1], self(1000, 3)))
		ps := fkCertProperty(t, "second occurrence signs", k)
		if count(ps, 13) != 1 || count(ps, 2) != 1 {
			t.Errorf("%d user IDs, %d signatures", count(ps, 13), count(ps, 2))
		}
	})
	t.Run("the same attribute twice, with the same signature", func(t *testing.T) {
		a := fkAttribute(t, 60)
		s := fkPacket{2, fkAttrSig(t, b, a.Body, 1000)}
		k := fkRead(t, fkJoin(head[0], head[1], head[2], a, s, a, s))
		ps := fkCertProperty(t, "attribute twice", k)
		if count(ps, 17) != 1 || count(ps, 2) != 2 || k.DuplicatesDropped != 2 || k.UserAttributes != 2 {
			t.Errorf("%d attributes in the certificate, %d signatures, %d duplicates, %d in the file", count(ps, 17), count(ps, 2), k.DuplicatesDropped, k.UserAttributes)
		}
	})
	t.Run("the same attribute twice, with no signature: counted once", func(t *testing.T) {
		a := fkAttribute(t, 60)
		other := fkAttribute(t, 61)
		k := fkRead(t, fkJoin(head[0], head[1], head[2], a, a, other))
		if k.UserAttributes != 3 || k.UserAttributesLeftOut != 2 {
			t.Errorf("%d attributes, %d left out, want 3 and 2 (two distinct bodies)", k.UserAttributes, k.UserAttributesLeftOut)
		}
	})
	t.Run("the same subkey twice, with the same binding", func(t *testing.T) {
		bind := fkPacket{2, w.sign(t, "sub", 0x18, w.areas(1000, fkSubpacket(27, false, 0x0C)), nil, 8, sha256.New, enc[0].pub.Body)}
		k := fkRead(t, fkJoin(head[0], head[1], head[2], enc[0].pub, bind, enc[0].pub, bind))
		ps := fkCertProperty(t, "subkey twice", k)
		if count(ps, 14) != 1 || len(k.Subkeys) != 2 || !k.Subkeys[0].InCertificate || !k.Subkeys[1].InCertificate || k.DuplicatesDropped != 2 {
			t.Errorf("%d subkeys in the certificate, %d in the view, duplicates %d", count(ps, 14), len(k.Subkeys), k.DuplicatesDropped)
		}
	})
}

// 4. The counts of what the certificate leaves out.
func TestForeignCountsOfWhatIsLeftOut(t *testing.T) {
	b := fkNamed(t, "ed25519")
	enc, _, other := fkDonors(t)
	me := b.primaryPair()
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	frame := func(sp fkSigSpec, f func(b *fkBase, sp fkSigSpec) []byte) fkPacket { return fkSplit(t, f(b, sp))[0] }

	// a certification revocation by ANOTHER key: counted, and not in the certificate
	t.Run("a revocation of a user ID by another key", func(t *testing.T) {
		rev := frame(fkSigSpec{Typ: 0x30}, func(b *fkBase, sp fkSigSpec) []byte { return b.certSig(t, other, me.pub, fkUser, sp) })
		k := fkRead(t, fkJoin(head[0], head[1], head[2], rev))
		u := k.UserIDs[0]
		ps := fkCertProperty(t, "revoked by another", k)
		if u.OtherRevocations != 1 || u.OtherSignatures != 1 || u.Revoked || len(fkCertTagsOf(ps, 2)) != 1 {
			t.Errorf("%+v", u)
		}
	})
	t.Run("a revocation of a subkey by another key", func(t *testing.T) {
		bind := fkBinding(t, b, enc[0].pub.Body)
		rev := frame(fkSigSpec{Typ: 0x28}, func(b *fkBase, sp fkSigSpec) []byte { return b.subSig(t, other, enc[0].pair.pub, sp) })
		k := fkRead(t, fkJoin(head[0], head[1], head[2], enc[0].pub, bind, rev))
		s := k.Subkeys[0]
		_ = fkCertProperty(t, "subkey revoked by another", k)
		if s.OtherRevocations != 1 || s.OtherSignatures != 1 || s.Revoked || !s.InCertificate {
			t.Errorf("%+v", s)
		}
	})
	t.Run("a key revocation by another key", func(t *testing.T) {
		rev := frame(fkSigSpec{Typ: 0x20}, func(b *fkBase, sp fkSigSpec) []byte { return b.keySig(t, other, me.pub, sp) })
		k := fkRead(t, fkJoin(head[0], rev, head[1], head[2]))
		_ = fkCertProperty(t, "key revoked by another", k)
		if k.OtherKeyRevocations != 1 || k.OtherKeySignatures != 1 || k.Primary.Revoked {
			t.Errorf("revocations %d, other signatures %d, revoked %v", k.OtherKeyRevocations, k.OtherKeySignatures, k.Primary.Revoked)
		}
	})
	t.Run("a subkey with no binding: not in the certificate, no fingerprint", func(t *testing.T) {
		for _, form := range []fkSubForm{fkAsPublic, fkAsSecret, fkAsCard} {
			k := fkRead(t, fkJoin(append(slicesClone(head), enc[0].packet(t, form))...))
			s := k.Subkeys[0]
			if s.InCertificate || s.Fingerprint != "" || s.KeyID != "" || s.Algorithm != enc[0].want {
				t.Errorf("form %v: %+v", form, s)
			}
			_ = fkCertProperty(t, "a subkey with no binding", k, enc[0].sec.Body[len(enc[0].pub.Body):])
		}
	})
	t.Run("a binding that go-crypto would not read", func(t *testing.T) {
		// a signing subkey with a binding that has no back-signature is in the certificate and the key ring of
		// go-crypto then refuses the certificate: written down in the report, not held here
		_ = gpacket.SigTypeSubkeyBinding
	})
}
