package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// E. The parsed view of a key: user IDs, attributes, direct-key signatures, revocations,
// certifications of other keys, subkeys and their bindings.

func fkAt(secs int) time.Time { return fkSigAt(secs) }

func TestForeignViewOfRichKey(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, protected := range []bool{false, true} {
			name := "unprotected"
			if protected {
				name = "protected"
			}
			t.Run(name, func(t *testing.T) {
				r := fkRichOf(t, b, protected, false)
				k := fkRead(t, r.file)
				fkViewKey(t, k, r)
				fkViewUsers(t, k, r)
				fkViewSubkeys(t, k, r)
			})
		}
	})
}

func fkViewKey(t *testing.T, k *openpgp.ForeignKey, r *fkRich) {
	t.Helper()
	if !k.Primary.Revoked {
		t.Error("a valid key revocation by the primary is not reported")
	}
	if k.Primary.Secret == 0 {
		t.Error("the secret state is not set")
	}
	if len(k.KeySignatures) != 3 {
		t.Fatalf("%d signatures on the key, want a direct-key signature, a revocation and a misplaced one: %+v", len(k.KeySignatures), k.KeySignatures)
	}
	direct, rev, mis := k.KeySignatures[0], k.KeySignatures[1], k.KeySignatures[2]
	if direct.Type != 0x1F || direct.Status != openpgp.SignatureValid || direct.KeyFlags != 3 || !direct.Created.Equal(fkAt(900)) ||
		!direct.KeyExpires.Equal(fkEpoch.Add(100*24*time.Hour)) {
		t.Errorf("direct-key signature %+v", direct)
	}
	if rev.Type != 0x20 || rev.Status != openpgp.SignatureValid || !rev.HasReason || rev.Reason != 2 || !rev.Created.Equal(fkAt(1500)) {
		t.Errorf("key revocation %+v", rev)
	}
	if mis.Type != 0x13 || mis.Status != openpgp.SignatureMisplaced {
		t.Errorf("a certification on the key itself %+v, want it misplaced", mis)
	}
	if k.OtherKeySignatures != 1 {
		t.Errorf("%d signatures of other keys on the key, want 1", k.OtherKeySignatures)
	}
	if k.UserAttributes != r.attrs || k.UserAttributeBytes != r.attrBytes || r.attrs != 2 {
		t.Errorf("%d user attributes of %d bytes, want %d of %d", k.UserAttributes, k.UserAttributeBytes, r.attrs, r.attrBytes)
	}
	if len(k.UserIDs) != len(fkRichUsers) || len(k.Subkeys) != len(fkRichSubs) {
		t.Fatalf("%d user IDs and %d subkeys, want %d and %d", len(k.UserIDs), len(k.Subkeys), len(fkRichUsers), len(fkRichSubs))
	}
}

func fkViewUsers(t *testing.T, k *openpgp.ForeignKey, r *fkRich) {
	t.Helper()
	u := func(name string) openpgp.ForeignUserID {
		t.Helper()
		got := k.UserIDs[r.uid[name]]
		if got.Text != fkRichUserID(name) {
			t.Fatalf("user ID %d is %q, want %q (the order of the file)", r.uid[name], got.Text, fkRichUserID(name))
		}
		return got
	}
	status := func(name string, i int, want openpgp.SignatureStatus, hash string) {
		t.Helper()
		got := u(name)
		if len(got.Signatures) <= i {
			t.Errorf("%s: %d signatures, want one at %d", name, len(got.Signatures), i)
			return
		}
		if s := got.Signatures[i]; s.Status != want || (hash != "" && s.Hash != hash) {
			t.Errorf("%s: signature %d is %v with %s, want %v with %s", name, i, s.Status, s.Hash, want, hash)
		}
	}

	p := u("primary")
	if !p.Valid || !p.Primary || p.KeyFlags != 3 || p.Revoked || !p.Created.Equal(fkAt(1000)) ||
		!p.KeyExpires.Equal(fkEpoch.Add(365*24*time.Hour)) || len(p.Signatures) != 1 || p.Certifications != 0 {
		t.Errorf("primary: %+v", p)
	}
	status("primary", 0, openpgp.SignatureValid, "SHA-256")
	if got := p.Signatures[0]; got.Type != 0x13 || !got.Primary || got.Expires != (time.Time{}) {
		t.Errorf("primary: signature %+v", got)
	}

	rv := u("revoked")
	if !rv.Valid || !rv.Revoked || !rv.RevokedAt.Equal(fkAt(1100)) || len(rv.Signatures) != 2 {
		t.Errorf("revoked: %+v", rv)
	} else if g := rv.Signatures[1]; g.Type != 0x30 || g.Status != openpgp.SignatureValid || !g.HasReason || g.Reason != 32 {
		t.Errorf("revoked: revocation %+v", g)
	}

	ex := u("expiring")
	if !ex.Valid || len(ex.Signatures) != 1 || !ex.Signatures[0].Expires.Equal(fkAt(1000).Add(100*time.Second)) {
		t.Errorf("expiring: %+v (the reader reads no clock, so it still counts)", ex)
	}

	if w := u("weak"); !w.Valid || !w.WeakHash || w.Revoked || !w.Created.Equal(fkAt(1000)) {
		t.Errorf("weak: a SHA-1 self-signature that verifies counts, and is flagged: %+v", w)
	}
	status("weak", 0, openpgp.SignatureValidWeakHash, "SHA-1")
	if u("primary").WeakHash || u("certified").WeakHash {
		t.Error("a user ID with a SHA-256 self-signature is flagged as weak")
	}
	if u("notaccepted").Valid {
		t.Error("notaccepted: a SHA-224 self-signature counts")
	}
	status("notaccepted", 0, openpgp.SignatureHashNotAccepted, "SHA-224")
	if u("critical").Valid {
		t.Error("critical: a self-signature with an unknown critical subpacket counts")
	}
	status("critical", 0, openpgp.SignatureUnknownCritical, "")
	if u("tampered").Valid {
		t.Error("tampered: a self-signature that does not verify counts")
	}
	status("tampered", 0, openpgp.SignatureNotVerified, "")

	c := u("certified")
	if !c.Valid || c.Certifications != 2 || c.OtherSignatures != 1 || len(c.Signatures) != 1 {
		t.Errorf("certified: %+v, want 2 certifications and 1 other signature of another key, counted and not listed", c)
	}

	rn := u("renewed")
	if !rn.Valid || rn.Revoked || !rn.RevokedAt.IsZero() || !rn.Created.Equal(fkAt(1050)) {
		t.Errorf("renewed: a soft revocation that is older than the newest self-signature does not revoke: %+v", rn)
	}
	ss := u("samesecond")
	if !ss.Valid || !ss.Revoked || !ss.RevokedAt.Equal(fkAt(1010)) {
		t.Errorf("samesecond: a revocation in the same second must revoke: %+v", ss)
	}
	nw := u("newest")
	if !nw.Valid || nw.KeyFlags != 1 || nw.Primary || !nw.Created.Equal(fkAt(1200)) {
		t.Errorf("newest: the fields come from the newest self-signature, not the last in the file: %+v", nw)
	}
	eq := u("equal")
	if !eq.Valid || eq.KeyFlags != 2 || !eq.Created.Equal(fkAt(1300)) {
		t.Errorf("equal: of two self-signatures in the same second the later in the file gives the fields: %+v", eq)
	}
	mp := u("misplaced")
	if mp.Valid || len(mp.Signatures) != 1 || mp.Signatures[0].Status != openpgp.SignatureMisplaced || mp.Signatures[0].Type != 0x18 {
		t.Errorf("misplaced: %+v", mp)
	}
	if bare := u("bare"); bare.Valid || len(bare.Signatures) != 0 || bare.Certifications != 0 {
		t.Errorf("bare: %+v", bare)
	}
}

func fkViewSubkeys(t *testing.T, k *openpgp.ForeignKey, r *fkRich) {
	t.Helper()
	s := func(name string) openpgp.ForeignSubkey {
		t.Helper()
		got := k.Subkeys[r.sub[name]]
		d := r.donor[name]
		// a subkey with no binding that verifies is left out of the certificate and has no fingerprint
		inCert := name != "revokedonly" && name != "other" && name != "misplaced"
		wantFP := ""
		if inCert {
			wantFP = hexOf(d.pair.pub.Fingerprint)
		}
		if got.Fingerprint != wantFP || got.InCertificate != inCert || got.Algorithm != d.want {
			t.Fatalf("subkey %d is %q %+v in certificate %v, want %q %+v %v (the order of the file)", r.sub[name], got.Fingerprint, got.Algorithm, got.InCertificate, wantFP, d.want, inCert)
		}
		if got.Form != r.form[name].wantForm() {
			t.Errorf("%s: form %v, want %v", name, got.Form, r.form[name].wantForm())
		}
		return got
	}
	created := fkEpoch.Add(time.Hour)

	v := s("valid")
	if !v.Bound || v.Revoked || v.Flags != 0x0C || !v.BoundAt.Equal(fkAt(1000)) || !v.Expires.Equal(created.Add(30*24*time.Hour)) || !v.Created.Equal(created) {
		t.Errorf("valid: %+v", v)
	}
	ex := s("expired")
	if !ex.Bound || len(ex.Signatures) != 1 || !ex.Signatures[0].Expires.Equal(fkAt(1000).Add(time.Minute)) || !ex.Expires.Equal(created.Add(time.Minute)) {
		t.Errorf("expired: %+v (reported with its dates, not refused)", ex)
	}
	rv := s("revoked")
	if !rv.Bound || !rv.Revoked || len(rv.Signatures) != 2 || rv.Signatures[1].Type != 0x28 || !rv.Signatures[1].HasReason || rv.Signatures[1].Reason != 3 {
		t.Errorf("revoked: %+v", rv)
	}
	if rb := s("rebound"); !rb.Bound || rb.Revoked || !rb.BoundAt.Equal(fkAt(1010)) {
		t.Errorf("rebound: a binding newer than the revocation: %+v", rb)
	}
	if ro := s("revokedonly"); ro.Bound || !ro.Revoked {
		t.Errorf("revokedonly: %+v", ro)
	}
	nb := s("nobacksig")
	if nb.Bound || len(nb.Signatures) != 1 || nb.Signatures[0].Status != openpgp.SignatureNotVerified {
		t.Errorf("nobacksig: a signing subkey with no back-signature is bound: %+v", nb)
	}
	if bs := s("backsig"); !bs.Bound || bs.Flags != 0x02 {
		t.Errorf("backsig: %+v", bs)
	}
	ot := s("other")
	if ot.Bound || ot.OtherSignatures != 1 || len(ot.Signatures) != 0 {
		t.Errorf("other: %+v", ot)
	}
	tb := s("twobind")
	if !tb.Bound || tb.Flags != 0x08 || !tb.BoundAt.Equal(fkAt(1005)) || len(tb.Signatures) != 2 {
		t.Errorf("twobind: the newest binding gives the fields, not the last in the file: %+v", tb)
	}
	for _, n := range []string{"public", "dummy", "card", "card254", "otherpass", "garbage"} {
		if got := s(n); !got.Bound || got.Revoked || got.Flags != 0x0C {
			t.Errorf("%s: %+v", n, got)
		}
	}
	wb := s("weakbind")
	if !wb.Bound || !wb.WeakHash || len(wb.Signatures) != 1 || wb.Signatures[0].Status != openpgp.SignatureValidWeakHash || wb.Flags != 0x0C {
		t.Errorf("weakbind: a SHA-1 binding that verifies is bound and flagged: %+v", wb)
	}
	if mp := s("misplaced"); mp.Bound || len(mp.Signatures) != 1 || mp.Signatures[0].Status != openpgp.SignatureMisplaced {
		t.Errorf("misplaced: %+v", mp)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// A key none of whose user IDs has a valid self-signature is refused by its kind, with a text that
// counts what the signatures were and shows no user ID.
func TestForeignNoValidSelfSignature(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		me := b.primaryPair()
		_, _, other := fkDonors(t)
		head := fkTemplateHead(t, b.file(t, fkProt{}))
		primary, uid := head[0], head[1]
		sig := func(s fkSigSpec) fkPacket { return fkSplit(t, b.certSig(t, me, me.pub, fkUser, s))[0] }
		third := fkSplit(t, b.certSig(t, other, me.pub, fkUser, fkSigSpec{Typ: gpacket.SigTypeGenericCert}))[0]
		good := sig(fkSigSpec{Typ: gpacket.SigTypePositiveCert})
		withHash := func(p fkPacket, h byte) fkPacket {
			body := bytes.Clone(p.Body)
			body[3] = h // the hash octet of a version 4 signature: the signature was made with SHA-256
			return fkPacket{2, body}
		}
		bad := bytes.Clone(good.Body)
		bad[len(bad)-1] ^= 1
		cases := []struct {
			name  string
			ps    []fkPacket
			words []string
		}{
			{"no user ID at all", []fkPacket{primary}, []string{"0 user IDs"}},
			{"a user ID with no signature", []fkPacket{primary, uid}, []string{"1 user IDs"}},
			{"only an MD5 self-signature", []fkPacket{primary, uid, withHash(good, 1)}, []string{"1 with a weak hash"}},
			{"only a RIPEMD-160 self-signature", []fkPacket{primary, uid, withHash(good, 3)}, []string{"1 with a weak hash"}},
			{"only a SHA-1 self-signature that does not verify", []fkPacket{primary, uid, withHash(good, 2)}, []string{"1 that do not verify"}},
			{"only a SHA-224 self-signature", []fkPacket{primary, uid, sig(fkSigSpec{Typ: gpacket.SigTypePositiveCert, Hash: crypto.SHA224})}, []string{"1 with a hash that is not accepted"}},
			{"only a critical subpacket", []fkPacket{primary, uid, sig(fkSigSpec{Typ: gpacket.SigTypePositiveCert, Critical: true})}, []string{"1 with an unknown critical subpacket"}},
			{"only a self-signature that does not verify", []fkPacket{primary, uid, {2, bad}}, []string{"1 that do not verify"}},
			{"only a certification by another key", []fkPacket{primary, uid, third}, []string{"1 user IDs"}},
			{"only a revocation", []fkPacket{primary, uid, sig(fkSigSpec{Typ: gpacket.SigTypeCertificationRevocation})}, []string{"1 user IDs"}},
			{"only a user attribute", []fkPacket{primary, fkAttribute(t, 20), sig(fkSigSpec{Typ: gpacket.SigTypePositiveCert})}, []string{"0 user IDs"}},
		}
		for _, c := range cases {
			err := fkRefused(t, c.name, fkJoin(c.ps...), b, openpgp.ErrForeignSelfSignature)
			if err == nil {
				continue
			}
			for _, w := range c.words {
				if !bytes.Contains([]byte(err.Error()), []byte(w)) {
					t.Errorf("%s: the text %q does not say %q", c.name, err, w)
				}
			}
		}
	})
}

// The signatures that the primary claims, in every form of claim and every fault of the head, made
// with an Ed25519 primary and a signer of the tests: the tests write the hashed area themselves.

// fkSubpacket writes one subpacket.
func fkSubpacket(typ byte, critical bool, data ...byte) []byte {
	n := len(data) + 1
	var out []byte
	switch {
	case n < 192:
		out = []byte{byte(n)}
	default:
		out = []byte{byte((n-192)>>8) + 192, byte(n - 192)}
	}
	if critical {
		typ |= 0x80
	}
	return append(append(out, typ), data...)
}

func fkU32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// fkEdSig is a version 4 certification of the user ID fkUser by the Ed25519 template, with the areas
// given and the hash SHA-256 (8). The signature is made over the hashed area as it is.
func fkEdSig(t testing.TB, b *fkBase, typ byte, hashed, unhashed []byte) []byte {
	t.Helper()
	priv, ok := b.ent.PrivateKey.PrivateKey.(*eddsa.PrivateKey)
	if !ok {
		t.Fatalf("not an EdDSA key")
	}
	pub := b.pubBody(t)
	h := sha256.New()
	h.Write([]byte{0x99, byte(len(pub) >> 8), byte(len(pub))})
	h.Write(pub)
	h.Write([]byte{0xB4})
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(fkUser))))
	h.Write([]byte(fkUser))
	tail := append([]byte{4, typ, 22, 8, byte(len(hashed) >> 8), byte(len(hashed))}, hashed...)
	h.Write(tail)
	h.Write([]byte{4, 0xFF})
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(tail))))
	digest := h.Sum(nil)
	r, s, err := eddsa.Sign(priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	body := append(bytes.Clone(tail), byte(len(unhashed)>>8), byte(len(unhashed)))
	body = append(body, unhashed...)
	body = append(body, digest[:2]...)
	body = append(body, fkMPI(r)...)
	body = append(body, fkMPI(s)...)
	return body
}

func TestForeignSignatureClaims(t *testing.T) {
	b := fkNamed(t, "ed25519")
	me := b.primaryPair()
	fp := me.pub.Fingerprint
	keyID := fp[12:]
	created := fkSubpacket(2, false, fkU32(uint32(fkAt(1000).Unix()))...)
	issuerFP := fkSubpacket(33, false, append([]byte{4}, fp...)...)
	issuerID := fkSubpacket(16, false, keyID...)
	flags := fkSubpacket(27, false, 3)
	otherFP := fkSubpacket(33, false, append([]byte{4}, bytes.Repeat([]byte{0x77}, 20)...)...)
	otherID := fkSubpacket(16, false, bytes.Repeat([]byte{0x77}, 8)...)
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	type want struct {
		status openpgp.SignatureStatus // 0: the signature is not the primary's: counted as a certification
		valid  bool
	}
	cases := []struct {
		name             string
		typ              byte
		hashed, unhashed []byte
		want             want
	}{
		{"issuer fingerprint, hashed", 0x13, cat(created, issuerFP, flags), nil, want{openpgp.SignatureValid, true}},
		{"issuer key ID, hashed, and no fingerprint", 0x13, cat(created, issuerID), nil, want{openpgp.SignatureValid, true}},
		{"issuer key ID, unhashed, and no fingerprint", 0x13, created, issuerID, want{openpgp.SignatureValid, true}},
		{"both, fingerprint and key ID", 0x13, cat(created, issuerFP), issuerID, want{openpgp.SignatureValid, true}},
		{"no issuer at all", 0x13, created, nil, want{0, false}},
		{"the fingerprint of another key and our key ID, unhashed", 0x13, cat(created, otherFP), issuerID, want{0, false}},
		{"the key ID of another key, hashed, and our fingerprint is absent", 0x13, cat(created, otherID), issuerID, want{0, false}},
		{"a fingerprint of the wrong length", 0x13, cat(created, fkSubpacket(33, false, append([]byte{4}, fp[:19]...)...)), issuerID, want{0, false}},
		{"a fingerprint of version 5", 0x13, cat(created, fkSubpacket(33, false, append([]byte{5}, fp...)...)), issuerID, want{0, false}},
		{"two creation times", 0x13, cat(created, created, issuerFP), nil, want{openpgp.SignatureUnreadable, false}},
		{"no creation time", 0x13, cat(issuerFP), nil, want{openpgp.SignatureUnreadable, false}},
		{"a creation time of three bytes", 0x13, cat(fkSubpacket(2, false, 1, 2, 3), issuerFP), nil, want{openpgp.SignatureUnreadable, false}},
		{"two sets of key flags", 0x13, cat(created, issuerFP, flags, flags), nil, want{openpgp.SignatureUnreadable, false}},
		{"two primary user ID flags", 0x13, cat(created, issuerFP, fkSubpacket(25, false, 1), fkSubpacket(25, false, 1)), nil, want{openpgp.SignatureUnreadable, false}},
		{"a signature expiration of three bytes", 0x13, cat(created, issuerFP, fkSubpacket(3, false, 1, 2, 3)), nil, want{openpgp.SignatureUnreadable, false}},
		{"a non-critical subpacket of an unknown type", 0x13, cat(created, issuerFP, fkSubpacket(100, false, 1, 2, 3)), nil, want{openpgp.SignatureValid, true}},
		{"a critical subpacket of an unknown type", 0x13, cat(created, issuerFP, fkSubpacket(100, true, 1, 2, 3)), nil, want{openpgp.SignatureUnknownCritical, false}},
		{"a critical subpacket of an unknown type in the unhashed area", 0x13, cat(created, issuerFP), fkSubpacket(100, true, 1), want{openpgp.SignatureUnknownCritical, false}},
		{"a critical notation", 0x13, cat(created, issuerFP, fkSubpacket(20, true, make([]byte, 8)...)), nil, want{openpgp.SignatureUnknownCritical, false}},
		{"a critical subpacket that is understood (preferred ciphers)", 0x13, cat(created, issuerFP, fkSubpacket(11, true, 9)), nil, want{openpgp.SignatureValid, true}},
		{"a signature expiration of zero is no expiry", 0x13, cat(created, issuerFP, fkSubpacket(3, false, fkU32(0)...)), nil, want{openpgp.SignatureValid, true}},
		{"a key expiration of zero is no expiry", 0x13, cat(created, issuerFP, fkSubpacket(9, false, fkU32(0)...)), nil, want{openpgp.SignatureValid, true}},
		{"a binding signature on a user ID", 0x18, cat(created, issuerFP), nil, want{openpgp.SignatureMisplaced, false}},
		{"a direct-key signature on a user ID", 0x1F, cat(created, issuerFP), nil, want{openpgp.SignatureMisplaced, false}},
		{"a key revocation on a user ID", 0x20, cat(created, issuerFP), nil, want{openpgp.SignatureMisplaced, false}},
		{"a certification revocation is listed, not a self-signature", 0x30, cat(created, issuerFP), nil, want{openpgp.SignatureValid, false}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			head := fkTemplateHead(t, b.file(t, fkProt{}))
			sig := fkPacket{2, fkEdSig(t, b, c.typ, c.hashed, c.unhashed)}
			// one valid self-signature so that the key is not refused, and the one under test
			file := fkJoin(head[0], head[1], sig, head[2])
			k := fkRead(t, file)
			u := k.UserIDs[0]
			if !u.Valid {
				t.Fatal("the control self-signature is not valid")
			}
			if c.want.status == 0 {
				if u.Certifications != 1 || len(u.Signatures) != 1 {
					t.Errorf("a signature that is not the primary's: %d certifications and %d listed, want 1 and 0 more than the control", u.Certifications, len(u.Signatures))
				}
				return
			}
			if len(u.Signatures) != 2 {
				t.Fatalf("%d signatures listed, want 2: %+v", len(u.Signatures), u.Signatures)
			}
			if got := u.Signatures[0]; got.Status != c.want.status || got.Type != c.typ {
				t.Errorf("status %v of type %#x, want %v of %#x", got.Status, got.Type, c.want.status, c.typ)
			}
			if u.Certifications != 0 {
				t.Errorf("%d certifications of other keys, want 0", u.Certifications)
			}
		})
	}
}

// A signature of the primary with another hash: the status follows from the hash alone, before any
// check of the signature, and each hash is named.
func TestForeignSignatureHashes(t *testing.T) {
	b := fkNamed(t, "ed25519")
	me := b.primaryPair()
	issuerFP := fkSubpacket(33, false, append([]byte{4}, me.pub.Fingerprint...)...)
	created := fkSubpacket(2, false, fkU32(uint32(fkAt(1000).Unix()))...)
	cases := []struct {
		id     byte
		name   string
		status openpgp.SignatureStatus
	}{
		{1, "MD5", openpgp.SignatureWeakHash},
		{2, "SHA-1", openpgp.SignatureNotVerified},
		{3, "RIPEMD-160", openpgp.SignatureWeakHash},
		{4, "hash 4", openpgp.SignatureWeakHash},
		{7, "hash 7", openpgp.SignatureWeakHash},
		{8, "SHA-256", openpgp.SignatureValid},
		{9, "SHA-384", openpgp.SignatureValid},
		{10, "SHA-512", openpgp.SignatureValid},
		{11, "SHA-224", openpgp.SignatureHashNotAccepted},
		{12, "SHA3-256", openpgp.SignatureHashNotAccepted},
		{14, "SHA3-512", openpgp.SignatureHashNotAccepted},
		{13, "hash 13", openpgp.SignatureHashNotAccepted},
		{99, "hash 99", openpgp.SignatureHashNotAccepted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			head := fkTemplateHead(t, b.file(t, fkProt{}))
			body := fkEdSig(t, b, 0x13, append(bytes.Clone(created), issuerFP...), nil)
			body[3] = c.id // the hash number; only a hash that the reader takes keeps a signature that verifies
			file := fkJoin(head[0], head[1], fkPacket{2, body}, head[2])
			k := fkRead(t, file)
			u := k.UserIDs[0]
			if len(u.Signatures) != 2 || u.Signatures[0].Hash != c.name {
				t.Fatalf("signatures %+v, want the hash %s", u.Signatures, c.name)
			}
			want := c.status
			if c.id == 9 || c.id == 10 || c.id == 2 {
				want = openpgp.SignatureNotVerified // the digest was made with SHA-256, and SHA-1, 384 and 512 go on to be verified
			}
			if u.Signatures[0].Status != want {
				t.Errorf("status %v, want %v", u.Signatures[0].Status, want)
			}
		})
	}
}

// A signature of version 3, 5 or 6, and one cut short.
func TestForeignSignatureVersions(t *testing.T) {
	b := fkNamed(t, "ed25519")
	me := b.primaryPair()
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	v3 := append([]byte{3, 5, 0x13}, fkU32(uint32(fkAt(1000).Unix()))...)
	v3 = append(v3, me.pub.Fingerprint[12:]...)
	v3 = append(v3, 22, 8, 0, 0, 0, 1, 1, 0, 1, 1)
	v3other := append([]byte{3, 5, 0x13}, fkU32(0)...)
	v3other = append(v3other, bytes.Repeat([]byte{0x77}, 8)...)
	v3other = append(v3other, 22, 8, 0, 0, 0, 1, 1, 0, 1, 1)
	cases := []struct {
		name     string
		body     []byte
		listed   int // signatures listed after the control one
		certs    int
		others   int
		status   openpgp.SignatureStatus
		hasEntry bool
	}{
		{"version 3 by this key", v3, 1, 0, 0, openpgp.SignatureUnreadable, true},
		{"version 3 by another key", v3other, 0, 1, 0, 0, false},
		{"version 5", []byte{5, 0x13, 22, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 1, 0, 0, false},
		{"version 6", []byte{6, 0x13, 22, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 1, 0, 0, false},
		{"cut short after the type", []byte{4, 0x13}, 0, 1, 0, 0, false},
		{"cut short in the hashed area", []byte{4, 0x13, 22, 8, 0, 20, 1, 2}, 0, 1, 0, 0, false},
		{"one byte, whose type cannot be read", []byte{4}, 0, 0, 1, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			file := fkJoin(head[0], head[1], fkPacket{2, c.body}, head[2])
			k := fkRead(t, file)
			u := k.UserIDs[0]
			if !u.Valid || u.Certifications != c.certs || u.OtherSignatures != c.others || len(u.Signatures) != 1+c.listed {
				t.Fatalf("certifications %d, others %d, listed %d: %+v", u.Certifications, u.OtherSignatures, len(u.Signatures), u)
			}
			if c.hasEntry && u.Signatures[0].Status != c.status {
				t.Errorf("status %v, want %v", u.Signatures[0].Status, c.status)
			}
		})
	}
}
