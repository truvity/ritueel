package openpgp_test

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // a SHA-1 signature is what the tests make: the reader counts it
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/eddsa"

	"ritueel.id/ritueel/internal/openpgp"
)

// The rules that the second round of the reader added: SHA-1 that verifies, hard and soft revocations,
// revocations that cannot be read, the new limits, the primes of the RSA primary, and the docs of a
// copy and of Certificate.

// fkWriter writes version 4 signatures of the Ed25519 template with the areas given, so that a
// test chooses every byte of both areas and of the hash. kind is "user" (a user ID of the primary),
// "key" (the primary itself) or "sub" (a subkey).
type fkWriter struct {
	b *fkBase
}

func (w fkWriter) sign(t testing.TB, kind string, typ byte, hashed, unhashed []byte, hashID byte, newHash func() hash.Hash, target []byte) []byte {
	t.Helper()
	priv, ok := w.b.ent.PrivateKey.PrivateKey.(*eddsa.PrivateKey)
	if !ok {
		t.Fatalf("not an EdDSA key")
	}
	pub := w.b.pubBody(t)
	h := newHash()
	h.Write([]byte{0x99, byte(len(pub) >> 8), byte(len(pub))})
	h.Write(pub)
	switch kind {
	case "user":
		h.Write([]byte{0xB4})
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(target))))
		h.Write(target)
	case "attr":
		h.Write([]byte{0xD1})
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(target))))
		h.Write(target)
	case "sub":
		h.Write([]byte{0x99, byte(len(target) >> 8), byte(len(target))})
		h.Write(target)
	}
	tail := append([]byte{4, typ, 22, hashID, byte(len(hashed) >> 8), byte(len(hashed))}, hashed...)
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

// areas are the usual hashed area: creation time, key flags where given, an issuer fingerprint.
func (w fkWriter) areas(at int, extra ...[]byte) []byte {
	out := fkSubpacket(2, false, fkU32(uint32(fkAt(at).Unix()))...)
	out = append(out, fkSubpacket(33, false, append([]byte{4}, w.b.ent.PrimaryKey.Fingerprint...)...)...)
	for _, e := range extra {
		out = append(out, e...)
	}
	return out
}

func fkReasonSub(code ...byte) []byte {
	if len(code) == 0 {
		return nil
	}
	return fkSubpacket(29, false, append(code, []byte("why")...)...)
}

// The file of the Ed25519 template with the signatures given on the user ID, on the key and on one
// subkey (a donor), after the template's own self-signature.
type fkParts struct {
	userSigs [][]byte
	keySigs  [][]byte
	subSigs  [][]byte // on the subkey, after its own binding
	noSelf   bool     // leave out the template's self-signature of the user ID
	noBind   bool     // leave out a binding of the subkey: the subkey is the donor with the signatures given only
}

func (w fkWriter) file(t testing.TB, p fkParts) []byte {
	t.Helper()
	enc, _, _ := fkDonors(t)
	head := fkTemplateHead(t, w.b.file(t, fkProt{}))
	ps := []fkPacket{head[0]}
	for _, s := range p.keySigs {
		ps = append(ps, fkPacket{2, s})
	}
	ps = append(ps, head[1])
	if !p.noSelf {
		ps = append(ps, head[2])
	}
	for _, s := range p.userSigs {
		ps = append(ps, fkPacket{2, s})
	}
	if p.subSigs != nil || !p.noBind {
		ps = append(ps, enc[3].pub)
		for _, s := range p.subSigs {
			ps = append(ps, fkPacket{2, s})
		}
	}
	return fkJoin(ps...)
}

func (w fkWriter) userSig(t testing.TB, typ byte, hashed, unhashed []byte) []byte {
	return w.sign(t, "user", typ, hashed, unhashed, 8, sha256.New, []byte(fkUser))
}

func (w fkWriter) keySig(t testing.TB, typ byte, hashed, unhashed []byte) []byte {
	return w.sign(t, "key", typ, hashed, unhashed, 8, sha256.New, nil)
}

func (w fkWriter) subSig(t testing.TB, typ byte, hashed, unhashed []byte) []byte {
	enc, _, _ := fkDonors(t)
	return w.sign(t, "sub", typ, hashed, unhashed, 8, sha256.New, enc[3].pub.Body)
}

// 4. SHA-1 that verifies counts, with its own status and a flag.
func TestForeignSHA1ThatVerifiesCounts(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	enc, _, _ := fkDonors(t)
	sha1Sig := func(kind string, typ byte, at int, target []byte) []byte {
		return w.sign(t, kind, typ, w.areas(at, fkSubpacket(27, false, 3)), nil, 2, sha1.New, target)
	}
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	one := func(sigs ...[]byte) *openpgp.ForeignKey {
		ps := []fkPacket{head[0], head[1]}
		for _, s := range sigs {
			ps = append(ps, fkPacket{2, s})
		}
		return fkRead(t, fkJoin(ps...))
	}

	// SHA-1 only: accepted, counted, flagged
	k := one(sha1Sig("user", 0x13, 1000, []byte(fkUser)))
	u := k.UserIDs[0]
	if !u.Valid || !u.WeakHash || len(u.Signatures) != 1 || u.Signatures[0].Status != openpgp.SignatureValidWeakHash || u.Signatures[0].Hash != "SHA-1" {
		t.Errorf("a SHA-1 self-signature that verifies: %+v", u)
	}
	if !u.Signatures[0].Status.Counts() || openpgp.SignatureValid.String() == openpgp.SignatureValidWeakHash.String() {
		t.Error("the status of a weak signature that counts does not count or has the name of a strong one")
	}
	// SHA-1 beside SHA-256: counted, not flagged
	k = one(sha1Sig("user", 0x13, 1000, []byte(fkUser)), w.userSig(t, 0x13, w.areas(1001, fkSubpacket(27, false, 3)), nil))
	if u := k.UserIDs[0]; !u.Valid || u.WeakHash || len(u.Signatures) != 2 {
		t.Errorf("SHA-1 beside SHA-256: %+v", u)
	}
	// SHA-1 that does not verify: not counted, and a key with only that is refused
	bad := sha1Sig("user", 0x13, 1000, []byte(fkUser))
	bad[len(bad)-1] ^= 1
	_ = fkRefused(t, "SHA-1 that does not verify", fkJoin(head[0], head[1], fkPacket{2, bad}), b, openpgp.ErrForeignSelfSignature)
	// a SHA-1 signature made over another user ID does not verify either
	other := sha1Sig("user", 0x13, 1000, []byte("someone else"))
	_ = fkRefused(t, "SHA-1 over another user ID", fkJoin(head[0], head[1], fkPacket{2, other}), b, openpgp.ErrForeignSelfSignature)
	// MD5 and RIPEMD-160 never count: the status is decided before any check
	for _, id := range []byte{1, 3} {
		body := w.sign(t, "user", 0x13, w.areas(1000), nil, id, sha256.New, []byte(fkUser))
		err := fkRefused(t, "a self-signature with a hash that does not count", fkJoin(head[0], head[1], fkPacket{2, body}), b, openpgp.ErrForeignSelfSignature)
		if err != nil && !strings.Contains(err.Error(), "weak hash") {
			t.Errorf("the text does not say weak hash: %v", err)
		}
	}
	// a SHA-1 binding: bound, flagged; beside a SHA-256 one, not flagged
	sha1Bind := w.sign(t, "sub", 0x18, w.areas(1000, fkSubpacket(27, false, 0x0C)), nil, 2, sha1.New, enc[3].pub.Body)
	file := w.file(t, fkParts{subSigs: [][]byte{sha1Bind}})
	s := fkRead(t, file).Subkeys[0]
	if !s.Bound || !s.WeakHash || s.Flags != 0x0C || s.Signatures[0].Status != openpgp.SignatureValidWeakHash {
		t.Errorf("a SHA-1 binding: %+v", s)
	}
	strong := w.sign(t, "sub", 0x18, w.areas(1000, fkSubpacket(27, false, 0x0C)), nil, 8, sha256.New, enc[3].pub.Body)
	file = w.file(t, fkParts{subSigs: [][]byte{sha1Bind, strong}})
	if s := fkRead(t, file).Subkeys[0]; !s.Bound || s.WeakHash {
		t.Errorf("a SHA-1 and a SHA-256 binding: %+v", s)
	}
	// a SHA-1 binding that does not verify does not bind
	badBind := bytes.Clone(sha1Bind)
	badBind[len(badBind)-1] ^= 1
	if s := fkRead(t, w.file(t, fkParts{subSigs: [][]byte{badBind}})).Subkeys[0]; s.Bound || s.WeakHash || s.Signatures[0].Status != openpgp.SignatureNotVerified {
		t.Errorf("a SHA-1 binding that does not verify: %+v", s)
	}
	// a SHA-1 key revocation that verifies counts: the key is revoked
	rev := w.sign(t, "key", 0x20, w.areas(1500, fkReasonSub(2)), nil, 2, sha1.New, nil)
	if !fkRead(t, w.file(t, fkParts{keySigs: [][]byte{rev}})).Primary.Revoked {
		t.Error("a SHA-1 key revocation that verifies does not revoke")
	}
	// the revocation with MD5 does not: it is listed as one that cannot be used
	md5rev := w.sign(t, "key", 0x20, w.areas(1500, fkReasonSub(2)), nil, 1, sha256.New, nil)
	k = fkRead(t, w.file(t, fkParts{keySigs: [][]byte{md5rev}}))
	if k.Primary.Revoked || k.UnreadableRevocations != 1 {
		t.Errorf("an MD5 key revocation: revoked %v, unreadable %d", k.Primary.Revoked, k.UnreadableRevocations)
	}
}

// 5. A hard revocation revokes whatever its date; a soft one only when it is not older.
func TestForeignHardAndSoftRevocations(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	reasons := []struct {
		name string
		code []byte // nil: no reason subpacket
		hard bool
	}{
		{"no reason subpacket", nil, true},
		{"no reason specified (0)", []byte{0}, true},
		{"key superseded (1)", []byte{1}, false},
		{"key material compromised (2)", []byte{2}, true},
		{"key retired (3)", []byte{3}, false},
		{"a code that is not known (4)", []byte{4}, true},
		{"a code that is not known (31)", []byte{31}, true},
		{"user ID no longer valid (32)", []byte{32}, false},
		{"a code that is not known (33)", []byte{33}, true},
		{"a code that is not known (255)", []byte{255}, true},
	}
	flags := fkSubpacket(27, false, 3)
	for _, r := range reasons {
		for _, when := range []struct {
			name string
			at   int // the revocation; the self-signature or binding is at 1000
		}{{"older", 900}, {"the same second", 1000}, {"newer", 1100}} {
			// soft: revokes only when it is not older; hard: whatever the date
			want := r.hard || when.at >= 1000
			t.Run("user ID, "+r.name+", "+when.name, func(t *testing.T) {
				self := w.userSig(t, 0x13, w.areas(1000, flags), nil)
				rev := w.userSig(t, 0x30, w.areas(when.at, fkReasonSub(r.code...)), nil)
				u := fkRead(t, w.file(t, fkParts{noSelf: true, userSigs: [][]byte{self, rev}})).UserIDs[0]
				if !u.Valid || u.Revoked != want {
					t.Errorf("revoked %v, want %v: %+v", u.Revoked, want, u)
				}
				if want && !u.RevokedAt.Equal(fkAt(when.at)) {
					t.Errorf("revoked at %v, want %v", u.RevokedAt, fkAt(when.at))
				}
				// the order of the file does not matter
				u = fkRead(t, w.file(t, fkParts{noSelf: true, userSigs: [][]byte{rev, self}})).UserIDs[0]
				if u.Revoked != want {
					t.Errorf("revocation first in the file: revoked %v, want %v", u.Revoked, want)
				}
			})
			t.Run("subkey, "+r.name+", "+when.name, func(t *testing.T) {
				bind := w.subSig(t, 0x18, w.areas(1000, fkSubpacket(27, false, 0x0C)), nil)
				rev := w.subSig(t, 0x28, w.areas(when.at, fkReasonSub(r.code...)), nil)
				s := fkRead(t, w.file(t, fkParts{subSigs: [][]byte{bind, rev}})).Subkeys[0]
				if !s.Bound || s.Revoked != want {
					t.Errorf("revoked %v, want %v: %+v", s.Revoked, want, s)
				}
				s = fkRead(t, w.file(t, fkParts{subSigs: [][]byte{rev, bind}})).Subkeys[0]
				if s.Revoked != want {
					t.Errorf("revocation first in the file: revoked %v, want %v", s.Revoked, want)
				}
			})
		}
		// with no binding or self-signature that counts, any revocation that counts revokes
		t.Run("subkey with no binding, "+r.name, func(t *testing.T) {
			rev := w.subSig(t, 0x28, w.areas(900, fkReasonSub(r.code...)), nil)
			s := fkRead(t, w.file(t, fkParts{subSigs: [][]byte{rev}})).Subkeys[0]
			if s.Bound || !s.Revoked {
				t.Errorf("%+v", s)
			}
		})
	}
	// a hard revocation and a soft one: the hard one wins whatever the dates
	self := w.userSig(t, 0x13, w.areas(1000, flags), nil)
	soft := w.userSig(t, 0x30, w.areas(900, fkReasonSub(32)), nil)
	hard := w.userSig(t, 0x30, w.areas(800, fkReasonSub(2)), nil)
	if u := fkRead(t, w.file(t, fkParts{noSelf: true, userSigs: [][]byte{self, soft, hard}})).UserIDs[0]; !u.Revoked || !u.RevokedAt.Equal(fkAt(800)) {
		t.Errorf("a hard and a soft revocation: %+v", u)
	}
	// the key revocation is hard whatever its reason and its date (the field of the primary says so)
	kflags := w.areas(1000, flags)
	direct := w.keySig(t, 0x1F, kflags, nil)
	for _, code := range [][]byte{nil, {1}, {2}, {3}, {32}} {
		rev := w.keySig(t, 0x20, w.areas(900, fkReasonSub(code...)), nil)
		if !fkRead(t, w.file(t, fkParts{keySigs: [][]byte{direct, rev}})).Primary.Revoked {
			t.Errorf("a key revocation with the reason %v, older than a direct-key signature, does not revoke", code)
		}
	}
	// the user ID "renewed" of the rich file: a revocation without a reason is hard, so a later
	// self-signature does not undo it, and one with the soft reason 32 is undone
	noReason := w.userSig(t, 0x30, w.areas(1000), nil)
	later := w.userSig(t, 0x13, w.areas(1050, flags), nil)
	if u := fkRead(t, w.file(t, fkParts{noSelf: true, userSigs: [][]byte{noReason, later}})).UserIDs[0]; !u.Revoked {
		t.Errorf("a revocation with no reason, then a newer self-signature: %+v, want revoked (it is hard)", u)
	}
	soft32 := w.userSig(t, 0x30, w.areas(1000, fkReasonSub(32)), nil)
	if u := fkRead(t, w.file(t, fkParts{noSelf: true, userSigs: [][]byte{soft32, later}})).UserIDs[0]; u.Revoked || !u.Created.Equal(fkAt(1050)) {
		t.Errorf("a soft revocation, then a newer self-signature: %+v, want not revoked", u)
	}
}

// 6. Revocations that cannot be read are listed and counted; one that is provably another key's is not.
func TestForeignUnreadableRevocations(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	fp := b.ent.PrimaryKey.Fingerprint
	created := fkSubpacket(2, false, fkU32(uint32(fkAt(1200).Unix()))...)
	issuer := fkSubpacket(33, false, append([]byte{4}, fp...)...)
	many := bytes.Clone(created)
	for i := 0; i < 40; i++ {
		many = append(many, fkSubpacket(100, false, byte(i))...)
	}
	many = append(many, issuer...)
	otherFP := fkSubpacket(33, false, append([]byte{4}, bytes.Repeat([]byte{0x77}, 20)...)...)
	otherV6 := fkSubpacket(33, false, append([]byte{6}, bytes.Repeat([]byte{0x77}, 32)...)...)
	otherID := fkSubpacket(16, false, bytes.Repeat([]byte{0x77}, 8)...)

	// one bad revocation body for each way that it cannot be read
	bodies := map[string]func(kind string, typ byte) []byte{
		"more than 32 subpackets": func(kind string, typ byte) []byte { return w.signFor(t, kind, typ, many, nil) },
		"a hashed area that runs past its packet": func(kind string, typ byte) []byte {
			return []byte{4, typ, 22, 8, 0xFF, 0xFF, 1, 2, 3}
		},
		"a signature cut short after its type": func(kind string, typ byte) []byte { return []byte{4, typ} },
		"a version 5 signature":                func(kind string, typ byte) []byte { return []byte{5, typ, 22, 8, 0, 0, 0, 0, 0, 0} },
		"a version 6 signature":                func(kind string, typ byte) []byte { return []byte{6, typ, 22, 8, 0, 0, 0, 0, 0, 0, 0, 0} },
		"a version 3 signature of another key": func(kind string, typ byte) []byte {
			return append([]byte{3, 5, typ}, append(fkU32(1), append(bytes.Repeat([]byte{0x77}, 8), 22, 8, 0, 0, 1, 1, 1)...)...)
		},
		"no issuer, a creation time that is not four bytes": func(kind string, typ byte) []byte {
			return w.signFor(t, kind, typ, fkSubpacket(2, false, 1, 2, 3), nil)
		},
		"an unknown critical subpacket": func(kind string, typ byte) []byte {
			return w.signFor(t, kind, typ, append(bytes.Clone(created), append(issuer, fkSubpacket(100, true, 1)...)...), nil)
		},
		"a hash that is not taken (SHA-224)": func(kind string, typ byte) []byte {
			body := w.signFor(t, kind, typ, append(bytes.Clone(created), issuer...), nil)
			body[3] = 11
			return body
		},
		"MD5": func(kind string, typ byte) []byte {
			body := w.signFor(t, kind, typ, append(bytes.Clone(created), issuer...), nil)
			body[3] = 1
			return body
		},
	}
	provablyOther := map[string]func(kind string, typ byte) []byte{
		"a hashed issuer fingerprint of another key": func(kind string, typ byte) []byte {
			return w.signFor(t, kind, typ, append(bytes.Clone(created), otherFP...), nil)
		},
		"a hashed issuer fingerprint of a version 6 key": func(kind string, typ byte) []byte {
			return w.signFor(t, kind, typ, append(bytes.Clone(created), otherV6...), nil)
		},
		"a hashed issuer key ID of another key": func(kind string, typ byte) []byte {
			return w.signFor(t, kind, typ, append(bytes.Clone(created), otherID...), nil)
		},
		"the fingerprint of another key and our key ID, unhashed": func(kind string, typ byte) []byte {
			return w.signFor(t, kind, typ, append(bytes.Clone(created), otherFP...), fkSubpacket(16, false, fp[12:]...))
		},
	}
	components := []struct {
		name  string
		kind  string
		typ   byte
		parts func(sig []byte) fkParts
		count func(k *openpgp.ForeignKey) (unreadable, other, listed int)
	}{
		{"the key", "key", 0x20, func(s []byte) fkParts { return fkParts{keySigs: [][]byte{s}} }, func(k *openpgp.ForeignKey) (int, int, int) {
			return k.UnreadableRevocations, k.OtherKeySignatures, len(k.KeySignatures)
		}},
		{"a user ID", "user", 0x30, func(s []byte) fkParts { return fkParts{userSigs: [][]byte{s}} }, func(k *openpgp.ForeignKey) (int, int, int) {
			u := k.UserIDs[0]
			return u.UnreadableRevocations, u.OtherSignatures + u.Certifications, len(u.Signatures) - 1
		}},
		{"a subkey", "sub", 0x28, func(s []byte) fkParts { return fkParts{subSigs: [][]byte{s}} }, func(k *openpgp.ForeignKey) (int, int, int) {
			s := k.Subkeys[0]
			return s.UnreadableRevocations, s.OtherSignatures, len(s.Signatures)
		}},
	}
	for _, c := range components {
		for name, mk := range bodies {
			t.Run(c.name+", "+name, func(t *testing.T) {
				k := fkRead(t, w.file(t, c.parts(mk(c.kind, c.typ))))
				unreadable, other, listed := c.count(k)
				if unreadable != 1 || other != 0 || listed != 1 {
					t.Errorf("unreadable %d, other %d, listed %d, want 1, 0 and 1", unreadable, other, listed)
				}
				if c.kind == "key" && k.Primary.Revoked {
					t.Error("a revocation that cannot be read revokes")
				}
			})
		}
		for name, mk := range provablyOther {
			t.Run(c.name+", "+name, func(t *testing.T) {
				k := fkRead(t, w.file(t, c.parts(mk(c.kind, c.typ))))
				unreadable, other, listed := c.count(k)
				if unreadable != 0 || other != 1 || listed != 0 {
					t.Errorf("unreadable %d, other %d, listed %d, want 0, 1 and 0", unreadable, other, listed)
				}
			})
		}
	}
	// a revocation that names no issuer and does not verify was read and is not the primary's: not counted;
	// one that names none and verifies is the primary's, and revokes
	noIssuer := w.signFor(t, "key", 0x20, created, nil)
	if k := fkRead(t, w.file(t, fkParts{keySigs: [][]byte{noIssuer}})); !k.Primary.Revoked || k.UnreadableRevocations != 0 {
		t.Errorf("a revocation with no issuer that verifies: revoked %v, unreadable %d", k.Primary.Revoked, k.UnreadableRevocations)
	}
	bad := bytes.Clone(noIssuer)
	bad[len(bad)-1] ^= 1
	if k := fkRead(t, w.file(t, fkParts{keySigs: [][]byte{bad}})); k.Primary.Revoked || k.UnreadableRevocations != 0 || len(k.KeySignatures) != 1 || k.KeySignatures[0].Status != openpgp.SignatureNotVerified {
		t.Errorf("a revocation with no issuer that does not verify: %+v", k.KeySignatures)
	}
}

// signFor signs for the kind of component with the areas given.
func (w fkWriter) signFor(t testing.TB, kind string, typ byte, hashed, unhashed []byte) []byte {
	t.Helper()
	enc, _, _ := fkDonors(t)
	switch kind {
	case "user":
		return w.sign(t, kind, typ, hashed, unhashed, 8, sha256.New, []byte(fkUser))
	case "sub":
		return w.sign(t, kind, typ, hashed, unhashed, 8, sha256.New, enc[3].pub.Body)
	}
	return w.sign(t, kind, typ, hashed, unhashed, 8, sha256.New, nil)
}

// 7. The new limits.
func TestForeignNewLimits(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	t.Run("MaxForeignUserIDBytes", func(t *testing.T) {
		// each user ID has its own self-signature by the primary
		ok := func(n int) []byte {
			text := bytes.Repeat([]byte("u"), n)
			sig := w.sign(t, "user", 0x13, w.areas(1000), nil, 8, sha256.New, text)
			return fkJoin(head[0], fkPacket{13, text}, fkPacket{2, sig})
		}
		k, err := openpgp.ReadForeignKey(ok(openpgp.MaxForeignUserIDBytes))
		if err != nil || len(k.UserIDs[0].Text) != openpgp.MaxForeignUserIDBytes || !k.UserIDs[0].Valid {
			t.Fatalf("a user ID of the limit: %v", err)
		}
		err = fkRefused(t, "a user ID one byte past the limit", ok(openpgp.MaxForeignUserIDBytes+1), b, openpgp.ErrForeignLimit)
		if err != nil && !strings.Contains(err.Error(), "MaxForeignUserIDBytes") {
			t.Errorf("the text does not name the limit: %v", err)
		}
		// a user attribute keeps the limit of a packet
		attr := fkPacket{17, make([]byte, openpgp.MaxForeignUserIDBytes+1)}
		if _, err := openpgp.ReadForeignKey(fkJoin(head[0], head[1], head[2], attr)); err != nil {
			t.Errorf("a user attribute past the limit of a user ID: %v", err)
		}
	})
	t.Run("MaxForeignClaimedSignatures", func(t *testing.T) {
		self := w.userSig(t, 0x13, w.areas(1000), nil)
		third := fkThird(t, b)
		cert := fkPacket{2, third.Body}
		build := func(claimed int, others int, extra ...fkPacket) []byte {
			// at most 1000 signatures stand on one user ID: the claimed ones are spread over user IDs
			ps := []fkPacket{head[0], head[1]}
			for i := 0; i < claimed; i++ {
				if i > 0 && i%1000 == 0 {
					ps = append(ps, fkPacket{13, []byte(fmt.Sprintf("spare %d <spare%d@example.org>", i, i))})
				}
				ps = append(ps, fkPacket{2, self})
			}
			for i := 0; i < others; i++ {
				ps = append(ps, cert)
			}
			return fkJoin(append(ps, extra...)...)
		}
		n := openpgp.MaxForeignClaimedSignatures
		k, err := openpgp.ReadForeignKey(build(n, 0))
		if err != nil {
			t.Fatalf("the limit: %v", err)
		}
		listed := 0
		for _, u := range k.UserIDs {
			listed += len(u.Signatures)
		}
		if listed != n {
			t.Fatalf("%d signatures listed at the limit, want %d", listed, n)
		}
		err = fkRefused(t, "one past the limit", build(n+1, 0), b, openpgp.ErrForeignLimit)
		if err != nil && !strings.Contains(err.Error(), "MaxForeignClaimedSignatures") {
			t.Errorf("the text does not name the limit: %v", err)
		}
		// certifications of other keys do not count toward it
		k, err = openpgp.ReadForeignKey(build(n-1, 400))
		certs := 0
		if k != nil {
			for _, u := range k.UserIDs {
				certs += u.Certifications
			}
		}
		if err != nil || certs != 400 {
			t.Errorf("the limit less one with 400 certifications of another key: %v", err)
		}
		k, err = openpgp.ReadForeignKey(build(1, openpgp.MaxForeignSignatures-1))
		if err != nil || k.UserIDs[0].Certifications != openpgp.MaxForeignSignatures-1 {
			t.Errorf("1023 certifications of other keys: %v", err)
		}
		// a revocation that is not provably another key's counts, one that is provably another's does not
		created := fkSubpacket(2, false, fkU32(uint32(fkAt(1200).Unix()))...)
		unknown := fkPacket{2, w.signFor(t, "user", 0x30, created, nil)}
		provable := fkPacket{2, w.signFor(t, "user", 0x30, append(bytes.Clone(created), fkSubpacket(33, false, append([]byte{4}, bytes.Repeat([]byte{0x77}, 20)...)...)...), nil)}
		if _, err := openpgp.ReadForeignKey(build(n-1, 0, unknown)); err != nil {
			t.Errorf("the limit less one and a revocation with no issuer: %v", err)
		}
		_ = fkRefused(t, "a revocation with no issuer counts", build(n, 0, unknown), b, openpgp.ErrForeignLimit)
		if _, err := openpgp.ReadForeignKey(build(n, 0, provable, provable, provable)); err != nil {
			t.Errorf("a revocation that is provably another key's counts: %v", err)
		}
		// the signatures on all components are counted together
		ps := []fkPacket{head[0], head[1], head[2]}
		enc, _, _ := fkDonors(t)
		for i := 0; i < n/2+1; i++ {
			if i > 0 && i%1000 == 0 {
				ps = append(ps, fkPacket{13, []byte("spare <spare@example.org>")})
			}
			ps = append(ps, fkPacket{2, self})
		}
		ps = append(ps, enc[0].pub)
		bind := fkPacket{2, w.subSig(t, 0x18, w.areas(1000), nil)}
		for i := 0; i < n/2; i++ {
			ps = append(ps, bind)
		}
		_ = fkRefused(t, "claimed signatures on two components", fkJoin(ps...), b, openpgp.ErrForeignLimit)
	})
}

// 9. The copy of the secret that the reader made is cleared when it refuses. What a test can see is that
// a refusal leaves no key, changes no byte of the file, and spoils nothing for the next read; that the
// copy is zero is not observable from outside the package.
func TestForeignRefusalAfterTheSecretWasClassified(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, prot := range []fkProt{{}, {Pass: fkPass}} {
			good := b.file(t, prot)
			ps := fkSplit(t, good)
			cases := map[string][]fkPacket{
				"no user ID":             {ps[0]},
				"no self-signature":      {ps[0], ps[1]},
				"a second primary":       append(append([]fkPacket{}, ps...), ps[0]),
				"a packet that is wrong": append(append([]fkPacket{}, ps...), fkPacket{8, []byte{1}}),
				"a subkey with no area":  append(append([]fkPacket{}, ps[:3]...), fkPacket{7, ps[3].Body[:20]}),
			}
			for name, c := range cases {
				file := fkJoin(c...)
				before := bytes.Clone(file)
				k, err := openpgp.ReadForeignKey(file)
				if k != nil || err == nil {
					t.Errorf("%s: read", name)
				}
				if !bytes.Equal(file, before) {
					t.Errorf("%s: the file changed", name)
				}
				fkCheckText(t, name, err, b)
				// a read of the good file after the refusal gives a key that opens
				again := fkRead(t, good)
				s, err := again.OpenSecret([]byte(prot.Pass))
				if err != nil {
					t.Fatalf("%s: the next read does not open: %v", name, err)
				}
				s.Wipe()
			}
		}
	})
}

// 10. The docs of a copy of a ForeignKey, of Certificate and of the other signatures.
func TestForeignDocsOfACopyAndOfCertificate(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, prot := range []fkProt{{}, {Pass: fkPass}} {
			// "A wipe of the copy does not mark the original as wiped": the original does not say ErrParams,
			// and since the memory is shared, it opens nothing either
			k := fkRead(t, b.file(t, prot))
			c := *k //nolint:govet // the doc comment speaks of a copy of the struct
			c.Wipe()
			s, err := c.OpenSecret([]byte(prot.Pass))
			if s != nil || !errors.Is(err, openpgp.ErrParams) {
				t.Errorf("the wiped copy: %v, want ErrParams", err)
			}
			s, err = k.OpenSecret([]byte(prot.Pass))
			if s != nil || err == nil {
				t.Errorf("the original after the wipe of the copy opens: %v", err)
			}
			if errors.Is(err, openpgp.ErrParams) {
				t.Errorf("the wipe of the copy marked the original as wiped: %v", err)
			}
			if !errors.Is(err, openpgp.ErrWrongPassphrase) && !errors.Is(err, openpgp.ErrForeignSecret) {
				t.Errorf("the original after the wipe of the copy says %v, want ErrWrongPassphrase or ErrForeignSecret", err)
			}
		}
	})
	// Certificate holds what the primary signed and no more: no user ID or subkey that nothing
	// confirms, no signature of another key, no signature that does not verify
	b := fkNamed(t, "ed25519")
	r := fkRichOf(t, b, false, false)
	k := fkRead(t, r.file)
	ps := fkCertProperty(t, "the rich file", k)
	invalid, certified, unconfirmed := 0, 0, 0
	for _, u := range k.UserIDs {
		if !u.Valid {
			invalid++
		}
		certified += u.Certifications + u.OtherSignatures
	}
	for _, s := range k.Subkeys {
		if !s.InCertificate {
			unconfirmed++
		}
	}
	if invalid == 0 || unconfirmed == 0 || certified == 0 {
		t.Fatalf("the rich file holds no user ID or subkey that is not valid, or no signature of another key (%d, %d, %d)", invalid, unconfirmed, certified)
	}
	if got, want := len(fkCertUsers(ps)), len(k.UserIDs)-invalid; got != want {
		t.Errorf("the certificate holds %d user IDs, the view says %d are valid", got, want)
	}
	if got, want := len(fkCertSubkeys(ps)), len(k.Subkeys)-unconfirmed; got != want {
		t.Errorf("the certificate holds %d subkeys, the view says %d are in it", got, want)
	}
	// "other signatures": those that the primary does not claim, and those whose type is not read and
	// whose issuer is not the primary's; a signature of an unknown type that the primary made is listed
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	w := fkWriter{b}
	created := w.areas(1000)
	other := fkSubpacket(33, false, append([]byte{4}, bytes.Repeat([]byte{0x77}, 20)...)...)
	unknownTypeByOther := w.signFor(t, "user", 0x00, append(fkSubpacket(2, false, fkU32(5)...), other...), nil)
	unknownTypeByPrimary := w.signFor(t, "user", 0x00, created, nil)
	u := fkRead(t, fkJoin(head[0], head[1], head[2], fkPacket{2, unknownTypeByOther}, fkPacket{2, unknownTypeByPrimary})).UserIDs[0]
	if u.OtherSignatures != 1 || u.Certifications != 0 || len(u.Signatures) != 2 || u.Signatures[1].Status != openpgp.SignatureMisplaced {
		t.Errorf("signatures of an unknown type: %+v", u)
	}
	cut := fkRead(t, fkJoin(head[0], head[1], head[2], fkPacket{2, []byte{4}})).UserIDs[0]
	if cut.OtherSignatures != 1 {
		t.Errorf("a signature whose type cannot be read: %+v", cut)
	}
}
