package openpgp_test

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"slices"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// The order of the packets decides nothing that the snapshot says: the same signatures in every order give
// one snapshot, whatever ties they hold. The certificate bytes differ with the order; the snapshot does not.

// qaPermutations calls f with every order of the elements of s.
func qaPermutations[T any](s []T, f func([]T)) {
	var rec func(k int)
	cur := slices.Clone(s)
	rec = func(k int) {
		if k == len(cur) {
			f(slices.Clone(cur))
			return
		}
		for i := k; i < len(cur); i++ {
			cur[k], cur[i] = cur[i], cur[k]
			rec(k + 1)
			cur[k], cur[i] = cur[i], cur[k]
		}
	}
	rec(0)
}

func TestQASnapshotDoesNotDependOnAnyOrderOfTheFile(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	sp := fkSubpacket
	life := func(days uint32) []byte { return sp(9, true, fkU32(days*86400)...) }
	flags := func(f byte) []byte { return sp(27, false, f) }
	enc, _, _ := fkDonors(t)
	const A, B, C = "Alpha Person <alpha@example.org>", "Bravo Person <bravo@example.org>", "Charlie Person <charlie@example.org>"

	// four self-signatures of one user ID: two strong in one second with other ends, a strong one in the same
	// second with the same end as the first and other subpackets, and a SHA-1 one in the same second
	userSigs := [][]byte{
		qaUserSig(t, w, A, 0x13, 8, 1000, flags(1), life(10), sp(21, false, 8)),
		qaUserSig(t, w, A, 0x13, 8, 1000, flags(2), life(20), sp(21, false, 10)),
		qaUserSig(t, w, A, 0x13, 8, 1000, flags(4), life(10), sp(11, false, 9)),
		qaUserSig(t, w, A, 0x13, 2, 1000, flags(8), life(10), sp(30, false, 1)),
	}
	// three user IDs with ends of their own, one of them marked primary
	others := []qaUserBlock{
		{B, [][]byte{qaUserSig(t, w, B, 0x13, 8, 1100, flags(3), life(365), sp(25, false, 1))}},
		{C, [][]byte{qaUserSig(t, w, C, 0x13, 8, 1100, flags(3), life(365))}},
	}
	// three direct-key signatures in one second: two ends and none
	keySigs := [][]byte{
		qaKeySig(t, w, 0x1F, 8, 1200, life(30)),
		qaKeySig(t, w, 0x1F, 8, 1200, life(20)),
		qaKeySig(t, w, 0x1F, 8, 1200),
	}
	// two subkeys, one of them with two bindings in one second
	bind := func(d fkDonorKey, at int, f byte) fkPacket {
		return fkPacket{2, w.sign(t, "sub", 0x18, w.areas(at, flags(f)), nil, 8, sha256.New, d.pub.Body)}
	}
	subs := [][]fkPacket{
		{enc[0].pub, bind(enc[0], 1000, 0x0C), bind(enc[0], 1000, 0x04)},
		{enc[1].pub, bind(enc[1], 1000, 0x0C)},
	}
	build := func(ks [][]byte, blocks []qaUserBlock, ss [][]fkPacket) []byte {
		head := fkTemplateHead(t, b.file(t, fkProt{}))
		ps := []fkPacket{head[0]}
		for _, s := range ks {
			ps = append(ps, fkPacket{2, s})
		}
		for _, u := range blocks {
			ps = append(ps, fkPacket{13, []byte(u.text)})
			for _, s := range u.sigs {
				ps = append(ps, fkPacket{2, s})
			}
		}
		for _, s := range ss {
			ps = append(ps, s...)
		}
		return fkJoin(ps...)
	}

	var first *openpgp.ForeignKey
	var firstCert []byte
	files, differentCerts := 0, 0
	qaPermutations(keySigs, func(ks [][]byte) {
		qaPermutations(userSigs, func(us [][]byte) {
			blocks := []qaUserBlock{{A, us}, others[0], others[1]}
			qaPermutations(blocks, func(bs []qaUserBlock) {
				qaPermutations(subs, func(ss [][]fkPacket) {
					k := fkRead(t, build(ks, bs, ss))
					files++
					kc, err := qaReadCert(k.Certificate())
					if err != nil {
						t.Fatalf("the certificate of an order is refused: %v", err)
					}
					if !qaSnapshotEqual(k, kc) || !reflect.DeepEqual(k.SigningBasis(), kc.SigningBasis()) {
						t.Fatal("the snapshot of a certificate is not the snapshot of its export")
					}
					if first == nil {
						first, firstCert = k, k.Certificate()
						return
					}
					if string(k.Certificate()) != string(firstCert) {
						differentCerts++
					}
					if !qaSnapshotEqual(first, k) {
						t.Fatalf("the snapshot depends on the order:\n%+v\n%+v", openpgp.SnapshotOf(first), openpgp.SnapshotOf(k))
					}
					// the digest of the certificate is the one thing of the basis that follows the bytes of the file
					fb, kb := first.SigningBasis(), k.SigningBasis()
					if fb.CertificateSHA256 != sha256.Sum256(first.Certificate()) || kb.CertificateSHA256 != sha256.Sum256(k.Certificate()) {
						t.Fatal("the digest of the basis is not the digest of the certificate")
					}
					fb.CertificateSHA256, kb.CertificateSHA256 = [32]byte{}, [32]byte{}
					if !reflect.DeepEqual(fb, kb) {
						t.Fatal("the description of the basis depends on the order")
					}
					p1, ok1 := openpgp.SnapshotPrimaryUserID(first)
					p2, ok2 := openpgp.SnapshotPrimaryUserID(k)
					if p1 != p2 || ok1 != ok2 {
						t.Fatalf("the primary user ID depends on the order: %q and %q", p1, p2)
					}
				})
			})
		})
	})
	t.Logf("%d orders of the signatures, the user IDs and the subkeys: one snapshot, one basis, one primary; %d certificates that differ", files, differentCerts)
	if files != 6*24*6*2 || differentCerts < files/2 {
		t.Errorf("%d files and %d different certificates: the permutations are not what they should be", files, differentCerts)
	}
	// what the one answer is: the earlier end wins the tie of the user ID, the smaller bytes the tie that is left, and
	// the tie is marked
	u := openpgp.SnapshotUsers(first)[0]
	t.Logf("the answer for the user ID with four signatures in one second: %+v", u)
	if u.Text != A || u.Expires.Sub(fkEpoch) != 10*86400*time.Second || !u.Signed.Equal(fkAt(1000)) || !u.Tied || u.Weak {
		t.Errorf("the user ID of the answer: %+v", u)
	}
	if e := openpgp.SnapshotKey(first).Expiry; !e.Any || e.Agree || e.Marked || e.Earliest.Sub(fkEpoch) != 10*86400*time.Second {
		t.Errorf("the end of the key of the answer: %+v", e)
	}
	if openpgp.SnapshotKey(first).DirectTied {
		t.Error("three direct-key signatures in one second with other ends are tied: the end decided")
	}
	if p, ok := openpgp.SnapshotPrimaryUserID(first); !ok || p != B {
		t.Errorf("the primary user ID is %q (%v), want the flagged one, %q", p, ok, B)
	}
	// the strong one wins the tie of the end, so that the flags are those of a strong signature: 1 or 4
	if u.Flags != 1 && u.Flags != 4 {
		t.Errorf("the flags of the user ID are %d: the SHA-1 signature, flags 8, or the one with the later end, won", u.Flags)
	}
	var tiedSubs []bool
	for _, s := range openpgp.SnapshotSubkeys(first) {
		tiedSubs = append(tiedSubs, s.Tied)
	}
	if len(tiedSubs) != 2 || tiedSubs[0] == tiedSubs[1] {
		t.Errorf("only the subkey with two bindings in one second is tied: %v", tiedSubs)
	}
}

// The four answers about the end of the key, each at its edges: whether there is a source, the earliest end,
// whether the sources agree, whether a source is marked. A source is the newest self-signature of each live
// user ID and the newest direct-key signature; a revoked user ID is none.
func TestQAExpiryAnswerAtItsEdges(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	sp := fkSubpacket
	life := func(days uint32) []byte { return sp(9, true, fkU32(days*86400)...) }
	sigLife := sp(3, false, fkU32(3600)...)
	const A, B = "Alpha Person <alpha@example.org>", "Bravo Person <bravo@example.org>"
	day := func(n int) time.Time {
		if n == 0 {
			return time.Time{}
		}
		return fkEpoch.Add(time.Duration(n) * 86400 * time.Second)
	}
	cert := func(text string, at int, extra ...[]byte) []byte { return qaUserSig(t, w, text, 0x13, 8, at, extra...) }
	revoke := func(text string, at int) []byte { return qaUserSig(t, w, text, 0x30, 8, at, fkReasonSub(32)) }
	direct := func(at int, extra ...[]byte) []byte { return qaKeySig(t, w, 0x1F, 8, at, extra...) }

	for _, c := range []struct {
		name  string
		keys  [][]byte
		users []qaUserBlock
		want  openpgp.ExpiryAnswer
	}{
		{"no source: the one user ID is revoked, no direct-key signature", nil,
			[]qaUserBlock{{A, [][]byte{cert(A, 1000, life(5)), revoke(A, 1100)}}},
			openpgp.ExpiryAnswer{Agree: true}},
		{"a revoked user ID and a direct-key signature: the direct-key signature is the only source", [][]byte{direct(1200, life(7))},
			[]qaUserBlock{{A, [][]byte{cert(A, 1000, life(5)), revoke(A, 1100)}}},
			openpgp.ExpiryAnswer{Earliest: day(7), Any: true, Agree: true}},
		{"one source with an end", nil,
			[]qaUserBlock{{A, [][]byte{cert(A, 1000, life(5))}}},
			openpgp.ExpiryAnswer{Earliest: day(5), Any: true, Agree: true}},
		{"one source with no end", nil,
			[]qaUserBlock{{A, [][]byte{cert(A, 1000)}}},
			openpgp.ExpiryAnswer{Any: true, Agree: true}},
		{"two sources that agree: two user IDs", nil,
			[]qaUserBlock{{A, [][]byte{cert(A, 1000, life(5))}}, {B, [][]byte{cert(B, 1100, life(5))}}},
			openpgp.ExpiryAnswer{Earliest: day(5), Any: true, Agree: true}},
		{"two sources that agree: a user ID and the direct-key signature", [][]byte{direct(1200, life(5))},
			[]qaUserBlock{{A, [][]byte{cert(A, 1000, life(5))}}},
			openpgp.ExpiryAnswer{Earliest: day(5), Any: true, Agree: true}},
		{"two sources that agree on no end", [][]byte{direct(1200)},
			[]qaUserBlock{{A, [][]byte{cert(A, 1000)}}},
			openpgp.ExpiryAnswer{Any: true, Agree: true}},
		{"two sources that differ: the earlier is the answer", nil,
			[]qaUserBlock{{A, [][]byte{cert(A, 1000, life(9))}}, {B, [][]byte{cert(B, 1100, life(5))}}},
			openpgp.ExpiryAnswer{Earliest: day(5), Any: true}},
		{"two sources that differ: an end and none", nil,
			[]qaUserBlock{{A, [][]byte{cert(A, 1000)}}, {B, [][]byte{cert(B, 1100, life(5))}}},
			openpgp.ExpiryAnswer{Earliest: day(5), Any: true}},
		{"three sources: the older sources are not looked at", [][]byte{direct(900, life(1)), direct(1300, life(8))},
			[]qaUserBlock{{A, [][]byte{cert(A, 800, life(2)), cert(A, 1000, life(6))}}},
			openpgp.ExpiryAnswer{Earliest: day(6), Any: true}},
		{"a revoked user ID is no source", nil,
			[]qaUserBlock{{A, [][]byte{cert(A, 1000, life(9))}}, {B, [][]byte{cert(B, 1100, life(5)), revoke(B, 1200)}}},
			openpgp.ExpiryAnswer{Earliest: day(9), Any: true, Agree: true}},
		{"a marked source: a user ID", nil,
			[]qaUserBlock{{A, [][]byte{cert(A, 1000, life(5), sigLife)}}},
			openpgp.ExpiryAnswer{Earliest: day(5), Any: true, Agree: true, Marked: true}},
		{"a marked source: the direct-key signature", [][]byte{direct(1200, life(5), sigLife)},
			[]qaUserBlock{{A, [][]byte{cert(A, 1000, life(5))}}},
			openpgp.ExpiryAnswer{Earliest: day(5), Any: true, Agree: true, Marked: true}},
		{"a marked source that is not the newest of its user ID", nil,
			[]qaUserBlock{{A, [][]byte{cert(A, 1000, life(5), sigLife), cert(A, 1100, life(5))}}},
			openpgp.ExpiryAnswer{Earliest: day(5), Any: true, Agree: true}},
		{"a marked source that is a revoked user ID", nil,
			[]qaUserBlock{{A, [][]byte{cert(A, 1000, life(5))}}, {B, [][]byte{cert(B, 1100, life(5), sigLife), revoke(B, 1200)}}},
			openpgp.ExpiryAnswer{Earliest: day(5), Any: true, Agree: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := fkRead(t, qaFile(t, b, c.keys, c.users...))
			if got := openpgp.SnapshotKey(k).Expiry; got != c.want {
				t.Errorf("the answer is %+v, want %+v", got, c.want)
			}
			kc, err := qaReadCert(k.Certificate())
			if err != nil || openpgp.SnapshotKey(kc).Expiry != c.want {
				t.Errorf("the answer of the certificate: %v", err)
			}
		})
	}
}

// UncountedClaims also counts the claims that the reader could not read at all: no creation time, two of them, one of
// three bytes, a field twice, a version it does not take. Each is pinned with the time that it gives, when it gives one.
func TestQAUncountedClaimsCountTheOnesThatCannotBeRead(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	sp := fkSubpacket
	issuer := sp(33, false, append([]byte{4}, b.ent.PrimaryKey.Fingerprint...)...)
	good := qaUserSig(t, w, fkUser, 0x13, 8, 1000)
	creation := func(at int) []byte { return sp(2, false, fkU32(uint32(fkAt(at).Unix()))...) }
	user := func(hashed ...[]byte) []byte {
		var h []byte
		for _, p := range hashed {
			h = append(h, p...)
		}
		return w.sign(t, "user", 0x13, h, nil, 8, sha256.New, []byte(fkUser))
	}
	direct := func(hashed ...[]byte) []byte {
		var h []byte
		for _, p := range hashed {
			h = append(h, p...)
		}
		return w.sign(t, "key", 0x1F, h, nil, 8, sha256.New, nil)
	}
	for _, c := range []struct {
		name   string
		keys   [][]byte
		sig    []byte
		n      int
		newest int // seconds, 0 for none
	}{
		{"no creation time", nil, user(issuer), 1, 0},
		{"two creation times", nil, user(creation(1500), creation(1600), issuer), 1, 0},
		{"a creation time of three bytes", nil, user(sp(2, false, 1, 2, 3), issuer), 1, 0},
		{"a key expiration twice", nil, user(creation(1500), sp(9, true, fkU32(5)...), sp(9, true, fkU32(6)...), issuer), 1, 1500},
		{"a key flags subpacket with no octet", nil, user(creation(1500), sp(27, false), issuer), 1, 1500},
		{"a primary flag of two octets", nil, user(creation(1500), sp(25, false, 1, 1), issuer), 1, 1500},
		{"a direct-key signature with no creation time", [][]byte{direct(issuer)}, nil, 1, 0},
		{"a direct-key signature with a field twice", [][]byte{direct(creation(1700), sp(3, false, fkU32(5)...), sp(3, false, fkU32(5)...), issuer)}, nil, 1, 1700},
		{"no issuer at all", nil, user(creation(1500)), 0, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			sigs := [][]byte{good}
			if c.sig != nil {
				sigs = append(sigs, c.sig)
			}
			k := fkRead(t, qaFile(t, b, c.keys, qaUserBlock{fkUser, sigs}))
			want := time.Time{}
			if c.newest != 0 {
				want = fkAt(c.newest)
			}
			if k.UncountedClaims != c.n || !k.UncountedClaimsNewest.Equal(want) {
				t.Errorf("%d claims, newest %v; pinned %d, %v", k.UncountedClaims, k.UncountedClaimsNewest, c.n, want)
			}
		})
	}
	// a version that is not 4 (3 and 5): the signature is not read
	for _, v := range []byte{3, 5, 6} {
		bad := bytes.Clone(good)
		bad[0] = v
		k, err := openpgp.ReadForeignKey(qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{good, bad}}))
		if err != nil {
			t.Logf("version %d: the file is refused: %v", v, err)
			continue
		}
		t.Logf("version %d: %d claims not counted, newest %v", v, k.UncountedClaims, k.UncountedClaimsNewest)
		if k.UncountedClaims > 1 {
			t.Errorf("version %d: %d claims", v, k.UncountedClaims)
		}
	}
}

// UncountedClaims covers the certifications of the user IDs and the direct-key signatures that the primary
// claims and the reader does not count. It does NOT cover a subkey binding, a user attribute signature or a
// key revocation: those are pinned here as they are, so that a change to the field shows.
func TestQAUncountedClaimsCoverOnlyCertificationsAndDirectKeySignatures(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	enc, _, _ := fkDonors(t)
	sp := fkSubpacket
	md5 := func(kind string, typ byte, at int, target []byte) []byte {
		return w.sign(t, kind, typ, w.areas(at), nil, 1, sha256.New, target)
	}
	good := qaUserSig(t, w, fkUser, 0x13, 8, 1000)
	photo := fkAttribute(t, 40)
	count := func(name string, file []byte, wantN int, wantAt int) {
		t.Helper()
		k := fkRead(t, file)
		if k.UncountedClaims != wantN || !k.UncountedClaimsNewest.Equal(fkAt(wantAt)) && !(wantAt == 0 && k.UncountedClaimsNewest.IsZero()) {
			t.Errorf("%s: %d claims, newest %v; pinned %d at %d", name, k.UncountedClaims, k.UncountedClaimsNewest, wantN, wantAt)
		}
		if kc, err := qaReadCert(k.Certificate()); err != nil || kc.UncountedClaims != 0 || !kc.UncountedClaimsNewest.IsZero() {
			t.Errorf("%s: the certificate has claims: %v", name, err)
		}
	}
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	// what is covered
	count("a certification with a hash that is not accepted", qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{good, md5("user", 0x13, 1500, []byte(fkUser))}}), 1, 1500)
	count("a certification with an unknown critical subpacket", qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{good, qaUserSig(t, w, fkUser, 0x13, 8, 1600, sp(100, true, 1))}}), 1, 1600)
	count("a direct-key signature with a hash that is not accepted", qaFile(t, b, [][]byte{md5("key", 0x1F, 1700, nil)}, qaUserBlock{fkUser, [][]byte{good}}), 1, 1700)
	// what is not: a binding of a subkey, a signature on an attribute, a key revocation
	bindFile := fkJoin(head[0], head[1], fkPacket{2, good}, enc[3].pub, fkPacket{2, md5("sub", 0x18, 1800, enc[3].pub.Body)})
	count("a subkey binding with a hash that is not accepted", bindFile, 0, 0)
	if k := fkRead(t, bindFile); len(k.Subkeys) != 1 || k.Subkeys[0].InCertificate {
		t.Errorf("the subkey of the file with only an uncounted binding: %+v", k.Subkeys)
	}
	attrFile := fkJoin(head[0], head[1], fkPacket{2, good}, photo, fkPacket{2, md5("attr", 0x13, 1900, photo.Body)})
	count("an attribute signature with a hash that is not accepted", attrFile, 0, 0)
	revFile := qaFile(t, b, [][]byte{md5("key", 0x20, 2000, nil)}, qaUserBlock{fkUser, [][]byte{good}})
	count("a key revocation with a hash that is not accepted", revFile, 0, 0)
	if k := fkRead(t, revFile); k.UnreadableRevocations != 1 || k.Primary.Revoked {
		t.Errorf("the key revocation with MD5: unreadable %d, revoked %v", k.UnreadableRevocations, k.Primary.Revoked)
	}
	// a certification of another key is not a claim of the primary
	_, _, other := fkDonors(t)
	foreign := fkSplit(t, b.certSig(t, other, b.ent.PrimaryKey, fkUser, fkSigSpec{Typ: 0x13, At: fkSigAt(2100)}))
	count("a certification by another key", fkJoin(append([]fkPacket{head[0], head[1], {2, good}}, foreign...)...), 0, 0)
	// a signature that does not verify is not counted either
	bad := bytes.Clone(good)
	bad[len(bad)-1] ^= 1
	count("a self-signature that does not verify", qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 1000), bad}}), 0, 0)
	// several, on several user IDs, including one that is left out of the certificate: the newest is the newest
	var ids []qaUserBlock
	ids = append(ids, qaUserBlock{fkUser, [][]byte{good, md5("user", 0x13, 1100, []byte(fkUser))}})
	ids = append(ids, qaUserBlock{"Left Out <out@example.org>", [][]byte{w.sign(t, "user", 0x13, w.areas(2200), nil, 1, sha256.New, []byte("Left Out <out@example.org>"))}})
	k := fkRead(t, qaFile(t, b, [][]byte{md5("key", 0x1F, 1300, nil)}, ids...))
	if k.UncountedClaims != 3 || !k.UncountedClaimsNewest.Equal(fkAt(2200)) || len(openpgp.SnapshotUsers(k)) != 1 {
		t.Errorf("the claims on several user IDs: %d, newest %v", k.UncountedClaims, k.UncountedClaimsNewest)
	}
}

// Which user ID is THE primary one: among the live user IDs whose source carries the primary flag, the newest
// source, a tie by the smaller text; and NONE when no live user ID carries the flag: the answer only describes,
// there is no fall-back to the newest user ID. The rule is held for every order of the user IDs in the file.
func TestQAPrimaryUserIDRule(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	prim := fkSubpacket(25, false, 1)
	const A, B, C = "Alpha Person <alpha@example.org>", "Bravo Person <bravo@example.org>", "Charlie Person <charlie@example.org>"
	cert := func(text string, at int, flagged bool) []byte {
		if flagged {
			return qaUserSig(t, w, text, 0x13, 8, at, prim)
		}
		return qaUserSig(t, w, text, 0x13, 8, at)
	}
	revoke := func(text string, at int) []byte { return qaUserSig(t, w, text, 0x30, 8, at, fkReasonSub(32)) }
	for _, c := range []struct {
		name   string
		blocks []qaUserBlock
		want   string // empty: none
		flags  int    // how many live user IDs carry the flag in their source
	}{
		{"two flagged: the newest source", []qaUserBlock{{A, [][]byte{cert(A, 1000, true)}}, {B, [][]byte{cert(B, 1100, true)}}}, B, 2},
		{"two flagged in one second: the smaller text", []qaUserBlock{{B, [][]byte{cert(B, 1000, true)}}, {A, [][]byte{cert(A, 1000, true)}}}, A, 2},
		{"three flagged, the newest in the middle", []qaUserBlock{{A, [][]byte{cert(A, 1000, true)}}, {C, [][]byte{cert(C, 1200, true)}}, {B, [][]byte{cert(B, 1100, true)}}}, C, 3},
		{"none flagged: none", []qaUserBlock{{A, [][]byte{cert(A, 1000, false)}}, {B, [][]byte{cert(B, 1100, false)}}}, "", 0},
		{"none flagged, in one second: none", []qaUserBlock{{B, [][]byte{cert(B, 1000, false)}}, {A, [][]byte{cert(A, 1000, false)}}}, "", 0},
		{"one flagged and older, one unflagged and newer: the flagged one", []qaUserBlock{{A, [][]byte{cert(A, 1000, true)}}, {B, [][]byte{cert(B, 1100, false)}}}, A, 1},
		{"the flag is in an older signature only: none", []qaUserBlock{{A, [][]byte{cert(A, 1000, true), cert(A, 1100, false)}}, {B, [][]byte{cert(B, 1050, false)}}}, "", 0},
		{"the flagged one is revoked: none", []qaUserBlock{{A, [][]byte{cert(A, 1000, true), revoke(A, 1200)}}, {B, [][]byte{cert(B, 1100, false)}}}, "", 0},
		{"the newer flagged one is revoked: the older flagged one", []qaUserBlock{{A, [][]byte{cert(A, 1000, true)}}, {B, [][]byte{cert(B, 1100, true), revoke(B, 1200)}}}, A, 1},
		{"all revoked: none", []qaUserBlock{{A, [][]byte{cert(A, 1000, true), revoke(A, 1200)}}, {B, [][]byte{cert(B, 1100, false), revoke(B, 1300)}}}, "", 0},
		{"one user ID, unflagged: none", []qaUserBlock{{A, [][]byte{cert(A, 1000, false)}}}, "", 0},
		{"one user ID, flagged", []qaUserBlock{{A, [][]byte{cert(A, 1000, true)}}}, A, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			qaPermutations(c.blocks, func(bs []qaUserBlock) {
				k := fkRead(t, qaFile(t, b, nil, bs...))
				for door, key := range map[string]*openpgp.ForeignKey{"export": k, "certificate": func() *openpgp.ForeignKey {
					kc, err := qaReadCert(k.Certificate())
					if err != nil {
						t.Fatal(err)
					}
					return kc
				}()} {
					got, ok := openpgp.SnapshotPrimaryUserID(key)
					if got != c.want || ok != (c.want != "") {
						t.Errorf("%s: the primary user ID is %q (%v), want %q", door, got, ok, c.want)
					}
					if got := key.SigningBasis().PrimaryFlagged; got != c.flags {
						t.Errorf("%s: %d live user IDs are flagged in the basis, want %d", door, got, c.flags)
					}
					marked := ""
					n := 0
					for _, u := range key.SigningBasis().UserIDs {
						if u.IsPrimary {
							marked, n = u.Text, n+1
						}
					}
					if marked != c.want || n > 1 || (c.want != "" && n != 1) {
						t.Errorf("%s: the basis marks %q (%d), want %q", door, marked, n, c.want)
					}
				}
			})
		})
	}
}
