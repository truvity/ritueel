package openpgp_test

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"slices"
	"sort"
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

// qaOrderFree returns the snapshot with the user IDs and the subkeys in a fixed order, which is the one thing
// of it that is the order of the file.
func qaUsersByText(k *openpgp.ForeignKey) []openpgp.SnapUser {
	u := openpgp.SnapshotUsers(k)
	sort.Slice(u, func(i, j int) bool { return u[i].Text < u[j].Text })
	return u
}

func TestQASnapshotDoesNotDependOnAnyOrderOfTheFile(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	sp := fkSubpacket
	life := func(days uint32) []byte { return sp(9, true, fkU32(days*86400)...) }
	flags := func(f byte) []byte { return sp(27, false, f) }
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

	var first *openpgp.ForeignKey
	var firstCert []byte
	files, differentCerts := 0, 0
	qaPermutations(keySigs, func(ks [][]byte) {
		qaPermutations(userSigs, func(us [][]byte) {
			blocks := []qaUserBlock{{A, us}, others[0], others[1]}
			qaPermutations(blocks, func(bs []qaUserBlock) {
				k := fkRead(t, qaFile(t, b, ks, bs...))
				files++
				kc, err := qaReadCert(k.Certificate())
				if err != nil {
					t.Fatalf("the certificate of an order is refused: %v", err)
				}
				if !qaSnapshotEqual(k, kc) {
					t.Fatal("the snapshot of a certificate is not the snapshot of its export")
				}
				if first == nil {
					first, firstCert = k, k.Certificate()
					return
				}
				if string(k.Certificate()) != string(firstCert) {
					differentCerts++
				}
				a, c := first, k
				if !reflect.DeepEqual(openpgp.SnapshotKey(a), openpgp.SnapshotKey(c)) {
					t.Fatalf("the key level depends on the order:\n%+v\n%+v", openpgp.SnapshotKey(a), openpgp.SnapshotKey(c))
				}
				if !reflect.DeepEqual(qaUsersByText(a), qaUsersByText(c)) {
					t.Fatalf("a user ID depends on the order:\n%+v\n%+v", qaUsersByText(a), qaUsersByText(c))
				}
			})
		})
	})
	t.Logf("%d orders of the signatures and the user IDs: one snapshot (the user IDs by text), %d certificates that differ", files, differentCerts)
	if files != 6*24*6 || differentCerts < files/2 {
		t.Errorf("%d files and %d different certificates: the permutations are not what they should be", files, differentCerts)
	}
	// what the one answer is: the earlier end wins the tie of the user ID, the smaller bytes the tie that is left
	u := qaUsersByText(first)[0]
	t.Logf("the answer for the user ID with four signatures in one second: %+v", u)
	if u.Text != A || u.Expires.Sub(fkEpoch) != 10*86400*time.Second || !u.Signed.Equal(fkAt(1000)) {
		t.Errorf("the user ID of the answer: %+v", u)
	}
	if e := openpgp.SnapshotKey(first).Expiry; !e.Any || e.Agree || e.Marked || e.Earliest.Sub(fkEpoch) != 10*86400*time.Second {
		t.Errorf("the end of the key of the answer: %+v", e)
	}
	// the order of the user IDs in the snapshot is the order of the file, and nothing else of it is
	k1 := fkRead(t, qaFile(t, b, keySigs, others[0], others[1]))
	k2 := fkRead(t, qaFile(t, b, keySigs, others[1], others[0]))
	switch {
	case qaSnapshotEqual(k1, k2):
		t.Error("two orders of the user IDs give the same list: the test no longer says what the list is")
	case !reflect.DeepEqual(qaUsersByText(k1), qaUsersByText(k2)) || !reflect.DeepEqual(openpgp.SnapshotKey(k1), openpgp.SnapshotKey(k2)):
		t.Error("two orders of the user IDs say different things")
	default:
		t.Log("FINDING: the list of the user IDs of the snapshot is in the order of the file; each user ID and the key level are not")
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
