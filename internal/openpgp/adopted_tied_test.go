package openpgp_test

import (
	"crypto/sha1" //nolint:gosec // a SHA-1 signature that verifies counts: the files here hold some
	"crypto/sha256"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// tied is set when the choice of the source was left to the bytes of the packets and it matters: the candidates
// that are still equal after the time, the end of the key and the strength of the hash differ in something that a
// builder uses (the key flags, the primary flag, the carried preferences, the dropped types, a signature
// expiration). It is not set when the time, the end or the strength decided, nor for the same content signed twice.

func TestQATiedIsSetExactlyWhenTheBytesDecideAndItMatters(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	enc, _, _ := fkDonors(t)
	sp := fkSubpacket
	life := func(d uint32) []byte { return sp(9, true, fkU32(d*86400)...) }
	flags := func(f byte) []byte { return sp(27, false, f) }
	user := func(hash byte, at int, extra ...[]byte) []byte {
		return qaUserSig(t, w, fkUser, 0x13, hash, at, extra...)
	}
	direct := func(hash byte, at int, extra ...[]byte) []byte { return qaKeySig(t, w, 0x1F, hash, at, extra...) }
	bind := func(hash byte, at int, extra ...[]byte) []byte {
		if hash == 2 {
			return w.sign(t, "sub", 0x18, w.areas(at, extra...), nil, 2, sha1.New, enc[3].pub.Body)
		}
		return w.sign(t, "sub", 0x18, w.areas(at, extra...), nil, 8, sha256.New, enc[3].pub.Body)
	}
	policy := sp(26, false, []byte("https://example.org/p")...)

	type result struct{ user, direct, sub bool }
	read := func(users, directs, subs [][]byte) result {
		k := fkRead(t, w.file(t, fkParts{noSelf: true, userSigs: users, keySigs: directs, subSigs: subs, noBind: subs == nil}))
		var r result
		if u := openpgp.SnapshotUsers(k); len(u) == 1 {
			r.user = u[0].Tied
		}
		r.direct = openpgp.SnapshotKey(k).DirectTied
		if s := openpgp.SnapshotSubkeys(k); len(s) == 1 {
			r.sub = s[0].Tied
		}
		return r
	}
	oneUser := func(a, b2 []byte) [][]byte { return [][]byte{a, b2} }
	for _, c := range []struct {
		name string
		got  result
		want bool // for the user ID
	}{
		{"the same content signed twice in one second: not tied", read(oneUser(user(8, 1000, flags(1), life(10)), user(8, 1000, flags(1), life(10))), nil, nil), false},
		{"one flag differs: tied", read(oneUser(user(8, 1000, flags(1), life(10)), user(8, 1000, flags(2), life(10))), nil, nil), true},
		{"the primary flag differs: tied", read(oneUser(user(8, 1000, flags(1), sp(25, false, 1)), user(8, 1000, flags(1))), nil, nil), true},
		{"a carried preference differs: tied", read(oneUser(user(8, 1000, sp(21, false, 8)), user(8, 1000, sp(21, false, 9))), nil, nil), true},
		{"a carried preference is on one only: tied", read(oneUser(user(8, 1000, sp(21, false, 8)), user(8, 1000)), nil, nil), true},
		{"a dropped type differs: tied", read(oneUser(user(8, 1000, policy), user(8, 1000)), nil, nil), true},
		{"a signature expiration time on one: tied", read(oneUser(user(8, 1000, sp(3, false, fkU32(60)...)), user(8, 1000)), nil, nil), true},
		{"the time decided: not tied", read(oneUser(user(8, 1000, flags(1)), user(8, 1001, flags(2))), nil, nil), false},
		{"the end decided: not tied", read(oneUser(user(8, 1000, flags(1), life(10)), user(8, 1000, flags(2), life(20))), nil, nil), false},
		{"an end and none: the end decided, not tied", read(oneUser(user(8, 1000, flags(1)), user(8, 1000, flags(2), life(20))), nil, nil), false},
		{"a weak and a strong of the same second and end: the strong one, not tied", read(oneUser(user(2, 1000, flags(1)), user(8, 1000, flags(2))), nil, nil), false},
		{"two weak ones that differ: tied", read(oneUser(user(2, 1000, flags(1)), user(2, 1000, flags(2))), nil, nil), true},
		{"two strong and a weak one: the two strong ones decide, tied when they differ", read([][]byte{user(2, 1000, flags(4)), user(8, 1000, flags(1)), user(8, 1000, flags(2))}, nil, nil), true},
		{"older signatures that tie are not the source: not tied", read([][]byte{user(8, 900, flags(1)), user(8, 900, flags(2)), user(8, 1000, flags(3))}, nil, nil), false},
		{"a revocation in the same second is no candidate: not tied", read([][]byte{user(8, 1000, flags(1)), qaUserSig(t, w, fkUser, 0x30, 8, 1000, fkReasonSub(32))}, nil, nil), false},
	} {
		if c.got.user != c.want {
			t.Errorf("%s: tied is %v", c.name, c.got.user)
		}
		if c.got.direct || c.got.sub {
			t.Errorf("%s: the direct-key signature or the subkey is tied: %+v", c.name, c.got)
		}
	}
	base := [][]byte{user(8, 500, flags(3))}
	for _, c := range []struct {
		name string
		got  result
		want bool
	}{
		{"direct-key: the same content twice, not tied", read(base, [][]byte{direct(8, 1000, sp(21, false, 8)), direct(8, 1000, sp(21, false, 8))}, nil), false},
		{"direct-key: a preference differs, tied", read(base, [][]byte{direct(8, 1000, sp(21, false, 8)), direct(8, 1000, sp(21, false, 9))}, nil), true},
		{"direct-key: the end decided, not tied", read(base, [][]byte{direct(8, 1000, life(10)), direct(8, 1000, life(20))}, nil), false},
		{"direct-key: the time decided, not tied", read(base, [][]byte{direct(8, 1000, flags(1)), direct(8, 1001, flags(2))}, nil), false},
		{"direct-key: a weak and a strong, the strong one, not tied", read(base, [][]byte{direct(2, 1000, flags(1)), direct(8, 1000, flags(2))}, nil), false},
		{"direct-key: a signature expiration on one, tied", read(base, [][]byte{direct(8, 1000, sp(3, false, fkU32(60)...)), direct(8, 1000)}, nil), true},
	} {
		if c.got.direct != c.want || c.got.user || c.got.sub {
			t.Errorf("%s: %+v", c.name, c.got)
		}
	}
	for _, c := range []struct {
		name string
		got  result
		want bool
	}{
		{"subkey: the same binding twice, not tied", read(base, nil, [][]byte{bind(8, 1000, flags(0x0C)), bind(8, 1000, flags(0x0C))}), false},
		{"subkey: other flags in one second, tied", read(base, nil, [][]byte{bind(8, 1000, flags(0x0C)), bind(8, 1000, flags(0x04))}), true},
		{"subkey: other times, not tied", read(base, nil, [][]byte{bind(8, 1000, flags(0x0C)), bind(8, 1001, flags(0x04))}), false},
		{"subkey: a weak and a strong binding, the strong one, not tied", read(base, nil, [][]byte{bind(2, 1000, flags(0x0C)), bind(8, 1000, flags(0x04))}), false},
	} {
		if c.got.sub != c.want || c.got.user || c.got.direct {
			t.Errorf("%s: %+v", c.name, c.got)
		}
	}
	// the same answers from the certificate
	k := fkRead(t, w.file(t, fkParts{noSelf: true, userSigs: [][]byte{user(8, 1000, flags(1)), user(8, 1000, flags(2))}}))
	kc, err := qaReadCert(k.Certificate())
	if err != nil || !openpgp.SnapshotUsers(kc)[0].Tied || !qaSnapshotEqual(k, kc) {
		t.Errorf("the certificate of a tied key: %v", err)
	}
	// and the strong one is the source of a weak and a strong signature of the same second and end
	k = fkRead(t, w.file(t, fkParts{noSelf: true, userSigs: [][]byte{user(2, 1000, flags(1)), user(8, 1000, flags(2))}}))
	if u := openpgp.SnapshotUsers(k)[0]; u.Flags != 2 || u.Weak || !u.AnyStrong {
		t.Errorf("the source of a weak and a strong signature of one second: %+v", u)
	}
	k = fkRead(t, w.file(t, fkParts{noSelf: true, userSigs: [][]byte{user(8, 1000, flags(2)), user(2, 1000, flags(1))}}))
	if u := openpgp.SnapshotUsers(k)[0]; u.Flags != 2 || u.Weak {
		t.Errorf("the same in the other order of the file: %+v", u)
	}
}
