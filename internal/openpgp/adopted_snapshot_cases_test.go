package openpgp_test

import (
	"crypto/sha1" //nolint:gosec // a SHA-1 self-signature that verifies counts, flagged weak: the files here hold some
	"crypto/sha256"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// What the snapshot says when a user ID has several self-signatures, when a key has a direct-key signature
// beside its certifications, and when two user IDs disagree: each case is pinned (the snapshot is what it
// is), and where the pinned answer is not what the person last chose with a strong signature the case says
// so and the test logs it. Whether such an answer is wrong is for the reader of the design to judge.

// qaSigAt makes a self-signature of a user ID text by the Ed25519 template with the hash given (8 is SHA-256,
// 2 is SHA-1), at secs after the creation of the key, with the subpackets given after the creation time and
// the issuer.
func qaUserSig(t testing.TB, w fkWriter, text string, typ byte, hash byte, secs int, extra ...[]byte) []byte {
	t.Helper()
	if hash == 2 {
		return w.sign(t, "user", typ, w.areas(secs, extra...), nil, 2, sha1.New, []byte(text))
	}
	return w.sign(t, "user", typ, w.areas(secs, extra...), nil, 8, sha256.New, []byte(text))
}

func qaKeySig(t testing.TB, w fkWriter, typ byte, hash byte, secs int, extra ...[]byte) []byte {
	t.Helper()
	if hash == 2 {
		return w.sign(t, "key", typ, w.areas(secs, extra...), nil, 2, sha1.New, nil)
	}
	return w.sign(t, "key", typ, w.areas(secs, extra...), nil, 8, sha256.New, nil)
}

// qaUsers is the file of the Ed25519 template with the user IDs given, each with its signatures, after the
// direct-key signatures given.
type qaUserBlock struct {
	text string
	sigs [][]byte
}

func qaFile(t testing.TB, b *fkBase, keySigs [][]byte, users ...qaUserBlock) []byte {
	t.Helper()
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	ps := []fkPacket{head[0]}
	for _, s := range keySigs {
		ps = append(ps, fkPacket{2, s})
	}
	for _, u := range users {
		ps = append(ps, fkPacket{13, []byte(u.text)})
		for _, s := range u.sigs {
			ps = append(ps, fkPacket{2, s})
		}
	}
	return fkJoin(ps...)
}

// qaSnapCase is a file and what is pinned of its snapshot.
type qaSnapCase struct {
	name  string
	file  func(t testing.TB, w fkWriter) []byte
	users []qaSnapUser
	// keyEnd and newest are the end of the key (days after its creation, 0 for none) and the time of the newest
	// signature (seconds after its creation).
	keyEnd int
	newest int
	// chosen is the end of the key that the person last chose with a strong signature, and the reason why the
	// pinned answer is another when it is: empty when they agree.
	chosenKeyEnd int
	report       string
}

type qaSnapUser struct {
	text    string
	flags   uint8
	primary bool
	end     int // days
	signed  int // seconds
	prefs   []byte
	revoked bool
}

func TestQASnapshotCases(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	sp := fkSubpacket
	life := func(days uint32) []byte { return sp(9, true, fkU32(days*86400)...) }
	flags := func(f byte) []byte { return sp(27, false, f) }
	primary := sp(25, false, 1)
	reason := func(c byte) []byte { return fkReasonSub(c) }
	one := func(sigs ...[]byte) []qaUserBlock { return []qaUserBlock{{fkUser, sigs}} }
	const A, B = "Alpha Person <alpha@example.org>", "Bravo Person <bravo@example.org>"

	cases := []qaSnapCase{
		{name: "two strong self-signatures, the newer one wins",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(1), life(10), primary, sp(21, false, 8)), qaUserSig(t, w, fkUser, 0x13, 8, 1100, flags(3), life(20), sp(21, false, 10)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 3, end: 20, signed: 1100, prefs: []byte{21}}},
			keyEnd: 20, newest: 1100, chosenKeyEnd: 20},
		{name: "two strong self-signatures, the newer one first in the file",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 8, 1100, flags(3), life(20)), qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(1), life(10), primary))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 3, end: 20, signed: 1100}},
			keyEnd: 20, newest: 1100, chosenKeyEnd: 20},
		{name: "two strong self-signatures in the same second, the later in the file wins",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(1), life(10), sp(21, false, 8)), qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(2), life(20), sp(21, false, 10)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 2, end: 20, signed: 1000, prefs: []byte{21}}},
			keyEnd: 20, newest: 1000, chosenKeyEnd: 0,
			report: "the same second: neither is newer; the order of the file decides, and a verifier that decides another way reads the other key flags and expiry"},
		{name: "two strong self-signatures in the same second, the other way round",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(2), life(20)), qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(1), life(10)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 1, end: 10, signed: 1000}},
			keyEnd: 10, newest: 1000, chosenKeyEnd: 0,
			report: "the same second: the answer follows the order of the file"},
		{name: "a SHA-1 self-signature newer than a strong one",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(1), life(10)), qaUserSig(t, w, fkUser, 0x13, 2, 1100, flags(3), life(5)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 1, end: 10, signed: 1100}},
			keyEnd: 5, newest: 1100, chosenKeyEnd: 10,
			report: "the user ID takes the older strong signature, and the end of the KEY takes the newer SHA-1 signature (5 days, not 10)"},
		{name: "a SHA-1 self-signature older than a strong one",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 2, 900, flags(3), life(5)), qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(1), life(10)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 1, end: 10, signed: 1000}},
			keyEnd: 10, newest: 1000, chosenKeyEnd: 10},
		{name: "a SHA-1 self-signature alone",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 2, 1000, flags(3), life(5)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 3, end: 5, signed: 1000}},
			keyEnd: 5, newest: 1000, chosenKeyEnd: 0,
			report: "no strong signature at all: the flags and the end are those of the SHA-1 signature"},
		{name: "a self-signature dated far after any ceremony",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(1), life(10)), qaUserSig(t, w, fkUser, 0x13, 8, 900000000, flags(2), life(99)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 2, end: 99, signed: 900000000}},
			keyEnd: 99, newest: 900000000, chosenKeyEnd: 10,
			report: "the snapshot has no ceremony time: a signature dated in the future is the newest, with its flags and expiry"},
		{name: "a direct-key signature newer than the certification",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, [][]byte{qaKeySig(t, w, 0x1F, 8, 1200, life(30), flags(1))}, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(3), life(10)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 3, end: 10, signed: 1000}},
			keyEnd: 30, newest: 1200, chosenKeyEnd: 30},
		{name: "a direct-key signature and a certification in the same second",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, [][]byte{qaKeySig(t, w, 0x1F, 8, 1000, life(30))}, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(3), life(10)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 3, end: 10, signed: 1000}},
			keyEnd: 10, newest: 1000, chosenKeyEnd: 0,
			report: "the same second: the certification stands after the direct-key signature in the certificate and wins"},
		{name: "a SHA-1 direct-key signature newer than a strong certification",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, [][]byte{qaKeySig(t, w, 0x1F, 2, 1200, life(30))}, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(3), life(10)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 3, end: 10, signed: 1000}},
			keyEnd: 30, newest: 1200, chosenKeyEnd: 10,
			report: "a SHA-1 direct-key signature gives the end of the key over a strong certification"},
		{name: "a direct-key signature newer than the certification, with no expiry",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, [][]byte{qaKeySig(t, w, 0x1F, 8, 1200)}, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(3), life(10)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 3, end: 10, signed: 1000}},
			keyEnd: 0, newest: 1200, chosenKeyEnd: 0},
		{name: "a newest self-signature with no key flags",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(3), life(10)), qaUserSig(t, w, fkUser, 0x13, 8, 1100, life(10)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 0, end: 10, signed: 1100}},
			keyEnd: 10, newest: 1100, chosenKeyEnd: 10},
		{name: "preferences: the older has them, the newer has none",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, sp(11, false, 9), sp(30, false, 1)), qaUserSig(t, w, fkUser, 0x13, 8, 1100))...)
			},
			users:  []qaSnapUser{{text: fkUser, signed: 1100}},
			keyEnd: 0, newest: 1100, chosenKeyEnd: 0},
		{name: "preferences: a newer SHA-1 signature has them, the strong one has other",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, sp(11, false, 9)), qaUserSig(t, w, fkUser, 0x13, 2, 1100, sp(21, false, 8)))...)
			},
			users:  []qaSnapUser{{text: fkUser, signed: 1100, prefs: []byte{11}}},
			keyEnd: 0, newest: 1100, chosenKeyEnd: 0},
		{name: "a user ID revoked softly by a revocation newer than its certification",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(3), life(10)), qaUserSig(t, w, fkUser, 0x30, 8, 1100, reason(32)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 3, end: 10, signed: 1000, revoked: true}},
			keyEnd: 0, newest: 1100, chosenKeyEnd: 10,
			report: "the only user ID is revoked: the key reads as one that never ends, though its last certification had an end"},
		{name: "a user ID revoked softly and certified again",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil, one(qaUserSig(t, w, fkUser, 0x13, 8, 1000, flags(3), life(10)), qaUserSig(t, w, fkUser, 0x30, 8, 1100, reason(32)), qaUserSig(t, w, fkUser, 0x13, 8, 1200, flags(3), life(40)))...)
			},
			users:  []qaSnapUser{{text: fkUser, flags: 3, end: 40, signed: 1200}},
			keyEnd: 40, newest: 1200, chosenKeyEnd: 40},
		{name: "two user IDs: the newer certification of the one that is not the primary gives the end of the key",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil,
					qaUserBlock{A, [][]byte{qaUserSig(t, w, A, 0x13, 8, 1000, flags(3), life(3650), primary)}},
					qaUserBlock{B, [][]byte{qaUserSig(t, w, B, 0x13, 8, 1100, flags(3), life(365))}})
			},
			users: []qaSnapUser{
				{text: A, flags: 3, primary: true, end: 3650, signed: 1000},
				{text: B, flags: 3, end: 365, signed: 1100}},
			keyEnd: 365, newest: 1100, chosenKeyEnd: 3650,
			report: "the end of the key is that of the newest certification of any live user ID, not that of the one marked primary"},
		{name: "two user IDs: the newer one is revoked, so the older gives the end",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil,
					qaUserBlock{A, [][]byte{qaUserSig(t, w, A, 0x13, 8, 1000, flags(3), life(3650), primary)}},
					qaUserBlock{B, [][]byte{qaUserSig(t, w, B, 0x13, 8, 1100, flags(3), life(365)), qaUserSig(t, w, B, 0x30, 8, 1150, reason(32))}})
			},
			users: []qaSnapUser{
				{text: A, flags: 3, primary: true, end: 3650, signed: 1000},
				{text: B, flags: 3, end: 365, signed: 1100, revoked: true}},
			keyEnd: 3650, newest: 1150, chosenKeyEnd: 3650},
		{name: "two user IDs, both marked primary",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil,
					qaUserBlock{A, [][]byte{qaUserSig(t, w, A, 0x13, 8, 1000, flags(3), primary)}},
					qaUserBlock{B, [][]byte{qaUserSig(t, w, B, 0x13, 8, 1100, flags(3), primary)}})
			},
			users: []qaSnapUser{
				{text: A, flags: 3, primary: true, signed: 1000},
				{text: B, flags: 3, primary: true, signed: 1100}},
			keyEnd: 0, newest: 1100, chosenKeyEnd: 0},
		{name: "two user IDs, none marked primary",
			file: func(t testing.TB, w fkWriter) []byte {
				return qaFile(t, b, nil,
					qaUserBlock{A, [][]byte{qaUserSig(t, w, A, 0x13, 8, 1000, flags(1))}},
					qaUserBlock{B, [][]byte{qaUserSig(t, w, B, 0x13, 8, 1100, flags(2))}})
			},
			users: []qaSnapUser{
				{text: A, flags: 1, signed: 1000},
				{text: B, flags: 2, signed: 1100}},
			keyEnd: 0, newest: 1100, chosenKeyEnd: 0},
	}
	reports := 0
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := fkRead(t, c.file(t, w))
			kc, err := openpgp.ReadForeignCertificate(k.Certificate())
			if err != nil || !qaSnapshotEqual(k, kc) {
				t.Fatalf("the certificate does not read back to the same snapshot: %v", err)
			}
			end := func(days int) time.Time {
				if days == 0 {
					return time.Time{}
				}
				return fkEpoch.Add(time.Duration(days) * 86400 * time.Second)
			}
			got := openpgp.SnapshotUsers(k)
			if len(got) != len(c.users) {
				t.Fatalf("%d user IDs in the snapshot, want %d: %+v", len(got), len(c.users), got)
			}
			for i, u := range got {
				w := c.users[i]
				var prefs []byte
				for _, p := range u.Prefs {
					prefs = append(prefs, p.Type)
				}
				if u.Text != w.text || u.Flags != w.flags || u.Primary != w.primary || !u.Expires.Equal(end(w.end)) ||
					!u.Signed.Equal(fkAt(w.signed)) || u.Revoked != w.revoked || string(prefs) != string(w.prefs) {
					t.Errorf("user ID %d of the snapshot: %+v (prefs %v), pinned %+v", i, u, prefs, w)
				}
			}
			key := openpgp.SnapshotKey(k)
			if !key.Expires.Equal(end(c.keyEnd)) || !key.Newest.Equal(fkAt(c.newest)) || key.Revoked {
				t.Errorf("the key of the snapshot: expires %v newest %v revoked %v, pinned %d days and %d s", key.Expires, key.Newest, key.Revoked, c.keyEnd, c.newest)
			}
			if c.keyEnd != c.chosenKeyEnd || c.report != "" {
				reports++
				t.Logf("REPORT: %s (the snapshot says %d days, the person last chose %d with a strong signature)", c.report, c.keyEnd, c.chosenKeyEnd)
			}
		})
	}
	t.Logf("%d of %d cases are not what the person last chose with a strong signature, or are ambiguous", reports, len(cases))
}

// The end of the key is the end that the person last chose with a strong signature. It is not so while a
// signature with a SHA-1 hash that is newer gives it (noteExpiry takes every certification that counts and
// every direct-key signature that counts, and not the strong ones alone, as the user ID does).
func TestQAKeyEndIgnoresAWeakSignature(t *testing.T) {
	qaKnownBug(t, "foreign_snapshot.go noteExpiry and foreign_sigs.go keyLevel offer SHA-1 signatures as the source of the expiry of the key, while summariseUserID takes the newest strong one")
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	life := func(days uint32) []byte { return fkSubpacket(9, true, fkU32(days*86400)...) }
	for name, file := range map[string][]byte{
		"a SHA-1 certification newer than a strong one": qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{
			qaUserSig(t, w, fkUser, 0x13, 8, 1000, life(10)), qaUserSig(t, w, fkUser, 0x13, 2, 1100, life(5))}}),
		"a SHA-1 direct-key signature newer than a strong certification": qaFile(t, b, [][]byte{qaKeySig(t, w, 0x1F, 2, 1200, life(30))},
			qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 1000, life(10))}}),
	} {
		k := fkRead(t, file)
		want := fkEpoch.Add(10 * 86400 * time.Second)
		if got := openpgp.SnapshotKey(k).Expires; !got.Equal(want) {
			t.Errorf("%s: the snapshot says the key ends %v, the last strong signature chose %v", name, got, want)
		}
	}
}

// The same cases for the other two algorithms, through go-crypto's own signing, so that the snapshot is not
// one that only this writer's signatures give: two certifications at different times with different flags and
// expiries, and a SHA-1 one that is newer.
func TestQASnapshotFollowsTheNewestStrongSelfSignatureForEveryAlgorithm(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		me := b.primaryPair()
		cert := func(s fkSigSpec) []byte { return b.certSig(t, me, me.pub, fkUser, s) }
		head := fkTemplateHead(t, b.file(t, fkProt{}))
		ps := []fkPacket{head[0], head[1]}
		for _, s := range [][]byte{
			cert(fkSigSpec{Typ: 0x13, At: fkSigAt(1000), Flags: 1, KeyLife: 10 * 86400, Primary: true}),
			cert(fkSigSpec{Typ: 0x13, At: fkSigAt(1200), Flags: 3, KeyLife: 20 * 86400}),
			cert(fkSigSpec{Typ: 0x13, At: fkSigAt(1100), Flags: 2, KeyLife: 5 * 86400}),
		} {
			ps = append(ps, fkSplit(t, s)...)
		}
		k := fkRead(t, fkJoin(ps...))
		u := openpgp.SnapshotUsers(k)
		if len(u) != 1 || u[0].Flags != 3 || u[0].Primary || !u[0].Signed.Equal(fkAt(1200)) || !u[0].Expires.Equal(fkEpoch.Add(20*86400*time.Second)) {
			t.Errorf("the user ID of the snapshot: %+v", u)
		}
		if key := openpgp.SnapshotKey(k); !key.Expires.Equal(u[0].Expires) || !key.Newest.Equal(fkAt(1200)) {
			t.Errorf("the key of the snapshot: %+v", key)
		}
	})
}
