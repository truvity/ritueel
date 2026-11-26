package openpgp_test

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // a SHA-1 signature is what the tests make, and the fingerprint of a version 4 key is a SHA-1 by the standard
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The snapshot of a key (what the signing of an adopted key may know of it) is filled by the reader out
// of the signatures that counted. These tests hold it to two things: the key read from its export and
// the same key read from the certificate that the export gave have the same snapshot, and the snapshot
// says what the view and a second reader (go-crypto) say of the certificate.

// fkSnapshotCases are the files of the property, for one template: its plain file, the protected one, the
// rich file with every shape that the reader judges (clean, with all the shapes, protected, armoured),
// and a file whose user ID stands twice.
func fkSnapshotCases(t testing.TB, b *fkBase) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		"plain":            b.plain,
		"protected":        b.file(t, fkProt{Pass: fkPass}),
		"rich clean":       fkRichOf(t, b, false, true).file,
		"rich all shapes":  fkRichOf(t, b, false, false).file,
		"rich protected":   fkRichOf(t, b, true, false).file,
		"armoured":         fkArmourKey(t, b.plain),
		"rich armoured":    fkArmourKey(t, fkRichOf(t, b, false, false).file),
		"user ID repeated": fkRepeatedUserID(t, b),
	}
}

// fkRepeatedUserID is the template file with its user ID and its self-signature written twice: the
// reader merges them into one user ID and drops the duplicates.
func fkRepeatedUserID(t testing.TB, b *fkBase) []byte {
	t.Helper()
	ps := fkSplit(t, b.plain)
	head := fkTemplateHead(t, b.plain)
	out := append([]fkPacket{head[0], head[1], head[2], head[1], head[2]}, ps[3:]...)
	return fkJoin(out...)
}

func TestSnapshotOfTheCertificateIsTheSnapshotOfTheExport(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for name, file := range fkSnapshotCases(t, b) {
			t.Run(name, func(t *testing.T) {
				k := fkRead(t, file)
				cert := k.Certificate()
				kc, err := fkReadCertificate(cert)
				if err != nil {
					t.Fatalf("ReadForeignCertificate of the certificate of the export: %v", err)
				}
				if !bytes.Equal(kc.Certificate(), cert) {
					t.Error("the certificate read again is not the certificate")
				}
				if !reflect.DeepEqual(openpgp.SnapshotOf(k), openpgp.SnapshotOf(kc)) {
					t.Errorf("the snapshot of the certificate is not the snapshot of the export:\n export:      %+v\n certificate: %+v", openpgp.SnapshotOf(k), openpgp.SnapshotOf(kc))
				}
				fkCheckSnapshot(t, k)
				fkCheckSnapshot(t, kc)
			})
		}
	})
}

// fkCheckSnapshot holds the snapshot of a key to the view of the same key and to go-crypto's reading
// of its certificate.
func fkCheckSnapshot(t *testing.T, k *openpgp.ForeignKey) {
	t.Helper()
	ps := fkSplit(t, k.Certificate())
	key := openpgp.SnapshotKey(k)
	if !bytes.Equal(key.Body, ps[0].Body) || !bytes.Equal(key.Packet, wrap(6, ps[0].Body)) {
		t.Error("the primary of the snapshot is not the primary of the certificate")
	}
	if hex.EncodeToString(key.Fingerprint) != k.Primary.Fingerprint || !key.Created.Equal(k.Primary.Created) || key.Revoked != k.Primary.Revoked {
		t.Errorf("the key level of the snapshot is not the view's: %+v", key)
	}
	// the newest signature: every signature of the certificate counted, so it is the newest that
	// go-crypto reads in it
	var newest time.Time
	var userBodies, subBodies [][]byte
	for _, p := range ps {
		switch p.Tag {
		case 2:
			g, err := gpacket.Read(bytes.NewReader(wrap(2, p.Body)))
			if err != nil {
				t.Fatalf("go-crypto does not read a signature of the certificate: %v", err)
			}
			if at := g.(*gpacket.Signature).CreationTime; at.After(newest) {
				newest = at
			}
		case 13:
			userBodies = append(userBodies, p.Body)
		case 14:
			subBodies = append(subBodies, p.Body)
		}
	}
	if !key.Newest.Equal(newest) {
		t.Errorf("the newest signature of the snapshot is %v, go-crypto reads %v", key.Newest, newest)
	}

	// the user IDs: those with a self-signature that counts, once each, in the order of the certificate
	var want []openpgp.ForeignUserID
	seen := map[string]bool{}
	for _, u := range k.UserIDs {
		if u.Valid && !seen[u.Text] {
			seen[u.Text] = true
			want = append(want, u)
		}
	}
	// the snapshot lists the user IDs by their text and the subkeys by their fingerprint, whatever the order of
	// the file
	slices.SortFunc(want, func(a, b openpgp.ForeignUserID) int { return strings.Compare(a.Text, b.Text) })
	slices.SortFunc(userBodies, bytes.Compare)
	got := openpgp.SnapshotUsers(k)
	if len(got) != len(want) || len(got) != len(userBodies) {
		t.Fatalf("the snapshot has %d user IDs, the view %d, the certificate %d", len(got), len(want), len(userBodies))
	}
	for i, u := range got {
		w := want[i]
		var signed time.Time
		var anyStrong bool
		for _, s := range w.Signatures {
			if s.Type >= 0x10 && s.Type <= 0x13 && s.Status.Counts() {
				signed = laterTime(signed, s.Created)
				anyStrong = anyStrong || s.Status == openpgp.SignatureValid
			}
		}
		// the newest self-signature of any hash: when it is alone at its time, it is the source of the fields
		var newest []openpgp.ForeignSignature
		for _, s := range w.Signatures {
			if s.Type >= 0x10 && s.Type <= 0x13 && s.Status.Counts() && s.Created.Equal(signed) {
				newest = append(newest, s)
			}
		}
		if u.Text != w.Text || u.Text != string(userBodies[i]) || u.Revoked != w.Revoked || !u.Signed.Equal(signed) || u.AnyStrong != anyStrong {
			t.Errorf("user ID %d of the snapshot is not the view's: %+v, view %+v", i, u, w)
		}
		// the view and the snapshot choose the same signature: the fields are the same, with no exception
		if len(newest) > 0 {
			if u.Flags != w.KeyFlags || u.Primary != w.Primary || !u.Expires.Equal(w.KeyExpires) || u.Weak != w.WeakHash {
				t.Errorf("user ID %d of the snapshot has other fields than the view's: %+v, view %+v", i, u, w)
			}
		}
	}

	// the subkeys: those in the certificate, in its order
	var wantSubs []openpgp.ForeignSubkey
	for _, s := range k.Subkeys {
		if s.InCertificate {
			wantSubs = append(wantSubs, s)
		}
	}
	slices.SortFunc(wantSubs, func(a, b openpgp.ForeignSubkey) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	bodyOf := map[string][]byte{} // the body of each subkey packet of the certificate, by its fingerprint
	for _, b := range subBodies {
		sum := sha1.Sum(append([]byte{0x99, byte(len(b) >> 8), byte(len(b))}, b...)) //nolint:gosec // the fingerprint of a version 4 key is a SHA-1 by the standard
		bodyOf[hex.EncodeToString(sum[:])] = b
	}
	subs := openpgp.SnapshotSubkeys(k)
	if len(subs) != len(wantSubs) {
		t.Fatalf("the snapshot has %d subkeys, the view %d, the certificate %d", len(subs), len(wantSubs), len(subBodies))
	}
	for i, s := range subs {
		w := wantSubs[i]
		var bound time.Time
		for _, g := range w.Signatures {
			if g.Type == 0x18 && g.Status.Counts() && g.Created.After(bound) {
				bound = g.Created
			}
		}
		if hex.EncodeToString(s.Fingerprint) != w.Fingerprint || !bytes.Equal(s.Body, bodyOf[hex.EncodeToString(s.Fingerprint)]) || s.Revoked != w.Revoked || !s.Bound.Equal(bound) || s.Weak != w.WeakHash {
			t.Errorf("subkey %d of the snapshot is not the view's: %+v, view %+v", i, s, w)
		}
	}
}

// fkEdSigs makes a template file of the Ed25519 key whose user ID has the self-signatures given, in the
// order given, in place of its own, and the direct-key signatures given after the primary.
func fkEdFile(t testing.TB, w fkWriter, keySigs, userSigs [][]byte) []byte {
	t.Helper()
	return w.file(t, fkParts{noSelf: true, noBind: true, keySigs: keySigs, userSigs: userSigs})
}

// What the snapshot says of a user ID comes from its newest self-signature. The end of the key is kept for
// each source (each live user ID's newest self-signature and the newest direct-key signature): the answer is
// the earliest, whether there is a source, and whether the sources agree.
func TestSnapshotUserIDAndExpiryFollowTheNewestSignature(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	life := func(days uint32) []byte { return fkSubpacket(9, true, fkU32(days*86400)...) }
	flags := func(f byte) []byte { return fkSubpacket(27, false, f) }
	primary := fkSubpacket(25, false, 1)
	cert := func(at int, extra ...[]byte) []byte { return w.userSig(t, 0x13, w.areas(at, extra...), nil) }
	direct := func(at int, extra ...[]byte) []byte { return w.keySig(t, 0x1F, w.areas(at, extra...), nil) }

	cases := []struct {
		name         string
		keySigs      [][]byte
		userSigs     [][]byte
		wantFlags    uint8
		wantPrimary  bool
		wantUserEnd  int // days after the creation of the key, 0 for none
		wantKeyEnd   int // the earliest end of the sources
		wantAgree    bool
		wantSignedAt int
		wantNewest   int
	}{
		{"older with an expiry, newer without", nil, [][]byte{cert(1000, flags(1), life(10), primary), cert(1100, flags(3))}, 3, false, 0, 0, true, 1100, 1100},
		{"older without, newer with", nil, [][]byte{cert(1000, flags(1)), cert(1100, flags(2), life(20), primary)}, 2, true, 20, 20, true, 1100, 1100},
		{"the newest comes first in the file", nil, [][]byte{cert(1100, flags(2), life(20)), cert(1000, flags(1), life(5))}, 2, false, 20, 20, true, 1100, 1100},
		{"a direct-key signature that is newer is a source of its own", [][]byte{direct(1200, life(30))}, [][]byte{cert(1000, flags(1), life(10))}, 1, false, 10, 10, false, 1000, 1200},
		{"a direct-key signature that is older is a source too", [][]byte{direct(900, life(30))}, [][]byte{cert(1000, flags(1), life(10))}, 1, false, 10, 10, false, 1000, 1000},
		{"a direct-key signature with no expiry disagrees with the user ID", [][]byte{direct(1200)}, [][]byte{cert(1000, flags(1), life(10))}, 1, false, 10, 10, false, 1000, 1200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := fkRead(t, fkEdFile(t, w, c.keySigs, c.userSigs))
			kc, err := fkReadCertificate(k.Certificate())
			if err != nil || !reflect.DeepEqual(openpgp.SnapshotOf(k), openpgp.SnapshotOf(kc)) {
				t.Fatalf("the certificate does not read back to the same snapshot: %v", err)
			}
			users, key := openpgp.SnapshotUsers(k), openpgp.SnapshotKey(k)
			if len(users) != 1 {
				t.Fatalf("%d user IDs in the snapshot", len(users))
			}
			u := users[0]
			end := func(days int) time.Time {
				if days == 0 {
					return time.Time{}
				}
				return fkEpoch.Add(time.Duration(days) * 86400 * time.Second)
			}
			if u.Flags != c.wantFlags || u.Primary != c.wantPrimary || !u.Expires.Equal(end(c.wantUserEnd)) || !u.Signed.Equal(fkAt(c.wantSignedAt)) {
				t.Errorf("the user ID of the snapshot: %+v", u)
			}
			if e := key.Expiry; !e.Earliest.Equal(end(c.wantKeyEnd)) || !e.Any || e.Agree != c.wantAgree || e.Marked ||
				!key.Newest.Equal(fkAt(c.wantNewest)) || key.Revoked {
				t.Errorf("the key of the snapshot: %+v", key)
			}
		})
	}
}

// The preference subpackets that a later signature may carry over are the six types, once each, of at
// most 32 octets, without the critical bit, in the order of the list; nothing else of the hashed area.
func TestSnapshotCarriesOnlyTheWhitelistedSubpackets(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	sp := fkSubpacket
	long := bytes.Repeat([]byte{7}, 33)
	exact := bytes.Repeat([]byte{8}, 32)
	hashed := w.areas(1000,
		sp(30, false, 1),                 // features
		sp(21, true, 8, 9, 10),           // preferred hashes, marked critical
		sp(11, false, 9, 8),              // preferred ciphers, twice: dropped
		sp(11, false, 9),                 // ...
		sp(22, false, long...),           // 33 octets: dropped
		sp(39, false, exact...),          // 32 octets: kept
		sp(26, false, []byte("http")...), // a policy URL: not whitelisted
		sp(28, false, []byte("me")...),   // a signer's user ID: not whitelisted
		sp(3, false, fkU32(5)...),        // a signature expiration time: not whitelisted
		sp(27, false, 3),                 // key flags: kept apart from the preferences
	)
	k := fkRead(t, fkEdFile(t, w, nil, [][]byte{w.userSig(t, 0x13, hashed, nil)}))
	users := openpgp.SnapshotUsers(k)
	if len(users) != 1 {
		t.Fatalf("%d user IDs in the snapshot", len(users))
	}
	want := []openpgp.SnapPref{{Type: 21, Data: []byte{8, 9, 10}}, {Type: 30, Data: []byte{1}}, {Type: 39, Data: exact}}
	if !reflect.DeepEqual(users[0].Prefs, want) {
		t.Errorf("the carried subpackets are %+v, want %+v", users[0].Prefs, want)
	}
	// a key that go-crypto made carries what go-crypto wrote, byte for byte
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		ks := fkRead(t, b.plain)
		ps := fkSplit(t, ks.Certificate())
		var self []byte
		for _, p := range ps {
			if p.Tag == 2 {
				self = p.Body
				break
			}
		}
		typ, hashed, _, ok := fkSigAreasOf(self)
		if !ok || typ != 0x13 {
			t.Fatalf("the first signature of the certificate is not a certification")
		}
		sps, ok := fkReadSubpackets(hashed)
		if !ok {
			t.Fatal("the hashed area does not read")
		}
		var carried []openpgp.SnapPref
		for _, s := range sps {
			switch s.typ {
			case 11, 21, 22, 23, 30, 39:
				carried = append(carried, openpgp.SnapPref{Type: s.typ, Data: s.data})
			}
		}
		sortPrefs(carried)
		if got := openpgp.SnapshotUsers(ks)[0].Prefs; !reflect.DeepEqual(got, carried) {
			t.Errorf("the carried subpackets are %+v, the signature has %+v", got, carried)
		}
	})
}

func sortPrefs(p []openpgp.SnapPref) {
	order := map[byte]int{11: 0, 21: 1, 22: 2, 23: 3, 30: 4, 39: 5}
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && order[p[j].Type] < order[p[j-1].Type]; j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}

// A soft revocation of a user ID that a later self-signature undoes leaves a live user ID, and a hard
// one, or a soft one that is not older, a revoked one: the snapshot says what the view says, and keeps
// the revoked user ID, marked, so that nothing adds it again.
func TestSnapshotMarksARevokedUserID(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, fkRichOf(t, b, false, true).file)
		revoked := map[string]bool{}
		for _, u := range openpgp.SnapshotUsers(k) {
			revoked[u.Text] = u.Revoked
		}
		if !revoked[fkRichUserID("revoked")] || revoked[fkRichUserID("renewed")] || revoked[fkRichUserID("primary")] {
			t.Errorf("the revoked user IDs of the snapshot: %v", revoked)
		}
		subs := map[string]bool{}
		for _, s := range openpgp.SnapshotSubkeys(k) {
			subs[hex.EncodeToString(s.Fingerprint)] = s.Revoked
		}
		r := fkRichOf(t, b, false, true)
		fpOf := func(name string) string { return hex.EncodeToString(r.donor[name].pair.pub.Fingerprint) }
		if !subs[fpOf("revoked")] || subs[fpOf("valid")] {
			t.Errorf("the revoked subkeys of the snapshot: %v", subs)
		}
	})
}

// A key that a revocation of its own revoked is marked in the snapshot, and the snapshot of the key that
// the rich file with every shape makes holds it.
func TestSnapshotMarksARevokedKey(t *testing.T) {
	b := fkNamed(t, "ed25519")
	if k := fkRead(t, fkRichOf(t, b, false, false).file); !openpgp.SnapshotKey(k).Revoked {
		t.Error("a key with a key revocation is not revoked in the snapshot")
	}
	if k := fkRead(t, b.plain); openpgp.SnapshotKey(k).Revoked {
		t.Error("a key with no key revocation is revoked in the snapshot")
	}
}

func laterTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// fkSHA1UserSig is a self-signature of the user ID of the Ed25519 template made with SHA-1.
func fkSHA1UserSig(t testing.TB, w fkWriter, hashed []byte) []byte {
	t.Helper()
	return w.sign(t, "user", 0x13, hashed, nil, 2, sha1.New, []byte(fkUser))
}

// What the snapshot says of a user ID is what the person chose LAST, whatever the hash of that signature:
// a SHA-1 self-signature that is newer than a SHA-256 one is the source, and its weakness is a mark of its
// own.
func TestSnapshotSourceIsTheNewestSelfSignatureOfAnyHash(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	flags := func(f byte) []byte { return fkSubpacket(27, false, f) }
	pref := func(v ...byte) []byte { return fkSubpacket(21, false, v...) }
	strong := func(at int, f byte, p ...byte) []byte {
		return w.userSig(t, 0x13, w.areas(at, flags(f), pref(p...)), nil)
	}
	weak := func(at int, f byte, p ...byte) []byte {
		return fkSHA1UserSig(t, w, w.areas(at, flags(f), pref(p...)))
	}
	cases := []struct {
		name                string
		sigs                [][]byte
		wantFlags           uint8
		wantPref            []byte
		wantWeak, wantAnyOK bool
	}{
		{"a weak one newer than a strong one", [][]byte{strong(1000, 0x23, 8), weak(1100, 1, 9, 10)}, 1, []byte{9, 10}, true, true},
		{"the same in the other order of the file", [][]byte{weak(1100, 1, 9, 10), strong(1000, 0x23, 8)}, 1, []byte{9, 10}, true, true},
		{"a strong one newer than a weak one", [][]byte{weak(1000, 1, 9, 10), strong(1100, 0x23, 8)}, 0x23, []byte{8}, false, true},
		{"a weak one alone", [][]byte{weak(1000, 1, 9, 10)}, 1, []byte{9, 10}, true, false},
		{"a strong one alone", [][]byte{strong(1000, 0x23, 8)}, 0x23, []byte{8}, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := fkRead(t, fkEdFile(t, w, nil, c.sigs))
			kc, err := fkReadCertificate(k.Certificate())
			if err != nil || !reflect.DeepEqual(openpgp.SnapshotOf(k), openpgp.SnapshotOf(kc)) {
				t.Fatalf("the certificate does not read back to the same snapshot: %v", err)
			}
			u := openpgp.SnapshotUsers(k)[0]
			if u.Flags != c.wantFlags || u.Weak != c.wantWeak || u.AnyStrong != c.wantAnyOK ||
				!reflect.DeepEqual(u.Prefs, []openpgp.SnapPref{{Type: 21, Data: c.wantPref}}) {
				t.Errorf("the user ID of the snapshot: %+v", u)
			}
		})
	}
}

// A tie in time is broken by what the signatures say, the earlier end of the key first, and then by their
// bytes, and never by their place in the file: the same signatures in any order give the same snapshot.
func TestSnapshotTiesDoNotDependOnTheOrderOfTheFile(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	life := func(days uint32) []byte { return fkSubpacket(9, true, fkU32(days*86400)...) }
	flags := func(f byte) []byte { return fkSubpacket(27, false, f) }
	user := func(extra ...[]byte) []byte { return w.userSig(t, 0x13, w.areas(1000, extra...), nil) }
	direct := func(extra ...[]byte) []byte { return w.keySig(t, 0x1F, w.areas(1200, extra...), nil) }
	day := func(n int) time.Time { return fkEpoch.Add(time.Duration(n) * 86400 * time.Second) }

	cases := []struct {
		name       string
		keySigs    [][]byte
		userSigs   [][]byte
		wantFlags  uint8
		wantEnd    time.Time // of the user ID
		wantEarly  time.Time // the earliest end of the sources
		wantAgrees bool
	}{
		{"an end and no end in one second: the end wins", nil, [][]byte{user(flags(1), life(10)), user(flags(2))}, 1, day(10), day(10), true},
		{"two ends in one second: the earlier wins", nil, [][]byte{user(flags(1), life(20)), user(flags(2), life(10))}, 2, day(10), day(10), true},
		{"the same end and other flags: the smaller bytes win", nil, [][]byte{user(flags(1), life(10)), user(flags(2), life(10))}, 0, day(10), day(10), true},
		{"two direct-key signatures in one second", [][]byte{direct(life(30)), direct(life(20))}, [][]byte{user(flags(1), life(10))}, 1, day(10), day(10), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var first any
			for _, order := range []string{"as given", "reversed"} {
				keys, users := c.keySigs, c.userSigs
				if order == "reversed" {
					keys, users = reversed(keys), reversed(users)
				}
				k := fkRead(t, fkEdFile(t, w, keys, users))
				kc, err := fkReadCertificate(k.Certificate())
				if err != nil {
					t.Fatalf("%s: the certificate is refused: %v", order, err)
				}
				if !reflect.DeepEqual(openpgp.SnapshotOf(k), openpgp.SnapshotOf(kc)) {
					t.Errorf("%s: the snapshot of the certificate is not the one of the export", order)
				}
				if first == nil {
					first = openpgp.SnapshotOf(k)
				} else if !reflect.DeepEqual(first, openpgp.SnapshotOf(k)) {
					t.Errorf("the snapshot depends on the order of the file")
				}
				u, e := openpgp.SnapshotUsers(k)[0], openpgp.SnapshotKey(k).Expiry
				if !u.Expires.Equal(c.wantEnd) || (c.wantFlags != 0 && u.Flags != c.wantFlags) || !e.Earliest.Equal(c.wantEarly) || e.Agree != c.wantAgrees {
					t.Errorf("%s: user ID %+v, expiry %+v", order, u, e)
				}
			}
		})
	}
}

func reversed[T any](s []T) []T {
	out := make([]T, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

// For each subkey: whether its newest binding is SHA-1, and whether some binding that counts is not.
func TestSnapshotMarksAWeakBindingOfASubkey(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	enc, _, _ := fkDonors(t)
	bind := func(at int, strong bool) []byte {
		areas := w.areas(at, fkSubpacket(27, false, 0x0C))
		if strong {
			return w.sign(t, "sub", 0x18, areas, nil, 8, sha256.New, enc[3].pub.Body)
		}
		return w.sign(t, "sub", 0x18, areas, nil, 2, sha1.New, enc[3].pub.Body)
	}
	cases := []struct {
		name                     string
		sigs                     [][]byte
		wantWeak, wantStrongSome bool
		wantBound                int
	}{
		{"SHA-1 only", [][]byte{bind(1000, false)}, true, false, 1000},
		{"SHA-1 newer than SHA-256", [][]byte{bind(900, true), bind(1000, false)}, true, true, 1000},
		{"SHA-256 newer than SHA-1", [][]byte{bind(900, false), bind(1000, true)}, false, true, 1000},
		{"SHA-256 only", [][]byte{bind(1000, true)}, false, true, 1000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := fkRead(t, w.file(t, fkParts{subSigs: c.sigs}))
			kc, err := fkReadCertificate(k.Certificate())
			if err != nil || !reflect.DeepEqual(openpgp.SnapshotOf(k), openpgp.SnapshotOf(kc)) {
				t.Fatalf("the certificate does not read back to the same snapshot: %v", err)
			}
			subs := openpgp.SnapshotSubkeys(k)
			if len(subs) != 1 || subs[0].Weak != c.wantWeak || subs[0].AnyStrong != c.wantStrongSome || !subs[0].Bound.Equal(fkAt(c.wantBound)) {
				t.Errorf("the subkey of the snapshot: %+v", subs)
			}
		})
	}
}

// A newest signature with a signature expiration time (type 3) is marked, on a user ID and on the
// direct-key signature, and the mark is in the answer about the end of the key.
func TestSnapshotMarksASourceWithASignatureExpiration(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	sigLife := fkSubpacket(3, false, fkU32(86400)...)
	user := func(at int, extra ...[]byte) []byte { return w.userSig(t, 0x13, w.areas(at, extra...), nil) }
	direct := func(at int, extra ...[]byte) []byte { return w.keySig(t, 0x1F, w.areas(at, extra...), nil) }

	k := fkRead(t, fkEdFile(t, w, nil, [][]byte{user(1000)}))
	if u := openpgp.SnapshotUsers(k)[0]; u.SigExpires || openpgp.SnapshotKey(k).Expiry.Marked {
		t.Errorf("a signature with no signature expiration time is marked")
	}
	k = fkRead(t, fkEdFile(t, w, nil, [][]byte{user(1000, sigLife)}))
	if u := openpgp.SnapshotUsers(k)[0]; !u.SigExpires || !openpgp.SnapshotKey(k).Expiry.Marked {
		t.Errorf("a self-signature with a signature expiration time is not marked: %+v", u)
	}
	// the mark follows the newest self-signature: an older marked one does not count
	k = fkRead(t, fkEdFile(t, w, nil, [][]byte{user(900, sigLife), user(1000)}))
	if u := openpgp.SnapshotUsers(k)[0]; u.SigExpires || openpgp.SnapshotKey(k).Expiry.Marked {
		t.Errorf("an older marked self-signature marks the user ID: %+v", u)
	}
	k = fkRead(t, fkEdFile(t, w, [][]byte{direct(1100, sigLife)}, [][]byte{user(1000)}))
	if u := openpgp.SnapshotUsers(k)[0]; u.SigExpires || !openpgp.SnapshotKey(k).Expiry.Marked {
		t.Errorf("a direct-key signature with a signature expiration time is not marked: %+v", u)
	}
	kc, err := fkReadCertificate(k.Certificate())
	if err != nil || !reflect.DeepEqual(openpgp.SnapshotOf(k), openpgp.SnapshotOf(kc)) {
		t.Errorf("the certificate does not read back to the same snapshot: %v", err)
	}
}

// The view of a key read from an export says how many self-signatures were claimed by the primary and not
// counted for their hash or an unknown critical subpacket, and the newest of them; the snapshot and the
// certificate do not know of them.
func TestTheViewCountsTheSelfSignaturesThatWereClaimedAndNotCounted(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	cert := func(at int, hashID byte, extra ...[]byte) []byte {
		return w.sign(t, "user", 0x13, w.areas(at, extra...), nil, hashID, sha256.New, []byte(fkUser))
	}
	direct := func(at int, hashID byte) []byte {
		return w.sign(t, "key", 0x1F, w.areas(at), nil, hashID, sha256.New, nil)
	}
	unknownCritical := fkSubpacket(100, true, 1)

	good := fkEdFile(t, w, nil, [][]byte{cert(1000, 8)})
	k := fkRead(t, good)
	if k.UncountedClaims != 0 || !k.UncountedClaimsNewest.IsZero() {
		t.Errorf("a file with nothing uncounted: %d, %v", k.UncountedClaims, k.UncountedClaimsNewest)
	}

	// MD5 at 2000, SHA-224 at 1500, an unknown critical subpacket at 3000, and a direct-key signature with
	// RIPEMD-160 at 500; a self-signature that does not verify is not of them
	bad := cert(1100, 8)
	bad[len(bad)-1] ^= 1
	file := fkEdFile(t, w,
		[][]byte{direct(500, 3)},
		[][]byte{cert(1000, 8), cert(2000, 1), cert(1500, 11), cert(3000, 8, unknownCritical), bad})
	k = fkRead(t, file)
	if k.UncountedClaims != 4 || !k.UncountedClaimsNewest.Equal(fkAt(3000)) {
		t.Errorf("the claims that were not counted: %d, newest %v", k.UncountedClaims, k.UncountedClaimsNewest)
	}
	// the snapshot and the certificate do not know of them, and the snapshot is the one of the certificate
	kc, err := fkReadCertificate(k.Certificate())
	if err != nil {
		t.Fatal(err)
	}
	if kc.UncountedClaims != 0 || !kc.UncountedClaimsNewest.IsZero() {
		t.Errorf("a certificate has uncounted claims: %d", kc.UncountedClaims)
	}
	if !reflect.DeepEqual(openpgp.SnapshotOf(k), openpgp.SnapshotOf(kc)) || !openpgp.SnapshotNewest(k).Equal(fkAt(1000)) {
		t.Error("the claims that were not counted entered the snapshot")
	}
}

// tied is true when the newest choice was made by the bytes of the packets: the same second and the same
// end of the key in two packets. It is not true when the time or the end decides.
func TestSnapshotMarksAChoiceThatTheBytesDecided(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	life := func(days uint32) []byte { return fkSubpacket(9, true, fkU32(days*86400)...) }
	flags := func(f byte) []byte { return fkSubpacket(27, false, f) }
	user := func(at int, extra ...[]byte) []byte { return w.userSig(t, 0x13, w.areas(at, extra...), nil) }
	direct := func(at int, extra ...[]byte) []byte { return w.keySig(t, 0x1F, w.areas(at, extra...), nil) }
	enc, _, _ := fkDonors(t)
	bind := func(at int, f byte) []byte {
		return w.sign(t, "sub", 0x18, w.areas(at, fkSubpacket(27, false, f)), nil, 8, sha256.New, enc[3].pub.Body)
	}
	cases := []struct {
		name                 string
		keySigs, userSigs    [][]byte
		subSigs              [][]byte
		wantUser, wantDirect bool
		wantSubkey           bool
	}{
		{"one signature each", [][]byte{direct(1100)}, [][]byte{user(1000, flags(1))}, [][]byte{bind(1000, 0x0C)}, false, false, false},
		{"another time", [][]byte{direct(1100), direct(1200)}, [][]byte{user(1000, flags(1)), user(1001, flags(2))}, [][]byte{bind(1000, 0x0C), bind(1001, 0x04)}, false, false, false},
		{"the same time and another end: the end decides", [][]byte{direct(1100, life(5)), direct(1100, life(6))}, [][]byte{user(1000, life(10)), user(1000, life(20))}, nil, false, false, false},
		{"the same time and the same end: the bytes decide", [][]byte{direct(1100, flags(1)), direct(1100, flags(2))}, [][]byte{user(1000, flags(1)), user(1000, flags(2))}, [][]byte{bind(1000, 0x0C), bind(1000, 0x04)}, true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var file []byte
			if c.subSigs != nil {
				file = w.file(t, fkParts{noSelf: true, keySigs: c.keySigs, userSigs: c.userSigs, subSigs: c.subSigs, noBind: true})
			} else {
				file = fkEdFile(t, w, c.keySigs, c.userSigs)
			}
			k := fkRead(t, file)
			kc, err := fkReadCertificate(k.Certificate())
			if err != nil || !reflect.DeepEqual(openpgp.SnapshotOf(k), openpgp.SnapshotOf(kc)) {
				t.Fatalf("the certificate does not read back to the same snapshot: %v", err)
			}
			if got := openpgp.SnapshotUsers(k)[0].Tied; got != c.wantUser {
				t.Errorf("the user ID is tied: %v, want %v", got, c.wantUser)
			}
			if got := openpgp.SnapshotKey(k).DirectTied; got != c.wantDirect {
				t.Errorf("the direct-key signature is tied: %v, want %v", got, c.wantDirect)
			}
			if subs := openpgp.SnapshotSubkeys(k); c.subSigs != nil && (len(subs) != 1 || subs[0].Tied != c.wantSubkey) {
				t.Errorf("the subkey: %+v, want tied %v", subs, c.wantSubkey)
			}
		})
	}
}

// The order of the file decides nothing of the snapshot: the user IDs and the subkeys of the rich key in
// the reverse order give the same snapshot, the certificate keeps the order of the file and is read as it
// stands, and the primary user ID is the same.
func TestSnapshotDoesNotDependOnTheOrderOfUserIDsAndSubkeys(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		file := fkRichOf(t, b, false, true).file
		reordered := fkReverseBlocks(t, file)
		if bytes.Equal(file, reordered) {
			t.Fatal("the file was not reordered")
		}
		k, r := fkRead(t, file), fkRead(t, reordered)
		if bytes.Equal(k.Certificate(), r.Certificate()) {
			t.Error("the certificate of the reordered file is not in the order of the file")
		}
		if !reflect.DeepEqual(openpgp.SnapshotOf(k), openpgp.SnapshotOf(r)) {
			t.Error("the snapshot depends on the order of the user IDs and the subkeys")
		}
		if _, err := fkReadCertificate(r.Certificate()); err != nil {
			t.Errorf("the certificate of the reordered file is refused: %v", err)
		}
		users := openpgp.SnapshotUsers(k)
		for i := 1; i < len(users); i++ {
			if users[i-1].Text >= users[i].Text {
				t.Errorf("the user IDs of the snapshot are not in the order of their text: %q, %q", users[i-1].Text, users[i].Text)
			}
		}
		subs := openpgp.SnapshotSubkeys(k)
		for i := 1; i < len(subs); i++ {
			if bytes.Compare(subs[i-1].Fingerprint, subs[i].Fingerprint) >= 0 {
				t.Errorf("the subkeys of the snapshot are not in the order of their fingerprint")
			}
		}
		pk, ok := openpgp.SnapshotPrimaryUserID(k)
		pr, ok2 := openpgp.SnapshotPrimaryUserID(r)
		if !ok || !ok2 || pk != pr || pk != fkRichUserID("primary") {
			t.Errorf("the primary user ID is %q and %q (%v %v), want %q", pk, pr, ok, ok2, fkRichUserID("primary"))
		}
	})
}

// fkReverseBlocks writes a file with its user ID blocks (a user ID or attribute with its signatures) and
// its subkey blocks (a subkey with its signatures) in the reverse order.
func fkReverseBlocks(t testing.TB, file []byte) []byte {
	t.Helper()
	var head []fkPacket
	var users, subs [][]fkPacket
	section := 0 // 0 the key and its signatures, 1 the user IDs, 2 the subkeys
	for _, p := range fkSplit(t, file) {
		switch {
		case p.Tag == 13 || p.Tag == 17:
			section = 1
			users = append(users, []fkPacket{p})
		case p.Tag == 7 || p.Tag == 14:
			section = 2
			subs = append(subs, []fkPacket{p})
		case section == 0:
			head = append(head, p)
		case section == 1:
			users[len(users)-1] = append(users[len(users)-1], p)
		default:
			subs[len(subs)-1] = append(subs[len(subs)-1], p)
		}
	}
	out := head
	for _, blocks := range [][][]fkPacket{reversed(users), reversed(subs)} {
		for _, blk := range blocks {
			out = append(out, blk...)
		}
	}
	return fkJoin(out...)
}
