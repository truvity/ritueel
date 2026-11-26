package openpgp_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
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
				kc, err := openpgp.ReadForeignCertificate(cert)
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
	got := openpgp.SnapshotUsers(k)
	if len(got) != len(want) || len(got) != len(userBodies) {
		t.Fatalf("the snapshot has %d user IDs, the view %d, the certificate %d", len(got), len(want), len(userBodies))
	}
	for i, u := range got {
		w := want[i]
		var signed time.Time
		for _, s := range w.Signatures {
			if s.Type >= 0x10 && s.Type <= 0x13 && s.Status.Counts() && s.Created.After(signed) {
				signed = s.Created
			}
		}
		if u.Text != w.Text || u.Text != string(userBodies[i]) || u.Revoked != w.Revoked || u.Flags != w.KeyFlags ||
			u.Primary != w.Primary || !u.Expires.Equal(w.KeyExpires) || !u.Signed.Equal(signed) {
			t.Errorf("user ID %d of the snapshot is not the view's: %+v, view %+v", i, u, w)
		}
	}

	// the subkeys: those in the certificate, in its order
	var wantSubs []openpgp.ForeignSubkey
	for _, s := range k.Subkeys {
		if s.InCertificate {
			wantSubs = append(wantSubs, s)
		}
	}
	subs := openpgp.SnapshotSubkeys(k)
	if len(subs) != len(wantSubs) || len(subs) != len(subBodies) {
		t.Fatalf("the snapshot has %d subkeys, the view %d, the certificate %d", len(subs), len(wantSubs), len(subBodies))
	}
	for i, s := range subs {
		w := wantSubs[i]
		if hex.EncodeToString(s.Fingerprint) != w.Fingerprint || !bytes.Equal(s.Body, subBodies[i]) || s.Revoked != w.Revoked || !s.Bound.Equal(w.BoundAt) {
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

// What the snapshot says of a user ID comes from its newest self-signature, and the expiry of the key from
// the newest self-signature of the key.
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
		wantKeyEnd   int
		wantSignedAt int
		wantNewest   int
	}{
		{"older with an expiry, newer without", nil, [][]byte{cert(1000, flags(1), life(10), primary), cert(1100, flags(3))}, 3, false, 0, 0, 1100, 1100},
		{"older without, newer with", nil, [][]byte{cert(1000, flags(1)), cert(1100, flags(2), life(20), primary)}, 2, true, 20, 20, 1100, 1100},
		{"the newest comes first in the file", nil, [][]byte{cert(1100, flags(2), life(20)), cert(1000, flags(1), life(5))}, 2, false, 20, 20, 1100, 1100},
		{"a direct-key signature that is newer gives the key's expiry", [][]byte{direct(1200, life(30))}, [][]byte{cert(1000, flags(1), life(10))}, 1, false, 10, 30, 1000, 1200},
		{"a direct-key signature that is older does not", [][]byte{direct(900, life(30))}, [][]byte{cert(1000, flags(1), life(10))}, 1, false, 10, 10, 1000, 1000},
		{"a direct-key signature with no expiry ends it", [][]byte{direct(1200)}, [][]byte{cert(1000, flags(1), life(10))}, 1, false, 10, 0, 1000, 1200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := fkRead(t, fkEdFile(t, w, c.keySigs, c.userSigs))
			kc, err := openpgp.ReadForeignCertificate(k.Certificate())
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
			if !key.Expires.Equal(end(c.wantKeyEnd)) || !key.Newest.Equal(fkAt(c.wantNewest)) || key.Revoked {
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
