package openpgp_test

import (
	"crypto/sha1" //nolint:gosec // a SHA-1 binding that verifies counts: the files here hold some
	"crypto/sha256"
	"fmt"
	"slices"
	"sort"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// The exported view of the reader makes the same choice as the snapshot (the newest signature of any hash, a
// tie by the end of the key, the strength of the hash and the bytes of the packets). This test reads every key of
// the kit and lists, by field, where the two disagree about one key. For a user ID or a subkey that occurs
// once in the export they do not. For one that occurs TWICE the view lists each occurrence with the signatures
// that stood under it, and the snapshot merges them: that case is pinned in its own test.
func TestQAViewAndSnapshotAgreeForTheKit(t *testing.T) {
	got := map[string]int{}
	example := map[string]string{}
	note := func(field, name string) {
		got[field]++
		if _, ok := example[field]; !ok {
			example[field] = name
		}
	}
	keys, repeated := 0, 0
	for _, f := range qaExports(t) {
		k, err := openpgp.ReadForeignKey(f.file)
		if err != nil {
			continue
		}
		keys++
		occurrences := map[string][]openpgp.ForeignUserID{}
		for _, u := range k.UserIDs {
			if u.Valid {
				occurrences[u.Text] = append(occurrences[u.Text], u)
			}
		}
		for _, s := range openpgp.SnapshotUsers(k) {
			occ := occurrences[s.Text]
			if len(occ) != 1 {
				repeated++
				continue
			}
			v := occ[0]
			for field, same := range map[string]bool{
				"user ID: key flags":               s.Flags == v.KeyFlags,
				"user ID: primary mark":            s.Primary == v.Primary,
				"user ID: end of the key":          s.Expires.Equal(v.KeyExpires),
				"user ID: revoked":                 s.Revoked == v.Revoked,
				"user ID: time of the source":      s.Signed.Equal(v.Created) || v.Revoked,
				"user ID: the source is SHA-1":     s.Weak == v.WeakHash,
				"user ID: Valid for a live source": v.Valid,
			} {
				if !same {
					note(field, f.name)
				}
			}
		}
		subs := map[string][]openpgp.ForeignSubkey{}
		for _, s := range k.Subkeys {
			if s.InCertificate {
				subs[s.Fingerprint] = append(subs[s.Fingerprint], s)
			}
		}
		for _, s := range openpgp.SnapshotSubkeys(k) {
			occ := subs[fmt.Sprintf("%x", s.Fingerprint)]
			if len(occ) != 1 {
				repeated++
				continue
			}
			v := occ[0]
			for field, same := range map[string]bool{
				"subkey: revoked":             s.Revoked == v.Revoked,
				"subkey: time of the source":  s.Bound.Equal(v.BoundAt) || v.Revoked || !v.Bound,
				"subkey: the source is SHA-1": s.Weak == v.WeakHash || v.Revoked || !v.Bound,
			} {
				if !same {
					note(field, f.name)
				}
			}
		}
		if openpgp.SnapshotKey(k).Revoked != k.Primary.Revoked {
			note("key: revoked", f.name)
		}
	}
	var fields []string
	for f := range got {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, f := range fields {
		t.Errorf("the view and the snapshot differ in %s: %d keys of the kit (first: %s)", f, got[f], example[f])
	}
	t.Logf("%d keys compared; %d users or subkeys that occur more than once were left to their own test", keys, repeated)
	if keys < 150 {
		t.Errorf("only %d keys were compared", keys)
	}
}

// A user ID that occurs twice in an export. The view lists each occurrence, with the signatures that stood
// under it, and says what each one alone says. The snapshot merges the two into one user ID whose source is the
// newest self-signature of both. The same for a subkey.
func TestQATheViewListsTheTwoOccurrencesOfAUserIDAndTheSnapshotMergesThem(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	sp := fkSubpacket
	head := fkTemplateHead(t, b.file(t, fkProt{}))
	first := qaUserSig(t, w, fkUser, 0x13, 8, 1000, sp(27, false, 1), sp(9, true, fkU32(10*86400)...))
	second := qaUserSig(t, w, fkUser, 0x13, 8, 1100, sp(27, false, 2), sp(9, true, fkU32(20*86400)...))
	file := fkJoin(head[0], fkPacket{13, []byte(fkUser)}, fkPacket{2, first}, fkPacket{13, []byte(fkUser)}, fkPacket{2, second})
	k := fkRead(t, file)
	if len(k.UserIDs) != 2 {
		t.Fatalf("the view lists %d user IDs: %+v", len(k.UserIDs), k.UserIDs)
	}
	v0, v1 := k.UserIDs[0], k.UserIDs[1]
	if v0.KeyFlags != 1 || v1.KeyFlags != 2 || !v0.Created.Equal(fkAt(1000)) || !v1.Created.Equal(fkAt(1100)) ||
		!v0.KeyExpires.Equal(fkEpoch.AddDate(0, 0, 10)) || !v1.KeyExpires.Equal(fkEpoch.AddDate(0, 0, 20)) {
		t.Errorf("each occurrence of the view says what its own signature says: %+v, %+v", v0, v1)
	}
	snap := openpgp.SnapshotUsers(k)
	if len(snap) != 1 || snap[0].Flags != 2 || !snap[0].Signed.Equal(fkAt(1100)) || !snap[0].Expires.Equal(fkEpoch.AddDate(0, 0, 20)) {
		t.Errorf("the snapshot merges them and takes the newest: %+v", snap)
	}
	if e := openpgp.SnapshotKey(k).Expiry; !e.Any || !e.Agree || !e.Earliest.Equal(fkEpoch.AddDate(0, 0, 20)) {
		t.Errorf("the end of the key is that of the merged user ID: %+v", e)
	}
	// the certificate has the user ID once, with both signatures
	kc, err := qaReadCert(k.Certificate())
	if err != nil || len(kc.UserIDs) != 1 || len(kc.UserIDs[0].Signatures) != 2 || !qaSnapshotEqual(k, kc) {
		t.Fatalf("the certificate of the key with a user ID twice: %v", err)
	}
	if kc.UserIDs[0].KeyFlags != 2 || !kc.UserIDs[0].Created.Equal(fkAt(1100)) {
		t.Errorf("the view of the certificate says what the snapshot says: %+v", kc.UserIDs[0])
	}
	// the occurrences listed by the view and the one of the snapshot are the same text
	texts := []string{v0.Text, v1.Text}
	if !slices.Equal(texts, []string{fkUser, fkUser}) {
		t.Errorf("%v", texts)
	}
}

// The view of a subkey makes the choice of the snapshot: the newest binding of any hash, a tie by the end, the
// strength of the hash and the bytes. A SHA-1 binding that is newer than a strong one is the source in both.
func TestQATheViewOfASubkeyMakesTheChoiceOfTheSnapshot(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	enc, _, _ := fkDonors(t)
	bind := func(hash byte, at int, flags byte, extra ...[]byte) []byte {
		areas := w.areas(at, append([][]byte{fkSubpacket(27, false, flags)}, extra...)...)
		if hash == 2 {
			return w.sign(t, "sub", 0x18, areas, nil, 2, sha1.New, enc[3].pub.Body)
		}
		return w.sign(t, "sub", 0x18, areas, nil, 8, sha256.New, enc[3].pub.Body)
	}
	life := func(d uint32) []byte { return fkSubpacket(9, true, fkU32(d*86400)...) }
	for _, c := range []struct {
		name      string
		sigs      [][]byte
		flags     uint8
		boundAt   int
		weak      bool
		wantTied  bool
		wantLife  uint32
		wantOrder string
	}{
		{"a SHA-1 binding newer than a strong one", [][]byte{bind(8, 1000, 0x0C), bind(2, 1100, 0x04)}, 0x04, 1100, true, false, 0, ""},
		{"the same, the other way round in the file", [][]byte{bind(2, 1100, 0x04), bind(8, 1000, 0x0C)}, 0x04, 1100, true, false, 0, ""},
		{"a strong binding newer than a SHA-1 one", [][]byte{bind(2, 1000, 0x04), bind(8, 1100, 0x0C)}, 0x0C, 1100, false, false, 0, ""},
		{"one second, a weak and a strong one: the strong one", [][]byte{bind(2, 1000, 0x04), bind(8, 1000, 0x0C)}, 0x0C, 1000, false, false, 0, ""},
		{"one second, two ends: the earlier end", [][]byte{bind(8, 1000, 0x04, life(20)), bind(8, 1000, 0x0C, life(10))}, 0x0C, 1000, false, false, 10, ""},
		{"one second, the same end, other flags: tied", [][]byte{bind(8, 1000, 0x04), bind(8, 1000, 0x0C)}, 0, 1000, false, true, 0, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			order := [][]byte{c.sigs[0], c.sigs[1]}
			for _, sigs := range [][][]byte{order, {order[1], order[0]}} {
				k := fkRead(t, w.file(t, fkParts{subSigs: sigs}))
				if len(k.Subkeys) != 1 || !k.Subkeys[0].Bound {
					t.Fatalf("the subkey: %+v", k.Subkeys)
				}
				v, s := k.Subkeys[0], openpgp.SnapshotSubkeys(k)[0]
				if !v.BoundAt.Equal(s.Bound) || v.WeakHash != s.Weak || s.Tied != c.wantTied || !v.BoundAt.Equal(fkAt(c.boundAt)) || v.WeakHash != c.weak {
					t.Errorf("view %+v, snapshot %+v", v, s)
				}
				if c.flags != 0 && v.Flags != c.flags {
					t.Errorf("the flags of the view are %#x, want %#x", v.Flags, c.flags)
				}
				if c.wantLife != 0 && !v.Expires.Equal(v.Created.AddDate(0, 0, int(c.wantLife))) {
					t.Errorf("the end of the view is %v", v.Expires)
				}
			}
		})
	}
}
