package openpgp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1" //nolint:gosec // the version 4 fingerprint is a SHA-1 by the standard
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// The two readers of untrusted bytes that the keyring file adds: the reader of the whole file and the
// one check of a certification that the builder shares with it. Neither target starts a program.

// wantFromFile makes a list from the key packets that a file holds, by the tests' own reader: one
// entry for each Public-Key packet, labelled A, B, ... in file order, with the fingerprint of that
// packet. The mode changes the list so that the reader meets each of its refusals of the list: 0 as
// it is, 1 reversed, 2 the first entry only, 3 one entry more, 4 the labels shifted by one.
func wantFromFile(file []byte, mode uint8) []openpgp.KeyringEntry {
	tags, bodies, ok := softPackets(file)
	var want []openpgp.KeyringEntry
	if ok {
		for i, tag := range tags {
			if tag != tagPublicKey || len(want) == openpgp.MaxKeyringCertificates {
				continue
			}
			b := bodies[i]
			h := sha1.New() //nolint:gosec // see the import
			h.Write([]byte{0x99, byte(len(b) >> 8), byte(len(b))})
			h.Write(b)
			want = append(want, openpgp.KeyringEntry{Label: string(rune('A' + len(want))), Fingerprint: fmt.Sprintf("%x", h.Sum(nil))})
		}
	}
	if len(want) == 0 {
		want = []openpgp.KeyringEntry{{Label: "A", Fingerprint: fmt.Sprintf("%040x", 1)}}
	}
	switch mode % 5 {
	case 1:
		slices.Reverse(want)
	case 2:
		want = want[:1]
	case 3:
		if len(want) < openpgp.MaxKeyringCertificates {
			want = append(want, openpgp.KeyringEntry{Label: string(rune('A' + len(want))), Fingerprint: fmt.Sprintf("%040x", 7)})
		}
	case 4:
		for i := range want {
			want[i].Label = string(rune('A' + (i+1)%26))
		}
	}
	return want
}

// softSignatures is the signature packets of a file by the tests' own packet reader, none when the file
// is not whole packets.
func softSignatures(file []byte) [][]byte {
	tags, bodies, ok := softPackets(file)
	if !ok {
		return nil
	}
	var out [][]byte
	for i, tag := range tags {
		if tag == tagSignature {
			out = append(out, bodies[i])
		}
	}
	return out
}

func hasDuplicate(want []openpgp.KeyringEntry) bool {
	seenL, seenF := map[string]bool{}, map[string]bool{}
	for _, e := range want {
		if seenL[e.Label] || seenF[e.Fingerprint] {
			return true
		}
		seenL[e.Label], seenF[e.Fingerprint] = true, true
	}
	return false
}

// checkAcceptedCertification is the oracle of the page, with the tests' own code: the packet is one
// whole signature packet, the shape is the one of the page and the signature verifies by the formula
// of the standard. It fails the test when an accepted certification is not one.
func checkAcceptedCertification(t *testing.T, pkt, keyPacket []byte, uid string) {
	t.Helper()
	tag, body, rest, ok := softPacket(pkt)
	if !ok || tag != tagSignature || len(rest) != 0 {
		t.Fatalf("accepted bytes that are not one signature packet")
	}
	_, kbody, _, ok := softPacket(keyPacket)
	if !ok || len(kbody) < 97 {
		t.Fatal("the key packet of the oracle is not whole")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), kbody[len(kbody)-97:])
	if err != nil {
		t.Fatal(err)
	}
	s := parseSig(t, body)
	if s.Version != 4 || s.Type != 0x13 || s.Algo != 19 || s.Hash != 9 {
		t.Fatalf("accepted a signature of version %d, type %#x, algorithm %d, hash %d", s.Version, s.Type, s.Algo, s.Hash)
	}
	got := types(s.Hashed)
	slices.Sort(got)
	if !bytes.Equal(got, []byte{2, 9, 27, 33}) || !bytes.Equal(types(s.Unhashed), []byte{16}) {
		t.Fatalf("accepted hashed types % d and unhashed types % d", got, types(s.Unhashed))
	}
	if c := critical(s.Hashed); !bytes.Equal(c, []byte{9}) || len(critical(s.Unhashed)) != 0 {
		t.Fatalf("accepted critical hashed types % d", c)
	}
	if !bytes.Equal(find(t, s.Hashed, 27).Data, []byte{1}) || len(find(t, s.Hashed, 2).Data) != 4 || len(find(t, s.Hashed, 9).Data) != 4 ||
		binary.BigEndian.Uint32(find(t, s.Hashed, 9).Data) == 0 {
		t.Fatal("accepted a flags, creation time or expiration subpacket that is not the page's")
	}
	fp := sha1OfKeyBody(kbody)
	if !bytes.Equal(find(t, s.Hashed, 33).Data, append([]byte{4}, fp...)) || !bytes.Equal(find(t, s.Unhashed, 16).Data, fp[12:]) {
		t.Fatal("accepted an issuer that is not the key")
	}
	n := len(uid)
	data := [][]byte{append([]byte{0x99, byte(len(kbody) >> 8), byte(len(kbody))}, kbody...), {0xB4, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, []byte(uid)}
	if !verifySig(t, pub, body, data...) {
		t.Fatal("accepted a signature that the formula of the standard refuses")
	}
}

func sha1OfKeyBody(b []byte) []byte {
	h := sha1.New() //nolint:gosec // see the import
	h.Write([]byte{0x99, byte(len(b) >> 8), byte(len(b))})
	h.Write(b)
	return h.Sum(nil)
}

// FuzzReadKeyring gives the reader, through the inner function that has no recover, any bytes and a
// list made from the file. An error returns no primary, is one of the three kinds and shows only
// printable ASCII. A success returns the primaries of the list in its order, makes one signature check
// for each certification, go-crypto reads the same fingerprints, no certification repeats another of its
// certificate, and every certification is one that the tests' own check of the page accepts.
func FuzzReadKeyring(f *testing.F) {
	v := loadVectorKeyring(f)
	a, b, z := newKeyringPrimary(f, "A", true), newKeyringPrimary(f, "B", true), newKeyringPrimary(f, "C", false)
	ext := cat(a.cert(f), a.extension(f, ceremony.Add(time.Hour)))
	for _, mode := range []uint8{0, 1, 2, 3, 4} {
		f.Add(cat(v.a, v.b), mode)
		f.Add(v.a, mode)
		f.Add(cat(v.a, v.z), mode)
		f.Add(cat(a.cert(f), b.cert(f)), mode)
		f.Add(cat(a.cert(f), z.cert(f)), mode)
		f.Add(ext, mode)
		f.Add(repack(f, cat(v.a, v.b), "old2"), mode)
		f.Add(repack(f, cat(a.cert(f), b.cert(f)), "new1"), mode)
	}
	good := a.good(f)
	rep := a.sig(f, ceremony, nil)
	repBody := splitPackets(f, rep)[0].Body
	repOld, _ := packetIn("old2", tagSignature, repBody)
	for _, c := range [][]byte{
		a.assemble(rep, rep), a.assemble(rep, repOld), a.assemble(rep, a.sig(f, ceremony.Add(time.Second), nil), rep),
		cat(a.good(f), b.good(f), z.good(f)), cat(a.good(f), z.good(f), b.good(f)), cat(a.chain(f, 3), b.chain(f, 2)),
	} {
		f.Add(c, uint8(0))
		f.Add(c, uint8(1))
	}
	for _, c := range [][]byte{
		nil, {0x00}, {0xC6, 0x00}, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----"), good[:len(good)-1], cat(good, []byte{0}),
		cat(a.keyPacket(), a.uidPacket()), cat(a.keyPacket(), a.sig(f, ceremony, nil)),
		cat(good, wrap(tagSubkey, keyBody(&b.key.PublicKey, created))), cat(a.keyPacket(), a.uidPacket(), a.uidPacket(), a.sig(f, ceremony, nil)),
		a.assemble(a.sig(f, ceremony, func(sp *sigSpec) { sp.Type = 0x10 })),
		a.assemble(a.sig(f, ceremony, func(sp *sigSpec) { sp.TagXOR = [2]byte{1, 0} })),
		a.assemble(a.sig(f, ceremony, func(sp *sigSpec) { sp.LongLengths, sp.OldHeader = true, true })),
		a.withUserID("junk").good(f),
		bytes.Repeat([]byte{0xC2, 0x00}, 300),
	} {
		f.Add(c, uint8(0))
	}
	f.Fuzz(func(t *testing.T, file []byte, mode uint8) {
		want := wantFromFile(file, mode)
		fileBefore := bytes.Clone(file)
		wantBefore := slices.Clone(want)
		// The reader without the net of a recover: a panic in it is a failure of this target, which the
		// exported function would turn into an error and hide.
		keys, err := openpgp.ReadKeyringNoRecover(file, want)
		if !bytes.Equal(file, fileBefore) || !slices.Equal(want, wantBefore) {
			t.Fatal("the reader changed its arguments")
		}
		// The counting reader runs the same inner function: it gives the same answer, and it never makes
		// more signature checks than the file holds certifications.
		ckeys, checked, cerr := openpgp.ReadKeyringCounting(file, want)
		if (err == nil) != (cerr == nil) || (err != nil && err.Error() != cerr.Error()) || len(keys) != len(ckeys) {
			t.Fatalf("the reader says %d primaries and %v, the counting reader %d and %v", len(keys), err, len(ckeys), cerr)
		}
		if n := len(softSignatures(file)); len(checked) > n {
			t.Fatalf("%d signature checks for %d signature packets", len(checked), n)
		}
		// The exported function gives the same answer as the inner one: the net changes no result.
		if ekeys, eerr := openpgp.ReadKeyring(file, want); (err == nil) != (eerr == nil) || (err != nil && err.Error() != eerr.Error()) || len(keys) != len(ekeys) {
			t.Fatalf("the inner reader says %d primaries and %v, ReadKeyring %d and %v", len(keys), err, len(ekeys), eerr)
		}
		if err != nil {
			if keys != nil {
				t.Fatalf("%d primaries with the error %v", len(keys), err)
			}
			switch {
			case errors.Is(err, openpgp.ErrKeyring):
				if errors.Is(err, openpgp.ErrParams) || (!errors.Is(err, openpgp.ErrKeyringForm) && !errors.Is(err, openpgp.ErrKeyringPrimaries)) {
					t.Fatalf("an error of the wrong kind: %v", err)
				}
			case errors.Is(err, openpgp.ErrParams):
				if !hasDuplicate(want) {
					t.Fatalf("an ErrParams for a list that holds no duplicate: %v", err)
				}
			default:
				t.Fatalf("an error of no kind: %v", err)
			}
			checkText(t, "fuzz", err)
			return
		}
		if len(checked) != len(softSignatures(file)) {
			t.Fatalf("an accepted file of %d certifications made %d signature checks", len(softSignatures(file)), len(checked))
		}
		if len(keys) != len(want) {
			t.Fatalf("%d primaries for %d entries", len(keys), len(want))
		}
		var fps []string
		for i, k := range keys {
			if k == nil || k.Fingerprint() != want[i].Fingerprint || k.PublicKey() == nil || k.Created().IsZero() || k.Created().Unix() < 1 {
				t.Fatalf("primary %d is %v", i, k)
			}
			fps = append(fps, k.Fingerprint())
		}
		if got := ringFingerprints(t, file); !slices.Equal(got, fps) {
			t.Fatalf("go-crypto reads %v, ReadKeyring %v", got, fps)
		}
		// The oracle of the page, with the tests' own packet reader.
		tags, bodies, ok := softPackets(file)
		if !ok {
			t.Fatal("accepted bytes that are not whole packets")
		}
		var keyPkt []byte
		var uid string
		var bodiesSince [][]byte
		ps := splitPackets(t, file)
		certs, test, plain := 0, 0, 0
		for i, tag := range tags {
			switch tag {
			case tagPublicKey:
				certs++
				bodiesSince = nil
				keyPkt = ps[i].Raw
				if i+1 >= len(tags) || tags[i+1] != tagUserID || i+2 >= len(tags) || tags[i+2] != tagSignature {
					t.Fatalf("accepted a certificate whose packets after the key are not 13, 2: tags % d", tags)
				}
			case tagUserID:
				uid = string(bodies[i])
				if strings.Contains(uid, " (TEST ONLY) <") {
					test++
				} else {
					plain++
				}
			case tagSignature:
				checkAcceptedCertification(t, ps[i].Raw, keyPkt, uid)
				if slices.ContainsFunc(bodiesSince, func(b []byte) bool { return bytes.Equal(b, bodies[i]) }) {
					t.Fatal("accepted a certification that repeats another of its certificate")
				}
				bodiesSince = append(bodiesSince, bodies[i])
			default:
				t.Fatalf("accepted a packet of tag %d", tag)
			}
		}
		if certs != len(want) || (test > 0 && plain > 0) {
			t.Fatalf("accepted %d certificates for %d entries, with %d test and %d real user IDs", certs, len(want), test, plain)
		}
	})
}

// FuzzCheckCertification gives the one shared check any bytes in place of the certification of a
// fixed key. A success is one whole signature packet of the page's shape that verifies by the tests'
// own formula; the check is the same on a second call; nothing is shown that the packet held.
func FuzzCheckCertification(f *testing.F) {
	m := newKeyringPrimary(f, "A", true)
	key := m.keyPacket()
	f.Add(m.sig(f, ceremony, nil), int64(0))
	f.Add(m.cert(f)[len(key)+len(m.uidPacket()):], int64(0))
	f.Add(m.sig(f, ceremony, func(sp *sigSpec) { sp.LongLengths = true }), int64(0))
	f.Add(m.sig(f, ceremony, func(sp *sigSpec) { sp.OldHeader = true }), int64(0))
	f.Add(m.sig(f, ceremony, func(sp *sigSpec) { sp.Hashed = reverse(sp.Hashed) }), int64(0))
	f.Add(m.sig(f, ceremony, func(sp *sigSpec) { sp.Type = 0x10 }), int64(0))
	f.Add(m.sig(f, ceremony, func(sp *sigSpec) { sp.TagXOR = [2]byte{0, 1} }), int64(0))
	f.Add(m.sig(f, ceremony, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, extraSubs(29)...) }), int64(0))
	f.Add(m.sig(f, ceremony, func(sp *sigSpec) { sp.Trailing = []byte{0} }), int64(0))
	f.Add(m.sig(f, ceremony, nil), ceremony.Unix()+1)
	f.Add(m.sig(f, ceremony, nil), int64(-1))
	f.Add([]byte{0xC2, 0x00}, int64(0))
	f.Add([]byte{}, int64(0))
	f.Add(wrapLong(tagSignature, bytes.Repeat([]byte{0x01, 100}, 2000)), int64(0))
	f.Fuzz(func(t *testing.T, pkt []byte, notBefore int64) {
		at := m.at
		if notBefore != 0 {
			at = time.Unix(notBefore, 0).UTC()
		}
		before := bytes.Clone(pkt)
		// The inner function has no recover: a panic in it fails this target.
		c1, l1, err := openpgp.CheckCertificationBytesNoRecover(pkt, key, m.uid, at)
		if !bytes.Equal(pkt, before) {
			t.Fatal("the check changed its packet")
		}
		c2, l2, err2 := openpgp.CheckCertificationBytesNoRecover(pkt, key, m.uid, at)
		if (err == nil) != (err2 == nil) || !c1.Equal(c2) || l1 != l2 {
			t.Fatal("the check is not the same on a second call")
		}
		// The shared check with its net gives the same answer.
		c3, l3, err3 := openpgp.CheckCertificationBytes(pkt, key, m.uid, at)
		if (err == nil) != (err3 == nil) || (err != nil && err.Error() != err3.Error()) || !c1.Equal(c3) || l1 != l3 {
			t.Fatal("the shared check with its net does not give the answer of the inner function")
		}
		if err != nil {
			if !c1.IsZero() || l1 != 0 {
				t.Fatalf("a result with the error %v", err)
			}
			checkText(t, "fuzz", err)
			return
		}
		if c1.Before(at) {
			t.Fatalf("accepted a certification made at %v, before %v", c1, at)
		}
		checkAcceptedCertification(t, pkt, key, m.uid)
	})
}
