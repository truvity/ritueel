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

// The subpackets that the snapshot carries from the newest self-signature (six types, each once, at most 32
// octets), the way a signature that carries one of every type reads, the aliasing of the snapshot, and what
// the key flags and the primary flag are.

// qaPayload is a subpacket of the type, with contents that the standard allows for it.
func qaPayload(typ byte) []byte {
	fp := bytes.Repeat([]byte{0xAB}, 20)
	switch typ {
	case 3, 9:
		return fkU32(7 * 86400)
	case 4, 7, 25, 27, 30:
		return []byte{1}
	case 5:
		return []byte{1, 120}
	case 6:
		return []byte("example.org$")
	case 11, 21, 22:
		return []byte{9, 8, 7}
	case 23:
		return []byte{0x80}
	case 12:
		return append([]byte{0x80, 22}, fp...)
	case 16:
		return bytes.Repeat([]byte{0xCD}, 8)
	case 20:
		name, value := "note@example.org", "v"
		return slices.Concat([]byte{0x80, 0, 0, 0, 0, byte(len(name)), 0, byte(len(value))}, []byte(name), []byte(value))
	case 24, 26, 28:
		return []byte("https://example.org/x")
	case 29:
		return []byte{32, 'o', 'k'}
	case 31:
		return append([]byte{22, 8}, bytes.Repeat([]byte{1}, 32)...)
	case 33, 35:
		return append([]byte{4}, fp...)
	case 34:
		return []byte{2, 7}
	case 39:
		return []byte{2, 9, 2, 7}
	}
	return []byte{1, 2, 3}
}

// qaCarriedBy reads a file whose newest self-signature carries the subpackets and returns the types that the
// snapshot carries, or false if the reader does not take the signature.
func qaCarriedBy(t testing.TB, w fkWriter, subs ...[]byte) ([]openpgp.SnapPref, bool) {
	t.Helper()
	b := w.b
	file := qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 1000, subs...)}})
	k, err := openpgp.ReadForeignKey(file)
	if err != nil {
		return nil, false
	}
	users := openpgp.SnapshotUsers(k)
	if len(users) != 1 {
		t.Fatalf("%d user IDs", len(users))
	}
	return users[0].Prefs, true
}

func TestQASnapshotCarriesOnlyTheSixTypesForEveryTypeThatExists(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	carried := map[byte]bool{11: true, 21: true, 22: true, 23: true, 30: true, 39: true}
	var types []byte
	for typ := byte(1); typ <= 41; typ++ {
		types = append(types, typ)
	}
	types = append(types, 63, 100, 101, 110, 127)
	taken := 0
	for _, typ := range types {
		if typ == 2 || typ == 33 {
			// the creation time and the issuer fingerprint are the signature's own, once each
			continue
		}
		for _, critical := range []bool{false, true} {
			for _, payload := range [][]byte{qaPayload(typ), nil, bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{5}, 33)} {
				got, ok := qaCarriedBy(t, w, fkSubpacket(typ, critical, payload...))
				if !ok {
					continue // a signature that does not count (a malformed field, a critical type that is not understood)
				}
				taken++
				want := carried[typ] && len(payload) <= 32
				switch {
				case want && (len(got) != 1 || got[0].Type != typ || !bytes.Equal(got[0].Data, payload)):
					t.Errorf("type %d (critical %v, %d octets): carried %+v, want it carried", typ, critical, len(payload), got)
				case !want && len(got) != 0:
					t.Errorf("type %d (critical %v, %d octets): carried %+v, want nothing", typ, critical, len(payload), got)
				}
			}
		}
	}
	t.Logf("%d signatures with one subpacket of a type were taken by the reader", taken)
	if taken < 150 {
		t.Errorf("only %d of the signatures were taken: the table of payloads is wrong", taken)
	}
	// the whitelisted types again: twice is dropped whatever the order, and one is kept beside the other
	for typ := range carried {
		one := fkSubpacket(typ, false, qaPayload(typ)...)
		var otherData, otherCritical = []byte{1}, []byte{7}
		if typ == 39 {
			otherData, otherCritical = []byte{2, 13}, []byte{2, 7}
		}
		other := fkSubpacket(typ, false, otherData...)
		if got, ok := qaCarriedBy(t, w, one, other); !ok || len(got) != 0 {
			t.Errorf("type %d twice: %+v taken=%v", typ, got, ok)
		}
		if got, ok := qaCarriedBy(t, w, one, fkSubpacket(typ, typ != 39, otherCritical...)); !ok || len(got) != 0 {
			t.Errorf("type %d twice, one critical: %+v taken=%v", typ, got, ok)
		}
		// the same type in the unhashed area is not the signature's: it is not carried, nor does it drop the one in the hashed area
		file := qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{w.sign(t, "user", 0x13, w.areas(1000, one), fkSubpacket(typ, false, 4, 4), 8, sha256.New, []byte(fkUser))}})
		k := fkRead(t, file)
		if u := openpgp.SnapshotUsers(k)[0]; len(u.Prefs) != 1 || !bytes.Equal(u.Prefs[0].Data, qaPayload(typ)) {
			t.Errorf("type %d in both areas: %+v", typ, u.Prefs)
		}
		file = qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{w.sign(t, "user", 0x13, w.areas(1000), fkSubpacket(typ, false, 4, 4), 8, sha256.New, []byte(fkUser))}})
		if u := openpgp.SnapshotUsers(fkRead(t, file))[0]; len(u.Prefs) != 0 {
			t.Errorf("type %d in the unhashed area only: %+v", typ, u.Prefs)
		}
	}
	// every type at once: the six, in the order of the whitelist, whatever the order in the file
	var all [][]byte
	for _, typ := range []byte{39, 30, 23, 22, 21, 11} {
		// the type 39 is one that go-crypto does not know: marked critical it would stop the signature from counting
		all = append(all, fkSubpacket(typ, typ != 39, qaPayload(typ)...))
	}
	if _, ok := qaCarriedBy(t, w, all...); !ok {
		t.Fatal("the signature with the six types is not taken")
	}
	// the others that go-crypto and the reader take beside them, one by one
	var left []byte
	for _, typ := range []byte{26, 28, 24, 20, 12, 31, 34, 35, 3, 4, 5, 6, 7, 10, 37, 100} {
		try := append(slices.Clone(all), fkSubpacket(typ, false, qaPayload(typ)...))
		if _, ok := qaCarriedBy(t, w, try...); ok {
			all = try
		} else {
			left = append(left, typ)
		}
	}
	t.Logf("subpackets of the types %v are not taken by the reader beside the others", left)
	got, ok := qaCarriedBy(t, w, all...)
	if !ok {
		t.Fatal("the signature with every type is not taken")
	}
	var order []byte
	for _, p := range got {
		order = append(order, p.Type)
	}
	if !bytes.Equal(order, []byte{11, 21, 22, 23, 30, 39}) {
		t.Errorf("the carried types are %v, want 11 21 22 23 30 39", order)
	}
}

// The key flags are the first octet of the subpacket of the newest signature, the primary mark is the
// subpacket read as a boolean, and a signature with either field twice, or too short, does not count.
func TestQASnapshotKeyFlagsAndThePrimaryMark(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	sp := fkSubpacket
	read := func(subs ...[]byte) (openpgp.SnapUser, bool) {
		file := qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 1000, subs...)}})
		k, err := openpgp.ReadForeignKey(file)
		if err != nil {
			return openpgp.SnapUser{}, false
		}
		return openpgp.SnapshotUsers(k)[0], true
	}
	for _, c := range []struct {
		name    string
		subs    [][]byte
		ok      bool
		flags   uint8
		primary bool
	}{
		{"flags of one octet", [][]byte{sp(27, false, 0x23)}, true, 0x23, false},
		{"flags of two octets: the first is read", [][]byte{sp(27, false, 0x03, 0x04)}, true, 0x03, false},
		{"flags of a hundred octets", [][]byte{sp(27, false, append([]byte{0x01}, make([]byte, 99)...)...)}, true, 0x01, false},
		{"no flags", nil, true, 0, false},
		{"flags with no octet", [][]byte{sp(27, false)}, false, 0, false},
		{"flags twice", [][]byte{sp(27, false, 1), sp(27, false, 1)}, false, 0, false},
		{"flags marked critical", [][]byte{sp(27, true, 0x03)}, true, 0x03, false},
		{"primary 1", [][]byte{sp(25, false, 1)}, true, 0, true},
		{"primary 0", [][]byte{sp(25, false, 0)}, true, 0, false},
		{"primary 2", [][]byte{sp(25, false, 2)}, true, 0, true},
		{"primary with two octets", [][]byte{sp(25, false, 1, 1)}, false, 0, false},
		{"primary with no octet", [][]byte{sp(25, false)}, false, 0, false},
		{"primary twice", [][]byte{sp(25, false, 1), sp(25, false, 1)}, false, 0, false},
		{"a key expiration twice", [][]byte{sp(9, true, fkU32(5)...), sp(9, true, fkU32(5)...)}, false, 0, false},
		{"a key expiration of three octets", [][]byte{sp(9, true, 0, 0, 5)}, false, 0, false},
	} {
		u, ok := read(c.subs...)
		if ok != c.ok {
			t.Errorf("%s: taken=%v, want %v", c.name, ok, c.ok)
			continue
		}
		if ok && (u.Flags != c.flags || u.Primary != c.primary) {
			t.Errorf("%s: flags %#x primary %v, want %#x and %v", c.name, u.Flags, u.Primary, c.flags, c.primary)
		}
	}
	// the flags of a direct-key signature are not those of the user ID
	file := qaFile(t, b, [][]byte{qaKeySig(t, w, 0x1F, 8, 1100, sp(27, false, 0x02))}, qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 1000, sp(27, false, 0x01))}})
	if u := openpgp.SnapshotUsers(fkRead(t, file))[0]; u.Flags != 1 {
		t.Errorf("the flags of the user ID with a newer direct-key signature: %#x", u.Flags)
	}
}

// qaScramble changes every exported field of a value that it can: strings, numbers, booleans and times are
// replaced, the elements of every slice are scrambled in place, then the slices are emptied and cut.
func qaScramble(v reflect.Value, deep int) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			qaScramble(v.Elem(), deep)
		}
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			if v.CanSet() {
				v.Set(reflect.ValueOf(time.Unix(42, 0)))
			}
			return
		}
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				qaScramble(v.Field(i), deep)
			}
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString("scrambled " + v.String())
		}
	case reflect.Bool:
		if v.CanSet() {
			v.SetBool(!v.Bool())
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.CanSet() {
			v.SetInt(v.Int() + 1)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.CanSet() {
			v.SetUint(v.Uint() ^ 0x55)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			qaScramble(v.Index(i), deep)
		}
		if deep > 1 && v.CanSet() {
			// grow into the spare room and then drop the slice
			v.Set(reflect.AppendSlice(v.Slice(0, 0), v.Slice(0, v.Len())))
			v.Set(reflect.Zero(v.Type()))
		}
	}
}

// What a caller does to the view of a key, field by field, changes nothing of the snapshot, for a key read from
// an export and for one read from a certificate; and what a caller does to the bytes it gave changes nothing
// either.
func TestQASnapshotIsNotReachedByTheView(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, shape := range []string{"rich", "plain"} {
			file := b.plain
			if shape == "rich" {
				file = fkRichOf(t, b, false, true).file
			}
			for _, door := range []string{"export", "certificate"} {
				input := bytes.Clone(file)
				var k *openpgp.ForeignKey
				var err error
				if door == "export" {
					k, err = openpgp.ReadForeignKey(input)
				} else {
					input = fkRead(t, file).Certificate()
					k, err = openpgp.ReadForeignCertificate(input)
				}
				if err != nil {
					t.Fatal(err)
				}
				ref := fkRead(t, file)
				if door == "certificate" {
					ref, _ = openpgp.ReadForeignCertificate(ref.Certificate())
				}
				want := openpgp.SnapshotOf(ref)
				if !reflect.DeepEqual(want, openpgp.SnapshotOf(k)) {
					t.Fatalf("%s: two reads of one input give two snapshots", door)
				}
				// the rich file holds a key revocation: no issuer is made of it
				var a *openpgp.AdoptedIssuer
				if !openpgp.SnapshotKey(k).Revoked {
					if a, err = openpgp.NewAdoptedIssuer(k, fkStdSigner(t, b)); err != nil {
						t.Fatalf("%s: %v", door, err)
					}
				}
				// the bytes that the caller gave
				clear(input)
				if !reflect.DeepEqual(want, openpgp.SnapshotOf(k)) {
					t.Errorf("%s: clearing the input changed the snapshot", door)
				}
				// the view, in place and then emptied; the copy of the certificate that the key hands out
				for _, deep := range []int{1, 2} {
					qaScramble(reflect.ValueOf(k), deep)
					c := k.Certificate()
					clear(c)
					if !reflect.DeepEqual(want, openpgp.SnapshotOf(k)) {
						t.Errorf("%s: scrambling the view (pass %d) changed the snapshot", door, deep)
					}
				}
				// the snapshot is what the issuer signs with: the view of a scrambled key is nothing to it
				if a == nil {
					continue
				}
				at := fkEpoch.Add(24 * time.Hour)
				dks, err := openpgp.DirectKeySignatureFor(nil, a, at)
				if err != nil {
					t.Fatalf("%s: %v", door, err)
				}
				m := qaNew(t, b)
				m.check(t, dks, 0x1F, at, m.keyData())
				// a key whose view was scrambled still makes an issuer
				if _, err := openpgp.NewAdoptedIssuer(k, fkStdSigner(t, b)); err != nil {
					t.Errorf("%s: an issuer of a key whose view was scrambled: %v", door, err)
				}
			}
		}
	})
}

// The critical bit is not carried: a preference that a later signature repeats is advice, and a reader that
// does not know its type should skip it, not refuse the signature.
func TestQASnapshotDropsTheCriticalBitOfWhatItCarries(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	sp := fkSubpacket
	file := qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 1000,
		sp(11, true, 9, 8), sp(21, true, 8), sp(22, true, 2), sp(23, true, 0x80), sp(30, true, 1), sp(39, false, 2, 9))}})
	k := fkRead(t, file)
	prefs := openpgp.SnapshotUsers(k)[0].Prefs
	bits := openpgp.SnapshotCriticalBits(k)
	if len(prefs) != 6 || len(bits) != 1 || len(bits[0]) != 6 {
		t.Fatalf("the snapshot carries %d subpackets (%v)", len(prefs), bits)
	}
	for i, c := range bits[0] {
		if c {
			t.Errorf("the carried subpacket of type %d is critical", prefs[i].Type)
		}
	}
	// the same key read from its certificate
	kc, err := openpgp.ReadForeignCertificate(k.Certificate())
	if err != nil || !reflect.DeepEqual(openpgp.SnapshotCriticalBits(kc), bits) {
		t.Errorf("the critical bits of the certificate: %v", err)
	}
}
