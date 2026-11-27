package openpgp_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// SigningBasis: the read-only description of what later signatures are made from.

func TestQASigningBasisIsTheSnapshotFieldByField(t *testing.T) {
	n := 0
	for _, f := range qaExports(t) {
		k, err := openpgp.ReadForeignKey(f.file)
		if err != nil {
			continue
		}
		n++
		if d := openpgp.BasisAgainstSnapshot(k); len(d) != 0 {
			t.Errorf("%s: the basis is not the snapshot: %v", f.name, d)
		}
		kc, err := qaReadCert(k.Certificate())
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		if !reflect.DeepEqual(k.SigningBasis(), kc.SigningBasis()) {
			t.Errorf("%s: the basis of the certificate is not the basis of the export:\n%+v\n%+v", f.name, k.SigningBasis(), kc.SigningBasis())
		}
		if d := openpgp.BasisAgainstSnapshot(kc); len(d) != 0 {
			t.Errorf("%s: the basis of the certificate is not its snapshot: %v", f.name, d)
		}
	}
	if n < 150 {
		t.Errorf("only %d keys", n)
	}
	// a key that nothing read has an empty basis
	var nilKey *openpgp.ForeignKey
	if !reflect.DeepEqual(nilKey.SigningBasis(), openpgp.ForeignBasis{}) || !reflect.DeepEqual((&openpgp.ForeignKey{}).SigningBasis(), openpgp.ForeignBasis{}) {
		t.Error("the basis of a key that nothing read is not empty")
	}
}

// What SigningBasis returns shares nothing with the key: every slice is changed in place, then emptied, and the
// key says the same when it is asked again.
func TestQASigningBasisSharesNothingWithTheKey(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, shape := range []string{"rich", "plain", "crafted"} {
			file := b.plain
			if shape == "crafted" && b.name != "ed25519" {
				continue // the writer of signatures here is the one of the Ed25519 template
			}
			switch shape {
			case "rich":
				file = fkRichOf(t, b, false, true).file
			case "crafted":
				// a direct-key source with preferences and dropped types, and a user ID with both
				w := fkWriter{b}
				file = qaFile(t, b, [][]byte{qaKeySig(t, w, 0x1F, 8, 1200, fkSubpacket(21, false, 8, 9), fkSubpacket(26, false, []byte("u")...))},
					qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 1000, fkSubpacket(11, false, 9), fkSubpacket(30, false, 1), fkSubpacket(20, false, qaPayload(20)...), fkSubpacket(12, false, qaPayload(12)...))}})
			}
			k := fkRead(t, file)
			want := k.SigningBasis()
			snap := openpgp.SnapshotOf(k)
			if shape == "crafted" && (len(want.DirectPrefs) != 1 || len(want.DirectDropped) != 1 || len(want.UserIDs[0].Prefs) != 2 || len(want.UserIDs[0].Dropped) != 2) {
				t.Fatalf("the crafted key has too little to alias: %+v", want)
			}
			if len(want.UserIDs) == 0 || (shape == "rich" && len(want.Subkeys) == 0) {
				t.Fatalf("%s: the basis has %d user IDs and %d subkeys", shape, len(want.UserIDs), len(want.Subkeys))
			}
			for round := 0; round < 2; round++ {
				got := k.SigningBasis()
				qaScramble(reflect.ValueOf(&got), 1)
				for i := range got.UserIDs {
					for j := range got.UserIDs[i].Prefs {
						clear(got.UserIDs[i].Prefs[j].Data)
					}
					clear(got.UserIDs[i].Dropped)
					got.UserIDs[i] = openpgp.ForeignBasisUserID{Text: "scribble"}
				}
				for j := range got.DirectPrefs {
					clear(got.DirectPrefs[j].Data)
				}
				clear(got.DirectDropped)
				for i := range got.Subkeys {
					got.Subkeys[i] = openpgp.ForeignBasisSubkey{Fingerprint: "scribble"}
				}
				got.UserIDs, got.Subkeys = got.UserIDs[:0], nil
				if again := k.SigningBasis(); !reflect.DeepEqual(again, want) {
					t.Fatalf("%s: the basis changed after a caller changed the one it was given", shape)
				}
				if !reflect.DeepEqual(openpgp.SnapshotOf(k), snap) {
					t.Fatalf("%s: the snapshot changed after a caller changed the basis", shape)
				}
			}
			// two calls give two bases that share no slice: an element of one is not an element of the other
			a, c := k.SigningBasis(), k.SigningBasis()
			if len(a.UserIDs) > 0 && &a.UserIDs[0] == &c.UserIDs[0] {
				t.Error("two bases share their list of user IDs")
			}
			if len(a.Subkeys) > 0 && &a.Subkeys[0] == &c.Subkeys[0] {
				t.Error("two bases share their list of subkeys")
			}
		}
	})
}

// The basis marks what a ceremony must show: the weak source, the tie, the text that a re-signing may cover, the
// primary user ID, and the algorithm of each subkey.
func TestQASigningBasisSaysWhatACeremonyMustShow(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	const A, B = "Alpha Person <alpha@example.org>", "Bravo\nPerson <bravo@example.org>"
	file := qaFile(t, b, nil,
		qaUserBlock{A, [][]byte{qaUserSig(t, w, A, 0x13, 8, 1000), qaUserSig(t, w, A, 0x13, 2, 1100)}},
		qaUserBlock{B, [][]byte{qaUserSig(t, w, B, 0x13, 8, 1000, fkSubpacket(25, false, 1)), qaUserSig(t, w, B, 0x13, 8, 1000, fkSubpacket(25, false, 1), fkSubpacket(27, false, 2))}})
	got := fkRead(t, file).SigningBasis()
	if len(got.UserIDs) != 2 {
		t.Fatalf("%+v", got)
	}
	a, bb := got.UserIDs[0], got.UserIDs[1] // sorted by text: "Alpha" before "Bravo"
	if a.Text != A || !a.Weak || !a.AnyStrong || a.Tied || !a.TextOK || a.IsPrimary {
		t.Errorf("the user ID with a SHA-1 source: %+v", a)
	}
	if bb.Text != B || bb.Weak || !bb.Tied || bb.TextOK || !bb.IsPrimary || !bb.Primary {
		t.Errorf("the user ID that is tied, has a text that may not be covered and is flagged: %+v", bb)
	}
	// a subkey: the algorithm is the one of its packet
	enc, _, _ := fkDonors(t)
	sb := fkRead(t, w.file(t, fkParts{subSigs: [][]byte{w.sign(t, "sub", 0x18, w.areas(1000, fkSubpacket(27, false, 0x0C)), nil, 8, sha256.New, enc[3].pub.Body)}})).SigningBasis().Subkeys
	if len(sb) != 1 || sb[0].Algorithm.ID != 18 || len(sb[0].Fingerprint) != 40 || sb[0].Fingerprint != strings.ToLower(sb[0].Fingerprint) {
		t.Errorf("the subkey of the basis: %+v", sb)
	}
	if _, err := hex.DecodeString(sb[0].Fingerprint); err != nil {
		t.Errorf("the fingerprint is not hexadecimal: %v", err)
	}
}

// ParseHeldDigest takes 64 lower-case hexadecimal digits and nothing else.
//
// That a HeldDigest cannot be made outside the package without ParseHeldDigest is a fact of the compiler, and no
// test says it: its one field is unexported, so another package can only write the zero value, which
// ReadForeignCertificate refuses.
func TestQAParseHeldDigest(t *testing.T) {
	good := strings.Repeat("ab", 32)
	d, err := openpgp.ParseHeldDigest(good)
	if err != nil || d.String() != good {
		t.Fatalf("the good digest: %v %q", err, d.String())
	}
	sum := sha256.Sum256([]byte("x"))
	if d, err := openpgp.ParseHeldDigest(hex.EncodeToString(sum[:])); err != nil || d.String() != hex.EncodeToString(sum[:]) {
		t.Errorf("the digest of a text: %v", err)
	}
	for name, text := range map[string]string{
		"empty":                   "",
		"upper case":              strings.ToUpper(good),
		"one upper-case digit":    "A" + good[1:],
		"63 digits":               good[:63],
		"65 digits":               good + "a",
		"a prefix":                "sha256:" + good,
		"a prefix of 0x":          "0x" + good[2:],
		"a space in front":        " " + good,
		"a space behind":          good + " ",
		"a line break behind":     good + "\n",
		"a space inside":          good[:32] + " " + good[33:],
		"a g":                     "g" + good[1:],
		"a non-ASCII digit":       "\u0661" + good[2:],
		"the zero digest":         strings.Repeat("0", 64),
		"a NUL":                   "\x00" + good[1:],
		"two digests":             good + good,
		"a colon between pairs":   strings.Repeat("ab:", 21) + "ab",
		"64 bytes of a wide rune": strings.Repeat("\u00e9", 32),
	} {
		d, err := openpgp.ParseHeldDigest(text)
		if err == nil || !errors.Is(err, openpgp.ErrParams) || d.String() != "" {
			t.Errorf("%s: %q: %v, %q", name, text, err, d.String())
			continue
		}
		if strings.Contains(err.Error(), "abab") {
			t.Errorf("%s: the text of the error holds the digest: %v", name, err)
		}
	}
	// the zero value is no digest: the reader refuses it before it looks at the certificate
	var zero openpgp.HeldDigest
	if zero.String() != "" {
		t.Errorf("the zero digest says %q", zero.String())
	}
	cert := fkRead(t, fkNamed(t, "ed25519").plain).Certificate()
	k, err := openpgp.ReadForeignCertificate(cert, zero)
	if k != nil || !errors.Is(err, openpgp.ErrParams) || errors.Is(err, openpgp.ErrForeignKey) {
		t.Errorf("the zero digest: %v", err)
	}
	// and for every input, so that it is no digest that a certificate is compared with
	for _, in := range [][]byte{nil, {1}, make([]byte, openpgp.MaxForeignKeyBytes+1)} {
		if _, err := openpgp.ReadForeignCertificate(in, zero); !errors.Is(err, openpgp.ErrParams) {
			t.Errorf("the zero digest and an input of %d bytes: %v", len(in), err)
		}
	}
}

// The certificate is copied before it is hashed and the copy is what is parsed. A slice that another goroutine
// changes during the call cannot give a key whose bytes are not the ones that were hashed: the outcome is the
// key of the original certificate, or the refusal of the digest, and never another refusal that a parse of
// changed bytes would give. The writer changes a byte of the caller's slice back and forth as fast as it goes.
//
// What this shows, and what it does not: the writer and the copy read and write the same memory, which is the
// caller's fault and which the race detector reports in the caller; so the test is skipped under the detector,
// which can only show that our own code makes no other access to the caller's slice than the one copy.
func TestQAACertificateThatChangesDuringTheReadIsNeverParsedAsOtherThanItWasHashed(t *testing.T) {
	if qaRaceEnabled {
		t.Skip("the caller's slice is written and read at once: the detector reports that, in the caller")
	}
	b := fkNamed(t, "ed25519")
	cert := fkRead(t, b.plain).Certificate()
	want := fkDigestOf(cert)
	in := bytes.Clone(cert)
	// the byte is the last of the signature of the user ID: a change of it is a signature that does not verify
	at := len(in) / 2
	stop, done := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			mu.Lock()
			in[at] ^= 0x40
			mu.Unlock()
		}
	}()
	ok, digest, other := 0, 0, 0
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		k, err := openpgp.ReadForeignCertificate(in, want)
		switch {
		case err == nil:
			if !bytes.Equal(k.Certificate(), cert) {
				t.Fatal("a key that is not the certificate that was hashed")
			}
			ok++
		case errors.Is(err, openpgp.ErrAdoptedCertificate) && strings.Contains(err.Error(), "SHA-256"):
			digest++
		default:
			other++
			t.Errorf("a refusal that is not the one of the digest: %v", err)
			if other > 3 {
				t.FailNow()
			}
		}
	}
	close(stop)
	<-done
	t.Logf("the caller's slice changed during %d reads: %d keys, %d refusals of the digest, %d other", ok+digest+other, ok, digest, other)
	if ok == 0 || digest == 0 {
		t.Errorf("the writer and the reader did not meet: %d keys, %d digests", ok, digest)
	}
}

// For each hashed subpacket type that exists, the source of a user ID and the direct-key source carry it, drop it
// or write it afresh: the whitelisted types (11, 21, 22, 23, 30, 39) are in Prefs with their exact bytes, once
// each and no longer than 32 octets; every other type that the rule drops is in Dropped, sorted, and its bytes
// are nowhere in the basis; the types that a later signature writes afresh (2, 9, 25, 27, 33) are in neither.
func TestQASigningBasisShowsWhatIsCarriedAndWhatIsDropped(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	marker := bytes.Repeat([]byte{0xE7}, 5)
	payload := func(typ byte) ([]byte, bool) { // the bytes, and whether they are distinctive enough to look for
		switch typ {
		case 6:
			return []byte("regex-ZQXWV$"), true
		case 12:
			return append([]byte{0x80, 22}, bytes.Repeat([]byte{0xAB}, 20)...), true
		case 16:
			return bytes.Repeat([]byte{0xCD}, 8), true
		case 20:
			name, value := "note-ZQXWV@example.org", "value-ZQXWV"
			return append(append([]byte{0x80, 0, 0, 0, 0, byte(len(name)), 0, byte(len(value))}, name...), value...), true
		case 24, 26, 28:
			return []byte("https://example.org/ZQXWV"), true
		case 10, 37, 100, 101, 110:
			return marker, true
		case 3, 4, 5, 7, 29, 31, 34, 35:
			return qaPayload(typ), false
		}
		return qaPayload(typ), false
	}
	rewritten := map[byte]bool{2: true, 9: true, 25: true, 27: true, 33: true}
	carried := map[byte]bool{11: true, 21: true, 22: true, 23: true, 30: true, 39: true}
	tried := 0
	for typ := byte(1); typ <= 127; typ++ {
		if typ == 2 || typ == 33 || (typ > 41 && typ != 63 && typ != 100 && typ != 101 && typ != 110 && typ != 127) {
			continue
		}
		data, distinctive := payload(typ)
		for _, size := range []string{"as it is", "33 octets", "twice"} {
			subs := [][]byte{fkSubpacket(typ, false, data...)}
			switch size {
			case "33 octets":
				if !carried[typ] {
					continue
				}
				data = bytes.Repeat([]byte{5}, 33)
				if typ == 39 {
					data = bytes.Repeat([]byte{5}, 34)
				}
				subs = [][]byte{fkSubpacket(typ, false, data...)}
			case "twice":
				if !carried[typ] {
					continue
				}
				subs = append(subs, fkSubpacket(typ, false, data...))
			}
			for _, where := range []string{"a user ID", "the direct-key signature"} {
				var file []byte
				good := qaUserSig(t, w, fkUser, 0x13, 8, 500)
				if where == "a user ID" {
					file = qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 1000, subs...)}})
				} else {
					file = qaFile(t, b, [][]byte{qaKeySig(t, w, 0x1F, 8, 1000, subs...)}, qaUserBlock{fkUser, [][]byte{good}})
				}
				k, err := openpgp.ReadForeignKey(file)
				if err != nil {
					continue // a signature that does not count with this subpacket: a malformed field
				}
				basis := k.SigningBasis()
				prefs, dropped := basis.UserIDs[0].Prefs, basis.UserIDs[0].Dropped
				if where != "a user ID" {
					prefs, dropped = basis.DirectPrefs, basis.DirectDropped
					if !basis.DirectHave {
						continue
					}
				}
				tried++
				name := fkItoa(int(typ)) + " " + size + " in " + where
				inPrefs := false
				for _, p := range prefs {
					if p.Type == typ {
						inPrefs = true
						if !bytes.Equal(p.Data, data) {
							t.Errorf("%s: the carried bytes are %x, want %x", name, p.Data, data)
						}
					}
					if !carried[p.Type] {
						t.Errorf("%s: the type %d is carried", name, p.Type)
					}
				}
				wantCarried := carried[typ] && size == "as it is" && len(data) <= 32
				if inPrefs != wantCarried {
					t.Errorf("%s: carried is %v, want %v", name, inPrefs, wantCarried)
				}
				inDropped := slices.Contains(dropped, typ)
				wantDropped := !rewritten[typ] && !wantCarried
				if inDropped != wantDropped {
					t.Errorf("%s: dropped is %v, want %v (dropped %v)", name, inDropped, wantDropped, dropped)
				}
				if !slices.IsSorted(dropped) || len(slices.Compact(slices.Clone(dropped))) != len(dropped) {
					t.Errorf("%s: the dropped types are not sorted and once each: %v", name, dropped)
				}
				if rewritten[typ] && (inPrefs || inDropped) {
					t.Errorf("%s: a type that is written afresh is shown", name)
				}
				// the bytes of what is dropped are nowhere in the basis, in any form
				if distinctive && !carried[typ] {
					probe := data
					if typ == 12 || typ == 16 {
						probe = bytes.Repeat([]byte{data[len(data)-1]}, 8)
					}
					if len(probe) > 12 {
						probe = probe[len(probe)-8:]
					}
					for _, s := range fkStrings(basis) {
						if bytes.Contains(s, probe) {
							t.Errorf("%s: the bytes of a dropped subpacket are in the basis: %q", name, s)
							break
						}
					}
				}
			}
		}
	}
	if tried < 100 {
		t.Errorf("only %d cases were taken by the reader", tried)
	}
}

// The key level of the basis is what the key says: its fingerprint, its algorithm and the SHA-256 of its certificate.
func TestQASigningBasisKeyLevel(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, b.plain)
		got := k.SigningBasis()
		sum := sha256.Sum256(k.Certificate())
		if got.Fingerprint != k.Primary.Fingerprint || !reflect.DeepEqual(got.Algorithm, k.Primary.Algorithm) || got.CertificateSHA256 != sum {
			t.Errorf("the key level of the basis: %+v", got)
		}
		if got.Fingerprint != strings.ToLower(got.Fingerprint) || len(got.Fingerprint) != 40 {
			t.Errorf("the fingerprint is %q", got.Fingerprint)
		}
		// a view that a caller edited is not what the basis says
		k.Primary.Fingerprint, k.Primary.Algorithm = "00", openpgp.ForeignAlgorithm{ID: 99}
		if again := k.SigningBasis(); again.Fingerprint != got.Fingerprint || !reflect.DeepEqual(again.Algorithm, got.Algorithm) {
			t.Errorf("an edit of the view changed the basis: %+v", again)
		}
		// the digest changes with the certificate, and it is the same for the key of the certificate
		kc, err := qaReadCert(k.Certificate())
		if err != nil || kc.SigningBasis().CertificateSHA256 != sum {
			t.Errorf("the digest of the basis of the certificate: %v", err)
		}
	})
}

// Key flags of more than one octet are marked (a re-signing writes one octet), and a carried preference whose
// source had the critical bit is listed in Dropped as well as in Prefs (the bit is lost when it is carried).
func TestQASigningBasisMarksLongFlagsAndALostCriticalBit(t *testing.T) {
	b := fkNamed(t, "ed25519")
	w := fkWriter{b}
	sp := fkSubpacket
	sources := map[string]func(subs ...[]byte) *openpgp.ForeignKey{
		"a user ID": func(subs ...[]byte) *openpgp.ForeignKey {
			return fkRead(t, qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 1000, subs...)}}))
		},
		"the direct-key signature": func(subs ...[]byte) *openpgp.ForeignKey {
			return fkRead(t, qaFile(t, b, [][]byte{qaKeySig(t, w, 0x1F, 8, 1000, subs...)}, qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 500)}}))
		},
	}
	view := func(where string, basis openpgp.ForeignBasis) (trunc bool, flags uint8, prefs []openpgp.ForeignBasisPref, dropped []uint8) {
		if where == "a user ID" {
			u := basis.UserIDs[0]
			return u.FlagsTruncated, u.KeyFlags, u.Prefs, u.Dropped
		}
		return basis.DirectFlagsTruncated, 0, basis.DirectPrefs, basis.DirectDropped
	}
	for where, read := range sources {
		for _, c := range []struct {
			name  string
			flags []byte
			trunc bool
		}{
			{"no flags", nil, false},
			{"flags of one octet", sp(27, false, 0x23), false},
			{"flags of two octets, the second zero", sp(27, false, 0x23, 0), true},
			{"flags of two octets, the second not zero", sp(27, false, 0x23, 0x04), true},
			{"flags of a hundred octets", sp(27, false, append([]byte{0x01}, make([]byte, 99)...)...), true},
			{"flags of one octet, critical", sp(27, true, 0x23), false},
		} {
			var subs [][]byte
			if c.flags != nil {
				subs = append(subs, c.flags)
			}
			trunc, flags, _, _ := view(where, read(subs...).SigningBasis())
			if trunc != c.trunc {
				t.Errorf("%s, %s: truncated is %v, want %v", where, c.name, trunc, c.trunc)
			}
			if where == "a user ID" && c.flags != nil && flags != c.flags[2] {
				t.Errorf("%s, %s: the first octet is %#x", where, c.name, flags)
			}
		}
		// each type of the list, with the critical bit and without
		for _, typ := range []byte{11, 21, 22, 23, 30, 39} {
			data := qaPayload(typ)
			for _, critical := range []bool{false, true} {
				k, err := openpgp.ReadForeignKey(qaSourceFile(t, b, where, sp(typ, critical, data...)))
				if err != nil {
					t.Logf("%s, type %d, critical %v: the reader does not count such a signature (%v)", where, typ, critical, err)
					continue
				}
				_, _, prefs, dropped := view(where, k.SigningBasis())
				carried := len(prefs) == 1 && prefs[0].Type == typ && bytes.Equal(prefs[0].Data, data)
				if !carried {
					t.Errorf("%s, type %d, critical %v: carried %+v", where, typ, critical, prefs)
				}
				if got := slices.Contains(dropped, typ); got != critical {
					t.Errorf("%s, type %d, critical %v: listed in Dropped is %v (%v)", where, typ, critical, got, dropped)
				}
			}
		}
	}
	// tie content: flags of two octets against one octet with the same first octet are not the same content
	k := fkRead(t, qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{
		qaUserSig(t, w, fkUser, 0x13, 8, 1000, sp(27, false, 0x03)),
		qaUserSig(t, w, fkUser, 0x13, 8, 1000, sp(27, false, 0x03, 0x00))}}))
	if u := k.SigningBasis().UserIDs[0]; !u.Tied {
		t.Errorf("flags of one and of two octets in one second are not tied: %+v", u)
	}
	// a carried type with and without the critical bit, in one second: tied
	k = fkRead(t, qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{
		qaUserSig(t, w, fkUser, 0x13, 8, 1000, sp(21, false, 8)),
		qaUserSig(t, w, fkUser, 0x13, 8, 1000, sp(21, true, 8))}}))
	if u := k.SigningBasis().UserIDs[0]; !u.Tied {
		t.Errorf("a preference with and without the critical bit in one second is not tied: %+v", u)
	}
	// both critical, the same content: not tied
	k = fkRead(t, qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{
		qaUserSig(t, w, fkUser, 0x13, 8, 1000, sp(21, true, 8)),
		qaUserSig(t, w, fkUser, 0x13, 8, 1000, sp(21, true, 8))}}))
	if u := k.SigningBasis().UserIDs[0]; u.Tied {
		t.Errorf("the same content twice is tied: %+v", u)
	}
}

// qaSourceFile is the file of the Ed25519 template whose user ID source or direct-key source carries the
// subpackets given.
func qaSourceFile(t testing.TB, b *fkBase, where string, subs ...[]byte) []byte {
	w := fkWriter{b}
	if where == "a user ID" {
		return qaFile(t, b, nil, qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 1000, subs...)}})
	}
	return qaFile(t, b, [][]byte{qaKeySig(t, w, 0x1F, 8, 1000, subs...)}, qaUserBlock{fkUser, [][]byte{qaUserSig(t, w, fkUser, 0x13, 8, 500)}})
}
