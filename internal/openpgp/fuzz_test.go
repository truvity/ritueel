package openpgp_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/openpgp"
)

// FuzzBindSubkey gives BindSubkey any subkey packet and any back-signature. A request that is
// refused must be an ErrRequest with no bytes; one that is accepted must come back as the subkey
// packet and a binding that the tests' own check verifies. The target starts no program.
func FuzzBindSubkey(f *testing.F) {
	s, b, m := bindFixture(f)
	f.Add(b.Subkey, b.BackSig)
	f.Add(wrapLong(tagSubkey, m.body()), b.BackSig)
	f.Add(b.Subkey, []byte{})
	// The shapes that a strict reader refuses and the builder must refuse too: the mutations start there.
	for _, tweak := range []func(*sigSpec){
		func(sp *sigSpec) { sp.Trailing = []byte{0xAA, 0xBB, 0xCC} },
		func(sp *sigSpec) { sp.Hashed[0].Data = u32(4102444800) },
		func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 3, Data: u32(1)}) },
		func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sub{Type: 3, Data: u32(1)}) },
		func(sp *sigSpec) { sp.TagXOR = [2]byte{1, 1} },
		func(sp *sigSpec) { sp.Hashed[0].Data = u32(uint32(ceremony.Unix())) },
		func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 100, Data: []byte{1, 2, 3}}) },
		func(sp *sigSpec) {
			sp.Hashed = append(sp.Hashed, sub{Type: 20, Critical: true, Data: append([]byte{0x80, 0, 0, 0, 0, 1, 0, 1}, 'n', 'v')})
		},
		func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sub{Type: 99, Critical: true, Data: []byte{1, 2}})
		},
		func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sub{Type: 9, Data: []byte{1}}) },
		func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 23, Critical: true, Data: []byte{0x80}}) },
		func(sp *sigSpec) { sp.Hashed[1].Critical = true },
		func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sp.Hashed[1]) },
		func(sp *sigSpec) { sp.LongLengths = true },
		func(sp *sigSpec) { sp.OldHeader = true },
	} {
		f.Add(b.Subkey, backSig(f, m.Key, m.Created, m.Primary, m.PrimaryAt, tweak))
	}
	f.Add([]byte{}, b.BackSig)
	f.Add(b.BackSig, b.Subkey)
	for _, name := range []string{"pgp-software-valid", "pgp-backsig-no-key-id", "pgp-ed25519"} {
		ps := splitPackets(f, vector(f, "requests", name+".subkey.pgp"))
		if len(ps) > 1 {
			f.Add(ps[0].Raw, ps[1].Raw)
		}
	}
	f.Fuzz(func(t *testing.T, subkey, backsig []byte) {
		before := s.calls
		p := b
		p.Subkey, p.BackSig = bytes.Clone(subkey), bytes.Clone(backsig)
		out, err := openpgp.BindSubkey(rand.Reader, p)
		if err != nil {
			if out != nil {
				t.Fatalf("%d bytes with the error %v", len(out), err)
			}
			if !errors.Is(err, openpgp.ErrRequest) {
				t.Fatalf("a request with good parameters failed with %v, want ErrRequest", err)
			}
			if s.calls != before {
				t.Fatal("the signer was asked for a request that was refused")
			}
			return
		}
		ps := splitPackets(t, out)
		if len(ps) != 2 || ps[0].Tag != tagSubkey || ps[1].Tag != tagSignature || !bytes.Equal(ps[0].Raw, subkey) {
			t.Fatalf("the answer has tags % d and does not start with the subkey as sent", tags(ps))
		}
		sig := parseSig(t, ps[1].Body)
		if !bytes.Equal(find(t, sig.Unhashed, 32).Data, splitPackets(t, backsig)[0].Body) {
			t.Fatal("the embedded signature is not the back-signature as sent")
		}
		if !pageAcceptsBackSig(t, &s.key.PublicKey, created, subkey, backsig) {
			t.Fatal("a back-signature was accepted that the independent check of the page refuses")
		}
		// What a strict reader needs of an accepted back-signature: the packet ends after the two
		// numbers (parseSig fails on a byte more), the creation time is one, between the creation of the
		// subkey and the ceremony, the shape of the page, and the whole unhashed area of the binding is
		// read by gpgv.
		back := parseSig(t, splitPackets(t, backsig)[0].Body)
		at := find(t, back.Hashed, 2).Data
		if len(at) != 4 {
			t.Fatalf("a creation time of %d bytes was accepted", len(at))
		}
		made := time.Unix(int64(binary.BigEndian.Uint32(at)), 0)
		if made.After(ceremony) || made.Before(time.Unix(int64(binary.BigEndian.Uint32(splitPackets(t, subkey)[0].Body[1:5])), 0)) {
			t.Fatalf("a back-signature made at %v was accepted", made)
		}
		// The exact shape of the page: the creation time and the issuer fingerprint in the hashed
		// area, the issuer key ID in the unhashed area, nothing else and no critical bit.
		if got := types(back.Hashed); !bytes.Equal(got, []byte{2, 33}) && !bytes.Equal(got, []byte{33, 2}) {
			t.Fatalf("a back-signature with the hashed subpackets % d was accepted", got)
		}
		if got := types(back.Unhashed); !bytes.Equal(got, []byte{16}) {
			t.Fatalf("a back-signature with the unhashed subpackets % d was accepted", got)
		}
		if c := append(critical(back.Hashed), critical(back.Unhashed)...); len(c) != 0 {
			t.Fatalf("a back-signature with the critical bit on types % d was accepted", c)
		}
		if len(find(t, back.Hashed, 33).Data) != 21 || len(find(t, back.Unhashed, 16).Data) != 8 {
			t.Fatal("a back-signature with an issuer of another length was accepted")
		}
		if len(sig.UnhashedRaw) > 10000 {
			t.Fatalf("a binding with an unhashed area of %d bytes was returned; gpgv reads no more than 10000", len(sig.UnhashedRaw))
		}
	})
}

// FuzzUserID gives NewPrimary any user ID. When it accepts one, the user ID packet holds exactly
// that text, and the text is of the form of the page: printable ASCII only, "<name> Release Root
// <label> [(TEST ONLY) ]<address>", with the angle brackets of the address and no other.
func FuzzUserID(f *testing.F) {
	f.Add(exampleUserID(true))
	f.Add(exampleUserID(false))
	f.Add("a\nb")
	f.Add("a\r\nb")
	f.Add("a\u2028b")
	f.Add("")
	f.Add("x <a@b> Release Root A <c@d>")
	f.Add("Acme Release Root A <a@b>")
	f.Add("Acme Release Root AB <a@b>")
	f.Add("Acme  Release Root A <a@b>")
	f.Add("Acme Release Root A <a@@b>")
	f.Fuzz(func(t *testing.T, id string) {
		s := newSigner(t)
		p := s.params()
		p.UserID = id
		cert, err := openpgp.NewPrimary(rand.Reader, p)
		if err != nil {
			if cert != nil || !errors.Is(err, openpgp.ErrParams) {
				t.Fatalf("%d bytes with the error %v", len(cert), err)
			}
			if s.calls != 0 {
				t.Fatal("the signer was asked for a user ID that was refused")
			}
			return
		}
		ps := splitPackets(t, cert)
		if string(ps[1].Body) != id {
			t.Fatal("the user ID packet does not hold the text given")
		}
		if len(id) > 1024 {
			t.Fatalf("a user ID of %d bytes was accepted", len(id))
		}
		for i := 0; i < len(id); i++ {
			if id[i] < 0x20 || id[i] > 0x7E {
				t.Fatalf("a user ID with the byte %#x was accepted", id[i])
			}
		}
		if strings.Count(id, "<") != 1 || strings.Count(id, ">") != 1 || !strings.HasSuffix(id, ">") || strings.Count(id, "@") != 1 {
			t.Fatalf("a user ID that is not of the form of the page was accepted: %q", id)
		}
		if strings.Contains(id, "  ") || strings.HasPrefix(id, " ") {
			t.Fatalf("a user ID with a space out of place was accepted: %q", id)
		}
		if !strings.Contains(id, " Release Root ") {
			t.Fatalf("a user ID without the words of the page was accepted: %q", id)
		}
	})
}

// FuzzUserIDParts gives UserID any three parts. When it makes a text, the text is the three parts in
// the form of the page, and NewPrimary takes it; when it does not, the error is an ErrParams and
// there is no text.
func FuzzUserIDParts(f *testing.F) {
	f.Add("Example Test", "A", "release@example.org", true)
	f.Add("Acme", "B", "a@b", false)
	f.Add("", "A", "a@b", false)
	f.Add("Acme", "", "a@b", false)
	f.Add("Acme", "A", "", false)
	f.Add("a <b> c", "A", "a@b", true)
	f.Add("Acme", "A>", "a@b", true)
	f.Add("Acme", "A", "a@b@c", true)
	f.Add("Acme", "A", strings.Repeat("a", 1100)+"@b", true)
	f.Fuzz(func(t *testing.T, name, label, address string, test bool) {
		id, err := openpgp.UserID(name, label, address, test)
		if err != nil {
			if id != "" || !errors.Is(err, openpgp.ErrParams) {
				t.Fatalf("%q with the error %v", id, err)
			}
			return
		}
		want := name + " Release Root " + label
		if test {
			want += " (TEST ONLY)"
		}
		want += " <" + address + ">"
		if id != want {
			t.Fatalf("UserID = %q, want %q", id, want)
		}
		if !utf8.ValidString(id) || strings.ContainsAny(name+label, "<>") || strings.Count(address, "@") != 1 || strings.ContainsAny(address, "<> ") {
			t.Fatalf("a text was made of parts that break the rules: %q", id)
		}
		s := newSigner(t)
		p := s.params()
		p.UserID = id
		if _, err := openpgp.NewPrimary(rand.Reader, p); err != nil {
			t.Fatalf("NewPrimary refuses what UserID made (%d bytes): %v", len(id), err)
		}
	})
}

// FuzzFingerprint gives Fingerprint any time. It never panics; when it answers, the answer is 40
// lower-case digits and there is no error, and when it does not, there is an ErrParams and no text.
func FuzzFingerprint(f *testing.F) {
	f.Add(int64(1767225600), int64(0))
	f.Add(int64(0), int64(0))
	f.Add(int64(-1), int64(0))
	f.Add(int64(1<<32-1), int64(0))
	f.Add(int64(1<<32), int64(0))
	f.Add(int64(1767225600), int64(1))
	k := genKey(f)
	f.Fuzz(func(t *testing.T, sec, nsec int64) {
		got, err := openpgp.Fingerprint(&k.PublicKey, time.Unix(sec, nsec))
		if err != nil {
			if got != "" || !errors.Is(err, openpgp.ErrParams) {
				t.Fatalf("%q with the error %v", got, err)
			}
			return
		}
		if len(got) != 40 || got != strings.ToLower(got) || nsecOf(sec, nsec) != 0 {
			t.Fatalf("Fingerprint = %q for %d s and %d ns", got, sec, nsec)
		}
	})
}

// nsecOf is the nanosecond part of the time, as time.Unix normalises it.
func nsecOf(sec, nsec int64) int { return time.Unix(sec, nsec).Nanosecond() }
