package openpgp_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// The three readers of a subkey request read bytes that a requester sent. These targets give them
// anything and check what has to hold when they accept and when they refuse. None of them starts a
// program or reads a path; the seeds are the vector files.

// FuzzSplitSubkeyFile gives SplitSubkeyFile any file and any bound. A file that is refused returns
// no bytes; a file that is accepted comes back as whole packets, in order, which joined are the file,
// the first of them a Public-Subkey packet, at most the bound of them after it, all of them copies.
func FuzzSplitSubkeyFile(f *testing.F) {
	for _, v := range vectorSubkeyFiles {
		f.Add(subkeyFile(f, v.name), 16)
	}
	m := newSubkey(f, &genKey(f).PublicKey, created, subAt)
	f.Add(m.Packet, 0)
	f.Add(append(bytes.Clone(m.Packet), m.BackSig...), 1)
	f.Add(append(bytes.Clone(m.Packet), m.BackSig...), 0)
	f.Add(append(bytes.Clone(m.Packet), 0xC2, 0xE0, 1), 16)
	f.Add(append(bytes.Clone(m.Packet), 0x8B, 1, 2), 16)
	f.Add(oldHeader(tagSubkey, m.body()), 2)
	f.Add([]byte{}, 16)
	f.Add(m.Packet, -1)
	f.Fuzz(func(t *testing.T, file []byte, maxSignatures int) {
		in := bytes.Clone(file)
		subkey, sigs, err := openpgp.SplitSubkeyFile(file, maxSignatures)
		if !bytes.Equal(in, file) {
			t.Fatal("the file was changed")
		}
		if maxSignatures < 0 {
			if !errors.Is(err, openpgp.ErrParams) || errors.Is(err, openpgp.ErrRequest) || subkey != nil || sigs != nil {
				t.Fatalf("a bound of %d: error %v, %d bytes, %d packets, want an ErrParams and nothing", maxSignatures, err, len(subkey), len(sigs))
			}
			return
		}
		if err != nil {
			if subkey != nil || sigs != nil {
				t.Fatalf("bytes came back with the error %v", err)
			}
			if !isRequestError(err, openpgp.ErrForm) {
				t.Fatalf("error %v is not an ErrForm", err)
			}
			return
		}
		if sigs == nil || len(sigs) > maxSignatures {
			t.Fatalf("%d packets after the subkey for the bound %d (nil: %v)", len(sigs), maxSignatures, sigs == nil)
		}
		ps := splitPackets(t, file)
		if len(ps) != 1+len(sigs) || ps[0].Tag != tagSubkey {
			t.Fatalf("the file holds %d packets and the first has tag %d; the split gave %d after the subkey", len(ps), ps[0].Tag, len(sigs))
		}
		if !bytes.Equal(subkey, ps[0].Raw) {
			t.Fatal("the subkey is not the first packet")
		}
		whole := bytes.Clone(subkey)
		for i, s := range sigs {
			if !bytes.Equal(s, ps[i+1].Raw) {
				t.Fatalf("packet %d is not the packet of the file at that place", i+1)
			}
			whole = append(whole, s...)
		}
		if !bytes.Equal(whole, file) {
			t.Fatal("the packets, joined, are not the file")
		}
		for _, b := range append([][]byte{subkey}, sigs...) {
			for i := range b {
				b[i] ^= 0xFF
			}
		}
		if !bytes.Equal(in, file) {
			t.Fatal("changing the returned byte lists changed the file")
		}
	})
}

// FuzzReadSubkey gives ReadSubkey any packet. A refusal is an ErrForm or an ErrAlgorithm, each an
// ErrRequest, with no key; an acceptance is one whole Public-Subkey packet of the profile whose
// fingerprint is the SHA-1 of the hash prefix and the body (computed here), whose creation time and
// point are the ones in the body, and which reads the same in the shortest form of its header.
func FuzzReadSubkey(f *testing.F) {
	for _, v := range vectorSubkeyFiles {
		f.Add(splitPackets(f, subkeyFile(f, v.name))[0].Raw)
	}
	k := genKey(f)
	body := keyBody(&k.PublicKey, subAt)
	for _, pkt := range [][]byte{
		wrap(tagSubkey, body), oldHeader(tagSubkey, body), wrapLong(tagSubkey, body),
		wrap(tagPublicKey, body), wrap(tagSubkey, bodyWith(body, setByte(0, 6))), wrap(tagSubkey, bodyWith(body, setByte(5, 22))),
		wrap(tagSubkey, bodyWith(body, withOID(oidP521))), wrap(tagSubkey, append(bytes.Clone(body), 0)),
		wrap(tagSubkey, body[:13]), wrap(tagSubkey, bodyWith(body, func(b []byte) []byte { b[1], b[2], b[3], b[4] = 0, 0, 0, 0; return b })),
		append(wrap(tagSubkey, body), 0), {},
	} {
		f.Add(pkt)
	}
	f.Fuzz(func(t *testing.T, pkt []byte) {
		in := bytes.Clone(pkt)
		sub, err := openpgp.ReadSubkey(pkt)
		if !bytes.Equal(in, pkt) {
			t.Fatal("the packet was changed")
		}
		if err != nil {
			if sub != nil {
				t.Fatal("a Subkey came back with the error")
			}
			if !isRequestError(err, openpgp.ErrForm) && !isRequestError(err, openpgp.ErrAlgorithm) {
				t.Fatalf("error %v is neither an ErrForm nor an ErrAlgorithm", err)
			}
			if errors.Is(err, openpgp.ErrForm) && errors.Is(err, openpgp.ErrAlgorithm) {
				t.Fatalf("error %v is of both kinds", err)
			}
			return
		}
		ps := splitPackets(t, pkt)
		if len(ps) != 1 || ps[0].Tag != tagSubkey {
			t.Fatalf("an accepted input of %d packets, the first of tag %d", len(ps), ps[0].Tag)
		}
		b := ps[0].Body
		if len(b) != 111 || b[0] != 4 || b[5] != 19 || !bytes.Equal(b[6:12], []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x22}) {
			t.Fatalf("a body of %d bytes, version %d, algorithm %d was accepted", len(b), b[0], b[5])
		}
		if got, want := sub.Fingerprint(), fingerprintOfBody(b); got != want {
			t.Fatalf("Fingerprint = %s, the standard gives %s", got, want)
		}
		secs := int64(binary.BigEndian.Uint32(b[1:5]))
		if secs < 1 || sub.Created().Unix() != secs || sub.Created().Location() != time.UTC {
			t.Fatalf("Created = %v for a time of %d", sub.Created(), secs)
		}
		if !bytes.Equal(point(sub.PublicKey()), b[len(b)-97:]) {
			t.Fatal("PublicKey is not the point of the packet")
		}
		again, err := openpgp.ReadSubkey(wrap(tagSubkey, b))
		if err != nil || again.Fingerprint() != sub.Fingerprint() {
			t.Fatalf("the same body in the shortest header: %v", err)
		}
	})
}

// FuzzVerifyBackSignature gives VerifyBackSignature any signature packet, any subkey packet that
// ReadSubkey accepts and any ceremony time. The primary is the first vector primary. A time outside
// the years 1970 to 2106 is an ErrParams and nothing else is; a refusal is an ErrBackSignature; an
// acceptance is one signature packet that the independent reader of the page (pageAcceptsBackSig)
// accepts too, with the shape of the page and a creation time between the subkey and the ceremony.
func FuzzVerifyBackSignature(f *testing.F) {
	for _, v := range vectorSubkeyFiles {
		ps := splitPackets(f, subkeyFile(f, v.name))
		for _, s := range ps[1:] {
			f.Add(s.Raw, ps[0].Raw, ceremony.Unix())
		}
	}
	good := splitPackets(f, subkeyFile(f, "pgp-software-valid"))
	f.Add(good[1].Raw, good[0].Raw, ceremony.Unix()-1)
	f.Add(good[1].Raw, good[0].Raw, int64(1)<<32-1)
	f.Add(good[1].Raw, good[0].Raw, int64(1)<<32)
	f.Add(good[1].Raw, good[0].Raw, int64(0))
	f.Add(good[1].Raw, good[0].Raw, int64(-1))
	f.Add(good[1].Raw[:len(good[1].Raw)-1], good[0].Raw, ceremony.Unix())
	m := newSubkey(f, &genKey(f).PublicKey, created, subAt)
	for _, tweak := range []func(*sigSpec){
		func(sp *sigSpec) { sp.Trailing = []byte{1} },
		func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 3, Data: u32(1)}) },
		func(sp *sigSpec) { sp.Hashed[1].Critical = true },
		func(sp *sigSpec) { sp.OldHeader = true },
		func(sp *sigSpec) { sp.LongLengths = true },
	} {
		f.Add(backSig(f, m.Key, m.Created, m.Primary, m.PrimaryAt, tweak), m.Packet, ceremony.Unix())
	}
	pubA, _ := vectorPrimary(f, "a")
	primary := primaryOf(f, "a")
	f.Fuzz(func(t *testing.T, sig, subkey []byte, unix int64) {
		sub, err := openpgp.ReadSubkey(subkey)
		if err != nil {
			t.Skip()
		}
		in := bytes.Clone(sig)
		err = openpgp.VerifyBackSignature(sig, primary, sub, time.Unix(unix, 0))
		if !bytes.Equal(in, sig) {
			t.Fatal("the signature was changed")
		}
		if unix < 1 || unix > 1<<32-1 {
			if !errors.Is(err, openpgp.ErrParams) || errors.Is(err, openpgp.ErrRequest) {
				t.Fatalf("a ceremony at %d: error %v, want an ErrParams", unix, err)
			}
			return
		}
		if err != nil {
			if !isRequestError(err, openpgp.ErrBackSignature) {
				t.Fatalf("error %v is not an ErrBackSignature", err)
			}
			return
		}
		if !pageAcceptsBackSig(t, pubA, created, subkey, sig) {
			t.Fatal("a back-signature was accepted that the independent reader of the page refuses")
		}
		ps := splitPackets(t, sig)
		back := parseSig(t, ps[0].Body)
		at := find(t, back.Hashed, 2).Data
		if len(ps) != 1 || len(at) != 4 {
			t.Fatalf("an accepted input of %d packets, a creation time of %d bytes", len(ps), len(at))
		}
		made := int64(binary.BigEndian.Uint32(at))
		if made > unix || made < sub.Created().Unix() {
			t.Fatalf("a back-signature made at %d was accepted for a subkey made at %d and a ceremony at %d", made, sub.Created().Unix(), unix)
		}
		if got := types(back.Hashed); !bytes.Equal(got, []byte{2, 33}) && !bytes.Equal(got, []byte{33, 2}) {
			t.Fatalf("hashed subpackets % d were accepted", got)
		}
		if got := types(back.Unhashed); !bytes.Equal(got, []byte{16}) {
			t.Fatalf("unhashed subpackets % d were accepted", got)
		}
		if c := append(critical(back.Hashed), critical(back.Unhashed)...); len(c) != 0 {
			t.Fatalf("critical subpackets % d were accepted", c)
		}
		// The first back-signature of the vector is the only one that this primary can sign for: the
		// fingerprint that it holds is the subkey's.
		if got := find(t, back.Hashed, 33).Data; !bytes.Equal(got, append([]byte{4}, mustFP(t, sub)...)) {
			t.Fatal("the issuer fingerprint is not the subkey's")
		}
	})
}

func mustFP(t testing.TB, s *openpgp.Subkey) []byte {
	t.Helper()
	fp := s.Fingerprint()
	out := make([]byte, 20)
	for i := range out {
		var v byte
		for _, c := range []byte(fp[2*i : 2*i+2]) {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			default:
				t.Fatalf("the fingerprint %q is not lower-case hexadecimal", fp)
			}
		}
		out[i] = v
	}
	return out
}
