package openpgp_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// The readers of an answer read bytes that come from outside. Each target gives one of them any
// bytes and holds the laws that must stay true: it never panics, a refusal returns nothing and is of
// the kind of the page, and what it accepts is what a second reader of the tests accepts too. The
// targets start no program. The seeds are the vector files and the bindings that the tests write.

// FuzzSplitBoundFile gives SplitBoundFile any file. The independent reader of the tests decides the
// same: exactly two whole packets, of tags 14 and 2, in at most 256 KiB.
func FuzzSplitBoundFile(f *testing.F) {
	k := newFixedBindKit(f, "split")
	pkt := k.build(f, nil)
	for _, v := range boundVectors {
		f.Add(boundFile(f, v.id))
	}
	f.Add([]byte{})
	f.Add(append(bytes.Clone(k.sub.Packet), pkt...))
	f.Add(append(bytes.Clone(k.sub.Packet), k.build(f, func(sp *sigSpec) { sp.OldHeader = true })...))
	f.Add(append(oldHeader(tagSubkey, k.sub.body()), pkt...))
	f.Add(append(bytes.Clone(k.sub.Packet), append(bytes.Clone(pkt), 0)...))
	f.Add(append(bytes.Clone(k.sub.Packet), pkt[:len(pkt)-1]...))
	f.Add(append(bytes.Clone(pkt), k.sub.Packet...))
	f.Add(k.sub.Packet)
	f.Add(append([]byte{0xCE, 0xE0}, pkt...))
	f.Add(append(bytes.Clone(k.sub.Packet), 0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
	f.Fuzz(func(t *testing.T, file []byte) {
		in := bytes.Clone(file)
		sub, sig, err := openpgp.SplitBoundFile(file)
		if !bytes.Equal(file, in) {
			t.Fatal("SplitBoundFile changed its input")
		}
		tags, _, whole := softPackets(file)
		want := whole && len(tags) == 2 && tags[0] == tagSubkey && tags[1] == tagSignature && len(file) <= maxBoundFile
		if err != nil {
			if sub != nil || sig != nil {
				t.Fatalf("a fault returned %d and %d bytes", len(sub), len(sig))
			}
			if !errors.Is(err, openpgp.ErrBoundFile) || !errors.Is(err, openpgp.ErrAnswer) || errors.Is(err, openpgp.ErrBinding) {
				t.Fatalf("the fault is %v, want an ErrBoundFile", err)
			}
			checkErrorText(t, "SplitBoundFile", err)
			if want {
				t.Fatalf("the tests' reader finds two packets, tags % d, and SplitBoundFile refuses: %v", tags, err)
			}
			return
		}
		if !want {
			t.Fatalf("SplitBoundFile accepts a file that is not a subkey packet and a signature packet (tags % d, whole %v)", tags, whole)
		}
		if !bytes.Equal(append(bytes.Clone(sub), sig...), file) {
			t.Fatal("the two packets are not the file")
		}
		// Copies, both ways.
		clear(sub)
		clear(sig)
		if !bytes.Equal(file, in) {
			t.Fatal("changing the returned packets changed the file")
		}
	})
}

// FuzzBindingIssuer gives BindingIssuer any bytes. The tests' own reader says what the issuer is:
// one signature packet of version 4 with at most 32 subpackets in each area, and one issuer
// fingerprint of version 4 in the hashed area.
func FuzzBindingIssuer(f *testing.F) {
	k := newFixedBindKit(f, "issuer")
	for _, v := range boundVectors {
		_, pkt, err := openpgp.SplitBoundFile(boundFile(f, v.id))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(pkt)
	}
	f.Add([]byte{})
	f.Add(k.build(f, nil))
	f.Add(k.build(f, func(sp *sigSpec) { sp.Hashed = sp.Hashed[:3] }))
	f.Add(k.build(f, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sp.Hashed[3]) }))
	f.Add(k.build(f, func(sp *sigSpec) { sp.Hashed[3].Data[0] = 5 }))
	f.Add(k.build(f, func(sp *sigSpec) { sp.LongLengths = true }))
	f.Add(k.build(f, func(sp *sigSpec) { sp.OldHeader = true }))
	f.Add(k.build(f, func(sp *sigSpec) { sp.Type = 0x19 }))
	f.Fuzz(func(t *testing.T, pkt []byte) {
		in := bytes.Clone(pkt)
		got, err := openpgp.BindingIssuer(pkt)
		if !bytes.Equal(pkt, in) {
			t.Fatal("BindingIssuer changed its input")
		}
		want, wantOK := independentIssuer(pkt)
		if err != nil {
			if got != "" {
				t.Fatalf("a fault returned the text %q", got)
			}
			if !errors.Is(err, openpgp.ErrBinding) || !errors.Is(err, openpgp.ErrAnswer) {
				t.Fatalf("the fault is %v, want an ErrBinding", err)
			}
			checkErrorText(t, "BindingIssuer", err)
			if wantOK {
				t.Fatalf("the tests' reader finds the issuer %s and BindingIssuer refuses: %v", want, err)
			}
			return
		}
		if !fingerprintPattern.MatchString(got) {
			t.Fatalf("the issuer %q is not 40 lower-case hexadecimal digits", got)
		}
		if !wantOK || got != want {
			t.Fatalf("BindingIssuer = %s; the tests' reader finds %q (found %v)", got, want, wantOK)
		}
	})
}

// independentIssuer is the tests' own reading of the issuer of one signature packet.
func independentIssuer(pkt []byte) (string, bool) {
	tag, body, rest, ok := softPacket(pkt)
	if !ok || tag != tagSignature || len(rest) != 0 || len(pkt) > maxBoundFile {
		return "", false
	}
	s, ok := softSigBody(body, 32)
	if !ok {
		return "", false
	}
	fp, ok := onlyOne(s.hashed, 33)
	if !ok || len(fp) != 21 || fp[0] != 4 {
		return "", false
	}
	return hex.EncodeToString(fp[1:]), true
}

// FuzzVerifyBinding gives VerifyBinding any bytes, with a primary and a subkey that are fixed: one
// made by the tests (which can write bindings that verify) and one of the vector set. A refusal is
// an ErrBinding or an ErrBindingShape with no binding. What is accepted is read again by the tests'
// own verifier, which must find a signature of the primary over the primary and the subkey, and has
// the subpackets of the page. A mutation of the embedded signature is accepted, which is what the
// comparison with Embeds is for.
func FuzzVerifyBinding(f *testing.F) {
	k := newFixedBindKit(f, "verify")
	vecSub, vecSigs := vectorSubkeyAndBindings(f)
	for _, pkt := range vecSigs {
		f.Add(pkt, uint8(1))
	}
	for _, tweak := range []func(*sigSpec){
		nil,
		func(sp *sigSpec) { sp.Hashed[1].Data = []byte{0x20} },
		func(sp *sigSpec) { sp.LongLengths = true },
		func(sp *sigSpec) { sp.OldHeader = true },
		func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 100, Data: []byte{1}}) },
		func(sp *sigSpec) { sp.Hashed[2].Critical = false },
		func(sp *sigSpec) { sp.Unhashed = sp.Unhashed[:1] },
		func(sp *sigSpec) { sp.Hashed = sp.Hashed[:3] },
		func(sp *sigSpec) { sp.Hashed[2].Data = u32(0) },
		func(sp *sigSpec) { sp.TagXOR = [2]byte{1, 1} },
		func(sp *sigSpec) { sp.Trailing = []byte{0} },
		func(sp *sigSpec) { sp.Type = 0x19 },
		func(sp *sigSpec) { sp.Hash = 10 },
		func(sp *sigSpec) { sp.Unhashed[1].Data = embeddedFor(10000) },
		func(sp *sigSpec) { sp.Unhashed[0], sp.Unhashed[1] = sp.Unhashed[1], sp.Unhashed[0] },
		func(sp *sigSpec) {
			for len(sp.Hashed) < 33 {
				sp.Hashed = append(sp.Hashed, sub{Type: 100, Data: []byte{1}})
			}
		},
	} {
		f.Add(k.build(f, tweak), uint8(0))
	}
	// The limits that the reader measures: the end of the subkey at and after the last second of a
	// time field, and an unhashed area of 10000 bytes and of 10004 bytes as it is written.
	for _, life := range []uint32{uint32(lastSecond - subAt.Unix()), uint32(lastSecond-subAt.Unix()) + 1, 0xFFFFFFFF} {
		f.Add(k.build(f, func(sp *sigSpec) { sp.Hashed[2].Data = u32(life) }), uint8(0))
	}
	for _, idLong := range []bool{false, true} {
		f.Add(writeUnhashed(f, k.build(f, nil), idLong, false, true, bytes.Repeat([]byte{0xCD}, 10000-10-3)), uint8(0))
	}
	f.Add([]byte{}, uint8(0))
	f.Add([]byte{0xC2, 0x00}, uint8(1))
	f.Fuzz(func(t *testing.T, pkt []byte, which uint8) {
		primary, sk := k.primary, k.subKey
		primaryPub, subPub := &k.key.PublicKey, &k.sub.Key.PublicKey
		primaryAt, subCreated := created.Unix(), subAt.Unix()
		if which%2 == 1 {
			primary, sk = vecSub.primary, vecSub.sub
			primaryPub, subPub = vecSub.primary.PublicKey(), vecSub.sub.PublicKey()
			primaryAt, subCreated = vecSub.primary.Created().Unix(), vecSub.sub.Created().Unix()
		}
		in := bytes.Clone(pkt)
		b, err := openpgp.VerifyBinding(pkt, primary, sk)
		if !bytes.Equal(pkt, in) {
			t.Fatal("VerifyBinding changed its input")
		}
		again, errAgain := openpgp.VerifyBinding(pkt, primary, sk)
		if (err == nil) != (errAgain == nil) || (err != nil && errors.Is(err, openpgp.ErrBinding) != errors.Is(errAgain, openpgp.ErrBinding)) || (b == nil) != (again == nil) {
			t.Fatalf("two calls differ: %v, %v", err, errAgain)
		}
		if err != nil {
			assertFaultResultKind(t, b, err)
			return
		}
		if b == nil {
			t.Fatal("no error and no binding")
		}
		// What is accepted is a binding by the primary over the primary and the subkey.
		tag, body, rest, ok := softPacket(pkt)
		if !ok || tag != tagSignature || len(rest) != 0 {
			t.Fatalf("an accepted binding is not one signature packet")
		}
		s, ok := softSigBody(body, 32)
		if !ok || s.typ != 0x18 || s.algo != 19 || s.hash != 9 {
			t.Fatalf("an accepted binding is not a type 0x18 signature with ECDSA and SHA-384 that the tests' reader reads (%v)", ok)
		}
		if !softSignatureValid(body, primaryPub, subPub, primaryAt, subCreated) {
			t.Fatal("an accepted binding does not verify under the tests' own verifier")
		}
		// The unhashed area is no longer than gpgv reads, as it is written.
		if l := layoutOf(body).unhashedLen; l > 10000 {
			t.Fatalf("an accepted binding has an unhashed area of %d bytes as written", l)
		}
		// The subpackets are the set of the page.
		if len(s.hashed) != 4 || len(s.unhashed) != 2 {
			t.Fatalf("an accepted binding has %d and %d subpackets", len(s.hashed), len(s.unhashed))
		}
		for _, x := range s.hashed {
			if x.Critical != (x.Type == 9) {
				t.Fatalf("an accepted binding has a subpacket of type %d with the critical bit %v", x.Type, x.Critical)
			}
		}
		for _, x := range s.unhashed {
			if x.Critical {
				t.Fatal("an accepted binding has a critical subpacket in the unhashed area")
			}
		}
		flags, ok1 := onlyOne(s.hashed, 27)
		life, ok2 := onlyOne(s.hashed, 9)
		made, ok3 := onlyOne(s.hashed, 2)
		fp, ok4 := onlyOne(s.hashed, 33)
		id, ok5 := onlyOne(s.unhashed, 16)
		emb, ok6 := onlyOne(s.unhashed, 32)
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || len(flags) != 1 || len(life) != 4 || len(made) != 4 || len(fp) != 21 || len(id) != 8 || len(emb) == 0 {
			t.Fatal("an accepted binding has not the six subpackets of the page, once each")
		}
		if bytes.Equal(life, []byte{0, 0, 0, 0}) || !bytes.Equal(fp[13:], id) {
			t.Fatal("an accepted binding has a key expiration of zero or an issuer key ID that is not the fingerprint's end")
		}
		wantCap := map[byte]string{0x02: "sign", 0x20: "authenticate"}[flags[0]]
		if wantCap == "" || b.Capability() != wantCap {
			t.Fatalf("flags %#x: Capability = %q", flags[0], b.Capability())
		}
		if hex.EncodeToString(fp[1:]) != b.IssuerFingerprint() || b.IssuerFingerprint() != primary.Fingerprint() {
			t.Fatalf("IssuerFingerprint = %s", b.IssuerFingerprint())
		}
		if b.Created().Unix() != int64(uint32(made[0])<<24|uint32(made[1])<<16|uint32(made[2])<<8|uint32(made[3])) {
			t.Fatalf("Created = %v", b.Created())
		}
		if secs := int64(uint32(life[0])<<24 | uint32(life[1])<<16 | uint32(life[2])<<8 | uint32(life[3])); b.Ends().Unix() != subCreated+secs {
			t.Fatalf("Ends = %v, want the subkey's creation plus %d seconds", b.Ends(), secs)
		}
		if b.Ends().Unix() > lastSecond {
			t.Fatalf("Ends = %v, after the last second that a time field holds", b.Ends())
		}
		if !b.Embeds(wrap(tagSignature, emb)) || b.Embeds(wrap(tagSignature, append(bytes.Clone(emb), 0))) {
			t.Fatal("Embeds does not hold the embedded signature, whole and only")
		}
		if got, ierr := openpgp.BindingIssuer(pkt); ierr != nil || got != b.IssuerFingerprint() {
			t.Fatalf("BindingIssuer = %q, %v; VerifyBinding says %s", got, ierr, b.IssuerFingerprint())
		}
		// A third reader, for the ones whose embedded signature it can read: go-crypto agrees.
		if which%2 == 0 && bytes.Equal(emb, k.sub.BackBody) && !goCryptoAccepts(t, primaryPub, subPub, primaryAt, subCreated, pkt) {
			t.Fatal("go-crypto refuses a binding that VerifyBinding accepts")
		}
	})
}

// assertFaultResultKind holds the laws of a refusal, for either kind.
func assertFaultResultKind(t *testing.T, b *openpgp.Binding, err error) {
	t.Helper()
	if b != nil {
		t.Fatalf("a binding was returned with the error %v", err)
	}
	if !errors.Is(err, openpgp.ErrAnswer) {
		t.Fatalf("the fault %v is not an ErrAnswer", err)
	}
	if errors.Is(err, openpgp.ErrBinding) == errors.Is(err, openpgp.ErrBindingShape) {
		t.Fatalf("the fault %v is both or neither of ErrBinding and ErrBindingShape", err)
	}
	checkErrorText(t, "VerifyBinding", err)
}

type vectorKeys struct {
	primary *openpgp.PrimaryKey
	sub     *openpgp.Subkey
}

// vectorSubkeyAndBindings returns the primary A and the subkey of the answer of pgp-software-valid,
// and the binding packets of the vector answers (with the keys that made them, only that one verifies).
func vectorSubkeyAndBindings(f testing.TB) (vectorKeys, [][]byte) {
	f.Helper()
	subPkt, _, err := openpgp.SplitBoundFile(boundFile(f, "pgp-software-valid"))
	if err != nil {
		f.Fatal(err)
	}
	sk, err := openpgp.ReadSubkey(subPkt)
	if err != nil {
		f.Fatal(err)
	}
	var bindings [][]byte
	for _, v := range boundVectors {
		_, pkt, err := openpgp.SplitBoundFile(boundFile(f, v.id))
		if err != nil {
			f.Fatal(err)
		}
		bindings = append(bindings, pkt)
	}
	pub, _ := vectorPrimary(f, "a")
	p, err := openpgp.NewPrimaryKey(pub, created)
	if err != nil {
		f.Fatal(err)
	}
	return vectorKeys{primary: p, sub: sk}, bindings
}
