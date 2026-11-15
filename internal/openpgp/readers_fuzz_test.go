package openpgp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"runtime"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"ritueel.id/ritueel/internal/openpgp"
)

// The readers of untrusted bytes of this part: SplitCertificate, ReadSignatureFile, RevocationIssuer and
// ReadRevocation. Each target gives one of them any bytes and holds the laws that must stay true: it
// never panics, never changes its input, returns nothing with an error, the error is of the kind of the
// reader and shows no byte of the input, and what it accepts is what an independent reader of the tests
// accepts too. The oracles are written apart from the code under test. The targets start no program.

// ---- SplitCertificate -------------------------------------------------------------------------

// independentCertificate is the tests' own reading of the first form: whole packets of the tags 6, 13 and
// then 1 to 256 of tag 2, in at most 1 MiB.
func independentCertificate(in []byte) bool {
	if len(in) == 0 || len(in) > openpgp.MaxKeyringBytes {
		return false
	}
	tags, _, ok := softPackets(in)
	if !ok || len(tags) < 3 || len(tags) > 2+openpgp.MaxCertifications {
		return false
	}
	if tags[0] != tagPublicKey || tags[1] != tagUserID {
		return false
	}
	for _, tag := range tags[2:] {
		if tag != tagSignature {
			return false
		}
	}
	return true
}

func FuzzSplitCertificate(f *testing.F) {
	m := newKeyringPrimary(f, "A", true)
	cert := m.cert(f)
	ps := splitPackets(f, cert)
	second := m.extension(f, ceremony.AddDate(0, 1, 0))
	f.Add(cert)
	f.Add(cat(cert, second))
	f.Add(vector(f, "pki", "test-primary-a.pgp"))
	f.Add(repack(f, cert, "old2"))
	f.Add(repack(f, cert, "old4"))
	f.Add(repack(f, cert, "new5"))
	f.Add([]byte{})
	f.Add(ps[0].Raw)
	f.Add(cat(ps[0].Raw, ps[1].Raw))
	f.Add(cat(ps[1].Raw, ps[0].Raw, ps[2].Raw))
	f.Add(cat(cert, []byte{0}))
	f.Add(cat(cert, wrap(tagSubkey, ps[0].Body)))
	f.Add(cat(cert, ps[1].Raw))
	f.Add(cert[:len(cert)-1])
	f.Add(cat(ps[0].Raw, ps[1].Raw, []byte{0xC2, 0xE0}, ps[2].Body))
	f.Add(cat(ps[0].Raw, ps[1].Raw, []byte{0x80 | tagSignature<<2 | 3}, ps[2].Body))
	f.Add(fakeCertificate(257))
	f.Fuzz(func(t *testing.T, in []byte) {
		before := bytes.Clone(in)
		c, err := openpgp.SplitCertificate(in)
		if !bytes.Equal(in, before) {
			t.Fatal("SplitCertificate changed its input")
		}
		want := independentCertificate(in)
		if err != nil {
			if c != nil {
				t.Fatalf("a certificate was returned with the error %v", err)
			}
			if !errors.Is(err, openpgp.ErrCertificateForm) || errors.Is(err, openpgp.ErrKeyring) {
				t.Fatalf("the fault is %v, want an ErrCertificateForm", err)
			}
			checkErrorText(t, "SplitCertificate", err)
			if want {
				t.Fatalf("the tests' reader finds the first form and SplitCertificate refuses: %v", err)
			}
			return
		}
		if !want {
			t.Fatal("SplitCertificate accepts bytes that are not the first form")
		}
		whole := [][]byte{c.Key, c.UserID}
		whole = append(whole, c.Signatures...)
		if !bytes.Equal(bytes.Join(whole, nil), in) {
			t.Fatal("the three kinds joined are not the input")
		}
		clear(c.Key)
		clear(c.UserID)
		for _, s := range c.Signatures {
			clear(s)
		}
		if !bytes.Equal(in, before) {
			t.Fatal("changing the result changed the input")
		}
	})
}

// ---- ReadSignatureFile ------------------------------------------------------------------------

// independentSignatureFile is the tests' own reading of a stored file of one signature. It returns the
// packet that the file holds, and whether the file is one that the page accepts.
func independentSignatureFile(file []byte) ([]byte, bool) {
	if len(file) == 0 || len(file) > openpgp.MaxSignatureFileBytes {
		return nil, false
	}
	var pkt []byte
	switch {
	case bytes.HasPrefix(file, []byte("age-encryption.org/")):
		return nil, false
	case bytes.HasPrefix(file, []byte("-----BEGIN")):
		blk, err := armor.Decode(bytes.NewReader(file))
		if err != nil || blk.Type != "PGP SIGNATURE" {
			return nil, false
		}
		body := make([]byte, 0, 1100)
		buf := make([]byte, 512)
		for {
			n, rerr := blk.Body.Read(buf)
			body = append(body, buf[:n]...)
			if rerr != nil || len(body) > 2000 {
				break
			}
		}
		if len(body) > 1024 {
			return nil, false
		}
		var forms [][]byte
		for _, h := range []map[string]string{nil, {"Comment": "TEST ONLY"}} {
			var b bytes.Buffer
			w, err := armor.Encode(&b, "PGP SIGNATURE", h)
			if err != nil {
				return nil, false
			}
			_, _ = w.Write(body)
			_ = w.Close()
			forms = append(forms, b.Bytes(), append(bytes.Clone(b.Bytes()), '\n'))
		}
		found := false
		for _, f := range forms {
			if bytes.Equal(f, file) {
				found = true
			}
		}
		if !found {
			return nil, false
		}
		pkt = body
	default:
		pkt = file
	}
	if len(pkt) > 1024 {
		return nil, false
	}
	tag, body, rest, ok := softPacket(pkt)
	if !ok || tag != tagSignature || len(rest) != 0 || !bytes.Equal(pkt, wrap(tagSignature, body)) {
		return nil, false
	}
	return pkt, true
}

func FuzzReadSignatureFile(f *testing.F) {
	k := newRevKit(f, "fuzz file")
	pkt := k.made(f, openpgp.Compromised)
	other := newKeyringPrimary(f, "B", true)
	f.Add(pkt)
	f.Add(goCryptoArmour(f, "PGP SIGNATURE", testOnly, pkt))
	f.Add(append(goCryptoArmour(f, "PGP SIGNATURE", testOnly, pkt), '\n'))
	f.Add(goCryptoArmour(f, "PGP SIGNATURE", nil, pkt))
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN PGP SIGNATURE-----\n"))
	f.Add([]byte("-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n"))
	f.Add(armourOpts{headers: []string{"Comment: TEST ONLY"}, crcXOR: 1}.text(pkt))
	f.Add(armourOpts{headers: []string{"Comment: TEST ONLY"}, noCRC: true}.text(pkt))
	f.Add(armourOpts{headers: []string{"Comment: TEST ONLY"}, eol: "\r\n"}.text(pkt))
	f.Add(armourOpts{headers: []string{"Comment: TEST ONLY"}, width: 76}.text(pkt))
	f.Add(armourOpts{typ: "PGP PUBLIC KEY BLOCK"}.text(other.cert(f)))
	f.Add(cat([]byte("note\n"), goCryptoArmour(f, "PGP SIGNATURE", testOnly, pkt)))
	f.Add(cat(goCryptoArmour(f, "PGP SIGNATURE", testOnly, pkt), goCryptoArmour(f, "PGP SIGNATURE", testOnly, pkt)))
	f.Add([]byte("age-encryption.org/v1\n-> scrypt abc 18\n"))
	f.Add([]byte("-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n"))
	f.Add(cat(pkt, pkt))
	inside := k.build(f, openpgp.Compromised, func(sp *sigSpec) {
		sp.Unhashed = append(sp.Unhashed, sub{Type: 100, Data: []byte("-----BEGIN PGP SIGNATURE-----")})
	})
	f.Add(inside)
	f.Add(inside[:len(inside)-1])
	f.Add(cat([]byte("note\n"), inside))
	f.Add(oldHeader(tagSignature, bodyOf(f, pkt)))
	f.Add(wrapLong(tagSignature, bodyOf(f, pkt)))
	f.Add(wrap(tagSignature, bytes.Repeat([]byte{4}, 1021)))
	f.Add(wrap(tagSignature, bytes.Repeat([]byte{4}, 1022)))
	f.Add(bytes.Repeat([]byte{0xFF}, openpgp.MaxSignatureFileBytes+1))
	f.Fuzz(func(t *testing.T, in []byte) {
		before := bytes.Clone(in)
		got, err := openpgp.ReadSignatureFile(in)
		if !bytes.Equal(in, before) {
			t.Fatal("ReadSignatureFile changed its input")
		}
		want, wantOK := independentSignatureFile(in)
		if err != nil {
			if got != nil {
				t.Fatalf("%d bytes were returned with the error %v", len(got), err)
			}
			if !errors.Is(err, openpgp.ErrSignatureFile) {
				t.Fatalf("the fault is %v, want an ErrSignatureFile", err)
			}
			checkErrorText(t, "ReadSignatureFile", err)
			if wantOK {
				t.Fatalf("the tests' reader accepts the file and ReadSignatureFile refuses: %v", err)
			}
			return
		}
		if !wantOK || !bytes.Equal(got, want) {
			t.Fatalf("ReadSignatureFile returns %d bytes; the tests' reader finds %d (accepts: %v)", len(got), len(want), wantOK)
		}
		clear(got)
		if !bytes.Equal(in, before) {
			t.Fatal("changing the packet changed the file")
		}
	})
}

// ---- RevocationIssuer and ReadRevocation -------------------------------------------------------

// independentRevocationIssuer is the tests' own reading of the issuer of one signature packet by the
// frame of a revocation: one whole packet of the shortest header, a version 4 body of at most 512
// bytes with at most 32 subpackets in each area, a signature of type 0x20, and one issuer fingerprint
// of version 4.
func independentRevocationIssuer(pkt []byte) (string, bool) {
	tag, body, rest, ok := softPacket(pkt)
	if !ok || tag != tagSignature || len(rest) != 0 || !bytes.Equal(pkt, wrap(tagSignature, body)) || len(body) > 512 {
		return "", false
	}
	s, ok := softSigBody(body, 32)
	if !ok || s.typ != 0x20 {
		return "", false
	}
	fp, ok := onlyOne(s.hashed, 33)
	if !ok || len(fp) != 21 || fp[0] != 4 {
		return "", false
	}
	return hex.EncodeToString(fp[1:]), true
}

// independentRevocation is the tests' own reading of a revocation signature of the primary of the kit:
// the exact shape of the page, and the signature verified with crypto/ecdsa over the digest of the key
// packet, the fields and the trailer. It returns the reason and the creation time.
func independentRevocation(pkt []byte, k revKit) (reason openpgp.Reason, at int64, ok bool) {
	tag, body, rest, ok := softPacket(pkt)
	if !ok || tag != tagSignature || len(rest) != 0 || !bytes.Equal(pkt, wrap(tagSignature, body)) || len(body) > 512 {
		return reason, 0, false
	}
	s, ok := softSigBody(body, 32)
	if !ok || s.typ != 0x20 || s.algo != 19 || s.hash != 9 || len(s.hashed) != 3 || len(s.unhashed) != 1 {
		return reason, 0, false
	}
	for _, sp := range append(append([]sub{}, s.hashed...), s.unhashed...) {
		if sp.Critical {
			return reason, 0, false
		}
	}
	when, ok1 := onlyOne(s.hashed, 2)
	why, ok2 := onlyOne(s.hashed, 29)
	issuer, ok3 := onlyOne(s.hashed, 33)
	id, ok4 := onlyOne(s.unhashed, 16)
	if !ok1 || !ok2 || !ok3 || !ok4 || len(when) != 4 || len(why) == 0 ||
		!bytes.Equal(issuer, append([]byte{4}, k.fp...)) || !bytes.Equal(id, k.fp[12:]) {
		return reason, 0, false
	}
	for _, c := range allReasons {
		if why[0] == c.r.Code && string(why[1:]) == c.r.Text {
			reason = c.r
		}
	}
	if reason.Text == "" {
		return reason, 0, false
	}
	at = int64(binary.BigEndian.Uint32(when))
	if at < created.Unix() || len(s.rest) < 2 {
		return reason, 0, false
	}
	r, tail, ok := softMPI(s.rest[2:])
	if !ok {
		return reason, 0, false
	}
	v, tail, ok := softMPI(tail)
	if !ok || len(tail) != 0 {
		return reason, 0, false
	}
	trailer := append([]byte{4, 0xFF}, u32(uint32(len(s.fields)))...)
	h := sha512.New384()
	h.Write(hashPrefix(&k.key.PublicKey, created))
	h.Write(s.fields)
	h.Write(trailer)
	digest := h.Sum(nil)
	if !bytes.Equal(digest[:2], s.rest[:2]) {
		return reason, 0, false
	}
	return reason, at, ecdsa.Verify(&k.key.PublicKey, digest, new(big.Int).SetBytes(r), new(big.Int).SetBytes(v))
}

func addRevocationSeeds(f *testing.F, k revKit) {
	for _, c := range allReasons {
		f.Add(k.made(f, c.r))
	}
	f.Add([]byte{})
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed = sp.Hashed[:2] }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sp.Hashed[2]) }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed[1].Data = []byte{9, 'x'} }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed[1].Critical = true }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Type = 0x28 }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Type = 0x13 }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Type = 0x18 }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Type = 0x19 }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Type = 0x00 }))
	f.Add(wrap(tagSignature, bytes.Repeat([]byte{4}, 513)))
	f.Add(wrapLong(tagSignature, bytes.Repeat([]byte{4}, 513)))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Hash = 8 }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.OldHeader = true }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.LongLengths = true }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.TagXOR = [2]byte{1, 0} }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Trailing = []byte{0} }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed[0].Data = u32(1) }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed[2].Data[0] = 5 }))
	f.Add(k.build(f, openpgp.Compromised, func(sp *sigSpec) { sp.Unhashed = nil }))
	f.Add(newRevKit(f, "fuzz other").made(f, openpgp.Superseded))
}

func FuzzRevocationIssuer(f *testing.F) {
	k := newRevKit(f, "fuzz issuer")
	addRevocationSeeds(f, k)
	f.Fuzz(func(t *testing.T, in []byte) {
		before := bytes.Clone(in)
		got, err := openpgp.RevocationIssuer(in)
		if !bytes.Equal(in, before) {
			t.Fatal("RevocationIssuer changed its input")
		}
		want, wantOK := independentRevocationIssuer(in)
		if err != nil {
			if got != "" {
				t.Fatalf("the text %q was returned with the error %v", got, err)
			}
			if !errors.Is(err, openpgp.ErrRevocation) || errors.Is(err, openpgp.ErrRevocationReason) {
				t.Fatalf("the fault is %v, want a plain ErrRevocation", err)
			}
			checkErrorText(t, "RevocationIssuer", err)
			checkRevocationText(t, "RevocationIssuer", err, in, "")
			if wantOK {
				t.Fatalf("the tests' reader finds the issuer %s and RevocationIssuer refuses: %v", want, err)
			}
			return
		}
		if !fingerprintPattern.MatchString(got) || !wantOK || got != want {
			t.Fatalf("RevocationIssuer = %q; the tests' reader finds %q (found %v)", got, want, wantOK)
		}
	})
}

func FuzzReadRevocation(f *testing.F) {
	k := newRevKit(f, "fuzz revocation")
	addRevocationSeeds(f, k)
	f.Fuzz(func(t *testing.T, in []byte) {
		before := bytes.Clone(in)
		rev, err := openpgp.ReadRevocation(in, k.primary)
		if !bytes.Equal(in, before) {
			t.Fatal("ReadRevocation changed its input")
		}
		reason, at, wantOK := independentRevocation(in, k)
		if err != nil {
			if rev != nil {
				t.Fatalf("a Revocation was returned with the error %v", err)
			}
			if !errors.Is(err, openpgp.ErrRevocation) {
				t.Fatalf("the fault is %v, want an ErrRevocation", err)
			}
			checkErrorText(t, "ReadRevocation", err)
			checkRevocationText(t, "ReadRevocation", err, in, hex.EncodeToString(k.fp))
			if wantOK {
				t.Fatalf("the tests' reader accepts the signature and ReadRevocation refuses: %v", err)
			}
			return
		}
		if !wantOK {
			t.Fatal("ReadRevocation accepts a signature that the tests' reader refuses")
		}
		sum := sha256.Sum256(in)
		if rev.Reason != reason || rev.Created.Unix() != at || rev.Issuer != hex.EncodeToString(k.fp) || rev.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("ReadRevocation read %+v, the tests' reader read %v at %d", rev, reason, at)
		}
		if fp, err := openpgp.RevocationIssuer(in); err != nil || fp != rev.Issuer {
			t.Fatalf("RevocationIssuer = %q, %v; ReadRevocation says %q", fp, err, rev.Issuer)
		}
	})
}

// FuzzReadRevocationBuilt builds a signature that verifies from the bytes of the input, so that the
// fuzzer reaches the checks behind the signature. The input chooses, one knob each, what to change in
// the signature of the page; the signature is made over the true digest of what it holds. The tests'
// reader says whether the result is the signature of the page, and ReadRevocation must agree.
func FuzzReadRevocationBuilt(f *testing.F) {
	k := newRevKit(f, "fuzz built")
	other := newRevKit(f, "fuzz built other")
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, knobs []byte) {
		kb := func(i int) byte {
			if i < len(knobs) {
				return knobs[i]
			}
			return 0
		}
		r := allReasons[int(kb(0))%4].r
		sp := k.spec(r)
		issuerAt := func() int {
			for i, h := range sp.Hashed {
				if h.Type == 33 {
					return i
				}
			}
			return -1
		}
		switch kb(0) >> 4 % 6 { // the reason subpacket
		case 1:
			sp.Hashed[1].Data = []byte{kb(14), 'x'}
		case 2:
			sp.Hashed[1].Data = nil
		case 3:
			sp.Hashed = []sub{sp.Hashed[0], sp.Hashed[2]}
		case 4:
			sp.Hashed = append(sp.Hashed, sp.Hashed[1])
		case 5:
			sp.Hashed[1].Data = append([]byte{r.Code}, "other"...)
		}
		crit := kb(1)
		for i := range sp.Hashed {
			sp.Hashed[i].Critical = crit>>uint(i)&1 == 1
		}
		if len(sp.Unhashed) > 0 {
			sp.Unhashed[0].Critical = crit>>3&1 == 1
		}
		switch kb(2) % 4 { // extra subpackets
		case 1:
			sp.Hashed = append(sp.Hashed, sub{Type: 27, Data: []byte{1}})
		case 2:
			sp.Hashed = append(sp.Hashed, sub{Type: 100, Data: []byte{kb(13)}})
		case 3:
			sp.Hashed = append(sp.Hashed, sub{Type: 33, Data: sp.Hashed[issuerAt()].Data})
		}
		switch kb(3) % 4 {
		case 1:
			sp.Unhashed = append(sp.Unhashed, sub{Type: 100, Data: []byte{1}})
		case 2:
			sp.Unhashed = nil
		case 3:
			sp.Unhashed = []sub{{Type: 16, Data: bytes.Clone(other.fp[12:])}}
		}
		switch kb(4) % 4 { // the issuer
		case 1:
			sp.Hashed[issuerAt()].Data = append([]byte{4}, other.fp...)
		case 2:
			sp.Hashed[issuerAt()].Data = append([]byte{5}, k.fp...)
		case 3:
			sp.Hashed[issuerAt()].Data = sp.Hashed[issuerAt()].Data[:20]
		}
		switch kb(5) % 4 { // the creation time
		case 1:
			sp.Hashed[0].Data = u32(uint32(created.Unix()) - 1 - uint32(kb(12)))
		case 2:
			sp.Hashed[0].Data = u32(uint32(created.Unix()) + uint32(kb(12))<<16)
		case 3:
			sp.Hashed[0].Data = u32(0)[:3]
		}
		sp.Type = []byte{0x20, 0x20, 0x20, 0x28, 0x18, 0x13, 0x20, 0x20}[kb(6)%8]
		sp.Hash = []byte{9, 9, 9, 8, 10, 9, 9, 9}[kb(7)%8]
		if kb(8)%8 == 1 {
			sp.TagXOR = [2]byte{1, 0}
		}
		if kb(8)%8 == 2 {
			sp.Trailing = []byte{kb(11)}
		}
		if kb(9)%8 == 1 {
			sp.Data = nil
		}
		if kb(9)%8 == 2 {
			sp.Key = other.key
		}
		sp.OldHeader = kb(10)%8 == 1
		sp.LongLengths = kb(10)%8 == 2 // read as the page's shape: the form of a length is not a field
		pkt := sp.build(t)
		_, _, wantOK := independentRevocation(pkt, k)
		rev, err := k.read(t, "built", pkt)
		if (err == nil) != wantOK {
			t.Fatalf("ReadRevocation accepts: %v (%v); the tests' reader accepts: %v", err == nil, err, wantOK)
		}
		if err != nil && rev != nil {
			t.Fatal("a Revocation with an error")
		}
		if err != nil {
			checkErrorText(t, "built", err)
		}
	})
}

// ---- the bounds ----------------------------------------------------------------------------------

// allocated is the bytes that f allocates, measured by the runtime. The tests of this package do not run
// in parallel, so what the runtime counts is the work of f.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// A reader that is given more than its limit, or a length field that claims more than there is, refuses
// before it allocates for the input: the work is held to a few kibibytes whatever the input is, and a
// whole certificate of the largest size that it takes costs a few copies of the input and no more. The
// inputs are made before the measure, so that what is counted is the work of the reader.
func TestTheReadersAllocateWithinTheBoundOfTheirInput(t *testing.T) {
	k := newRevKit(t, "alloc")
	claims := func(n int) []byte { // a header that claims n bytes, and 1 MiB of body that is not it
		return cat([]byte{0xC2, 0xFF, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, make([]byte, 1<<20))
	}
	const small = 64 << 10
	hugeClaim, mibClaim := claims(1<<32-1), claims(1<<20)
	pastLimit := make([]byte, openpgp.MaxKeyringBytes+1)
	pastFile := make([]byte, openpgp.MaxSignatureFileBytes+1)
	claimInFile := hugeClaim[:openpgp.MaxSignatureFileBytes]
	armourFile := cat([]byte("-----BEGIN PGP SIGNATURE-----\n\n"), bytes.Repeat([]byte("A"), openpgp.MaxSignatureFileBytes-31))
	bigBody := wrap(tagSignature, bytes.Repeat([]byte{4}, 1<<20))
	bigLong := wrapLong(tagSignature, bytes.Repeat([]byte{4}, 1<<20))
	wideArea := withBody(append([]byte{4, 0x20, 19, 9, 0xFF, 0xFF}, make([]byte, 400)...))
	for name, f := range map[string]func(){
		"SplitCertificate of 1 MiB and a byte":      func() { _, _ = openpgp.SplitCertificate(pastLimit) },
		"SplitCertificate of a claim of 4 GiB":      func() { _, _ = openpgp.SplitCertificate(hugeClaim) },
		"SplitCertificate of a claim of 1 MiB":      func() { _, _ = openpgp.SplitCertificate(mibClaim) },
		"ReadSignatureFile of 8 KiB and a byte":     func() { _, _ = openpgp.ReadSignatureFile(pastFile) },
		"ReadSignatureFile of a claim of 4 GiB":     func() { _, _ = openpgp.ReadSignatureFile(claimInFile) },
		"ReadSignatureFile of an armour of 8 KiB":   func() { _, _ = openpgp.ReadSignatureFile(armourFile) },
		"RevocationIssuer of a claim of 4 GiB":      func() { _, _ = openpgp.RevocationIssuer(hugeClaim) },
		"RevocationIssuer of 1 MiB of body":         func() { _, _ = openpgp.RevocationIssuer(bigBody) },
		"ReadRevocation of a claim of 4 GiB":        func() { _, _ = openpgp.ReadRevocation(hugeClaim, k.primary) },
		"ReadRevocation of 1 MiB of body":           func() { _, _ = openpgp.ReadRevocation(bigLong, k.primary) },
		"ReadRevocation of a hashed area of 64 KiB": func() { _, _ = openpgp.ReadRevocation(wideArea, k.primary) },
	} {
		if got := allocated(f); got > small {
			t.Errorf("%s: %d bytes allocated, the bound is %d", name, got, small)
		}
	}
	whole := fakeCertificate(openpgp.MaxCertifications)
	if got := allocated(func() { _, _ = openpgp.SplitCertificate(whole) }); got > 4*uint64(len(whole))+small {
		t.Errorf("SplitCertificate of %d bytes allocated %d bytes", len(whole), got)
	}
}
