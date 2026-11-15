package openpgp_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// Three points of the readers: the size of a revocation packet is judged
// before any byte is copied, RevocationIssuer names the issuer of a key revocation only, and a file is
// armour only when it starts with the armour head line.

// ---- the size of a revocation packet is judged first -------------------------------------------

// leastAllocated is the smallest count of bytes that f allocates in three runs, so that a stray
// allocation of the runtime does not count against it.
func leastAllocated(f func()) uint64 {
	least := allocated(f)
	for range 2 {
		least = min(least, allocated(f))
	}
	return least
}

// A packet whose body is longer than 512 bytes is refused for its length by both readers, and the work
// of refusing it does not grow with the packet: a few kibibytes for a body of 513 bytes and for a body
// of 16 MiB alike. The first test is the smallest packet that is too long and the largest that a test
// can hold; the header is in each form, because the length is judged before the header is compared.
func TestARevocationPacketOverTheBoundIsRefusedWithNoWorkThatGrowsWithIt(t *testing.T) {
	k := newRevKit(t, "bound")
	const work = 8 << 10
	for _, size := range []int{513, 514, 600, 1024, 4096, 64 << 10, 1 << 20, 16 << 20} {
		body := bytes.Repeat([]byte{4}, size)
		old := oldHeader(tagSignature, body)
		if size > 0xFFFF {
			old = mustForm(t, "old4", tagSignature, body)
		}
		for form, pkt := range map[string][]byte{
			"the shortest header": wrap(tagSignature, body),
			"a five-octet header": wrapLong(tagSignature, body),
			"an old-format one":   old,
		} {
			t.Run(fmt.Sprintf("%d bytes with %s", size, form), func(t *testing.T) {
				before := bytes.Clone(pkt[:min(len(pkt), 64)])
				if fp, err := openpgp.RevocationIssuer(pkt); err == nil || fp != "" ||
					!errors.Is(err, openpgp.ErrRevocation) || errors.Is(err, openpgp.ErrRevocationReason) ||
					!strings.Contains(err.Error(), "longer than 512 bytes") {
					t.Errorf("RevocationIssuer = %q, %v; want a plain ErrRevocation that says the signature is longer than 512 bytes", fp, err)
				}
				if rev, err := openpgp.ReadRevocation(pkt, k.primary); err == nil || rev != nil ||
					!errors.Is(err, openpgp.ErrRevocation) || errors.Is(err, openpgp.ErrRevocationReason) ||
					!strings.Contains(err.Error(), "longer than 512 bytes") {
					t.Errorf("ReadRevocation = %v, %v; want a plain ErrRevocation that says the signature is longer than 512 bytes", rev, err)
				}
				if !bytes.Equal(before, pkt[:len(before)]) {
					t.Error("a reader changed its input")
				}
				if got := leastAllocated(func() { _, _ = openpgp.RevocationIssuer(pkt) }); got > work {
					t.Errorf("RevocationIssuer allocated %d bytes for a body of %d, the bound is %d", got, size, work)
				}
				if got := leastAllocated(func() { _, _ = openpgp.ReadRevocation(pkt, k.primary) }); got > work {
					t.Errorf("ReadRevocation allocated %d bytes for a body of %d, the bound is %d", got, size, work)
				}
			})
		}
	}
}

// The length is judged before the header form. A body of 513 bytes with a five-octet header is refused
// for its length, and a body of 512 bytes with the same header is refused for its header: the two texts
// are told apart by the size of the body, not by the form.
func TestTheLengthOfARevocationPacketIsJudgedBeforeTheFormOfItsHeader(t *testing.T) {
	k := newRevKit(t, "bound order")
	for _, c := range []struct {
		name string
		size int
		want string
	}{
		{"512 bytes", 512, "shortest"},
		{"511 bytes", 511, "shortest"},
		{"513 bytes", 513, "longer than 512"},
		{"2 KiB", 2 << 10, "longer than 512"},
	} {
		body := bytes.Repeat([]byte{4}, c.size)
		for form, pkt := range map[string][]byte{
			"a five-octet header": wrapLong(tagSignature, body),
			"an old-format one":   oldHeader(tagSignature, body),
		} {
			t.Run(c.name+" with "+form, func(t *testing.T) {
				if _, err := openpgp.RevocationIssuer(pkt); err == nil || !strings.Contains(err.Error(), c.want) {
					t.Errorf("RevocationIssuer: the refusal is %v, want a text that holds %q", err, c.want)
				}
				if _, err := openpgp.ReadRevocation(pkt, k.primary); err == nil || !strings.Contains(err.Error(), c.want) {
					t.Errorf("ReadRevocation: the refusal is %v, want a text that holds %q", err, c.want)
				}
			})
		}
	}
}

// A body of exactly 512 bytes with the shortest header is not refused for its length, and one byte
// more is: the bound is on the body, the same for both readers.
func TestARevocationBodyOf512BytesPassesTheBoundAndOneByteMoreDoesNot(t *testing.T) {
	k := newRevKit(t, "bound edge")
	build := func(pad int) []byte {
		return k.build(t, openpgp.Compromised, func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sub{Type: 100, Data: bytes.Repeat([]byte{1}, pad)})
		})
	}
	pad := 300
	pkt := build(pad)
	for range 4 {
		got := len(bodyOf(t, pkt))
		if got == 512 {
			break
		}
		pad += 512 - got
		pkt = build(pad)
	}
	if got := len(bodyOf(t, pkt)); got != 512 {
		t.Fatalf("the test made a body of %d bytes", got)
	}
	if fp, err := openpgp.RevocationIssuer(pkt); err != nil || fp != hex.EncodeToString(k.fp) {
		t.Errorf("RevocationIssuer of 512 bytes = %q, %v", fp, err)
	}
	if _, err := openpgp.ReadRevocation(pkt, k.primary); err == nil || strings.Contains(err.Error(), "longer than") {
		t.Errorf("ReadRevocation of 512 bytes: %v, want a refusal that is not for the length (the extra subpacket)", err)
	}
	over := build(pad + 1)
	if got := len(bodyOf(t, over)); got != 513 {
		t.Fatalf("the test made a body of %d bytes", got)
	}
	for name, err := range map[string]error{
		"RevocationIssuer": func() error { _, e := openpgp.RevocationIssuer(over); return e }(),
		"ReadRevocation":   func() error { _, e := openpgp.ReadRevocation(over, k.primary); return e }(),
	} {
		if err == nil || !strings.Contains(err.Error(), "longer than 512 bytes") {
			t.Errorf("%s of 513 bytes: %v, want the refusal for the length", name, err)
		}
	}
}

// ---- RevocationIssuer names the issuer of a key revocation only --------------------------------

// A function that names the issuer of a revocation does not name the issuer of another kind of
// signature. Every type byte but 0x20 is refused with a plain ErrRevocation, the kind that ReadRevocation
// gives for a wrong type, and the refusal says what it wants. The packets are built with an issuer
// fingerprint that is whole, so that the type is the one fault.
func TestRevocationIssuerRefusesEveryTypeOfSignatureButAKeyRevocation(t *testing.T) {
	k := newRevKit(t, "issuer type")
	want := hex.EncodeToString(k.fp)
	for typ := range 256 {
		pkt := k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Type = byte(typ) })
		if typ == 0x20 {
			if fp, err := openpgp.RevocationIssuer(pkt); err != nil || fp != want {
				t.Errorf("type 0x20: RevocationIssuer = %q, %v; want %q", fp, err, want)
			}
			continue
		}
		fp, err := openpgp.RevocationIssuer(pkt)
		if err == nil || fp != "" {
			t.Errorf("type 0x%02X: RevocationIssuer = %q, %v; want an error and no issuer", typ, fp, err)
			continue
		}
		if !errors.Is(err, openpgp.ErrRevocation) || errors.Is(err, openpgp.ErrRevocationReason) || errors.Is(err, openpgp.ErrBinding) {
			t.Errorf("type 0x%02X: the fault is %v, want a plain ErrRevocation", typ, err)
		}
		if !strings.Contains(err.Error(), "type 0x20") {
			t.Errorf("type 0x%02X: the text %q does not say that a type 0x20 signature is wanted", typ, err.Error())
		}
		checkErrorText(t, fmt.Sprintf("type 0x%02X", typ), err)
		checkRevocationText(t, fmt.Sprintf("type 0x%02X", typ), err, pkt, want)
		// ReadRevocation gives the same kind of fault for the same packet.
		if _, rerr := k.read(t, "type", pkt); rerr == nil || !errors.Is(rerr, openpgp.ErrRevocation) || errors.Is(rerr, openpgp.ErrRevocationReason) {
			t.Errorf("type 0x%02X: ReadRevocation gives %v, want the same plain ErrRevocation", typ, rerr)
		}
	}
}

// The signatures that the writers of this package make, other than the revocation: the certification
// of NewPrimary and of ExtendPrimary (0x13), the binding of BindSubkey (0x18), the back-signature that
// the binding embeds (0x19), and a signature of a message (0x00). Each has an issuer fingerprint, and
// RevocationIssuer refuses each for its type (none is longer than the bound of a revocation).
func TestRevocationIssuerRefusesTheSignaturesThatTheWritersOfThePackageMake(t *testing.T) {
	w := buildWorld(t, nowWorldTimes())
	parts, err := openpgp.SplitCertificate(w.cert)
	if err != nil {
		t.Fatal(err)
	}
	more, err := openpgp.ExtendPrimary(rand.Reader, w.pp)
	if err != nil {
		t.Fatal(err)
	}
	var binding []byte
	for _, p := range splitPackets(t, w.bound) {
		if p.Tag == tagSignature {
			binding = p.Raw
		}
	}
	if binding == nil {
		t.Fatal("the bound subkey holds no signature packet")
	}
	for _, c := range []struct {
		name string
		pkt  []byte
		typ  byte
	}{
		{"the certification of NewPrimary", parts.Signatures[0], 0x13},
		{"the certification of ExtendPrimary", more, 0x13},
		{"the binding of BindSubkey", binding, 0x18},
		{"the back-signature of the binding", w.sub.BackSig, 0x19},
		{"a signature of a message", w.signMessage(t, nowSec().Add(-time.Hour), message), 0x00},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := parseSig(t, splitPackets(t, c.pkt)[0].Body).Type; got != c.typ {
				t.Fatalf("the packet is a signature of type 0x%02X, the test expects 0x%02X", got, c.typ)
			}
			fp, err := openpgp.RevocationIssuer(c.pkt)
			if err == nil || fp != "" {
				t.Fatalf("RevocationIssuer = %q, %v; want an error and no issuer", fp, err)
			}
			if !errors.Is(err, openpgp.ErrRevocation) || errors.Is(err, openpgp.ErrRevocationReason) {
				t.Errorf("the fault is %v, want a plain ErrRevocation", err)
			}
			if !strings.Contains(err.Error(), "type 0x20") {
				t.Errorf("the text %q does not say that a type 0x20 signature is wanted", err.Error())
			}
			t.Logf("a body of %d bytes: %v", len(bodyOf(t, c.pkt)), err)
			checkErrorText(t, c.name, err)
		})
	}
}

// The same signatures with the one fault taken away: the certification, the binding, the back-signature
// and a message signature are refused by RevocationIssuer for their type even when their body is short
// enough and holds one issuer fingerprint. This one is built by the tests' own writer with the types of
// the page, so that the text is the one of the type check and not of a bound.
func TestRevocationIssuerSaysTheTypeForTheTypesOfThePage(t *testing.T) {
	k := newRevKit(t, "issuer page types")
	for _, c := range []struct {
		name string
		typ  byte
	}{
		{"a message signature", 0x00}, {"a certification", 0x13}, {"a binding", 0x18},
		{"a back-signature", 0x19}, {"a direct-key signature", 0x1F}, {"a subkey revocation", 0x28},
		{"a certification revocation", 0x30}, {"a timestamp", 0x40},
	} {
		t.Run(c.name, func(t *testing.T) {
			pkt := k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Type = c.typ })
			if _, err := openpgp.RevocationIssuer(pkt); err == nil || !strings.Contains(err.Error(), "not a type 0x20 signature") {
				t.Errorf("the refusal is %v, want \"the signature is not a type 0x20 signature\"", err)
			}
		})
	}
}

// ---- a file is armour only when it starts as armour ---------------------------------------------

const headLine = "-----BEGIN PGP SIGNATURE-----"

// A binary revocation packet that holds the bytes of an armour head line is a binary packet: it is read
// as one, and is returned whole. The bytes stand in the unhashed area, in the two numbers of the
// signature, in a subpacket of the hashed area, or in a body that is no signature at all (the reader
// judges the frame only).
func TestReadSignatureFileReadsABinaryPacketThatHoldsTheArmourHeadLineAsABinaryPacket(t *testing.T) {
	k := newRevKit(t, "head inside")
	for _, head := range []string{headLine, "-----BEGIN", "-----BEGIN PGP SIGNATURE-----\n", "\n-----BEGIN PGP SIGNATURE-----\n\n", "-----BEGIN PGP PUBLIC KEY BLOCK-----"} {
		name := fmt.Sprintf("%q", head)
		t.Run(name, func(t *testing.T) {
			for what, pkt := range map[string][]byte{
				"the unhashed area": k.build(t, openpgp.Compromised, func(sp *sigSpec) {
					sp.Unhashed = append(sp.Unhashed, sub{Type: 100, Data: []byte(head)})
				}),
				"the hashed area": k.build(t, openpgp.Compromised, func(sp *sigSpec) {
					sp.Hashed = append(sp.Hashed, sub{Type: 100, Data: []byte(head)})
				}),
				"the signature numbers": k.build(t, openpgp.Compromised, func(sp *sigSpec) {
					sp.Numbers = func(_, _ *big.Int) []byte { return []byte(head) }
				}),
				"a body that is only the bytes": wrap(tagSignature, []byte(head)),
				"a body that ends with them":    wrap(tagSignature, cat(bytes.Repeat([]byte{4}, 50), []byte(head))),
			} {
				if !bytes.Contains(pkt, []byte("-----BEGIN")) {
					t.Fatalf("%s: the packet does not hold the bytes", what)
				}
				assertFile(t, what, pkt, pkt)
				// The same packet in its armour is read as before.
				assertFile(t, what+" armoured", goCryptoArmour(t, "PGP SIGNATURE", testOnly, pkt), pkt)
			}
		})
	}
}

// ReadSignatureFile judges the frame; ReadRevocation and RevocationIssuer say what the packet is. A
// packet that holds the head line in its unhashed area is a signature packet with an extra subpacket,
// which ReadRevocation refuses and RevocationIssuer reads, and none of them is told apart by the bytes.
func TestAPacketThatHoldsTheArmourHeadLineGoesThroughTheTwoReadersOfARevocationAsAnyOther(t *testing.T) {
	k := newRevKit(t, "head inside readers")
	pkt := k.build(t, openpgp.Compromised, func(sp *sigSpec) {
		sp.Unhashed = append(sp.Unhashed, sub{Type: 100, Data: []byte(headLine)})
	})
	got, err := openpgp.ReadSignatureFile(pkt)
	if err != nil {
		t.Fatalf("ReadSignatureFile: %v", err)
	}
	if fp, err := openpgp.RevocationIssuer(got); err != nil || fp != hex.EncodeToString(k.fp) {
		t.Errorf("RevocationIssuer = %q, %v", fp, err)
	}
	k.assertNotRevoked(t, "an extra unhashed subpacket", got, false)
	// The numbers of the signature replaced by the bytes: the frame is read, the signature is not.
	bad := k.build(t, openpgp.Compromised, func(sp *sigSpec) {
		sp.Numbers = func(_, _ *big.Int) []byte { return []byte(headLine) }
	})
	if got, err := openpgp.ReadSignatureFile(bad); err != nil || !bytes.Equal(got, bad) {
		t.Fatalf("ReadSignatureFile of numbers that hold the head line: %v", err)
	}
	k.assertNotRevoked(t, "numbers that are the head line", bad, false)
}

// A binary file that holds the head line and is not a whole signature packet is refused with the text
// that is true of a binary file: it does not say "armour", and it does not say "before". Each fault has
// its own text.
func TestReadSignatureFileRefusesABinaryFileThatHoldsTheArmourHeadLineWithTheTextOfABinaryFile(t *testing.T) {
	k := newRevKit(t, "head inside refused")
	good := k.build(t, openpgp.Compromised, func(sp *sigSpec) {
		sp.Unhashed = append(sp.Unhashed, sub{Type: 100, Data: []byte(headLine)})
	})
	body := bodyOf(t, good)
	block := goCryptoArmour(t, "PGP SIGNATURE", testOnly, k.made(t, openpgp.Compromised))
	for _, c := range []struct {
		name string
		in   []byte
		want string
	}{
		{"cut by one byte", good[:len(good)-1], "not a whole packet"},
		{"cut inside the head line", good[:bytes.Index(good, []byte("-----BEGIN"))+12], "not a whole packet"},
		{"cut after the header", good[:2], "not a whole packet"},
		{"with a byte after", cat(good, []byte{0}), "bytes after"},
		{"with a second packet after", cat(good, good), "bytes after"},
		{"with an armour block after", cat(good, block), "bytes after"},
		{"with a five-octet header", wrapLong(tagSignature, body), "shortest"},
		{"with an old-format header", oldHeader(tagSignature, body), "shortest"},
		{"as a key packet", wrap(tagPublicKey, body), "not a Signature"},
		{"as a user ID packet", wrap(tagUserID, body), "not a Signature"},
		{"with a partial length", cat([]byte{0xC2, 0xE0}, body), "not a whole packet"},
		{"with an indeterminate length", cat([]byte{0x80 | tagSignature<<2 | 3}, body), "not a whole packet"},
		{"with a length past the file", cat([]byte{0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, body), "not a whole packet"},
		{"longer than 1 KiB", wrap(tagSignature, cat([]byte(headLine), bytes.Repeat([]byte{4}, 1030))), "longer than 1024"},
		{"text and then the block", cat([]byte("a note\n"), block), "not a whole packet"},
		{"a line end and then the block", cat([]byte("\n"), block), "not a whole packet"},
		{"a space and then the block", cat([]byte(" "), block), "not a whole packet"},
		{"a zero byte and then the block", cat([]byte{0}, block), "not a whole packet"},
		{"the head line cut: text of 29 bytes", []byte(headLine), "armour"},
	} {
		t.Run(c.name, func(t *testing.T) {
			assertFileRefused(t, c.name, c.in, c.want)
			if c.want == "armour" {
				return
			}
			_, err := openpgp.ReadSignatureFile(c.in)
			for _, bad := range []string{"armour", "before", "second"} {
				if err != nil && strings.Contains(err.Error(), bad) {
					t.Errorf("the text %q says %q for a file that is binary", err.Error(), bad)
				}
			}
		})
	}
}

// An armour block still starts the file: a block read from the first byte is read as armour, with the
// texts of armour, and a file that starts with the head line and is wrong is refused as armour, whatever
// it holds after.
func TestAFileThatStartsWithTheHeadLineIsStillReadAsArmour(t *testing.T) {
	k := newRevKit(t, "head start")
	pkt := k.made(t, openpgp.Compromised)
	block := goCryptoArmour(t, "PGP SIGNATURE", testOnly, pkt)
	assertFile(t, "a block", block, pkt)
	assertFileRefused(t, "a block and a byte", cat(block, []byte{0}))
	assertFileRefused(t, "a block and a second block", cat(block, block), "second armour block")
	assertFileRefused(t, "a public key block", armourOpts{typ: "PGP PUBLIC KEY BLOCK"}.text(pkt), "PGP SIGNATURE")
	assertFileRefused(t, "the head line and a packet", cat([]byte(headLine+"\n"), pkt), "armour")
	assertFileRefused(t, "an age armour", []byte("-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n"), "age")
}

// The type is judged before the issuer is looked up: a signature of another type that also has no issuer
// fingerprint is refused for its type, the same order as ReadRevocation, which judges the type before
// the subpackets.
func TestRevocationIssuerJudgesTheTypeBeforeItLooksForTheIssuer(t *testing.T) {
	k := newRevKit(t, "issuer type first")
	for name, tweak := range map[string]func(*sigSpec){
		"no issuer":          func(sp *sigSpec) { sp.Type = 0x13; sp.Hashed = sp.Hashed[:2] },
		"two issuers":        func(sp *sigSpec) { sp.Type = 0x18; sp.Hashed = append(sp.Hashed, sp.Hashed[2]) },
		"a version 5 issuer": func(sp *sigSpec) { sp.Type = 0x19; sp.Hashed[2].Data[0] = 5 },
	} {
		t.Run(name, func(t *testing.T) {
			pkt := k.build(t, openpgp.Compromised, tweak)
			if _, err := openpgp.RevocationIssuer(pkt); err == nil || !strings.Contains(err.Error(), "type 0x20") {
				t.Errorf("the refusal is %v, want the text about the type", err)
			}
		})
	}
	// With the type right and the issuer wrong, the text is about the issuer.
	pkt := k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed = sp.Hashed[:2] })
	if _, err := openpgp.RevocationIssuer(pkt); err == nil || strings.Contains(err.Error(), "type 0x20") {
		t.Errorf("the refusal is %v, want a text about the issuer and not about the type", err)
	}
}
