package openpgp_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// RevocationIssuer names the primary that a revocation signature claims, so that a caller picks the
// primary before it verifies. It reads the frame as ReadRevocation does and verifies nothing.

func issuerSafely(t testing.TB, what string, pkt []byte) (fp string, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: RevocationIssuer panicked: %v", what, r)
			fp, err = "", errors.New("panic")
		}
	}()
	return openpgp.RevocationIssuer(pkt)
}

// assertNoIssuer fails the test unless RevocationIssuer refuses pkt with an ErrRevocation, returns
// nothing, and shows no byte of the packet.
func assertNoIssuer(t testing.TB, what string, pkt []byte) {
	t.Helper()
	before := bytes.Clone(pkt)
	fp, err := issuerSafely(t, what, pkt)
	if err == nil {
		t.Errorf("%s: RevocationIssuer = %q, want an error", what, fp)
		return
	}
	if fp != "" {
		t.Errorf("%s: %q was returned with the error %v", what, fp, err)
	}
	if !errors.Is(err, openpgp.ErrRevocation) || errors.Is(err, openpgp.ErrRevocationReason) || errors.Is(err, openpgp.ErrParams) ||
		errors.Is(err, openpgp.ErrBinding) || errors.Is(err, openpgp.ErrAnswer) {
		t.Errorf("%s: error = %v, want a plain ErrRevocation", what, err)
	}
	if !bytes.Equal(pkt, before) {
		t.Errorf("%s: RevocationIssuer changed its input", what)
	}
	checkErrorText(t, what, err)
	checkRevocationText(t, what, err, pkt, "")
}

func TestRevocationIssuerNamesThePrimaryForEachReason(t *testing.T) {
	k := newRevKit(t, "issuer names")
	other := newRevKit(t, "issuer names other")
	for _, c := range allReasons {
		t.Run(c.name, func(t *testing.T) {
			pkt := k.made(t, c.r)
			before := bytes.Clone(pkt)
			got, err := openpgp.RevocationIssuer(pkt)
			if err != nil {
				t.Fatalf("RevocationIssuer: %v", err)
			}
			if want := hex.EncodeToString(k.fp); got != want {
				t.Errorf("the issuer is %q, want %q", got, want)
			}
			if want := fingerprintOf(t, &k.key.PublicKey, created); got != want {
				t.Errorf("the issuer is %q, Fingerprint says %q", got, want)
			}
			if len(got) != 40 || got != strings.ToLower(got) {
				t.Errorf("the issuer %q is not 40 lower-case digits", got)
			}
			if !bytes.Equal(pkt, before) {
				t.Error("RevocationIssuer changed its input")
			}
			if got == hex.EncodeToString(other.fp) {
				t.Error("the issuer is the fingerprint of another key")
			}
			// The two readers agree on the issuer.
			rev := k.assertRevoked(t, c.name, pkt, c.r)
			if rev != nil && rev.Issuer != got {
				t.Errorf("ReadRevocation says %q, RevocationIssuer says %q", rev.Issuer, got)
			}
		})
	}
}

func TestRevocationIssuerVerifiesNothing(t *testing.T) {
	k := newRevKit(t, "issuer verifies nothing")
	other := newRevKit(t, "issuer verifies nothing other")
	want := hex.EncodeToString(k.fp)
	for name, pkt := range map[string][]byte{
		"a signature made by another key":  k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Key = other.key }),
		"a wrong start of the digest":      k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.TagXOR = [2]byte{1, 1} }),
		"a signature over other bytes":     k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Data = nil }),
		"a reason that is not one of four": k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed[1].Data = []byte{9, 'x'} }),
		"no reason at all":                 k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed = []sub{sp.Hashed[0], sp.Hashed[2]} }),
		"a creation time before the key":   k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed[0].Data = u32(5) }),
		"an extra subpacket":               k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 100, Data: []byte{1}}) }),
		"a critical subpacket":             k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed[1].Critical = true }),
		"the last byte of the number":      func() []byte { p := k.made(t, openpgp.Compromised); p[len(p)-1] ^= 1; return p }(),
	} {
		t.Run(name, func(t *testing.T) {
			// ReadRevocation refuses each of these, RevocationIssuer names the primary, as the page of its
			// use says: the caller picks the primary first and then verifies.
			k.assertNotRevoked(t, name, pkt, strings.Contains(name, "reason"))
			got, err := openpgp.RevocationIssuer(pkt)
			if err != nil || got != want {
				t.Errorf("RevocationIssuer = %q, %v; want %q", got, err, want)
			}
		})
	}
}

func TestRevocationIssuerRefusesAPacketWithNoOrTwoIssuerFingerprints(t *testing.T) {
	k := newRevKit(t, "issuer none")
	other := newRevKit(t, "issuer none other")
	fpOf := func(v byte, fp []byte) []byte { return append([]byte{v}, fp...) }
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"no issuer fingerprint", func(sp *sigSpec) { sp.Hashed = sp.Hashed[:2] }},
		{"the issuer fingerprint in the unhashed area only", func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sp.Hashed[2])
			sp.Hashed = sp.Hashed[:2]
		}},
		{"no hashed subpacket", func(sp *sigSpec) { sp.Hashed = nil }},
		{"two issuer fingerprints that are the same", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sp.Hashed[2]) }},
		{"two issuer fingerprints of two keys", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 33, Data: fpOf(4, other.fp)}) }},
		{"two, the second of version 5", func(sp *sigSpec) {
			sp.Hashed = append(sp.Hashed, sub{Type: 33, Data: fpOf(5, bytes.Repeat([]byte{1}, 32))})
		}},
		{"a version 5 fingerprint", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(5, bytes.Repeat([]byte{1}, 32)) }},
		{"a version 6 fingerprint", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(6, bytes.Repeat([]byte{1}, 32)) }},
		{"a version 3 byte on 20 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(3, k.fp) }},
		{"a version 5 byte on 20 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(5, k.fp) }},
		{"19 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(4, k.fp[:19]) }},
		{"21 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = fpOf(4, append(bytes.Clone(k.fp), 1)) }},
		{"no version byte", func(sp *sigSpec) { sp.Hashed[2].Data = bytes.Clone(k.fp) }},
		{"an empty subpacket", func(sp *sigSpec) { sp.Hashed[2].Data = nil }},
		{"only the key ID", func(sp *sigSpec) { sp.Hashed = sp.Hashed[:2] }},
	} {
		t.Run(c.name, func(t *testing.T) { assertNoIssuer(t, c.name, k.build(t, openpgp.Compromised, c.tweak)) })
	}
}

// RevocationIssuer reads the frame as ReadRevocation does, with the same bounds and the same shape of
// header, so that the primary a caller picks is for a packet that ReadRevocation would also read.
func TestRevocationIssuerHoldsTheFrameOfReadRevocation(t *testing.T) {
	k := newRevKit(t, "issuer frame")
	good := k.made(t, openpgp.Compromised)
	body := bodyOf(t, good)
	for name, pkt := range map[string][]byte{
		"a nil packet":                nil,
		"an empty packet":             {},
		"one byte":                    {0xC2},
		"a header only":               {0xC2, 0},
		"a cut by one byte":           good[:len(good)-1],
		"a byte after":                cat(good, []byte{0}),
		"two packets":                 cat(good, good),
		"an old-format header":        oldHeader(tagSignature, body),
		"a five-octet header":         wrapLong(tagSignature, body),
		"a partial length":            cat([]byte{0xC2, 0xE0}, body),
		"an indeterminate length":     cat([]byte{0x80 | tagSignature<<2 | 3}, body),
		"the tag of a key":            wrap(tagPublicKey, body),
		"the tag of a user ID":        wrap(tagUserID, body),
		"version 5":                   withBody(append([]byte{5}, body[1:]...)),
		"version 3":                   withBody(append([]byte{3}, body[1:]...)),
		"a hashed area past the body": withBody(append([]byte{4, 0x20, 19, 9, 0xFF, 0xFF}, body[6:]...)),
		"zeros":                       withBody(make([]byte, 80)),
		"a body of 513 bytes": k.build(t, openpgp.Compromised, func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sub{Type: 100, Data: bytes.Repeat([]byte{1}, 420)})
		}),
		"a body of 1 MiB": withBody(bytes.Repeat([]byte{4}, 1<<20)),
	} {
		t.Run(name, func(t *testing.T) { assertNoIssuer(t, name, pkt) })
	}
	t.Run("33 subpackets in the hashed area", func(t *testing.T) {
		var extra []sub
		for i := range 30 {
			extra = append(extra, sub{Type: byte(100 + i%20), Data: []byte{1}})
		}
		pkt := k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, extra...) })
		assertNoIssuer(t, "33 subpackets", pkt)
		if _, err := openpgp.RevocationIssuer(pkt); err == nil || !strings.Contains(err.Error(), "more subpackets") {
			t.Errorf("the refusal is %v, want one that says there are more subpackets than the limit", err)
		}
	})
	t.Run("32 subpackets in the hashed area are read", func(t *testing.T) {
		var extra []sub
		for i := range 29 {
			extra = append(extra, sub{Type: byte(100 + i%20), Data: []byte{1}})
		}
		pkt := k.build(t, openpgp.Compromised, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, extra...) })
		if fp, err := openpgp.RevocationIssuer(pkt); err != nil || fp != hex.EncodeToString(k.fp) {
			t.Errorf("RevocationIssuer = %q, %v; want the issuer of a packet of 32 subpackets", fp, err)
		}
	})
	t.Run("a body of 512 bytes is read", func(t *testing.T) {
		pad := 300
		var pkt []byte
		for range 4 {
			pkt = k.build(t, openpgp.Compromised, func(sp *sigSpec) {
				sp.Unhashed = append(sp.Unhashed, sub{Type: 100, Data: bytes.Repeat([]byte{1}, pad)})
			})
			if got := len(bodyOf(t, pkt)); got == 512 {
				break
			} else {
				pad += 512 - got
			}
		}
		if got := len(bodyOf(t, pkt)); got != 512 {
			t.Fatalf("the test made a body of %d bytes", got)
		}
		if fp, err := openpgp.RevocationIssuer(pkt); err != nil || fp != hex.EncodeToString(k.fp) {
			t.Errorf("RevocationIssuer = %q, %v; want the issuer of a body of exactly 512 bytes", fp, err)
		}
	})
}

// Whatever ReadRevocation accepts, RevocationIssuer names the issuer that it names, in the form that it
// returns.
func TestRevocationIssuerAgreesWithReadRevocationOnWhatItAccepts(t *testing.T) {
	k := newRevKit(t, "issuer agrees")
	for _, c := range allReasons {
		for i := range 3 {
			t.Run(fmt.Sprintf("%s %d", c.name, i), func(t *testing.T) {
				pkt := k.made(t, c.r)
				rev := k.assertRevoked(t, c.name, pkt, c.r)
				fp, err := openpgp.RevocationIssuer(pkt)
				if err != nil || rev == nil || fp != rev.Issuer {
					t.Errorf("RevocationIssuer = %q, %v; ReadRevocation says %+v", fp, err, rev)
				}
			})
		}
	}
}
