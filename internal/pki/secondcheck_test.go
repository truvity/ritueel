package pki_test

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
)

// Nothing reaches the second reading of a body (the standard library reads the finished body) from outside: every input that
// the standard library's parser can refuse is refused earlier, in the kind of its source. The table of the checks of the code has one
// row for each thing that the parser can refuse; here each row has inputs that try to pass the earlier reading and fail the
// parser. intermediateTBS (helpers_test.go) fails the test on any error that names the standard library's reading or says
// "a fault of this package"; so a row that finds an input that passes the earlier reading and not the parser is a failing test.
//
// The rows, by what the parser refuses:
//   1. a name that is not a sequence, a set, an attribute, an OID (issuer and subject): TestHostileNames... and the name tables;
//   2. a string invalid in its type (UTF-8, PrintableString, IA5String): this file, strings;
//   3. OID arcs the parser cannot read (issuer, subject, extended key usage): this file, OIDs;
//   4. version, algorithm, trailing data, signature element: constants of the writer (no input), and the form tests of Assemble;
//   5. a serial that is negative, malformed or too long: this file, serials;
//   6. dates malformed: this file, dates;
//   7. a key that is not on the curve, a SubjectPublicKeyInfo that is not canonical: this file, keys;
//   8. a duplicate extension, basic constraints, key usage, extended key usage, key identifiers: this file, extensions;
//   9. name constraints (DNS and URI text, IP length and mask, an IP address as a URI): this file, and TestEveryTextOfAConstraintIsReadAsTheTableSays.

func TestNothingThatTheParserRefusesPassesTheEarlierReading(t *testing.T) {
	root := buildRoot(t, nil)
	tried, issued := 0, 0
	try := func(p pki.IntermediateParams) {
		t.Helper()
		tried++
		p = withIssuerInRoots(p) // the roots hold the issuer that the input chose
		tbs, err := intermediateTBS(t, p)
		if err == nil {
			issued++
			// An accepted input is a body that the standard library reads and that both signing and assembly take.
			if sig, err := pki.SignIntermediate(nil, root.key, p, tbs); err != nil {
				t.Errorf("an accepted input is not signed: %v", err)
			} else if _, err := pki.Assemble(tbs, sig, &root.key.PublicKey); err != nil {
				t.Errorf("an accepted input is not assembled: %v", err)
			}
		} else if !strings.HasPrefix(err.Error(), "pki: ") {
			t.Errorf("the error is not of the package: %v", err)
		}
	}
	base := func() (*testCSR, pki.IntermediateParams) {
		c := withExtensions(t, goodExtensions()...)
		return c, root.interParams(c)
	}

	t.Run("strings: every tag and every octet that a parser could refuse, as an issuer and as a subject", func(t *testing.T) {
		tags := []byte{tUTF8, tPrintable, tIA5, 0x14, 0x1e, 0x12, 0x1a, 0x1b, 0x1c, 0x19, 0x16, 0x0d}
		octets := [][]byte{{0x00}, {0x1f}, {0x20}, {'*'}, {'&'}, {'@'}, {'_'}, {0x7f}, {0x80}, {0xc3, 0xa9}, {0xff}, {0xc0, 0x80}, {0xed, 0xa0, 0x80}, {0xf4, 0x90, 0x80, 0x80}, []byte("ok")}
		attrs := []asn1.ObjectIdentifier{{2, 5, 4, 3}, {2, 5, 4, 6}, {2, 5, 4, 5}, {2, 5, 4, 46}, {0, 9, 2342, 19200300, 100, 1, 25}, {1, 2, 840, 113549, 1, 9, 1}, {1, 3, 6, 1, 4, 1, 99999, 7}}
		for _, a := range attrs {
			for _, tag := range tags {
				for _, o := range octets {
					name := nameOf(rdn(atv(mustOID(a), tlv(tag, o))))
					c, p := base()
					p.IssuerSubject = name
					try(p)
					c.RawSubject = name
					p2 := root.interParams(c)
					try(p2)
				}
			}
		}
	})

	t.Run("OIDs: arcs that the parser cannot read, in an issuer, a subject and an extended key usage", func(t *testing.T) {
		raws := [][]byte{
			{0x06, 0x00}, {0x06, 0x01, 0x80}, {0x06, 0x02, 0x80, 0x01}, {0x06, 0x03, 0x55, 0x04, 0x80}, {0x06, 0x01, 0x28}, {0x06, 0x01, 0x50},
			{0x06, 0x02, 0x88, 0x37}, {0x06, 0x02, 0x88, 0x38}, {0x06, 0x01, 0x7f}, {0x06, 0x03, 0x55, 0x04, 0x00},
			{0x06, 0x06, 0x2b, 0x81, 0x80, 0x80, 0x80, 0x00}, {0x06, 0x05, 0x2b, 0x8f, 0xff, 0xff, 0x7f}, {0x06, 0x06, 0x2b, 0x90, 0x80, 0x80, 0x80, 0x00},
			{0x06, 0x0a, 0x2b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, {0x06, 0x0b, 0x2b, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00},
			{0x06, 0x04, 0x2b, 0x06, 0x01, 0x05}, {0x06, 0x03, 0x69, 0x06, 0x01}, {0x06, 0x01, 0x2a},
		}
		for _, raw := range raws {
			for _, mk := range []func(oid []byte) []byte{
				func(oid []byte) []byte { return nameOf(rdn(tlv(0x30, oid, tlv(tUTF8, []byte("x"))))) },
				func(oid []byte) []byte {
					return nameOf(rdn(tlv(0x30, oid, tlv(tUTF8, []byte("x")))), rdn(atv(oidAttrCN, str(tUTF8, "ca"))))
				},
			} {
				name := mk(raw)
				c, p := base()
				p.IssuerSubject = name
				try(p)
				c.RawSubject = name
				try(root.interParams(c))
			}
			eku := tlv(0x30, raw)
			c := withExtensions(t, extBasicConstraints(), extKeyUsage(kuKeyCertSign), extNameConstraints("example.org"), pkix.Extension{Id: oidExtKeyUsage, Value: eku})
			try(root.interParams(c))
			c2 := withExtensions(t, extBasicConstraints(), extKeyUsage(kuKeyCertSign), extNameConstraints("example.org"), pkix.Extension{Id: oidExtKeyUsage, Value: tlv(0x30, mustOID(asn1.ObjectIdentifier{2, 5, 29, 37}), raw)})
			try(root.interParams(c2))
		}
	})

	t.Run("serials and dates", func(t *testing.T) {
		c := withExtensions(t, goodExtensions()...)
		for bits := 1; bits <= 170; bits++ {
			for _, delta := range []int64{-1, 0, 1} {
				n := new(big.Int).Lsh(big.NewInt(1), uint(bits))
				n.Add(n, big.NewInt(delta))
				p := root.interParams(c)
				p.Serial = n
				try(p)
				p.Serial = new(big.Int).Neg(n)
				try(p)
			}
		}
		for _, y := range []int{-1, 0, 1, 2, 1949, 1950, 1951, 2049, 2050, 2051, 9997, 9998, 9999, 10000, 10001} {
			for _, m := range []time.Month{time.January, time.February, time.November, time.December} {
				for _, d := range []int{1, 28, 29, 30, 31} {
					for _, sec := range []int{0, 59} {
						p := root.interParams(c)
						p.CeremonyTime = time.Date(y, m, d, 23, 59, sec, 0, time.UTC)
						try(p)
						p.CeremonyTime = p.CeremonyTime.Add(time.Nanosecond)
						try(p)
					}
				}
			}
		}
	})

	t.Run("keys: every octet of the SubjectPublicKeyInfo of the request changed, and the keys of the issuer", func(t *testing.T) {
		c := withExtensions(t, goodExtensions()...)
		spki := c.SPKI()
		for i := range spki {
			for _, mask := range []byte{0x01, 0x80, 0xff} {
				d := copyCSR(c)
				d.RawSubjectPublicKeyInfo = append([]byte(nil), spki...)
				d.RawSubjectPublicKeyInfo[i] ^= mask
				try(root.interParams(d))
			}
		}
		for name, key := range badKeys(t) {
			p := root.interParams(c)
			p.IssuerKey = key
			tried++
			_, err := intermediateTBS(t, p)
			if err == nil {
				t.Errorf("an issuer key %s is accepted", name)
			}
		}
	})

	t.Run("extensions: duplicates, basic constraints, key usage, extended key usage, key identifiers", func(t *testing.T) {
		goodBC, goodKU, goodNC := extBasicConstraints(), extKeyUsage(kuKeyCertSign, kuCRLSign), extNameConstraints("example.org")
		ext := func(id asn1.ObjectIdentifier, critical bool, v []byte) pkix.Extension {
			return pkix.Extension{Id: id, Critical: critical, Value: v}
		}
		sets := [][]pkix.Extension{
			{goodBC, goodKU, goodNC, goodBC}, {goodBC, goodKU, goodNC, goodKU}, {goodBC, goodKU, goodNC, goodNC},
			{goodBC, goodKU, goodNC, extExtKeyUsage(false, oidServerAuth), extExtKeyUsage(true, oidClientAuth)},
			{goodBC, goodKU, goodNC, ext(oidSubjectKeyID, false, tlv(0x04, make([]byte, 20)))},
			{goodBC, goodKU, goodNC, ext(oidAuthorityKeyID, false, tlv(0x30, tlv(0x80, make([]byte, 20))))},
			{goodBC, goodKU, goodNC, ext(asn1.ObjectIdentifier{2, 5, 29, 17}, false, tlv(0x30))},
			{goodBC, goodKU, goodNC, ext(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, false, tlv(0x30))},
		}
		for _, bc := range [][]byte{{0x30, 0x00}, {0x30, 0x03, 0x01, 0x01, 0xff}, {0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01}, {0x30, 0x06, 0x01, 0x01, 0x00, 0x02, 0x01, 0x00}, {0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0xff}, {0x30, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x00}, {}, {0x04, 0x00}} {
			sets = append(sets, []pkix.Extension{ext(oidBasicConstraints, true, bc), goodKU, goodNC}, []pkix.Extension{ext(oidBasicConstraints, false, bc), goodKU, goodNC})
		}
		for unused := byte(0); unused < 8; unused++ {
			for b := 0; b < 256; b += 1 {
				for _, ln := range []int{1, 2} {
					v := []byte{0x03, byte(ln + 1), unused, byte(b)}
					if ln == 2 {
						v = []byte{0x03, 0x03, unused, byte(b), 0x80}
					}
					sets = append(sets, []pkix.Extension{goodBC, ext(oidKeyUsage, true, v), goodNC})
				}
			}
		}
		for _, v := range [][]byte{{0x30, 0x00}, {0x30, 0x02, 0x05, 0x00}, {0x30, 0x03, 0x06, 0x01, 0x2a}, {0x30, 0x80, 0x00, 0x00}, {0x31, 0x00}, {0x04, 0x00}, {}, {0x30, 0x01}, {0x30, 0x0a, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00}} {
			sets = append(sets, []pkix.Extension{goodBC, goodKU, goodNC, ext(oidExtKeyUsage, false, v)})
		}
		for _, es := range sets {
			try(root.interParams(withExtensions(t, es...)))
		}
	})

	t.Run("name constraints: the forms of a subtree, as permitted and as excluded", func(t *testing.T) {
		for l := 0; l <= 40; l++ {
			for _, fill := range []byte{0x00, 0xff, 0x80, 0x0f} {
				ip := ncSub(tlv(0x87, append([]byte(nil), repeatByte(fill, l)...)))
				try(root.interParams(ncRequest(t, ncValue([][]byte{ncSub(dns("example.org"))}, [][]byte{ip}))))
				try(root.interParams(ncRequest(t, ncValue([][]byte{ip}, nil))))
			}
		}
		for _, tag := range []byte{0x80, 0x81, 0x82, 0x84, 0x85, 0x86, 0x87, 0x88, 0xa0, 0xa3, 0xa4, 0xa5} {
			for _, body := range [][]byte{{}, []byte("example.org"), []byte(".example.org"), []byte("10.0.0.1"), []byte("a@example.org"), {0xff}, repeatByte('a', 300)} {
				try(root.interParams(ncRequest(t, ncValue([][]byte{ncSub(tlv(tag, body))}, nil))))
			}
		}
	})

	t.Logf("%d inputs tried, %d of them issued, the rest refused by the readings before the second one", tried, issued)
	if tried < 6000 || issued < 100 {
		t.Errorf("tried %d, issued %d: the rows are too few or none reaches the end", tried, issued)
	}
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
