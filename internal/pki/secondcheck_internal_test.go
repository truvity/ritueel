package pki

import (
	"encoding/asn1"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// The second reading of a body, `readable`: the standard library reads the finished body. Nothing reaches it from outside
// (the readings before it refuse every input that it would refuse), so these tests call it directly, on bodies that the
// builders cannot write because the parts are hostile: the parts are given to the internal writers, which write what they are
// given. It must refuse them; and the words of the builders that call it must say that reaching it is a fault of the package.

func TestTheSecondReadingRefusesBodiesThatTheBuildersCannotWrite(t *testing.T) {
	key := newTestKey(t)
	_, point, err := spki(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	spkiDER, _, err := spki(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serial := big.NewInt(0).SetBytes([]byte{0x4b, 1, 2, 3, 4, 5, 6, 7, 8})
	nb := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	na, err := AddMonths(nb, IntermediateValidityMonths)
	if err != nil {
		t.Fatal(err)
	}
	name := func(b []byte) []byte { // one common name, a UTF8String of the given octets
		return shortSeq(short(tagSet, shortSeq(oid(oidCommonName), short(tagUTF8String, b))))
	}
	nc := []byte{0x30, 0x0e, 0xa0, 0x0c, 0x30, 0x0a, 0x82, 0x08, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 'x'}
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{oidServerAuth, oidClientAuth})
	if err != nil {
		t.Fatal(err)
	}
	asked := requested{keyUsage: keyUsageValue(usageKeyCertSign, usageCRLSign), nameConstraints: nc, extKeyUsage: eku}
	intermediate := func(issuer, subject []byte) []byte {
		body, err := intermediateBody(serial, issuer, nb, na, subject, spkiDER, keyIdentifier(point), keyIdentifier(point[:len(point)-1]), asked)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	good := name([]byte("acme root"))
	if err := readable(intermediate(good, name([]byte("acme ca"))), serial, nb, na); err != nil {
		t.Fatalf("a body of good parts is refused: %v", err)
	}
	for _, bad := range [][]byte{{0xff}, {0xc0, 0x80}, {0xe2, 0x82}, {0xed, 0xa0, 0x80}, {0xf4, 0x90, 0x80, 0x80}, []byte("a\x80")} {
		for what, body := range map[string][]byte{
			"as the issuer":  intermediate(name(bad), name([]byte("acme ca"))),
			"as the subject": intermediate(good, name(bad)),
		} {
			err := readable(body, serial, nb, na)
			if err == nil {
				t.Errorf("%q %s: the body is read", bad, what)
			} else if !strings.Contains(err.Error(), "x509") {
				t.Errorf("%q %s: the error is not the standard library's: %v", bad, what, err)
			}
		}
	}
	// A root whose name is not UTF-8: the root builder never writes one (its name is ASCII), the writer writes what it is given.
	rootOK, err := rootBody(serial, "Acme Root K", nb, spkiDER, point)
	if err != nil {
		t.Fatal(err)
	}
	rootEnd, _ := AddMonths(nb, RootValidityMonths)
	if err := readable(rootOK, serial, nb, rootEnd); err != nil {
		t.Errorf("a good root body is refused: %v", err)
	}
	rootBad, err := rootBody(serial, "Acme \xff Root K", nb, spkiDER, point)
	if err != nil {
		t.Fatal(err)
	}
	if err := readable(rootBad, serial, nb, rootEnd); err == nil {
		t.Error("a root whose name is not UTF-8 is read")
	}
}

// The builders that call the second reading say, in the text of its refusal, that reaching it is a fault of this package, and
// they call it. A refusal at that place cannot be made by any input, so the words and the call are held by reading the
// source of the two builders: a break that removes the call, or the words, is found here.
func TestTheBuildersCallTheSecondReadingAndSayWhatItsRefusalMeans(t *testing.T) {
	for _, f := range []string{"intermediate.go", "root.go"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(data)
		if !strings.Contains(src, "\tif err := readable(body, p.Serial, notBefore, notAfter); err != nil {\n") {
			t.Errorf("%s does not call the second reading of the body and refuse what it refuses", f)
		}
		if !strings.Contains(src, "the body is not a certificate that the standard library reads (a fault of this package") {
			t.Errorf("%s does not say that a refusal of the second reading is a fault of this package", f)
		}
		if n := strings.Count(src, "readable("); n != 1 {
			t.Errorf("%s calls the second reading %d times, want once", f, n)
		}
	}
}
