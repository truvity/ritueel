package piv_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
	"ritueel.id/ritueel/internal/handoff/evidence/piv"
)

// The page, "Evidence for a PIV key (check 7)" and the table of extensions: a good slot certificate gives the
// key, the firmware, the PIN and touch policy, and the slot, serial number and form factor.
func TestAGoodSlotCertificateGivesTheEvidenceThePageNames(t *testing.T) {
	m := newMaker(t)
	b := m.Bundle(t)
	v := newVerifier(t, b)
	key := p384(t)
	ev, err := verifyPIV(t, v, m.PIVEvidence(t, key, attesttest.Slot{}))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Key.Equal(key) {
		t.Error("the key is not the attested key")
	}
	if ev.Firmware != "5.8.0" || ev.PINPolicy != handoff.PINOnce || ev.TouchPolicy != "never" {
		t.Errorf("firmware %q, PIN %q, touch %q", ev.Firmware, ev.PINPolicy, ev.TouchPolicy)
	}
	if ev.Unprotected {
		t.Error("a key in a token is marked unprotected")
	}
	if len(ev.SignPrincipals) != 0 {
		t.Errorf("principals %v", ev.SignPrincipals)
	}
	want := map[string]string{
		attest.DetailSlot:          "9c",
		attest.DetailSerial:        "12345678",
		attest.DetailFormFactor:    "2",
		attest.DetailPolicyRead:    "true",
		attest.DetailBundleVersion: b.Version(),
		attest.DetailBundleSHA256:  b.SHA256(),
	}
	if !maps.Equal(ev.Details, want) {
		t.Errorf("details %v, want %v", ev.Details, want)
	}
	// The names of the details are the ones of the ceremony record (proposed).
	for k, wantName := range map[string]string{
		attest.DetailSlot: "slot", attest.DetailSerial: "serial", attest.DetailFormFactor: "form_factor",
		attest.DetailPolicyRead: "policy_read", attest.DetailBundleVersion: "attestation_bundle_version",
		attest.DetailBundleSHA256: "attestation_bundle_sha256",
	} {
		if k != wantName {
			t.Errorf("the detail key %q, want %q", k, wantName)
		}
	}
}

// The request is not read by this verifier, and the proof's other members do not matter.
func TestTheRequestIsNotRead(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	ev := m.PIVEvidence(t, p384(t), attesttest.Slot{})
	p := proofOf(handoff.StorePIV, ev)
	for _, r := range []*handoff.Request{nil, {}, {Stem: "x", Files: map[string][]byte{"proof.json": []byte("junk")}}} {
		got, err := v.Verify(t.Context(), r, p, clock)
		if err != nil || got == nil {
			t.Errorf("request %+v: %v", r, err)
		}
	}
}

// The result is a copy: a change to the key or to the details that the caller gets reaches neither the next
// answer nor the proof's evidence.
func TestTheResultSharesNothing(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	wantKey := p384(t)
	ev := m.PIVEvidence(t, wantKey, attesttest.Slot{})
	first, err := verifyPIV(t, v, ev)
	if err != nil {
		t.Fatal(err)
	}
	first.Key.X.SetInt64(1) //nolint:staticcheck // the coordinates are the only way to change a key in place
	first.Key.Y.SetInt64(1) //nolint:staticcheck // the coordinates are the only way to change a key in place
	first.Details[attest.DetailSlot] = "changed"
	first.Details["extra"] = "x"
	first.Firmware = "0.0.0"
	second, err := verifyPIV(t, v, ev)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Key.Equal(wantKey) {
		t.Error("a change to the returned key reached the next answer")
	}
	if second.Details[attest.DetailSlot] != "9c" || second.Details["extra"] != "" || second.Firmware != "5.8.0" {
		t.Errorf("a change to the returned value reached the next answer: %+v", second)
	}
}

// Slots lists the 24 slots of record 0003, rule 3, in its order: 9a, 9c, 9d, 9e, then 82 to 95 in
// hexadecimal, lower case. Each call gives a new slice.
func TestSlotsAreTheTwentyFourOfTheRecord(t *testing.T) {
	want := []string{
		"9a", "9c", "9d", "9e",
		"82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
		"90", "91", "92", "93", "94", "95",
	}
	got := piv.Slots()
	if !slices.Equal(got, want) {
		t.Fatalf("slots %v, want %v", got, want)
	}
	if len(got) != 24 {
		t.Errorf("%d slots", len(got))
	}
	got[0] = "zz"
	if piv.Slots()[0] != "9a" {
		t.Error("Slots returned a shared slice")
	}
}

// The page: the slot certificate's subject is "YubiKey PIV Attestation <slot>" where the slot is one of the
// 24. All 24 are accepted, and the slot is in the details as the page writes it.
func TestEverySlotIsAccepted(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	for _, slot := range piv.Slots() {
		t.Run(slot, func(t *testing.T) {
			ev, err := verifyPIV(t, v, m.PIVEvidence(t, p384(t), attesttest.Slot{Subject: "YubiKey PIV Attestation " + slot}))
			if err != nil {
				t.Fatal(err)
			}
			if ev.Details[attest.DetailSlot] != slot {
				t.Errorf("slot %q, want %q", ev.Details[attest.DetailSlot], slot)
			}
		})
	}
}

// Refused subjects. A subject that is not exactly the page's is refused with proof-invalid.
func TestASubjectThatIsNotAPIVSlotIsRefused(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	for _, cn := range []string{
		"YubiKey PIV Attestation f9", "YubiKey PIV Attestation 9b", "YubiKey PIV Attestation 81",
		"YubiKey PIV Attestation 96", "YubiKey PIV Attestation 9C", "YubiKey PIV Attestation 8A",
		"YubiKey PIV Attestation 8F", "YubiKey PIV Attestation 9A", "YubiKey PIV Attestation 9a ",
		"YubiKey PIV Attestation  9a", " YubiKey PIV Attestation 9a", "YubiKey PIV Attestation",
		"YubiKey PIV Attestation ", "YubiKey PIV Attestation 9", "YubiKey PIV Attestation 9a9c",
		"YubiKey PIV Attestation 9a 9c", "YubiKey PIV Attestation 0x9a", "YubiKey PIV Attestation 130",
		"YubiKey PIV Attestation 09", "YubiKey PIV Attestation 00", "YubiKey PIV Attestation 80",
		"YubiKey PIV Attestation f9 ", "YubiKey PIV Attestation 9с", "YubiKey PIV Attestation 9c\x00",
		"YubiKey PIV Attestation \x009c", "YubiKey OPGP Attestation 9a", "YubiKey OPGP Attestation SIG",
		"yubikey piv attestation 9c", "YubiKey PIV attestation 9c", "YubiKey PIV Attestation: 9c",
		"PIV Attestation 9c", "9c", "Yubico PIV Attestation 9c", "YubiKey PIV Attestation 9c\n",
		"YubiKey PIV Attestation 9c, O=acme", "YubiKey PIV Attestation 9c",
		"x" + strings.Repeat("YubiKey PIV Attestation 9c", 40),
		"YubiKey PIV Attestation " + strings.Repeat("9", 1000),
		strings.Repeat("a", 1000),
	} {
		t.Run(fmt.Sprintf("%.60q", cn), func(t *testing.T) {
			ev, err := verifyPIV(t, v, m.PIVEvidence(t, p384(t), attesttest.Slot{Subject: cn}))
			wantRefusal(t, ev, err, handoff.CodeProofInvalid)
		})
	}
}

// ATV is an attribute of a name: the common name with a value of the given ASN.1 tag, or another type.
type atv struct {
	oid asn1.ObjectIdentifier
	tag int
	val string
}

var (
	oidCN  = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOrg = asn1.ObjectIdentifier{2, 5, 4, 10}
)

const goodCN = "YubiKey PIV Attestation 9c"

// rawNameBytes writes a DER name from relative names, each a list of attributes whose values carry the tag.
// It panics on an error of the encoder, which only a test that built a wrong value can cause.
func rawNameBytes(rdns ...[]atv) []byte {
	var seq pkix.RDNSequence
	for _, r := range rdns {
		var set pkix.RelativeDistinguishedNameSET
		for _, a := range r {
			set = append(set, pkix.AttributeTypeAndValue{Type: a.oid, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: a.tag, Bytes: []byte(a.val)}})
		}
		seq = append(seq, set)
	}
	b, err := asn1.Marshal(seq)
	if err != nil {
		panic(err)
	}
	return b
}

// rawName is rawNameBytes for a test that has a testing value at hand.
func rawName(t testing.TB, rdns ...[]atv) []byte {
	t.Helper()
	return rawNameBytes(rdns...)
}

// evidenceWithName is the evidence of a slot certificate whose subject is the raw DER name.
func evidenceWithName(t testing.TB, m *attesttest.Maker, name []byte) []byte {
	t.Helper()
	return m.PIVEvidence(t, p384(t), attesttest.Slot{
		Tweak: func(c *x509.Certificate) { c.RawSubject = name },
		Check: attesttest.CheckNone,
	})
}

// The subject is exactly one relative name of one attribute, the common name, as a UTF8String or a
// PrintableString. Anything else about the shape is refused: more names, more attributes, another
// attribute, an empty name, a constructed value. (The page names only the text; the string types other
// than the two are refused as the code stands, which fails closed.)
func TestTheSubjectIsExactlyOneCommonName(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	const utf8, printable, ia5, t61, bmp = 0x0c, 0x13, 0x16, 0x14, 0x1e
	cn := func(tag int, s string) atv { return atv{oidCN, tag, s} }
	cases := []struct {
		name string
		rdns [][]atv
		ok   bool
	}{
		{"a UTF8String", [][]atv{{cn(utf8, goodCN)}}, true},
		{"a PrintableString", [][]atv{{cn(printable, goodCN)}}, true},
		{"an IA5String", [][]atv{{cn(ia5, goodCN)}}, false},
		{"a TeletexString", [][]atv{{cn(t61, goodCN)}}, false},
		{"a BMPString", [][]atv{{cn(bmp, goodCN)}}, false},
		{"an empty subject", nil, false},
		{"an empty common name", [][]atv{{cn(utf8, "")}}, false},
		{"two common names", [][]atv{{cn(utf8, goodCN)}, {cn(utf8, goodCN)}}, false},
		{"two common names, the second another slot", [][]atv{{cn(utf8, goodCN)}, {cn(utf8, "YubiKey PIV Attestation 9a")}}, false},
		{"a common name and an organisation", [][]atv{{cn(utf8, goodCN)}, {{oidOrg, utf8, "acme"}}}, false},
		{"an organisation and a common name", [][]atv{{{oidOrg, utf8, "acme"}}, {cn(utf8, goodCN)}}, false},
		{"a multi-valued relative name", [][]atv{{cn(utf8, goodCN), {oidOrg, utf8, "acme"}}}, false},
		{"a multi-valued relative name of two common names", [][]atv{{cn(utf8, goodCN), cn(utf8, goodCN)}}, false},
		{"the right text under the organisation", [][]atv{{{oidOrg, utf8, goodCN}}}, false},
		{"the right text under another attribute", [][]atv{{{asn1.ObjectIdentifier{2, 5, 4, 11}, utf8, goodCN}}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, err := verifyPIV(t, v, evidenceWithName(t, m, rawName(t, c.rdns...)))
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantRefusal(t, ev, err, handoff.CodeProofInvalid)
		})
	}
	// A UTF8String that is constructed (BER), holding the right text, is not the page's subject.
	cons, err := asn1.Marshal(pkix.RDNSequence{{pkix.AttributeTypeAndValue{Type: oidCN, Value: asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: utf8, IsCompound: true, Bytes: []byte(goodCN),
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	evc, errc := verifyPIV(t, v, evidenceWithName(t, m, cons))
	wantRefusal(t, evc, errc, handoff.CodeProofInvalid)
	// A value that is a constructed element.
	seq := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: nil}
	set, err := asn1.Marshal(pkix.RDNSequence{{pkix.AttributeTypeAndValue{Type: oidCN, Value: seq}}})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := verifyPIV(t, v, evidenceWithName(t, m, set))
	wantRefusal(t, ev, err, handoff.CodeProofInvalid)
}

// The direct reader of the subject, on the DER of names that are not certificates' at all: never a panic.
func TestSlotOfOnHostileNames(t *testing.T) {
	good := rawName(t, []atv{{oidCN, 0x0c, goodCN}})
	// A name whose attribute has a third element after the type and the value, the text being the page's.
	der := func(v any) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	constructed := func(tag int, parts ...[]byte) []byte {
		return der(asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, IsCompound: true, Bytes: bytes.Join(parts, nil)})
	}
	attribute := constructed(asn1.TagSequence, der(oidCN), der(asn1.RawValue{Class: asn1.ClassUniversal, Tag: 0x0c, Bytes: []byte(goodCN)}), der(asn1.NullRawValue))
	cases := map[string][]byte{
		"an attribute with a third element":     constructed(asn1.TagSequence, constructed(asn1.TagSet, attribute)),
		"empty":                                 nil,
		"one byte":                              {0x30},
		"an empty sequence":                     {0x30, 0x00},
		"a set":                                 {0x31, 0x00},
		"trailing bytes":                        append(bytes.Clone(good), 0),
		"cut":                                   good[:len(good)-1],
		"two names":                             append(bytes.Clone(good), good...),
		"a long length that lies":               {0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00},
		"an indefinite length":                  {0x30, 0x80, 0x00, 0x00},
		"nested sequences":                      bytes.Repeat([]byte{0x30, 0x02}, 1000),
		"the common name OID alone":             {0x30, 0x0a, 0x31, 0x08, 0x30, 0x06, 0x06, 0x03, 0x55, 0x04, 0x03},
		"all 0xff":                              bytes.Repeat([]byte{0xff}, 100),
		"a context tag for the name":            {0xa0, 0x00},
		"a context-specific constructed tag 16": {0xb0, 0x00},
		"the name with a context-specific tag":  withByte(good, 0, 0xb0),
		"the relative name with a context-specific tag": withByte(good, 2, 0xb1),
		"the attribute with a context-specific tag":     withByte(good, 4, 0xb0),
		"the name with a primitive tag 16":              withByte(good, 0, 0x10),
		"the relative name with a primitive tag 17":     withByte(good, 2, 0x11),
		"the attribute with a primitive tag 16":         withByte(good, 4, 0x10),
		"a primitive tag 16":                            {0x10, 0x00},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := piv.SlotOf(&x509.Certificate{RawSubject: raw})
			if err == nil || s != "" {
				t.Errorf("slot %q, error %v", s, err)
			}
		})
	}
	if s, err := piv.SlotOf(&x509.Certificate{RawSubject: good}); err != nil || s != "9c" {
		t.Errorf("the good name: %q, %v", s, err)
	}
}

// slotWith is the evidence for a slot certificate with raw values for the extensions.
func slotWith(t testing.TB, m *attesttest.Maker, s attesttest.Slot) []byte {
	t.Helper()
	return m.PIVEvidence(t, p384(t), s)
}

// The page: "the extensions .3, .7 and .8 are present". Each left out is refused, and .9 left out is
// accepted with no form factor (proposed, built as the page says).
func TestTheThreeExtensionsAreRequiredAndTheFourthIsNot(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	for _, name := range []string{attesttest.ExtFirmware, attesttest.ExtSerial, attesttest.ExtPolicy} {
		t.Run("without "+name, func(t *testing.T) {
			ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Omit: map[string]bool{name: true}}))
			if d := wantRefusal(t, ev, err, handoff.CodeProofInvalid); !strings.Contains(d, "lacks") {
				t.Errorf("the detail %q does not say that an extension is missing", d)
			}
		})
	}
	t.Run("without all four", func(t *testing.T) {
		ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Omit: map[string]bool{
			attesttest.ExtFirmware: true, attesttest.ExtSerial: true, attesttest.ExtPolicy: true, attesttest.ExtForm: true,
		}}))
		wantRefusal(t, ev, err, handoff.CodeProofInvalid)
	})
	t.Run("without the form factor", func(t *testing.T) {
		ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Omit: map[string]bool{attesttest.ExtForm: true}}))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ev.Details[attest.DetailFormFactor]; ok {
			t.Errorf("a form factor %q for a certificate that has none", ev.Details[attest.DetailFormFactor])
		}
		if ev.Details[attest.DetailSlot] != "9c" {
			t.Errorf("details %v", ev.Details)
		}
	})
}

// Extension .3: three raw octets, major, minor and patch, written in decimal with no leading zero.
func TestFirmware(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	good := map[string][]byte{
		"5.7.4": {5, 7, 4}, "5.10.0": {5, 10, 0}, "255.255.255": {255, 255, 255}, "0.0.0": {0, 0, 0},
		"5.8.0": {5, 8, 0}, "5.4.3": {5, 4, 3}, "5.7.100": {5, 7, 100}, "1.2.3": {1, 2, 3},
	}
	for want, raw := range good {
		ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Firmware: raw}))
		if err != nil {
			t.Errorf("%s: %v", want, err)
		} else if ev.Firmware != want {
			t.Errorf("firmware %q, want %q", ev.Firmware, want)
		}
	}
	for name, raw := range map[string][]byte{
		"empty": {}, "one octet": {5}, "two octets": {5, 8}, "four octets": {5, 8, 0, 0},
		"a long value": bytes.Repeat([]byte{5}, 300),
	} {
		t.Run(name, func(t *testing.T) {
			ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Firmware: raw}))
			wantRefusal(t, ev, err, handoff.CodeProofInvalid)
		})
	}
}

// Extension .7: a DER INTEGER, positive, in its shortest form, at most 8 octets of content (the bound is
// proposed); written in decimal.
func TestSerial(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	good := map[string][]byte{
		"1":                   {0x02, 0x01, 0x01},
		"127":                 {0x02, 0x01, 0x7f},
		"128":                 {0x02, 0x02, 0x00, 0x80},
		"255":                 {0x02, 0x02, 0x00, 0xff},
		"256":                 {0x02, 0x02, 0x01, 0x00},
		"12345678":            {0x02, 0x04, 0x00, 0xbc, 0x61, 0x4e},
		"9223372036854775807": {0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"72057594037927936":   {0x02, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		"36028797018963968":   {0x02, 0x08, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	for want, raw := range good {
		ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Serial: raw}))
		if err != nil {
			t.Errorf("%s: %v", want, err)
		} else if ev.Details[attest.DetailSerial] != want {
			t.Errorf("serial %q, want %q", ev.Details[attest.DetailSerial], want)
		}
	}
	bad := map[string][]byte{
		"empty":                    {},
		"a tag only":               {0x02},
		"a tag and a length":       {0x02, 0x01},
		"a length of zero":         {0x02, 0x00},
		"zero":                     {0x02, 0x01, 0x00},
		"negative one":             {0x02, 0x01, 0xff},
		"a negative number":        {0x02, 0x01, 0x80},
		"a negative of two octets": {0x02, 0x02, 0xff, 0x7f},
		"a leading zero too many":  {0x02, 0x02, 0x00, 0x01},
		"two leading zeros":        {0x02, 0x03, 0x00, 0x00, 0x80},
		"a long-form length":       {0x02, 0x81, 0x01, 0x05},
		"a length that is short":   {0x02, 0x02, 0x05},
		"a length that is long":    {0x02, 0x01, 0x05, 0x06},
		"a byte after":             {0x02, 0x01, 0x05, 0x00},
		"a second integer":         {0x02, 0x01, 0x05, 0x02, 0x01, 0x06},
		"an octet string":          {0x04, 0x01, 0x05},
		"a sequence":               {0x30, 0x03, 0x02, 0x01, 0x05},
		"a tag with a class":       {0x82, 0x01, 0x05},
		"nine octets, a high one":  {0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0},
		"nine octets with sign":    {0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"ten octets":               {0x02, 0x0a, 0x01, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		"a huge length":            append([]byte{0x02, 0x82, 0x01, 0x00}, bytes.Repeat([]byte{1}, 256)...),
		"raw bytes, not DER":       {0xbc, 0x61, 0x4e},
	}
	for name, raw := range bad {
		t.Run(name, func(t *testing.T) {
			ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Serial: raw}))
			wantRefusal(t, ev, err, handoff.CodeProofInvalid)
		})
	}
}

// Extension .8: two raw octets. The first is the PIN policy (1 never, 2 once, 3 always), the second the touch
// policy (1 never, 2 always, 3 cached). A length other than two, or a value outside, is refused.
func TestPolicy(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	pin := map[byte]handoff.PINPolicy{1: handoff.PINNever, 2: handoff.PINOnce, 3: handoff.PINAlways}
	touch := map[byte]string{1: "never", 2: "always", 3: "cached"}
	for _, p := range []byte{0, 1, 2, 3, 4, 255} {
		for _, h := range []byte{0, 1, 2, 3, 4, 255} {
			wantPIN, okP := pin[p]
			wantTouch, okH := touch[h]
			t.Run(fmt.Sprintf("%d,%d", p, h), func(t *testing.T) {
				ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Policy: []byte{p, h}}))
				if okP && okH {
					if err != nil {
						t.Fatal(err)
					}
					if ev.PINPolicy != wantPIN || ev.TouchPolicy != wantTouch {
						t.Errorf("PIN %q touch %q, want %q %q", ev.PINPolicy, ev.TouchPolicy, wantPIN, wantTouch)
					}
					return
				}
				wantRefusal(t, ev, err, handoff.CodeProofInvalid)
			})
		}
	}
	for name, raw := range map[string][]byte{"empty": {}, "one octet": {2}, "three octets": {2, 1, 1}, "an integer": {0x02, 0x01, 0x02, 0x01}, "long": bytes.Repeat([]byte{1}, 300)} {
		t.Run(name, func(t *testing.T) {
			ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Policy: raw}))
			wantRefusal(t, ev, err, handoff.CodeProofInvalid)
		})
	}
}

// Extension .9: one raw octet, recorded in decimal and not enforced.
func TestFormFactor(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	for _, b := range []byte{0, 1, 2, 3, 4, 7, 255} {
		ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Form: []byte{b}}))
		if err != nil {
			t.Errorf("form factor %d: %v", b, err)
		} else if got := ev.Details[attest.DetailFormFactor]; got != strconv.Itoa(int(b)) {
			t.Errorf("form factor %q, want %d", got, b)
		}
	}
	for name, raw := range map[string][]byte{"empty": {}, "two octets": {2, 2}, "an integer": {0x02, 0x01, 0x02}, "long": bytes.Repeat([]byte{2}, 300)} {
		t.Run(name, func(t *testing.T) {
			ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Form: raw}))
			wantRefusal(t, ev, err, handoff.CodeProofInvalid)
		})
	}
}

// The extensions of the arc with other numbers are not read; the same extension twice does not parse; one
// that is critical is refused.
func TestOtherExtensionsOfTheArcAndRepeatedOnes(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	oid := func(n int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, n} }
	for _, n := range []int{1, 2, 4, 5, 6, 10, 11, 100} {
		ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Tweak: func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: oid(n), Value: []byte{9, 9, 9}})
		}}))
		if err != nil {
			t.Errorf("an extension .%d: %v", n, err)
		} else if ev.Firmware != "5.8.0" {
			t.Errorf("an extension .%d changed the firmware to %q", n, ev.Firmware)
		}
	}
	// A longer arc that begins with .3 is another extension.
	ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Tweak: func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: append(oid(3), 1), Value: []byte{9}})
	}}))
	if err != nil || ev.Firmware != "5.8.0" {
		t.Errorf("a longer arc: %v", err)
	}
	// An extension of another arc that has the number 3.
	ev, err = verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Tweak: func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 5, 3}, Value: []byte{9}})
	}}))
	if err != nil || ev.Firmware != "5.8.0" {
		t.Errorf("an extension of the arc .5: %v", err)
	}
	// The same extension twice: the certificate does not parse.
	for _, name := range []string{"firmware", "serial", "policy", "form"} {
		dup := slotWith(t, m, attesttest.Slot{Check: attesttest.CheckNone, Tweak: func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: map[string]asn1.ObjectIdentifier{
				"firmware": oid(3), "serial": oid(7), "policy": oid(8), "form": oid(9),
			}[name], Value: []byte{1, 1, 1}})
		}})
		ev, err := verifyPIV(t, v, dup)
		wantRefusal(t, ev, err, handoff.CodeProofInvalid)
	}
	// A critical one: refused, with fixed words about the critical extension.
	for _, name := range []string{attesttest.ExtFirmware, attesttest.ExtSerial, attesttest.ExtPolicy, attesttest.ExtForm} {
		ev, err := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{Critical: map[string]bool{name: true}}))
		if d := wantRefusal(t, ev, err, handoff.CodeProofInvalid); !strings.Contains(d, "critical extension") {
			t.Errorf("critical %s: detail %q", name, d)
		}
	}
}

// The order of the page: the certificate parses, the chain verifies, and only then are the subject, the
// extensions and the key read. A refusal of the chain is given whatever else is wrong with the certificate,
// and nothing of a certificate whose chain failed is handed on.
func TestNothingIsReadBeforeTheChainHasPassed(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	_, baseline := verifyPIV(t, v, slotWith(t, m, attesttest.Slot{UnpinnedIssuer: true}))
	baseDetail := wantRefusal(t, nil, baseline, handoff.CodeProofInvalid)

	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, mk := range map[string]func() []byte{
		"a bad subject": func() []byte {
			return slotWith(t, m, attesttest.Slot{UnpinnedIssuer: true, Subject: "not a slot"})
		},
		"a missing extension": func() []byte {
			return slotWith(t, m, attesttest.Slot{UnpinnedIssuer: true, Omit: map[string]bool{attesttest.ExtPolicy: true}})
		},
		"a bad policy": func() []byte {
			return slotWith(t, m, attesttest.Slot{UnpinnedIssuer: true, Policy: []byte{9, 9}})
		},
		"a P-256 key": func() []byte {
			return m.PIVEvidence(t, p256.Public(), attesttest.Slot{UnpinnedIssuer: true})
		},
		"an RSA key": func() []byte {
			return m.PIVEvidence(t, rsaKey.Public(), attesttest.Slot{UnpinnedIssuer: true})
		},
		"every fault at once": func() []byte {
			return m.PIVEvidence(t, rsaKey.Public(), attesttest.Slot{UnpinnedIssuer: true, Subject: "x", Firmware: []byte{1}, Serial: []byte{1}, Policy: []byte{1}, Form: []byte{}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			ev, err := verifyPIV(t, v, mk())
			if d := wantRefusal(t, ev, err, handoff.CodeProofInvalid); d != baseDetail {
				t.Errorf("the detail %q is not the chain's %q", d, baseDetail)
			}
		})
	}

	// With a good chain the same faults are found, in the order of the page: subject, then extensions, then
	// the key, so each detail differs from the chain's and from the other faults'.
	details := map[string]string{}
	for name, mk := range map[string]func() []byte{
		"subject":    func() []byte { return slotWith(t, m, attesttest.Slot{Subject: "not a slot"}) },
		"extensions": func() []byte { return slotWith(t, m, attesttest.Slot{Policy: []byte{9, 9}}) },
		"key":        func() []byte { return m.PIVEvidence(t, p256.Public(), attesttest.Slot{}) },
	} {
		ev, err := verifyPIV(t, v, mk())
		d := wantRefusal(t, ev, err, handoff.CodeProofInvalid)
		if d == baseDetail {
			t.Errorf("%s: the detail is the chain's: %q", name, d)
		}
		details[name] = d
	}
	if details["subject"] == details["extensions"] || details["extensions"] == details["key"] || details["subject"] == details["key"] {
		t.Errorf("the faults share their words: %v", details)
	}
	// Order among the faults: the subject first, then the extensions, then the key.
	ev, err := verifyPIV(t, v, m.PIVEvidence(t, p256.Public(), attesttest.Slot{Subject: "not a slot", Policy: []byte{9, 9}}))
	if d := wantRefusal(t, ev, err, handoff.CodeProofInvalid); d != details["subject"] {
		t.Errorf("subject and extensions and key all wrong: %q, want the subject's %q", d, details["subject"])
	}
	ev, err = verifyPIV(t, v, m.PIVEvidence(t, p256.Public(), attesttest.Slot{Policy: []byte{9, 9}}))
	if d := wantRefusal(t, ev, err, handoff.CodeProofInvalid); d != details["extensions"] {
		t.Errorf("extensions and key both wrong: %q, want the extensions' %q", d, details["extensions"])
	}
}

// A key that is not ECDSA on P-384 is refused with proof-invalid by this verifier too (the page leaves the
// code open; proof-invalid is the one built).
func TestAKeyThatIsNotP384IsRefused(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, pub := range map[string]any{"P-256": p256.Public(), "P-521": p521.Public(), "RSA": rsaKey.Public()} {
		t.Run(name, func(t *testing.T) {
			ev, err := verifyPIV(t, v, m.PIVEvidence(t, pub, attesttest.Slot{}))
			wantRefusal(t, ev, err, handoff.CodeProofInvalid)
		})
	}
}

// A chain of the openpgp applet offered as piv evidence, and the reverse, is refused when the bundle keeps
// the two groups apart. When the maker has one intermediate for both applets and the bundle pins it for both,
// the cross-use is accepted.
func TestOneApplet(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	ev, err := verifyPIV(t, v, m.OpenPGPEvidenceWith(t, p384(t), attesttest.Slot{Subject: goodCN, PIVExtensions: true}))
	wantRefusal(t, ev, err, handoff.CodeProofInvalid)

	// With one intermediate for both applets, pinned for both, the other applet's chain is accepted. This
	// test records that weakness, so that a decision to close it changes a visible test.
	shared := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, Now: clock, SharedIntermediate: true})
	sv := newVerifier(t, shared.Bundle(t))
	ev, err = verifyPIV(t, sv, shared.OpenPGPEvidenceWith(t, p384(t), attesttest.Slot{Subject: goodCN, PIVExtensions: true}))
	if err != nil || ev == nil {
		t.Errorf("a shared intermediate: %v", err)
	}
}

// The faults of the caller are errors that are not refusals, and none gives evidence or a panic.
func TestFaultsOfTheCaller(t *testing.T) {
	m := newMaker(t)
	b := m.Bundle(t)
	v := newVerifier(t, b)
	ev := m.PIVEvidence(t, p384(t), attesttest.Slot{})
	var nilV *piv.Verifier
	var noCtx context.Context

	got, err := nilV.Verify(t.Context(), nil, proofOf(handoff.StorePIV, ev), clock)
	wantPlainError(t, got, err)
	got, err = (&piv.Verifier{}).Verify(t.Context(), nil, proofOf(handoff.StorePIV, ev), clock)
	wantPlainError(t, got, err)
	got, err = v.Verify(done(), nil, proofOf(handoff.StorePIV, ev), clock)
	wantPlainError(t, got, err)
	got, err = v.Verify(noCtx, nil, proofOf(handoff.StorePIV, ev), clock)
	wantPlainError(t, got, err)
	got, err = v.Verify(t.Context(), nil, nil, clock)
	wantPlainError(t, got, err)
	for _, store := range []handoff.Store{handoff.StoreOpenPGPCard, handoff.StoreKMS, handoff.StoreSoftware, ""} {
		got, err = v.Verify(t.Context(), nil, proofOf(store, ev), clock)
		wantPlainError(t, got, err)
	}
	got, err = v.Verify(t.Context(), nil, proofOf(handoff.StorePIV, ev), time.Time{})
	wantPlainError(t, got, err)

	// The good call after all the faults: the verifier holds no state that a fault changed.
	if got, err := verifyPIV(t, v, ev); err != nil || got == nil {
		t.Errorf("the good call: %v", err)
	}
}

func TestNewRefusesNoBundle(t *testing.T) {
	v, err := piv.New(nil)
	if err == nil || v != nil {
		t.Errorf("New(nil): %v, %v", v, err)
	}
	// A zero bundle holds no root: New may refuse it, and a verifier that it makes refuses every call.
	if zero, err := piv.New(&attest.Bundle{}); err == nil {
		ev := newMaker(t).PIVEvidence(t, p384(t), attesttest.Slot{})
		got, err := verifyPIV(t, zero, ev)
		wantPlainError(t, got, err)
	}
}

// 32 goroutines call one verifier on the same input, are joined with a WaitGroup, and the results are
// compared with the first. No sleep, no timeout.
func TestConcurrentUse(t *testing.T) {
	m := newMaker(t)
	v := newVerifier(t, m.Bundle(t))
	ev := m.PIVEvidence(t, p384(t), attesttest.Slot{})
	const n = 32
	results := make([]*handoff.Evidence, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = v.Verify(t.Context(), nil, proofOf(handoff.StorePIV, ev), clock)
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		a, b := results[0], results[i]
		if !a.Key.Equal(b.Key) || a.Firmware != b.Firmware || a.PINPolicy != b.PINPolicy || a.TouchPolicy != b.TouchPolicy || !maps.Equal(a.Details, b.Details) {
			t.Errorf("goroutine %d got %+v, the first got %+v", i, b, a)
		}
		if i > 0 && a == b {
			t.Errorf("goroutine %d got the same value as the first", i)
		}
	}
}

// withByte returns a copy of b with the byte at i replaced.
func withByte(b []byte, i int, v byte) []byte {
	c := bytes.Clone(b)
	c[i] = v
	return c
}
