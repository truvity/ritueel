package ceremony

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"slices"
	"strings"
	"testing"
)

// The form of the two times of a root certificate, judged on the bytes (RFC 5280, 4.1.2.5). The
// standard library reads the certificate first and refuses most other spellings itself, so these
// tests call the judgement of the bytes directly.

func TestTheContentOfATimeIsInTheFormOfRFC5280OrIsNot(t *testing.T) {
	cases := []struct {
		name string
		tag  int
		text string
		ok   bool
	}{
		{"a UTCTime", asn1.TagUTCTime, "261120100000Z", true},
		{"a UTCTime of zeros", asn1.TagUTCTime, "000000000000Z", true},
		{"a UTCTime of nines", asn1.TagUTCTime, "999999999999Z", true},
		{"a GeneralizedTime", asn1.TagGeneralizedTime, "20501120100000Z", true},
		{"a GeneralizedTime of zeros", asn1.TagGeneralizedTime, "00000000000000Z", true},
		{"a UTCTime with no seconds", asn1.TagUTCTime, "2611201000Z", false},
		{"a UTCTime with an offset", asn1.TagUTCTime, "261120100000+0100", false},
		{"a UTCTime with no Z but thirteen digits", asn1.TagUTCTime, "2611201000000", false},
		{"a UTCTime with a lower case z", asn1.TagUTCTime, "261120100000z", false},
		{"a UTCTime with a letter for the Z", asn1.TagUTCTime, "261120100000X", false},
		{"a UTCTime with a byte after the Z", asn1.TagUTCTime, "261120100000Z0", false},
		{"a UTCTime with a space after the Z", asn1.TagUTCTime, "261120100000Z ", false},
		{"a UTCTime with a byte before", asn1.TagUTCTime, " 261120100000Z", false},
		{"a UTCTime of fifteen bytes", asn1.TagUTCTime, "20261120100000Z", false},
		{"a UTCTime that is empty", asn1.TagUTCTime, "", false},
		{"a UTCTime that is the Z", asn1.TagUTCTime, "Z", false},
		{"a UTCTime of twelve bytes", asn1.TagUTCTime, "26112010000Z", false},
		{"a letter in the first byte", asn1.TagUTCTime, "a61120100000Z", false},
		{"a letter in the middle", asn1.TagUTCTime, "26112a100000Z", false},
		{"a letter in the last digit", asn1.TagUTCTime, "26112010000aZ", false},
		{"a colon after the nines", asn1.TagUTCTime, "26112010000:Z", false},
		{"a slash before the zeros", asn1.TagUTCTime, "26112010000/Z", false},
		{"a plus in the first byte", asn1.TagUTCTime, "+61120100000Z"[:13], false},
		{"a UTCTime with a NUL", asn1.TagUTCTime, "26112010\x00000Z", false},
		{"a non-ASCII digit", asn1.TagUTCTime, "26112010000\xd9\xa1Z"[:13], false},
		{"a GeneralizedTime with no seconds", asn1.TagGeneralizedTime, "205011201000Z", false},
		{"a GeneralizedTime with a fraction", asn1.TagGeneralizedTime, "20501120100000.5Z", false},
		{"a GeneralizedTime with an offset", asn1.TagGeneralizedTime, "20501120100000+0100", false},
		{"a GeneralizedTime with no Z but fifteen digits", asn1.TagGeneralizedTime, "205011201000000", false},
		{"a GeneralizedTime with a lower case z", asn1.TagGeneralizedTime, "20501120100000z", false},
		{"a GeneralizedTime with a byte after the Z", asn1.TagGeneralizedTime, "20501120100000Z0", false},
		{"a GeneralizedTime of a UTCTime's length", asn1.TagGeneralizedTime, "501120100000Z", false},
		{"a GeneralizedTime with a letter", asn1.TagGeneralizedTime, "2050112010000aZ", false},
		{"a GeneralizedTime with a letter at the start", asn1.TagGeneralizedTime, "a0501120100000Z", false},
		{"a GeneralizedTime that is empty", asn1.TagGeneralizedTime, "", false},
		{"a UTCTime of the length of a GeneralizedTime", asn1.TagUTCTime, "20501120100000Z", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRFC5280Time([]byte(tc.text), tc.tag); got != tc.ok {
				t.Fatalf("isRFC5280Time(%q, %d) = %v, want %v", tc.text, tc.tag, got, tc.ok)
			}
		})
	}
	if isRFC5280Time(nil, asn1.TagUTCTime) || isRFC5280Time(nil, asn1.TagGeneralizedTime) {
		t.Error("no bytes are a time")
	}
}

// goodValidity is the certificate of a staged run, its tbs and the facts that it was made from.
func goodValidity(t *testing.T) (tbsDoc, *x509.Certificate, RootCertWant) {
	t.Helper()
	m := stagedMaker(t)
	cert, err := x509.ParseCertificate(m.certs["A"])
	if err != nil {
		t.Fatal(err)
	}
	var tbs tbsDoc
	if _, err := asn1.Unmarshal(cert.RawTBSCertificate, &tbs); err != nil {
		t.Fatal(err)
	}
	return tbs, cert, RootCertWant{NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}
}

func TestTheValidityOfAGoodCertificateIsAccepted(t *testing.T) {
	tbs, cert, w := goodValidity(t)
	bad := func(member, format string, args ...any) error {
		return artifactErr("root certificate A", member, format, args...)
	}
	if err := checkRootValidity(bad, tbs, cert, w); err != nil {
		t.Fatalf("checkRootValidity: %v", err)
	}
}

func TestTheValidityIsJudgedOnTheBytesOfEachTimeAsTheyStand(t *testing.T) {
	bad := func(member, format string, args ...any) error {
		return artifactErr("root certificate A", member, format, args...)
	}
	for _, member := range []string{"notBefore", "notAfter"} {
		edits := map[string]func(v *asn1.RawValue){
			"a compound value": func(v *asn1.RawValue) { v.IsCompound = true },
			"the other time type": func(v *asn1.RawValue) {
				v.Tag = asn1.TagGeneralizedTime
			},
			"a context class":      func(v *asn1.RawValue) { v.Class = asn1.ClassContextSpecific },
			"an application class": func(v *asn1.RawValue) { v.Class = asn1.ClassApplication },
			"a byte more":          func(v *asn1.RawValue) { v.Bytes = append(slices.Clone(v.Bytes), 'Z') },
			"a byte less":          func(v *asn1.RawValue) { v.Bytes = v.Bytes[:len(v.Bytes)-1] },
			"no seconds":           func(v *asn1.RawValue) { v.Bytes = append(slices.Clone(v.Bytes[:len(v.Bytes)-3]), 'Z') },
			"a lower case z":       func(v *asn1.RawValue) { v.Bytes = []byte(strings.ToLower(string(v.Bytes))) },
			"no Z but a digit": func(v *asn1.RawValue) {
				v.Bytes = append(slices.Clone(v.Bytes[:len(v.Bytes)-1]), '0')
			},
			"a letter for a digit": func(v *asn1.RawValue) {
				b := slices.Clone(v.Bytes)
				b[3] = 'a'
				v.Bytes = b
			},
			"a plus for a digit": func(v *asn1.RawValue) {
				b := slices.Clone(v.Bytes)
				b[len(b)-2] = '+'
				v.Bytes = b
			},
			"an empty value": func(v *asn1.RawValue) { v.Bytes = nil },
		}
		for name, edit := range edits {
			t.Run(member+" "+name, func(t *testing.T) {
				tbs, cert, w := goodValidity(t)
				if member == "notBefore" {
					edit(&tbs.Validity.NotBefore)
				} else {
					edit(&tbs.Validity.NotAfter)
				}
				err := checkRootValidity(bad, tbs, cert, w)
				var ae *ArtifactError
				ok := errors.As(err, &ae)
				if !ok || ae.Member != member {
					t.Fatalf("the error is %T (%v), want an *ArtifactError of %s", err, err, member)
				}
			})
		}
	}
}
