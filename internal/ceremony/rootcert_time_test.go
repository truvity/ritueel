//go:build linux || darwin

package ceremony_test

import (
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
)

// RFC 5280, 4.1.2.5.1 and 4.1.2.5.2: a UTCTime (the years to 2049) is YYMMDDhhmmssZ and a
// GeneralizedTime (from 2050) is YYYYMMDDhhmmssZ: Zulu, with seconds, no offset, no fraction. The
// standard library reads other spellings of the same instant, so the bytes are judged as they stand.

func TestEveryOtherSpellingOfAUTCTimeIsRefusedForBothTimes(t *testing.T) {
	// The certificate is the profile's in every other way: 2026-11-20 10:00:00Z for 36 months.
	spellings := map[string]string{
		"no seconds":                   "2611201000Z",
		"no seconds and no minutes":    "26112010Z",
		"an offset of plus":            "261120" + "110000+0100",
		"an offset of minus":           "261120" + "090000-0100",
		"an offset of zero":            "261120" + "100000+0000",
		"a lower case z":               "261120" + "100000z",
		"no Z":                         "261120" + "100000",
		"a byte after the Z":           "261120" + "100000Z ",
		"a line feed after the Z":      "261120" + "100000Z\n",
		"a digit after the Z":          "261120" + "100000Z0",
		"a letter among the digits":    "26112010000aZ",
		"a space among the digits":     "2611201000 0Z",
		"a sign among the digits":      "26112010-000Z",
		"a four digit year":            "20261120100000Z",
		"a fraction of a second":       "261120" + "100000.5Z",
		"an empty time":                "",
		"only the Z":                   "Z",
		"a time that is one byte long": "0",
	}
	for name, text := range spellings {
		raw := mkDER(0x17, []byte(text))
		t.Run("notBefore "+name, func(t *testing.T) {
			c := mkCertSpec{NotBeforeDER: raw}.build()
			if err := ceremony.CheckRootCertificate(c.DER, c.Want); err == nil {
				t.Fatalf("a notBefore written as %q is accepted", text)
			}
		})
	}
	// For notAfter the instant of the same spelling is that of the profile (2029-11-20 10:00:00Z).
	notAfter := map[string]string{
		"no seconds":                "2911201000Z",
		"an offset of plus":         "291120" + "110000+0100",
		"an offset of minus":        "291120" + "090000-0100",
		"a lower case z":            "291120" + "100000z",
		"a byte after the Z":        "291120" + "100000Z ",
		"a letter among the digits": "29112010000aZ",
		"a four digit year":         "20291120100000Z",
		"a fraction of a second":    "291120" + "100000.5Z",
		"an empty time":             "",
	}
	for name, text := range notAfter {
		raw := mkDER(0x17, []byte(text))
		t.Run("notAfter "+name, func(t *testing.T) {
			c := mkCertSpec{}.buildWithNotAfterDER(raw)
			if err := ceremony.CheckRootCertificate(c.DER, c.Want); err == nil {
				t.Fatalf("a notAfter written as %q is accepted", text)
			}
		})
	}
}

func TestTheSpellingsThatTheStandardLibraryReadsAreRefusedWithTheTimeNamed(t *testing.T) {
	// A spelling that crypto/x509 reads as the right instant is found by the check of the bytes, and
	// the member that the error names is the time. A spelling that the library refuses is refused
	// with the certificate named; either way it is refused. At least one of these spellings must be
	// read by the library, or this test holds nothing.
	read := 0
	for _, tc := range []struct {
		text   string
		member string
		after  bool
	}{
		{"2611201000Z", "notBefore", false},
		{"261120" + "110000+0100", "notBefore", false},
		{"261120" + "090000-0100", "notBefore", false},
		{"261120" + "100000+0000", "notBefore", false},
		{"2911201000Z", "notAfter", true},
		{"291120" + "110000+0100", "notAfter", true},
		{"291120" + "100000+0000", "notAfter", true},
	} {
		raw := mkDER(0x17, []byte(tc.text))
		var c mkCert
		if tc.after {
			c = mkCertSpec{}.buildWithNotAfterDER(raw)
		} else {
			c = mkCertSpec{NotBeforeDER: raw}.build()
		}
		err := ceremony.CheckRootCertificate(c.DER, c.Want)
		if _, perr := x509ParseCertificate(c.DER); perr != nil {
			mkWantArtifactError(t, err, "root certificate A", "certificate")
			continue
		}
		read++
		mkWantArtifactError(t, err, "root certificate A", tc.member)
	}
	if read == 0 {
		t.Log("the standard library of this toolchain refuses every one of these spellings itself")
	}
}

func TestEveryOtherSpellingOfAGeneralizedTimeIsRefusedFromTheYear2050(t *testing.T) {
	// notBefore 2050-01-01 00:00:00Z, notAfter 2053-01-01 00:00:00Z, both as GeneralizedTime.
	nb := time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)
	good := mkCertSpec{NotBefore: nb, NotBeforeGT: true, NotAfterGT: true}.build()
	if err := ceremony.CheckRootCertificate(good.DER, good.Want); err != nil {
		t.Fatalf("the control is refused: %v", err)
	}
	for name, text := range map[string]string{
		"no seconds":                "205001" + "010000Z",
		"a fraction of a second":    "20500101000000.0Z",
		"a fraction of a minute":    "205001" + "010000.5Z",
		"an offset of plus":         "20500101010000+0100",
		"an offset of minus":        "20491231230000-0100",
		"an offset of zero":         "20500101000000+0000",
		"a lower case z":            "20500101000000z",
		"no Z":                      "20500101000000",
		"a byte after the Z":        "20500101000000Z ",
		"a letter among the digits": "2050010100000aZ",
		"a two digit year":          "500101" + "000000Z",
		"an empty time":             "",
	} {
		raw := mkDER(0x18, []byte(text))
		t.Run("notBefore "+name, func(t *testing.T) {
			c := mkCertSpec{NotBefore: nb, NotBeforeDER: raw, NotAfterGT: true}.build()
			if err := ceremony.CheckRootCertificate(c.DER, c.Want); err == nil {
				t.Fatalf("a notBefore written as %q is accepted", text)
			}
		})
	}
	na := time.Date(2053, 1, 1, 0, 0, 0, 0, time.UTC)
	for name, text := range map[string]string{
		"no seconds":             "205301" + "010000Z",
		"a fraction of a second": "20530101000000.0Z",
		"an offset of plus":      "20530101010000+0100",
		"a lower case z":         "20530101000000z",
		"a byte after the Z":     "20530101000000Z\n",
		"an empty time":          "",
	} {
		raw := mkDER(0x18, []byte(text))
		t.Run("notAfter "+name, func(t *testing.T) {
			c := mkCertSpec{NotBefore: nb, NotBeforeGT: true, NotAfterDER: raw}.build()
			if c.Want.NotAfter != na {
				t.Fatalf("the control is wrong: notAfter %v", c.Want.NotAfter)
			}
			if err := ceremony.CheckRootCertificate(c.DER, c.Want); err == nil {
				t.Fatalf("a notAfter written as %q is accepted", text)
			}
		})
	}
}

func TestATimeThatIsWrittenAsTheFormAsksIsAcceptedOnBothSidesOf2050(t *testing.T) {
	for name, spec := range map[string]mkCertSpec{
		"UTCTime to the last year of it":      {NotBefore: time.Date(2046, 12, 31, 23, 59, 59, 0, time.UTC)},
		"UTCTime and then GeneralizedTime":    {NotBefore: time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), NotAfterGT: true},
		"GeneralizedTime for both from 2050":  {NotBefore: time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC), NotBeforeGT: true, NotAfterGT: true},
		"a leap day and the seconds of a day": {NotBefore: time.Date(2028, 2, 29, 23, 59, 59, 0, time.UTC)},
	} {
		t.Run(name, func(t *testing.T) {
			c := spec.build()
			if err := ceremony.CheckRootCertificate(c.DER, c.Want); err != nil {
				t.Fatalf("a time that is written as RFC 5280 asks is refused: %v", err)
			}
		})
	}
}

func TestACompoundTimeIsRefused(t *testing.T) {
	// A UTCTime or a GeneralizedTime with the constructed bit set (tags 0x37 and 0x38) is not the
	// primitive value that RFC 5280 asks for, and holds the right bytes inside.
	for name, tag := range map[string]byte{"UTCTime": 0x37, "GeneralizedTime": 0x38} {
		t.Run("notBefore "+name, func(t *testing.T) {
			c := mkCertSpec{NotBeforeDER: mkDER(tag, []byte("261120"+"100000Z"))}.build()
			if err := ceremony.CheckRootCertificate(c.DER, c.Want); err == nil {
				t.Fatal("a compound notBefore is accepted")
			}
		})
		t.Run("notAfter "+name, func(t *testing.T) {
			c := mkCertSpec{}.buildWithNotAfterDER(mkDER(tag, []byte("291120"+"100000Z")))
			if err := ceremony.CheckRootCertificate(c.DER, c.Want); err == nil {
				t.Fatal("a compound notAfter is accepted")
			}
		})
	}
	// A time that holds another time inside it.
	inner := mkDER(0x17, []byte("261120"+"100000Z"))
	c := mkCertSpec{NotBeforeDER: mkDER(0x37, inner)}.build()
	if err := ceremony.CheckRootCertificate(c.DER, c.Want); err == nil {
		t.Fatal("a notBefore that holds a time inside it is accepted")
	}
}
