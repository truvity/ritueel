package files_test

import (
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// A label names an X.509 key and an OpenPGP primary together (docs/reference/bundle.md, "root.json"),
// so the journal of births holds two lines for one label, one for each purpose. The reader of one
// line does not know the others: the pair of label and purpose is held to be born once by the
// writer of the journal and by the reader of the record, not here.

func TestABirthLineOfEachPurposeOfALabelIsReadAndWrittenAsItIs(t *testing.T) {
	for _, purpose := range []string{"x509-root", "openpgp-primary"} {
		t.Run(purpose, func(t *testing.T) {
			in := &files.BirthLine{At: "2026-11-14T10:00:00Z", Label: "A", Purpose: purpose, Store: "software", Place: "A." + purpose + ".key", PublicKeySHA256: dg('a')}
			b, err := in.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			want := `{"at":"2026-11-14T10:00:00Z","label":"A","place":"A.` + purpose + `.key","public_key_sha256":"` + dg('a') + `","purpose":"` + purpose + `","store":"software"}`
			if string(b) != want {
				t.Errorf("Canonical = %s\nwant %s", b, want)
			}
			back, err := files.ReadBirthLine(b)
			if err != nil || !reflect.DeepEqual(back, in) {
				t.Errorf("read back %+v, %v", back, err)
			}
		})
	}
}

// Two lines for one label are two lines that the reader of a line takes each on its own.
func TestTwoBirthLinesOfOneLabelAreEachReadOnItsOwn(t *testing.T) {
	x := &files.BirthLine{At: "2026-11-14T10:00:00Z", Label: "A", Purpose: "x509-root", Store: "software", Place: "A.x509.key.pem", PublicKeySHA256: dg('a')}
	p := &files.BirthLine{At: "2026-11-14T10:00:01Z", Label: "A", Purpose: "openpgp-primary", Store: "software", Place: "A.openpgp.key.asc", PublicKeySHA256: dg('b')}
	for _, l := range []*files.BirthLine{x, p, x} {
		b, err := l.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := files.ReadBirthLine(b); err != nil {
			t.Errorf("%s: %v", b, err)
		}
	}
}

// A signature line of an OpenPGP primary holds a key of 40 digits (the fingerprint), and one of an
// X.509 key a pin of 64: the line takes both and no other length.
func TestASignatureLineTakesAFingerprintOfFortyDigitsAndAPinOfSixtyFour(t *testing.T) {
	for name, key := range map[string]string{"a pin": dg('a'), "a fingerprint": strings.Repeat("ab", 20)} {
		for _, kind := range []string{files.KindRootCertificate, files.KindPrimarySelfSignature, files.KindPrimaryRevocation, files.KindRootRemoval} {
			l := &files.SignatureLine{At: "2026-11-14T10:00:05Z", N: 7, Kind: kind, Key: key, SignatureSHA256: dg('f')}
			b, err := l.Canonical()
			if err != nil {
				t.Errorf("%s %s: %v", name, kind, err)
				continue
			}
			back, err := files.ReadSignatureLine(b)
			if err != nil || !reflect.DeepEqual(back, l) {
				t.Errorf("%s %s: read back %+v, %v", name, kind, back, err)
			}
		}
	}
	for _, key := range []string{strings.Repeat("a", 39), strings.Repeat("a", 41), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 40)} {
		l := &files.SignatureLine{At: "2026-11-14T10:00:05Z", N: 1, Kind: files.KindPrimaryRevocation, Key: key, SignatureSHA256: dg('f')}
		if b, err := l.Canonical(); err == nil || b != nil {
			t.Errorf("a key of %d characters %q is written: %s", len(key), key[:3], b)
		}
	}
}

// The limit of lines is a number of the program, and the same for the two journals.
func TestTheMostLinesOfAJournalAreSevenForEachLabelAndEightMore(t *testing.T) {
	if files.MaxJournalLines != 190 {
		t.Fatalf("MaxJournalLines = %d, want 190", files.MaxJournalLines)
	}
	// The 190th number of a signature is read and the 191st is refused.
	for n, ok := range map[int]bool{189: true, 190: true, 191: false, 192: false, 1000: false} {
		m := sigMap()
		m["n"] = n
		_, err := files.ReadSignatureLine(canon(t, m))
		if (err == nil) != ok {
			t.Errorf("n = %d: err = %v, want accepted %v", n, err, ok)
		}
	}
}
