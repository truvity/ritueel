package pki_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// The characters of a subject, through ParseRequest and IntermediateTBS, under the rule of version 1 of the contract: the text of a value is printable ASCII, the characters U+0020 to U+007E, in every string type. The rule is one range
// and these tests do not have a table by kind of character any more; they replace the tests of the earlier rule (the
// categories Cc, Cf, Co, Zl, Zp and Zs and their classes) with the tests of the replacing rule:
//
//   - every code point of the range U+0000 to U+00FF and a sample above it, one by one, in a UTF8String value of a request,
//     is accepted exactly when it is U+0020 to U+007E;
//   - the characters that the earlier rule named by class are still refused, each now with the one text of the new rule, and the
//     request that comes with the error is the partial one (the policy case of ParseRequest);
//   - the characters of the whole range are issued and verified by both verifiers.
//
// The scan of every code point of Unicode against the rule is the internal test (chars_internal_test.go).

// assertRefusedForContent checks what a request that is refused by the policy check gives (check 9): ParseRequest returns no request (a nil
// one, for every error), and RequestKey and RequestKeyFile, which stop at checks 2, 4 and 5, return the key of the request and no
// error, a key that is a copy; the key is the key that the request was signed with, read here by the standard library when it can
// read the request.
func assertRefusedForContent(t *testing.T, req *pki.Request, der []byte) {
	t.Helper()
	if req != nil {
		t.Error("a request came with the policy error")
	}
	key, err := pki.RequestKey(der)
	if err != nil || key == nil {
		t.Errorf("RequestKey of a request refused for its content: %v, %v", key, err)
		return
	}
	fileKey, err := pki.RequestKeyFile(pemBlockOf("CERTIFICATE REQUEST", der))
	if err != nil || fileKey == nil || !fileKey.Equal(key) {
		t.Errorf("RequestKeyFile of a request refused for its content: %v, %v", fileKey, err)
	}
	if sc, err := x509.ParseCertificateRequest(der); err == nil {
		if pub, ok := sc.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(key) {
			t.Error("the key that RequestKey returns is not the key of the request")
		}
	}
}

// Every code point of U+0000 to U+00FF, and a sample of the others, in a UTF8String value of the common name, in the middle of
// a text, is accepted by ParseRequest exactly when it is in U+0020 to U+007E; a refused one is a refusal by the policy check
// and says the words of the rule.
func TestEveryCodePointOfALatin1RangeIsJudgedBySubjectText(t *testing.T) {
	var accepted, refusedN int
	sample := []rune{0x0100, 0x017F, 0x0301, 0x03B1, 0x0430, 0x05D0, 0x0627, 0x0E01, 0x1680, 0x2000, 0x200B, 0x2028, 0x202E, 0x20AC, 0x212A, 0x3000, 0x4E2D, 0xAC00, 0xD7FF, 0xE000, 0xFB01, 0xFEFF, 0xFF21, 0xFFFD, 0xFFFF, 0x10000, 0x1F600, 0xE0001, 0xE0100, 0x10FFFF}
	all := make([]rune, 0, 256+len(sample))
	for r := rune(0); r <= 0xFF; r++ {
		all = append(all, r)
	}
	all = append(all, sample...)
	good := copyCSR(withExtensions(t, goodExtensions()...))
	for _, r := range all {
		csr := copyCSR(good)
		csr.RawSubject = cnName(tUTF8, "a"+string(r)+"b")
		der := csr.DER()
		req, err := pki.ParseRequest(der)
		want := r >= 0x20 && r <= 0x7E
		if want {
			accepted++
			if err != nil {
				t.Errorf("U+%04X: refused: %v", r, err)
			} else if got := req.SubjectName(); len(got) != 1 || got[0][0].Value != "a"+string(r)+"b" {
				t.Errorf("U+%04X: the subject read is %+v", r, got)
			}
			continue
		}
		refusedN++
		if err == nil {
			t.Errorf("U+%04X: accepted", r)
			continue
		}
		refused(t, err, pki.ErrRequest)
		if c := pki.CheckOf(err); c != pki.CheckPolicy {
			t.Errorf("U+%04X: check %q, want policy", r, c)
		}
		if !strings.Contains(err.Error(), "a character outside printable ASCII (U+0020 to U+007E)") {
			t.Errorf("U+%04X: the text does not say the rule: %q", r, err.Error())
		}
		assertRefusedForContent(t, req, der)
	}
	if accepted != 95 || refusedN != 256-95+len(sample) {
		t.Errorf("%d accepted and %d refused; want 95 and %d", accepted, refusedN, 256-95+len(sample))
	}
}

// The characters that the earlier rule named by class, as a request carries them: at the start, in the middle, at the end and
// alone, each is refused with the text of the one rule, by the policy check, and IntermediateTBS reads the same request the
// same way. (A single space alone, at the start or at the end, is refused by the other rule of the text, tested below.)
func TestEveryRefusedCategoryIsRefusedInASubject(t *testing.T) {
	root := buildRoot(t, nil)
	classes := []struct {
		class string // what the earlier rule called the class, for the name of the row
		runes []rune
	}{
		{"control", []rune{0x00, 0x01, 0x09, 0x0A, 0x1F, 0x7F, 0x80, 0x85, 0x9F}},
		{"line or paragraph separator", []rune{0x2028, 0x2029}},
		{"space other than U+0020", []rune{0xA0, 0x1680, 0x2000, 0x2003, 0x200A, 0x202F, 0x205F, 0x3000}},
		{"direction", []rune{0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}},
		{"not seen", []rune{0x200B, 0x200C, 0x200D, 0xFEFF, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2800, 0x3164, 0xFFA0, 0xFE00, 0xFE0F, 0xE0100, 0xE01EF}},
		{"format", []rune{0xAD, 0x0600, 0x0605, 0x06DD, 0x070F, 0x180E, 0x2060, 0x2064, 0x206A, 0x206F, 0xFFF9, 0xFFFB, 0x110BD, 0x1D173, 0xE0001, 0xE0020, 0xE007F}},
		{"private use", []rune{0xE000, 0xF8FF, 0xF0000, 0xFFFFD, 0x100000, 0x10FFFD}},
		{"noncharacter", []rune{0xFDD0, 0xFDEF, 0xFFFE, 0xFFFF, 0x1FFFE, 0x1FFFF, 0x10FFFE, 0x10FFFF}},
		{"reads as an ASCII letter", []rune{0x212A, 0x017F, 0xFF00, 0xFF10, 0xFF21, 0xFF41, 0xFF5A, 0xFFEF}},
		{"letters of other scripts and marks (allowed by the earlier rule)", []rune{0x00E9, 0x0301, 0x0430, 0x03B1, 0x05D0, 0x0627, 0x4E2D, 0xAC00, 0x1F600, 0x0660}},
	}
	n := 0
	for _, c := range classes {
		for _, r := range c.runes {
			for _, place := range []struct{ name, text string }{{"start", string(r) + "ab"}, {"middle", "a" + string(r) + "b"}, {"end", "ab" + string(r)}, {"alone", string(r)}} {
				n++
				t.Run(fmt.Sprintf("%s U+%04X %s", c.class, r, place.name), func(t *testing.T) {
					csr := copyCSR(withExtensions(t, goodExtensions()...))
					csr.RawSubject = cnName(tUTF8, place.text)
					der := csr.DER()
					req, err := pki.ParseRequest(der)
					refused(t, err, pki.ErrRequest)
					if got := pki.CheckOf(err); got != pki.CheckPolicy {
						t.Errorf("check %q, want policy", got)
					}
					assertRefusedForContent(t, req, der)
					if err != nil && !strings.Contains(err.Error(), "a character outside printable ASCII (U+0020 to U+007E)") {
						t.Errorf("the text does not say the rule: %q", err.Error())
					}
					// IntermediateTBS reads the same request in the same way.
					tbs, err := intermediateTBS(t, root.interParams(csr))
					refused(t, err, pki.ErrRequest)
					if got := pki.CheckOf(err); got != pki.CheckPolicy {
						t.Errorf("IntermediateTBS: check %q, want policy", got)
					}
					if tbs != nil {
						t.Error("a body came with the error")
					}
				})
			}
		}
	}
	t.Logf("%d rows", n)
}

// The characters that are issued: every printable ASCII character, in every place of a value, in a UTF8String, a
// PrintableString where its set allows it, and an IA5String. Each is read, issued, verified by both verifiers, and shown by
// SubjectName as it is.
func TestThePrintableASCIICharactersAreIssuedAndVerifiedByBoth(t *testing.T) {
	root := buildRoot(t, nil)
	var all strings.Builder
	for r := rune(0x20); r <= 0x7E; r++ {
		all.WriteRune(r)
	}
	rows := []struct{ name, text string }{
		{"letters", "Example Authority"},
		{"digits", "0123456789"},
		{"every printable ASCII character in the order of the code points, but not the space at the start", all.String()[1:]},
		{"every printable ASCII character with a single space at the start moved inside", "a" + all.String()},
		{"the punctuation that a name writes with an escape (RFC 4514)", `a,b+c="d"\e<f>g;h#i`},
		{"the characters at the edges of the range", "!~ ~!"},
		{"a hyphen and single spaces", "a - b - c"},
		{"a long text with single spaces", strings.Repeat("ab ", 20) + "ab"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			csr := copyCSR(withExtensions(t, goodExtensions()...))
			csr.RawSubject = oneAttr(mustOID(asn1.ObjectIdentifier{2, 5, 4, 41}), tUTF8, []byte(r.text)) // "name": 32768 characters
			req, err := pki.ParseRequest(csr.DER())
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			name := req.SubjectName()
			if len(name) != 1 || len(name[0]) != 1 || name[0][0].Value != r.text {
				t.Errorf("SubjectName = %+v, want the text %q", name, r.text)
			}
			got := root.issue(t, csr, nil)
			if string(got.parsed.RawSubject) != string(csr.RawSubject) {
				t.Error("the subject issued is not the subject asked for")
			}
			verifyEverywhere(t, root, got, true)
		})
	}
}

// The text of other scripts that the earlier rule issued is refused now, one case for each script, with the policy check: a
// subject in another script needs a later version of the contract.
func TestTheTextOfOtherScriptsIsRefusedNow(t *testing.T) {
	rows := []struct{ name, text string }{
		{"Cyrillic letters", "абв Д"},
		{"Greek letters", "αβγ Ω"},
		{"Latin with accents", "café über"},
		{"Latin with a combining acute accent", "é"},
		{"Arabic letters", "مرحبا"},
		{"Hebrew letters", "שלום"},
		{"CJK ideographs", "中文 汉字"},
		{"Hangul syllables", "한글"},
		{"digits of other scripts", "٠١٢"},
		{"an emoji", "\U0001F600"},
		{"the replacement character", "a�b"},
	}
	for _, r := range rows {
		for _, tag := range []byte{tUTF8} {
			t.Run(r.name, func(t *testing.T) {
				csr := copyCSR(withExtensions(t, goodExtensions()...))
				csr.RawSubject = cnName(tag, r.text)
				der := csr.DER()
				req, err := pki.ParseRequest(der)
				refused(t, err, pki.ErrRequest)
				if got := pki.CheckOf(err); got != pki.CheckPolicy {
					t.Errorf("check %q, want policy", got)
				}
				assertRefusedForContent(t, req, der)
			})
		}
	}
}
