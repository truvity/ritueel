package pki_test

import (
	"bytes"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// The text of a name in a name constraint: a table written from the RFCs, then the comparison with the code.
//
// RFC 5280, 4.2.1.10: "DNS name restrictions are expressed as host.example.com. Any DNS name that can be
// constructed by simply adding zero or more labels to the left-hand side of the name satisfies the name
// constraint." For a URI: "the constraint applies to the host part of the name. The constraint MUST be
// specified as a fully qualified domain name and MAY specify a host or a domain. Examples would be
// 'host.example.com' and '.example.com'." So the text of a DNS constraint is a domain name, and the text of a
// URI constraint is a domain name or a period and a domain name.
//
// RFC 5280, 4.2.1.6: a dNSName "MUST be in the 'preferred name syntax', as specified by Section 3.5 of
// [RFC1034] and as modified by Section 2.1 of [RFC1123]"; the empty name " " is a legal domain name there.
//
// RFC 1034, 3.5 (preferred name syntax):
//
//	<domain>    ::= <subdomain> | " "
//	<subdomain> ::= <label> | <subdomain> "." <label>
//	<label>     ::= <letter> [ [ <ldh-str> ] <let-dig> ]
//	<ldh-str>   ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
//
// "Labels must be 63 characters or less." RFC 1035, 2.3.4: "names 255 octets or less" on the wire, which is 253
// characters of text (one length octet per label and one for the root). RFC 1123, 2.1: "The syntax of a legal
// Internet host name was specified in RFC-952 [DNS:4]. One aspect of host name syntax is hereby changed: the
// restriction on the first character is relaxed to allow either a letter or a digit." And "a valid host name
// can never have the dotted-decimal form #.#.#.#, since at least the highest-level component label will be
// alphabetic". RFC 4343 and RFC 1035, 2.3.3: names are compared without regard to case, so "Example.org" is
// the same name as "example.org".
//
// Each row is a text, my verdict "as a host name" by the RFCs above, and the verdict of the code. Where they
// differ the row says why; those are the differences of the report.
type hostRow struct {
	text string
	rfc  bool   // a host name by the RFCs, as I read them
	code bool   // what the builder does
	why  string // for a row where they differ
}

func labelOf(c byte, n int) string { return strings.Repeat(string(c), n) }

// longName is a name of exactly n characters of labels of at most 63.
func longName(n int) string {
	var labels []string
	for n > 0 {
		l := min(63, n)
		if n-l == 1 { // a label may not be empty: leave two characters for the last
			l--
		}
		labels = append(labels, labelOf('a', l))
		n -= l + 1
	}
	return strings.Join(labels, ".")
}

func hostRows() []hostRow {
	var rows []hostRow
	have := map[string]bool{}
	add := func(text string, rfc, code bool, why string) {
		if have[text] {
			return
		}
		have[text] = true
		rows = append(rows, hostRow{text, rfc, code, why})
	}
	both := func(text string, v bool) { add(text, v, v, "") }

	// The last label is not all digits (RFC 1123, 2.1: "a valid host name can never have the dotted-decimal form
	// #.#.#.#, since at least the highest-level component label will be alphabetic"). A label of digits in any other
	// place is a name ("could legally be entirely numeric"), and a last label with one letter or a hyphen is not numeric.
	for _, s := range []string{"1", "123", "0", "example.123", "a.1", "a.b.9", "1.2.3.4", "10.0.0.1", "255.255.255.255", "0.0.0.0", "90.99", "1.1", "a.0", "x-y.007", "1.2.3", "9999999999", "256.256.256.256"} {
		both(s, false)
	}
	for _, s := range []string{"1.example.com", "1.a", "a.1.b", "1.1.1.example", "1a", "a.1a", "a.b1", "a.1-1", "1.2.3.4a", "0xff", "a.9z", "10.0.0.1.example", "123.example"} {
		both(s, true)
	}
	// Names.
	for _, s := range []string{"example.org", "a", "a.b", "a.b.c.d.e", "www.example.org", "a-b.example", "a--b.example", "xn--bcher-kva.example", "a1.example", "9a.example", "a9", "z"} {
		both(s, true)
	}
	both("1.example", true) // RFC 1123, 2.1: a digit may start a label
	both("0a", true)
	both("a-b-c-d", true)
	both(labelOf('a', 63)+".example", true)
	both("example."+labelOf('z', 63), true)
	both(labelOf('a', 64)+".example", false)
	both("example."+labelOf('a', 64), false)
	both(labelOf('a', 100), false)
	both(longName(253), true)
	both(longName(252), true)
	both(longName(254), false)
	both(longName(255), false)
	both(longName(300), false)

	// The hyphen: "interior characters only letters, digits, and hyphen", and a label ends with a letter or digit.
	for _, s := range []string{"-a.example", "a-.example", "example.-b", "example.b-", "-", "--", "-a-", "a.-.b", "-example.org", "example.org-", "a.b-.c", "a.-b.c"} {
		both(s, false)
	}
	// What is not a letter, a digit or a hyphen.
	for _, s := range []string{"a_b.example", "_dmarc.example", "*.example.org", "a*.example", "*", "ex ample.org", " example.org", "example.org ", "a b",
		"example.org/", "example.org/path", "example.org:443", "a@b.example", "a,b", "a;b", "a+b", "a=b", "a!b", "a#b", "a$b", "a%b", "a&b", "a'b", "a(b", "a)b",
		"a?b", "a[b", "a]b", "a\\b", "a|b", "a~b", "a`b", "a^b", "a<b", "a>b", "a\"b", "a{b", "a}b", "a:b",
		"b\u00fccher.example", "\u4f8b.example", "a\u00a0b", "a\tb", "a\nb", "a\rb", "a\x00b", "a\x7fb", "a\x01b", "a\x1fb", "a\u200bb", "\ufeffa", "a\ufeff"} {
		both(s, false)
	}
	// The periods.
	for _, s := range []string{".example.org", "example.org.", "a..b", "..", ".", "a.", ".a", "a...b", "example..org", "example.org..", "..example.org", ".example.org."} {
		both(s, false)
	}
	// The ASCII range around the permitted characters, one by one: the edges of the three ranges and the
	// hyphen and the period, which sit between others.
	for _, c := range []byte{'/', ':', '@', '[', '`', '{', ',', '.', '+', ' '} {
		both("a"+string(c)+"b", c == '.') // "a.b" is a name; the others are not
	}
	for _, c := range []byte{'0', '9', 'a', 'z', '-'} {
		both("a"+string(c)+"b", true)
	}

	// Where the table and the code differ. Each of these is stated, with the reason of the code.
	add("", true, false, "RFC 1034, 3.5: the empty name \" \" is a domain name; a constraint of it matches every name. The contract wants a permitted DNS zone or a URI host, so an empty text is not one")
	for _, s := range []string{"Example.org", "EXAMPLE.ORG", "example.Org", "A", "a.B"} {
		add(s, true, false, "RFC 1035, 2.3.3 and RFC 5280, 4.2.1.6: no significance is attached to case; the code keeps one form (lower case) so that a verifier that folds only some letters reads the same name")
	}
	return rows
}

// The table itself is consistent: every row marked as a difference is stated, and a row that is not a
// difference has no note.
func TestHostNameTableIsWellFormed(t *testing.T) {
	rows := hostRows()
	if len(rows) < 120 {
		t.Fatalf("only %d rows", len(rows))
	}
	diffs := 0
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.text] {
			t.Errorf("the text %q is twice in the table", r.text)
		}
		seen[r.text] = true
		if (r.rfc != r.code) != (r.why != "") {
			t.Errorf("%q: rfc=%v code=%v why=%q", r.text, r.rfc, r.code, r.why)
		}
		if r.rfc != r.code {
			diffs++
		}
	}
	if diffs != 6 {
		t.Errorf("%d differences, want 6 (the empty name and 5 upper-case names)", diffs)
	}
}

// codeVerdict is the verdict of the code on a text in a form: the row's, except for what the form changes.
// A text that starts with a period is, as a URI constraint, the domain form with the rest of the text, so it is
// read as that.
func codeVerdict(form ncText, r hostRow) bool {
	if form.uri && !form.dotted && strings.HasPrefix(r.text, ".") {
		return rfcHostName(r.text[1:])
	}
	return r.code
}

// The forms in which a text is a constraint: a DNS name, a URI host, and a URI domain (a period and the name).
type ncText struct {
	name string
	base func(text string) []byte
	// dotted: the text of a URI domain starts with a period; the other forms do not.
	dotted bool
	uri    bool
}

func ncTexts() []ncText {
	return []ncText{
		{"a DNS name", dns, false, false},
		{"a URI host", func(s string) []byte { return tlv(0x86, []byte(s)) }, false, true},
		{"a URI domain", func(s string) []byte { return tlv(0x86, []byte("."+s)) }, true, true},
	}
}

func TestEveryTextOfAConstraintIsReadAsTheTableSays(t *testing.T) {
	root := buildRoot(t, nil)
	for _, form := range ncTexts() {
		for _, r := range hostRows() {
			t.Run(form.name+" "+quote(r.text), func(t *testing.T) {
				value := ncValue([][]byte{ncSub(form.base(r.text))}, nil)
				tbs, err := intermediateTBS(t, root.interParams(ncRequest(t, value)))
				if codeVerdict(form, r) {
					if err != nil {
						t.Fatalf("the code refuses %q: %v", r.text, err)
					}
					cert := parseBodyOf(t, tbs)
					if got := extensionOf(cert, oidNameConstraints); got == nil || !bytes.Equal(got.Value, value) {
						t.Errorf("the value in the body is not the value of the request")
					}
					return
				}
				// Refused by the rule of the text, and not by the second check of the standard library; a name of the
				// right shape whose last label is all digits is refused with the words of that rule.
				host := r.text
				if form.uri && !form.dotted && strings.HasPrefix(host, ".") {
					host = host[1:]
				}
				words := "is not a name of lower-case labels"
				if rfcShape(host) && rfcNumericLast(host) {
					words = "last label is all digits"
				}
				refusedSaying(t, err, pki.ErrRequest, words)
				if tbs != nil {
					t.Error("a body came with the error")
				}
			})
		}
	}
}

func quote(s string) string {
	if len(s) > 40 {
		return s[:20] + "...(" + string(rune('0'+len(s)/100)) + string(rune('0'+len(s)/10%10)) + string(rune('0'+len(s)%10)) + ")"
	}
	return strings.NewReplacer("\x00", "NUL", "\n", "LF", "\t", "TAB").Replace(s)
}

// My table as an executable rule, written without looking at the code: a regular expression of the preferred
// syntax of RFC 1034 as relaxed by RFC 1123 (lower-case only, so the one form), the length of a label and of
// the name. The code is compared with it on texts that are made at random from the characters around the edges.
var (
	rfcLabel   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	rfcNumeric = regexp.MustCompile(`^[0-9]+$`)
)

func rfcShape(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) > 63 || !rfcLabel.MatchString(l) {
			return false
		}
	}
	return true
}

func rfcNumericLast(s string) bool {
	return rfcNumeric.MatchString(s[strings.LastIndexByte(s, '.')+1:])
}

// rfcHostName is the table as a rule: the shape of RFC 1034 and 1123, and the highest-level label is alphabetic
// (RFC 1123, 2.1).
func rfcHostName(s string) bool { return rfcShape(s) && !rfcNumericLast(s) }

// The executable table has the same rules as the table of rows (the shape, and a last label that is not all digits),
// so on every text, in every form, it and the code agree. The texts are made of the characters around the edges, with
// digits and periods common enough that last labels of digits are made.
func TestTheCodeAgreesWithTheExecutableTableOnRandomTexts(t *testing.T) {
	root := buildRoot(t, nil)
	rng := rand.New(rand.NewPCG(7, 13))
	alphabet := []byte("ab09-.-._ *AZ/@:~\x00\x7f\x80")
	accepted, refusedN := 0, 0
	for i := 0; i < 1500; i++ {
		n := 1 + rng.IntN(14)
		b := make([]byte, n)
		for j := range b {
			// Mostly characters of names, so that accepted texts are common.
			if rng.IntN(5) == 0 {
				b[j] = alphabet[rng.IntN(len(alphabet))]
			} else {
				b[j] = "ab09-."[rng.IntN(6)]
			}
		}
		text := string(b)
		for _, form := range ncTexts() {
			want := rfcHostName(text)
			if form.uri && !form.dotted && strings.HasPrefix(text, ".") {
				want = rfcHostName(text[1:])
			}
			value := ncValue([][]byte{ncSub(form.base(text))}, nil)
			_, err := intermediateTBS(t, root.interParams(ncRequest(t, value)))
			if want != (err == nil) {
				t.Fatalf("%s %q: the table says %v, the code says %v (%v)", form.name, text, want, err == nil, err)
			}
			if want {
				accepted++
			} else {
				refusedN++
			}
		}
	}
	t.Logf("random texts: %d accepted, %d refused, no difference", accepted, refusedN)
	if accepted < 300 || refusedN < 300 {
		t.Errorf("only %d accepted and %d refused texts: the generator does not reach both sides", accepted, refusedN)
	}
}

// A text that is long: names of 253 characters in a URI domain have 254 characters in the text, with the
// period: the period is not part of the name, so 253 is the limit of the name in every form.
func TestTheLengthLimitIsOfTheNameNotOfTheTextWithItsPeriod(t *testing.T) {
	root := buildRoot(t, nil)
	for _, n := range []int{253, 254} {
		name := longName(n)
		for _, form := range ncTexts() {
			value := ncValue([][]byte{ncSub(form.base(name))}, nil)
			_, err := intermediateTBS(t, root.interParams(ncRequest(t, value)))
			if (err == nil) != (n == 253) {
				t.Errorf("%s of %d characters: %v", form.name, n, err)
			}
		}
	}
}
