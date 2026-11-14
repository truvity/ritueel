package pki_test

import (
	"flag"
	"regexp"
	"sort"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// The last test of the package: see a_refusals_test.go for what it holds and how.

// reachedOnlyThroughTheIssuer are refusals of a name that a request cannot meet, because ParseRequest has judged the structure of the
// subject before the name reader sees it; the issuer, a parameter, meets them as an ErrParams.
var reachedOnlyThroughTheIssuer = map[string]bool{
	"%s is not a name: one DER sequence (RFC 5280, 4.1.2.4)": true,
	"%s has bytes after the name":                            true,
}

// unreachableToday are the refusals that no input reaches: the code that holds them is a second line of defence behind a stricter
// reader of the standard library. It was tried with every single-byte change of a good value and 270,000 changes of the one or two bytes
// at the front, with no result. (A second one, the canonical form of a key, was on this list in an earlier round: a key with an element
// after its bit string reaches it, because encoding/asn1 ignores an element after the last field of a struct.) If one is ever reached, the
// test accepts it, and the row can move out of here.
var unreachableToday = map[string]string{
	"the key of the request is not in the canonical form": "a key that the standard library reads and that is not the one DER form is one with an element after its last field, and the form of the structure refuses it first (an algorithm and a bit string, nothing else); 3,000,000 changed keys, and every structure that the standard library reads with that leniency, were tried: no input reaches it. It is dead code today, kept as a second line of defence",
	"the extended key usage is not in the DER form":       "encoding/asn1 refuses every list that does not marshal to the bytes it was read from (a non-minimal length, a non-minimal arc, indefinite length)",
}

// formatPattern is the regular expression of the texts that a format gives.
func formatPattern(format string) *regexp.Regexp {
	verbs := regexp.MustCompile(`%[a-z]`)
	var b strings.Builder
	b.WriteString("(?s)^")
	last := 0
	for _, loc := range verbs.FindAllStringIndex(format, -1) {
		b.WriteString(regexp.QuoteMeta(format[last:loc[0]]))
		b.WriteString(".*")
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(format[last:]))
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// ZZ: the last test of the package. Every text of a refusal that the tests saw is a refusal of the source with its check, and every
// refusal of the source was seen.
func TestZEveryRefusalIsReachedByATestWithItsCheck(t *testing.T) {
	if f := flag.Lookup("test.run"); f != nil && f.Value.String() != "" {
		t.Skip("a -run filter is given: the other tests have not all run, and this one reads what they saw")
	}
	if testing.Short() {
		t.Skip("short")
	}
	const prefix = "pki: certificate request refused: "
	const paramsPrefix = "pki: invalid parameter: "
	refusalLog.Lock()
	seen := map[string]pki.Check{}
	for k, v := range refusalLog.seen {
		seen[k] = v
	}
	refusalLog.Unlock()
	if len(seen) < 100 {
		t.Fatalf("the tests saw only %d different refusals of a request", len(seen))
	}
	reached := map[string]bool{}
	texts := map[string]bool{}
	var unknown []string
	viaIssuer := map[string]bool{}
	for text, check := range seen {
		if strings.HasPrefix(text, paramsPrefix) {
			for format := range reachedOnlyThroughTheIssuer {
				if formatPattern(paramsPrefix + format).MatchString(text) {
					viaIssuer[format] = true
				}
			}
			continue
		}
		if !strings.HasPrefix(text, prefix) {
			t.Errorf("an ErrRequest with the text %q", text)
			continue
		}
		matched := false
		for format, want := range refusalChecks {
			if !formatPattern(prefix + format).MatchString(text) {
				continue
			}
			matched = true
			reached[format] = true
			if check != want {
				t.Errorf("%q: the check seen is %q, the contract gives %q", text, check, want)
			}
		}
		for _, ft := range faultTexts {
			if strings.Contains(text, ft) {
				matched = true
				texts[ft] = true
				if check != pki.CheckPolicy {
					t.Errorf("%q: the check seen is %q, want policy", text, check)
				}
			}
		}
		if !matched && !strings.Contains(text, "a fault of this package") {
			unknown = append(unknown, text)
		}
	}
	sort.Strings(unknown)
	for _, u := range unknown {
		t.Errorf("a refusal that the source walk does not know: %q", u)
	}
	var missing []string
	for format := range refusalChecks {
		switch {
		case reached[format]:
			if reachedOnlyThroughTheIssuer[format] {
				t.Errorf("the refusal %q is met by a request: the row moves out of reachedOnlyThroughTheIssuer", format)
			}
		case reachedOnlyThroughTheIssuer[format]:
			if !viaIssuer[format] {
				missing = append(missing, format+" (not even through the issuer)")
			}
		default:
			if _, ok := unreachableToday[format]; !ok {
				missing = append(missing, format)
			}
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("no test reaches the refusal %q", m)
	}
	for _, ft := range faultTexts {
		if !texts[ft] {
			t.Errorf("no test reaches the refusal text %q", ft)
		}
	}
	t.Logf("%d different refusals seen, %d refusals of the source reached by a request, %d only through the issuer, %d that no input reaches", len(seen), len(reached), len(viaIssuer), len(unreachableToday))
}
