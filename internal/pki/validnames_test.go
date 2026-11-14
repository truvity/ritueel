package pki_test

import (
	"math/rand/v2"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// ValidDNSName and ValidURIHost are the form of a permitted name that a delegation file is held to. They
// must say what the builder says: a name that they accept and the builder refuses (or the reverse)
// would let a delegation list a name that no request can ever hold, or refuse one that can.

func TestValidDNSNameAndValidURIHostAgreeWithTheBuilderOnEveryRow(t *testing.T) {
	root := buildRoot(t, nil)
	rows := hostRows()
	if len(rows) == 0 {
		t.Fatal("the table of host names is empty: a check that finds nothing to check fails")
	}
	builderAccepts := func(form ncText, text string) bool {
		value := ncValue([][]byte{ncSub(form.base(text))}, nil)
		_, err := intermediateTBS(t, root.interParams(ncRequest(t, value)))
		return err == nil
	}
	forms := ncTexts()
	valid := map[string]func(string) bool{
		"a DNS name":   pki.ValidDNSName,
		"a URI host":   pki.ValidURIHost,
		"a URI domain": func(s string) bool { return pki.ValidURIHost("." + s) },
	}
	for _, form := range forms {
		check, ok := valid[form.name]
		if !ok {
			t.Fatalf("no exported check for the form %q", form.name)
		}
		for _, r := range rows {
			if got, want := check(r.text), builderAccepts(form, r.text); got != want {
				t.Errorf("%s %s: the exported check says %v, the builder says %v", form.name, quote(r.text), got, want)
			}
		}
	}
}

func TestValidDNSNameAndValidURIHostAgreeWithTheBuilderOnRandomTexts(t *testing.T) {
	root := buildRoot(t, nil)
	rng := rand.New(rand.NewPCG(21, 34))
	alphabet := []byte("ab09-.-._ *AZ/@:~\x00\x7f\x80")
	accepted, refused := 0, 0
	for i := 0; i < 600; i++ {
		b := make([]byte, 1+rng.IntN(14))
		for j := range b {
			if rng.IntN(5) == 0 {
				b[j] = alphabet[rng.IntN(len(alphabet))]
			} else {
				b[j] = "ab09-."[rng.IntN(6)]
			}
		}
		text := string(b)
		for _, form := range ncTexts() {
			value := ncValue([][]byte{ncSub(form.base(text))}, nil)
			_, err := intermediateTBS(t, root.interParams(ncRequest(t, value)))
			var got bool
			switch form.name {
			case "a DNS name":
				got = pki.ValidDNSName(text)
			case "a URI host":
				got = pki.ValidURIHost(text)
			default:
				got = pki.ValidURIHost("." + text)
			}
			if got != (err == nil) {
				t.Errorf("%s %s: the exported check says %v, the builder says %v", form.name, quote(text), got, err == nil)
			}
			if err == nil {
				accepted++
			} else {
				refused++
			}
		}
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("the random texts gave %d accepted and %d refused: both must occur", accepted, refused)
	}
}

func TestValidURIHostTakesOneLeadingPeriodAndNoMore(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want bool
	}{
		{"example.org", true},
		{".example.org", true},
		{"..example.org", false},
		{"...example.org", false},
		{".", false},
		{"..", false},
		{"", false},
		{".example.org.", false},
		{"example.org.", false},
		{". example.org", false},
		{".Example.org", false},
		{".example.123", false},
		{"." + strings.Repeat("a", 63) + ".example", true},
		{"." + strings.Repeat("a", 64) + ".example", false},
	} {
		if got := pki.ValidURIHost(tc.s); got != tc.want {
			t.Errorf("ValidURIHost(%s) = %v, want %v", quote(tc.s), got, tc.want)
		}
	}
}

func TestValidDNSNameTakesNoLeadingPeriod(t *testing.T) {
	for _, s := range []string{".example.org", ".", "..", "", ".a", "..a"} {
		if pki.ValidDNSName(s) {
			t.Errorf("ValidDNSName(%s) = true", quote(s))
		}
	}
	for _, s := range []string{"example.org", "a", "a.b", "1.example"} {
		if !pki.ValidDNSName(s) {
			t.Errorf("ValidDNSName(%s) = false", quote(s))
		}
	}
}

// A name of 253 characters is the longest; the period of a URI domain does not count in the length.
func TestTheLengthOfAURIDomainDoesNotCountItsPeriod(t *testing.T) {
	name := longName(253)
	if len(name) != 253 {
		t.Fatalf("longName(253) has %d characters", len(name))
	}
	if !pki.ValidDNSName(name) || !pki.ValidURIHost(name) || !pki.ValidURIHost("."+name) {
		t.Error("a name of 253 characters is refused in one of the three forms")
	}
	long := longName(254)
	if pki.ValidDNSName(long) || pki.ValidURIHost(long) || pki.ValidURIHost("."+long) {
		t.Error("a name of 254 characters is accepted in one of the three forms")
	}
}
