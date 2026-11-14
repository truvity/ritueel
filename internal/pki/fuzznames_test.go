package pki_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// FuzzValidNames never panics, and the three forms agree with each other: a URI host is a DNS name with at most one
// leading period, and a name that is accepted is made of lower-case letters, digits, hyphens and periods, at most
// 253 characters.
func FuzzValidNames(f *testing.F) {
	for _, r := range hostRows() {
		f.Add(r.text)
	}
	f.Add(".")
	f.Add("..a")
	f.Fuzz(func(t *testing.T, s string) {
		dns, uri := pki.ValidDNSName(s), pki.ValidURIHost(s)
		if dns && !uri {
			t.Fatalf("%q is a DNS name and no URI host", s)
		}
		if uri != pki.ValidDNSName(strings.TrimPrefix(s, ".")) {
			t.Fatalf("%q: the URI host and the DNS name of the rest disagree", s)
		}
		if dns {
			if len(s) > 253 || s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
				t.Fatalf("%q is accepted", s)
			}
			for i := 0; i < len(s); i++ {
				c := s[i]
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
					t.Fatalf("%q is accepted with the byte %q", s, c)
				}
			}
		}
	})
}
