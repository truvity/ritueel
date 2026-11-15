//go:build linux || darwin

package cli

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// The STEM and the --delegation values of check request are any bytes, and the flag may be given any number of times.
// The command ends with an exit code of its page, writes printable ASCII, leaves the bundle as it found it, gives the
// usage error of the repeated flag whenever the flag is given twice or more and the STEM is a stem, and accepts only
// the one command line that names the good delegation once.
func FuzzCheckRequestDelegationFlags(f *testing.F) {
	m := crqManifestOf(f)
	c := m.byID(f, "x509-software-valid")
	dir := crqBundle(f, m, c)
	stem := c.stem(f)
	now := m.clock(f)
	for _, s := range []struct {
		stem, d1, d2 string
		n            uint8
	}{
		{stem, crqDelegation, crqDelegation, 1}, {stem, crqDelegation, crqDelegation, 2}, {stem, crqDelegation, "other", 2},
		{stem, "", "", 2}, {stem, "", "", 1}, {stem, "Acme", "a_b", 3}, {stem, "a b", "", 0}, {"", crqDelegation, "", 1},
		{"Stem", "a", "b", 2}, {"a/b", "a", "b", 2}, {"-x", "a", "b", 1}, {"\x00", "\xff", "\x1b[31m", 2}, {stem, "a=b", "-x", 2},
		{strings.Repeat("a", 64), strings.Repeat("b", 64), "", 2}, {stem, strings.Repeat("b", 64), "", 1},
	} {
		f.Add(s.stem, s.d1, s.d2, s.n)
	}
	f.Fuzz(func(t *testing.T, s, d1, d2 string, n uint8) {
		n %= 4
		args := []string{"--output", "json", "check", "request", "--dir", dir}
		for i := uint8(0); i < n; i++ {
			if i == 0 {
				args = append(args, "--delegation="+d1)
			} else {
				args = append(args, "--delegation="+d2)
			}
		}
		args = append(args, "--", s)
		before := crqSnapshot(t, dir)
		r := crqRun(t, now, args...)
		crqSame(t, "check request", before, crqSnapshot(t, dir))
		if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
			t.Fatalf("a byte that is not printable ASCII for %q: %q %q", args, r.stdout, r.stderr)
		}
		switch r.code {
		case ExitOK, ExitFailure, ExitUsage, ExitRefused:
		default:
			t.Fatalf("exit code %d for %q", int(r.code), args)
		}
		if n >= 2 && handoff.ValidStem(s) && (r.code != ExitUsage || !strings.Contains(r.stderr, repeatedDelegationSentence)) {
			t.Fatalf("the flag was given %d times: (%d, %q), want the usage error of the repeated flag", n, int(r.code), r.stderr)
		}
		if n >= 2 && r.code == ExitOK {
			t.Fatalf("a repeated flag gave exit code 0 for %q", args)
		}
		if r.code == ExitOK && (n != 1 || d1 != crqDelegation || s != stem) {
			t.Fatalf("exit code 0 for %q", args)
		}
		obj := object(t, r.stdout)
		if obj["exit_code"].(interface{ String() string }).String() != string(rune('0'+int(r.code))) {
			t.Fatalf("exit code %d and the object %s", int(r.code), r.stdout)
		}
	})
}
