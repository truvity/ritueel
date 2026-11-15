//go:build linux || darwin

package cli

import (
	"fmt"
	"strings"
	"testing"
)

// A bundle in which the same trust sets are listed by many records stands at one place of each set for each record. The
// most that a run holds is MaxSetPlaces (131,072) places in all; one more ends the command with exit code 1 and a
// sentence that names the limit, and writes nothing. The bundle is made by hand like the others: every file is spelled
// out and every digest is worked out with crypto/sha256.

// placesBundle is a bundle of records records in a chain; each lists the sets trust sets, each with the same two files.
func placesBundle(t *testing.T, records, sets int) *hbundle {
	t.Helper()
	b := newHB(t, 0)
	var artifacts []string
	var keysOf, listOf = func(n int) string { return fmt.Sprintf("keys of set %d\n", n) }, func(n int) string {
		return `{"roots":[{"label":"A","x509_spki_sha256":"` + hbPin(1) + `"}],"sequence":` + fmt.Sprint(n) + `,"version":1}`
	}
	for s := 1; s <= sets; s++ {
		name := fmt.Sprintf("%03d-aaaaaaaa", s)
		hbWrite(t, b.dir, "trust/"+name+"/keys.txt", keysOf(s))
		hbWrite(t, b.dir, "trust/"+name+"/root-list.json", listOf(s))
		artifacts = append(artifacts,
			`{"path":"trust/`+name+`/keys.txt","sha256":"`+hbSum(keysOf(s))+`"}`,
			`{"path":"trust/`+name+`/root-list.json","sha256":"`+hbSum(listOf(s))+`"}`)
	}
	listed := `[` + strings.Join(artifacts, ",") + `]`
	for n := 1; n <= records; n++ {
		c := hbMake(n, b.end(), false)
		c.noSet = true
		c.record = strings.Replace(hbRecord(c, c.prev), `"artifacts":[]`, `"artifacts":`+listed, 1)
		c.digest = hbSum(c.record)
		hbWriteCeremony(t, b.dir, c)
		b.cs = append(b.cs, c)
	}
	return b
}

func TestCheckHistoryEndsWithExitCodeOneWhenTheTrustSetsStandAtTooManyPlaces(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a bundle of 130,000 places")
	}
	t.Run("one place more than the limit", func(t *testing.T) {
		b := placesBundle(t, 512, 257)
		for _, args := range [][]string{{"check", "history", "--dir", b.dir}, {"check", "history", "--dir", b.dir, "--output", "json"}} {
			r := chRun(t, args...)
			if r.code != ExitFailure {
				t.Fatalf("%v: exit %d, stdout %q, stderr %q; want exit 1", args, r.code, r.stdout, r.stderr)
			}
			if !strings.Contains(r.stderr, "MaxSetPlaces") || !strings.Contains(r.stderr, "131072") {
				t.Errorf("%v: standard error %q does not name the limit", args, r.stderr)
			}
			if strings.Contains(r.stderr, "root-returns") || strings.Contains(r.stderr, "ritueel: refused") {
				t.Errorf("%v: a run that did not finish gives findings: %q", args, r.stderr)
			}
		}
	})
	t.Run("at the limit the run is done", func(t *testing.T) {
		b := placesBundle(t, 512, 256)
		r := chRun(t, "check", "history", "--dir", b.dir)
		if r.code == ExitFailure || r.code == ExitUsage {
			t.Fatalf("exit %d, stderr %q; the run at the limit must finish", r.code, r.stderr)
		}
		if strings.Contains(r.stderr, "MaxSetPlaces") {
			t.Errorf("the limit is named at the limit: %q", r.stderr)
		}
	})
}
