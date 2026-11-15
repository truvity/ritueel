//go:build linux || darwin

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// "apply --plan-only" with a leftover of a stopped write in want/roots, want/delegations or want/cards:
// a name that starts with ".rt-", in any case, is skipped, and the plan is the plan of the bundle
// without it (record 0006, rule 45). The names of this file start with at.

const atDelegation = "version: 1\ntype: x509-intermediate\nroot: x509\npermitted_dns_names: [example.org]\npermitted_uri_hosts: [example.org]\n"

// atLeftovers makes leftovers of several kinds and names in each of the three folders and returns
// their paths.
func atLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	var made []string
	for _, folder := range []string{"roots", "delegations", "cards"} {
		base := filepath.Join(dir, "want", folder)
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, text := range map[string]string{
			".rt-k3j9x0a1b2c":      "not a record: [",
			".rt-k3j9x0a1b2d.yaml": newX509TestText,
			".RT-X.YAML":           "version: 1\nkind: nonsense\n",
			".Rt-":                 "",
		} {
			p := filepath.Join(base, name)
			if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
			made = append(made, p)
		}
		sub := filepath.Join(base, ".rt-folder")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, "x509.yaml"), []byte(newX509TestText), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, ".RT-link.yaml")
		if err := os.Symlink("x509.yaml", link); err != nil {
			t.Fatal(err)
		}
		fifo := filepath.Join(base, ".rT-fifo")
		if err := syscall.Mkfifo(fifo, 0o644); err != nil {
			t.Fatal(err)
		}
		made = append(made, sub, link, fifo)
	}
	return made
}

// The serials of the certificates in a plan are drawn at random, so the digest of a plan and its
// prefix differ from one run to the next. atNormal makes two runs comparable: it puts a fixed word in
// place of every digest, prefix and serial.
var (
	atSerial = regexp.MustCompile(`"serial":"[0-9a-f]+"`)
	atDigest = regexp.MustCompile(`[0-9a-f]{64}`)
	atPrefix = regexp.MustCompile(`\b[0-9a-f]{8}\b`)
)

func atNormal(s string) string {
	s = atSerial.ReplaceAllString(s, `"serial":"S"`)
	s = atDigest.ReplaceAllString(s, "D")
	return atPrefix.ReplaceAllString(s, "P")
}

// atHistory is the lines of a snapshot that are below history/, with the plan digests made equal. The
// copies of the wanted files keep their digests: they are the bytes of the wanted files.
func atHistory(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, "history") {
			if strings.HasSuffix(strings.Fields(l)[0], "plan.json") {
				l = strings.Fields(l)[0]
			}
			out = append(out, l)
		}
	}
	return out
}

func TestApplyPlanOnlyWithLeftoversInTheWantedFoldersMakesTheSamePlan(t *testing.T) {
	files := apFiles()
	files["want/delegations/acme-tls.yaml"] = atDelegation
	for _, output := range []string{"text", "json"} {
		t.Run(output, func(t *testing.T) {
			plain := apBundle(t, files)
			with := apBundle(t, files)
			made := atLeftovers(t, with)
			keys := apKeys(t)
			want := apPlanOnly(t, apClock, plain, "--key-dir", keys, "--output", output)
			if want.code != ExitOK {
				t.Fatalf("without leftovers: exit code %d; stderr %q", want.code, want.stderr)
			}
			before := apSnapshot(t, with)
			got := apPlanOnly(t, apClock, with, "--key-dir", keys, "--output", output)
			if got.code != ExitOK {
				t.Fatalf("with leftovers: exit code %d; stderr %q", got.code, got.stderr)
			}
			if atNormal(got.stdout) != atNormal(want.stdout) || atNormal(got.stderr) != atNormal(want.stderr) {
				t.Errorf("the words differ:\nstdout %q\nstderr %q\nwithout:\nstdout %q\nstderr %q", got.stdout, got.stderr, want.stdout, want.stderr)
			}
			// What the command wrote is the same, byte for byte, with and without the leftovers.
			if g, w := atHistory(apSnapshot(t, with)), atHistory(apSnapshot(t, plain)); !slices.Equal(g, w) || len(g) == 0 {
				t.Errorf("history with leftovers:\n%s\nwithout:\n%s", strings.Join(g, "\n"), strings.Join(w, "\n"))
			}
			planOf := func(dir string) string {
				b, err := os.ReadFile(filepath.Join(dir, "history", apName, "plan.json"))
				if err != nil {
					t.Fatal(err)
				}
				return atNormal(string(b))
			}
			if planOf(with) != planOf(plain) {
				t.Errorf("the plans differ:\n%s\n%s", planOf(with), planOf(plain))
			}
			// Nothing else changed, and no leftover was removed or copied.
			after := apSnapshot(t, with)
			var added []string
			for _, l := range after {
				if !slices.Contains(before, l) {
					added = append(added, l)
				}
			}
			for _, l := range added {
				if !strings.HasPrefix(l, "history") {
					t.Errorf("the command wrote outside history/: %q", l)
				}
				if strings.Contains(strings.ToLower(l), ".rt-") {
					t.Errorf("a leftover was copied into the plan: %q", l)
				}
			}
			for _, l := range before {
				if !slices.Contains(after, l) {
					t.Errorf("the command changed or removed %q", l)
				}
			}
			for _, p := range made {
				if _, err := os.Lstat(p); err != nil {
					t.Errorf("a leftover is gone: %v", err)
				}
			}
		})
	}
}

func TestApplyPlanOnlyOfALeftoverAndABadNameIsRefusedWithTheBadName(t *testing.T) {
	for _, bad := range []string{"want/roots/BAD.yaml", "want/delegations/BAD.yaml", "want/roots/.rtx.yaml"} {
		t.Run(bad, func(t *testing.T) {
			files := apFiles()
			files[bad] = atDelegation
			dir := apBundle(t, files)
			atLeftovers(t, dir)
			before := apSnapshot(t, dir)
			r := apPlanOnly(t, apClock, dir)
			if r.code != ExitFailure {
				t.Fatalf("exit code %d; stderr %q", r.code, r.stderr)
			}
			if !strings.Contains(r.stderr, bad) {
				t.Errorf("the words %q do not name %s", r.stderr, bad)
			}
			if strings.Contains(strings.ToLower(strings.ReplaceAll(r.stderr, "want/roots/.rtx.yaml", "")), ".rt-") {
				t.Errorf("the words name a leftover: %q", r.stderr)
			}
			crqSame(t, "apply --plan-only", before, apSnapshot(t, dir))
		})
	}
}

func TestApplyPlanOnlyOfABundleWithOnlyLeftoversInTheRootsFolderHasNothingToApply(t *testing.T) {
	dir := apBundle(t, map[string]string{"ritueel.yaml": newSettingsTestText})
	atLeftovers(t, dir)
	before := apSnapshot(t, dir)
	r := apPlanOnly(t, apClock, dir)
	if r.code != ExitOK {
		t.Fatalf("exit code %d; stderr %q", r.code, r.stderr)
	}
	crqSame(t, "apply --plan-only", before, apSnapshot(t, dir))
}
