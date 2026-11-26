package wanted_test

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/wanted"
)

// Fuzz targets for the two readers that a person's files added. They read bytes in memory only. The root file with
// keys: an accepted file gives keys of the shape that the page states, and a file made again from those keys is
// read to the same keys. The user IDs file: an accepted file holds no byte outside printable ASCII in any user ID,
// and the same holds after it is written again.

var (
	fingerprintShape = regexp.MustCompile(`^[0-9a-f]{40}$`)
	userNameShape    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 .'-]{0,63}$`)
)

func personalRootSeeds() []string {
	seeds := []string{
		personalOpenPGP,
		"version: 1\nkind: openpgp\nencryption: false\nkeys:\n  - {label: Z, role: adopted, fingerprint: \"" + strings.ToUpper(adoptedFP) + "\", valid_until: \"2105-12-31\"}\n",
		"version: 1\nkind: openpgp\ntest: true\nrevocation_reasons: [compromised, superseded, retired, no-reason]\nencryption: true\nkeys:\n  - {label: A, role: adopted, fingerprint: \"" + adoptedFP + "\", valid_until: \"2000-02-29\"}\n",
		"version: 1\nkind: openpgp\nencryption: true\nkeys:\n  - {label: A, role: adopted, fingerprint: \"" + adoptedFP + "\", valid_until: \"2029-11-26\"}\n  - {label: B, role: standby}\n",
		"version: 1\nkind: openpgp\nencryption: true\nkeys:\n  - {label: A, role: adopted, fingerprint: \"" + adoptedFP + "\", valid_until: \"2029-11-26\", card: x}\n",
		"version: 1\nkind: openpgp\nencryption: true\nkeys:\n  - {label: A, role: adopted, fingerprint: \"" + wanted.PlaceholderFingerprint + "\", valid_until: \"2029-11-26\"}\n",
		"version: 1\nkind: openpgp\nencryption: yes\nkeys: []\n",
		"version: 1\nkind: openpgp\nkeys:\n  - {label: \"A\\U0000202e\", role: adopted, fingerprint: x, valid_until: 2029-11-26}\n",
		"version: 1\nkind: x509\nkeys:\n",
	}
	seeds = append(seeds, seedTexts()...)
	return seeds
}

// renderRoot writes the members of a parsed root as a file in the form of the page.
func renderRoot(r *wanted.Root) string {
	var b strings.Builder
	fmt.Fprintf(&b, "version: 1\nkind: %s\n", r.Kind)
	if r.Test {
		b.WriteString("test: true\n")
	}
	if reasons := r.RevocationReasons(); len(reasons) > 0 {
		fmt.Fprintf(&b, "revocation_reasons: [%s]\n", strings.Join(reasons, ", "))
	}
	if v, set := r.Encryption(); set {
		fmt.Fprintf(&b, "encryption: %v\n", v)
	}
	if keys := r.Keys(); len(keys) > 0 {
		b.WriteString("keys:\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "  - {label: %s, role: %s, fingerprint: \"%s\", valid_until: \"%s\"}\n", k.Label, k.Role, k.Fingerprint, k.ValidUntil)
		}
	}
	return b.String()
}

func FuzzPersonalRootKeys(f *testing.F) {
	for _, s := range personalRootSeeds() {
		f.Add([]byte(s))
	}
	clocks := []time.Time{
		{}, time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC), time.Date(2104, 1, 1, 0, 0, 0, 0, time.FixedZone("x", 14*3600)),
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := wanted.ParseRoot("openpgp", data)
		var file wanted.File
		if r != nil {
			file = r.File
			keys := r.Keys()
			if len(keys) > wanted.MaxKeys || (len(keys) > 0 && r.Kind != wanted.RootOpenPGP) {
				t.Fatalf("keys that break what the reader promises: %+v", keys)
			}
			seenLabel, seenFP := map[string]bool{}, map[string]bool{}
			for _, k := range keys {
				y := k.ValidUntil.Time().Year()
				switch {
				case len(k.Label) != 1 || k.Label[0] < 'A' || k.Label[0] > 'Z' || seenLabel[k.Label]:
					t.Fatalf("a label that breaks the rule: %+v", k)
				case !fingerprintShape.MatchString(k.Fingerprint) || k.Fingerprint == wanted.PlaceholderFingerprint || k.Fingerprint == wanted.ExampleFingerprint || seenFP[k.Fingerprint]:
					t.Fatalf("a fingerprint that breaks the rule: %+v", k)
				case k.Role != wanted.RoleAdopted:
					t.Fatalf("a role that is not built: %+v", k)
				case k.ValidUntil.IsZero() || y < 2000 || y > 2105 || k.ValidUntil.Time().Location() != time.UTC || k.ValidUntil.Time() != k.ValidUntil.Time().Truncate(24*time.Hour):
					t.Fatalf("a day that breaks the rule: %+v", k)
				}
				seenLabel[k.Label], seenFP[k.Fingerprint] = true, true
				if k.ValidUntil.String() != k.ValidUntil.Time().Format(time.DateOnly) {
					t.Fatalf("the text of the day is not the day: %+v", k)
				}
				for _, now := range clocks {
					if why := k.ExpiryProblem(now); why != "" && !printable(why) {
						t.Fatalf("the text of an expiry problem is not printable ASCII: %q", why)
					}
				}
			}
			// The same bytes read again give the same values.
			again, err2 := wanted.ParseRoot("openpgp", data)
			if err2 != nil || !sameRoot(r, again) {
				t.Fatalf("a second reading differs: %v", err2)
			}
			// A file made again from the values is read to the same values.
			if len(keys) > 0 || r.Kind != wanted.RootOpenPGP {
				back, err3 := wanted.ParseRoot("openpgp", []byte(renderRoot(r)))
				if err3 != nil || !sameRoot(r, back) {
					t.Fatalf("the written-again file is read to other values: %v\n%s", err3, renderRoot(r))
				}
			}
			// The accessors give copies.
			if len(keys) > 0 {
				keys[0].Fingerprint = "changed"
				if r.Keys()[0].Fingerprint == "changed" {
					t.Fatal("Keys shares memory with the root")
				}
			}
			if rs := r.RevocationReasons(); len(rs) > 0 {
				rs[0] = "changed"
				if r.RevocationReasons()[0] == "changed" {
					t.Fatal("RevocationReasons shares memory with the root")
				}
			}
			// Whatever the root holds, the checks across files give an error or nil and never panic.
			s, serr := wanted.ParseSettings(wanted.SettingsPath, []byte(personalPerson))
			if serr != nil {
				t.Fatal(serr)
			}
			for _, now := range clocks {
				if cerr := wanted.CheckPersonal(s, []*wanted.Root{r}, nil, nil, nil, now); cerr != nil && !printable(cerr.Error()) {
					t.Fatalf("not printable: %q", cerr)
				}
			}
			_ = wanted.CheckCompanyRoots([]*wanted.Root{r})
		}
		checkResult(t, "root keys", data, r != nil, file, err)
	})
}

func sameRoot(a, b *wanted.Root) bool {
	av, aset := a.Encryption()
	bv, bset := b.Encryption()
	return a.Kind == b.Kind && a.Test == b.Test && a.Name == b.Name && av == bv && aset == bset &&
		slices.Equal(a.RevocationReasons(), b.RevocationReasons()) && slices.Equal(a.Keys(), b.Keys())
}

func userIDSeeds() []string {
	seeds := []string{
		idsBase,
		"version: 1\nuser_ids: []\n",
		"version: 1\n",
		idsHead + "  - {name: Ada Old, address: ada@old.example.com, retire: true}\n  - {name: Ada, address: ADA@Example.org}\n",
		idsHead + "  - {name: " + strings.Repeat("N", 64) + ", address: " + addressOf(254) + "}\n",
		idsHead + "  - {name: \"Ada\\U0000202eB\", address: a@example.org}\n",
		idsHead + "  - {name: Ada, address: \"a@[127.0.0.1]\"}\n",
		idsHead + "  - {name: Ada, address: \"\\\"a@b\\\"@example.org\"}\n",
		idsHead + "  - {name: Ada, address: a@example.org}\n  - {name: ADA, address: A@EXAMPLE.ORG}\n",
	}
	seeds = append(seeds, seedTexts()...)
	return seeds
}

func renderIDs(entries []wanted.UserID) string {
	var b strings.Builder
	b.WriteString("version: 1\n")
	if len(entries) == 0 {
		return b.String()
	}
	b.WriteString("user_ids:\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "  - {name: \"%s\", address: \"%s\", retire: %v}\n", e.Name, e.Address, e.Retire)
	}
	return b.String()
}

func FuzzPersonalUserIDs(f *testing.F) {
	for _, s := range userIDSeeds() {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		u, err := wanted.ParseUserIDs(data)
		var file wanted.File
		if u != nil {
			file = u.File
			entries := u.Entries()
			active := 0
			for i, e := range entries {
				if !e.Retire {
					active++
				}
				whole := e.Name + " <" + e.Address + ">"
				switch {
				case !userNameShape.MatchString(e.Name) || strings.HasSuffix(e.Name, " ") || strings.Contains(e.Name, "  "):
					t.Fatalf("a name that breaks the rule: %q", e.Name)
				case len(e.Address) == 0 || len(e.Address) > 254 || strings.Count(e.Address, "@") != 1 || strings.ContainsAny(e.Address, "<>[]"):
					t.Fatalf("an address that breaks the rule: %q", e.Address)
				case !printable(whole) || strings.ContainsAny(e.Address, " \t\n"):
					t.Fatalf("a user ID with a byte outside printable ASCII: %q", whole)
				case len(whole) > 1024:
					t.Fatalf("a user ID of %d bytes", len(whole))
				}
				for _, p := range entries[:i] {
					if strings.EqualFold(p.Name, e.Name) && strings.EqualFold(p.Address, e.Address) {
						t.Fatalf("a user ID twice: %+v %+v", p, e)
					}
				}
			}
			if len(entries) > wanted.MaxUserIDs || active > wanted.MaxActiveUserIDs {
				t.Fatalf("too many user IDs: %d, %d active", len(entries), active)
			}
			again, err2 := wanted.ParseUserIDs(data)
			if err2 != nil || !slices.Equal(entries, again.Entries()) || again.File.SHA256 != u.File.SHA256 {
				t.Fatalf("a second reading differs: %v", err2)
			}
			back, err3 := wanted.ParseUserIDs([]byte(renderIDs(entries)))
			if err3 != nil || !slices.Equal(entries, back.Entries()) {
				t.Fatalf("the written-again file is read to other entries: %v\n%s", err3, renderIDs(entries))
			}
			if len(entries) > 0 {
				c := u.Entries()
				c[0].Name = "changed"
				if u.Entries()[0].Name == "changed" {
					t.Fatal("Entries shares memory with the file")
				}
			}
			s, serr := wanted.ParseSettings(wanted.SettingsPath, []byte(personalPerson))
			if serr != nil {
				t.Fatal(serr)
			}
			root, rerr := wanted.ParseRoot("openpgp", []byte(personalOpenPGP))
			if rerr != nil {
				t.Fatal(rerr)
			}
			if cerr := wanted.CheckPersonal(s, []*wanted.Root{root}, nil, nil, u, personalNow); cerr != nil && !printable(cerr.Error()) {
				t.Fatalf("not printable: %q", cerr)
			}
		}
		checkResult(t, "user ids", data, u != nil, file, err)
	})
}
