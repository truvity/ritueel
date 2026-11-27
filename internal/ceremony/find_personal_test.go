package ceremony_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
)

// A personal bundle in Find: its wanted files are judged against each other with the clock of the command, and a
// bundle whose files pass is refused as not built, with a text of its own and nothing written.

const (
	pnRoot = "version: 1\nkind: openpgp\nencryption: true\nkeys:\n" +
		"  - {label: A, role: adopted, fingerprint: \"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\", valid_until: \"2029-11-26\"}\n"
	pnCard    = "version: 1\nserial: \"1234\"\nkind: day-to-day\napplications: [openpgp]\n"
	pnSign    = "version: 1\ntype: openpgp-subkey\nroot: openpgp\ncapability: sign\ncard: day-ana\n"
	pnRefusal = "a personal bundle (kind: personal in ritueel.yaml) passed the check of its wanted files; adoption and subkeys are built by later parts"
)

var pnNow = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

func pnFiles() map[string]string {
	return map[string]string{"ritueel.yaml": pfPersonal, "want/roots/openpgp.yaml": pnRoot, "want/cards/day-ana.yaml": pnCard, "want/delegations/daily.yaml": pnSign}
}

func pnFind(t testing.TB, dir string, now func() time.Time) (*ceremony.Found, error) {
	t.Helper()
	return ceremony.Find(context.Background(), ceremony.FindInput{FS: pfOpen(t, dir), Now: now})
}

func pnWith(extra map[string]string, drop ...string) map[string]string {
	files := pnFiles()
	for _, d := range drop {
		delete(files, d)
	}
	for k, v := range extra {
		files[k] = v
	}
	return files
}

func TestAPersonalBundleThatPassesItsWantedFilesIsRefusedAsNotBuilt(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"all the files":      pnFiles(),
		"the root only":      pnWith(nil, "want/cards/day-ana.yaml", "want/delegations/daily.yaml"),
		"with further users": pnWith(map[string]string{"want/openpgp.yaml": "version: 1\nuser_ids:\n  - {name: Ada, address: ada@example.org}\n"}),
	} {
		t.Run(name, func(t *testing.T) {
			dir := pfWrite(t, files)
			before := tree(t, dir)
			f, err := pnFind(t, dir, func() time.Time { return pnNow })
			if f != nil || pfKind(err) != "not-built" || !errors.Is(err, ceremony.ErrNotBuilt) {
				t.Fatalf("Find = %+v, %v (%s)", f, err, pfKind(err))
			}
			if !strings.Contains(err.Error(), pnRefusal) || !strings.HasSuffix(err.Error(), "nothing was written") || !pfPrintable(err.Error()) {
				t.Errorf("the text: %v", err)
			}
			sameTree(t, "Find", before, tree(t, dir))
		})
	}
}

func TestAPersonalBundleWhoseWantedFilesFailIsRefusedByTheFileNotAsNotBuilt(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		now   func() time.Time
		words []string
	}{
		"an x509 root":                     {pnWith(map[string]string{"want/roots/openpgp.yaml": pfX509Test}, "want/delegations/daily.yaml"), nil, []string{"want/roots/openpgp.yaml", "personal bundle has one OpenPGP root"}},
		"no root":                          {pnWith(nil, "want/roots/openpgp.yaml", "want/delegations/daily.yaml"), nil, []string{"want/roots", "personal bundle needs one root file"}},
		"two roots":                        {pnWith(map[string]string{"want/roots/other.yaml": pnRoot}), nil, []string{"want/roots/other.yaml", "second root file"}},
		"too many roots":                   {manyRoots(), nil, []string{"want/roots", "one root file"}},
		"the placeholder":                  {pnWith(map[string]string{"want/roots/openpgp.yaml": strings.Replace(pnRoot, "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", strings.Repeat("0", 40), 1)}), nil, []string{"want/roots/openpgp.yaml:5", "replace the placeholder"}},
		"a key that ended":                 {pnFiles(), func() time.Time { return time.Date(2029, 11, 26, 0, 0, 0, 0, time.UTC) }, []string{"want/roots/openpgp.yaml:5", "keys[1]", "not after now"}},
		"a key too far":                    {pnFiles(), func() time.Time { return time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC) }, []string{"keys[1]", "more than 36 months"}},
		"no clock":                         {pnFiles(), nil, []string{"no clock"}},
		"a zero clock":                     {pnFiles(), func() time.Time { return time.Time{} }, []string{"no clock"}},
		"the example fingerprint":          {pnWith(map[string]string{"want/roots/openpgp.yaml": strings.Replace(pnRoot, "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", "0123456789abcdef0123456789abcdef01234567", 1)}), nil, []string{"want/roots/openpgp.yaml:5", "the fingerprint of the examples"}},
		"the example person":               {pnWith(map[string]string{"ritueel.yaml": strings.Replace(strings.Replace(pfPersonal, "Example Person", "Ada Example", 1), "person@example.org", "ada@example.com", 1)}), nil, []string{"ritueel.yaml", "replace the example person with your name and address"}},
		"a store that a person cannot use": {pnWith(map[string]string{"ritueel.yaml": strings.Replace(pfPersonal, "[openpgp-card]", "[openpgp-card, aws-kms]", 1)}), nil, []string{"ritueel.yaml", "policy.stores holds aws-kms"}},
		"17 delegations":                   {seventeenDelegations(), nil, []string{"want/delegations", "at most 16 delegation files"}},
		"a card that is gone":              {pnWith(nil, "want/cards/day-ana.yaml"), nil, []string{"want/delegations/daily.yaml", "has no card file"}},
		"a delegation with no card": {pnWith(map[string]string{"want/delegations/daily.yaml": strings.Replace(pnSign, "card: day-ana\n", "", 1)}), nil,
			[]string{"want/delegations/daily.yaml", "needs the member card"}},
		"the same pair twice":        {pnWith(map[string]string{"want/delegations/again.yaml": pnSign}), nil, []string{"want/delegations/daily.yaml", "in the delegation again already"}},
		"user IDs that fail":         {pnWith(map[string]string{"want/openpgp.yaml": "version: 1\nuser_ids:\n  - {name: Example Person, address: person@example.org, retire: true}\n"}), nil, []string{"want/openpgp.yaml", "cannot be retired here"}},
		"user IDs that are not read": {pnWith(map[string]string{"want/openpgp.yaml": "version: 1\nprimary: x\n"}), nil, []string{"want/openpgp.yaml:2", "not known"}},
		"aws_kms in the settings":    {pnWith(map[string]string{"ritueel.yaml": pfPersonal + "aws_kms: {}\n"}), nil, []string{"ritueel.yaml", "aws_kms is not allowed in a personal bundle"}},
		"a bad card file":            {pnWith(map[string]string{"want/cards/bad.yaml": "version: 2\n"}), nil, []string{"want/cards/bad.yaml"}},
	} {
		t.Run(name, func(t *testing.T) {
			now := tc.now
			if now == nil && name != "no clock" {
				now = func() time.Time { return pnNow }
			}
			dir := pfWrite(t, tc.files)
			before := tree(t, dir)
			f, err := pnFind(t, dir, now)
			if f != nil || err == nil || pfKind(err) == "not-built" || errors.Is(err, ceremony.ErrNotBuilt) {
				t.Fatalf("Find = %+v, %v (%s)", f, err, pfKind(err))
			}
			for _, w := range tc.words {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the text %q lacks %q", err, w)
				}
			}
			if !pfPrintable(err.Error()) {
				t.Errorf("the text is not printable ASCII: %+q", err.Error())
			}
			sameTree(t, "Find", before, tree(t, dir))
		})
	}
}

// seventeenDelegations has 17 files that no reader would accept: the count is refused before any is read.
func seventeenDelegations() map[string]string {
	files := pnFiles()
	for i := range 17 {
		files[fmt.Sprintf("want/delegations/x%02d.yaml", i)] = "not a delegation\n"
	}
	return files
}

func manyRoots() map[string]string {
	files := pnWith(nil, "want/delegations/daily.yaml")
	for i := range 10 {
		files[fmt.Sprintf("want/roots/r%d.yaml", i)] = pnRoot
	}
	return files
}

func TestTheKeysOfAPersonAreNotARootOfACompanyBundle(t *testing.T) {
	dir := pfWrite(t, map[string]string{"ritueel.yaml": pfSettings, "want/roots/openpgp.yaml": pnRoot})
	f, err := pfFind(t, dir)
	if f != nil || err == nil || errors.Is(err, ceremony.ErrNotBuilt) || !strings.Contains(err.Error(), "want/roots/openpgp.yaml") || !strings.Contains(err.Error(), "for the OpenPGP root of a personal bundle") {
		t.Errorf("Find = %+v, %v", f, err)
	}
	// What a company bundle held before is as it was: an OpenPGP root file is not built.
	dir = pfWrite(t, map[string]string{"ritueel.yaml": pfSettings, "want/roots/openpgp.yaml": pfOpenPGPTest})
	if _, err := pfFind(t, dir); pfKind(err) != "not-built" {
		t.Errorf("Find = %v (%s)", err, pfKind(err))
	}
}
