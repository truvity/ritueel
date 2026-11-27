package wanted_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/wanted"
)

// One test for each point of the second round on the wanted files of a person.

// Point 5: the placeholder and the example fingerprint are constants. This does not compile when one is a variable.
const (
	_ = wanted.PlaceholderFingerprint
	_ = wanted.ExampleFingerprint
)

func TestOneRuleForEveryAddress(t *testing.T) {
	for name, addr := range map[string]string{
		"two at signs":     `"\"a@b\"@example.org"`,
		"a domain literal": `"a@[127.0.0.1]"`,
		"a bracket":        `"a]@example.org"`,
		"no at sign":       `"example.org"`,
	} {
		t.Run(name, func(t *testing.T) {
			_ = refuseSettings(t, strings.Replace(personalPerson, "ben@example.com", addr, 1), 3, "person.address is one bare address")
			_ = refuseSettings(t, strings.Replace(goodSettings, "release@example.org", addr, 1), 3, "release_address is one bare address")
			_, err := wanted.ParseUserIDs([]byte("version: 1\nuser_ids:\n  - {name: Ada, address: " + addr + "}\n"))
			_ = wantFault(t, err, wanted.UserIDsPath, 3, "user_ids[1].address is one bare address")
		})
	}
}

func TestMoreThan16DelegationNamesAreRefusedBeforeAnyIsRead(t *testing.T) {
	files := map[string]string{"ritueel.yaml": personalPerson}
	for i := range wanted.MaxPersonalDelegations + 1 {
		files[fmt.Sprintf("want/delegations/d%02d.yaml", i)] = "not a delegation\n"
	}
	_, fsys := bundleDir(t, files)
	s := mustPersonal(t)
	for name, call := range map[string]func() error{
		"ListDelegations":  func() error { _, err := wanted.ListDelegations(fsys, s); return err },
		"CheckDelegations": func() error { return wanted.CheckDelegations(fsys, s) },
	} {
		_ = wantFault(t, call(), wanted.DelegationsDir, 0, "a personal bundle holds at most 16 delegation files")
		_ = name
	}
	// A company bundle has no such limit: the files are read, and the first one is refused as a file.
	err := wanted.CheckDelegations(fsys, mustSettings(t, goodSettings))
	_ = wantFault(t, err, "want/delegations/d00.yaml", -1)
}

func TestKMSReadRolesAreNotInAPersonalDelegation(t *testing.T) {
	text := personalSign + "kms_read_roles:\n  \"111122223333\": arn:aws:iam::111122223333:role/example-certifier-read\n"
	d, err := wanted.ParseDelegation("daily", []byte(text), mustPersonal(t))
	if d != nil {
		t.Error("a value beside the error")
	}
	_ = wantFault(t, err, "want/delegations/daily.yaml", 6, "kms_read_roles is not a member of a delegation of a personal bundle")
}

func TestTheExpiryTextsSayTheZoneAndTodayInUTC(t *testing.T) {
	west := time.Date(2026, 11, 26, 20, 0, 0, 0, time.FixedZone("west", -8*3600)) // 2026-11-27 04:00 UTC
	key := mustRoot(t, "openpgp", strings.Replace(personalOpenPGP, "2029-11-26", "2026-11-27", 1)).Keys()[0]
	got := key.ExpiryProblem(west)
	for _, w := range []string{"00:00 UTC", "today in UTC is 2026-11-27"} {
		if !strings.Contains(got, w) {
			t.Errorf("%q lacks %q", got, w)
		}
	}
	far := mustRoot(t, "openpgp", personalOpenPGP).Keys()[0].ExpiryProblem(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
	if !strings.Contains(far, "00:00 UTC") || !strings.Contains(far, "latest day is 2029-11-20") {
		t.Errorf("%q", far)
	}
}

func TestUserIDsThatDifferOnlyInTheCaseOfTheNameAreOne(t *testing.T) {
	_, err := wanted.ParseUserIDs([]byte("version: 1\nuser_ids:\n  - {name: Ada Example, address: a@example.org}\n  - {name: ADA EXAMPLE, address: A@EXAMPLE.ORG}\n"))
	_ = wantFault(t, err, wanted.UserIDsPath, -1, "user_ids[2] is a user ID that an earlier entry has")
	ids, err := wanted.ParseUserIDs([]byte("version: 1\nuser_ids:\n  - {name: BEN EXAMPLE, address: ben@example.com}\n"))
	if err != nil {
		t.Fatal(err)
	}
	_ = wantFault(t, wanted.CheckPersonal(mustPersonal(t), []*wanted.Root{mustRoot(t, "openpgp", personalOpenPGP)}, nil, nil, ids, personalNow),
		wanted.UserIDsPath, -1, "user_ids[1]", "always the primary user ID")
}

func TestTheFingerprintOfTheExamplesIsRefusedByName(t *testing.T) {
	for _, fp := range []string{wanted.ExampleFingerprint, strings.ToUpper(wanted.ExampleFingerprint)} {
		refuseKeys(t, strings.Replace(personalOpenPGP, adoptedFP, fp, 1), 6, "keys[1].fingerprint is the fingerprint of the examples: replace it with the fingerprint of your key")
	}
}

func TestTheExamplePersonOfTheStarterIsRefusedByName(t *testing.T) {
	for _, person := range []string{
		"person: {name: Ada Example, address: ada@example.com}",
		"person: {name: ADA EXAMPLE, address: Ada@Example.com}",
	} {
		_ = refuseSettings(t, strings.Replace(personalPerson, "person: {name: Ben Example, address: ben@example.com}", person, 1), 3, "replace the example person with your name and address")
	}
	// The name alone, or the address alone, is no example person.
	mustSettings(t, strings.Replace(personalPerson, "ben@example.com", "ada@example.com", 1))
	mustSettings(t, strings.Replace(personalPerson, "Ben Example", "Ada Example", 1))
}

func TestAZeroClockIsNoClock(t *testing.T) {
	key := mustRoot(t, "openpgp", personalOpenPGP).Keys()[0]
	if got := key.ExpiryProblem(time.Time{}); !strings.Contains(got, "no clock") {
		t.Errorf("ExpiryProblem = %q", got)
	}
	err := wanted.CheckPersonal(mustPersonal(t), []*wanted.Root{mustRoot(t, "openpgp", personalOpenPGP)}, nil, nil, nil, time.Time{})
	_ = wantFault(t, err, "ritueel.yaml", -1, "no clock")
}

func TestAPersonalBundleHoldsOnlyTheStoresOfAPersonsKey(t *testing.T) {
	with := func(stores string) string {
		return strings.Replace(personalPerson, "[openpgp-card, software]", stores, 1)
	}
	for _, stores := range []string{"[openpgp-card]", "[software]", "[openpgp-card, software]"} {
		mustSettings(t, with(stores))
	}
	for stores, word := range map[string]string{"[aws-kms]": "aws-kms", "[openpgp-card, aws-kms]": "aws-kms"} {
		_ = refuseSettings(t, with(stores), 5, "policy.stores holds "+word+", which a person's key cannot use", "openpgp-card and software")
	}
	// The store piv is reserved for stage two, like the roles published and standby.
	for _, stores := range []string{"[piv]", "[software, piv]"} {
		_ = refuseSettings(t, with(stores), 5, "policy.stores holds piv, which is reserved for stage two", "which is not built yet")
	}
	// A company bundle keeps all four.
	mustSettings(t, goodSettings)
}

// CheckPersonal refuses a nil entry and a value that no reader made, and never panics.
func TestCheckPersonalRefusesANilEntryAndAValueNoReaderMade(t *testing.T) {
	s := mustPersonal(t)
	root := mustRoot(t, "openpgp", personalOpenPGP)
	card := mustCard(t, "day-ana", personalCard)
	deleg, err := wanted.ParseDelegation("daily", []byte(personalSign), s)
	if err != nil {
		t.Fatal(err)
	}
	roots := []*wanted.Root{root}
	if err := wanted.CheckPersonal(s, roots, []*wanted.Delegation{deleg}, []*wanted.Card{card}, nil, personalNow); err != nil {
		t.Fatalf("the control: %v", err)
	}
	for name, call := range map[string]func() error{
		"nil settings":  func() error { return wanted.CheckPersonal(nil, roots, nil, nil, nil, personalNow) },
		"zero settings": func() error { return wanted.CheckPersonal(&wanted.Settings{}, roots, nil, nil, nil, personalNow) },
		"a nil root":    func() error { return wanted.CheckPersonal(s, []*wanted.Root{nil}, nil, nil, nil, personalNow) },
		"a zero root":   func() error { return wanted.CheckPersonal(s, []*wanted.Root{{}}, nil, nil, nil, personalNow) },
		"a nil delegation": func() error {
			return wanted.CheckPersonal(s, roots, []*wanted.Delegation{nil}, []*wanted.Card{card}, nil, personalNow)
		},
		"a zero delegation": func() error {
			return wanted.CheckPersonal(s, roots, []*wanted.Delegation{{}}, []*wanted.Card{card}, nil, personalNow)
		},
		"a nil card": func() error {
			return wanted.CheckPersonal(s, roots, []*wanted.Delegation{deleg}, []*wanted.Card{nil}, nil, personalNow)
		},
		"a zero card": func() error {
			return wanted.CheckPersonal(s, roots, []*wanted.Delegation{deleg}, []*wanted.Card{{}}, nil, personalNow)
		},
		"zero user IDs":       func() error { return wanted.CheckPersonal(s, roots, nil, nil, &wanted.UserIDs{}, personalNow) },
		"a nil list of roots": func() error { return wanted.CheckPersonal(s, nil, nil, nil, nil, personalNow) },
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			var e *wanted.Error
			if !errors.As(err, &e) {
				t.Fatalf("the error is %T (%v), want a *wanted.Error", err, err)
			}
		})
	}
}
