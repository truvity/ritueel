package wanted_test

import (
	"os"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// knownFaultsEnv switches on the tests that prove a fault that is reported and not fixed yet. They are skipped by
// default so that the suite stays green: run them with RITUEEL_KNOWN_FAULTS=1 to see them fail.
const knownFaultsEnv = "RITUEEL_KNOWN_FAULTS"

func knownFault(t *testing.T, what string) {
	t.Helper()
	if os.Getenv(knownFaultsEnv) == "" {
		t.Skipf("a known fault, not fixed yet (%s=1 runs it): %s", knownFaultsEnv, what)
	}
}

// CheckPersonal is given values that the readers made: its doc comment says so, and every other function of the
// package that takes a Settings, a Root, a UserIDs or a Card refuses a value whose Valid is false (a Delegation and
// a Card have Valid too). It checks the Settings, the roots and the user IDs, and takes a delegation or a card
// as it comes: a nil element is a nil dereference at personal.go (checkSubkeys reads d.Type and c.Name), and a
// Delegation or a Card that a caller built by hand, with the right fields, passes as if a reader had read it.
func TestCheckPersonalRefusesADelegationOrACardThatNoReaderMade(t *testing.T) {
	knownFault(t, "personal.go checkSubkeys: a nil delegation or card panics, and a hand-made one passes the check")
	s, root := mustPersonal(t), mustRoot(t, "openpgp", personalOpenPGP)
	good := mustDelegationFor(t, s)
	card := mustCard(t, "day-ana", personalCard)
	handDelegation := &wanted.Delegation{Name: "daily", Type: wanted.TypeOpenPGPSubkey, Root: "openpgp", Capability: "sign", Card: "day-ana"}
	handCard := &wanted.Card{Name: "day-ana", Kind: wanted.CardDayToDay, Applications: []wanted.Application{wanted.AppOpenPGP}}
	for name, tc := range map[string]struct {
		ds []*wanted.Delegation
		cs []*wanted.Card
	}{
		"a nil delegation":          {[]*wanted.Delegation{nil}, []*wanted.Card{card}},
		"a nil card":                {[]*wanted.Delegation{good}, []*wanted.Card{nil}},
		"a delegation made by hand": {[]*wanted.Delegation{handDelegation}, []*wanted.Card{card}},
		"a card made by hand":       {[]*wanted.Delegation{good}, []*wanted.Card{handCard}},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("CheckPersonal panics: %v", r)
				}
			}()
			err := wanted.CheckPersonal(s, []*wanted.Root{root}, tc.ds, tc.cs, nil, personalNow)
			if err == nil {
				t.Fatal("CheckPersonal accepts it")
			}
			_ = wantFault(t, err, "", -1, "not made by the reader")
		})
	}
}
