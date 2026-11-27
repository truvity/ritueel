package wanted_test

import (
	"errors"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// Each argument of CheckPersonal that a reader makes is refused when no reader made it: nil, the zero value and a
// value built by hand with the right fields, one at a time with every other argument good. No call panics.
func TestEachArgumentOfCheckPersonalIsRefusedWhenNoReaderMadeIt(t *testing.T) {
	s := mustPersonal(t)
	root := mustRoot(t, "openpgp", personalOpenPGP)
	card := mustCard(t, "day-ana", personalCard)
	deleg := mustDelegationFor(t, s)
	ids, err := wanted.ParseUserIDs([]byte("version: 1\nuser_ids: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	handSettings := &wanted.Settings{Personal: true, Person: &wanted.Person{Name: "Ben Example", Address: "ben@example.com"}, Version: 1}
	handRoot := &wanted.Root{Name: "openpgp", Kind: wanted.RootOpenPGP}
	handDeleg := &wanted.Delegation{Name: "daily", Type: wanted.TypeOpenPGPSubkey, Root: "openpgp", Capability: "sign", Card: "day-ana"}
	handCard := &wanted.Card{Name: "day-ana", Kind: wanted.CardDayToDay, Applications: []wanted.Application{wanted.AppOpenPGP}}
	call := func(s *wanted.Settings, r *wanted.Root, d *wanted.Delegation, c *wanted.Card, u *wanted.UserIDs) error {
		return wanted.CheckPersonal(s, []*wanted.Root{r}, []*wanted.Delegation{d}, []*wanted.Card{c}, u, personalNow)
	}
	if err := call(s, root, deleg, card, ids); err != nil {
		t.Fatalf("the control: %v", err)
	}
	if err := call(s, root, deleg, card, nil); err != nil {
		t.Fatalf("no user IDs file is no fault: %v", err)
	}
	for name, run := range map[string]func() error{
		"nil settings":         func() error { return call(nil, root, deleg, card, ids) },
		"zero settings":        func() error { return call(&wanted.Settings{}, root, deleg, card, ids) },
		"hand-made settings":   func() error { return call(handSettings, root, deleg, card, ids) },
		"a nil root":           func() error { return call(s, nil, deleg, card, ids) },
		"a zero root":          func() error { return call(s, &wanted.Root{}, deleg, card, ids) },
		"a hand-made root":     func() error { return call(s, handRoot, deleg, card, ids) },
		"a nil delegation":     func() error { return call(s, root, nil, card, ids) },
		"a zero delegation":    func() error { return call(s, root, &wanted.Delegation{}, card, ids) },
		"hand-made delegation": func() error { return call(s, root, handDeleg, card, ids) },
		"a nil card":           func() error { return call(s, root, deleg, nil, ids) },
		"a zero card":          func() error { return call(s, root, deleg, &wanted.Card{}, ids) },
		"a hand-made card":     func() error { return call(s, root, deleg, handCard, ids) },
		"zero user IDs":        func() error { return call(s, root, deleg, card, &wanted.UserIDs{}) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("CheckPersonal panics: %v", r)
				}
			}()
			err := run()
			var e *wanted.Error
			if !errors.As(err, &e) {
				t.Fatalf("the error is %T (%v), want a *wanted.Error", err, err)
			}
			_ = wantFault(t, err, "", -1, "not made by the reader")
		})
	}
}
