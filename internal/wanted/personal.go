package wanted

import (
	"fmt"
	"slices"
	"time"
)

// MaxPersonalDelegations is the most delegation files of a personal bundle.
const MaxPersonalDelegations = 16

// CheckPersonal judges the wanted files of a personal bundle against each other, after each has passed its own
// reader. It returns nil, or the first fault as an [*Error] that names the file. The caller gives every file
// that the bundle has: the roots of want/roots (roots), the delegations, the cards and, when the file exists,
// the user IDs (nil when it does not). now is the clock of the caller's environment: the package reads none.
//
// A personal bundle has exactly one root, of the kind openpgp, and no X.509 or SSH CA root. The root has
// encryption and 1 to [MaxKeys] keys, and every key expires on a day after now and within [MaxValidMonths]
// months. A delegation is one key: the type openpgp-subkey under that root, for one card and one capability, and
// no pair of card and capability is there twice; there are at most [MaxPersonalDelegations] of them. The card
// that it names has a card file, is of the kind day-to-day (or rehearsal, when the root is a test root) and has
// the application openpgp. The person of ritueel.yaml is the one primary user ID, so a user ID of the user IDs
// file is not the person's own, and in particular does not retire it.
func CheckPersonal(s *Settings, roots []*Root, delegations []*Delegation, cards []*Card, userIDs *UserIDs, now time.Time) error {
	if !s.Valid() || !s.Personal || s.Person == nil {
		return errorf(SettingsPath, 0, "the settings of a personal bundle are needed to judge its wanted files, and these were not made by the reader")
	}
	root, err := personalRoot(roots, now)
	if err != nil {
		return err
	}
	if len(delegations) > MaxPersonalDelegations {
		return errorf(DelegationsDir, 0, fmt.Sprintf("a personal bundle holds at most %d delegation files", MaxPersonalDelegations))
	}
	if err := checkSubkeys(root, delegations, cards); err != nil {
		return err
	}
	if userIDs == nil {
		return nil
	}
	if !userIDs.Valid() {
		return errorf(UserIDsPath, 0, "the user IDs were not made by the reader")
	}
	own := UserID{Name: s.Person.Name, Address: s.Person.Address}
	for i, u := range userIDs.entries {
		switch {
		case sameUserID(own, u) && u.Retire:
			return errorf(UserIDsPath, 0, fmt.Sprintf("user_ids[%d] retires the user ID of person in %s: that is the primary user ID of the key, and it cannot be retired here", i+1, SettingsPath))
		case sameUserID(own, u):
			return errorf(UserIDsPath, 0, fmt.Sprintf("user_ids[%d] is the user ID of person in %s, which is always the primary user ID: write only further ones", i+1, SettingsPath))
		}
	}
	return nil
}

// personalRoot returns the one root of a personal bundle after judging it and its keys.
func personalRoot(roots []*Root, now time.Time) (*Root, error) {
	for _, r := range roots {
		if !r.Valid() {
			return nil, errorf(RootsDir, 0, "a root file was not made by the reader")
		}
		if r.Kind != RootOpenPGP {
			return nil, errorf(r.File.Path, 0, "a personal bundle has one OpenPGP root and no root of the kind "+string(r.Kind)+": delete this file")
		}
	}
	switch len(roots) {
	case 0:
		return nil, errorf(RootsDir, 0, "a personal bundle needs one root file of the kind openpgp")
	case 1:
	default:
		return nil, errorf(roots[1].File.Path, 0, "a personal bundle has one root, and this is the second root file: delete one")
	}
	root := roots[0]
	if _, set := root.Encryption(); !set {
		return nil, errorf(root.File.Path, 0, "a root file of a personal bundle needs the member encryption: true for an encryption subkey on every day-to-day card, false for none")
	}
	if len(root.keys) == 0 {
		return nil, errorf(root.File.Path, 0, fmt.Sprintf("a root file of a personal bundle needs the member keys, with 1 to %d entries", MaxKeys))
	}
	for i, k := range root.keys {
		if why := k.ExpiryProblem(now); why != "" {
			return nil, errorf(root.File.Path, k.line, fmt.Sprintf("keys[%d]: %s", i+1, why))
		}
	}
	return root, nil
}

// checkSubkeys judges the delegations of a personal bundle against its root and its card files.
func checkSubkeys(root *Root, delegations []*Delegation, cards []*Card) error {
	byName := make(map[string]*Card, len(cards))
	for _, c := range cards {
		byName[c.Name] = c
	}
	type pair struct{ card, capability string }
	seen := map[pair]string{}
	for _, d := range delegations {
		fail := func(msg string) error { return errorf(d.File.Path, 0, msg) }
		if d.Type != TypeOpenPGPSubkey {
			return fail("a personal bundle holds delegations of the type " + TypeOpenPGPSubkey + " only")
		}
		if d.Root != root.Name {
			return fail("the delegation is under the root " + d.Root + ", and a personal bundle has the one root " + root.Name)
		}
		c := byName[d.Card]
		switch {
		case c == nil:
			return fail("the card " + d.Card + " has no card file in " + CardsDir)
		case c.Kind != CardDayToDay && (c.Kind != CardRehearsal || !root.Test):
			return fail("the card " + d.Card + " is of the kind " + string(c.Kind) + ": the subkeys of a person are on a day-to-day card (a rehearsal card only for a test root)")
		case !slices.Contains(c.Applications, AppOpenPGP):
			return fail("the card " + d.Card + " does not list the application openpgp")
		}
		p := pair{d.Card, d.Capability}
		if first, dup := seen[p]; dup {
			return fail("the card " + d.Card + " has the capability " + d.Capability + " in the delegation " + first + " already: one delegation is one key")
		}
		seen[p] = d.Name
	}
	return nil
}

// CheckCompanyRoots refuses, in a bundle that is not personal, the members of a root file that are a person's:
// the keys and the encryption switch of an OpenPGP root. The revocation reasons are no person's alone.
func CheckCompanyRoots(roots []*Root) error {
	for _, r := range roots {
		if !r.Valid() {
			return errorf(RootsDir, 0, "a root file was not made by the reader")
		}
		if len(r.keys) > 0 || r.encryptionS {
			return errorf(r.File.Path, 0, "the members keys and encryption are for the OpenPGP root of a personal bundle (kind: personal in ritueel.yaml) only")
		}
	}
	return nil
}
