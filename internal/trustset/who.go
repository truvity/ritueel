package trustset

import (
	"slices"

	"ritueel.id/ritueel/internal/rootlist"
)

// Kind says what a list does to the root keys of the list it replaces. The zero value is invalid.
type Kind int

// The kinds of list. A list is of one kind: the root keys of a list change by one act at a time
// (record 0007, rule 9; the transitions page).
const (
	// KindFirst is the first list of a bundle: no list before it, sequence 1.
	KindFirst Kind = iota + 1
	// KindRenewal has the same entries of roots as the list before it.
	KindRenewal
	// KindAdd adds one or more root keys and removes none.
	KindAdd
	// KindRetire removes one or more root keys by retiring them and adds none.
	KindRetire
	// KindRevoke removes one or more root keys by revoking them and adds none.
	KindRevoke
)

// String returns "first", "renewal", "add", "retire" or "revoke", and "invalid" for any other value.
func (k Kind) String() string {
	switch k {
	case KindFirst:
		return "first"
	case KindRenewal:
		return "renewal"
	case KindAdd:
		return "add"
	case KindRetire:
		return "retire"
	case KindRevoke:
		return "revoke"
	}
	return "invalid"
}

// Leave says how a root key leaves the list. The zero value is invalid.
type Leave int

// The two ways a root key leaves.
const (
	// LeaveRetired means that the key signs the list itself; the list names no authorisation for it.
	LeaveRetired Leave = iota + 1
	// LeaveRevoked means that the list carries the stored authorisation of the key, if there is one.
	LeaveRevoked
)

// Departure says how one root key of the previous list leaves.
type Departure struct {
	// X509SPKISHA256 is the pin of the key that leaves.
	X509SPKISHA256 string
	// Leave is how the key leaves.
	Leave Leave
	// Authorisation is the stored removal authorisation, the compact JWS, of a revoked key. Empty
	// means "lost": the key must then sign the list itself. It must be empty for a retired key.
	Authorisation string
}

// plan is the result of classify: what kind of list it is and who signs it.
type plan struct {
	kind Kind
	// required are the labels that must sign, in label order; empty for a first list and a renewal.
	required []string
	// oneOf are the labels of which exactly one signs, in label order; empty for the other kinds.
	oneOf []string
	// unnamed are the labels of the revoked keys whose authorisation is lost, in label order.
	unnamed []string
	// signers maps the label of every key that may be asked to sign to its pin. A retired key and
	// a revoked key without an authorisation carry the label of the previous list.
	signers map[string]string
	// silent maps the label of every revoked key whose stored authorisation stands for its
	// signature to its pin: such a key is never asked to sign (record 0007, rule 12).
	silent map[string]string
	// removals are the entries of removals, in label order, one for each revoked key whose
	// authorisation is given. The authorisation is not judged here.
	removals []Removal
}

// classify decides the kind of a list and who signs it, from the entries of the new list, the
// list before it (nil for a first list) and the departures. It is the one place of the rule of who
// signs (list page, "Who signs"; record 0006, rule 18; record 0007, rules 9 and 12). Every change
// that is not one of the five kinds is ErrParams: a list that retires one key and revokes another,
// that adds and removes keys at once (record 0007, rule 9: a change of the root keys runs alone),
// a kept key whose label or fingerprint changed (a label names a key and is never reused), a removed
// key without a departure, a departure for a key that is not removed, a departure twice, a retired
// key with an authorisation, and a list with a first-list departure. roots are in label order and
// have passed checkRoots; the departures have passed checkDepartures.
func classify(prev *rootlist.List, roots []Root, deps []Departure) (plan, error) {
	if prev == nil {
		return classifyFirst(roots, deps)
	}
	byPin := make(map[string]Root, len(roots))
	for _, r := range roots {
		byPin[r.X509SPKISHA256] = r
	}
	prevByPin := make(map[string]rootlist.Root, len(prev.Roots))
	for _, r := range prev.Roots {
		prevByPin[r.X509SPKISHA256] = r
	}
	var removed []rootlist.Root
	for _, p := range prev.Roots {
		now, kept := byPin[p.X509SPKISHA256]
		if !kept {
			removed = append(removed, p)
			continue
		}
		if now.Label != p.Label || now.OpenPGPFingerprint != p.OpenPGPFingerprint {
			return plan{}, fail(ErrParams, "root key %s is kept and its label or its fingerprint changed: a label names a key and is never reused", p.Label)
		}
	}
	var added []Root
	for _, r := range roots {
		if _, had := prevByPin[r.X509SPKISHA256]; !had {
			added = append(added, r)
		}
	}
	switch {
	case len(added) > 0 && len(removed) > 0:
		return plan{}, fail(ErrParams, "a list adds root keys or removes root keys, not both: a change of the root keys runs alone")
	case len(added) == 0 && len(removed) == 0:
		return classifyRenewal(roots, deps)
	case len(removed) == 0:
		return classifyAdd(roots, deps)
	}
	return classifyRemoval(roots, removed, deps)
}

// classifyFirst is the first list: no departure, exactly one signature by any root key.
func classifyFirst(roots []Root, deps []Departure) (plan, error) {
	if len(deps) != 0 {
		return plan{}, fail(ErrParams, "the first list has no root key that leaves")
	}
	return plan{kind: KindFirst, oneOf: labelsOf(roots), signers: signersOf(roots)}, nil
}

// classifyRenewal is a list with the entries of the list before it: exactly one signature by any
// root key (list page, "Who signs", first bullet).
func classifyRenewal(roots []Root, deps []Departure) (plan, error) {
	if len(deps) != 0 {
		return plan{}, fail(ErrParams, "a departure is given for a root key that is not removed")
	}
	return plan{kind: KindRenewal, oneOf: labelsOf(roots), signers: signersOf(roots)}, nil
}

// classifyAdd adds keys: every key of the list before it signs and every added key signs, so every
// label of the new list (list page, "Who signs", second bullet).
func classifyAdd(roots []Root, deps []Departure) (plan, error) {
	if len(deps) != 0 {
		return plan{}, fail(ErrParams, "a departure is given for a root key that is not removed")
	}
	return plan{kind: KindAdd, required: labelsOf(roots), signers: signersOf(roots)}, nil
}

// classifyRemoval removes keys, all retired or all revoked.
func classifyRemoval(roots []Root, removed []rootlist.Root, deps []Departure) (plan, error) {
	depOf := make(map[string]Departure, len(deps))
	for _, d := range deps {
		depOf[d.X509SPKISHA256] = d
	}
	isRemoved := make(map[string]bool, len(removed))
	for _, r := range removed {
		isRemoved[r.X509SPKISHA256] = true
		if _, ok := depOf[r.X509SPKISHA256]; !ok {
			return plan{}, fail(ErrParams, "root key %s leaves and no departure is given for it", r.Label)
		}
	}
	for _, d := range deps {
		if !isRemoved[d.X509SPKISHA256] {
			return plan{}, fail(ErrParams, "a departure is given for a root key that is not removed")
		}
	}
	retired, revoked := 0, 0
	for _, d := range deps {
		switch d.Leave {
		case LeaveRetired:
			if d.Authorisation != "" {
				return plan{}, fail(ErrParams, "a retired root key has no authorisation in the list")
			}
			retired++
		case LeaveRevoked:
			revoked++
		}
	}
	if retired > 0 && revoked > 0 {
		return plan{}, fail(ErrParams, "a list retires root keys or revokes root keys, not both: a change of the root keys runs alone")
	}
	p := plan{signers: signersOf(roots), silent: map[string]string{}}
	for _, r := range removed {
		d := depOf[r.X509SPKISHA256]
		switch {
		case d.Leave == LeaveRetired:
			p.kind = KindRetire
			p.signers[r.Label] = r.X509SPKISHA256
			p.required = append(p.required, r.Label)
		case d.Authorisation != "":
			p.kind = KindRevoke
			p.silent[r.Label] = r.X509SPKISHA256
			p.removals = append(p.removals, Removal{Label: r.Label, X509SPKISHA256: r.X509SPKISHA256, Authorisation: d.Authorisation})
		default:
			p.kind = KindRevoke
			p.signers[r.Label] = r.X509SPKISHA256
			p.required = append(p.required, r.Label)
			p.unnamed = append(p.unnamed, r.Label)
		}
	}
	for _, r := range roots {
		p.required = append(p.required, r.Label)
	}
	slices.Sort(p.required)
	slices.Sort(p.unnamed)
	p.removals = sortRemovals(p.removals)
	return p, nil
}

// checkDepartures takes the departures as they come: at most MaxRoots, each a pin of 64 lower-case
// hexadecimal digits, one of the two ways of leaving, an authorisation of at most MaxBytes, and no
// pin twice. It does not read an authorisation.
func checkDepartures(deps []Departure) error {
	if len(deps) > MaxRoots {
		return fail(ErrParams, "there are at most %d departures, there are %d", MaxRoots, len(deps))
	}
	pins := make(map[string]bool, len(deps))
	for i, d := range deps {
		if !isLowerHex(d.X509SPKISHA256, 64) {
			return fail(ErrParams, "departure %d: the pin is not 64 lower-case hexadecimal digits", i)
		}
		if d.Leave != LeaveRetired && d.Leave != LeaveRevoked {
			return fail(ErrParams, "departure %d: the way of leaving is not retired or revoked", i)
		}
		if len(d.Authorisation) > MaxBytes {
			return fail(ErrParams, "departure %d: the authorisation is longer than %d bytes", i, MaxBytes)
		}
		if pins[d.X509SPKISHA256] {
			return fail(ErrParams, "departure %d: a departure appears twice for one root key", i)
		}
		pins[d.X509SPKISHA256] = true
	}
	return nil
}

// labelsOf returns the labels of roots, in label order.
func labelsOf(roots []Root) []string {
	out := make([]string, len(roots))
	for i, r := range roots {
		out[i] = r.Label
	}
	slices.Sort(out)
	return out
}

// signersOf maps the label of each root to its pin.
func signersOf(roots []Root) map[string]string {
	out := make(map[string]string, len(roots))
	for _, r := range roots {
		out[r.Label] = r.X509SPKISHA256
	}
	return out
}
