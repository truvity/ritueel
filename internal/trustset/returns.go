package trustset

import (
	"strings"

	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/rootlist"
)

// signedNotBeforePrevious is the one switch of the proposed rule that signed_at of a list is not
// earlier than signed_at of the list before it: a clock that went back would give a list that
// expires before the one it replaces. The pages are silent. Equal is allowed.
const signedNotBeforePrevious = true

// labelNeverReused is the one switch of the rule that a label which an earlier list held under
// one pin is not given to another pin (list page, "The list": a label names a key and is never
// reused). `check history` reads pins and fingerprints, not labels, so this refusal is the
// writer's own.
const labelNeverReused = true

// checkEarlier takes the root lists that the caller gives as the history of the bundle before the
// new list. The builder does not order them: the caller gives them in the order of the hash chain,
// the list before the new one last, and a name of a trust set is never read for an order (record
// 0006, rule 54; history.FindReturns). Each list must be one that can be read: at least one and at
// most MaxRoots entries, each with a label A to Z, a pin of 64 lower-case hexadecimal digits and a
// fingerprint of 40 or none. The number of lists is at most MaxEarlier and the entries of all of
// them at most history.MaxRootEntries. A list that is marked unreadable is refused: a writer that
// cannot read a list before it cannot say that no key returns. The names of the lists are never
// shown.
func checkEarlier(earlier []history.RootList) error {
	if len(earlier) > MaxEarlier {
		return fail(ErrParams, "at most %d earlier root lists may be given, there are %d", MaxEarlier, len(earlier))
	}
	total := 0
	for i, l := range earlier {
		if l.Unreadable {
			return fail(ErrParams, "earlier root list %d cannot be read, so no one can say that no root key returns", i)
		}
		if len(l.Keys) == 0 || len(l.Keys) > MaxRoots {
			return fail(ErrParams, "earlier root list %d holds %d entries, a list holds from 1 to %d", i, len(l.Keys), MaxRoots)
		}
		total += len(l.Keys)
		if total > history.MaxRootEntries {
			return fail(ErrParams, "the earlier root lists hold more than %d entries", history.MaxRootEntries)
		}
		for j, k := range l.Keys {
			if !isLabel(k.Label) || !isLowerHex(k.Pin, 64) || (k.Fingerprint != "" && !isLowerHex(k.Fingerprint, 40)) {
				return fail(ErrParams, "earlier root list %d, entry %d: the label, the pin or the fingerprint is not in the form of the page", i, j)
			}
		}
	}
	return nil
}

// checkHistory is the check of the count and of the end of the history. Earlier holds one
// list for each sequence before the new one, so len(Earlier) is Sequence - 1; the last of them holds
// the same entries as Previous; and Previous is read as a list of sequence Sequence - 1. It returns
// the list before the new one, nil for a first list. A bundle whose numbers skip is not built until
// the bundle page says how it is numbered (it says: "Until then the number grows by one"); when it
// does, this is the one place to change.
func checkHistory(in Input) (*rootlist.List, error) {
	if err := checkEarlier(in.Earlier); err != nil {
		return nil, err
	}
	if in.Sequence == 1 {
		if in.Previous != nil || len(in.Earlier) != 0 {
			return nil, fail(ErrParams, "the first list has no list before it")
		}
		return nil, nil
	}
	if in.Previous == nil || int64(len(in.Earlier)) != in.Sequence-1 {
		return nil, fail(ErrParams, "a list of sequence %d needs the previous list and %d earlier lists, the root lists of the bundle in the order of the history", in.Sequence, in.Sequence-1)
	}
	if len(in.Previous) > MaxBytes {
		return nil, fail(ErrParams, "the previous root-list.json is longer than %d bytes", MaxBytes)
	}
	held, err := rootlist.ParseHeld(in.Previous)
	if err != nil {
		return nil, failWith(ErrParams, "the previous root-list.json cannot be read", err)
	}
	if held.List.Sequence != in.Sequence-1 {
		return nil, fail(ErrParams, "the previous list has sequence %d, the new list needs it to be %d", held.List.Sequence, in.Sequence-1)
	}
	if !sameKeys(held.List.Roots, in.Earlier[len(in.Earlier)-1].Keys) {
		return nil, fail(ErrParams, "the last of the earlier lists does not hold the entries of the previous list")
	}
	return held.List, nil
}

// sameKeys reports whether the entries of a list and the keys of a history list are the same
// entries (label, pin, fingerprint), in any order.
func sameKeys(roots []rootlist.Root, keys []history.RootKey) bool {
	if len(roots) != len(keys) {
		return false
	}
	for _, r := range roots {
		want := history.RootKey{Label: r.Label, Pin: r.X509SPKISHA256, Fingerprint: r.OpenPGPFingerprint}
		found := false
		for _, k := range keys {
			if k == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// checkLabelsNeverReused refuses an added entry of the new list that carries a label which an
// earlier list held under another pin, and a removal whose label stands in the roots of the new
// list under another pin (a label is never reused: list page, "The list"). An added entry is one
// whose pin is not in the last of the earlier lists, the list before the new one. A kept entry is
// not asked: a history that reused a label once must not stop the renewal of the key that holds
// it now.
func checkLabelsNeverReused(earlier []history.RootList, roots []Root, removals []Removal) error {
	if !labelNeverReused {
		return nil
	}
	inPrevious := map[string]bool{}
	if len(earlier) > 0 {
		for _, k := range earlier[len(earlier)-1].Keys {
			inPrevious[k.Pin] = true
		}
	}
	heldPins := make(map[string]map[string]bool)
	for _, l := range earlier {
		for _, k := range l.Keys {
			if heldPins[k.Label] == nil {
				heldPins[k.Label] = map[string]bool{}
			}
			heldPins[k.Label][k.Pin] = true
		}
	}
	for _, r := range roots {
		if inPrevious[r.X509SPKISHA256] {
			continue
		}
		for pin := range heldPins[r.Label] {
			if pin != r.X509SPKISHA256 {
				return fail(ErrParams, "the label %s was held by another root key in an earlier list, and a label is never reused", r.Label)
			}
		}
	}
	byLabel := make(map[string]string, len(roots))
	for _, r := range roots {
		byLabel[r.Label] = r.X509SPKISHA256
	}
	for _, rm := range removals {
		if pin, ok := byLabel[rm.Label]; ok && pin != rm.X509SPKISHA256 {
			return fail(ErrParams, "the label %s of a removal stands in roots under another pin, and a label is never reused", rm.Label)
		}
	}
	return nil
}

// checkReturns asks history.FindReturns about the new list before anything is written (record
// 0006, rule 54). roots are in label order. A non-empty answer is ErrReturns: the text starts with
// the reason code and names the label of each entry and whether it came back by its pin, by its
// fingerprint or both. It shows no name of an earlier list, and does not rely on what
// Return.PinHeldOn and Return.FingerprintHeldOn hold.
func checkReturns(earlier []history.RootList, roots []Root) error {
	keys := make([]history.RootKey, len(roots))
	for i, r := range roots {
		keys[i] = history.RootKey{Label: r.Label, Pin: r.X509SPKISHA256, Fingerprint: r.OpenPGPFingerprint}
	}
	found, err := history.FindReturns(earlier, history.RootList{Name: "new", Keys: keys})
	if err != nil {
		return failWith(ErrParams, "the earlier root lists cannot be asked about returns", err)
	}
	if len(found) == 0 {
		return nil
	}
	parts := make([]string, 0, len(found))
	for _, r := range found {
		label := "?"
		if r.Entry >= 0 && r.Entry < len(roots) {
			label = roots[r.Entry].Label
		}
		how := "by its pin"
		switch {
		case r.ByPin && r.ByFingerprint:
			how = "by its pin and by its fingerprint"
		case r.ByFingerprint:
			how = "by its fingerprint"
		}
		parts = append(parts, "root key "+label+" comes back "+how)
	}
	return fail(ErrReturns, "%s: %s; a root key that left never returns (record 0006, rule 54)", CodeRootReturns, strings.Join(parts, "; "))
}
