//go:build linux || darwin

package history

import (
	"strconv"
	"strings"
)

// The words of a finding of root-returns, in the forms that the page of the finding and the doc
// of returnDetail give. The reason comes first and has no name of a set in it; what the reason
// refers to (the set that held the key, the list before, the sets whose order is not sure) comes
// after the rule, each part with its own words, as trust/<name>.

// wsetOf is a set as the detail names it.
func wsetOf(set string) string { return "trust/" + set }

// wPin is the reason of a return by the pin, when the list before can be read.
func wPin(pin string) string {
	return "its pin " + pin[:16] + "... was on an earlier list and is not on the list before this one"
}

// wFP is the reason of a return by the OpenPGP fingerprint, when the list before can be read.
func wFP(fp string) string {
	return "its OpenPGP fingerprint " + fp[:16] + "... was on an earlier list and the list before this one did not hold it under this pin"
}

// wBoth is the reason of an entry that returns by both.
func wBoth(pin, fp string) string {
	return "its pin " + pin[:16] + "... and its OpenPGP fingerprint " + fp[:16] + "... were on an earlier list and the list before this one did not hold them"
}

// wPinUnread, wFPUnread and wBothUnread are the reasons when the list before cannot be read.
func wPinUnread(pin string) string {
	return "its pin " + pin[:16] + "... was on an earlier list and the list before this one cannot be read"
}

func wFPUnread(fp string) string {
	return "its OpenPGP fingerprint " + fp[:16] + "... was on an earlier list and the list before this one cannot be read"
}

func wBothUnread(pin, fp string) string {
	return "its pin " + pin[:16] + "... and its OpenPGP fingerprint " + fp[:16] + "... were on an earlier list and the list before this one cannot be read"
}

// wPinFloating and wFPFloating are the reasons for a set whose place cannot be told.
func wPinFloating(pin string) string {
	return "its pin " + pin[:16] + "... was on another list; the place of this trust set in the chain cannot be told"
}

func wFPFloating(fp string) string {
	return "its OpenPGP fingerprint " + fp[:16] + "... was on another list; the place of this trust set in the chain cannot be told"
}

// wHeldPin, wHeldFP and wBefore are the parts that name a set.
func wHeldPin(set string) string { return "pin held on " + wsetOf(set) }
func wHeldFP(set string) string  { return "fingerprint held on " + wsetOf(set) }
func wBefore(set string) string  { return "list before " + wsetOf(set) }

// wUnsure is what a detail says when the order of the sets is not sure.
const wUnsure = "the order of the trust sets is not sure (record 0006, rule 54)"

// wRule is the rule that closes the reason.
const wRule = " (record 0006, rule 54)"

// wAmong is the part that names the sets whose order is not sure.
func wAmong(sets ...string) string {
	var out []string
	for i, s := range sets {
		if i == 2 {
			return "among " + strings.Join(out, ", ") + " and " + strconv.Itoa(len(sets)-2) + " more"
		}
		out = append(out, wsetOf(s))
	}
	return "among " + strings.Join(out, ", ")
}
