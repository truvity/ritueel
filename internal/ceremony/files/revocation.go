package files

import (
	"fmt"
	"maps"
	"slices"
)

// The reasons of a revocation signature of an OpenPGP primary, in the words of the page
// (docs/reference/revocation-material.md, "What is made"; record 0007, rule 21), and the reason of the
// entry of a removal authorisation in the list "revocations" of a record.
const (
	// ReasonCompromised is the reason of the signature that says the key was compromised. It is
	// always made.
	ReasonCompromised = "compromised"
	// ReasonSuperseded is the reason of the signature that says the key was superseded. It is
	// always made.
	ReasonSuperseded = "superseded"
	// ReasonRetired is the reason of the signature that says the key was retired. The holder asks
	// for it.
	ReasonRetired = "retired"
	// ReasonNoReason is the reason of the signature that gives no reason. The holder asks for it.
	ReasonNoReason = "no-reason"
	// ReasonRootRemoval is the reason of the entry of a removal authorisation: the digest of the
	// text of the authorisation, not of a signature packet.
	ReasonRootRemoval = "root-removal"
)

// MaxRevocations is the most entries that the list "revocations" of one record holds: 5 for each of
// the 26 labels that a trust set can hold (a removal authorisation and the four reasons), 130. A
// list that is longer is not a list of this program.
const MaxRevocations = 5 * 26

// revocationReasons are the four reasons of a revocation signature, the always-made two first.
var revocationReasons = []string{ReasonCompromised, ReasonSuperseded, ReasonRetired, ReasonNoReason}

// RevocationEntry is one entry of "revocations" of a record: the digest of one revocation signature
// packet or of one removal authorisation, and the reason. It holds no signature and no part of
// one (record 0007, rule 23): a digest names material that is kept elsewhere.
type RevocationEntry struct {
	// Label is the label of the root key the entry is for: one upper-case letter.
	Label string `json:"label"`
	// Reason is compromised, superseded, retired, no-reason, or root-removal.
	Reason string `json:"reason"`
	// SHA256 is the digest: of the binary signature packet, or, for root-removal, of the text of
	// the removal authorisation as stored. 64 lower-case hexadecimal digits.
	SHA256 string `json:"sha256"`
}

// CheckRevocationEntry judges the form of one entry: the label, the reason and the digest, each
// required. It returns a *[FormatError] that names the member, or nil.
func CheckRevocationEntry(e RevocationEntry) error {
	return checkRevocationEntry(checker{what: "ceremony record"}, "revocations", e)
}

func checkRevocationEntry(c checker, at string, e RevocationEntry) error {
	if e.Label == "" {
		return c.missing(at + ".label")
	}
	if err := c.label(at+".label", e.Label); err != nil {
		return err
	}
	if err := c.oneOf(at+".reason", e.Reason, append([]string{ReasonRootRemoval}, revocationReasons...)...); err != nil {
		return err
	}
	return c.digest(at+".sha256", e.SHA256, true)
}

// checkRevocations judges the list "revocations" of a record: not an empty list (a writer leaves the
// member out), at most [MaxRevocations] entries (checked before an entry is looked at), each entry
// whole and in its form, and no (label, reason) pair twice.
func (c checker) revocations(list []RevocationEntry) error {
	if list == nil {
		return nil
	}
	if len(list) == 0 {
		return formatError(c.what, "revocations", "is an empty list: leave the member out, or give it an entry")
	}
	if len(list) > MaxRevocations {
		return formatError(c.what, "revocations", "holds %d entries, more than the %d that a record lists", len(list), MaxRevocations)
	}
	seen := make(map[[2]string]bool, len(list))
	for i, e := range list {
		at := fmt.Sprintf("revocations[%d]", i)
		if err := checkRevocationEntry(c, at, e); err != nil {
			return err
		}
		k := [2]string{e.Label, e.Reason}
		if seen[k] {
			return formatError(c.what, at, "is the key %s and the reason %s again: an entry stands once for a pair", shown(e.Label), shown(e.Reason))
		}
		seen[k] = true
	}
	return nil
}

// revocationDigests judges the member "revocations" of a root.json: an object from a reason to the
// SHA-256 of that signature packet. It must hold compromised and superseded (record 0007, rule 21),
// may hold retired and no-reason, and holds no other key and no other value than a digest.
func (c checker) revocationDigests(m map[string]string) error {
	for _, w := range []string{ReasonCompromised, ReasonSuperseded} {
		if _, ok := m[w]; !ok {
			return c.missing("revocations." + w)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if !slices.Contains(revocationReasons, k) {
			return formatError(c.what, "revocations", "the key %s is not one of the four reasons", shown(k))
		}
		if err := c.digest("revocations."+k, m[k], true); err != nil {
			return err
		}
	}
	return nil
}
