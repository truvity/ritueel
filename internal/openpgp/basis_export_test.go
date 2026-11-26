package openpgp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
)

// BasisAgainstSnapshot compares what SigningBasis says with the snapshot, field by field, and returns each
// difference. It is visible to the tests of the package that stand outside it.
func BasisAgainstSnapshot(k *ForeignKey) []string {
	var diffs []string
	note := func(f string, a ...any) { diffs = append(diffs, fmt.Sprintf(f, a...)) }
	b, s := k.SigningBasis(), &k.snap
	e := s.expiry()
	if b.Fingerprint != hex.EncodeToString(s.fp) || b.Algorithm != k.pub.alg || b.CertificateSHA256 != sha256.Sum256(k.cert) {
		note("Fingerprint, Algorithm or CertificateSHA256")
	}
	if b.PrimaryFlagged != s.flaggedUserIDs() {
		note("PrimaryFlagged")
	}
	if b.DirectHave != s.direct.have || b.DirectWeak != s.direct.weak || b.DirectSigExpires != s.direct.sigExpires ||
		!b.DirectEnd.Equal(s.direct.expires) || !bytes.Equal(b.DirectDropped, s.direct.dropped) || !samePrefs(b.DirectPrefs, s.direct.prefs) {
		note("the direct-key source")
	}
	if b.Revoked != s.revoked {
		note("Revoked")
	}
	if !b.ExpiryEarliest.Equal(e.earliest) || b.ExpiryAny != e.any || b.ExpiryAgree != e.agree || b.ExpiryMarked != e.marked {
		note("the answers about the end of the key")
	}
	if b.DirectTied != s.direct.tied {
		note("DirectTied")
	}
	if !b.Newest.Equal(s.newest) {
		note("Newest")
	}
	if len(b.UserIDs) != len(s.users) {
		note("the number of user IDs: %d and %d", len(b.UserIDs), len(s.users))
	} else {
		primary, have := s.primaryUserID()
		for i, u := range s.users {
			g := b.UserIDs[i]
			switch {
			case g.Text != string(u.text):
				note("user ID %d: Text", i)
			case g.Revoked != u.revoked || !g.Signed.Equal(u.signed) || g.KeyFlags != u.flags || g.Primary != u.primary || !g.KeyExpires.Equal(u.expires):
				note("user ID %d: Revoked, Signed, KeyFlags, Primary or KeyExpires", i)
			case g.SigExpires != u.sigExpires || g.Weak != u.weak || g.AnyStrong != u.anyStrong || g.Tied != u.tied:
				note("user ID %d: SigExpires, Weak, AnyStrong or Tied", i)
			case !samePrefs(g.Prefs, u.prefs) || !bytes.Equal(g.Dropped, u.dropped):
				note("user ID %d: Prefs or Dropped", i)
			case g.IsPrimary != (have && i == primary):
				note("user ID %d: IsPrimary", i)
			case g.TextOK != (checkExistingUserID(u.text) == nil):
				note("user ID %d: TextOK", i)
			}
		}
	}
	if len(b.Subkeys) != len(s.subkeys) {
		note("the number of subkeys: %d and %d", len(b.Subkeys), len(s.subkeys))
	} else {
		for i, u := range s.subkeys {
			g := b.Subkeys[i]
			if g.Fingerprint != hex.EncodeToString(u.fp) || g.Algorithm != u.alg || g.Revoked != u.revoked || g.Weak != u.weak || g.AnyStrong != u.anyStrong || g.Tied != u.tied {
				note("subkey %d", i)
			}
		}
	}
	if !slices.IsSortedFunc(b.UserIDs, func(x, y ForeignBasisUserID) int { return compareStrings(x.Text, y.Text) }) {
		note("the user IDs of the basis are not sorted by text")
	}
	return diffs
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func samePrefs(a []ForeignBasisPref, b []subpacket) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].typ || !bytes.Equal(a[i].Data, b[i].data) {
			return false
		}
	}
	return true
}
