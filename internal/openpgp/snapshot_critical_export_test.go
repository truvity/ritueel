package openpgp

// SnapshotCriticalBits returns, for each user ID of the snapshot, the critical bit of each carried
// subpacket. It is visible to the tests of the package that stand outside it: the exported view of a
// snapshot carries the type and the contents only.
func SnapshotCriticalBits(k *ForeignKey) [][]bool {
	var out [][]bool
	for _, u := range k.snap.users {
		var row []bool
		for _, p := range u.prefs {
			row = append(row, p.critical)
		}
		out = append(out, row)
	}
	return out
}
