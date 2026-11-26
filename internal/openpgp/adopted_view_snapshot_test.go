package openpgp_test

import (
	"slices"
	"sort"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// The exported view of the reader prefers the newest STRONG signature and breaks ties by position; the snapshot
// takes the newest of any hash and breaks ties by what the signatures say. This test reads every key of the
// kit and lists, by field, where the two disagree about one key. The list is a finding, pinned so that a
// change of either side shows.
func TestQAViewAndSnapshotAreCompared(t *testing.T) {
	type diff struct {
		n       int
		example string
	}
	got := map[string]*diff{}
	note := func(field, name string) {
		d := got[field]
		if d == nil {
			d = &diff{example: name}
			got[field] = d
		}
		d.n++
	}
	keys := 0
	for _, f := range qaExports(t) {
		k, err := openpgp.ReadForeignKey(f.file)
		if err != nil {
			continue
		}
		keys++
		snap := openpgp.SnapshotUsers(k)
		byText := map[string]openpgp.ForeignUserID{}
		for _, u := range k.UserIDs {
			if u.Valid {
				if _, ok := byText[u.Text]; !ok {
					byText[u.Text] = u
				}
			}
		}
		for _, s := range snap {
			v, ok := byText[s.Text]
			if !ok {
				note("user ID: in the snapshot and not live in the view", f.name)
				continue
			}
			if s.Flags != v.KeyFlags {
				note("user ID: key flags", f.name+" / "+s.Text)
			}
			if s.Primary != v.Primary {
				note("user ID: primary mark", f.name)
			}
			if !s.Expires.Equal(v.KeyExpires) {
				note("user ID: end of the key", f.name)
			}
			if s.Revoked != v.Revoked {
				note("user ID: revoked", f.name)
			}
			if !s.Signed.Equal(v.Created) {
				note("user ID: time of the newest self-signature (Created)", f.name)
			}
			if s.Weak && !v.WeakHash {
				note("user ID: the source is SHA-1 and the view says WeakHash false", f.name)
			}
			if v.WeakHash != !s.AnyStrong {
				note("user ID: WeakHash against anyStrong", f.name)
			}
		}
		var viewSubs []openpgp.ForeignSubkey
		for _, s := range k.Subkeys {
			if s.InCertificate {
				viewSubs = append(viewSubs, s)
			}
		}
		for i, s := range openpgp.SnapshotSubkeys(k) {
			if i >= len(viewSubs) {
				break
			}
			v := viewSubs[i]
			if !s.Bound.Equal(v.BoundAt) {
				note("subkey: time of the newest binding (BoundAt)", f.name)
			}
			if s.Revoked != v.Revoked {
				note("subkey: revoked", f.name)
			}
			if s.Weak != v.WeakHash && s.Weak {
				note("subkey: the newest binding is SHA-1 and the view says WeakHash false", f.name)
			}
		}
		if openpgp.SnapshotKey(k).Revoked != k.Primary.Revoked {
			note("key: revoked", f.name)
		}
	}
	var fields []string
	for f := range got {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, f := range fields {
		t.Logf("FINDING: the view and the snapshot differ in %s: %d keys of the kit (first: %s)", f, got[f].n, got[f].example)
	}
	t.Logf("%d keys compared", keys)
	want := []string{
		"user ID: end of the key",
		"user ID: key flags",
		"user ID: primary mark",
		"user ID: the source is SHA-1 and the view says WeakHash false",
		"user ID: time of the newest self-signature (Created)",
	}
	if !slices.Equal(fields, want) {
		t.Errorf("the fields in which the view and the snapshot differ for the kit are %q, pinned %q", fields, want)
	}
	if keys < 150 {
		t.Errorf("only %d keys were compared", keys)
	}
}
