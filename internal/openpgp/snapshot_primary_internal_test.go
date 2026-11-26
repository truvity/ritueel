package openpgp

import (
	"testing"
	"time"
)

// The rule for "which user ID is the primary one" depends on nothing of the order of the list.
func TestSnapshotPrimaryUserID(t *testing.T) {
	at := func(n int) time.Time { return time.Unix(1700000000+int64(n), 0).UTC() }
	u := func(text string, primary, revoked bool, signed int) snapUserID {
		return snapUserID{text: []byte(text), primary: primary, revoked: revoked, signed: at(signed)}
	}
	cases := []struct {
		name  string
		users []snapUserID
		want  string
		ok    bool
	}{
		{"one", []snapUserID{u("a", false, false, 1)}, "a", true},
		{"none live", []snapUserID{u("a", true, true, 5), u("b", false, true, 6)}, "", false},
		{"no user ID", nil, "", false},
		{"the flag beats a newer user ID", []snapUserID{u("a", true, false, 1), u("b", false, false, 9)}, "a", true},
		{"the newest of the flagged", []snapUserID{u("a", true, false, 1), u("b", true, false, 2), u("c", true, false, 0)}, "b", true},
		{"the same second: the smaller text", []snapUserID{u("b", true, false, 3), u("a", true, false, 3)}, "a", true},
		{"none flagged: the newest", []snapUserID{u("a", false, false, 1), u("b", false, false, 4), u("c", false, false, 2)}, "b", true},
		{"none flagged, the same second: the smaller text", []snapUserID{u("c", false, false, 4), u("b", false, false, 4)}, "b", true},
		{"a revoked one that is flagged and newest is not it", []snapUserID{u("a", true, true, 9), u("b", false, false, 1)}, "b", true},
		{"a revoked one does not count as flagged", []snapUserID{u("a", true, true, 9), u("b", true, false, 1), u("c", false, false, 5)}, "b", true},
	}
	for _, c := range cases {
		for _, order := range []string{"as given", "reversed"} {
			users := append([]snapUserID(nil), c.users...)
			if order == "reversed" {
				for i, j := 0, len(users)-1; i < j; i, j = i+1, j-1 {
					users[i], users[j] = users[j], users[i]
				}
			}
			s := fkSnapshot{users: users}
			i, ok := s.primaryUserID()
			got := ""
			if ok {
				got = string(users[i].text)
			}
			if ok != c.ok || got != c.want {
				t.Errorf("%s (%s): %q %v, want %q %v", c.name, order, got, ok, c.want, c.ok)
			}
		}
	}
}
