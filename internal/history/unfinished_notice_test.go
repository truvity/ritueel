//go:build linux || darwin

package history

import (
	"strings"
	"testing"
)

// The words of the notice of an unfinished ceremony are for a person. What the notice must state is
// a fact: the end that the end line shows is the end before the ceremony that is open,
// so a person who sees a count of records lower than the one they wrote down knows what a removal
// of a finished ceremony's record looks like. Nothing here holds more than that.
func TestUnfinishedNoticeStatesThatTheEndShownIsTheEndBeforeThatCeremony(t *testing.T) {
	b := newBundle(t)
	b.apply()
	b.apply()
	u := b.unfinished()
	rep := b.run()
	wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(u)}})
	full := detail(rep, UnfinishedCeremony, setPath(u))
	d := strings.ToLower(full)
	if !strings.Contains(d, "end") || !strings.Contains(d, "before") || !strings.Contains(full, u.folder) {
		t.Errorf("the detail %q does not say that the end shown is the end before the ceremony %s", d, u.folder)
	}
}
