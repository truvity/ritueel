package ceremonytest_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony/ceremonytest"
)

// Two calls with equal Options write the same bytes into plan.json and under wanted/: a copy of the
// workstation at AtPlan and a copy of the stick at Recorded are made by two calls and must agree on
// the plan. The keys differ, so the pins, the journals, the root list and the record differ.
func TestEqualOptionsWriteTheSamePlanAndCopies(t *testing.T) {
	a := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtPlan})
	b := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	c := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	if a.Ceremony != b.Ceremony || a.PlanSHA256 != b.PlanSHA256 || b.PlanSHA256 != c.PlanSHA256 {
		t.Errorf("ceremony %s %s, plan %s %s %s", a.Ceremony, b.Ceremony, a.PlanSHA256, b.PlanSHA256, c.PlanSHA256)
	}
	base := filepath.Join("history", a.Ceremony)
	for _, p := range []string{"plan.json", "wanted/ritueel.yaml", "wanted/want/roots/x509.yaml"} {
		x, y, z := readFile(t, a.Dir, base, p), readFile(t, b.Dir, base, p), readFile(t, c.Dir, base, p)
		if !bytes.Equal(x, y) || !bytes.Equal(y, z) {
			t.Errorf("%s differs between two calls with equal options", p)
		}
	}
	// The wanted files of the bundle are the same too, and the copies are those files.
	for _, p := range []string{"ritueel.yaml", "want/roots/x509.yaml"} {
		if !bytes.Equal(readFile(t, a.Dir, p), readFile(t, b.Dir, base, "wanted", p)) {
			t.Errorf("the copy of %s is not the file", p)
		}
	}
	if slices.Equal(b.Pins, c.Pins) || b.Pins[0] == c.Pins[0] || b.Pins[1] == c.Pins[1] {
		t.Errorf("the pins of two runs agree: %v %v: the keys must be new each time", b.Pins, c.Pins)
	}
	if bytes.Equal(readFile(t, b.Dir, "trust", b.Set, "root-list.json"), readFile(t, c.Dir, "trust", c.Set, "root-list.json")) {
		t.Error("two runs wrote the same root list: the keys are not new")
	}
	if b.Set == c.Set {
		t.Errorf("two runs have the trust set %s", b.Set)
	}
}

func readFile(t testing.TB, parts ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func jsonOf(t testing.TB, data []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("%v in %q", err, data)
	}
	return v
}

// Options.Now is read once. The plan, the name of the ceremony folder, the attempt, the record and
// the root list follow it; a time in another zone or with a fraction is the same second in UTC; the
// lines of the journals follow it by one second at each call, strictly one after the other.
func TestNowIsTheClockOfTheCeremony(t *testing.T) {
	zone := time.FixedZone("far", 5*3600+1800)
	at := time.Date(2025, 3, 31, 23, 59, 58, 987654321, zone) // 2025-03-31T18:29:58Z in UTC
	var calls atomic.Int32
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded, Now: func() time.Time { calls.Add(1); return at }})
	if n := calls.Load(); n != 1 {
		t.Errorf("Now was called %d times, want once", n)
	}
	if m.Ceremony != "20250331T182958Z-apply" {
		t.Errorf("Ceremony = %s", m.Ceremony)
	}
	c := filepath.Join("history", m.Ceremony)
	plan := jsonOf(t, readFile(t, m.Dir, c, "plan.json"))
	for _, k := range []string{"made_at", "ceremony_time"} {
		if plan[k] != "2025-03-31T18:29:58Z" {
			t.Errorf("plan %s = %v", k, plan[k])
		}
	}
	if plan["ceremony"] != m.Ceremony {
		t.Errorf("plan ceremony = %v", plan["ceremony"])
	}
	if got := jsonOf(t, readFile(t, m.Dir, c, "attempt.json"))["started_at"]; got != "2025-03-31T18:29:58Z" {
		t.Errorf("started_at = %v", got)
	}
	rec := jsonOf(t, readFile(t, m.Dir, c, "record.json"))
	if rec["started_at"] != "2025-03-31T18:29:58Z" || rec["finished_at"] != "2025-03-31T18:34:58Z" {
		t.Errorf("record started_at %v finished_at %v", rec["started_at"], rec["finished_at"])
	}
	// The root list is good for 13 months from the ceremony.
	list := jsonOf(t, readFile(t, m.Dir, "trust", m.Set, "root-list.json"))
	if list["signed_at"] != "2025-03-31T18:29:58Z" || list["expires_at"] != "2026-04-30T18:29:58Z" {
		t.Errorf("signed_at %v expires_at %v", list["signed_at"], list["expires_at"])
	}
	// The journals: each line is a second after the one before it, and after the plan.
	prev := at.UTC().Truncate(time.Second)
	for _, name := range []string{"births.jsonl", "signatures.jsonl"} {
		for _, line := range strings.Split(strings.TrimSuffix(string(readFile(t, m.Dir, c, name)), "\n"), "\n") {
			ts, err := time.Parse(time.RFC3339, jsonOf(t, []byte(line))["at"].(string))
			if err != nil {
				t.Fatal(err)
			}
			first := prev.Equal(at.UTC().Truncate(time.Second))
			if !ts.After(prev) || (!first && ts.Sub(prev) != time.Second) {
				t.Errorf("%s: a line at %v after %v: the clock runs one second at a call", name, ts, prev)
			}
			prev = ts
		}
	}
}

// A clock of real time minus 13 months plus 50, 25 and 10 days gives a root list that ends in that
// many days: the bands of a command that reads the root list are reached by the age of the bundle.
func TestNowBringsTheEndOfTheRootListToADay(t *testing.T) {
	for _, days := range []int{50, 25, 10, 0, -3} {
		now := time.Now().UTC().Truncate(time.Second)
		start := now.AddDate(0, -13, days)
		m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded, Now: func() time.Time { return start }})
		list := jsonOf(t, readFile(t, m.Dir, "trust", m.Set, "root-list.json"))
		end, err := time.Parse(time.RFC3339, list["expires_at"].(string))
		if err != nil {
			t.Fatal(err)
		}
		// The ends are within the second that the test took, and a month is the month of the calendar.
		want := start.AddDate(0, 13, 0)
		if !end.Equal(want) {
			t.Errorf("days %d: expires_at %v, want %v", days, end, want)
		}
		if left := end.Sub(now); left < time.Duration(days-1)*24*time.Hour-48*time.Hour || left > time.Duration(days+1)*24*time.Hour+48*time.Hour {
			t.Errorf("days %d: the root list ends in %v", days, left)
		}
	}
}

// Another clock gives another plan: the plan follows Now and nothing else of the run.
func TestAnotherClockAnotherPlan(t *testing.T) {
	a := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtPlan})
	b := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtPlan, Now: func() time.Time { return time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC) }})
	if a.PlanSHA256 == b.PlanSHA256 || a.Ceremony == b.Ceremony {
		t.Errorf("the plans agree: %s %s", a.Ceremony, b.Ceremony)
	}
	if b.Ceremony != "20270102T030405Z-apply" {
		t.Errorf("Ceremony = %s", b.Ceremony)
	}
}

// The years that a timestamp can hold are 1 to 9999. Year 1 gives a bundle; a clock outside the
// years is refused as a clock; a year so late that the certificates of the roots would end after
// the year 9999 is refused by the plan, and the message says so.
func TestClockYearEdges(t *testing.T) {
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtPlan, Now: func() time.Time { return time.Date(1, 6, 1, 0, 0, 0, 0, time.UTC) }})
	if m.Ceremony != "00010601T000000Z-apply" {
		t.Errorf("Ceremony = %s", m.Ceremony)
	}
	for _, c := range []struct {
		year int
		want string
	}{
		{0, "clock"}, {10000, "clock"}, {-1, "clock"},
		{9999, "plan cannot be made"}, {9997, "plan cannot be made"},
	} {
		msg := failsWith(t, func(tb testing.TB) {
			ceremonytest.Bundle(tb, ceremonytest.Options{Step: ceremonytest.AtPlan, Now: func() time.Time { return time.Date(c.year, 6, 1, 0, 0, 0, 0, time.UTC) }})
		})
		if !strings.Contains(msg, c.want) {
			t.Errorf("year %d: message %q, want it to say %q", c.year, msg, c.want)
		}
	}
	if m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtPlan, Now: func() time.Time { return time.Date(9996, 12, 31, 23, 59, 59, 0, time.UTC) }}); m.Ceremony != "99961231T235959Z-apply" {
		t.Errorf("Ceremony = %s", m.Ceremony)
	}
}
