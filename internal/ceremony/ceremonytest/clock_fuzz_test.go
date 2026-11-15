package ceremonytest_test

import (
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony/ceremonytest"
)

// FuzzBundleClock gives the ceremony any clock: a second, a fraction of a second and a zone from
// the bytes. A time in the years 1 to 9999 gives a bundle whose ceremony folder is named by that
// second in UTC; any other time fails the test with the word clock, and never a panic and never a
// folder with a wrong name. No program is started.
func FuzzBundleClock(f *testing.F) {
	f.Add(int64(1795168800), int64(0), int32(0))
	f.Add(int64(-62135596800), int64(0), int32(0)) // year 1
	f.Add(int64(253402300799), int64(999999999), int32(0))
	f.Add(int64(253402300800), int64(0), int32(0)) // year 10000
	f.Add(int64(-62135596801), int64(0), int32(0)) // year 0
	f.Add(int64(1700000000), int64(123456789), int32(5*3600+1800))
	f.Add(int64(1700000000), int64(-5), int32(-12*3600))
	f.Add(int64(-1<<62), int64(1<<40), int32(1<<30))
	f.Fuzz(func(t *testing.T, sec, nsec int64, offset int32) {
		zone := time.FixedZone("z", int(offset%(26*3600)))
		at := time.Unix(sec, nsec).In(zone)
		dir := t.TempDir() + "/ca"
		ft := &fakeTB{TB: t}
		done := make(chan struct{})
		var made *ceremonytest.Made
		var panicked any
		go func() {
			defer close(done)
			defer func() { panicked = recover() }()
			made = ceremonytest.Bundle(ft, ceremonytest.Options{Step: ceremonytest.AtPlan, Dir: dir, Now: func() time.Time { return at }})
		}()
		<-done
		if panicked != nil {
			t.Fatalf("panic: %v", panicked)
		}
		want := at.UTC().Truncate(time.Second)
		valid := want.Year() >= 1 && want.Year() <= 9999
		switch {
		case !valid && !strings.Contains(ft.msg, "clock"):
			t.Fatalf("the time %v was not refused with the word clock: %q", want, ft.msg)
		case valid && ft.msg != "":
			// A time that is valid may still be refused by a later step of the run (a plan whose
			// certificates would end after the year 9999); the message then says which.
			if !strings.Contains(ft.msg, "ceremonytest:") {
				t.Fatalf("an unknown failure for %v: %q", want, ft.msg)
			}
		case valid:
			if made == nil || made.Ceremony != want.Format("20060102T150405Z")+"-apply" {
				t.Fatalf("Ceremony = %v for %v", made, want)
			}
		}
	})
}
