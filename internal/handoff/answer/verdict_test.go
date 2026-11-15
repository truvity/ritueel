package answer_test

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/answer"
)

// Only Verdict.Accepted says that the requester may install the answer.
func TestAZeroVerdictAndAVerdictMadeByHandAreNeverAccepted(t *testing.T) {
	var zero answer.Verdict
	if zero.Accepted() || zero.AnswerRefused() || zero.RequestRefused() || zero.Floor() || len(zero.Checks) != 0 || zero.Info != nil {
		t.Fatalf("the zero Verdict says something: %+v", zero)
	}
	var passed []answer.CheckResult
	for n := 1; n <= 9; n++ {
		passed = append(passed, answer.CheckResult{N: n, Status: handoff.StatusPassed})
	}
	for name, v := range map[string]answer.Verdict{
		"nine passed checks and Info":         {Checks: passed, Info: &answer.Info{Type: handoff.TypeX509}},
		"eight passed checks and Info":        {Checks: passed[:8], Info: &answer.Info{Type: handoff.TypeOpenPGP}},
		"passed checks, Info and no code":     {Checks: passed, Info: &answer.Info{}},
		"no checks and Info":                  {Info: &answer.Info{Type: handoff.TypeX509}},
		"nothing but Info":                    {Info: &answer.Info{Type: handoff.TypeX509, Issuer: "x"}},
		"a code of nothing":                   {Checks: passed},
		"certifier reasons and passed checks": {Checks: passed, Info: &answer.Info{}, CertifierReasons: []handoff.Code{handoff.CodePolicy}},
	} {
		if v.Accepted() {
			t.Errorf("%s: a verdict made by hand is accepted", name)
		}
	}
}

// An accepted verdict that a caller changes is no longer accepted.
func TestAnAcceptedVerdictThatIsChangedByHandIsNotAcceptedAny(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	for _, kind := range []string{"x509", "openpgp"} {
		var base answer.Verdict
		var err error
		if kind == "x509" {
			base, err = k.newX509(nil).check(chk)
		} else {
			base, err = k.newPGP("sign").check(chk)
		}
		if err != nil || !base.Accepted() {
			t.Fatalf("%s: control %v", kind, err)
		}
		clone := func() answer.Verdict {
			v := base
			v.Checks = slices.Clone(base.Checks)
			in := *base.Info
			v.Info = &in
			return v
		}
		if v := clone(); !v.Accepted() {
			t.Fatalf("%s: a copy of an accepted verdict is not accepted", kind)
		}
		for name, change := range map[string]func(v *answer.Verdict){
			"a code":                      func(v *answer.Verdict) { v.Code = answer.CodeIssuer },
			"a reason of the certifier":   func(v *answer.Verdict) { v.CertifierReasons = []handoff.Code{handoff.CodePolicy} },
			"no Info":                     func(v *answer.Verdict) { v.Info = nil },
			"a check failed":              func(v *answer.Verdict) { v.Checks[3].Status = handoff.StatusFailed },
			"a check not run":             func(v *answer.Verdict) { v.Checks[len(v.Checks)-1].Status = handoff.StatusNotRun },
			"the first check not run":     func(v *answer.Verdict) { v.Checks[0].Status = handoff.StatusNotRun },
			"a check with another status": func(v *answer.Verdict) { v.Checks[1].Status = "passed-ish" },
			"one check less":              func(v *answer.Verdict) { v.Checks = v.Checks[:len(v.Checks)-1] },
			"one check more":              func(v *answer.Verdict) { v.Checks = append(v.Checks, answer.CheckResult{Status: handoff.StatusPassed}) },
			"no checks":                   func(v *answer.Verdict) { v.Checks = nil },
			"the type of Info": func(v *answer.Verdict) {
				if v.Info.Type == handoff.TypeX509 {
					v.Info.Type = handoff.TypeOpenPGP
				} else {
					v.Info.Type = handoff.TypeX509
				}
			},
		} {
			v := clone()
			change(&v)
			if v.Accepted() {
				t.Errorf("%s: an accepted verdict with %s is accepted", kind, name)
			}
		}
	}
}

// A verdict that comes with an error is neither accepted nor refused, and a refusal has no Info.
func TestAVerdictThatComesWithAnErrorIsNeverAccepted(t *testing.T) {
	k := newKit(t)
	t.Run("no key for the primary", func(t *testing.T) {
		chk := k.checker(func(c *answer.Config) { c.Primaries = nil })
		v, err := k.newPGP("sign").check(chk)
		if !errors.Is(err, answer.ErrNoPrimaryKey) || v.Accepted() || v.AnswerRefused() || v.RequestRefused() || v.Info != nil {
			t.Fatalf("%v accepted %v", err, v.Accepted())
		}
	})
	t.Run("a clock that is outside the years", func(t *testing.T) {
		chk := k.checker(func(c *answer.Config) { c.Now = func() time.Time { return time.Time{} } })
		v, err := k.newX509(nil).check(chk)
		if !errors.Is(err, answer.ErrInternal) || v.Accepted() || v.Info != nil || v.Code != "" {
			t.Fatalf("%v accepted %v", err, v.Accepted())
		}
	})
	t.Run("an SSH request", func(t *testing.T) {
		c := vectorCase(t, "ssh-piv-valid")
		m := readVectorManifest(t)
		v, err := mustChecker(t, vectorConfig(t, m)).Check(vectorAsked(t, c), vectorAnswer(t, c))
		if !errors.Is(err, answer.ErrTypeNotBuilt) || v.Accepted() || v.AnswerRefused() || len(v.Checks) != 0 {
			t.Fatalf("%v accepted %v", err, v.Accepted())
		}
	})
	t.Run("the SSH answer is not read first: any answer to an SSH request is not built", func(t *testing.T) {
		c := vectorCase(t, "ssh-piv-valid")
		m := readVectorManifest(t)
		for _, ans := range []*answer.Answer{
			{Stem: "x"}, {Stem: "x", Files: map[string][]byte{answer.FileResult: []byte("not json")}}, vectorAnswer(t, c),
		} {
			_, err := mustChecker(t, vectorConfig(t, m)).Check(vectorAsked(t, c), ans)
			if !errors.Is(err, answer.ErrTypeNotBuilt) {
				t.Errorf("error %v", err)
			}
		}
	})
}

// Every verdict is its own: the lists of two verdicts share nothing, and Info is a copy.
func TestTheVerdictsOfTwoCallsShareNothing(t *testing.T) {
	k := newKit(t)
	k.expires = "2026-11-01T00:00:00Z"
	k.writeList([]memRoot{k.a, k.b})
	chk := k.checker(nil)
	x := k.newX509(nil)
	v1, err := x.check(chk)
	if err != nil {
		t.Fatal(err)
	}
	v1.Checks[0].Status = handoff.StatusFailed
	v1.Info.Issuer = "changed"
	v1.Warnings[0] = "changed"
	v2, err := x.check(chk)
	want(t, v2, err, "", "ppppppppp")
	if v2.Info.Issuer == "changed" || v2.Warnings[0] != "held-expired" {
		t.Errorf("a change of one verdict reached another: %+v %v", *v2.Info, v2.Warnings)
	}
}

// The clock is read once for each call, never by New, cut to whole seconds, and a clock that is out of range or
// that panics is an internal error and never an acceptance.
func TestTheClockIsReadOnceForEachCall(t *testing.T) {
	k := newKit(t)
	var calls atomic.Int64
	chk := k.checker(func(c *answer.Config) { c.Now = func() time.Time { calls.Add(1); return testNow } })
	if calls.Load() != 0 {
		t.Fatalf("New read the clock %d times", calls.Load())
	}
	for _, mk := range []func() (answer.Verdict, error){
		func() (answer.Verdict, error) { return k.newX509(nil).check(chk) },
		func() (answer.Verdict, error) { return k.newPGP("sign").check(chk) },
		func() (answer.Verdict, error) {
			return k.newX509(nil).with(func(m map[string]any) { m["trust_sequence"] = 8 }).check(chk)
		},
	} {
		before := calls.Load()
		if _, err := mk(); err != nil {
			t.Fatal(err)
		}
		if got := calls.Load() - before; got != 1 {
			t.Errorf("the clock was read %d times by one call", got)
		}
	}
	// A call that stops at a stem that is not a stem, or at a zero Asked, reads no clock.
	before := calls.Load()
	_, _ = chk.Check(nil, nil)
	if calls.Load() != before {
		t.Error("a refused call read the clock")
	}
	// The floor reads it once too.
	ca := newForeignCA(t, caSpec{})
	var fcalls atomic.Int64
	fchk := mustChecker(t, floorConfig(t, func(c *answer.Config) { c.Now = func() time.Time { fcalls.Add(1); return testNow } }, ca))
	if _, err := newFloorCase(t, k, ca, certSpec{}).check(fchk); err != nil || fcalls.Load() != 1 {
		t.Errorf("%v: the floor read the clock %d times", err, fcalls.Load())
	}
}

func TestAClockOutsideTheYearsOrThatPanicsIsAnInternalErrorAndNeverAnAcceptance(t *testing.T) {
	k := newKit(t)
	for name, now := range map[string]func() time.Time{
		"the zero time":                     func() time.Time { return time.Time{} },
		"the year 1969":                     func() time.Time { return time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC) },
		"the year 1900":                     func() time.Time { return time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC) },
		"the year 2107":                     func() time.Time { return time.Date(2107, 1, 1, 0, 0, 0, 0, time.UTC) },
		"the year 3000":                     func() time.Time { return time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"a clock that panics":               func() time.Time { panic("the clock is broken") },
		"a clock that panics with an error": func() time.Time { panic(errors.New("broken")) },
	} {
		chk := k.checker(func(c *answer.Config) { c.Now = now })
		for kind, run := range map[string]func() (answer.Verdict, error){
			"x509":    func() (answer.Verdict, error) { return k.newX509(nil).check(chk) },
			"openpgp": func() (answer.Verdict, error) { return k.newPGP("sign").check(chk) },
		} {
			v, err := run()
			if !errors.Is(err, answer.ErrInternal) {
				t.Errorf("%s, %s: error %v", name, kind, err)
			}
			if v.Accepted() || v.Info != nil || v.AnswerRefused() {
				t.Errorf("%s, %s: accepted %v", name, kind, v.Accepted())
			}
		}
		ca := newForeignCA(t, caSpec{})
		fchk := mustChecker(t, floorConfig(t, func(c *answer.Config) { c.Now = now }, ca))
		if v, err := newFloorCase(t, k, ca, certSpec{}).check(fchk); !errors.Is(err, answer.ErrInternal) || v.Accepted() {
			t.Errorf("%s, floor: %v", name, err)
		}
	}
	t.Run("the last second of 2105 and the first second of 1970 are read", func(t *testing.T) {
		for _, at := range []time.Time{time.Unix(1, 0).UTC(), time.Date(2106, 2, 7, 6, 28, 15, 0, time.UTC)} {
			chk := k.checker(func(c *answer.Config) { c.Now = func() time.Time { return at } })
			v, err := k.newX509(nil).check(chk)
			if err != nil {
				t.Fatalf("%v: %v", at, err)
			}
			if v.Accepted() || v.Code != answer.CodeValidity && v.Code != answer.CodeIssuer {
				t.Errorf("%v: code %q accepted %v", at, v.Code, v.Accepted())
			}
		}
	})
}

// The two ends of what an OpenPGP time field holds: the second after the last one is refused, and the clock
// that reads the last second is read.
func TestTheClockIsHeldToTheSecondAtBothEnds(t *testing.T) {
	k := newKit(t)
	last := time.Unix(1<<32-1, 0).UTC() // 2106-02-07T06:28:15Z
	for _, c := range []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"the last second that a time field holds", last, true},
		{"the second after it", last.Add(time.Second), false},
		{"half a second after the last second", last.Add(500 * time.Millisecond), true},
		{"the first second after 1970", time.Unix(1, 0).UTC(), true},
		{"a second before the first second after 1970", time.Unix(0, 0).UTC(), false},
		{"a second before 1970", time.Unix(-1, 0).UTC(), false},
	} {
		chk := k.checker(func(cfg *answer.Config) { cfg.Now = func() time.Time { return c.at } })
		v, err := k.newX509(nil).check(chk)
		if c.ok != (err == nil) {
			t.Errorf("%s: error %v", c.name, err)
		}
		if err != nil && (!errors.Is(err, answer.ErrInternal) || v.Accepted()) {
			t.Errorf("%s: error %v accepted %v", c.name, err, v.Accepted())
		}
	}
}

// The files of the answer are copied at the top of the call: a clock that changes them while it is read changes
// nothing of the verdict.
func TestTheFilesOfTheAnswerAreCopiedBeforeTheClockIsRead(t *testing.T) {
	k := newKit(t)
	for _, kind := range []string{"x509", "openpgp"} {
		var ans *answer.Answer
		var asked *answer.Asked
		var suffix string
		switch kind {
		case "x509":
			x := k.newX509(nil)
			ans, asked, suffix = x.answer(), x.csr.asked(t), answer.FileCert
		default:
			p := k.newPGP("sign")
			ans, asked, suffix = p.answer(), p.req.asked(), answer.FileBound
		}
		chk := k.checker(func(cfg *answer.Config) {
			cfg.Now = func() time.Time {
				for _, f := range ans.Files {
					for i := range f {
						f[i] ^= 0xff // every byte of every file
					}
				}
				return testNow
			}
		})
		v, err := chk.Check(asked, ans)
		if err != nil || !v.Accepted() {
			t.Errorf("%s: a change of the files while the clock is read changes the verdict: %v %q", kind, err, v.Code)
		}
		_ = suffix
	}
}

// A clock that gives a fraction of a second is the same as the whole second below it.
func TestTheClockIsCutToWholeSeconds(t *testing.T) {
	k := newKit(t)
	at := func(d time.Duration) *answer.Checker {
		return k.checker(func(c *answer.Config) { c.Now = func() time.Time { return testNow.Add(d) } })
	}
	// A certificate that ends at the clock's second is valid for the whole of that second.
	ends := k.newX509(nil)
	ends.spec.notBefore = time.Date(2025, 10, 15, 12, 0, 0, 0, time.UTC) // ends 2026-11-15T12:00:00Z
	v, err := ends.check(at(999 * time.Millisecond))
	want(t, v, err, "", "ppppppppp")
	v, err = ends.check(at(time.Second))
	want(t, v, err, answer.CodeValidity, st7)
	// A certificate that starts at the clock's second is not valid before it.
	starts := k.newX509(nil)
	v, err = starts.check(at(-time.Millisecond))
	want(t, v, err, answer.CodeValidity, st7)
	v, err = starts.check(at(0))
	want(t, v, err, "", "ppppppppp")
	// The same in another time zone and with a monotonic reading.
	loc := time.FixedZone("example", 5*3600+1800)
	chk := k.checker(func(c *answer.Config) { c.Now = func() time.Time { return testNow.In(loc) } })
	v, err = starts.check(chk)
	want(t, v, err, "", "ppppppppp")
	// The binding of an OpenPGP answer ends at the instant, whole seconds.
	p := k.newPGP("sign")
	v, err = p.check(k.checker(func(c *answer.Config) { c.Now = func() time.Time { return pgpEnds.Add(-time.Millisecond) } }))
	want(t, v, err, "", pOK)
}

// One Checker serves many calls at the same time, with the same verdicts as when alone.
func TestOneCheckerServesManyCallsAtTheSameTimeWithTheVerdictsOfOneCall(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	type job struct {
		run  func() (answer.Verdict, error)
		code answer.Code
		st   string
	}
	good := k.newX509(nil)
	bad := k.newX509(nil)
	bad.with(func(m map[string]any) { m["trust_sequence"] = 8 })
	pgood, pbad := k.newPGP("sign"), k.newPGP("sign")
	pbad.with(func(m map[string]any) { m["trust_sequence"] = 8 })
	refused := k.newX509(nil)
	refused.with(func(m map[string]any) {
		for _, key := range []string{"artifacts", "valid_from", "valid_until", "issuer"} {
			delete(m, key)
		}
		m["outcome"], m["reasons"] = "refused", []string{"policy"}
	})
	// Everything is made before the goroutines start; they share the Checker, the Asked values and the answers, and
	// only read them.
	judge := func(asked *answer.Asked, ans *answer.Answer) func() (answer.Verdict, error) {
		return func() (answer.Verdict, error) { return chk.Check(asked, ans) }
	}
	refusedAnswer := &answer.Answer{Stem: refused.stem, Files: map[string][]byte{answer.FileResult: refused.files()[answer.FileResult]}}
	jobs := []job{
		{judge(good.csr.asked(t), good.answer()), "", "ppppppppp"},
		{judge(bad.csr.asked(t), bad.answer()), answer.CodeIssuer, st4},
		{judge(pgood.req.asked(), pgood.answer()), "", pOK},
		{judge(pbad.req.asked(), pbad.answer()), answer.CodeIssuer, pst5},
		{judge(refused.csr.asked(t), refusedAnswer), "", "pppnnnnnn"},
	}
	// The answers and the Asked values are shared by the goroutines, and only read.
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 40; g++ {
		j := jobs[g%len(jobs)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			v, err := j.run()
			if err != nil || v.Code != j.code || statuses(v) != j.st {
				errs <- "a verdict differs from the verdict of one call"
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// A verdict names its checks in order, one number for each, and each in words of its own.
func TestTheChecksOfAVerdictAreNumberedInOrderAndNamed(t *testing.T) {
	k := newKit(t)
	ca := newForeignCA(t, caSpec{})
	x, err := k.newX509(nil).check(k.checker(nil))
	if err != nil {
		t.Fatal(err)
	}
	p, err := k.newPGP("sign").check(k.checker(nil))
	if err != nil {
		t.Fatal(err)
	}
	f, err := newFloorCase(t, k, ca, certSpec{}).check(mustChecker(t, floorConfig(t, nil, ca)))
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]answer.Verdict{"x509": x, "openpgp": p, "floor": f} {
		want := 9
		if name == "openpgp" {
			want = 8
		}
		if len(v.Checks) != want {
			t.Errorf("%s: %d checks", name, len(v.Checks))
		}
		seen := map[string]bool{}
		for i, c := range v.Checks {
			if c.N != i+1 || c.Name == "" || seen[c.Name] {
				t.Errorf("%s: check %d reads %+v", name, i+1, c)
			}
			seen[c.Name] = true
		}
	}
	// The first three checks are the same in the three tables: the version, the files, the request.
	for i := 0; i < 3; i++ {
		if x.Checks[i].Name != p.Checks[i].Name || x.Checks[i].Name != f.Checks[i].Name {
			t.Errorf("check %d is named %q, %q and %q", i+1, x.Checks[i].Name, p.Checks[i].Name, f.Checks[i].Name)
		}
	}
	if x.Checks[3].Name == f.Checks[3].Name {
		t.Error("the check of the anchor is named the same on the floor and on the full contract")
	}
}
