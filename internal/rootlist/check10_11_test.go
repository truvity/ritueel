package rootlist_test

import (
	"testing"
	"time"

	"ritueel.id/ritueel/internal/rootlist"
)

func TestCheck10ChangingTheRootKeysNeedsTheSignaturesOfThePage(t *testing.T) {
	b := newBase(t)
	w := b.w
	type signing struct {
		name    string
		signers []*key
		want    bool // accepted
	}
	cases := []struct {
		name     string
		cand     func(t *testing.T) spec
		signings []signing
	}{
		{"the same pins with another fingerprint", func(*testing.T) spec {
			s := listOf(8, w.a, w.b)
			s.roots[0].fp = w.z.fp()
			return s
		}, []signing{{"A", []*key{w.a}, false}, {"B", []*key{w.b}, false}, {"A and B", []*key{w.a, w.b}, true}}},
		{"the same pins with another label", func(*testing.T) spec {
			s := listOf(8, w.a, w.b)
			s.roots[1].label = "Q"
			return s
		}, []signing{{"A", []*key{w.a}, false}, {"A and B", []*key{w.a, w.b}, true}}},
		{"the same pins with the fingerprint left out", func(*testing.T) spec {
			s := listOf(8, w.a, w.b)
			s.roots[0].noFP = true
			return s
		}, []signing{{"B", []*key{w.b}, false}, {"A and B", []*key{w.a, w.b}, true}}},
		{"A and B swap their labels", func(*testing.T) spec {
			s := listOf(8, w.a, w.b)
			s.roots[0].label, s.roots[1].label = "B", "A"
			return s
		}, []signing{{"A", []*key{w.a}, false}, {"A and B", []*key{w.a, w.b}, true}}},
		{"B is left out and nothing is stored for it", func(*testing.T) spec { return listOf(8, w.a) },
			[]signing{{"A", []*key{w.a}, false}, {"B", []*key{w.b}, false}, {"A and B", []*key{w.a, w.b}, true}}},
		{"A is left out and nothing is stored for it", func(*testing.T) spec { return listOf(8, w.b) },
			[]signing{{"B", []*key{w.b}, false}, {"A", []*key{w.a}, false}, {"A and B", []*key{w.a, w.b}, true}}},
		{"A is left out with its authorisation", func(t *testing.T) spec { return listOf(8, w.b).withRemovals(removalOf(t, w.a)) },
			[]signing{{"B", []*key{w.b}, true}, {"A", []*key{w.a}, false}, {"A and B", []*key{w.a, w.b}, true}}},
		{"B is left out with its authorisation", func(t *testing.T) spec { return listOf(8, w.a).withRemovals(removalOf(t, w.b)) },
			[]signing{{"A", []*key{w.a}, true}, {"B", []*key{w.b}, false}}},
		{"C is added", func(*testing.T) spec { return listOf(8, w.a, w.b, w.c) },
			[]signing{{"A", []*key{w.a}, false}, {"B", []*key{w.b}, false}, {"A and B", []*key{w.a, w.b}, false},
				{"A and C", []*key{w.a, w.c}, false}, {"B and C", []*key{w.b, w.c}, false}, {"A, B and C", []*key{w.a, w.b, w.c}, true}, {"C, A and B", []*key{w.c, w.a, w.b}, true}}},
		{"C is added and B is left out with its authorisation", func(t *testing.T) spec {
			return listOf(8, w.a, w.c).withRemovals(removalOf(t, w.b))
		}, []signing{{"A and C", []*key{w.a, w.c}, true}, {"A", []*key{w.a}, false}, {"B and C", []*key{w.b, w.c}, false}}},
		{"C is added and B is left out with no authorisation", func(*testing.T) spec { return listOf(8, w.a, w.c) },
			[]signing{{"A and C", []*key{w.a, w.c}, false}, {"A, B and C", []*key{w.a, w.b, w.c}, true}}},
		{"A and B are both replaced by C", func(*testing.T) spec { return listOf(8, w.c) },
			[]signing{{"A and C", []*key{w.a, w.c}, false}, {"B and C", []*key{w.b, w.c}, false}, {"A, B and C", []*key{w.a, w.b, w.c}, true}}},
		{"A is replaced by C with A's authorisation", func(t *testing.T) spec {
			return listOf(8, w.b, w.c).withRemovals(removalOf(t, w.a))
		}, []signing{{"B and C", []*key{w.b, w.c}, true}, {"B", []*key{w.b}, false}}},
	}
	for _, c := range cases {
		for _, s := range c.signings {
			t.Run(c.name+", signed by "+s.name, func(t *testing.T) {
				v := b.verify(t, c.cand(t), s.signers...)
				if s.want {
					accepts(t, v)
					return
				}
				refuses(t, v, rootlist.InsufficientSigners, 10)
			})
		}
	}
	t.Run("a held list of three root keys", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b, w.c))
		for _, s := range []struct {
			name    string
			cand    spec
			signers []*key
			want    bool
		}{
			{"the same keys, signed by C alone", listOf(8, w.a, w.b, w.c), []*key{w.c}, true},
			{"C is left out, A and B sign", listOf(8, w.a, w.b), []*key{w.a, w.b}, false},
			{"C is left out, all three sign", listOf(8, w.a, w.b), []*key{w.a, w.b, w.c}, true},
			{"Z is added, A and B and Z sign", listOf(8, w.a, w.b, w.c, w.z), []*key{w.a, w.b, w.z}, false},
			{"Z is added, A and B and C sign", listOf(8, w.a, w.b, w.c, w.z), []*key{w.a, w.b, w.c}, false},
			{"Z is added, all four sign", listOf(8, w.a, w.b, w.c, w.z), []*key{w.a, w.b, w.c, w.z}, true},
		} {
			v := rootlist.Verify(signed(t, s.cand, s.signers...), held, now)
			if s.want {
				accepts(t, v)
			} else {
				refuses(t, v, rootlist.InsufficientSigners, 10)
			}
		}
	})
}

func TestCheck10AgainstInitialPins(t *testing.T) {
	w := newWorld(t)
	for _, c := range []struct {
		name    string
		pins    []*key
		cand    func(*testing.T) spec
		signers []*key
		want    bool
	}{
		{"the same pins", []*key{w.a, w.b}, func(*testing.T) spec { return listOf(1, w.a, w.b) }, []*key{w.a}, true},
		{"the same pins in another order", []*key{w.a, w.b}, func(*testing.T) spec { return listOf(1, w.b, w.a) }, []*key{w.b}, true},
		{"the same pins with other fingerprints and labels", []*key{w.a, w.b}, func(*testing.T) spec {
			s := listOf(1, w.a, w.b)
			s.roots[0].fp, s.roots[1].label = w.z.fp(), "Q"
			return s
		}, []*key{w.a}, true},
		{"the same pins with no fingerprints", []*key{w.a, w.b}, func(*testing.T) spec {
			s := listOf(1, w.a, w.b)
			s.roots[0].noFP, s.roots[1].noFP = true, true
			return s
		}, []*key{w.b}, true},
		{"one pin short: the list adds B", []*key{w.a}, func(*testing.T) spec { return listOf(1, w.a, w.b) }, []*key{w.a}, false},
		{"one pin short: the list adds B and B signs", []*key{w.a}, func(*testing.T) spec { return listOf(1, w.a, w.b) }, []*key{w.a, w.b}, true},
		{"one pin short: B only signs", []*key{w.a}, func(*testing.T) spec { return listOf(1, w.a, w.b) }, []*key{w.b}, false},
		{"one pin too many: the list leaves B out", []*key{w.a, w.b}, func(*testing.T) spec { return listOf(1, w.a) }, []*key{w.a}, false},
		{"one pin too many: the list leaves B out, B signs", []*key{w.a, w.b}, func(*testing.T) spec { return listOf(1, w.a) }, []*key{w.a, w.b}, true},
		{"one pin too many: the list leaves B out with its authorisation", []*key{w.a, w.b}, func(t *testing.T) spec { return listOf(1, w.a).withRemovals(removalOf(t, w.b)) }, []*key{w.a}, true},
		{"the list adds C", []*key{w.a, w.b}, func(*testing.T) spec { return listOf(1, w.a, w.b, w.c) }, []*key{w.a, w.b}, false},
		{"the list adds C and C signs", []*key{w.a, w.b}, func(*testing.T) spec { return listOf(1, w.a, w.b, w.c) }, []*key{w.a, w.b, w.c}, true},
		{"the list adds C and A and C sign", []*key{w.a, w.b}, func(*testing.T) spec { return listOf(1, w.a, w.b, w.c) }, []*key{w.a, w.c}, false},
		{"another key at the place of B", []*key{w.a, w.b}, func(*testing.T) spec { return listOf(1, w.a, w.c) }, []*key{w.a, w.c}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var pins []string
			for _, k := range c.pins {
				pins = append(pins, k.pin)
			}
			v := rootlist.Verify(signed(t, c.cand(t), c.signers...), pinsOf(t, pins...), now)
			if c.want {
				accepts(t, v)
				return
			}
			if v.Accepted {
				t.Fatalf("accepted")
			}
			// A signer that is not trusted at all is unknown-signer at check 2; the rest are check 10.
			if v.Check != 10 && v.Check != 2 {
				t.Fatalf("refused at check %d: %s", v.Check, v.Detail)
			}
			if v.Check == 10 {
				refuses(t, v, rootlist.InsufficientSigners, 10)
			}
		})
	}
	t.Run("the pin of a root key that is not signed or removed, whichever the held entries say", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b))
		pins := pinsOf(t, w.a.pin, w.b.pin)
		cand := signed(t, listOf(8, w.a), w.a)
		refuses(t, rootlist.Verify(cand, held, now), rootlist.InsufficientSigners, 10)
		refuses(t, rootlist.Verify(cand, pins, now), rootlist.InsufficientSigners, 10)
	})
}

func TestCheck11TheListMustNotHaveExpired(t *testing.T) {
	b := newBase(t)
	w := b.w
	expires := mustTime(expiresAt)
	cand := signed(t, b.cand, w.a)
	trust := b.trust(t)
	for _, c := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"a year before", expires.AddDate(-1, 0, 0), true},
		{"a day before", expires.Add(-24 * time.Hour), true},
		{"a second before", expires.Add(-time.Second), true},
		{"a nanosecond before", expires.Add(-time.Nanosecond), true},
		{"at the moment", expires, false},
		{"a nanosecond after", expires.Add(time.Nanosecond), false},
		{"a second after", expires.Add(time.Second), false},
		{"a day after", expires.Add(24 * time.Hour), false},
		{"ten years after", expires.AddDate(10, 0, 0), false},
		{"the moment, in a zone that is ahead", expires.In(time.FixedZone("ahead", 5*3600)), false},
		{"the moment, in a zone that is behind", expires.In(time.FixedZone("behind", -7*3600)), false},
		{"a second before, in a zone that is ahead", expires.Add(-time.Second).In(time.FixedZone("ahead", 5*3600)), true},
		{"a second before, in a zone that is behind", expires.Add(-time.Second).In(time.FixedZone("behind", -7*3600)), true},
		{"a clock with the same wall time in another zone, which is an hour later", time.Date(2027, 12, 15, 12, 0, 0, 0, time.FixedZone("ahead", 3600)), true},
		{"a clock with the same wall time in another zone, which is an hour earlier", time.Date(2027, 12, 15, 12, 0, 0, 0, time.FixedZone("behind", -3600)), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := rootlist.Verify(cand, trust, c.at)
			if c.want {
				accepts(t, v)
				return
			}
			refuses(t, v, rootlist.Expired, 11)
		})
	}
	t.Run("the expiry that counts is the candidate's, not the held list's", func(t *testing.T) {
		// The list the host holds is not judged by the date rules of check 5 (they are for a candidate;
		// the host accepted its list under the clock of its day), so a held list with an expiry that
		// has passed, and that is not 13 months after its signing, is still a trust.
		held := listOf(7, w.a, w.b)
		held.expiresAt = `"2026-11-20T12:00:00Z"` // before the clock
		accepts(t, rootlist.Verify(cand, heldOf(t, held), now))
		refuses(t, rootlist.Verify(signed(t, b.cand.at(longAgo), w.a), trust, now), rootlist.Expired, 11)
	})
	t.Run("against initial pins", func(t *testing.T) {
		pins := pinsOf(t, w.a.pin, w.b.pin)
		accepts(t, rootlist.Verify(cand, pins, expires.Add(-time.Second)))
		refuses(t, rootlist.Verify(cand, pins, expires), rootlist.Expired, 11)
	})
}

func TestCheckHeldWarnsOfAnExpiredList(t *testing.T) {
	w := newWorld(t)
	expires := mustTime(expiresAt)
	h, err := rootlist.ParseHeld(listOf(7, w.a, w.b).json())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"long before", expires.AddDate(-1, 0, 0), false},
		{"a second before", expires.Add(-time.Second), false},
		{"a nanosecond before", expires.Add(-time.Nanosecond), false},
		{"at the moment", expires, true},
		{"a second after", expires.Add(time.Second), true},
		{"a year after", expires.AddDate(1, 0, 0), true},
		{"the moment in another zone", expires.In(time.FixedZone("ahead", 5*3600)), true},
		{"a second before in another zone", expires.Add(-time.Second).In(time.FixedZone("behind", -3*3600)), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := rootlist.CheckHeld(h, c.at)
			if c.want && (len(got) != 1 || got[0] != "held-expired") {
				t.Errorf("got %v, want [held-expired]", got)
			}
			if !c.want && len(got) != 0 {
				t.Errorf("got %v, want no warning", got)
			}
		})
	}
	t.Run("a host with nothing held has nothing to warn of", func(t *testing.T) {
		if got := rootlist.CheckHeld(nil, expires.AddDate(5, 0, 0)); len(got) != 0 {
			t.Errorf("got %v", got)
		}
		if got := rootlist.CheckHeld(&rootlist.Held{}, expires.AddDate(5, 0, 0)); len(got) != 0 {
			t.Errorf("got %v", got)
		}
	})
	t.Run("an expired held list is kept as a trust: it still verifies a candidate", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b))
		// A candidate signed after the held list expired, with its 13 months still to run.
		cand := listOf(8, w.a, w.b).at("2028-06-15T12:00:00Z")
		accepts(t, rootlist.Verify(signed(t, cand, w.a), held, expires.AddDate(1, 0, 0)))
		if got := rootlist.CheckHeld(h, expires.AddDate(1, 0, 0)); len(got) != 1 {
			t.Errorf("the same moment does not warn: %v", got)
		}
	})
}
