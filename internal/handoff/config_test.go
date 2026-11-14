package handoff_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// A Checker is made by New from a Config, and a Checker that is not made by New refuses every request. No
// rule is switched off by a field that was left empty: New refuses the configuration instead.

func TestNewMakesACheckerFromAWholeConfiguration(t *testing.T) {
	c, err := handoff.New(defaultConfig(t))
	if err != nil || c == nil {
		t.Fatalf("checker %v, error %v", c, err)
	}
	// Evidence is the one part that may be left out: a store with no verifier stops at check 7.
	cfg := defaultConfig(t)
	cfg.Evidence = nil
	if _, err := handoff.New(cfg); err != nil {
		t.Errorf("a configuration with no verifier: %v", err)
	}
	cfg.Evidence = map[handoff.Store]handoff.EvidenceVerifier{}
	if _, err := handoff.New(cfg); err != nil {
		t.Errorf("a configuration with an empty map of verifiers: %v", err)
	}
}

// The delegation is the one part that may be left out: its absence is a statement (the rules that need it are
// not run and are named), and nodelegation_test.go holds the tests of that.
func TestNewRefusesAConfigurationWithAPartThatIsLeftEmpty(t *testing.T) {
	for name, change := range map[string]func(c *handoff.Config){
		"the whole configuration":     func(c *handoff.Config) { *c = handoff.Config{} },
		"the policy":                  func(c *handoff.Config) { c.Policy = handoff.Policy{} },
		"the stores of the policy":    func(c *handoff.Config) { c.Policy.Stores = nil },
		"the minimum firmware":        func(c *handoff.Config) { c.Policy.MinFirmware = "" },
		"the PIN policies":            func(c *handoff.Config) { c.Policy.PINPolicies = nil },
		"the delegation's type":       func(c *handoff.Config) { c.Delegation.Type = "" },
		"the roots":                   func(c *handoff.Config) { c.Roots = nil },
		"the roots, as an empty list": func(c *handoff.Config) { c.Roots = []handoff.RootRef{} },
		"the clock":                   func(c *handoff.Config) { c.Now = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := defaultConfig(t)
			change(&cfg)
			wantConfigError(t, cfg)
		})
	}
}

// A verifier that is nil in any way that a Go interface can hold nil.
type (
	nilMapVerifier   map[string]int
	nilFuncVerifier  func()
	nilSliceVerifier []int
	nilChanVerifier  chan int
	nilPtrVerifier   struct{ _ int }
)

func (nilMapVerifier) Verify(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
	return nil, errors.New("called")
}

func (nilFuncVerifier) Verify(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
	return nil, errors.New("called")
}

func (nilSliceVerifier) Verify(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
	return nil, errors.New("called")
}

func (nilChanVerifier) Verify(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
	return nil, errors.New("called")
}

func (*nilPtrVerifier) Verify(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
	return nil, errors.New("called")
}

func TestNewRefusesAVerifierThatIsNilInAnyForm(t *testing.T) {
	var nilStub *stub
	var nilPtr *nilPtrVerifier
	for name, v := range map[string]handoff.EvidenceVerifier{
		"nothing":             nil,
		"a typed nil pointer": nilStub,
		"a typed nil pointer to a struct that has methods": nilPtr,
		"a nil map":     nilMapVerifier(nil),
		"a nil func":    nilFuncVerifier(nil),
		"a nil slice":   nilSliceVerifier(nil),
		"a nil channel": nilChanVerifier(nil),
	} {
		t.Run(name, func(t *testing.T) {
			for _, store := range []handoff.Store{handoff.StorePIV, handoff.StoreKMS, handoff.StoreSoftware} {
				cfg := defaultConfig(t)
				cfg.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StoreOpenPGPCard: &stub{fn: nil}, store: v}
				wantConfigError(t, cfg)
			}
		})
	}
	// A verifier that is a value and is not nil is a verifier, empty or not.
	cfg := defaultConfig(t)
	cfg.Evidence = map[handoff.Store]handoff.EvidenceVerifier{
		handoff.StorePIV: nilMapVerifier{}, handoff.StoreKMS: &nilPtrVerifier{}, handoff.StoreOpenPGPCard: nilSliceVerifier{},
	}
	if _, err := handoff.New(cfg); err != nil {
		t.Errorf("verifiers that are not nil: %v", err)
	}
}

func TestNewRefusesAVerifierForAStoreThatIsNotOneOfTheFour(t *testing.T) {
	for _, store := range []handoff.Store{"", "tpm", "PIV", "piv ", "software\x00"} {
		cfg := defaultConfig(t)
		cfg.Evidence = map[handoff.Store]handoff.EvidenceVerifier{store: &stub{}}
		wantConfigError(t, cfg)
	}
}

func TestACheckerThatNewDidNotMakeRefusesEveryRequest(t *testing.T) {
	soft := newFixture(t, handoff.StoreSoftware, csrSpec{}).request()
	piv := newFixture(t, handoff.StorePIV, csrSpec{}).request()
	copyOfMade := *newChecker(t) // a copy of a checker that New made is still one that New made
	for name, c := range map[string]*handoff.Checker{
		"the zero value":   {},
		"new(Checker)":     new(handoff.Checker),
		"a nil checker":    nil,
		"a copy of a zero": func() *handoff.Checker { var z handoff.Checker; c := z; return &c }(),
	} {
		for rname, r := range map[string]*handoff.Request{
			"a good software request": soft, "a good piv request": piv, "an openpgp request": pgpRequest(nil), "an ssh request": sshRequest(nil),
			"a request with no files": {Stem: testStem},
		} {
			t.Run(name+"/"+rname, func(t *testing.T) {
				v, err := c.Check(t.Context(), r)
				wantUndecided(t, v, err, handoff.ErrConfig, "nnnnnnnnn")
				if len(v.Checks) != 9 || v.Code != "" || v.Detail != "" {
					t.Errorf("verdict %+v", v)
				}
				for i, c := range v.Checks {
					if c.N != i+1 || c.Name == "" {
						t.Errorf("check %d reads %+v", i+1, c)
					}
				}
			})
		}
	}
	// And the copy of a checker that New made works as the original does.
	v, err := copyOfMade.Check(t.Context(), soft)
	wantAccepted(t, v, err)
}

func TestAConfigurationFaultIsItsOwnKindOfError(t *testing.T) {
	_, err := handoff.New(handoff.Config{})
	if errors.Is(err, handoff.ErrInternal) || errors.Is(err, handoff.ErrNoVerifier) || errors.Is(err, handoff.ErrTypeNotBuilt) {
		t.Errorf("a fault of the configuration is also another kind of error: %v", err)
	}
	if err == nil || !plain(err.Error()) {
		t.Errorf("error %v", err)
	}
}

// The Checker keeps its own copy of the configuration.

func TestWhatTheCallerDoesToTheConfigurationAfterNewHasNoEffect(t *testing.T) {
	root := newRoot(t, "Example Test Root")
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	sv := returning(f.goodEvidence(handoff.StorePIV))
	other := failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "swapped"})
	cfg := defaultConfig(t)
	cfg.Roots = []handoff.RootRef{root.ref()}
	cfg.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: sv}
	chk := mustNew(t, cfg)

	good := f.request()
	dnsReq := newFixture(t, handoff.StoreSoftware, csrSpec{exts: goodExtensions(dnsName("example.org"))}).request()
	rootKey := newFixture(t, handoff.StoreSoftware, csrSpec{key: root.key}).request()
	badName := newFixture(t, handoff.StoreSoftware, csrSpec{exts: goodExtensions(uriName("example.net"))}).request()
	want := func(stage string) {
		t.Helper()
		v, err := chk.Check(t.Context(), good)
		if err != nil || !v.Accepted() {
			t.Fatalf("%s: a request that was accepted is not: code %q (%s), error %v", stage, v.Code, v.Detail, err)
		}
		v, err = chk.Check(t.Context(), rootKey)
		wantRefusal(t, v, err, handoff.CodePolicy, 9)
		v, err = chk.Check(t.Context(), badName)
		wantRefusal(t, v, err, handoff.CodePolicy, 9)
		v, err = chk.Check(t.Context(), dnsReq)
		if err != nil || !v.Accepted() {
			t.Fatalf("%s: a request for a DNS name of the delegation: code %q (%s), error %v", stage, v.Code, v.Detail, err)
		}
	}
	want("before the change")

	// Every part of the configuration that the caller still holds is changed.
	cfg.Policy.Stores[0] = handoff.StoreSoftware
	cfg.Policy.Stores = nil
	cfg.Policy.MinFirmware = "9.9.9"
	cfg.Policy.PINPolicies[0] = handoff.PINNever
	cfg.Policy.PINPolicies = nil
	cfg.Policy.ValidityMonths = -1
	cfg.Delegation.Type = handoff.TypeSSH
	cfg.Delegation.PermittedURIHosts[0] = "example.net"
	cfg.Delegation.PermittedDNSNames[0] = "example.net"
	cfg.Delegation.PermittedURIHosts = nil
	cfg.Delegation.KMSReadRoles = map[string]string{"1": "x"}
	cfg.Roots[0].Subject[0] ^= 0xff
	cfg.Roots[0] = handoff.RootRef{}
	cfg.Roots = nil
	cfg.Evidence[handoff.StorePIV] = other
	delete(cfg.Evidence, handoff.StorePIV)
	cfg.Evidence[handoff.StoreKMS] = other
	cfg.Now = func() time.Time { return time.Time{} }
	want("after the change")
	if sv.calls.Load() != 2 || other.calls.Load() != 0 {
		t.Errorf("the verifier was called %d times, the swapped one %d times", sv.calls.Load(), other.calls.Load())
	}
}

func TestACheckerServesCallsWhileTheCallerChangesTheConfiguration(t *testing.T) {
	// The race detector sees a read of the configuration that the caller can write.
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	cfg := defaultConfig(t)
	cfg.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: returning(f.goodEvidence(handoff.StorePIV))}
	chk := mustNew(t, cfg)
	req := f.request()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				v, err := chk.Check(t.Context(), req)
				if err != nil || !v.Accepted() {
					errs <- fmt.Sprintf("code %q, error %v", v.Code, err)
					return
				}
			}
		}()
	}
	for i := range 200 {
		cfg.Policy.Stores[i%len(cfg.Policy.Stores)] = handoff.Store("x")
		cfg.Policy.PINPolicies[0] = handoff.PINNever
		cfg.Delegation.PermittedURIHosts[0] = "example.net"
		cfg.Delegation.Type = handoff.TypeSSH
		cfg.Roots[0].Subject[0] ^= 1
		cfg.Evidence[handoff.StorePIV] = nil
	}
	close(stop)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// A verifier that panics.

type panicWith struct{ value any }

func (p panicWith) Verify(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
	panic(p.value)
}

func TestAVerifierThatPanicsGivesAnErrorAndNeverAnAcceptance(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	var nilMap map[string]int
	for name, value := range map[string]any{
		"a string":                   "the verifier broke",
		"an error":                   errors.New("the verifier broke"),
		"nothing":                    nil,
		"a refusal of the evidence":  &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "a panic that looks like a refusal"},
		"the error of an internal":   handoff.ErrInternal,
		"the error of no verifier":   handoff.ErrNoVerifier,
		"a text that is not plain":   "x \x1b[2J\n\u202e",
		"a number":                   42,
		"a nil map as the value":     nilMap,
		"a nil pointer as the value": (*int)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			v, err := checkerWith(t, handoff.StorePIV, panicWith{value}).Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
			if !plain(err.Error()) {
				t.Errorf("the error is not plain text: %q", err.Error())
			}
			if !strings.Contains(err.Error(), "panicked") {
				t.Errorf("the error does not say that the verifier panicked: %q", err.Error())
			}
		})
	}
}

func TestAVerifierThatTouchesANilMapOrAPointerGivesAnError(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	for name, fn := range map[string]func(){
		"a write to a nil map":      func() { m := nilMapOf(); m["x"] = 1 },
		"a nil pointer":             func() { var p *handoff.Evidence; _ = p.Firmware },
		"an index out of range":     func() { var a []int; _ = a[3] },
		"a failed type assertion":   func() { var x any = 1; _ = x.(string) },
		"a close of a closed chan":  func() { c := make(chan int); close(c); close(c) },
		"an explicit runtime error": func() { panic(fmt.Errorf("runtime: %w", errors.New("x"))) },
	} {
		t.Run(name, func(t *testing.T) {
			sv := &stub{fn: func(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
				fn()
				return f.goodEvidence(handoff.StorePIV), nil
			}}
			v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
		})
	}
}

func TestACheckerThatHadAVerifierPanicStillServesTheNextCalls(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	var n int
	var mu sync.Mutex
	sv := &stub{fn: func(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
		mu.Lock()
		n++
		first := n == 1
		mu.Unlock()
		if first {
			panic("the first call breaks")
		}
		return f.goodEvidence(handoff.StorePIV), nil
	}}
	chk := checkerWith(t, handoff.StorePIV, sv)
	v, err := chk.Check(t.Context(), f.request())
	wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
	v, err = chk.Check(t.Context(), f.request())
	wantAccepted(t, v, err)
}

func TestVerifiersThatPanicInSeveralCallsAtOnceDoNotStopTheProcessOrTheOthers(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	var n atomicCounter
	sv := &stub{fn: func(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
		if n.next()%2 == 0 {
			panic("every second call breaks")
		}
		return f.goodEvidence(handoff.StorePIV), nil
	}}
	chk := checkerWith(t, handoff.StorePIV, sv)
	req := f.request()
	var wg sync.WaitGroup
	results := make(chan string, 64)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 8 {
				v, err := chk.Check(t.Context(), req)
				switch {
				case err == nil && v.Accepted():
					results <- "accepted"
				case errors.Is(err, handoff.ErrInternal) && !v.Accepted() && !v.Refused():
					results <- "internal"
				default:
					results <- fmt.Sprintf("bad: code %q, error %v", v.Code, err)
				}
			}
		}()
	}
	wg.Wait()
	close(results)
	count := map[string]int{}
	for r := range results {
		count[r]++
	}
	if count["accepted"] != 32 || count["internal"] != 32 || len(count) != 2 {
		t.Errorf("results %v, want 32 accepted and 32 internal", count)
	}
}

type atomicCounter struct {
	mu sync.Mutex
	n  int
}

func (a *atomicCounter) next() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	return a.n
}

func TestAVerifierThatReturnsAnErrorOfTheInternalKindIsNotAnAcceptanceEither(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	sv := failing(fmt.Errorf("the verifier gave up: %w", handoff.ErrInternal))
	v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), f.request())
	wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
}

func nilMapOf() map[string]int { return nil }
