//go:build linux || darwin

package ceremony_test

import (
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
)

// A store that returns a key together with an error has broken its contract. The key is closed, the
// error is returned, and the run goes no further.

var errMkBirth = errors.New("test: the store failed after the key was made")

func TestAKeyThatComesBackWithAnErrorFromTheBirthIsClosedOnce(t *testing.T) {
	for _, label := range []string{"A", "B"} {
		t.Run("the birth of "+label, func(t *testing.T) {
			r := newMkRun(t)
			r.store.keyAndErr = map[string]error{label: errMkBirth}
			m, err := r.make()
			if m != nil || err == nil {
				t.Fatalf("MakeRoots made a result (%v): %v", m != nil, err)
			}
			if !errors.Is(err, errMkBirth) {
				t.Errorf("the error is not the error of the store: %v", err)
			}
			me, ok := mkAs[*ceremony.MakeError](err)
			if !ok || me.Step != "births" {
				t.Errorf("the error is %T (%v), want a *MakeError of the step births", err, err)
			}
			if len(r.store.keys) == 0 {
				t.Fatal("the store made no key")
			}
			for _, k := range r.store.keys {
				if k.closed() != 1 {
					t.Errorf("the key %s was closed %d times, want 1", k.label, k.closed())
				}
			}
			if n := r.log.count("birth "); (label == "A" && n != 1) || (label == "B" && n != 2) {
				t.Errorf("%d births were asked for:\n%s", n, strings.Join(r.log.all(), "\n"))
			}
			if n := r.log.count("sign "); n != 0 {
				t.Errorf("%d signatures were made", n)
			}
			if n := r.log.count("console:"); n != 0 {
				t.Errorf("a fingerprint was shown")
			}
			// No line says that the key that came with an error was born.
			want := 0
			if label == "B" {
				want = 1
			}
			if n := r.log.count("births-line"); n != want {
				t.Errorf("%d birth lines, want %d", n, want)
			}
		})
	}
}

func TestAKeyThatComesBackWithAnErrorAndCannotBeClosedStopsTheRunWithoutACrash(t *testing.T) {
	for name, panicOn := range map[string]string{"a close that panics": "close", "a close that works": ""} {
		t.Run(name, func(t *testing.T) {
			r := newMkRun(t)
			r.store.keyAndErr = map[string]error{"A": errMkBirth}
			r.store.afterBirth = func(label string) {
				if panicOn != "" && len(r.store.keys) > 0 {
					r.store.keys[0].panicOn = panicOn
				}
			}
			m, err := r.make()
			if m != nil || !errors.Is(err, errMkBirth) {
				t.Fatalf("MakeRoots: %v, %v", m != nil, err)
			}
		})
	}
}

func TestARefusalThatComesWithAKeyIsReturnedAsItIs(t *testing.T) {
	// A refusal of the store that has a reason code is for the command to map, so it is not wrapped,
	// also when the store broke its contract and returned a key with it.
	r := newMkRun(t)
	refusal := &ceremony.BackendError{Reasons: []string{"key-exists"}, Msg: "test: a key file is in the way"}
	r.store.keyAndErr = map[string]error{"A": refusal}
	_, err := r.make()
	if mkBackendReason(err) != "key-exists" {
		t.Fatalf("the error is %v, want the refusal as it is", err)
	}
	for _, k := range r.store.keys {
		if k.closed() != 1 {
			t.Errorf("the key %s was closed %d times, want 1", k.label, k.closed())
		}
	}
}
