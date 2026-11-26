//go:build linux || darwin

package ceremony_test

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
)

// A fault of a signing while the context has ended: the stop names the real cause and adds the end of the
// context beside it; only a fault that is itself a cancel or a deadline is reported as the end of the context.
// The root certificate is the first signature of a key (n = 1), the removal authorisation the second (n = 2),
// and the second goes through a signer of the trust set writer that keeps the text of an error only.

type sfCase struct {
	name string
	n    int // which signature of the key A fails: 1 is the certificate, 2 the removal authorisation
}

var sfSteps = []sfCase{{"the root certificate", 1}, {"the removal authorisation", 2}}

// sfRun makes the signing of A fail on its n-th signature with the error that fault gives, the context having
// ended (cancelled, or past its deadline) when the fault comes.
func sfRun(t *testing.T, n int, deadline bool, fault func(ctx context.Context) error) (*ceremony.Made, *mkRun, error) {
	t.Helper()
	r := newMkRun(t)
	var ctx context.Context
	var cancel context.CancelFunc
	if deadline {
		ctx, cancel = context.WithTimeout(context.Background(), 150*time.Millisecond)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	t.Cleanup(cancel)
	r.store.wrapKey = mkWrap(func(k *mkKey) {
		calls := 0
		k.signFn = func(rd io.Reader, digest []byte, o crypto.SignerOpts) ([]byte, error) {
			calls++
			if k.label != "A" || calls != n {
				return k.Key.Sign(rd, digest, o)
			}
			if deadline {
				<-ctx.Done()
			} else {
				cancel()
			}
			return nil, fault(ctx)
		}
	})
	m, err := ceremony.MakeRoots(ctx, r.in())
	return m, r, err
}

func TestASigningFaultThatIsNotACancelKeepsItsCauseAndNamesTheEndOfTheContextBesideIt(t *testing.T) {
	cause := errors.New("test: the key of the store changed")
	for _, step := range sfSteps {
		for _, deadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, deadline %v", step.name, deadline), func(t *testing.T) {
				m, r, err := sfRun(t, step.n, deadline, func(context.Context) error { return cause })
				if m != nil || err == nil {
					t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
				}
				me, ok := mkAs[*ceremony.MakeError](err)
				if !ok || me.Step != "signatures" {
					t.Fatalf("the error is %T %v, want a fault of the step signatures", err, err)
				}
				if !strings.Contains(err.Error(), "the key of the store changed") || !strings.Contains(err.Error(), "the context also ended") {
					t.Errorf("the line names the cause and the end of the context beside it: %v", err)
				}
				want := context.Canceled
				if deadline {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) {
					t.Errorf("the end of the context is not reachable: %v", err)
				}
				if step.n == 1 && !errors.Is(err, cause) {
					t.Errorf("the cause is not reachable: %v", err)
				}
				if err.Error() == context.Canceled.Error() || err.Error() == context.DeadlineExceeded.Error() {
					t.Errorf("the fault is reported as the end of the context alone: %v", err)
				}
				if r.log.count("signatures-line 2") != 0 && step.n == 1 {
					t.Errorf("the run went on:\n%s", strings.Join(r.log.all(), "\n"))
				}
			})
		}
	}
}

// A fault that is itself a cancel or a deadline is the end of the context, plain: typed, wrapped, or, where a signer
// keeps the text only, as the words of the context package.
func TestASigningFaultThatIsACancelOrADeadlineIsReportedAsTheEndOfTheContext(t *testing.T) {
	cases := []struct {
		name     string
		deadline bool
		fault    func(ctx context.Context) error
		steps    []sfCase
	}{
		{"a typed cancel", false, func(context.Context) error { return context.Canceled }, sfSteps},
		{"a wrapped cancel", false, func(context.Context) error { return fmt.Errorf("test: signing: %w", context.Canceled) }, sfSteps},
		{"a typed deadline", true, func(context.Context) error { return context.DeadlineExceeded }, sfSteps},
		{"a wrapped deadline", true, func(ctx context.Context) error { return fmt.Errorf("test: signing: %w", ctx.Err()) }, sfSteps},
		// These arrive as text: no type, no wrapping. The certificate is signed in the process, so its error
		// keeps no type either way; both steps are tried.
		{"a cancel that arrives as text", false, func(context.Context) error { return errors.New("test: the store: context canceled") }, sfSteps},
		{"a deadline that arrives as text", true, func(context.Context) error { return errors.New("test: the store: context deadline exceeded") }, sfSteps},
	}
	for _, c := range cases {
		for _, step := range c.steps {
			t.Run(c.name+", "+step.name, func(t *testing.T) {
				m, r, err := sfRun(t, step.n, c.deadline, c.fault)
				if m != nil || err == nil {
					t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
				}
				want := context.Canceled
				if c.deadline {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) || err != want { //nolint:errorlint // the error of the context itself, as the run reports it between two steps
					t.Errorf("the error is %T %v, want the error of the context itself", err, err)
				}
				if _, ok := mkAs[*ceremony.MakeError](err); ok {
					t.Errorf("the end of the context is reported as a fault of the step signatures: %v", err)
				}
				if r.log.count("save-removal") != 0 {
					t.Errorf("a removal authorisation was stored after the context ended:\n%s", strings.Join(r.log.all(), "\n"))
				}
			})
		}
	}
}

// With a context that has not ended, the words of a cancel in the text of a fault are only words.
func TestTheWordsOfACancelInTheTextOfASigningFaultAreNoCancelWhileTheContextLives(t *testing.T) {
	for _, step := range sfSteps {
		t.Run(step.name, func(t *testing.T) {
			r := newMkRun(t)
			r.store.wrapKey = mkWrap(func(k *mkKey) {
				calls := 0
				k.signFn = func(rd io.Reader, digest []byte, o crypto.SignerOpts) ([]byte, error) {
					calls++
					if k.label == "A" && calls == step.n {
						return nil, errors.New(`test: the store refused, and its reason quotes "context canceled" and "context deadline exceeded"`)
					}
					return k.Key.Sign(rd, digest, o)
				}
			})
			m, err := r.make()
			me, ok := mkAs[*ceremony.MakeError](err)
			if m != nil || !ok || me.Step != "signatures" || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("MakeRoots: a result %v, the error %T %v; want a fault of the step signatures", m != nil, err, err)
			}
		})
	}
}

// A refusal of the store whose reason quotes the words of the context package, while the context has ended for
// another reason, is a refusal of the store and not the end of the context.
func TestASigningRefusalThatQuotesTheWordsOfACancelIsNotTakenForTheEndOfTheContext(t *testing.T) {
	for _, step := range sfSteps {
		t.Run(step.name, func(t *testing.T) {
			m, _, err := sfRun(t, step.n, false, func(context.Context) error {
				return errors.New(`test: the store refused: the reason "context canceled" is quoted from a request`)
			})
			if m != nil || err == nil {
				t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
			}
			if me, ok := mkAs[*ceremony.MakeError](err); !ok || me.Step != "signatures" || !strings.Contains(err.Error(), "the reason") {
				t.Errorf("the refusal of the store lost its cause: %T %v", err, err)
			}
		})
	}
}
