//go:build linux || darwin

package ceremony_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	keyv1alpha1 "github.com/truvity/atoom/key/gen/atoom/key/v1alpha1"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
	"github.com/truvity/atoom/key/keyid"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/keystore/port"
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

// sfDeadlineCtx is a context whose deadline passes when the test says so, and not before: Done is open and Err
// is nil until expire, then Done is closed and Err is context.DeadlineExceeded, as for a context past its deadline.
// A real deadline of some milliseconds would pass wherever the machine is slow, in the making of a key or the
// writing of a file, and the run would stop at another step than the one the test means.
type sfDeadlineCtx struct {
	context.Context
	done chan struct{}
	mu   sync.Mutex
	err  error
	at   time.Time
}

func newSfDeadlineCtx() *sfDeadlineCtx {
	return &sfDeadlineCtx{Context: context.Background(), done: make(chan struct{})}
}

// expire makes the deadline passed; a second call does nothing.
func (c *sfDeadlineCtx) expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err, c.at = context.DeadlineExceeded, time.Now()
		close(c.done)
	}
}

func (c *sfDeadlineCtx) Done() <-chan struct{} { return c.done }

func (c *sfDeadlineCtx) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *sfDeadlineCtx) Deadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at, c.err != nil
}

// sfRun makes the signing of A fail on its n-th signature with the error that fault gives, the context having
// ended (cancelled, or past its deadline) when the fault comes. The test itself ends the context, inside the
// signature that fails and before the fault is returned, so the end of the context comes at that point and at no
// other, however slow the machine is: nothing waits for a time.
func sfRun(t *testing.T, n int, deadline bool, fault func(ctx context.Context) error) (*ceremony.Made, *mkRun, error) {
	t.Helper()
	r := newMkRun(t)
	var ctx context.Context
	var end func() // ends the context: a cancel, or the passing of the deadline
	if deadline {
		d := newSfDeadlineCtx()
		ctx, end = d, d.expire
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(context.Background())
		end = cancel
	}
	t.Cleanup(end)
	r.store.wrapKey = mkWrap(func(k *mkKey) {
		calls := 0
		k.signFn = func(rd io.Reader, digest []byte, o crypto.SignerOpts) ([]byte, error) {
			calls++
			if k.label != "A" || calls != n {
				return k.Key.Sign(rd, digest, o)
			}
			end()
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

// A fault that is itself a cancel or a deadline (typed, or wrapped) is the end of the context, plain. The signers of
// the trust set keep that one fact of their cause and no text.
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

// The words of a cancel or a deadline that arrive as text only are no cancel: the fault is what it is, and the end of the
// context is named beside it.
func TestACancelThatArrivesOnlyAsTextIsTheFaultItIsWithTheEndOfTheContextBesideIt(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		words := "context canceled"
		want := context.Canceled
		if deadline {
			words, want = "context deadline exceeded", context.DeadlineExceeded
		}
		for _, step := range sfSteps {
			t.Run(fmt.Sprintf("%s, %s", words, step.name), func(t *testing.T) {
				m, _, err := sfRun(t, step.n, deadline, func(context.Context) error { return errors.New("test: the store: " + words) })
				me, ok := mkAs[*ceremony.MakeError](err)
				if m != nil || !ok || me.Step != "signatures" {
					t.Fatalf("MakeRoots: a result %v, the error %T %v; want a fault of the step signatures", m != nil, err, err)
				}
				if !strings.Contains(err.Error(), "the store: "+words) || !strings.Contains(err.Error(), "the context also ended") {
					t.Errorf("the line names the fault and the end of the context beside it: %v", err)
				}
				if !errors.Is(err, want) {
					t.Errorf("the end of the context is not reachable: %v", err)
				}
			})
		}
	}
}

// sfPortClient is a key-port client whose Sign fails with the error of the test, as the client of the port does when
// the call is cancelled or its deadline passes; the key that the engine signs with is a key of the port over it.
type sfPortClient struct {
	keyv1alpha1connect.KeyStoreServiceClient
	spki []byte
	fail error
}

func (c sfPortClient) Capabilities(context.Context, *connect.Request[keyv1alpha1.CapabilitiesRequest]) (*connect.Response[keyv1alpha1.CapabilitiesResponse], error) {
	return connect.NewResponse(&keyv1alpha1.CapabilitiesResponse{Store: "software", Purposes: []*keyv1alpha1.PurposeInfo{{Name: "x509-root-a", Algorithm: "ES384", Operations: []string{"sign"}}}}), nil
}

func (c sfPortClient) PublicKey(context.Context, *connect.Request[keyv1alpha1.PublicKeyRequest]) (*connect.Response[keyv1alpha1.PublicKeyResponse], error) {
	return connect.NewResponse(&keyv1alpha1.PublicKeyResponse{SpkiDer: c.spki, KeyId: keyid.Software(c.spki)}), nil
}

func (c sfPortClient) Sign(context.Context, *connect.Request[keyv1alpha1.SignRequest]) (*connect.Response[keyv1alpha1.SignResponse], error) {
	return nil, c.fail
}

// A Connect error with the code for cancel or for deadline, as the client of the key port returns it, is the end of the
// context for the engine, as a typed one is, in the certificate and in the removal authorisation; any other code is
// the fault it is.
func TestAConnectCancelOrDeadlineFromTheKeyPortIsTheEndOfTheContext(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		code     connect.Code
		deadline bool
		ended    bool // reported as the end of the context
	}{
		{"the code canceled", connect.CodeCanceled, false, true},
		{"the code deadline_exceeded", connect.CodeDeadlineExceeded, true, true},
		{"the code unavailable while the context was cancelled", connect.CodeUnavailable, false, false},
		{"the code internal while the deadline passed", connect.CodeInternal, true, false},
	}
	for _, c := range cases {
		for _, step := range sfSteps {
			t.Run(c.name+", "+step.name, func(t *testing.T) {
				client := sfPortClient{spki: spki, fail: connect.NewError(c.code, errors.New("test: the store"))}
				m, r, err := sfRun(t, step.n, c.deadline, func(ctx context.Context) error {
					k, kerr := port.NewKey(context.Background(), client, "x509-root-a")
					if kerr != nil {
						t.Errorf("NewKey: %v", kerr)
						return kerr
					}
					digest := sha512.Sum384([]byte("x"))
					_, serr := k.Sign(rand.Reader, digest[:], crypto.SHA384)
					return serr
				})
				_ = r
				if m != nil || err == nil {
					t.Fatalf("MakeRoots: a result %v, the error %v", m != nil, err)
				}
				want := context.Canceled
				if c.deadline {
					want = context.DeadlineExceeded
				}
				_, isMake := mkAs[*ceremony.MakeError](err)
				if c.ended {
					if err != want || isMake { //nolint:errorlint // the error of the context itself
						t.Errorf("the error is %T %v, want the error of the context itself", err, err)
					}
					return
				}
				if !isMake || !errors.Is(err, want) || !strings.Contains(err.Error(), "the context also ended") {
					t.Errorf("the error is %T %v, want the fault of the step signatures with the end of the context beside it", err, err)
				}
			})
		}
	}
}

// The context of the tests above is open until the test lets its deadline pass, and then it is what a context past
// its deadline is: closed Done, DeadlineExceeded, a deadline in the past, and the same for a context derived from it.
func TestTheDeadlineContextOfTheSigningFaultTestsIsOpenUntilItPassesAndThenIsPastItsDeadline(t *testing.T) {
	d := newSfDeadlineCtx()
	child, cancel := context.WithCancel(d)
	defer cancel()
	if d.Err() != nil || child.Err() != nil {
		t.Fatalf("before: %v, %v", d.Err(), child.Err())
	}
	select {
	case <-d.Done():
		t.Fatal("Done is closed before the deadline passed")
	default:
	}
	if _, ok := d.Deadline(); ok {
		t.Error("a deadline is reported before it passed")
	}
	d.expire()
	d.expire()
	<-child.Done() // the derived context follows the parent at once
	for name, err := range map[string]error{"the context": d.Err(), "a derived context": child.Err(), "its cause": context.Cause(child)} {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: %v, want context.DeadlineExceeded", name, err)
		}
	}
	if at, ok := d.Deadline(); !ok || time.Until(at) > 0 {
		t.Errorf("the deadline: %v, %v; want one in the past", at, ok)
	}
}
