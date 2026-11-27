package openpgpapp

import (
	"bytes"
	"errors"
	"runtime"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

// A wiped or empty secret is never sent as a PIN: the length rule of the row refuses it before anything
// reaches the transport. (The apdu package encodes it as no body at all, never as zeros.)
func TestWipedAndEmptySecretsAreNeverSent(t *testing.T) {
	wiped := apdu.NewSecret(qaPIN)
	wiped.Wipe()
	for name, c := range map[string]apdu.Command{
		"verify, wiped":        apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(wiped),
		"verify, empty":        apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(apdu.NewSecret(nil)),
		"verify Admin, wiped":  apdu.Command{INS: 0x20, P2: 0x83}.WithSecretData(wiped),
		"change, both wiped":   apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(wiped, wiped),
		"change Admin, wiped":  apdu.Command{INS: 0x24, P2: 0x83}.WithSecretPair(wiped, wiped),
		"change, both empty":   apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(apdu.NewSecret(nil), apdu.NewSecret(nil)),
		"verify, the zero one": apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(apdu.Secret{}),
	} {
		for _, ro := range []bool{false, true} {
			q := &qaTransport{script: []qaStep{qaOK()}}
			s := qaSession(t, q, Options{ReadOnly: ro}, nil)
			if _, err := s.send(c); err == nil || q.calls() != 0 || s.Dead() {
				t.Errorf("%s (read-only %v): %v, %d calls, %x", name, ro, err, q.calls(), q.sent)
			}
		}
	}
	// A secret that is wiped after its command was made: the command no longer holds a PIN.
	s1 := apdu.NewSecret(qaPIN)
	c := apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(s1)
	q := &qaTransport{script: []qaStep{qaOK(), qaOK()}}
	s := qaSession(t, q, Options{}, nil)
	if _, err := s.send(c); err != nil {
		t.Fatal(err)
	}
	s1.Wipe()
	if _, err := s.send(c); !errors.Is(err, ErrNotAllowed) || q.calls() != 1 {
		t.Fatalf("after the wipe: %v, %d calls", err, q.calls())
	}
}

// A secret that two commands share: the sending of the one uses nothing up, the wipe of the secret reaches
// both, and send never wipes it.
func TestOneSecretInTwoCommandsAndTwoSessions(t *testing.T) {
	s := apdu.NewSecret(qaPIN)
	c81 := apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(s)
	c82 := apdu.Command{INS: 0x20, P2: 0x82}.WithSecretData(s)
	q1 := &qaTransport{script: []qaStep{qaOK(), qaOK()}}
	q2 := &qaTransport{script: []qaStep{qaOK()}}
	s1, s2 := qaSession(t, q1, Options{}, nil), qaSession(t, q2, Options{}, nil)
	for _, step := range []struct {
		s *Session
		c apdu.Command
	}{{s1, c81}, {s2, c82}, {s1, c82}} {
		if _, err := step.s.send(step.c); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []*qaTransport{q1, q2} {
		qaAllZero(t, "the commands", q.refs)
		for _, w := range q.sent {
			if !bytes.Equal(w[5:], qaPIN) {
				t.Fatalf("the wire: %x", w)
			}
		}
	}
	if s.Len() != len(qaPIN) {
		t.Fatal("send used the secret up")
	}
	s.Wipe()
	for _, c := range []apdu.Command{c81, c82} {
		qq := &qaTransport{}
		if _, err := qaSession(t, qq, Options{}, nil).send(c); !errors.Is(err, ErrNotAllowed) || qq.calls() != 0 {
			t.Fatalf("after the wipe: %v", err)
		}
	}
}

// A wipe while send encodes. The code guarantees, and the race detector confirms there is no data race
// (the bytes are read only inside Secret.Use, under its lock), that one of three things happens and no
// other: the whole PIN is on the wire (the wipe came after the copy), or nothing is sent and the call is
// ErrNotAllowed (the wipe came before the length rule ran) or apdu.ErrSecretChanged (it came between the
// length and the copy; the half-made command is cleared, the session lives). Never a part of the PIN, never zeros.
// The secret is the caller's: the wipe is the caller's to do, here from another goroutine.
func TestWipeDuringSend(t *testing.T) {
	full := append([]byte{0x00, 0x20, 0x00, 0x81, byte(len(qaPIN))}, qaPIN...)
	counts := map[string]int{}
	for round := range 500 {
		s := apdu.NewSecret(qaPIN)
		c := apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(s)
		q := &qaTransport{script: []qaStep{qaOK()}}
		sess := qaSession(t, q, Options{}, nil)
		var wg sync.WaitGroup
		wg.Add(2)
		var err error
		go func() {
			defer wg.Done()
			for range round % 7 {
				runtime.Gosched()
			}
			s.Wipe()
		}()
		go func() {
			defer wg.Done()
			_, err = sess.send(c)
		}()
		wg.Wait()
		switch {
		case err == nil:
			counts["sent"]++
			if q.calls() != 1 || !bytes.Equal(q.sent[0], full) {
				t.Fatalf("round %d: sent %x", round, q.sent)
			}
		case errors.Is(err, ErrNotAllowed):
			counts["refused"]++
			if q.calls() != 0 {
				t.Fatalf("round %d: refused, %d calls", round, q.calls())
			}
		case errors.Is(err, apdu.ErrSecretChanged):
			counts["changed"]++
			if q.calls() != 0 || sess.Dead() {
				t.Fatalf("round %d: %v, %d calls", round, err, q.calls())
			}
		default:
			t.Fatalf("round %d: %v", round, err)
		}
		qaAllZero(t, "the command", q.refs)
		for _, w := range q.sent {
			if bytes.Contains(w, make([]byte, 3)) {
				t.Fatalf("round %d: zeros on the wire: %x", round, w)
			}
		}
	}
	t.Logf("500 rounds: %v", counts)
}

// The wipe between the judgement of the allowlist and the encoding, made certain with the hook of the
// session: the secret is wiped at the moment after the length rule ran. Nothing reaches the transport (above
// all, never a VERIFY with a header and no body), the error is apdu.ErrSecretChanged (apdu.ErrSecretEmpty is
// one), the session lives, and the command still holds its other secret.
func TestWipeBetweenJudgementAndEncoding(t *testing.T) {
	pinA, pinB := []byte("Xk9#mQ2$"), []byte("Zr4&vT8!jW")
	for name, tc := range map[string]struct {
		make func() (apdu.Command, []apdu.Secret)
		wipe []int
	}{
		"verify": {func() (apdu.Command, []apdu.Secret) {
			a := apdu.NewSecret(pinA)
			return apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(a), []apdu.Secret{a}
		}, []int{0}},
		"verify Admin": {func() (apdu.Command, []apdu.Secret) {
			a := apdu.NewSecret(pinA)
			return apdu.Command{INS: 0x20, P2: 0x83}.WithSecretData(a), []apdu.Secret{a}
		}, []int{0}},
		"change, the old one": {func() (apdu.Command, []apdu.Secret) {
			a, b := apdu.NewSecret(pinA), apdu.NewSecret(pinB)
			return apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(a, b), []apdu.Secret{a, b}
		}, []int{0}},
		"change, the new one": {func() (apdu.Command, []apdu.Secret) {
			a, b := apdu.NewSecret(pinA), apdu.NewSecret(pinB)
			return apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(a, b), []apdu.Secret{a, b}
		}, []int{1}},
		"change, both": {func() (apdu.Command, []apdu.Secret) {
			a, b := apdu.NewSecret(pinA), apdu.NewSecret(pinB)
			return apdu.Command{INS: 0x24, P2: 0x83}.WithSecretPair(a, b), []apdu.Secret{a, b}
		}, []int{0, 1}},
	} {
		c, secrets := tc.make()
		q := &qaTransport{script: []qaStep{qaOK(), qaOK()}}
		s := qaSession(t, q, Options{}, nil)
		fired := 0
		s.afterJudge = func() {
			fired++
			for _, i := range tc.wipe {
				secrets[i].Wipe()
			}
		}
		_, err := s.send(c)
		if fired != 1 || !errors.Is(err, apdu.ErrSecretChanged) || !errors.Is(err, apdu.ErrSecretEmpty) || q.calls() != 0 || s.Dead() {
			t.Fatalf("%s: %v, %d calls, wire %x, hook %d", name, err, q.calls(), q.sent, fired)
		}
		// The session goes on.
		s.afterJudge = nil
		if _, err := s.send(qaGetData(0x004F)); err != nil || q.calls() != 1 {
			t.Fatalf("%s: the session did not go on: %v", name, err)
		}
	}
}

// The comparison in send of the encoded length with the length that was judged. Encode refuses a part that
// holds no byte, so the two can differ only by a fault of the code between them; the test makes the fault
// by handing one the wrong length, and holds that nothing is sent, the buffer is cleared and the
// session lives; and that the right length, for each form and each Le, passes.
func TestEncodedLengthMustBeTheJudgedLength(t *testing.T) {
	for _, le := range []int{0, 1, 256} {
		for _, extended := range []bool{false, true} {
			for name, c := range map[string]apdu.Command{
				"verify": qaVerify(qaPIN),
				"change": qaChange(qaPIN, []byte("Zr4&vT8!jW")),
			} {
				c.Le = le
				q := &qaTransport{ext: extended, script: []qaStep{qaOK(), qaOK()}}
				s := qaSession(t, q, Options{}, nil)
				spec, judged, ok := judge(s.table, c, false)
				if !ok {
					t.Fatal(name)
				}
				if want := c.BodyLen(); judged != want {
					t.Fatalf("%s: judged %d, body %d", name, judged, want)
				}
				for _, wrong := range []int{judged - 1, judged + 1, 0, judged + 255} {
					if _, _, err := s.one(spec, c, extended, s.budget, wrong); !errors.Is(err, apdu.ErrSecretChanged) || q.calls() != 0 {
						t.Fatalf("%s, Le %d, extended %v, judged %d: %v, %d calls", name, le, extended, wrong, err, q.calls())
					}
				}
				if _, _, err := s.one(spec, c, extended, s.budget, judged); err != nil || q.calls() != 1 {
					t.Fatalf("%s, Le %d, extended %v: %v", name, le, extended, err)
				}
				qaAllZero(t, name, q.refs)
				if !bytes.Contains(q.sent[0], qaPIN) {
					t.Fatalf("%s: the PIN is not on the wire: %x", name, q.sent[0])
				}
			}
		}
	}
}
