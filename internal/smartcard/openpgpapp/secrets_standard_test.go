package openpgpapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

var qaPIN = []byte("Xk9#mQ2$")

// qaSecretCase: a command that holds a PIN as Secret values, in the ways that it can go. make returns a new
// command, with the secrets that it holds and what they hold.
type qaSecretCase struct {
	name  string
	table []commandSpec
	ext   bool
	make  func() (apdu.Command, []apdu.Secret, [][]byte)
	steps func() []qaStep
}

func (c qaSecretCase) session(t testing.TB, q *qaTransport) *Session {
	q.ext = c.ext
	s := qaSession(t, q, Options{}, c.table)
	if c.ext {
		s.allowExtended(2000)
	}
	return s
}

func qaSecretCases() []qaSecretCase {
	one := func() (apdu.Command, []apdu.Secret, [][]byte) {
		s := apdu.NewSecret(qaPIN)
		return apdu.Command{INS: 0x20, P2: 0x81}.WithSecretData(s), []apdu.Secret{s}, [][]byte{qaPIN}
	}
	two := func() (apdu.Command, []apdu.Secret, [][]byte) {
		old, next := apdu.NewSecret(qaPIN), apdu.NewSecret([]byte("Zr4&vT8!jW"))
		return apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(old, next), []apdu.Secret{old, next}, [][]byte{qaPIN, []byte("Zr4&vT8!jW")}
	}
	long := func() (apdu.Command, []apdu.Secret, [][]byte) {
		pin := append(bytes.Clone(qaPIN), bytes.Repeat([]byte{0x41}, 592)...)
		s := apdu.NewSecret(pin)
		return apdu.Command{INS: 0xDA, P1: 0x01}.WithSecretData(s), []apdu.Secret{s}, [][]byte{pin}
	}
	okOne := func() []qaStep { return []qaStep{qaOK()} }
	return []qaSecretCase{
		{"a verification", nil, false, one, okOne},
		{"a change of PIN", nil, false, two, okOne},
		{"a body of 600 bytes in the extended form", qaTable(true, true), true, long, okOne},
	}
}

// qaStillHolds says that the secrets hold what they held: send never wipes the secret of the caller.
func qaStillHolds(t testing.TB, what string, secrets []apdu.Secret, pins [][]byte) {
	t.Helper()
	for i, s := range secrets {
		var got []byte
		s.Use(func(b []byte) { got = bytes.Clone(b) })
		if !bytes.Equal(got, pins[i]) || s.Len() != len(pins[i]) {
			t.Errorf("%s: secret %d was changed or wiped by send", what, i)
		}
	}
}

// TestSecretBuffersAreOverwritten: after the call returns, whatever way it ended (success, a status word,
// an error of the transport, an answer that cannot be read, a panic), the encoded command that held the
// PIN is overwritten, in the very slice that the transport was handed (the recorded slices alias what
// send owned). The Secret values themselves still hold the PIN afterwards: they are the caller's, and
// the caller wipes them (with Wipe) when it is done; send does not wipe them behind the caller, and this
// test pins that.
func TestSecretBuffersAreOverwritten(t *testing.T) {
	boom := errors.New("reader: " + string(qaPIN) + " 586b3923 WGsjbVEyJA== 88 107 57")
	endings := []struct {
		name string
		step qaStep
	}{
		{"a status word", qaSW(0x69, 0x82)},
		{"a blocked PIN", qaSW(0x69, 0x83)},
		{"more data", qaSW(0x61, 0x02, 1)},
		{"an error of the transport", qaStep{err: boom}},
		{"no bytes", qaStep{resp: []byte{}}},
		{"one byte", qaStep{resp: []byte{0x90}}},
		{"too many bytes", qaStep{resp: make([]byte, 400)}},
		{"a panic", qaStep{panicVal: "boom"}},
		{"a wrong application", qaSW(0x6D, 0x00)},
	}
	for _, sc := range qaSecretCases() {
		// Success.
		{
			cmd, secrets, pins := sc.make()
			q := &qaTransport{script: sc.steps()}
			s := sc.session(t, q)
			if _, err := s.send(cmd); err != nil {
				t.Fatalf("%s: %v", sc.name, err)
			}
			if len(q.refs) != 1 {
				t.Fatalf("%s: %d commands", sc.name, len(q.refs))
			}
			qaAllZero(t, sc.name+", success", q.refs)
			qaStillHolds(t, sc.name+", success", secrets, pins)
		}
		for _, end := range endings {
			name := fmt.Sprintf("%s, %s", sc.name, end.name)
			cmd, secrets, pins := sc.make()
			script := sc.steps()
			script[0] = end.step
			q := &qaTransport{script: script}
			s := sc.session(t, q)
			var err error
			func() {
				defer func() { _ = recover() }()
				_, err = s.send(cmd)
			}()
			qaAllZero(t, name, q.refs[:1])
			qaAllZero(t, name+": answers", q.given)
			qaStillHolds(t, name, secrets, pins)
			if err != nil {
				for _, pin := range pins {
					qaNoPIN(t, name, pin, err.Error())
					qaNoPIN(t, name+" (%+v)", pin, fmt.Sprintf("%+v", err))
					qaNoPIN(t, name+" (%#v)", pin, fmt.Sprintf("%#v", err))
				}
			}
		}
	}
}

// qaWalk collects the text of an error and of everything below it that Unwrap gives.
func qaWalk(err error) []string {
	if err == nil {
		return nil
	}
	out := []string{err.Error()}
	switch u := err.(type) { //nolint:errorlint // the walk is by the methods themselves, not by errors.Is
	case interface{ Unwrap() error }:
		out = append(out, qaWalk(u.Unwrap())...)
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			out = append(out, qaWalk(e)...)
		}
	}
	return out
}

// TestLostErrorOfASecretShowsNoCause: with a transport whose error text holds the PIN (raw, in hex, base64
// and decimal), no way of printing or encoding the error of a command that holds a PIN shows it, and the
// cause is still found by errors.Is and errors.As. For a command that holds none, the cause is shown.
func TestLostErrorOfASecretShowsNoCause(t *testing.T) {
	boom := errors.New("reader: Xk9#mQ2$ 586b39236d51322 4 WGs5I21RMiQ= 88 107 57 35 109 81 50 36")
	for _, sc := range qaSecretCases() {
		{
			script := sc.steps()
			script[0] = qaStep{err: boom}
			q := &qaTransport{script: script}
			s := sc.session(t, q)
			cmd, _, _ := sc.make()
			_, err := s.send(cmd)
			name := sc.name
			var lost *LostError
			if !errors.As(err, &lost) {
				t.Fatalf("%s: %v", name, err)
			}
			copied := *lost
			if lost.Err != nil || len(qaWalk(err)) != 1 || errors.Unwrap(err) != nil {
				t.Fatalf("%s: the cause is reachable by field or by Unwrap: %v %v", name, lost.Err, qaWalk(err))
			}
			if !errors.Is(err, boom) || !errors.Is(err, ErrSessionDead) || errors.Is(err, ErrNotAllowed) {
				t.Fatalf("%s: Is: %v", name, err)
			}
			var viaAs interface{ Error() string }
			if !errors.As(err, &viaAs) {
				t.Fatalf("%s: As finds nothing", name)
			}
			texts := qaWalk(err)
			for _, v := range []any{err, lost, copied, &copied} {
				for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10.3v", "%-40s"} {
					texts = append(texts, fmt.Sprintf(verb, v))
				}
				texts = append(texts, fmt.Sprint(v), fmt.Sprintln(v))
				if j, jerr := json.Marshal(v); jerr == nil {
					texts = append(texts, string(j))
				}
				for _, h := range []func(*bytes.Buffer) slog.Handler{
					func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
					func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
				} {
					var buf bytes.Buffer
					slog.New(h(&buf)).Error("m", "err", v, slog.Group("g", slog.Any("e", v)))
					texts = append(texts, buf.String())
				}
			}
			texts = append(texts, fmt.Errorf("outer: %w", err).Error(), fmt.Sprint(errors.Join(err, errors.New("x"))))
			for i, text := range texts {
				qaNoPIN(t, fmt.Sprintf("%s, text %d", name, i), qaPIN, text)
				if strings.Contains(text, "reader:") {
					t.Fatalf("%s: text %d shows the cause: %q", name, i, text)
				}
			}
			if !strings.Contains(err.Error(), "may have carried out the command") || !lost.OutcomeUnknown {
				t.Fatalf("%s: the text does not say the card may have changed: %q", name, err)
			}
		}
	}
	// The same for a continuation whose GET RESPONSE is refused: the StatusError cause is reachable and
	// is not in the text.
	q := &qaTransport{script: []qaStep{qaSW(0x61, 0x01, 1), qaSW(0x6A, 0x88)}}
	_, err := qaSession(t, q, Options{}, nil).send(qaVerify(qaPIN))
	var se *StatusError
	if !errors.As(err, &se) || se.SW != 0x6A88 || strings.Contains(err.Error(), "6A88") {
		t.Fatalf("a continuation: %v", err)
	}
	// A command with no PIN keeps the cause where it was: in the field, in Unwrap, in the text.
	q = &qaTransport{script: []qaStep{{err: boom}}}
	_, err = qaSession(t, q, Options{}, nil).send(qaGetData(0x004F))
	var lost *LostError
	if !errors.As(err, &lost) || !errors.Is(lost.Err, boom) || !strings.Contains(err.Error(), "reader:") || !errors.Is(err, boom) || !errors.Is(err, ErrSessionDead) {
		t.Fatalf("a read: %v", err)
	}
	if w := qaWalk(err); len(w) != 3 || w[1] != boom.Error() || w[2] != ErrSessionDead.Error() {
		t.Fatalf("the walk of a read: %q", w)
	}
	if got := fmt.Sprintf("%#v", err); !strings.Contains(got, "OutcomeUnknown") || !strings.Contains(got, "Op:") {
		t.Fatalf("%%#v of a read: %q", got)
	}
}

// TestNoErrorHoldsThePIN walks the errors that send gives on its other paths, with a command that
// carries a PIN, and searches each for the PIN.
func TestNoErrorHoldsThePIN(t *testing.T) {
	pin := qaPIN
	for name, run := range map[string]func() error{
		"not allowed (a PIN too short)": func() error {
			_, err := qaSession(t, &qaTransport{}, Options{}, nil).send(qaVerify(pin[:3]))
			return err
		},
		"not allowed (a PIN in plain Data)": func() error {
			_, err := qaSession(t, &qaTransport{}, Options{}, nil).send(qaPlain(0x20, 0, 0x81, bytes.Clone(pin)))
			return err
		},
		"not allowed (a PIN in plain Data and a secret)": func() error {
			c := qaVerify(pin)
			c.Data = bytes.Clone(pin)
			_, err := qaSession(t, &qaTransport{}, Options{}, nil).send(c)
			return err
		},
		"not allowed (the wrong reference)": func() error {
			_, err := qaSession(t, &qaTransport{}, Options{}, nil).send(apdu.Command{INS: 0x20, P2: 0x84}.WithSecretData(apdu.NewSecret(pin)))
			return err
		},
		"read-only": func() error {
			_, err := qaSession(t, &qaTransport{}, Options{ReadOnly: true}, nil).send(qaVerify(pin))
			return err
		},
		"not selected": func() error {
			_, err := qaUnselected(t, &qaTransport{}, Options{}, nil).send(qaVerify(pin))
			return err
		},
		"a status word": func() error {
			_, err := qaSession(t, &qaTransport{script: []qaStep{qaSW(0x69, 0x83)}}, Options{}, nil).send(qaVerify(pin))
			return err
		},
		"too long for any form": func() error {
			c := apdu.Command{INS: 0xDA, P1: 0x01}.WithSecretData(apdu.NewSecret(append(bytes.Clone(pin), make([]byte, 70000)...)))
			_, err := qaSession(t, &qaTransport{}, Options{}, qaTable(true, true)).send(c)
			return err
		},
		"a dead session": func() error {
			s := qaSession(t, &qaTransport{script: []qaStep{{err: errors.New("gone")}}}, Options{}, nil)
			_, _ = s.send(qaGetData(0x004F))
			_, err := s.send(qaVerify(pin))
			return err
		},
		"a closed session": func() error {
			s := qaSession(t, &qaTransport{}, Options{}, nil)
			_ = s.Close()
			_, err := s.send(qaVerify(pin))
			return err
		},
		"a lost secret command": func() error {
			s := qaSession(t, &qaTransport{script: []qaStep{{err: errors.New("gone: " + string(pin))}}}, Options{}, nil)
			_, err := s.send(qaVerify(pin))
			return err
		},
	} {
		err := run()
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		for i, text := range append(qaWalk(err), fmt.Sprintf("%v|%+v|%#v|%s|%q", err, err, err, err, err)) {
			qaNoPIN(t, fmt.Sprintf("%s (%d)", name, i), pin, text)
		}
	}
	// And the command, printed by the layer's error paths or by the test log, holds none either.
	qaNoPIN(t, "the command", pin, fmt.Sprintf("%v %+v %#v %s", qaVerify(pin), qaVerify(pin), qaVerify(pin), qaVerify(pin)))
	// A PIN command printed or encoded by any means shows nothing of the PIN, in plain or in the pair form.
	for _, c := range []apdu.Command{qaVerify(pin), qaChange(pin, []byte("Zr4&vT8!jW"))} {
		out, _ := json.Marshal(struct {
			Cmd  apdu.Command
			List []apdu.Command
		}{c, []apdu.Command{c}})
		qaNoPIN(t, "json of a command", pin, string(out))
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "cmd", c)
		slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "cmd", c, "all", []apdu.Command{c})
		qaNoPIN(t, "slog of a command", pin, buf.String())
		wrapped := struct{ c apdu.Command }{c}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%p", "%q", "%x"} {
			qaNoPIN(t, "a command in an unexported field, "+verb, pin, fmt.Sprintf(verb, wrapped)) //nolint:staticcheck // the verbs that do not fit are the point
		}
	}
}
