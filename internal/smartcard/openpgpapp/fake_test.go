package openpgpapp

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

// fakeTransport is a scripted Transport for the tests of send: each Transmit takes the next step. It
// records a copy of every command at the time of the call, the slice it was given, and the slice it
// returned, so that a test can see what was overwritten afterwards. The real fake card is a later piece.
type fakeTransport struct {
	mu       sync.Mutex
	ext      bool
	script   []step
	sent     [][]byte
	sentRefs [][]byte
	budgets  []time.Duration
	given    [][]byte
	closed   int
	powered  int
}

type step struct {
	resp []byte
	err  error
}

func ok(data ...byte) step { return step{resp: append(append([]byte(nil), data...), 0x90, 0x00)} }
func sw(hi, lo byte, data ...byte) step {
	return step{resp: append(append([]byte(nil), data...), hi, lo)}
}

func (f *fakeTransport) PowerOn(time.Duration) ([]byte, error) { f.powered++; return nil, nil }
func (f *fakeTransport) PowerOff(time.Duration) error          { f.powered++; return nil }
func (f *fakeTransport) ExtendedAPDU() bool                    { return f.ext }
func (f *fakeTransport) Close() error                          { f.closed++; return nil }

func (f *fakeTransport) Transmit(command []byte, budget time.Duration) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, append([]byte(nil), command...))
	f.sentRefs = append(f.sentRefs, command)
	f.budgets = append(f.budgets, budget)
	if len(f.script) == 0 {
		return nil, errors.New("fake: script exhausted")
	}
	s := f.script[0]
	f.script = f.script[1:]
	if s.err != nil {
		return nil, s.err
	}
	out := append([]byte(nil), s.resp...)
	f.given = append(f.given, out)
	return out, nil
}

// calls is the number of commands that reached the transport.
func (f *fakeTransport) calls() int { return len(f.sent) }

func newSession(t testing.TB, f *fakeTransport, o Options) *Session {
	t.Helper()
	s, err := NewSession(f, o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func zeros(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

// getData is a command that the allowlist allows and that needs nothing else.
func getData(tag uint16, le int) apdu.Command {
	return apdu.Command{CLA: 0x00, INS: 0xCA, P1: byte(tag >> 8), P2: byte(tag), Le: le}
}

func verifyCmd(pin []byte) apdu.Command {
	return apdu.Command{CLA: 0x00, INS: 0x20, P2: 0x81, Data: pin}
}
