package openpgpapp

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

// The support of the tests of the allowlist and of send that were written from the card specification and
// from the list of commands, not from the table. Names start with qa so that they stand apart from the
// helpers of the other test files.

// qaStep is one scripted answer of qaTransport: a response, an error, or a panic.
type qaStep struct {
	resp     []byte
	err      error
	panicVal any
}

// qaTransport is a scripted Transport that keeps what it was handed: a copy of each command at the time
// of the call, and the very slice (which send overwrites for a command that holds a secret), and the
// slices it returned.
type qaTransport struct {
	mu       sync.Mutex
	ext      bool
	script   []qaStep
	sent     [][]byte
	refs     [][]byte
	budgets  []time.Duration
	given    [][]byte
	closed   int
	closeErr error
	// powerErr is returned by PowerOn and PowerOff; power counts the calls to them.
	powerErr error
	power    int
}

func qaOK(data ...byte) qaStep { return qaStep{resp: append(append([]byte(nil), data...), 0x90, 0x00)} }
func qaSW(hi, lo byte, data ...byte) qaStep {
	return qaStep{resp: append(append([]byte(nil), data...), hi, lo)}
}
func qaWord(w int, data ...byte) qaStep { return qaSW(byte(w>>8), byte(w), data...) }

func (q *qaTransport) PowerOn(time.Duration) ([]byte, error) { q.power++; return nil, q.powerErr }
func (q *qaTransport) PowerOff(time.Duration) error          { q.power++; return q.powerErr }
func (q *qaTransport) ExtendedAPDU() bool                    { return q.ext }
func (q *qaTransport) Close() error                          { q.closed++; return q.closeErr }

func (q *qaTransport) Transmit(command []byte, budget time.Duration) ([]byte, error) {
	q.mu.Lock()
	q.sent = append(q.sent, append([]byte(nil), command...))
	q.refs = append(q.refs, command)
	q.budgets = append(q.budgets, budget)
	if len(q.script) == 0 {
		q.mu.Unlock()
		return nil, errors.New("qa: script exhausted")
	}
	s := q.script[0]
	q.script = q.script[1:]
	q.mu.Unlock()
	if s.panicVal != nil {
		panic(s.panicVal)
	}
	if s.err != nil {
		return nil, s.err
	}
	out := append([]byte(nil), s.resp...)
	q.mu.Lock()
	q.given = append(q.given, out)
	q.mu.Unlock()
	return out, nil
}

func (q *qaTransport) calls() int { return len(q.sent) }

// qaSession returns a session on q that has the application selected, as it is after the piece that
// opens a card; qaUnselected is one that has not. table replaces the allowlist when it is not nil.
func qaSession(t testing.TB, q *qaTransport, o Options, table []commandSpec) *Session {
	t.Helper()
	s := qaUnselected(t, q, o, table)
	s.selected = true
	return s
}

func qaUnselected(t testing.TB, q *qaTransport, o Options, table []commandSpec) *Session {
	t.Helper()
	s, err := NewSession(q, o)
	if err != nil {
		t.Fatal(err)
	}
	if table != nil {
		s.table = table
	}
	return s
}

// qaTable is a table of rows that take any amount of data, for the tests of chaining and of the extended
// form, which no row of the real table needs; its rows are named put-qa (secret or not, changing or
// not) and get-response.
func qaTable(secret, changes bool) []commandSpec {
	return []commandSpec{
		{name: "put-qa", cla: 0x00, ins: 0xDA, params: []uint16{0x0100}, data: lengths(0, 70000), changes: changes, secret: secret, mayWait: true},
		{name: "get-response", cla: 0x00, ins: 0xC0, params: []uint16{0x0000}, data: noData(), readOnly: true, internal: true},
	}
}

func qaPut(n, le int) apdu.Command {
	d := make([]byte, n)
	for i := range d {
		d[i] = byte(i*5 + 1)
	}
	return apdu.Command{INS: 0xDA, P1: 0x01, Data: d, Le: le}
}

func qaZero(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

func qaAllZero(t testing.TB, what string, refs [][]byte) {
	t.Helper()
	for i, r := range refs {
		if !qaZero(r) {
			t.Errorf("%s: buffer %d was not overwritten: %x", what, i, r)
		}
	}
}

func qaHexOf(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// qaForms are the ways that the bytes of a PIN could show in a text.
func qaForms(pin []byte) map[string]string {
	h := hex.EncodeToString(pin)
	var dec []string
	for _, b := range pin {
		dec = append(dec, strconv.Itoa(int(b)))
	}
	f := map[string]string{
		"raw": string(pin), "hex": h, "HEX": strings.ToUpper(h),
		"decimal": strings.Join(dec, " "), "decimal commas": strings.Join(dec, ","), "decimal squashed": strings.Join(dec, ""),
		"base64": base64.StdEncoding.EncodeToString(pin), "base64 raw": base64.RawStdEncoding.EncodeToString(pin),
		"base64 url": base64.URLEncoding.EncodeToString(pin), "base64 raw url": base64.RawURLEncoding.EncodeToString(pin),
	}
	for i := 0; i+4 <= len(pin); i++ {
		f["raw window "+strconv.Itoa(i)] = string(pin[i : i+4])
	}
	return f
}

func qaNoPIN(t testing.TB, what string, pin []byte, text string) {
	t.Helper()
	for name, f := range qaForms(pin) {
		if f != "" && strings.Contains(text, f) {
			t.Errorf("%s: the text shows the PIN as %s: %q", what, name, text)
			return
		}
	}
}
