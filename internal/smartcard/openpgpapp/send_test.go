package openpgpapp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

func TestSendShort(t *testing.T) {
	f := &fakeTransport{script: []step{ok(0xAA, 0xBB, 0xCC)}}
	s := newSession(t, f, Options{})
	got, err := s.send(getData(0x7F66, 256))
	if err != nil || !bytes.Equal(got, []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("%v %x", err, got)
	}
	if hex.EncodeToString(f.sent[0]) != "00ca7f6600" {
		t.Fatalf("sent %x", f.sent[0])
	}
	if f.budgets[0] != DefaultBudget {
		t.Fatalf("budget %v", f.budgets[0])
	}
	if !zeros(f.given[0]) {
		t.Fatalf("the response buffer was not overwritten: %x", f.given[0])
	}
	// A returned slice is a copy that the caller owns.
	got[0] = 0
	if s.Dead() {
		t.Fatal("dead")
	}
}

func TestSendBudgets(t *testing.T) {
	f := &fakeTransport{script: []step{ok(), ok(), sw(0x61, 0x02, 0x01), ok(0x02)}}
	s := newSession(t, f, Options{Budget: 2 * time.Second, WaitBudget: 40 * time.Second})
	digest := bytes.Repeat([]byte{7}, 48)
	if _, err := s.send(apdu.Command{INS: 0x2A, P1: 0x9E, P2: 0x9A, Data: digest, Le: 256}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.send(getData(0x004F, 256)); err != nil {
		t.Fatal(err)
	}
	// A continuation of an ordinary command is ordinary.
	if _, err := s.send(getData(0x006E, 256)); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{40 * time.Second, 2 * time.Second, 2 * time.Second, 2 * time.Second}
	for i, w := range want {
		if f.budgets[i] != w {
			t.Errorf("budget %d: %v, want %v", i, f.budgets[i], w)
		}
	}
}

func TestOptions(t *testing.T) {
	if _, err := NewSession(nil, Options{}); !errors.Is(err, ErrNoTransport) {
		t.Errorf("nil: %v", err)
	}
	for _, o := range []Options{{Budget: -1}, {WaitBudget: -1}, {Budget: MaxBudget + 1}, {WaitBudget: MaxBudget + 1}} {
		if _, err := NewSession(&fakeTransport{}, o); !errors.Is(err, ErrBadOptions) {
			t.Errorf("%+v: %v", o, err)
		}
	}
	s, err := NewSession(&fakeTransport{}, Options{Budget: MaxBudget, WaitBudget: MaxBudget, ReadOnly: true})
	if err != nil || !s.ReadOnly() {
		t.Errorf("limit: %v", err)
	}
}

func TestContinuation(t *testing.T) {
	f := &fakeTransport{script: []step{sw(0x61, 0x03, 0xAA, 0xBB), sw(0x61, 0x00, 0xCC, 0xDD, 0xEE), ok(0x01)}}
	s := newSession(t, f, Options{})
	got, err := s.send(getData(0x7F21, 256))
	if err != nil || !bytes.Equal(got, []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}) {
		t.Fatalf("%v %x", err, got)
	}
	// GET RESPONSE carries the count that the card announced; 00 stands for 256.
	if hex.EncodeToString(f.sent[1]) != "00c0000003" || hex.EncodeToString(f.sent[2]) != "00c0000000" {
		t.Fatalf("sent %x", f.sent[1:])
	}
	for i, g := range f.given {
		if !zeros(g) {
			t.Errorf("response %d not overwritten", i)
		}
	}
}

func TestContinuationCaps(t *testing.T) {
	// The size cap, in one answer.
	big := make([]byte, MaxResponse+1)
	f := &fakeTransport{script: []step{ok(big...)}}
	s := newSession(t, f, Options{})
	_, err := s.send(getData(0x7F21, 256))
	var lost *LostError
	if !errors.As(err, &lost) || !errors.Is(err, ErrResponseTooLong) || !errors.Is(err, ErrSessionDead) || lost.OutcomeUnknown || !s.Dead() {
		t.Fatalf("one big answer: %v", err)
	}
	// The size cap, over several.
	chunk := bytes.Repeat([]byte{1}, 255)
	f = &fakeTransport{}
	for range 17 {
		f.script = append(f.script, sw(0x61, 0xFF, chunk...))
	}
	s = newSession(t, f, Options{})
	if _, err = s.send(getData(0x7F21, 256)); !errors.Is(err, ErrResponseTooLong) || !s.Dead() {
		t.Fatalf("many answers: %v", err)
	}
	for i, g := range f.given {
		if !zeros(g) {
			t.Errorf("response %d not overwritten", i)
		}
	}
	// The count of rounds, for a card that announces data and sends none.
	f = &fakeTransport{}
	for range maxContinuations + 5 {
		f.script = append(f.script, sw(0x61, 0x05))
	}
	s = newSession(t, f, Options{})
	if _, err = s.send(getData(0x7F21, 256)); !errors.Is(err, ErrResponseTooLong) || !s.Dead() {
		t.Fatalf("empty rounds: %v", err)
	}
	if f.calls() != maxContinuations+1 {
		t.Fatalf("%d calls", f.calls())
	}
	// At the cap exactly, an answer is whole.
	f = &fakeTransport{ext: true, script: []step{ok(make([]byte, MaxResponse)...)}}
	se := newSession(t, f, Options{})
	se.allowExtended(2000)
	if got, err := se.send(getData(0x7F21, 65536)); err != nil || len(got) != MaxResponse {
		t.Fatalf("at the cap: %v", err)
	}
}

func TestStatusErrorsAreFinalAndNeverRetried(t *testing.T) {
	for _, w := range []uint16{0x6A88, 0x6982, 0x6983, 0x6700, 0x6C20, 0x6285, 0x6600, 0x63C2, 0x6D00} {
		f := &fakeTransport{script: []step{sw(byte(w>>8), byte(w), 0xDE, 0xAD), ok(0x01)}}
		s := newSession(t, f, Options{})
		got, err := s.send(getData(0x00D6, 256))
		var se *StatusError
		if !errors.As(err, &se) || se.Op != "get-data" || se.SW != w || got != nil {
			t.Fatalf("%04X: %v %x", w, err, got)
		}
		if f.calls() != 1 {
			t.Fatalf("%04X: %d calls: a command was retried or followed", w, f.calls())
		}
		if s.Dead() {
			t.Fatalf("%04X: a status word kills the session", w)
		}
		if !zeros(f.given[0]) {
			t.Fatalf("%04X: response not overwritten", w)
		}
		// The text has the operation and the word, and no command byte.
		if msg := se.Error(); !strings.HasPrefix(msg, "openpgpapp: get-data: the card answered "+strings.ToUpper(hex.EncodeToString([]byte{byte(w >> 8), byte(w)}))) {
			t.Fatalf("text: %q", msg)
		}
		// The session goes on.
		if g, err := s.send(getData(0x00D6, 256)); err != nil || !bytes.Equal(g, []byte{1}) {
			t.Fatalf("%04X: next: %v", w, err)
		}
	}
}

// A command whose answer began (61xx) has run; an error status to the GET RESPONSE is not its refusal.
func TestLateErrorAfterContinuationIsALostExchange(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmd     apdu.Command
		unknown bool
	}{
		{"a read", getData(0x7F21, 256), false},
		{"key generation", apdu.Command{INS: 0x47, P1: 0x80, Data: []byte{0xB6, 0x00}, Le: 256}, true},
		{"attestation", apdu.Command{CLA: 0x80, INS: 0xFB, P1: 0x01, Le: 256}, true},
	} {
		f := &fakeTransport{script: []step{sw(0x61, 0x02, 0x01), sw(0x6A, 0x88), ok()}}
		s := newSession(t, f, Options{})
		got, err := s.send(tc.cmd)
		var lost *LostError
		var se *StatusError
		if !errors.As(err, &lost) || !errors.As(err, &se) || got != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if lost.Op != "get-response" || se.Op != "get-response" || se.SW != 0x6A88 || lost.OutcomeUnknown != tc.unknown || !s.Dead() || !errors.Is(err, ErrSessionDead) {
			t.Fatalf("%s: %+v %+v dead %v", tc.name, lost, se, s.Dead())
		}
		if !zeros(f.given[0]) || !zeros(f.given[1]) {
			t.Fatalf("%s: not overwritten", tc.name)
		}
		if _, err := s.send(getData(0x004F, 256)); !errors.Is(err, ErrSessionDead) || f.calls() != 2 {
			t.Fatalf("%s: later call: %v", tc.name, err)
		}
	}
}

func TestLostSession(t *testing.T) {
	boom := errors.New("reader unplugged")
	for _, tc := range []struct {
		name    string
		cmd     apdu.Command
		unknown bool
	}{
		{"a read", getData(0x004F, 256), false},
		{"a verification", verifyCmd([]byte("123456")), true},
		{"a put", apdu.Command{INS: 0xDA, P2: 0xC4, Data: []byte{1}}, true},
		{"a signature", apdu.Command{INS: 0x2A, P1: 0x9E, P2: 0x9A, Data: make([]byte, 48)}, true},
		{"an authentication", apdu.Command{INS: 0x88, Data: make([]byte, 48), Le: 256}, false},
	} {
		f := &fakeTransport{script: []step{{err: boom}}}
		s := newSession(t, f, Options{})
		_, err := s.send(tc.cmd)
		var lost *LostError
		if !errors.As(err, &lost) || lost.OutcomeUnknown != tc.unknown || !errors.Is(err, boom) || !errors.Is(err, ErrSessionDead) {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !s.Dead() {
			t.Fatalf("%s: not dead", tc.name)
		}
		// Later calls name one error and touch nothing.
		for range 3 {
			if _, err := s.send(getData(0x004F, 256)); !errors.Is(err, ErrSessionDead) {
				t.Fatalf("%s: later call: %v", tc.name, err)
			}
		}
		if f.calls() != 1 {
			t.Fatalf("%s: the transport was touched after the failure: %d", tc.name, f.calls())
		}
		// A refused command is still a refusal, and the reader is given back by Close.
		if err := s.Close(); err != nil || f.closed != 1 {
			t.Fatalf("%s: close: %v %d", tc.name, err, f.closed)
		}
		if err := s.Close(); err != nil || f.closed != 1 {
			t.Fatalf("%s: second close: %v %d", tc.name, err, f.closed)
		}
		if _, err := s.send(getData(0x004F, 256)); !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("%s: after close: %v", tc.name, err)
		}
	}
}

func TestLostDuringContinuationOfAWrite(t *testing.T) {
	// The attestation answers with 61xx for its later reads in practice; the command itself had taken
	// effect when the exchange failed, so the loss says the outcome is unknown.
	f := &fakeTransport{script: []step{sw(0x61, 0x02, 0x01), {err: errors.New("gone")}}}
	s := newSession(t, f, Options{})
	_, err := s.send(apdu.Command{CLA: 0x80, INS: 0xFB, P1: 0x01, Le: 256})
	var lost *LostError
	if !errors.As(err, &lost) || !lost.OutcomeUnknown || lost.Op != "generate-attestation" {
		t.Fatalf("%v", err)
	}
	if !zeros(f.given[0]) {
		t.Fatal("not overwritten")
	}
}

func TestMalformedResponseKillsTheSession(t *testing.T) {
	for _, resp := range [][]byte{nil, {0x90}} {
		f := &fakeTransport{script: []step{{resp: resp}}}
		s := newSession(t, f, Options{})
		_, err := s.send(getData(0x004F, 256))
		if !errors.Is(err, ErrMalformedResponse) || !errors.Is(err, ErrSessionDead) || !s.Dead() {
			t.Fatalf("%x: %v", resp, err)
		}
	}
}

func TestSecretCommandIsOverwritten(t *testing.T) {
	pin := []byte("987654")
	f := &fakeTransport{script: []step{ok()}}
	s := newSession(t, f, Options{})
	if _, err := s.send(verifyCmd(pin)); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(f.sent[0]) != "00200081"+"06"+hex.EncodeToString(pin) {
		t.Fatalf("sent %x", f.sent[0])
	}
	if !zeros(f.sentRefs[0]) {
		t.Fatalf("the command buffer was not overwritten: %x", f.sentRefs[0])
	}
	if string(pin) != "987654" {
		t.Fatal("the caller's own bytes were changed")
	}
	// The same on a transport error and on a status word.
	for _, st := range []step{{err: errors.New("gone")}, sw(0x69, 0x82)} {
		f = &fakeTransport{script: []step{st}}
		s = newSession(t, f, Options{})
		_, err := s.send(verifyCmd(pin))
		if err == nil || !zeros(f.sentRefs[0]) {
			t.Fatalf("%v", err)
		}
		// No error text shows the PIN, in text or in hex.
		for _, form := range []string{string(pin), hex.EncodeToString(pin), strings.ToUpper(hex.EncodeToString(pin))} {
			if strings.Contains(err.Error(), form) {
				t.Fatalf("the error shows the PIN: %q", err)
			}
		}
	}
}

func TestReadOnly(t *testing.T) {
	f := &fakeTransport{script: []step{ok(0x01), ok(), ok()}}
	s := newSession(t, f, Options{ReadOnly: true})
	for _, c := range []apdu.Command{
		verifyCmd([]byte("123456")),
		{INS: 0x20, P1: 0xFF, P2: 0x81},
		{INS: 0xDA, P2: 0xC4, Data: []byte{1}},
		{INS: 0x47, P1: 0x80, Data: []byte{0xB6, 0x00}, Le: 256},
		{INS: 0x2A, P1: 0x9E, P2: 0x9A, Data: make([]byte, 48)},
		{INS: 0x88, Data: make([]byte, 48)},
		{CLA: 0x80, INS: 0xFB, P1: 0x01},
	} {
		_, err := s.send(c)
		if !errors.Is(err, ErrReadOnly) || errors.Is(err, ErrNotAllowed) || s.Dead() {
			t.Fatalf("%x: %v", c.INS, err)
		}
	}
	if f.calls() != 0 {
		t.Fatalf("a refused command reached the transport")
	}
	if _, err := s.send(getData(0x004F, 256)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.send(apdu.Command{INS: 0xA4, P1: 0x04, Data: []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}, Le: 256}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.send(apdu.Command{INS: 0x47, P1: 0x81, Data: []byte{0xB6, 0x00}, Le: 256}); err != nil {
		t.Fatal(err)
	}
	// The text names the operation, not a byte.
	_, err := s.send(verifyCmd([]byte("123456")))
	if !strings.Contains(err.Error(), "verify") || strings.Contains(err.Error(), "123456") {
		t.Fatalf("%q", err)
	}
}

func TestNothingIsSentForARefusal(t *testing.T) {
	f := &fakeTransport{}
	s := newSession(t, f, Options{})
	for _, c := range []apdu.Command{
		{INS: 0xE6}, {INS: 0x44}, {INS: 0xC0}, // terminate, activate, and GET RESPONSE asked for by a caller
		getData(0x00C5, 256), getData(0x00CD, 256),
	} {
		if _, err := s.send(c); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("%x: %v", c.INS, err)
		}
	}
	// Data that cannot be encoded is a fault before anything is sent, and the session lives.
	s.table = []commandSpec{{name: "wide", cla: 0, ins: 0xDA, params: []uint16{0x00C4}, data: lengths(0, 70000)}}
	if _, err := s.send(apdu.Command{INS: 0xDA, P2: 0xC4, Data: make([]byte, 65536)}); !errors.Is(err, apdu.ErrDataTooLong) {
		t.Fatal(err)
	}
	if f.calls() != 0 || s.Dead() {
		t.Fatalf("calls %d dead %v", f.calls(), s.Dead())
	}
}

// putTable is a table with one row that takes any amount of data, for the tests of chaining and of the
// extended form, which no command of the real table needs yet.
func putTable(secret bool) []commandSpec {
	return []commandSpec{
		{name: "put-big", cla: 0x00, ins: 0xDA, params: []uint16{0x0100}, data: lengths(0, 70000), changes: true, secret: secret, mayWait: true},
		{name: "get-response", cla: 0x00, ins: 0xC0, params: []uint16{0x0000}, data: noData(), readOnly: true, internal: true},
	}
}

func bigPut(n, le int) apdu.Command {
	d := make([]byte, n)
	for i := range d {
		d[i] = byte(i)
	}
	return apdu.Command{INS: 0xDA, P1: 0x01, Data: d, Le: le}
}

func TestChaining(t *testing.T) {
	f := &fakeTransport{script: []step{ok(), ok(), ok(0xAB)}}
	s := newSession(t, f, Options{})
	s.table = putTable(true)
	cmd := bigPut(600, 256)
	got, err := s.send(cmd)
	if err != nil || !bytes.Equal(got, []byte{0xAB}) {
		t.Fatalf("%v %x", err, got)
	}
	if f.calls() != 3 {
		t.Fatalf("%d blocks", f.calls())
	}
	var joined []byte
	for i, b := range f.sent {
		last := i == 2
		cla := b[0]
		if (cla == 0x10) == last || (cla != 0x10 && cla != 0x00) {
			t.Errorf("block %d: class %02x", i, cla)
		}
		if b[1] != 0xDA || b[2] != 0x01 || b[3] != 0x00 {
			t.Errorf("block %d: header %x", i, b[:4])
		}
		n := int(b[4])
		joined = append(joined, b[5:5+n]...)
		switch {
		case !last && (n != 255 || len(b) != 5+255):
			t.Errorf("block %d: %d bytes, %d long (an intermediate block has no Le)", i, n, len(b))
		case last && (n != 90 || len(b) != 5+90+1 || b[len(b)-1] != 0x00):
			t.Errorf("last block: %d bytes, %x", n, b[len(b)-1])
		}
	}
	if !bytes.Equal(joined, cmd.Data) {
		t.Fatal("the blocks do not join to the data")
	}
	for i, r := range f.sentRefs {
		if !zeros(r) {
			t.Errorf("block %d not overwritten", i)
		}
	}
	if f.budgets[0] != DefaultBudget || f.budgets[2] != DefaultWaitBudget {
		t.Errorf("budgets %v", f.budgets)
	}
	// Exactly 255 and exactly 256 bytes.
	f = &fakeTransport{script: []step{ok()}}
	s = newSession(t, f, Options{})
	s.table = putTable(false)
	if _, err := s.send(bigPut(255, 0)); err != nil || f.calls() != 1 || f.sent[0][0] != 0 {
		t.Fatalf("255: %v %d", err, f.calls())
	}
	f = &fakeTransport{script: []step{ok(), ok()}}
	s = newSession(t, f, Options{})
	s.table = putTable(false)
	if _, err := s.send(bigPut(256, 0)); err != nil || f.calls() != 2 || len(f.sent[1]) != 5+1 {
		t.Fatalf("256: %v %d", err, f.calls())
	}
}

func TestChainRefusedInTheMiddleLosesTheSession(t *testing.T) {
	for _, st := range []step{sw(0x68, 0x83), sw(0x61, 0x02, 0x01), sw(0x90, 0x01)} {
		f := &fakeTransport{script: []step{ok(), st, ok()}}
		s := newSession(t, f, Options{})
		s.table = putTable(false)
		_, err := s.send(bigPut(700, 0))
		var se *StatusError
		var lost *LostError
		if !errors.As(err, &se) || !errors.As(err, &lost) || se.Op != "put-big" || !lost.OutcomeUnknown || f.calls() != 2 || !s.Dead() {
			t.Fatalf("%v, %d calls", err, f.calls())
		}
	}
	// A lost exchange in the middle of a chain: dead, outcome unknown.
	f := &fakeTransport{script: []step{ok(), {err: errors.New("gone")}}}
	s := newSession(t, f, Options{})
	s.table = putTable(false)
	_, err := s.send(bigPut(700, 0))
	var lost *LostError
	if !errors.As(err, &lost) || !lost.OutcomeUnknown || !s.Dead() {
		t.Fatalf("%v", err)
	}
	// A chain beyond what any form carries is refused before anything is sent.
	f = &fakeTransport{}
	s = newSession(t, f, Options{})
	s.table = putTable(false)
	if _, err := s.send(bigPut(65536, 0)); !errors.Is(err, apdu.ErrDataTooLong) || f.calls() != 0 {
		t.Fatalf("%v", err)
	}
}

func TestExtendedForm(t *testing.T) {
	// Both the transport and the card must take it.
	cases := []struct {
		name         string
		transportExt bool
		cardMax      int // 0: not told
		n, le        int
		blocks       int
		extended     bool
	}{
		{"both take it", true, 3000, 600, 256, 1, true},
		{"transport does not", false, 3000, 600, 256, 3, false},
		{"card not told", true, 0, 600, 256, 3, false},
		{"too big for the card", true, 400, 600, 256, 3, false},
		{"fits the card exactly", true, 609, 600, 256, 1, true},
		{"short data, long Le", true, 3000, 10, 3000, 1, true},
		{"short data, long Le, not allowed", false, 3000, 10, 3000, 1, false},
		{"short data, short Le stays short", true, 3000, 10, 256, 1, false},
	}
	for _, tc := range cases {
		f := &fakeTransport{ext: tc.transportExt, script: []step{ok(), ok(), ok()}}
		s := newSession(t, f, Options{})
		s.table = putTable(false)
		if tc.cardMax > 0 {
			s.allowExtended(tc.cardMax)
		}
		if _, err := s.send(bigPut(tc.n, tc.le)); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if f.calls() != tc.blocks {
			t.Errorf("%s: %d commands, want %d", tc.name, f.calls(), tc.blocks)
		}
		first := f.sent[0]
		isExt := tc.n > 0 && first[4] == 0x00 && len(first) >= 7 && int(first[5])<<8|int(first[6]) == tc.n
		if tc.n == 0 {
			isExt = len(first) == 7
		}
		if tc.n == 10 {
			isExt = first[4] == 0x00 && len(first) == 4+3+10+2
		}
		if isExt != tc.extended {
			t.Errorf("%s: extended %v, want %v: %x", tc.name, isExt, tc.extended, first[:min(len(first), 8)])
		}
		if tc.extended {
			tail := first[len(first)-2:]
			if tc.le == 3000 && !bytes.Equal(tail, []byte{0x0B, 0xB8}) {
				t.Errorf("%s: Le %x", tc.name, tail)
			}
		}
	}
	// Without the extended form, an Le above 256 asks for 256 (the card continues with 61xx).
	f := &fakeTransport{script: []step{ok()}}
	s := newSession(t, f, Options{})
	if _, err := s.send(getData(0x7F21, 65536)); err != nil || hex.EncodeToString(f.sent[0]) != "00ca7f2100" {
		t.Fatalf("%v %x", err, f.sent[0])
	}
	// With it, 65536 is the two bytes 0000 after the zero byte.
	f = &fakeTransport{ext: true, script: []step{ok()}}
	s = newSession(t, f, Options{})
	s.allowExtended(2000)
	if _, err := s.send(getData(0x7F21, 65536)); err != nil || hex.EncodeToString(f.sent[0]) != "00ca7f21"+"000000" {
		t.Fatalf("%v %x", err, f.sent[0])
	}
}

func TestSessionClosed(t *testing.T) {
	f := &fakeTransport{}
	s := newSession(t, f, Options{})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.send(getData(0x004F, 256)); !errors.Is(err, ErrSessionClosed) || f.calls() != 0 {
		t.Fatal(err)
	}
}

// A panic of the transport: the command is still overwritten, the session is dead, the panic goes on.
func TestPanicOfTheTransport(t *testing.T) {
	for _, chain := range []bool{false, true} {
		f := &panicTransport{fakeTransport: fakeTransport{script: []step{ok()}}, after: 0}
		cmd := verifyCmd([]byte("987654"))
		s := newSession(t, &f.fakeTransport, Options{})
		s.t = f
		if chain {
			f.after = 1
			s.table = putTable(true)
			cmd = bigPut(600, 0)
		}
		func() {
			defer func() {
				if r := recover(); r != "boom" {
					t.Fatalf("chain %v: the panic did not go on: %v", chain, r)
				}
			}()
			_, _ = s.send(cmd)
		}()
		if !s.Dead() || s.selected {
			t.Fatalf("chain %v: not dead", chain)
		}
		for i, r := range f.sentRefs {
			if !zeros(r) {
				t.Fatalf("chain %v: command %d not overwritten", chain, i)
			}
		}
		if _, err := s.send(getData(0x004F, 256)); !errors.Is(err, ErrSessionDead) {
			t.Fatalf("chain %v: %v", chain, err)
		}
	}
}

// panicTransport panics on the call after `after` calls have returned.
type panicTransport struct {
	fakeTransport
	after int
}

func (p *panicTransport) Transmit(c []byte, b time.Duration) ([]byte, error) {
	if p.calls() >= p.after {
		p.sent = append(p.sent, append([]byte(nil), c...))
		p.sentRefs = append(p.sentRefs, c)
		panic("boom")
	}
	return p.fakeTransport.Transmit(c, b)
}

func TestLostErrorShowsNoCauseForASecret(t *testing.T) {
	cause := errors.New("reader said: 987654 3938373635")
	f := &fakeTransport{script: []step{{err: cause}}}
	s := newSession(t, f, Options{})
	_, err := s.send(verifyCmd([]byte("987654")))
	if err == nil || strings.Contains(err.Error(), "987654") || strings.Contains(err.Error(), "reader") {
		t.Fatalf("%v", err)
	}
	if !errors.Is(err, cause) || !errors.Is(err, ErrSessionDead) {
		t.Fatalf("the cause is not reachable: %v", err)
	}
	// A command with no secret keeps the cause in its text.
	f = &fakeTransport{script: []step{{err: cause}}}
	_, err = newSession(t, f, Options{}).send(getData(0x004F, 256))
	if err == nil || !strings.Contains(err.Error(), "reader said") {
		t.Fatalf("%v", err)
	}
	// And so for the status of a continuation of a secret command.
	f = &fakeTransport{script: []step{sw(0x61, 0x02, 0x01), sw(0x6A, 0x88)}}
	_, err = newSession(t, f, Options{}).send(verifyCmd([]byte("987654")))
	if err == nil || strings.Contains(err.Error(), "6A88") {
		t.Fatalf("%v", err)
	}
}

func TestNotSelected(t *testing.T) {
	aid := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	selectCmd := apdu.Command{INS: 0xA4, P1: 0x04, Data: aid, Le: 256}
	f := &fakeTransport{script: []step{sw(0x6A, 0x82), ok(), ok(0x01), sw(0x6A, 0x82), sw(0x61, 0x01, 0x07), ok(0x08), ok(0x01)}}
	s := newUnselected(t, f, Options{})
	// Nothing but the selection is sent before it.
	for _, c := range []apdu.Command{getData(0x004F, 256), verifyCmd([]byte("123456")), {INS: 0xF1, Le: 256}} {
		if _, err := s.send(c); !errors.Is(err, ErrNotSelected) || s.Dead() {
			t.Fatalf("%v", err)
		}
	}
	if f.calls() != 0 {
		t.Fatal("a command was sent before the selection")
	}
	// A failed selection leaves it unselected.
	var se *StatusError
	if _, err := s.send(selectCmd); !errors.As(err, &se) || se.Op != "select-application" {
		t.Fatalf("%v", err)
	}
	if _, err := s.send(getData(0x004F, 256)); !errors.Is(err, ErrNotSelected) {
		t.Fatalf("after a failed selection: %v", err)
	}
	// A good one opens the session; a later failed selection closes it again.
	if _, err := s.send(selectCmd); err != nil {
		t.Fatal(err)
	}
	if _, err := s.send(getData(0x004F, 256)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.send(selectCmd); err == nil {
		t.Fatal("the failed selection passed")
	}
	if _, err := s.send(getData(0x004F, 256)); !errors.Is(err, ErrNotSelected) {
		t.Fatalf("after a second, failed selection: %v", err)
	}
	// A selection that answers in two parts is a selection when it ends in success.
	if _, err := s.send(selectCmd); err != nil {
		t.Fatal(err)
	}
	if _, err := s.send(getData(0x004F, 256)); err != nil {
		t.Fatal(err)
	}
	// A dead session is not selected.
	f.script = []step{{err: errors.New("gone")}}
	_, _ = s.send(getData(0x004F, 256))
	if s.selected || !s.Dead() {
		t.Fatal("a dead session is selected")
	}
}

func TestResponseLargerThanTheFormIsLost(t *testing.T) {
	f := &fakeTransport{script: []step{ok(make([]byte, 300)...)}}
	s := newSession(t, f, Options{})
	_, err := s.send(getData(0x7F21, 256))
	if !errors.Is(err, ErrResponseTooLong) || !s.Dead() || !zeros(f.given[0]) {
		t.Fatalf("%v", err)
	}
	// 256 bytes of data and the status word is the most that a short answer holds.
	f = &fakeTransport{script: []step{ok(make([]byte, 256)...)}}
	if got, err := newSession(t, f, Options{}).send(getData(0x7F21, 256)); err != nil || len(got) != 256 {
		t.Fatalf("%v", err)
	}
}
