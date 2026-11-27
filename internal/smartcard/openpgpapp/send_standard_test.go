package openpgpapp

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

// qaGetData is a read of one tag, with Le 256.
func qaGetData(tag uint16) apdu.Command {
	return apdu.Command{INS: 0xCA, P1: byte(tag >> 8), P2: byte(tag), Le: 256}
}

func qaVerify(pin []byte) apdu.Command { return apdu.Command{INS: 0x20, P2: 0x81, Data: pin} }

var (
	qaGenerate = apdu.Command{INS: 0x47, P1: 0x80, Data: []byte{0xB6, 0x00}, Le: 256}
	qaPWStatus = apdu.Command{INS: 0xDA, P2: 0xC4, Data: []byte{0x01}}
)

// qaChainBlocks writes by hand the blocks on the wire of a command of the table qaTable (INS DA, P1 01,
// P2 00): the class 10 on every block but the last, at most 255 data bytes in each, the byte Le (00 for
// 256) on the last block only.
func qaChainBlocks(data []byte, le int, sizes []int) [][]byte {
	var out [][]byte
	off := 0
	for i, n := range sizes {
		cla := byte(0x10)
		if i == len(sizes)-1 {
			cla = 0x00
		}
		b := append([]byte{cla, 0xDA, 0x01, 0x00, byte(n)}, data[off:off+n]...)
		if i == len(sizes)-1 && le > 0 {
			b = append(b, byte(le%256))
		}
		out = append(out, b)
		off += n
	}
	return out
}

func TestChainBlocksOnTheWire(t *testing.T) {
	for _, tc := range []struct {
		n     int
		sizes []int
	}{
		{255, []int{255}},
		{256, []int{255, 1}},
		{510, []int{255, 255}},
		{511, []int{255, 255, 1}},
		{1000, []int{255, 255, 255, 235}},
	} {
		for _, le := range []int{0, 256} {
			for _, secret := range []bool{false, true} {
				cmd := qaPut(tc.n, le)
				orig := bytes.Clone(cmd.Data)
				script := make([]qaStep, len(tc.sizes))
				for i := range script {
					script[i] = qaOK(0xEE) // the data of an intermediate answer is dropped
				}
				script[len(script)-1] = qaOK(0xAB)
				q := &qaTransport{script: script}
				s := qaSession(t, q, Options{Budget: 2 * time.Second, WaitBudget: 40 * time.Second}, qaTable(secret, true))
				got, err := s.send(cmd)
				name := fmt.Sprintf("%d bytes, Le %d, secret %v", tc.n, le, secret)
				if err != nil || !bytes.Equal(got, []byte{0xAB}) {
					t.Errorf("%s: %v %x", name, err, got)
					continue
				}
				want := qaChainBlocks(orig, le, tc.sizes)
				if q.calls() != len(want) {
					t.Errorf("%s: %d blocks, want %d", name, q.calls(), len(want))
					continue
				}
				for i := range want {
					if !bytes.Equal(q.sent[i], want[i]) {
						t.Errorf("%s: block %d on the wire\n %x\nwant\n %x", name, i, q.sent[i], want[i])
					}
					// The intermediate blocks have the shorter budget, the last the longer.
					wantBudget := 2 * time.Second
					if i == len(want)-1 {
						wantBudget = 40 * time.Second
					}
					if q.budgets[i] != wantBudget {
						t.Errorf("%s: block %d has the budget %v", name, i, q.budgets[i])
					}
				}
				if secret {
					qaAllZero(t, name, q.refs)
				}
				qaAllZero(t, name+": answers", q.given)
				// The data of the caller is the caller's, whatever the row holds.
				if !bytes.Equal(cmd.Data, orig) {
					t.Errorf("%s: send changed the data of the command", name)
				}
				if s.Dead() {
					t.Errorf("%s: dead", name)
				}
			}
		}
	}
}

func TestChainMoreDataAfterTheLastBlock(t *testing.T) {
	q := &qaTransport{script: []qaStep{qaOK(), qaSW(0x61, 0x03, 0xAA), qaOK(0xBB, 0xCC, 0xDD)}}
	s := qaSession(t, q, Options{}, qaTable(false, true))
	got, err := s.send(qaPut(300, 256))
	if err != nil || !bytes.Equal(got, []byte{0xAA, 0xBB, 0xCC, 0xDD}) || q.calls() != 3 {
		t.Fatalf("%v %x %d", err, got, q.calls())
	}
	if !bytes.Equal(q.sent[2], []byte{0x00, 0xC0, 0x00, 0x00, 0x03}) {
		t.Fatalf("GET RESPONSE %x", q.sent[2])
	}
	// And an error to the GET RESPONSE after a chain loses the session: the card ran the command.
	q = &qaTransport{script: []qaStep{qaOK(), qaSW(0x61, 0x03, 0xAA), qaSW(0x6A, 0x88)}}
	s = qaSession(t, q, Options{}, qaTable(false, true))
	_, err = s.send(qaPut(300, 256))
	var lost *LostError
	if !errors.As(err, &lost) || lost.Op != "get-response" || !lost.OutcomeUnknown || !s.Dead() {
		t.Fatalf("%v", err)
	}
}

// A block of a chain that the card does not take with plain success loses the session: the card holds
// a partial chain. The rest is never sent.
func TestChainRefusedAtEveryBlock(t *testing.T) {
	words := []int{0x6883, 0x6884, 0x6A88, 0x6283, 0x6100, 0x61FF, 0x9001, 0x6C00, 0x6700, 0x6982, 0x0000, 0xFFFF, 0x6D00, 0x6E00}
	for _, changes := range []bool{true, false} {
		for _, secret := range []bool{false, true} {
			for block := range 3 { // the blocks before the last of four
				for _, w := range words {
					script := []qaStep{qaOK(), qaOK(), qaOK(), qaOK(0xAB)}
					script[block] = qaWord(w, 0x55)
					q := &qaTransport{script: script}
					s := qaSession(t, q, Options{}, qaTable(secret, changes))
					got, err := s.send(qaPut(1000, 256))
					name := fmt.Sprintf("changes %v secret %v block %d word %04X", changes, secret, block, w)
					var lost *LostError
					var se *StatusError
					if got != nil || !errors.As(err, &lost) || !errors.As(err, &se) || se.SW != uint16(w) || se.Op != "put-qa" || lost.Op != "put-qa" {
						t.Fatalf("%s: %v", name, err)
					}
					if lost.OutcomeUnknown != changes || !s.Dead() || q.calls() != block+1 || !errors.Is(err, ErrSessionDead) {
						t.Fatalf("%s: unknown %v dead %v calls %d", name, lost.OutcomeUnknown, s.Dead(), q.calls())
					}
					if reflect.TypeOf(err) == reflect.TypeFor[*StatusError]() {
						t.Fatalf("%s: a plain refusal", name)
					}
					if secret {
						qaAllZero(t, name, q.refs)
					}
					qaAllZero(t, name, q.given)
				}
			}
		}
	}
	// The last block is a refusal of the command, as for any command.
	q := &qaTransport{script: []qaStep{qaOK(), qaOK(), qaOK(), qaSW(0x6A, 0x88)}}
	s := qaSession(t, q, Options{}, qaTable(false, true))
	_, err := s.send(qaPut(1000, 256))
	var se *StatusError
	var lost *LostError
	if !errors.As(err, &se) || errors.As(err, &lost) || s.Dead() || se.SW != 0x6A88 {
		t.Fatalf("the last block: %v", err)
	}
}

// Every status word, at the first block of a chain.
func TestChainEveryWordAtTheFirstBlock(t *testing.T) {
	for w := range 0x10000 {
		if w == 0x9000 {
			continue
		}
		q := &qaTransport{script: []qaStep{qaWord(w), qaOK(), qaOK()}}
		s := qaSession(t, q, Options{}, qaTable(false, true))
		_, err := s.send(qaPut(600, 0))
		var lost *LostError
		var se *StatusError
		if !errors.As(err, &lost) || !errors.As(err, &se) || se.SW != uint16(w) || q.calls() != 1 || !s.Dead() {
			t.Fatalf("%04X: %v %d calls", w, err, q.calls())
		}
	}
}

// qaContinuation: a card that answers a command with n pieces, each announced by 61xx, the last by 9000.
func qaContinuation(pieces ...[]byte) []qaStep {
	var out []qaStep
	for i, p := range pieces {
		if i == len(pieces)-1 {
			out = append(out, qaOK(p...))
			break
		}
		next := len(pieces[i+1])
		out = append(out, qaSW(0x61, byte(next), p...))
	}
	return out
}

func TestContinuationRoundsOnTheWire(t *testing.T) {
	for _, rounds := range []int{0, 1, 2, 3, 64} {
		var pieces [][]byte
		var want []byte
		for i := 0; i <= rounds; i++ {
			p := bytes.Repeat([]byte{byte(i + 1)}, 1+i%7)
			pieces = append(pieces, p)
			want = append(want, p...)
		}
		q := &qaTransport{script: qaContinuation(pieces...)}
		s := qaSession(t, q, Options{}, nil)
		got, err := s.send(qaGetData(0x7F21))
		if err != nil || !bytes.Equal(got, want) || q.calls() != rounds+1 || s.Dead() {
			t.Fatalf("%d rounds: %v %d calls", rounds, err, q.calls())
		}
		for i := 1; i <= rounds; i++ {
			if w := []byte{0x00, 0xC0, 0x00, 0x00, byte(len(pieces[i]))}; !bytes.Equal(q.sent[i], w) {
				t.Fatalf("%d rounds: GET RESPONSE %d is %x, want %x", rounds, i, q.sent[i], w)
			}
		}
		qaAllZero(t, "answers", q.given)
	}
}

// qaWrites are a read and a write whose answers can continue.
var qaCapCommands = []struct {
	name    string
	cmd     apdu.Command
	op      string
	changes bool
}{
	{"a read", qaGetData(0x7F21), "get-data", false},
	{"key generation", qaGenerate, "generate-key", true},
}

func TestContinuationCapsForReadAndWrite(t *testing.T) {
	for _, tc := range qaCapCommands {
		// 65 rounds: the 64th GET RESPONSE still answers "more data", and a 65th is never sent.
		script := []qaStep{qaSW(0x61, 0x01, 1)}
		for range 64 {
			script = append(script, qaSW(0x61, 0x01, 1))
		}
		script = append(script, qaOK(1), qaOK(1))
		q := &qaTransport{script: script}
		s := qaSession(t, q, Options{}, nil)
		_, err := s.send(tc.cmd)
		var lost *LostError
		if !errors.As(err, &lost) || !errors.Is(err, ErrResponseTooLong) || !errors.Is(err, ErrSessionDead) || lost.OutcomeUnknown != tc.changes || lost.Op != tc.op {
			t.Fatalf("%s, 65 rounds: %v", tc.name, err)
		}
		if q.calls() != 65 || !s.Dead() {
			t.Fatalf("%s, 65 rounds: %d calls", tc.name, q.calls())
		}
		// 64 rounds, the last of them ending in success: whole.
		script = []qaStep{qaSW(0x61, 0x01, 1)}
		for range 63 {
			script = append(script, qaSW(0x61, 0x01, 1))
		}
		script = append(script, qaOK(2))
		q = &qaTransport{script: script}
		got, err := qaSession(t, q, Options{}, nil).send(tc.cmd)
		if err != nil || len(got) != 65 || q.calls() != 65 {
			t.Fatalf("%s, 64 rounds: %v %d bytes %d calls", tc.name, err, len(got), q.calls())
		}
		// Rounds that announce data and send none, 70 of them: the cap of rounds ends it.
		script = nil
		for range 70 {
			script = append(script, qaSW(0x61, 0x05))
		}
		q = &qaTransport{script: script}
		s = qaSession(t, q, Options{}, nil)
		if _, err = s.send(tc.cmd); !errors.Is(err, ErrResponseTooLong) || q.calls() != 65 || !s.Dead() {
			t.Fatalf("%s, empty rounds: %v %d calls", tc.name, err, q.calls())
		}
		// The total: 16 pieces of 256 bytes are 4096, the cap, and one byte more is over it.
		piece := bytes.Repeat([]byte{7}, 256)
		script = nil
		for range 15 {
			script = append(script, qaSW(0x61, 0x00, piece...))
		}
		script = append(script, qaOK(piece...))
		q = &qaTransport{script: script}
		got, err = qaSession(t, q, Options{}, nil).send(tc.cmd)
		if err != nil || len(got) != MaxResponse || q.calls() != 16 {
			t.Fatalf("%s, 4096 bytes: %v %d bytes %d calls", tc.name, err, len(got), q.calls())
		}
		script = nil
		for range 16 {
			script = append(script, qaSW(0x61, 0x01, piece...))
		}
		script = append(script, qaOK(9), qaOK(9))
		q = &qaTransport{script: script}
		s = qaSession(t, q, Options{}, nil)
		_, err = s.send(tc.cmd)
		if !errors.As(err, &lost) || !errors.Is(err, ErrResponseTooLong) || lost.OutcomeUnknown != tc.changes || !s.Dead() || q.calls() != 17 {
			t.Fatalf("%s, 4097 bytes: %v %d calls", tc.name, err, q.calls())
		}
		qaAllZero(t, tc.name, q.given)
		// One answer of 4097 bytes in the extended form, and of 4096.
		q = &qaTransport{ext: true, script: []qaStep{qaOK(make([]byte, MaxResponse+1)...)}}
		s = qaSession(t, q, Options{}, nil)
		s.allowExtended(5000)
		cmd := tc.cmd
		cmd.Le = 65536
		if _, err = s.send(cmd); !errors.Is(err, ErrResponseTooLong) || !s.Dead() {
			t.Fatalf("%s, one answer of 4097 bytes: %v", tc.name, err)
		}
		q = &qaTransport{ext: true, script: []qaStep{qaOK(make([]byte, MaxResponse)...)}}
		s = qaSession(t, q, Options{}, nil)
		s.allowExtended(5000)
		if got, err = s.send(cmd); err != nil || len(got) != MaxResponse {
			t.Fatalf("%s, one answer of 4096 bytes: %v", tc.name, err)
		}
	}
}

// Once an answer began with 61xx the card has run the command: any ending but success is a lost
// exchange named for GET RESPONSE, and never a refusal of the command.
func TestLateErrorIsALostExchange(t *testing.T) {
	for _, tc := range qaCapCommands {
		for later := range 3 { // the error comes to the first, the second or the third GET RESPONSE
			for _, w := range []int{0x6A88, 0x6700, 0x6982, 0x6983, 0x6C20, 0x6285, 0x6600, 0x63C2, 0x9001, 0x6D00, 0x6E00, 0x0000, 0xFFFF} {
				script := []qaStep{qaSW(0x61, 0x01, 1), qaSW(0x61, 0x01, 2), qaSW(0x61, 0x01, 3)}
				script[later] = qaWord(w, 9)
				if later == 0 {
					script = append([]qaStep{qaSW(0x61, 0x01, 1)}, script...)
					script[1] = qaWord(w, 9)
					script = script[:2]
				}
				q := &qaTransport{script: append(script, qaOK(4))}
				s := qaSession(t, q, Options{}, nil)
				got, err := s.send(tc.cmd)
				var lost *LostError
				var se *StatusError
				name := fmt.Sprintf("%s, error %04X at GET RESPONSE %d", tc.name, w, later+1)
				if got != nil || !errors.As(err, &lost) || !errors.As(err, &se) || se.SW != uint16(w) || se.Op != "get-response" || lost.Op != "get-response" {
					t.Fatalf("%s: %v", name, err)
				}
				if plain := reflect.TypeOf(err) == reflect.TypeFor[*StatusError](); plain || lost.OutcomeUnknown != tc.changes || !s.Dead() || !errors.Is(err, ErrSessionDead) {
					t.Fatalf("%s: plain %v unknown %v dead %v", name, plain, lost.OutcomeUnknown, s.Dead())
				}
				if q.calls() > later+2 {
					t.Fatalf("%s: %d calls: something was sent after the error", name, q.calls())
				}
				qaAllZero(t, name, q.given)
			}
		}
	}
	// Every status word as the answer to the first GET RESPONSE.
	for _, tc := range qaCapCommands {
		for w := range 0x10000 {
			if w == 0x9000 || w>>8 == 0x61 {
				continue
			}
			q := &qaTransport{script: []qaStep{qaSW(0x61, 0x01, 1), qaWord(w), qaOK()}}
			s := qaSession(t, q, Options{}, nil)
			_, err := s.send(tc.cmd)
			var lost *LostError
			var se *StatusError
			if !errors.As(err, &lost) || !errors.As(err, &se) || se.SW != uint16(w) || q.calls() != 2 || !s.Dead() || lost.OutcomeUnknown != tc.changes {
				t.Fatalf("%s: %04X: %v %d calls", tc.name, w, err, q.calls())
			}
		}
	}
}

// Every status word as the answer to one command: success returns the data, 61xx is followed with exactly
// one GET RESPONSE, and every other word is that command's final status, with exactly one call on the
// transport, no retry and no second reading, and a session that goes on. The words 6D00 and 6E00
// forget the selection, and no other word does.
func TestEveryStatusWordOfOneCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  apdu.Command
		op   string
	}{
		{"a read", qaGetData(0x004F), "get-data"},
		{"a verification", qaVerify([]byte("Xk9#mQ")), "verify-user"},
		{"a signature", apdu.Command{INS: 0x2A, P1: 0x9E, P2: 0x9A, Data: make([]byte, 48), Le: 256}, "compute-signature"},
	} {
		for _, ro := range []bool{false, true} {
			if ro && tc.op != "get-data" {
				continue
			}
			for w := range 0x10000 {
				script := []qaStep{qaWord(w, 0xDE, 0xAD), qaOK(0x01)}
				if w>>8 == 0x61 {
					script = []qaStep{qaWord(w, 0xDE), qaOK(0xAD), qaOK(0x01)}
				}
				q := &qaTransport{script: script}
				s := qaSession(t, q, Options{ReadOnly: ro}, nil)
				got, err := s.send(tc.cmd)
				switch {
				case w == 0x9000:
					if err != nil || !bytes.Equal(got, []byte{0xDE, 0xAD}) || q.calls() != 1 {
						t.Fatalf("%s %04X: %v %x", tc.name, w, err, got)
					}
				case w>>8 == 0x61:
					if err != nil || !bytes.Equal(got, []byte{0xDE, 0xAD}) || q.calls() != 2 {
						t.Fatalf("%s %04X: %v %x %d calls", tc.name, w, err, got, q.calls())
					}
				default:
					var se *StatusError
					var lost *LostError
					if !errors.As(err, &se) || errors.As(err, &lost) || se.SW != uint16(w) || se.Op != tc.op || got != nil || q.calls() != 1 || s.Dead() {
						t.Fatalf("%s %04X: %v %d calls", tc.name, w, err, q.calls())
					}
					if !strings.Contains(err.Error(), tc.op) || !strings.Contains(err.Error(), fmt.Sprintf("%04X", w)) {
						t.Fatalf("%s %04X: the text %q", tc.name, w, err)
					}
				}
				qaAllZero(t, fmt.Sprintf("%s %04X", tc.name, w), q.given)
				if tc.op == "verify-user" {
					qaAllZero(t, "the PIN", q.refs[:1])
				}
				// The next command: ErrNotSelected, with no call, exactly after 6D00 and 6E00.
				before := q.calls()
				_, err = s.send(qaGetData(0x004F))
				cleared := w == 0x6D00 || w == 0x6E00
				switch {
				case cleared && (!errors.Is(err, ErrNotSelected) || q.calls() != before):
					t.Fatalf("%s %04X: the selection was kept: %v", tc.name, w, err)
				case !cleared && errors.Is(err, ErrNotSelected):
					t.Fatalf("%s %04X: the selection was forgotten", tc.name, w)
				}
			}
		}
	}
}

func TestSelectionIsLostByAFailedSelectionAndRegained(t *testing.T) {
	sel := apdu.Command{INS: 0xA4, P1: 0x04, Data: qaAID, Le: 256}
	for w := range 0x10000 {
		if w == 0x9000 {
			continue
		}
		script := []qaStep{qaWord(w), qaOK(), qaOK(), qaOK()}
		if w>>8 == 0x61 {
			script = []qaStep{qaWord(w), qaOK(), qaOK(), qaOK()}
		}
		q := &qaTransport{script: script}
		s := qaUnselected(t, q, Options{}, nil)
		_, err := s.send(sel)
		if w>>8 == 0x61 { // 61xx then success: a selection in two parts
			if err != nil || !s.selected {
				t.Fatalf("%04X: %v", w, err)
			}
			continue
		}
		if err == nil || s.selected || s.Dead() {
			t.Fatalf("%04X: %v selected %v", w, err, s.selected)
		}
	}
	// A selection that fails clears one that was there.
	q := &qaTransport{script: []qaStep{qaOK(), qaSW(0x6A, 0x82), qaOK()}}
	s := qaUnselected(t, q, Options{}, nil)
	if _, err := s.send(sel); err != nil || !s.selected {
		t.Fatal(err)
	}
	if _, err := s.send(sel); err == nil || s.selected {
		t.Fatal("a failed selection kept the selection")
	}
	if _, err := s.send(qaGetData(0x004F)); !errors.Is(err, ErrNotSelected) || q.calls() != 2 {
		t.Fatalf("%v %d", err, q.calls())
	}
	if _, err := s.send(sel); err != nil || !s.selected {
		t.Fatalf("a new selection: %v", err)
	}
	// A selection whose continuation fails, and a selection that is lost, both clear it and kill the session.
	for name, script := range map[string][]qaStep{
		"late error":   {qaSW(0x61, 0x01), qaSW(0x6A, 0x82)},
		"transport":    {{err: errors.New("gone")}},
		"malformed":    {{resp: []byte{0x90}}},
		"empty answer": {{resp: []byte{}}},
	} {
		q := &qaTransport{script: script}
		s := qaUnselected(t, q, Options{}, nil)
		s.selected = true
		if _, err := s.send(sel); err == nil || s.selected || !s.Dead() {
			t.Fatalf("%s: %v selected %v dead %v", name, err, s.selected, s.Dead())
		}
	}
}

func TestPowerCycleForgetsTheSelection(t *testing.T) {
	q := &qaTransport{script: []qaStep{qaOK(), qaOK()}}
	s := qaSession(t, q, Options{}, nil)
	if _, err := s.powerOn(); err != nil || s.selected || q.power != 1 {
		t.Fatalf("power on: %v %v", err, s.selected)
	}
	if _, err := s.send(qaGetData(0x004F)); !errors.Is(err, ErrNotSelected) || q.calls() != 0 {
		t.Fatalf("after power on: %v", err)
	}
	s.selected = true
	if err := s.powerOff(); err != nil || s.selected || q.power != 2 {
		t.Fatalf("power off: %v %v", err, s.selected)
	}
	if _, err := s.send(qaGetData(0x004F)); !errors.Is(err, ErrNotSelected) || q.calls() != 0 {
		t.Fatalf("after power off: %v", err)
	}
	// A transport error ends the session.
	boom := errors.New("reader unplugged")
	for _, off := range []bool{false, true} {
		q := &qaTransport{powerErr: boom}
		s := qaSession(t, q, Options{}, nil)
		var err error
		if off {
			err = s.powerOff()
		} else {
			_, err = s.powerOn()
		}
		var lost *LostError
		if !errors.As(err, &lost) || !errors.Is(err, boom) || !errors.Is(err, ErrSessionDead) || !s.Dead() || s.selected {
			t.Fatalf("off %v: %v", off, err)
		}
		// A dead session powers nothing.
		calls := q.power
		if _, err := s.powerOn(); !errors.Is(err, ErrSessionDead) || q.power != calls {
			t.Fatalf("off %v: power on of a dead session: %v", off, err)
		}
		if err := s.powerOff(); !errors.Is(err, ErrSessionDead) || q.power != calls {
			t.Fatalf("off %v: power off of a dead session: %v", off, err)
		}
	}
	// A closed one neither.
	q = &qaTransport{}
	s = qaSession(t, q, Options{}, nil)
	_ = s.Close()
	if _, err := s.powerOn(); !errors.Is(err, ErrSessionClosed) || q.power != 0 {
		t.Fatalf("power on of a closed session: %v", err)
	}
	if err := s.powerOff(); !errors.Is(err, ErrSessionClosed) || q.power != 0 {
		t.Fatalf("power off of a closed session: %v", err)
	}
}

// qaScenario is one way to use a session, with the number of calls that it makes on a card that answers
// them all.
type qaScenario struct {
	name    string
	table   []commandSpec
	cmd     apdu.Command
	op      string
	changes bool
	secret  bool
	script  []qaStep
}

func qaScenarios() []qaScenario {
	pin := []byte("Xk9#mQ2$")
	return []qaScenario{
		{"a read", nil, qaGetData(0x7F21), "get-data", false, false, []qaStep{qaOK(1)}},
		{"a write", nil, qaPWStatus, "put-pw-status", true, false, []qaStep{qaOK()}},
		{"a verification", nil, qaVerify(pin), "verify-user", true, true, []qaStep{qaOK()}},
		{"a change of PIN", nil, apdu.Command{INS: 0x24, P2: 0x81, Data: append(bytes.Clone(pin), pin...)}, "change-user-pin", true, true, []qaStep{qaOK()}},
		{"a chain of a write", qaTable(false, true), qaPut(1000, 256), "put-qa", true, false, []qaStep{qaOK(), qaOK(), qaOK(), qaOK()}},
		{"a chain that changes nothing", qaTable(false, false), qaPut(1000, 256), "put-qa", false, false, []qaStep{qaOK(), qaOK(), qaOK(), qaOK()}},
		{"a chain with a secret", qaTable(true, true), qaPut(600, 0), "put-qa", true, true, []qaStep{qaOK(), qaOK(), qaOK()}},
		{"a continuation of a read", nil, qaGetData(0x7F21), "get-data", false, false, qaContinuation([]byte{1}, []byte{2}, []byte{3})},
		{"a continuation of a generation", nil, qaGenerate, "generate-key", true, false, qaContinuation([]byte{1}, []byte{2}, []byte{3})},
		{"a continuation of a secret command", nil, qaVerify(pin), "verify-user", true, true, qaContinuation([]byte{1}, []byte{2}, []byte{3})},
	}
}

// TestLostExchangeAtEveryCall: for every scenario and every call of it, a transport that fails at that
// call (an error, no bytes, one byte, an answer that no form can carry, or a panic) leaves the session
// dead. The call returns a LostError that says whether the card may have changed; every later call
// returns the dead error with no call on the transport; Close reaches the transport once; the encoded
// commands that held a PIN are overwritten.
func TestLostExchangeAtEveryCall(t *testing.T) {
	boom := errors.New("reader unplugged: the reader said so")
	kinds := []struct {
		name  string
		step  qaStep
		cause error
	}{
		{"an error", qaStep{err: boom}, boom},
		{"no bytes", qaStep{resp: []byte{}}, ErrMalformedResponse},
		{"one byte", qaStep{resp: []byte{0x90}}, ErrMalformedResponse},
		{"too many bytes for the form", qaStep{resp: make([]byte, 259)}, ErrResponseTooLong},
		{"a panic", qaStep{panicVal: "boom"}, nil},
	}
	for _, sc := range qaScenarios() {
		for k := range sc.script {
			for _, kind := range kinds {
				name := fmt.Sprintf("%s, %s at call %d", sc.name, kind.name, k)
				script := append([]qaStep(nil), sc.script...)
				script[k] = kind.step
				q := &qaTransport{script: script}
				s := qaSession(t, q, Options{}, sc.table)
				var err error
				var panicked any
				func() {
					defer func() { panicked = recover() }()
					_, err = s.send(sc.cmd)
				}()
				if q.calls() != k+1 || !s.Dead() || s.selected {
					t.Fatalf("%s: %d calls, dead %v, selected %v", name, q.calls(), s.Dead(), s.selected)
				}
				if sc.secret {
					// The blocks of the command hold the PIN; the GET RESPONSE after it does not.
					secretCalls := 1
					if strings.Contains(sc.name, "chain") {
						secretCalls = len(sc.script)
					}
					qaAllZero(t, name, q.refs[:min(secretCalls, len(q.refs))])
				}
				if kind.name == "a panic" {
					if panicked != "boom" || err != nil {
						t.Fatalf("%s: the panic did not go on: %v %v", name, panicked, err)
					}
				} else {
					var lost *LostError
					if panicked != nil || !errors.As(err, &lost) {
						t.Fatalf("%s: %v %v", name, err, panicked)
					}
					if lost.OutcomeUnknown != sc.changes || lost.Op != sc.op || !errors.Is(err, ErrSessionDead) || !errors.Is(err, kind.cause) {
						t.Fatalf("%s: %+v %v", name, lost, err)
					}
					text := err.Error()
					if may := strings.Contains(text, "may have carried out the command"); may != sc.changes {
						t.Fatalf("%s: the text %q says the card may have changed: %v", name, text, may)
					}
					// The cause is in the text of a command with no secret, and never in one with a secret.
					if shown := strings.Contains(text, "the reader said so") || strings.Contains(text, "malformed") || strings.Contains(text, "no status word"); kind.name == "an error" && shown == sc.secret {
						t.Fatalf("%s: the cause shown %v for secret %v: %q", name, shown, sc.secret, text)
					}
				}
				// Every later call: the dead error, no call.
				calls := q.calls()
				for _, cmd := range []apdu.Command{qaGetData(0x004F), qaPWStatus, qaVerify([]byte("Xk9#mQ")), {INS: 0xE6}, {INS: 0xA4, P1: 0x04, Data: qaAID}, {INS: 0xC0}} {
					if _, err := s.send(cmd); !errors.Is(err, ErrSessionDead) || errors.Is(err, ErrNotAllowed) || q.calls() != calls {
						t.Fatalf("%s: a later call: %v, %d calls", name, err, q.calls())
					}
				}
				if _, err := s.powerOn(); !errors.Is(err, ErrSessionDead) || q.power != 0 {
					t.Fatalf("%s: power on: %v", name, err)
				}
				// The reader is given back, once.
				if err := s.Close(); err != nil || q.closed != 1 {
					t.Fatalf("%s: close: %v %d", name, err, q.closed)
				}
				if err := s.Close(); err != nil || q.closed != 1 {
					t.Fatalf("%s: second close: %v %d", name, err, q.closed)
				}
				if _, err := s.send(qaGetData(0x004F)); !errors.Is(err, ErrSessionClosed) || q.calls() != calls {
					t.Fatalf("%s: after close: %v", name, err)
				}
			}
		}
	}
}

func TestCloseOfALiveSession(t *testing.T) {
	boom := errors.New("close failed")
	q := &qaTransport{closeErr: boom}
	s := qaSession(t, q, Options{}, nil)
	if err := s.Close(); !errors.Is(err, boom) || q.closed != 1 {
		t.Fatalf("close: %v", err)
	}
	if err := s.Close(); err != nil || q.closed != 1 {
		t.Fatalf("second close: %v %d", err, q.closed)
	}
	for _, cmd := range []apdu.Command{qaGetData(0x004F), {INS: 0xE6}, qaVerify([]byte("Xk9#mQ"))} {
		if _, err := s.send(cmd); !errors.Is(err, ErrSessionClosed) || q.calls() != 0 {
			t.Fatalf("after close: %v", err)
		}
	}
}

// A response that no form can carry is a lost exchange, judged before the answer is copied.
func TestResponseOverTheFormIsLostEverywhere(t *testing.T) {
	for _, tc := range []struct {
		name string
		ext  bool
		size int
		ok   bool
	}{
		{"short, 256 bytes and the word", false, 256, true},
		{"short, 257 bytes and the word", false, 257, false},
		{"short, 1000 bytes", false, 1000, false},
		{"extended, 4096 bytes", true, MaxResponse, true},
		{"extended, 4097 bytes", true, MaxResponse + 1, false},
		{"extended, 65537 bytes", true, 65537, false},
	} {
		for _, sc := range []struct {
			cmd     apdu.Command
			changes bool
		}{{qaGetData(0x7F21), false}, {qaGenerate, true}} {
			q := &qaTransport{ext: tc.ext, script: []qaStep{qaOK(make([]byte, tc.size)...)}}
			s := qaSession(t, q, Options{}, nil)
			cmd := sc.cmd
			if tc.ext {
				s.allowExtended(70000)
				cmd.Le = 65536
			}
			got, err := s.send(cmd)
			var lost *LostError
			switch {
			case tc.ok && (err != nil || len(got) != tc.size):
				t.Errorf("%s: %v", tc.name, err)
			case !tc.ok && (!errors.As(err, &lost) || !errors.Is(err, ErrResponseTooLong) || lost.OutcomeUnknown != sc.changes || !s.Dead() || got != nil):
				t.Errorf("%s: %v", tc.name, err)
			}
			qaAllZero(t, tc.name, q.given)
		}
	}
	// In a continuation and in a block of a chain, the same.
	q := &qaTransport{script: []qaStep{qaSW(0x61, 0x01, 1), qaOK(make([]byte, 257)...)}}
	s := qaSession(t, q, Options{}, nil)
	if _, err := s.send(qaGetData(0x7F21)); !errors.Is(err, ErrResponseTooLong) || !s.Dead() {
		t.Errorf("continuation: %v", err)
	}
	q = &qaTransport{script: []qaStep{qaOK(make([]byte, 300)...)}}
	s = qaSession(t, q, Options{}, qaTable(false, true))
	if _, err := s.send(qaPut(600, 0)); !errors.Is(err, ErrResponseTooLong) || !s.Dead() {
		t.Errorf("chain: %v", err)
	}
	qaAllZero(t, "chain answers", q.given)
}

// Nothing is sent in the extended form until the card is known to take it, and then only when the
// transport takes it too.
func TestExtendedFormIsNotReachedBeforeAllowExtended(t *testing.T) {
	big := qaPut(300, 3000)
	for _, ext := range []bool{false, true} {
		// A command with 300 bytes goes as a chain of short blocks, and Le is cut to 256.
		q := &qaTransport{ext: ext, script: []qaStep{qaOK(), qaOK()}}
		s := qaSession(t, q, Options{}, qaTable(false, true))
		if _, err := s.send(big); err != nil || q.calls() != 2 || q.sent[0][0] != 0x10 || q.sent[0][4] != 0xFF || q.sent[1][0] != 0x00 || q.sent[1][4] != 45 || q.sent[1][len(q.sent[1])-1] != 0x00 {
			t.Fatalf("ext %v: %v %x", ext, err, q.sent)
		}
		// A read that asks for 3000 bytes asks for 256.
		q = &qaTransport{ext: ext, script: []qaStep{qaOK()}}
		s = qaSession(t, q, Options{}, nil)
		cmd := qaGetData(0x7F21)
		cmd.Le = 3000
		if _, err := s.send(cmd); err != nil || !bytes.Equal(q.sent[0], []byte{0x00, 0xCA, 0x7F, 0x21, 0x00}) {
			t.Fatalf("ext %v: %v %x", ext, err, q.sent)
		}
	}
	// A card that is told it takes less than the header needs is not an extended one either.
	for _, max := range []int{0, 1, 9} {
		q := &qaTransport{ext: true, script: []qaStep{qaOK()}}
		s := qaSession(t, q, Options{}, nil)
		s.allowExtended(max)
		cmd := qaGetData(0x7F21)
		cmd.Le = 3000
		if _, err := s.send(cmd); err != nil || len(q.sent[0]) != 5 {
			t.Fatalf("max %d: %v %x", max, err, q.sent)
		}
	}
	// Both allow it: the extended form, exactly.
	q := &qaTransport{ext: true, script: []qaStep{qaOK()}}
	s := qaSession(t, q, Options{}, nil)
	s.allowExtended(3062)
	cmd := qaGetData(0x7F21)
	cmd.Le = 3000
	if _, err := s.send(cmd); err != nil || !bytes.Equal(q.sent[0], []byte{0x00, 0xCA, 0x7F, 0x21, 0x00, 0x0B, 0xB8}) {
		t.Fatalf("%v %x", err, q.sent)
	}
	// The transport does not take it: the card is not asked, and the call goes short.
	q = &qaTransport{ext: false, script: []qaStep{qaOK()}}
	s = qaSession(t, q, Options{}, nil)
	s.allowExtended(3062)
	if _, err := s.send(cmd); err != nil || len(q.sent[0]) != 5 {
		t.Fatalf("%v %x", err, q.sent)
	}
}
