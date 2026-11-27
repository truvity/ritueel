package openpgpapp

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzResponsePathAgainstAModel runs send against a small model of a card that answers one command in
// pieces. The bytes of the input are the lengths of the pieces (0 to 256, byte by byte, at most 100
// pieces); the card answers piece 0 with the status 61xx that announces piece 1, and so on, and the last
// with 9000. The model says what send must do: return the pieces joined while the total is within
// MaxResponse and the number of GET RESPONSE commands within the cap; otherwise lose the session at the
// first piece that breaks a cap. In every case send makes exactly as many calls as the model counts (none
// after a final status), asks for each piece with the count that the card announced, overwrites every
// answer, and keeps its caps.
func FuzzResponsePathAgainstAModel(f *testing.F) {
	f.Add([]byte{0}, false)
	f.Add([]byte{5, 3}, false)
	f.Add([]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1}, true)
	f.Add(bytes.Repeat([]byte{1}, 70), false)
	f.Add(bytes.Repeat([]byte{0}, 66), true)
	f.Add(bytes.Repeat([]byte{200}, 21), true)
	f.Fuzz(func(t *testing.T, lengths []byte, write bool) {
		if len(lengths) == 0 || len(lengths) > 100 {
			return
		}
		pieces := make([][]byte, len(lengths))
		for i, n := range lengths {
			pieces[i] = bytes.Repeat([]byte{byte(i + 1)}, int(n))
		}
		var script []qaStep
		for i, p := range pieces {
			if i == len(pieces)-1 {
				script = append(script, qaOK(p...))
			} else {
				script = append(script, qaSW(0x61, byte(len(pieces[i+1])), p...)) // 00 stands for 256, and is also what 0 bytes announce
			}
		}
		script = append(script, qaOK(0xEE), qaOK(0xEE)) // what a call after the end would get
		cmd, changes := qaGetData(0x7F21), false
		if write {
			cmd, changes = qaGenerate, true
		}

		// The model.
		var want []byte
		calls, lost, total := 0, false, 0
		for j, p := range pieces {
			calls = j + 1
			want = append(want, p...)
			total += len(p)
			if total > MaxResponse {
				lost = true
				break
			}
			if j == len(pieces)-1 {
				break
			}
			if j == maxContinuations { // the answer to the 64th GET RESPONSE announces a 65th
				lost = true
				break
			}
		}

		q := &qaTransport{script: script}
		s := qaSession(t, q, Options{}, nil)
		got, err := s.send(cmd)
		if q.calls() != calls {
			t.Fatalf("%d calls, the model says %d (lost %v)", q.calls(), calls, lost)
		}
		for i := 1; i < q.calls(); i++ {
			if w := []byte{0x00, 0xC0, 0x00, 0x00, byte(len(pieces[i]))}; !bytes.Equal(q.sent[i], w) {
				t.Fatalf("GET RESPONSE %d is %x, the card announced %x", i, q.sent[i], w)
			}
		}
		qaAllZero(t, "answers", q.given)
		if lost {
			var le *LostError
			if !errors.As(err, &le) || !errors.Is(err, ErrResponseTooLong) || !errors.Is(err, ErrSessionDead) || le.OutcomeUnknown != changes || got != nil || !s.Dead() {
				t.Fatalf("the model says lost: %v %x", err, got)
			}
			return
		}
		if err != nil || !bytes.Equal(got, want) || s.Dead() || len(got) > MaxResponse {
			t.Fatalf("the model says whole: %v, %d bytes, want %d", err, len(got), len(want))
		}
		// The data is the caller's: changing it changes nothing of the session.
		clear(got)
	})
}

// FuzzSendNeverCallsAfterAFinalStatus: whatever status word comes back for a read, the number of calls
// is one, or 1 + the rounds of a continuation; it never goes on after a final word.
func FuzzSendNeverCallsAfterAFinalStatus(f *testing.F) {
	f.Add(uint16(0x9000), uint16(0x6A88), uint16(0x9000))
	f.Add(uint16(0x6100), uint16(0x6C20), uint16(0x6D00))
	f.Fuzz(func(t *testing.T, a, b, c uint16) {
		q := &qaTransport{script: []qaStep{qaWord(int(a), 1), qaWord(int(b), 2), qaWord(int(c), 3), qaOK(4), qaOK(5), qaOK(6)}}
		s := qaSession(t, q, Options{}, nil)
		_, err := s.send(qaGetData(0x7F21))
		words := []uint16{a, b, c}
		want := 1
		for i := range words {
			if words[i]>>8 != 0x61 {
				break
			}
			want = i + 2
		}
		if q.calls() != want {
			t.Fatalf("%04X %04X %04X: %d calls, want %d (%v)", a, b, c, q.calls(), want, err)
		}
	})
}
