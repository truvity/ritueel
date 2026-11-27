package openpgpapp

import (
	"errors"
	"testing"
)

// FuzzSendAnswers holds that whatever a card answers, send never panics, never returns more than
// MaxResponse bytes, ends a lost exchange with a dead session that stays dead without touching the
// transport, and overwrites every response buffer it does not hand on. Each answer in the input is
// cut at a byte of value 0xFE.
func FuzzSendAnswers(f *testing.F) {
	f.Add([]byte{0x90, 0x00})
	f.Add([]byte{0x01, 0x61, 0x02, 0xFE, 0x02, 0x03, 0x90, 0x00})
	f.Add([]byte{0x61, 0x00, 0xFE, 0x61, 0x00})
	f.Add([]byte{0x90})
	f.Fuzz(func(t *testing.T, in []byte) {
		ft := &fakeTransport{}
		start := 0
		for i := 0; i <= len(in); i++ {
			if i == len(in) || in[i] == 0xFE {
				ft.script = append(ft.script, step{resp: append([]byte(nil), in[start:i]...)})
				start = i + 1
			}
		}
		s := newSession(t, ft, Options{})
		got, err := s.send(getData(0x7F21, 256))
		if len(got) > MaxResponse {
			t.Fatal("more than the cap")
		}
		if err != nil && got != nil {
			t.Fatal("data with an error")
		}
		for i, g := range ft.given {
			// The data of a returned answer is a copy; what the transport handed over is gone.
			if !zeros(g) {
				t.Fatalf("answer %d not overwritten", i)
			}
		}
		var lost *LostError
		if errors.As(err, &lost) {
			calls := ft.calls()
			if _, again := s.send(getData(0x004F, 256)); !errors.Is(again, ErrSessionDead) || ft.calls() != calls {
				t.Fatal("a dead session reached the transport")
			}
		}
	})
}
