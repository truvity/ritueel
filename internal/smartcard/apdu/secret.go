package apdu

import (
	"fmt"
	"sync"
)

// redacted is the one text that a [Secret] shows, whatever it holds and however it is asked.
const redacted = "[secret]"

// Secret holds a PIN. It is made by copying a byte slice, gives its bytes only to the function passed
// to [Secret.Use], and is wiped with [Secret.Wipe]. Every way that Go prints or encodes a value shows
// the word [secret] and never a byte: String, GoString, Format (every verb and flag, so also %v, %+v,
// %x and %q), MarshalText and MarshalJSON. A Secret has no way to be filled by decoding. Copies of a
// Secret value share one holder, so wiping any copy wipes them all; the zero value holds nothing.
//
// What a Secret cannot do: it cannot stop a function given to Use from copying the bytes, and it
// cannot reach the copies that the caller made before NewSecret. The caller wipes the slice it passed
// in, and a command built inside Use must be cleared by its sender.
type Secret struct{ h *holder }

type holder struct {
	mu sync.Mutex
	b  []byte
}

// NewSecret returns a Secret that holds a copy of b. The caller still owns b and wipes it.
func NewSecret(b []byte) Secret {
	return Secret{h: &holder{b: append([]byte(nil), b...)}}
}

// Use calls f with the bytes of the secret and returns when f does. It does not call f when the secret
// is empty or wiped, so a caller that must have a PIN checks [Secret.Len] first. The slice is the
// holder's own, not a copy: it is valid only inside f, and f must not keep it. f must not call Len
// or Wipe on the same Secret, or Use on it again: each would wait for the lock that Use holds, and
// the program would stop. A concurrent Wipe waits for f to return.
func (s Secret) Use(f func(b []byte)) {
	if s.h == nil {
		return
	}
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	if len(s.h.b) == 0 {
		return
	}
	f(s.h.b)
}

// Len returns the number of bytes held: zero for the zero value and after Wipe.
func (s Secret) Len() int {
	if s.h == nil {
		return 0
	}
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	return len(s.h.b)
}

// Wipe overwrites the bytes with zeros and forgets them. It is safe to call twice, and on a zero value.
func (s Secret) Wipe() {
	if s.h == nil {
		return
	}
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	clear(s.h.b)
	s.h.b = nil
}

// String returns the fixed word.
func (Secret) String() string { return redacted }

// GoString returns the fixed word, for the %#v verb.
func (Secret) GoString() string { return redacted }

// Format writes the fixed word for every verb.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// MarshalText returns the fixed word.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// MarshalJSON returns the fixed word as a JSON string.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
