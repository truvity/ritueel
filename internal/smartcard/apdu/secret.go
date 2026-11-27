package apdu

import (
	"fmt"
	"sync"
)

// redacted is the one text that a [Secret] shows, whatever it holds and however it is asked.
const redacted = "[secret]"

// Secret holds a PIN. It is made by copying a byte slice, gives its bytes only to the function passed
// to [Secret.Use], and is wiped with [Secret.Wipe].
//
// The bytes are not reachable from the value. A Secret is one pointer to three function values, each a
// method of a holder that only they can reach, so a program that prints a Secret by reflection (fmt
// does so for a value in an unexported field of a struct, for a verb that its method does not cover,
// and for %p) follows the pointer and finds function addresses and no byte; neither can encoding/json,
// encoding/xml or encoding/gob, which see no exported field. This was chosen over an opaque handle into
// a private table because it needs no table, no lock of its own, and no entry that nothing frees. A
// Secret can be compared and used as a map key; two are equal when they are copies of one. What a Secret prints with fmt's own methods
// is the word [secret], for every verb: String, GoString, Format, MarshalText, MarshalJSON. Encoding/gob
// refuses it, as it refuses any type with no exported field. A Secret has no way to be filled by
// decoding.
//
// A copy of a Secret value is the same secret: the copies share one holder, so a Wipe of any of them
// wipes it for all. The zero value holds nothing.
//
// What a Secret cannot do: it cannot stop a function given to Use from copying the bytes, and it
// cannot reach the copies that the caller made before NewSecret. The caller wipes the slice it passed
// in.
type Secret struct{ h *handle }

// handle holds the three functions that reach a holder. It has no field that reflection can print as
// bytes.
type handle struct {
	use  func(f func(b []byte))
	size func() int
	wipe func()
}

type holder struct {
	mu sync.Mutex
	b  []byte
}

func (h *holder) useBytes(f func(b []byte)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.b) == 0 {
		return
	}
	f(h.b)
}

func (h *holder) length() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.b)
}

func (h *holder) clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.b)
	h.b = nil
}

// NewSecret returns a Secret that holds a copy of b. The caller still owns b and wipes it.
func NewSecret(b []byte) Secret {
	h := &holder{b: append([]byte(nil), b...)}
	return Secret{h: &handle{use: h.useBytes, size: h.length, wipe: h.clear}}
}

// Use calls f with the bytes of the secret and returns when f does. It does not call f when the secret
// is empty or wiped, so a caller that must have a PIN checks [Secret.Len] first. The slice is the
// holder's own, not a copy: it is valid only inside f, and f must not keep it. f must not call Len
// or Wipe on the same Secret, or Use on it again: each would wait for the lock that Use holds, and
// the program would stop. A concurrent Wipe waits for f to return.
func (s Secret) Use(f func(b []byte)) {
	if s.h != nil {
		s.h.use(f)
	}
}

// Len returns the number of bytes held: zero for the zero value and after Wipe.
func (s Secret) Len() int {
	if s.h == nil {
		return 0
	}
	return s.h.size()
}

// Wipe overwrites the bytes with zeros and forgets them, for this Secret and every copy of it. It is
// safe to call twice, and on a zero value.
func (s Secret) Wipe() {
	if s.h != nil {
		s.h.wipe()
	}
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
