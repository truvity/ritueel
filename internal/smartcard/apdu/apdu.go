// Package apdu holds the bytes that a smart card exchange is made of: a command and its encoding in the
// short and in the extended form (ISO/IEC 7816-3, clause 12.1, cases 1 to 4; ISO/IEC 7816-4, clause
// 5.1), a response split into its data and its status word, the status words that the application
// layer names, and [Secret], the holder that a PIN lives in. It belongs to the code that speaks to a
// card (internal/smartcard), not to package internal/cards, which reads the card files of a bundle.
//
// The package sends nothing and opens no device. It has no list of commands: which commands may be
// sent is decided by the package that owns the application (package openpgpapp holds that list as
// data).
package apdu

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Limits of the two forms. A short command carries at most 255 data bytes and asks for at most 256; an
// extended one carries at most 65535 and asks for at most 65536.
const (
	MaxShortData    = 255
	MaxShortLe      = 256
	MaxExtendedData = 65535
	MaxExtendedLe   = 65536
)

var (
	// ErrDataTooLong marks command data that does not fit the form that was asked for.
	ErrDataTooLong = errors.New("apdu: command data longer than the form allows")
	// ErrLeOutOfRange marks an expected length that is negative or does not fit the form that was
	// asked for.
	ErrLeOutOfRange = errors.New("apdu: expected length out of range")
	// ErrResponseTooShort marks a response of fewer than the two bytes of a status word.
	ErrResponseTooShort = errors.New("apdu: response shorter than a status word")
	// ErrBodyConflict marks a command that holds plain Data and a secret body at once.
	ErrBodyConflict = errors.New("apdu: a command has plain data and a secret body")
	// ErrSecretChanged marks a secret that changed (it was wiped) between the moment its length was
	// read and the moment its bytes were copied, or whose bytes are not the length that was judged.
	// Nothing is returned with it, and nothing was sent.
	ErrSecretChanged = errors.New("apdu: a secret changed while the command was encoded")
	// ErrSecretEmpty marks a command with a secret part that holds no byte (it was wiped): a body
	// with a part missing is not the body that was meant, and is never encoded.
	// It is also an [ErrSecretChanged].
	ErrSecretEmpty = fmt.Errorf("apdu: a secret part is empty (%w)", ErrSecretChanged)
)

// Command is the header, the body and the expected response length of one command APDU. The body is
// either plain Data, or, for a PIN, one or two [Secret] values set with [Command.WithSecretData] or
// [Command.WithSecretPair]; the two are exclusive, and [Command.Encode] refuses both at once. An empty
// body means no data field (no Lc). Le is the largest answer that the sender will take: 0 means no Le
// field, 1 to 255 is that many bytes, 256 is written as the byte 00 in the short form, and in the
// extended form 65536 is written as 0000.
//
// A PIN is never in Data: a Command that carries one holds it in a Secret, whose bytes cannot be reached
// by printing, by reflection or by an encoder (see [Secret]). So no way of printing or encoding a Command
// shows a PIN, in any field of any struct. What a Command does show: String, GoString, Format,
// MarshalText and MarshalJSON show the header, the length of the body and Le, never the data. A Command
// in an unexported field of a printed struct, a %p, a reflective dump and encoding/gob do show Data, which
// is plain: a digest to sign, a fingerprint, key attributes. Keep nothing secret in Data.
type Command struct {
	CLA, INS, P1, P2 byte
	Data             []byte
	Le               int
	secret, second   Secret
}

// WithSecretData returns the command with the secret as its body, in place of Data (which it clears).
func (c Command) WithSecretData(s Secret) Command {
	c.Data, c.secret, c.second = nil, s, Secret{}
	return c
}

// WithSecretPair returns the command with the two secrets, one after the other, as its body, in place
// of Data (which it clears). It is for the change of a PIN: the old one, then the new one.
func (c Command) WithSecretPair(first, second Secret) Command {
	c.Data, c.secret, c.second = nil, first, second
	return c
}

// HasSecret reports whether the body is held in secrets. It is true for a secret that was wiped since.
func (c Command) HasSecret() bool { return c.secret.h != nil || c.second.h != nil }

// SecretParts is the number of secrets in the body: 0, 1 or 2.
func (c Command) SecretParts() int {
	n := 0
	for _, s := range []Secret{c.secret, c.second} {
		if s.h != nil {
			n++
		}
	}
	return n
}

// PartLen is the length of the secret part i (0 or 1), or 0 for a part that is absent or wiped. It
// gives the length and never the bytes: it is what an allowlist judges a PIN by.
func (c Command) PartLen(i int) int {
	switch i {
	case 0:
		return c.secret.Len()
	case 1:
		return c.second.Len()
	}
	return 0
}

// EncodedLen is the length of an encoded command with a body of bodyLen bytes and an expected length of
// le, in the short or the extended form: what [Command.Encode] returns, for a caller that holds the
// length it judged and compares.
func EncodedLen(bodyLen, le int, extended bool) int {
	n := 4
	if bodyLen > 0 {
		n += bodyLen + 1
		if extended {
			n += 2
		}
	}
	if le > 0 {
		switch {
		case !extended:
			n++
		case bodyLen > 0:
			n += 2
		default:
			n += 3
		}
	}
	return n
}

// BodyLen is the length of the body: of Data, or of the secrets together.
func (c Command) BodyLen() int { return len(c.Data) + c.secret.Len() + c.second.Len() }

// String shows the command without its body: class, instruction, parameters, the length of the body
// and Le.
func (c Command) String() string {
	return fmt.Sprintf("apdu.Command{CLA:%02X INS:%02X P1:%02X P2:%02X Lc:%d Le:%d}", c.CLA, c.INS, c.P1, c.P2, c.BodyLen(), c.Le)
}

// GoString is [Command.String], for the %#v verb.
func (c Command) GoString() string { return c.String() }

// MarshalText returns [Command.String].
func (c Command) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// MarshalJSON returns [Command.String] as a JSON string.
func (c Command) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// Format writes [Command.String] for every verb and flag.
func (c Command) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(c.String())) }

// Encode returns the bytes of the command. With extended false it writes the short form and refuses
// a body over 255 bytes and an Le over 256; with extended true it writes the extended form, in which the
// length fields of the command are all in the extended form (a zero byte, then two bytes for Lc, and
// two bytes for Le, with no zero byte again when Lc was written). The case of the command follows
// from the body and Le: no body and no Le is case 1; Le only, case 2; body only, case 3; both, case 4.
// A secret body is copied into the returned slice at the last moment, inside [Secret.Use], and
// nowhere else. The returned slice is new and belongs to the caller, who overwrites it when it holds a PIN.
func (c Command) Encode(extended bool) ([]byte, error) {
	if len(c.Data) > 0 && c.HasSecret() {
		return nil, ErrBodyConflict
	}
	maxData, maxLe := MaxShortData, MaxShortLe
	if extended {
		maxData, maxLe = MaxExtendedData, MaxExtendedLe
	}
	// The length of each secret part is read once. A part with no byte is refused, and so is a part
	// whose bytes, when they are taken, are not the length that sized the output.
	var lens [2]int
	n := len(c.Data)
	if c.HasSecret() {
		for i, p := range []Secret{c.secret, c.second} {
			if p.h == nil {
				continue
			}
			if lens[i] = p.Len(); lens[i] == 0 {
				return nil, ErrSecretEmpty
			}
			n += lens[i]
		}
	}
	if n > maxData {
		return nil, ErrDataTooLong
	}
	if c.Le < 0 || c.Le > maxLe {
		return nil, ErrLeOutOfRange
	}
	out := make([]byte, 4, 4+3+n+2)
	out[0], out[1], out[2], out[3] = c.CLA, c.INS, c.P1, c.P2
	hasData, hasLe := n > 0, c.Le > 0
	if hasData {
		if extended {
			out = append(out, 0x00, byte(n>>8), byte(n))
		} else {
			out = append(out, byte(n))
		}
		if c.HasSecret() {
			for i, p := range []Secret{c.secret, c.second} {
				if p.h == nil {
					continue
				}
				ok := false
				p.Use(func(b []byte) {
					// Never past the room that was made, so no copy is left behind.
					if len(b) == lens[i] {
						out = append(out, b...)
						ok = true
					}
				})
				if !ok {
					clear(out)
					return nil, ErrSecretChanged
				}
			}
		} else {
			out = append(out, c.Data...)
		}
	}
	if hasLe {
		switch {
		case !extended:
			out = append(out, byte(c.Le%256)) // 256 is the byte 00
		default:
			if !hasData {
				out = append(out, 0x00) // case 2: the marker byte comes before Le
			}
			le := c.Le % 65536 // 65536 is the two bytes 0000
			out = append(out, byte(le>>8), byte(le))
		}
	}
	return out, nil
}

// Response is the answer to one command: its data and its status word.
type Response struct {
	Data   []byte
	Status Status
}

// ParseResponse splits the bytes of a response into data and status word (the last two bytes). Data is
// a part of raw, not a copy; it is empty when raw is only the status word.
func ParseResponse(raw []byte) (Response, error) {
	if len(raw) < 2 {
		return Response{}, ErrResponseTooShort
	}
	n := len(raw) - 2
	return Response{Data: raw[:n], Status: Status(uint16(raw[n])<<8 | uint16(raw[n+1]))}, nil
}
