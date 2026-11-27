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
)

// Command is the header, the data and the expected response length of one command APDU. An empty Data
// means no data field (no Lc). Le is the largest answer that the sender will take: 0 means no Le field,
// 1 to 255 is that many bytes, 256 is written as the byte 00 in the short form, and in the extended
// form 65536 is written as 0000.
//
// A Command may hold a PIN, so it prints without its data: String, GoString, Format, MarshalText and
// MarshalJSON show the header, the length of the data and Le. Two ways of printing still reach the
// data, because they do not call a method of a field they cannot reach: a Command in an unexported
// field of a struct that is printed with %+v or %#v, and any reflective dump. A Command must not be
// embedded in a struct that is printed.
type Command struct {
	CLA, INS, P1, P2 byte
	Data             []byte
	Le               int
}

// String shows the command without its data: class, instruction, parameters, the length of the data
// and Le. A command may hold a PIN, so no way of printing it shows a byte of Data.
func (c Command) String() string {
	return fmt.Sprintf("apdu.Command{CLA:%02X INS:%02X P1:%02X P2:%02X Lc:%d Le:%d}", c.CLA, c.INS, c.P1, c.P2, len(c.Data), c.Le)
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
// data over 255 bytes and an Le over 256; with extended true it writes the extended form, in which the
// length fields of the command are all in the extended form (a zero byte, then two bytes for Lc, and
// two bytes for Le, with no zero byte again when Lc was written). The case of the command follows
// from Data and Le: no data and no Le is case 1; Le only, case 2; data only, case 3; both, case 4.
// The returned slice is new and belongs to the caller.
func (c Command) Encode(extended bool) ([]byte, error) {
	maxData, maxLe := MaxShortData, MaxShortLe
	if extended {
		maxData, maxLe = MaxExtendedData, MaxExtendedLe
	}
	if len(c.Data) > maxData {
		return nil, ErrDataTooLong
	}
	if c.Le < 0 || c.Le > maxLe {
		return nil, ErrLeOutOfRange
	}
	out := make([]byte, 4, 4+3+len(c.Data)+2)
	out[0], out[1], out[2], out[3] = c.CLA, c.INS, c.P1, c.P2
	hasData, hasLe := len(c.Data) > 0, c.Le > 0
	switch {
	case !extended:
		if hasData {
			out = append(out, byte(len(c.Data)))
			out = append(out, c.Data...)
		}
		if hasLe {
			out = append(out, byte(c.Le%256)) // 256 is the byte 00
		}
	default:
		if hasData {
			out = append(out, 0x00, byte(len(c.Data)>>8), byte(len(c.Data)))
			out = append(out, c.Data...)
		}
		if hasLe {
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
