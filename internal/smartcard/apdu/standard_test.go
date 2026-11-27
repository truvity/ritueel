package apdu_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

// The expected bytes of this file are written by hand from ISO/IEC 7816-3 clause 12.1 (the four cases of
// a command APDU, in the short and in the extended form) and ISO/IEC 7816-4 clause 5.1, and from the
// status table of the OpenPGP smart card application, specification 3.4.1, section 7.9.

func hx(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// body makes n bytes that differ from each other for a while, so that a shift or a cut shows.
func body(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return b
}

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestLimitsAreTheStandards(t *testing.T) {
	if apdu.MaxShortData != 255 || apdu.MaxShortLe != 256 || apdu.MaxExtendedData != 65535 || apdu.MaxExtendedLe != 65536 {
		t.Fatal("a limit of a form is not the one of ISO/IEC 7816-3")
	}
}

func TestEncodeEveryCase(t *testing.T) {
	const head = "00 CA 12 34"
	for _, tc := range []struct {
		name     string
		cmd      apdu.Command
		extended bool
		want     []byte
	}{
		// Short form. Case 1: no data, no Le.
		{"short case 1", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34}, false, hx(t, head)},
		{"short case 1, empty non-nil body", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: []byte{}}, false, hx(t, head)},
		{"short case 1, the class byte is the caller's", apdu.Command{CLA: 0x80, INS: 0xFB, P1: 0x01}, false, hx(t, "80 FB 01 00")},
		// Case 2: Le only.
		{"short case 2, Le 1", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Le: 1}, false, hx(t, head+" 01")},
		{"short case 2, Le 2", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Le: 2}, false, hx(t, head+" 02")},
		{"short case 2, Le 255", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Le: 255}, false, hx(t, head+" FF")},
		{"short case 2, Le 256 is the byte 00", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Le: 256}, false, hx(t, head+" 00")},
		// Case 3: data only.
		{"short case 3, 1 byte", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(1)}, false, join(hx(t, head+" 01"), body(1))},
		{"short case 3, 254 bytes", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(254)}, false, join(hx(t, head+" FE"), body(254))},
		{"short case 3, 255 bytes", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(255)}, false, join(hx(t, head+" FF"), body(255))},
		// Case 4: both.
		{"short case 4, 1 byte and Le 1", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(1), Le: 1}, false, join(hx(t, head+" 01"), body(1), hx(t, "01"))},
		{"short case 4, 1 byte and Le 256", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(1), Le: 256}, false, join(hx(t, head+" 01"), body(1), hx(t, "00"))},
		{"short case 4, 255 bytes and Le 255", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(255), Le: 255}, false, join(hx(t, head+" FF"), body(255), hx(t, "FF"))},
		{"short case 4, 255 bytes and Le 256", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(255), Le: 256}, false, join(hx(t, head+" FF"), body(255), hx(t, "00"))},
		// Extended form. Case 1 is the same four bytes.
		{"extended case 1", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34}, true, hx(t, head)},
		// Case 2E: a zero byte, then Le in two bytes.
		{"extended case 2, Le 1", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Le: 1}, true, hx(t, head+" 00 0001")},
		{"extended case 2, Le 255", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Le: 255}, true, hx(t, head+" 00 00FF")},
		{"extended case 2, Le 256", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Le: 256}, true, hx(t, head+" 00 0100")},
		{"extended case 2, Le 65535", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Le: 65535}, true, hx(t, head+" 00 FFFF")},
		{"extended case 2, Le 65536 is 0000", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Le: 65536}, true, hx(t, head+" 00 0000")},
		// Case 3E: a zero byte, Lc in two bytes, the data.
		{"extended case 3, 1 byte", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(1)}, true, join(hx(t, head+" 00 0001"), body(1))},
		{"extended case 3, 255 bytes", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(255)}, true, join(hx(t, head+" 00 00FF"), body(255))},
		{"extended case 3, 256 bytes", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(256)}, true, join(hx(t, head+" 00 0100"), body(256))},
		{"extended case 3, 65535 bytes", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(65535)}, true, join(hx(t, head+" 00 FFFF"), body(65535))},
		// Case 4E: Lc as in case 3E, then Le in two bytes with no zero byte before it.
		{"extended case 4, 1 byte and Le 1", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(1), Le: 1}, true,
			join(hx(t, head+" 00 0001"), body(1), hx(t, "0001"))},
		{"extended case 4, 255 bytes and Le 255", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(255), Le: 255}, true,
			join(hx(t, head+" 00 00FF"), body(255), hx(t, "00FF"))},
		{"extended case 4, 256 bytes and Le 256", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(256), Le: 256}, true,
			join(hx(t, head+" 00 0100"), body(256), hx(t, "0100"))},
		{"extended case 4, 256 bytes and Le 65535", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(256), Le: 65535}, true,
			join(hx(t, head+" 00 0100"), body(256), hx(t, "FFFF"))},
		{"extended case 4, 65535 bytes and Le 65536", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(65535), Le: 65536}, true,
			join(hx(t, head+" 00 FFFF"), body(65535), hx(t, "0000"))},
		// The extended form is used as asked, also for a command that would fit the short one.
		{"extended form of a short command", apdu.Command{INS: 0xCA, P1: 0x12, P2: 0x34, Data: body(2), Le: 3}, true,
			join(hx(t, head+" 00 0002"), body(2), hx(t, "0003"))},
	} {
		data := bytes.Clone(tc.cmd.Data)
		got, err := tc.cmd.Encode(tc.extended)
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Errorf("%s: %v\n got  %X\n want %X", tc.name, err, got[:min(len(got), 16)], tc.want[:min(len(tc.want), 16)])
			continue
		}
		// The slice is new: changing it changes nothing of the command, and the command is not changed.
		if len(got) > 0 {
			clear(got)
		}
		if !bytes.Equal(tc.cmd.Data, data) {
			t.Errorf("%s: Encode changed the data of the command", tc.name)
		}
	}
}

func TestEncodeRefusalsBeforeEncoding(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	minInt := -maxInt - 1
	for _, tc := range []struct {
		name string
		cmd  apdu.Command
		ext  bool
		want error
	}{
		{"short, data 256", apdu.Command{Data: body(256)}, false, apdu.ErrDataTooLong},
		{"short, data 65535", apdu.Command{Data: body(65535)}, false, apdu.ErrDataTooLong},
		{"short, Le 257", apdu.Command{Le: 257}, false, apdu.ErrLeOutOfRange},
		{"short, Le 65536", apdu.Command{Le: 65536}, false, apdu.ErrLeOutOfRange},
		{"short, Le -1", apdu.Command{Le: -1}, false, apdu.ErrLeOutOfRange},
		{"short, the largest int", apdu.Command{Le: maxInt}, false, apdu.ErrLeOutOfRange},
		{"short, the smallest int", apdu.Command{Le: minInt}, false, apdu.ErrLeOutOfRange},
		{"short, 255 bytes and Le 257", apdu.Command{Data: body(255), Le: 257}, false, apdu.ErrLeOutOfRange},
		{"extended, data 65536", apdu.Command{Data: body(65536)}, true, apdu.ErrDataTooLong},
		{"extended, data 70000 and Le 1", apdu.Command{Data: body(70000), Le: 1}, true, apdu.ErrDataTooLong},
		{"extended, Le 65537", apdu.Command{Le: 65537}, true, apdu.ErrLeOutOfRange},
		{"extended, Le -1", apdu.Command{Le: -1}, true, apdu.ErrLeOutOfRange},
		{"extended, the largest int", apdu.Command{Le: maxInt}, true, apdu.ErrLeOutOfRange},
		{"extended, the smallest int", apdu.Command{Le: minInt}, true, apdu.ErrLeOutOfRange},
		{"extended, 65535 bytes and Le 65537", apdu.Command{Data: body(65535), Le: 65537}, true, apdu.ErrLeOutOfRange},
	} {
		got, err := tc.cmd.Encode(tc.ext)
		if !errors.Is(err, tc.want) || got != nil {
			t.Errorf("%s: %v %x", tc.name, err, got)
		}
	}
}

func TestParseResponseEveryShape(t *testing.T) {
	for _, in := range [][]byte{nil, {}, {0x90}, {0x00}} {
		r, err := apdu.ParseResponse(in)
		if !errors.Is(err, apdu.ErrResponseTooShort) || len(r.Data) != 0 || r.Status != 0 {
			t.Errorf("%x: %v %+v", in, err, r)
		}
	}
	// Two bytes: the status word and no data.
	r, err := apdu.ParseResponse([]byte{0x6A, 0x88})
	if err != nil || len(r.Data) != 0 || r.Status != 0x6A88 {
		t.Errorf("two bytes: %v %+v", err, r)
	}
	// Three bytes: one byte of data.
	r, err = apdu.ParseResponse([]byte{0xAB, 0x90, 0x00})
	if err != nil || !bytes.Equal(r.Data, []byte{0xAB}) || r.Status != apdu.StatusSuccess {
		t.Errorf("three bytes: %v %+v", err, r)
	}
	// Data that looks like a status word stays data.
	r, err = apdu.ParseResponse([]byte{0x90, 0x00, 0x61, 0x05})
	if err != nil || !bytes.Equal(r.Data, []byte{0x90, 0x00}) || r.Status != 0x6105 {
		t.Errorf("data that looks like a word: %v %+v", err, r)
	}
	// A long answer.
	long := append(body(65536), 0x90, 0x00)
	r, err = apdu.ParseResponse(long)
	if err != nil || len(r.Data) != 65536 || !bytes.Equal(r.Data, body(65536)) || r.Status != 0x9000 {
		t.Errorf("long: %v", err)
	}
	// Data is a part of the raw bytes, not a copy (the documented contract that the layer above relies
	// on when it wipes the raw answer).
	raw := []byte{1, 2, 3, 0x90, 0x00}
	r, _ = apdu.ParseResponse(raw)
	clear(raw)
	if !bytes.Equal(r.Data, []byte{0, 0, 0}) {
		t.Errorf("Data does not share the raw bytes: %x", r.Data)
	}
	// Every two-byte answer.
	for w := range 0x10000 {
		r, err := apdu.ParseResponse([]byte{byte(w >> 8), byte(w)})
		if err != nil || r.Status != apdu.Status(w) || len(r.Data) != 0 {
			t.Fatalf("%04X: %v %+v", w, err, r)
		}
	}
}

func TestStatusNamedValues(t *testing.T) {
	for _, tc := range []struct {
		sw   apdu.Status
		num  uint16
		text string
	}{
		{apdu.StatusSuccess, 0x9000, "9000 (success)"},
		{apdu.StatusWrongLength, 0x6700, "6700 (wrong length)"},
		{apdu.StatusSecurityNotSatisfied, 0x6982, "6982 (security status not satisfied)"},
		{apdu.StatusAuthBlocked, 0x6983, "6983 (authentication method blocked)"},
		{apdu.StatusNotFound, 0x6A88, "6A88 (referenced data not found)"},
		{apdu.StatusInstructionNotSupported, 0x6D00, "6D00 (instruction not supported)"},
		{apdu.StatusClassNotSupported, 0x6E00, "6E00 (class not supported)"},
	} {
		if uint16(tc.sw) != tc.num || tc.sw.String() != tc.text {
			t.Errorf("%04X: %q", tc.num, tc.sw.String())
		}
		if n, more := tc.sw.MoreData(); more || n != 0 {
			t.Errorf("%04X is not more data", tc.num)
		}
		if tc.sw.IsSuccess() != (tc.num == 0x9000) {
			t.Errorf("%04X: IsSuccess", tc.num)
		}
	}
}

func TestStatusEveryWord(t *testing.T) {
	named := map[uint16]string{
		0x9000: "9000 (success)", 0x6700: "6700 (wrong length)", 0x6982: "6982 (security status not satisfied)",
		0x6983: "6983 (authentication method blocked)", 0x6A88: "6A88 (referenced data not found)",
		0x6D00: "6D00 (instruction not supported)", 0x6E00: "6E00 (class not supported)",
	}
	for w := range 0x10000 {
		s := apdu.Status(w)
		n, more := s.MoreData()
		wantMore := w>>8 == 0x61
		wantN := 0
		if wantMore {
			wantN = w & 0xFF
			if wantN == 0 {
				wantN = 256 // SW2 = 00 stands for 256 bytes
			}
		}
		if more != wantMore || n != wantN {
			t.Fatalf("%04X: MoreData = %d, %v; want %d, %v", w, n, more, wantN, wantMore)
		}
		if s.IsSuccess() != (w == 0x9000) {
			t.Fatalf("%04X: IsSuccess", w)
		}
		want, ok := named[uint16(w)]
		switch {
		case ok:
		case wantMore:
			want = fmt.Sprintf("%04X (more data available)", w)
		default:
			want = fmt.Sprintf("%04X", w)
		}
		if s.String() != want {
			t.Fatalf("%04X: String = %q, want %q", w, s.String(), want)
		}
	}
	// A 6Cxx word is an error and not more data: nothing in the card specification lets the layer resend with its count.
	for lo := range 0x100 {
		if _, more := apdu.Status(0x6C00 | uint16(lo)).MoreData(); more {
			t.Fatalf("6C%02X is not more data", lo)
		}
	}
}
