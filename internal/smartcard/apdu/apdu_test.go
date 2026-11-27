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

func TestEncodeShort(t *testing.T) {
	aid := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	for _, tc := range []struct {
		name string
		cmd  apdu.Command
		want string
	}{
		{"case 1", apdu.Command{CLA: 0x00, INS: 0x44}, "00440000"},
		{"case 2", apdu.Command{CLA: 0x00, INS: 0xCA, P2: 0x4F, Le: 256}, "00CA004F00"},
		{"case 2, Le 1", apdu.Command{CLA: 0x00, INS: 0xCA, Le: 1}, "00CA000001"},
		{"case 2, Le 255", apdu.Command{CLA: 0x00, INS: 0xCA, Le: 255}, "00CA0000FF"},
		{"case 3", apdu.Command{CLA: 0x00, INS: 0xDA, P2: 0xC4, Data: []byte{0x01}}, "00DA00C40101"},
		{"case 4", apdu.Command{CLA: 0x00, INS: 0xA4, P1: 0x04, Data: aid, Le: 256}, "00A40400" + "06D27600012401" + "00"},
	} {
		got, err := tc.cmd.Encode(false)
		if err != nil || hex.EncodeToString(got) != lower(tc.want) {
			t.Errorf("%s: %v %x, want %s", tc.name, err, got, tc.want)
		}
	}
	// 255 bytes is the most of a short command.
	got, err := apdu.Command{INS: 0xDA, Data: make([]byte, 255)}.Encode(false)
	if err != nil || len(got) != 4+1+255 || got[4] != 0xFF {
		t.Errorf("255 bytes: %v %d", err, len(got))
	}
}

func lower(s string) string { return string(bytes.ToLower([]byte(s))) }

func TestEncodeExtended(t *testing.T) {
	data300 := bytes.Repeat([]byte{0xAB}, 300)
	for _, tc := range []struct {
		name   string
		cmd    apdu.Command
		prefix string
		length int
	}{
		{"case 1", apdu.Command{CLA: 0x00, INS: 0x44}, "00440000", 4},
		{"case 2", apdu.Command{INS: 0xCA, P2: 0x4F, Le: 256}, "00CA004F" + "00" + "0100", 7},
		{"case 2, Le 65536", apdu.Command{INS: 0xCA, P2: 0x4F, Le: 65536}, "00CA004F" + "00" + "0000", 7},
		{"case 3", apdu.Command{INS: 0xDA, P2: 0xC4, Data: data300}, "00DA00C4" + "00" + "012C", 4 + 3 + 300},
		{"case 4", apdu.Command{INS: 0xDA, P2: 0xC4, Data: data300, Le: 65536}, "00DA00C4" + "00" + "012C", 4 + 3 + 300 + 2},
		{"case 4, Le 3000", apdu.Command{INS: 0xDA, Data: []byte{1, 2}, Le: 3000}, "00DA0000" + "00" + "0002" + "0102" + "0BB8", 4 + 3 + 2 + 2},
	} {
		got, err := tc.cmd.Encode(true)
		if err != nil || len(got) != tc.length || hex.EncodeToString(got)[:len(tc.prefix)] != lower(tc.prefix) {
			t.Errorf("%s: %v %x", tc.name, err, got)
		}
	}
	// Exact tails: the Le of a case 4 comes after the data, with no second zero byte.
	got, _ := apdu.Command{INS: 0xDA, Data: data300, Le: 65536}.Encode(true)
	if !bytes.Equal(got[len(got)-2:], []byte{0, 0}) || !bytes.Equal(got[7:len(got)-2], data300) {
		t.Errorf("case 4 tail: %x", got[len(got)-4:])
	}
	// The extended form reaches 65535 bytes of data.
	if _, err := (apdu.Command{Data: make([]byte, apdu.MaxExtendedData)}).Encode(true); err != nil {
		t.Errorf("65535: %v", err)
	}
}

func TestEncodeRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  apdu.Command
		ext  bool
		want error
	}{
		{"short data 256", apdu.Command{Data: make([]byte, 256)}, false, apdu.ErrDataTooLong},
		{"short Le 257", apdu.Command{Le: 257}, false, apdu.ErrLeOutOfRange},
		{"extended data 65536", apdu.Command{Data: make([]byte, 65536)}, true, apdu.ErrDataTooLong},
		{"extended Le 65537", apdu.Command{Le: 65537}, true, apdu.ErrLeOutOfRange},
		{"negative Le", apdu.Command{Le: -1}, true, apdu.ErrLeOutOfRange},
	} {
		got, err := tc.cmd.Encode(tc.ext)
		if !errors.Is(err, tc.want) || got != nil {
			t.Errorf("%s: %v %x", tc.name, err, got)
		}
	}
}

func TestResponse(t *testing.T) {
	r, err := apdu.ParseResponse([]byte{0x01, 0x02, 0x90, 0x00})
	if err != nil || !bytes.Equal(r.Data, []byte{1, 2}) || r.Status != apdu.StatusSuccess || !r.Status.IsSuccess() {
		t.Fatalf("%v %+v", err, r)
	}
	r, err = apdu.ParseResponse([]byte{0x6A, 0x88})
	if err != nil || len(r.Data) != 0 || r.Status != apdu.StatusNotFound {
		t.Fatalf("%v %+v", err, r)
	}
	for _, in := range [][]byte{nil, {0x90}} {
		if _, err := apdu.ParseResponse(in); !errors.Is(err, apdu.ErrResponseTooShort) {
			t.Errorf("%x: %v", in, err)
		}
	}
}

func TestStatus(t *testing.T) {
	for _, tc := range []struct {
		sw    apdu.Status
		more  int
		isMor bool
		text  string
	}{
		{0x9000, 0, false, "9000 (success)"},
		{0x6100, 256, true, "6100 (more data available)"},
		{0x6105, 5, true, "6105 (more data available)"},
		{0x61FF, 255, true, "61FF (more data available)"},
		{0x6C20, 0, false, "6C20"},
		{0x6700, 0, false, "6700 (wrong length)"},
		{0x6982, 0, false, "6982 (security status not satisfied)"},
		{0x6983, 0, false, "6983 (authentication method blocked)"},
		{0x6A88, 0, false, "6A88 (referenced data not found)"},
		{0x6283, 0, false, "6283"},
	} {
		n, ok := tc.sw.MoreData()
		if n != tc.more || ok != tc.isMor || tc.sw.String() != tc.text {
			t.Errorf("%04X: %d %v %q", uint16(tc.sw), n, ok, tc.sw.String())
		}
	}
}

func TestCommandPrintsNoData(t *testing.T) {
	c := apdu.Command{CLA: 0x00, INS: 0x20, P2: 0x81, Data: []byte("987654"), Le: 0}
	type holder struct{ Cmd apdu.Command }
	var outs []string
	for _, v := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q", "%d"} {
		outs = append(outs, fmt.Sprintf(v, c), fmt.Sprintf(v, &c), fmt.Sprintf(v, holder{c}), fmt.Sprintf(v, []apdu.Command{c}))
	}
	outs = append(outs, c.String(), c.GoString())
	for _, o := range outs {
		if strings.Contains(o, "987654") || strings.Contains(o, "393837") || strings.Contains(strings.ToLower(o), "3938") {
			t.Errorf("the data is shown: %q", o)
		}
	}
	if c.String() != "apdu.Command{CLA:00 INS:20 P1:00 P2:81 Lc:6 Le:0}" {
		t.Errorf("%q", c.String())
	}
}
