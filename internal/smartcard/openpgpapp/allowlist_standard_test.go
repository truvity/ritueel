package openpgpapp

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

// These tests hold the allowlist to the list of commands that was checked against the OpenPGP smart card
// application, specification 3.4.1 (sections 4.4, 5 and 7), and against the vendor's pages on attestation and
// on the touch setting. The oracle below is that list written again as a function, with no use of the
// table: every command goes through Session.send, so that what is checked is what reaches the card.

var (
	qaAID    = []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	qaSelDO  = []byte{0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21}
	qaP384   = []byte{0x13, 0x2B, 0x81, 0x04, 0x00, 0x22}
	qaCRTs   = [][]byte{{0xB6, 0x00}, {0xA4, 0x00}, {0xB8, 0x00}}
	qaReadOK = map[uint16]bool{
		0x004F: true, 0x5F52: true, 0x006E: true, 0x00C4: true, 0x00DE: true, 0x00F9: true, 0x00FA: true,
		0x00D6: true, 0x00D7: true, 0x00D8: true, 0x00D9: true, 0x007A: true, 0x7F21: true, 0x7F66: true, 0x7F74: true, 0x00FC: true,
	}
)

// qaPartOK: each PIN, by itself, is at least the minimum of its kind and at most 127 bytes (what seven bits
// of the length in the PW status bytes can state).
func qaPartOK(n, min int) bool { return n >= min && n <= 127 }

// qaOracle says whether the list allows the command, and whether it is a read that a read-only session
// may send.
func qaOracle(c apdu.Command) (allowed, readOnly bool) {
	tag := uint16(c.P1)<<8 | uint16(c.P2)
	n := c.BodyLen()
	secret := c.HasSecret()
	// A PIN travels only as a Secret (one for a verification, two for a change), never in plain Data;
	// no other command has a secret body.
	pinRow := (c.INS == 0x20 && c.P1 == 0x00) || c.INS == 0x24
	if secret && (!pinRow || len(c.Data) > 0) {
		return false, false
	}
	hasCRT := slices.ContainsFunc(qaCRTs, func(b []byte) bool { return bytes.Equal(b, c.Data) })
	if c.CLA == 0x80 && c.INS == 0xFB { // the vendor's attestation: SIG (01) or AUT (03), no data
		return (tag == 0x0100 || tag == 0x0300) && n == 0, false
	}
	if c.CLA != 0x00 {
		return false, false
	}
	switch c.INS {
	case 0xA4: // SELECT by the application identifier
		ok := tag == 0x0400 && bytes.Equal(c.Data, qaAID)
		return ok, ok
	case 0xCA: // GET DATA
		ok := n == 0 && qaReadOK[tag]
		return ok, ok
	case 0x47: // GENERATE ASYMMETRIC KEY PAIR: P1 81 reads, P1 80 generates
		switch tag {
		case 0x8100:
			return hasCRT, hasCRT
		case 0x8000:
			return hasCRT, false
		}
	case 0xF1: // the vendor's firmware version
		ok := tag == 0 && n == 0
		return ok, ok
	case 0xA5: // SELECT DATA of the cardholder certificate
		ok := (tag == 0x0004 || tag == 0x0104 || tag == 0x0204) && bytes.Equal(c.Data, qaSelDO)
		return ok, ok
	case 0x20: // VERIFY
		switch {
		case c.P1 == 0x00 && (c.P2 == 0x81 || c.P2 == 0x82):
			return secret && c.SecretParts() == 1 && qaPartOK(c.PartLen(0), 6), false
		case c.P1 == 0x00 && c.P2 == 0x83:
			return secret && c.SecretParts() == 1 && qaPartOK(c.PartLen(0), 8), false
		case c.P1 == 0xFF && (c.P2 == 0x81 || c.P2 == 0x82 || c.P2 == 0x83):
			return n == 0 && !secret, false
		}
	case 0x24: // CHANGE REFERENCE DATA
		switch {
		case c.P1 == 0x00 && c.P2 == 0x81:
			return secret && c.SecretParts() == 2 && qaPartOK(c.PartLen(0), 6) && qaPartOK(c.PartLen(1), 6), false
		case c.P1 == 0x00 && c.P2 == 0x83:
			return secret && c.SecretParts() == 2 && qaPartOK(c.PartLen(0), 8) && qaPartOK(c.PartLen(1), 8), false
		}
	case 0xDA: // PUT DATA
		switch tag {
		case 0x00C1, 0x00C3:
			return bytes.Equal(c.Data, qaP384), false
		case 0x00C4:
			return bytes.Equal(c.Data, []byte{0x00}) || bytes.Equal(c.Data, []byte{0x01}), false
		case 0x00C7, 0x00C8, 0x00C9:
			return n == 20, false
		case 0x00CE, 0x00CF, 0x00D0:
			return n == 4, false
		case 0x00D6, 0x00D7, 0x00D8:
			return n == 2 && c.Data[1] == 0x20 && (c.Data[0] == 0x00 || c.Data[0] == 0x01 || c.Data[0] == 0x03), false
		}
	case 0x2A: // PSO: COMPUTE DIGITAL SIGNATURE of a SHA-384 digest
		return tag == 0x9E9A && n == 48, false
	case 0x88: // INTERNAL AUTHENTICATE of the same
		return tag == 0x0000 && n == 48, false
	}
	return false, false
}

// qaSecretCmd is a PIN command: one Secret for a verification, two (the old PIN, then the new one) for a change.
func qaSecretCmd(ins, p1, p2 byte, pins ...[]byte) apdu.Command {
	c := apdu.Command{INS: ins, P1: p1, P2: p2}
	if len(pins) == 2 {
		return c.WithSecretPair(apdu.NewSecret(pins[0]), apdu.NewSecret(pins[1]))
	}
	return c.WithSecretData(apdu.NewSecret(pins[0]))
}

// qaPlain is the same command with its PIN in plain Data: no way to send a PIN.
func qaPlain(ins, p1, p2 byte, pin []byte) apdu.Command {
	return apdu.Command{INS: ins, P1: p1, P2: p2, Data: pin}
}

// qaRows is every command of the list, with the bytes that must reach the card, written by hand
// (CLA INS P1 P2 [Lc data] [Le]), and the name that the table gives it.
type qaRow struct {
	name string
	cmd  apdu.Command
	wire string
	op   string
	ro   bool // a read that a read-only session sends
}

func qaRows(t testing.TB) []qaRow {
	pin6, pin8 := []byte("Xk9#mQ"), []byte("Xk9#mQ2$")
	d20, d4, d48 := bytes.Repeat([]byte{0x11}, 20), []byte{0x65, 0x6B, 0x00, 0x00}, bytes.Repeat([]byte{0x22}, 48)
	h := func(s string) string { return strings.ReplaceAll(s, " ", "") }
	x := func(b []byte) string { return fmt.Sprintf("%x", b) }
	rows := []qaRow{
		{"select the application", apdu.Command{INS: 0xA4, P1: 0x04, Data: qaAID, Le: 256}, h("00A40400 06 D27600012401 00"), "select-application", true},
	}
	for _, tag := range []uint16{0x004F, 0x5F52, 0x006E, 0x00C4, 0x00DE, 0x00F9, 0x00FA, 0x00D6, 0x00D7, 0x00D8, 0x00D9, 0x007A, 0x7F21, 0x7F66, 0x7F74, 0x00FC} {
		rows = append(rows, qaRow{fmt.Sprintf("get data %04X", tag), apdu.Command{INS: 0xCA, P1: byte(tag >> 8), P2: byte(tag), Le: 256},
			fmt.Sprintf("00CA%04X00", tag), "get-data", true})
	}
	for i, crt := range []string{"B600", "A400", "B800"} {
		rows = append(rows,
			qaRow{"read the public key " + crt, apdu.Command{INS: 0x47, P1: 0x81, Data: qaCRTs[i], Le: 256}, h("00478100 02") + crt + "00", "get-public-key", true},
			qaRow{"generate " + crt, apdu.Command{INS: 0x47, P1: 0x80, Data: qaCRTs[i], Le: 256}, h("00478000 02") + crt + "00", "generate-key", false})
	}
	rows = append(rows, qaRow{"firmware version", apdu.Command{INS: 0xF1, Le: 256}, h("00F10000 00"), "get-firmware-version", true})
	for p1 := byte(0); p1 < 3; p1++ {
		rows = append(rows, qaRow{fmt.Sprintf("select data %d", p1), apdu.Command{INS: 0xA5, P1: p1, P2: 0x04, Data: qaSelDO, Le: 256},
			fmt.Sprintf("00A5%02X04 06 60045C027F21 00", p1), "select-data", true})
	}
	rows = append(rows,
		qaRow{"verify user, signing", qaSecretCmd(0x20, 0, 0x81, pin6), h("00200081 06") + x(pin6), "verify-user", false},
		qaRow{"verify user, other uses", qaSecretCmd(0x20, 0, 0x82, pin8), h("00200082 08") + x(pin8), "verify-user", false},
		qaRow{"verify Admin", qaSecretCmd(0x20, 0, 0x83, pin8), h("00200083 08") + x(pin8), "verify-admin", false},
		qaRow{"end verification 81", apdu.Command{INS: 0x20, P1: 0xFF, P2: 0x81}, "0020FF81", "deauthenticate", false},
		qaRow{"end verification 82", apdu.Command{INS: 0x20, P1: 0xFF, P2: 0x82}, "0020FF82", "deauthenticate", false},
		qaRow{"end verification 83", apdu.Command{INS: 0x20, P1: 0xFF, P2: 0x83}, "0020FF83", "deauthenticate", false},
		qaRow{"change user PIN", qaSecretCmd(0x24, 0, 0x81, pin6, pin6), h("00240081 0C") + x(pin6) + x(pin6), "change-user-pin", false},
		qaRow{"change Admin PIN", qaSecretCmd(0x24, 0, 0x83, pin8, pin8), h("00240083 10") + x(pin8) + x(pin8), "change-admin-pin", false},
		qaRow{"change user PIN, the two PINs differ", qaSecretCmd(0x24, 0, 0x81, pin6, []byte("Zr4&vT")), h("00240081 0C") + x(pin6) + x([]byte("Zr4&vT")), "change-user-pin", false},
		qaRow{"attributes SIG", apdu.Command{INS: 0xDA, P2: 0xC1, Data: qaP384}, h("00DA00C1 06 132B81040022"), "put-key-attributes", false},
		qaRow{"attributes AUT", apdu.Command{INS: 0xDA, P2: 0xC3, Data: qaP384}, h("00DA00C3 06 132B81040022"), "put-key-attributes", false},
		qaRow{"PW status 00", apdu.Command{INS: 0xDA, P2: 0xC4, Data: []byte{0}}, h("00DA00C4 01 00"), "put-pw-status", false},
		qaRow{"PW status 01", apdu.Command{INS: 0xDA, P2: 0xC4, Data: []byte{1}}, h("00DA00C4 01 01"), "put-pw-status", false},
	)
	for _, tag := range []uint16{0xC7, 0xC8, 0xC9} {
		rows = append(rows, qaRow{fmt.Sprintf("fingerprint %02X", tag), apdu.Command{INS: 0xDA, P2: byte(tag), Data: d20}, fmt.Sprintf("00DA00%02X14", tag) + x(d20), "put-fingerprint", false})
	}
	for _, tag := range []uint16{0xCE, 0xCF, 0xD0} {
		rows = append(rows, qaRow{fmt.Sprintf("time %02X", tag), apdu.Command{INS: 0xDA, P2: byte(tag), Data: d4}, fmt.Sprintf("00DA00%02X04", tag) + x(d4), "put-creation-time", false})
	}
	for _, tag := range []uint16{0xD6, 0xD7, 0xD8} {
		for _, v := range []byte{0, 1, 3} {
			rows = append(rows, qaRow{fmt.Sprintf("touch %02X %02X", tag, v), apdu.Command{INS: 0xDA, P2: byte(tag), Data: []byte{v, 0x20}},
				fmt.Sprintf("00DA00%02X02%02X20", tag, v), "put-touch-policy", false})
		}
	}
	rows = append(rows,
		qaRow{"sign", apdu.Command{INS: 0x2A, P1: 0x9E, P2: 0x9A, Data: d48, Le: 256}, h("002A9E9A 30") + x(d48) + "00", "compute-signature", false},
		qaRow{"authenticate", apdu.Command{INS: 0x88, Data: d48, Le: 256}, h("00880000 30") + x(d48) + "00", "authenticate", false},
		qaRow{"attest SIG", apdu.Command{CLA: 0x80, INS: 0xFB, P1: 0x01, Le: 256}, h("80FB0100 00"), "generate-attestation", false},
		qaRow{"attest AUT", apdu.Command{CLA: 0x80, INS: 0xFB, P1: 0x03, Le: 256}, h("80FB0300 00"), "generate-attestation", false},
	)
	return rows
}

// TestEveryRowOfTheList: each command of the list passes in a full session with exactly its bytes, is
// refused in a read-only session when it changes the card or uses a key or a PIN (with no call on the
// transport), and passes there when it is a read. Every row of the table is reached by one of them.
func TestEveryRowOfTheList(t *testing.T) {
	reached := map[string]bool{}
	for _, r := range qaRows(t) {
		if ok, ro := qaOracle(r.cmd); !ok || ro != r.ro {
			t.Fatalf("%s: the oracle disagrees with the row (%v %v)", r.name, ok, ro)
		}
		spec, ok := lookup(allowlist, r.cmd, false)
		if !ok || spec.name != r.op {
			t.Errorf("%s: the table names it %v, want %s", r.name, spec, r.op)
			continue
		}
		reached[r.op] = true
		// A full session.
		q := &qaTransport{script: []qaStep{qaOK(0xAB)}}
		s := qaSession(t, q, Options{}, nil)
		got, err := s.send(r.cmd)
		if err != nil || !bytes.Equal(got, []byte{0xAB}) || q.calls() != 1 {
			t.Errorf("%s: %v %x %d calls", r.name, err, got, q.calls())
			continue
		}
		if want := qaHexOf(t, r.wire); !bytes.Equal(q.sent[0], want) {
			t.Errorf("%s: the card gets\n %x\nwant\n %x", r.name, q.sent[0], want)
		}
		// A read-only session.
		q = &qaTransport{script: []qaStep{qaOK(0xAB)}}
		s = qaSession(t, q, Options{ReadOnly: true}, nil)
		got, err = s.send(r.cmd)
		switch {
		case r.ro && (err != nil || !bytes.Equal(got, []byte{0xAB}) || q.calls() != 1 || !bytes.Equal(q.sent[0], qaHexOf(t, r.wire))):
			t.Errorf("%s: a read in a read-only session: %v %d calls", r.name, err, q.calls())
		case !r.ro && (!errors.Is(err, ErrReadOnly) || errors.Is(err, ErrNotAllowed) || q.calls() != 0 || s.Dead()):
			t.Errorf("%s: a write in a read-only session: %v %d calls", r.name, err, q.calls())
		}
	}
	for _, spec := range allowlist {
		if !reached[spec.name] && !spec.internal {
			t.Errorf("row %s is reached by no command of the list", spec.name)
		}
	}
	if reached["get-response"] {
		t.Error("get-response is reached by a caller")
	}
}

// TestUnselectedSessionSendsOnlyTheSelection holds, for every row, that nothing but select-application
// reaches the transport before the application was selected.
func TestUnselectedSessionSendsOnlyTheSelection(t *testing.T) {
	for _, ro := range []bool{false, true} {
		for _, r := range qaRows(t) {
			q := &qaTransport{script: []qaStep{qaOK(), qaOK()}}
			s := qaUnselected(t, q, Options{ReadOnly: ro}, nil)
			_, err := s.send(r.cmd)
			switch {
			case r.op == "select-application":
				if err != nil || q.calls() != 1 {
					t.Errorf("%s: %v", r.name, err)
				}
				if _, err := s.send(qaRows(t)[1].cmd); err != nil && !errors.Is(err, ErrNotSelected) {
					t.Errorf("after the selection: %v", err)
				}
			case ro && !r.ro:
				if !errors.Is(err, ErrReadOnly) || q.calls() != 0 {
					t.Errorf("%s (read-only): %v", r.name, err)
				}
			default:
				if !errors.Is(err, ErrNotSelected) || errors.Is(err, ErrNotAllowed) || q.calls() != 0 || s.Dead() {
					t.Errorf("%s (read-only %v): %v, %d calls", r.name, ro, err, q.calls())
				}
			}
		}
	}
	// A caller's GET RESPONSE is not on the list at any time.
	q := &qaTransport{}
	s := qaUnselected(t, q, Options{}, nil)
	if _, err := s.send(apdu.Command{INS: 0xC0}); !errors.Is(err, ErrNotAllowed) || q.calls() != 0 {
		t.Errorf("GET RESPONSE: %v", err)
	}
}

// qaRig sends every command that a sweep names through a full and a read-only session, and checks the
// answer against the oracle. The commands that the oracle refuses go through two sessions that live
// through the whole sweep, with a transport that has no script: a call on it is a failure on the spot.
type qaRig struct {
	t        *testing.T
	full, ro *Session
	fq, rq   *qaTransport
	sent     int
	allowed  int
}

func newRig(t *testing.T) *qaRig {
	fq, rq := &qaTransport{}, &qaTransport{}
	return &qaRig{t: t, fq: fq, rq: rq, full: qaSession(t, fq, Options{}, nil), ro: qaSession(t, rq, Options{ReadOnly: true}, nil)}
}

func (r *qaRig) check(c apdu.Command) {
	r.t.Helper()
	allowed, readOnly := qaOracle(c)
	r.sent++
	if allowed {
		r.allowed++
		q := &qaTransport{script: []qaStep{qaOK()}}
		if _, err := qaSession(r.t, q, Options{}, nil).send(c); err != nil || q.calls() != 1 {
			r.t.Fatalf("%v: the list allows it and send says %v (%d calls)", c, err, q.calls())
		}
	} else {
		_, err := r.full.send(c)
		if !errors.Is(err, ErrNotAllowed) || errors.Is(err, ErrReadOnly) || r.fq.calls() != 0 {
			r.t.Fatalf("%v: refused in no session, and send says %v (%d calls)\n%s", c, err, r.fq.calls(), qaDump(c))
		}
	}
	switch {
	case allowed && readOnly:
		q := &qaTransport{script: []qaStep{qaOK()}}
		if _, err := qaSession(r.t, q, Options{ReadOnly: true}, nil).send(c); err != nil || q.calls() != 1 {
			r.t.Fatalf("%v: a read, refused in a read-only session: %v", c, err)
		}
	case allowed:
		_, err := r.ro.send(c)
		if !errors.Is(err, ErrReadOnly) || r.rq.calls() != 0 {
			r.t.Fatalf("%v: a write in a read-only session: %v (%d calls)", c, err, r.rq.calls())
		}
	default:
		_, err := r.ro.send(c)
		if !errors.Is(err, ErrNotAllowed) || errors.Is(err, ErrReadOnly) || r.rq.calls() != 0 {
			r.t.Fatalf("%v: refused in no session, read-only says %v (%d calls)", c, err, r.rq.calls())
		}
	}
}

func qaDump(c apdu.Command) string {
	return fmt.Sprintf("CLA %02X INS %02X P1 %02X P2 %02X data %x Le %d", c.CLA, c.INS, c.P1, c.P2, c.Data, c.Le)
}

func (r *qaRig) done(what string, minAllowed int) {
	r.t.Helper()
	if r.fq.calls() != 0 || r.rq.calls() != 0 {
		r.t.Fatalf("%s: a refused command reached the transport", what)
	}
	if r.allowed < minAllowed {
		r.t.Fatalf("%s: only %d commands were allowed, want at least %d: the sweep did not reach the list", what, r.allowed, minAllowed)
	}
}

// TestEveryInstructionByte puts every instruction byte into every command of the list: only the
// instructions of the list pass, and then only with the rest of a command of the list.
func TestEveryInstructionByte(t *testing.T) {
	r := newRig(t)
	rows := qaRows(t)
	for _, row := range rows {
		for ins := range 0x100 {
			c := row.cmd
			c.INS = byte(ins)
			r.check(c)
		}
	}
	r.done("instruction bytes", len(rows))
}

// TestEveryClassByte puts every class byte into every command of the list: the plain class passes, and the
// vendor class 80 only for the attestation. The chaining bit is refused when a caller sets it: send sets
// it itself on the blocks of a chain.
func TestEveryClassByte(t *testing.T) {
	r := newRig(t)
	rows := qaRows(t)
	for _, row := range rows {
		for cla := range 0x100 {
			c := row.cmd
			c.CLA = byte(cla)
			r.check(c)
		}
		for _, bit := range []byte{0x10, 0x90, 0x04, 0x0C, 0x40, 0x80} {
			c := row.cmd
			c.CLA |= bit
			r.check(c)
		}
	}
	r.done("class bytes", len(rows))
}

// TestEveryParameterByte puts every value into P1 and into P2 of every command of the list, one at a time.
func TestEveryParameterByte(t *testing.T) {
	r := newRig(t)
	rows := qaRows(t)
	for _, row := range rows {
		for v := range 0x100 {
			c := row.cmd
			c.P1 = byte(v)
			r.check(c)
			c = row.cmd
			c.P2 = byte(v)
			r.check(c)
		}
	}
	r.done("parameter bytes", len(rows))
}

// TestEveryTagOfReadsAndWrites: GET DATA for all 65536 tags passes for exactly the 16 tags of the list (and
// not for C0 to C3, C5, C6, CD, 73, 93, which the card gives only inside 6E); PUT DATA for all 65536
// tags, with each body that a row of the list takes and with bodies near them, passes for exactly the
// thirteen... the twelve tags of the list.
func TestEveryTagOfReadsAndWrites(t *testing.T) {
	for _, tag := range []uint16{0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C5, 0x00C6, 0x00CD, 0x0073, 0x0093, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x7F48, 0x005F} {
		if ok, _ := qaOracle(apdu.Command{INS: 0xCA, P1: byte(tag >> 8), P2: byte(tag)}); ok {
			t.Fatalf("the oracle reads %04X alone", tag)
		}
	}
	r := newRig(t)
	bodies := [][]byte{nil, {0}, {1}, {2}, {3}, {4}, {0xFF}, {0, 0x20}, {1, 0x20}, {2, 0x20}, {3, 0x20}, {4, 0x20}, make([]byte, 4), make([]byte, 6),
		qaP384, make([]byte, 20), make([]byte, 21), make([]byte, 48), append(bytes.Clone(qaP384), 0xFF), {0x12, 0x2B, 0x81, 0x04, 0x00, 0x22}}
	allowedReads, allowedWrites := 0, 0
	for p := range 0x10000 {
		get := apdu.Command{INS: 0xCA, P1: byte(p >> 8), P2: byte(p), Le: 256}
		if ok, _ := qaOracle(get); ok {
			allowedReads++
		}
		r.check(get)
		for _, b := range bodies {
			put := apdu.Command{INS: 0xDA, P1: byte(p >> 8), P2: byte(p), Data: b}
			if ok, _ := qaOracle(put); ok {
				allowedWrites++
			}
			r.check(put)
		}
	}
	r.done("tags", 16+13)
	if allowedReads != 16 {
		t.Errorf("%d tags are read alone, want 16", allowedReads)
	}
	// By hand: C1 and C3 (one body each, 2), C4 (two bodies, 2), C7 to C9 (one each, 3), CE, CF and D0
	// (one each, 3), D6 to D8 (three bodies each, 9): 19 pairs of a tag and a body.
	if allowedWrites != 19 {
		t.Errorf("%d (tag, body) pairs are written, want 19", allowedWrites)
	}
}

// qaPINOf builds the PIN command of n bytes in secret form: one Secret of n bytes for a verification, two of
// n bytes each for a change (the rule of the row is on each secret by itself).
func qaPINOf(ins, p1, p2 byte, n int) apdu.Command {
	pin := bytes.Repeat([]byte{0x41}, n)
	if ins == 0x24 {
		return qaSecretCmd(ins, p1, p2, pin, pin)
	}
	return qaSecretCmd(ins, p1, p2, pin)
}

// TestPINLengthEdges holds each PIN row, in the secret form, at its edges: each PIN by itself one under, at and
// one over each bound. The same body in plain Data is refused at every length: a PIN in Data is no way to
// send one.
func TestPINLengthEdges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ins    byte
		p1, p2 byte
		min    int
	}{
		{"verify user 81", 0x20, 0, 0x81, 6},
		{"verify user 82", 0x20, 0, 0x82, 6},
		{"verify Admin 83", 0x20, 0, 0x83, 8},
		{"change user PIN", 0x24, 0, 0x81, 6},
		{"change Admin PIN", 0x24, 0, 0x83, 8},
	} {
		r := newRig(t)
		for n := 0; n <= 300; n++ {
			c := qaPINOf(tc.ins, tc.p1, tc.p2, n)
			want := n >= tc.min && n <= 127
			if got, _ := qaOracle(c); got != want {
				t.Fatalf("%s: the oracle is wrong at %d", tc.name, n)
			}
			r.check(c)
			plain := qaPlain(tc.ins, tc.p1, tc.p2, bytes.Repeat([]byte{0x41}, n))
			if got, _ := qaOracle(plain); got {
				t.Fatalf("%s: the oracle allows a PIN in plain Data at %d", tc.name, n)
			}
			r.check(plain)
		}
		r.done(tc.name, 127-tc.min+1)
		// The edges by name, through send, and the text of the refusal.
		for _, n := range []int{tc.min - 1, tc.min, tc.min + 1, 126, 127, 128} {
			q := &qaTransport{script: []qaStep{qaOK()}}
			_, err := qaSession(t, q, Options{}, nil).send(qaPINOf(tc.ins, tc.p1, tc.p2, n))
			if (err == nil) != (n >= tc.min && n <= 127) || (err != nil && (!errors.Is(err, ErrNotAllowed) || q.calls() != 0)) {
				t.Errorf("%s: %d bytes: %v", tc.name, n, err)
			}
		}
	}
	// P1 and P2 of VERIFY and CHANGE: every pair, with each length around the bounds, in the secret form and
	// in plain Data.
	r := newRig(t)
	for p := range 0x10000 {
		for _, n := range []int{0, 5, 6, 7, 8, 9, 127, 128} {
			r.check(qaPINOf(0x20, byte(p>>8), byte(p), n))
			r.check(qaPlain(0x20, byte(p>>8), byte(p), make([]byte, n)))
			r.check(qaPINOf(0x24, byte(p>>8), byte(p), n))
			r.check(qaPlain(0x24, byte(p>>8), byte(p), make([]byte, 2*n)))
		}
	}
	// By hand: VERIFY at 81 and 82 with 6, 7, 8, 9 and 127 bytes (10), at 83 with 8, 9 and 127 (3); the end of a
	// verification at FF81 to FF83 with no body (3, the plain commands of length 0); CHANGE at 81 with two PINs
	// of 6, 7, 8, 9 and 127 (5), at 83 with 8, 9 and 127 (3).
	r.done("verify and change, every P1 and P2", 24)
	if r.allowed != 24 {
		t.Errorf("%d commands allowed, want 24", r.allowed)
	}
}

// TestEverySplitOfAChange: the two PINs of a change are judged each by itself, so a pair that is long enough
// together is refused when one of them is short, wiped or empty. Every pair (old, new) of lengths 0 to 130
// goes through send for the user PIN and the Admin PIN: it passes exactly when each is within its bounds.
func TestEverySplitOfAChange(t *testing.T) {
	for _, tc := range []struct {
		p2  byte
		min int
	}{{0x81, 6}, {0x83, 8}} {
		allowed := 0
		for a := 0; a <= 130; a++ {
			for b := 0; b <= 130; b++ {
				c := qaSecretCmd(0x24, 0, tc.p2, bytes.Repeat([]byte{0x41}, a), bytes.Repeat([]byte{0x42}, b))
				want := a >= tc.min && a <= 127 && b >= tc.min && b <= 127
				q := &qaTransport{script: []qaStep{qaOK()}}
				_, err := qaSession(t, q, Options{}, nil).send(c)
				if (err == nil) != want || (err == nil && q.calls() != 1) || (err != nil && (!errors.Is(err, ErrNotAllowed) || q.calls() != 0)) {
					t.Fatalf("P2 %02X, old %d, new %d: %v, %d calls", tc.p2, a, b, err, q.calls())
				}
				if err == nil {
					allowed++
					// Old, then new, with no separator.
					if len(q.sent[0]) != 5+a+b || !bytes.Equal(q.sent[0][5:5+a], bytes.Repeat([]byte{0x41}, a)) || !bytes.Equal(q.sent[0][5+a:], bytes.Repeat([]byte{0x42}, b)) {
						t.Fatalf("the wire: %x", q.sent[0])
					}
				}
			}
		}
		if want := (127 - tc.min + 1) * (127 - tc.min + 1); allowed != want {
			t.Errorf("P2 %02X: %d pairs allowed, want %d", tc.p2, allowed, want)
		}
	}
	// Named: the sum is long enough and one part is not.
	for name, c := range map[string]apdu.Command{
		"5 and 7 (user)":     qaSecretCmd(0x24, 0, 0x81, bytes.Repeat([]byte{1}, 5), bytes.Repeat([]byte{1}, 7)),
		"7 and 5 (user)":     qaSecretCmd(0x24, 0, 0x81, bytes.Repeat([]byte{1}, 7), bytes.Repeat([]byte{1}, 5)),
		"7 and 9 (Admin)":    qaSecretCmd(0x24, 0, 0x83, bytes.Repeat([]byte{1}, 7), bytes.Repeat([]byte{1}, 9)),
		"9 and 7 (Admin)":    qaSecretCmd(0x24, 0, 0x83, bytes.Repeat([]byte{1}, 9), bytes.Repeat([]byte{1}, 7)),
		"6 and 128 (user)":   qaSecretCmd(0x24, 0, 0x81, bytes.Repeat([]byte{1}, 6), bytes.Repeat([]byte{1}, 128)),
		"128 and 6 (user)":   qaSecretCmd(0x24, 0, 0x81, bytes.Repeat([]byte{1}, 128), bytes.Repeat([]byte{1}, 6)),
		"0 and 20 (user)":    qaSecretCmd(0x24, 0, 0x81, nil, bytes.Repeat([]byte{1}, 20)),
		"20 and 0 (Admin)":   qaSecretCmd(0x24, 0, 0x83, bytes.Repeat([]byte{1}, 20), nil),
		"254 and 0 (user)":   qaSecretCmd(0x24, 0, 0x81, bytes.Repeat([]byte{1}, 254), nil),
		"127 and 127 (user)": qaSecretCmd(0x24, 0, 0x81, bytes.Repeat([]byte{1}, 127), bytes.Repeat([]byte{1}, 128)),
	} {
		q := &qaTransport{script: []qaStep{qaOK()}}
		if _, err := qaSession(t, q, Options{}, nil).send(c); !errors.Is(err, ErrNotAllowed) || q.calls() != 0 {
			t.Errorf("%s: %v, %d calls", name, err, q.calls())
		}
	}
}

// TestSecretFormOfTheOtherRows: a body in secrets is the form of the PIN rows only. Every other row refuses
// it, and so do the PIN rows when the number of secrets is not the number the row holds.
func TestSecretFormOfTheOtherRows(t *testing.T) {
	r := newRig(t)
	for _, row := range qaRows(t) {
		if strings.HasPrefix(row.op, "verify") || strings.HasPrefix(row.op, "change") {
			continue
		}
		c := row.cmd
		c.Data = nil
		for _, n := range []int{0, 1, 2, 4, 6, 20, 48} {
			r.check(c.WithSecretData(apdu.NewSecret(make([]byte, n))))
			r.check(c.WithSecretPair(apdu.NewSecret(make([]byte, n)), apdu.NewSecret(make([]byte, n))))
		}
	}
	// A verification with two secrets, a change with one, and with a secret and plain Data together.
	for _, n := range []int{6, 8, 12, 16, 20} {
		r.check(qaSecretCmd(0x20, 0, 0x81, bytes.Repeat([]byte{1}, n), bytes.Repeat([]byte{1}, n)))
		r.check(qaSecretCmd(0x24, 0, 0x81, bytes.Repeat([]byte{1}, n)))
		both := qaSecretCmd(0x20, 0, 0x81, bytes.Repeat([]byte{1}, n))
		both.Data = []byte{1, 2, 3}
		r.check(both)
		bothPair := qaSecretCmd(0x24, 0, 0x81, bytes.Repeat([]byte{1}, n), bytes.Repeat([]byte{1}, n))
		bothPair.Data = []byte{1}
		r.check(bothPair)
	}
	r.done("the other rows in the secret form", 0)
	if r.allowed != 0 {
		t.Errorf("%d commands allowed", r.allowed)
	}
}

// TestPINCommandNeedingAChainIsRefusedBeforeAnythingIsSent: no row takes a PIN of more than 254 bytes, and a PIN
// is never cut into blocks. A row that would (a table of the tests) refuses a body over 255 bytes with
// ErrDataTooLong before anything is sent, with the session alive, unless the card takes the extended form,
// in which case the PIN goes in one extended command, and the encoded buffer is overwritten.
func TestPINCommandNeedingAChainIsRefusedBeforeAnythingIsSent(t *testing.T) {
	for _, n := range []int{256, 300, 510, 1000, 65535} {
		for _, ext := range []bool{false, true} {
			big := apdu.Command{INS: 0xDA, P1: 0x01, Le: 0}.WithSecretData(apdu.NewSecret(bytes.Repeat([]byte{0x41}, n)))
			q := &qaTransport{ext: ext, script: []qaStep{qaOK()}}
			s := qaSession(t, q, Options{}, qaTable(true, true))
			_, err := s.send(big)
			if !errors.Is(err, apdu.ErrDataTooLong) || q.calls() != 0 || s.Dead() {
				t.Fatalf("%d bytes, ext %v (the card is not told it takes it): %v, %d calls", n, ext, err, q.calls())
			}
		}
		// Told that the card takes it, and the transport takes it: one extended command, no chain.
		q := &qaTransport{ext: true, script: []qaStep{qaOK()}}
		s := qaSession(t, q, Options{}, qaTable(true, true))
		s.allowExtended(70000)
		big := apdu.Command{INS: 0xDA, P1: 0x01}.WithSecretData(apdu.NewSecret(bytes.Repeat([]byte{0x41}, n)))
		if _, err := s.send(big); err != nil || q.calls() != 1 || len(q.sent[0]) != 7+n || q.sent[0][0] != 0x00 {
			t.Fatalf("%d bytes, extended: %v %d calls", n, err, q.calls())
		}
		qaAllZero(t, "the extended command", q.refs)
		// Told, but the body is more than the card takes: a chain would be needed, and is refused.
		q = &qaTransport{ext: true, script: []qaStep{qaOK()}}
		s = qaSession(t, q, Options{}, qaTable(true, true))
		s.allowExtended(300)
		if n > 291 {
			if _, err := s.send(big); !errors.Is(err, apdu.ErrDataTooLong) || q.calls() != 0 || s.Dead() {
				t.Fatalf("%d bytes over what the card takes: %v, %d calls", n, err, q.calls())
			}
		}
	}
	// The same body without the secret form is a chain, as before, for a row that is not a PIN row.
	q := &qaTransport{script: []qaStep{qaOK(), qaOK()}}
	if _, err := qaSession(t, q, Options{}, qaTable(false, true)).send(qaPut(300, 0)); err != nil || q.calls() != 2 {
		t.Fatalf("%v %d", err, q.calls())
	}
}

// A change of the PIN whose old PIN was wiped, or is empty, is refused with nothing sent, whatever the other PIN
// is: the allowlist counts a wiped secret as a secret of length 0, and judges each part by itself. Earlier
// the sum of the two was judged, and a long new PIN alone passed and went on the wire as if it were both.
func TestChangeWithAPartMissingIsRefused(t *testing.T) {
	wiped := func(n int) apdu.Secret {
		s := apdu.NewSecret(bytes.Repeat([]byte{0x41}, n))
		s.Wipe()
		return s
	}
	live := func(n int) apdu.Secret { return apdu.NewSecret(bytes.Repeat([]byte{0x42}, n)) }
	for name, c := range map[string]apdu.Command{
		"user, old wiped":         apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(wiped(6), live(14)),
		"user, new wiped":         apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(live(14), wiped(6)),
		"user, new empty":         apdu.Command{INS: 0x24, P2: 0x81}.WithSecretPair(live(12), apdu.NewSecret(nil)),
		"Admin, old empty":        apdu.Command{INS: 0x24, P2: 0x83}.WithSecretPair(apdu.NewSecret(nil), live(20)),
		"Admin, both wiped, long": apdu.Command{INS: 0x24, P2: 0x83}.WithSecretPair(wiped(100), wiped(100)),
	} {
		for _, ro := range []bool{false, true} {
			q := &qaTransport{script: []qaStep{qaOK()}}
			s := qaSession(t, q, Options{ReadOnly: ro}, nil)
			if _, err := s.send(c); err == nil || q.calls() != 0 || s.Dead() {
				t.Errorf("%s (read-only %v): sent, %d calls, wire %x", name, ro, q.calls(), q.sent)
			}
		}
	}
}

// TestTouchSettingEveryValue writes every value byte and every second byte to every tag of the touch
// objects D6 to D9 (and to the three objects near them): only 00, 01 and 03 with the second byte 20, to
// D6, D7 and D8. The two values that cannot be undone (02 fixed, 04 cached and fixed) and every value the
// specification does not define are refused, and so is D9, the touch setting of the attestation key.
func TestTouchSettingEveryValue(t *testing.T) {
	r := newRig(t)
	for _, tag := range []byte{0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA} {
		for v := range 0x100 {
			for second := range 0x100 {
				r.check(apdu.Command{INS: 0xDA, P2: tag, Data: []byte{byte(v), byte(second)}})
			}
			r.check(apdu.Command{INS: 0xDA, P2: tag, Data: []byte{byte(v)}})
			r.check(apdu.Command{INS: 0xDA, P2: tag, Data: []byte{byte(v), 0x20, 0x00}})
		}
	}
	r.done("touch values", 9)
	for _, v := range []byte{0x02, 0x04} {
		for _, tag := range []byte{0xD6, 0xD7, 0xD8, 0xD9} {
			q := &qaTransport{}
			_, err := qaSession(t, q, Options{}, nil).send(apdu.Command{INS: 0xDA, P2: tag, Data: []byte{v, 0x20}})
			if !errors.Is(err, ErrNotAllowed) || q.calls() != 0 {
				t.Errorf("touch %02X to %02X: %v", v, tag, err)
			}
		}
	}
}

// TestKeyAttributeBodies: for the slots C1, C2 and C3, every body of 0 to 16 bytes that is one change, one
// added byte or one removed byte away from the allowed attribute bytes, and every length of zeros: only the
// ECDSA P-384 bytes, to the signature and the authentication slot.
func TestKeyAttributeBodies(t *testing.T) {
	var bodies [][]byte
	for n := 0; n <= 16; n++ {
		bodies = append(bodies, make([]byte, n))
	}
	for i := range qaP384 {
		for v := range 0x100 {
			b := bytes.Clone(qaP384)
			b[i] = byte(v)
			bodies = append(bodies, b)
		}
		bodies = append(bodies, slices.Delete(bytes.Clone(qaP384), i, i+1))
	}
	for i := 0; i <= len(qaP384); i++ {
		for v := range 0x100 {
			bodies = append(bodies, slices.Insert(bytes.Clone(qaP384), i, byte(v)))
		}
	}
	// The vendor's other curves and RSA, as a card lists them.
	bodies = append(bodies,
		[]byte{0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
		[]byte{0x13, 0x2B, 0x81, 0x04, 0x00, 0x23},
		[]byte{0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01},
		[]byte{0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01},
		[]byte{0x01, 0x08, 0x00, 0x00, 0x20, 0x00})
	r := newRig(t)
	seen := map[string]bool{}
	for _, slot := range []byte{0xC0, 0xC1, 0xC2, 0xC3} {
		for _, b := range bodies {
			if key := string(rune(slot)) + string(b); seen[key] { // a change to the value a byte has is no change
				continue
			} else {
				seen[key] = true
			}
			r.check(apdu.Command{INS: 0xDA, P2: slot, Data: b})
		}
	}
	r.done("attributes", 2)
	if r.allowed != 2 { // the one body, in the slots C1 and C3
		t.Fatalf("%d (slot, body) pairs were allowed, want 2", r.allowed)
	}
}

// TestCallerGetResponse: GET RESPONSE asked for by a caller is refused, whatever its parameters, data and
// class; only send itself asks for it, after an answer 61xx.
func TestCallerGetResponse(t *testing.T) {
	r := newRig(t)
	for p := range 0x10000 {
		for _, le := range []int{0, 1, 256} {
			r.check(apdu.Command{INS: 0xC0, P1: byte(p >> 8), P2: byte(p), Le: le})
		}
	}
	for cla := range 0x100 {
		r.check(apdu.Command{CLA: byte(cla), INS: 0xC0, Le: 256})
		r.check(apdu.Command{CLA: byte(cla), INS: 0xC0, Data: []byte{1}})
	}
	r.done("GET RESPONSE", 0)
	// And send itself does ask for it, in a read-only session as well.
	for _, ro := range []bool{false, true} {
		q := &qaTransport{script: []qaStep{qaSW(0x61, 0x02, 0x01), qaOK(0x02, 0x03)}}
		got, err := qaSession(t, q, Options{ReadOnly: ro}, nil).send(apdu.Command{INS: 0xCA, P2: 0x4F, Le: 256})
		if err != nil || !bytes.Equal(got, []byte{1, 2, 3}) || q.calls() != 2 || !bytes.Equal(q.sent[1], []byte{0x00, 0xC0, 0x00, 0x00, 0x02}) {
			t.Errorf("read-only %v: %v %x %x", ro, err, got, q.sent)
		}
	}
}

// TestNeverSentCommands: the commands that must never be sent are refused in both modes, with every
// parameter pair and with data of every length that the nearest row takes; nothing reaches the transport.
func TestNeverSentCommands(t *testing.T) {
	r := newRig(t)
	for _, ins := range []byte{0xE6, 0x44, 0x2C, 0xDB, 0x4D, 0x84, 0x0E, 0xD6, 0xDC, 0xE2, 0xE4, 0xA8} {
		for _, n := range []int{0, 1, 2, 6, 8, 16, 20, 48, 100} {
			for _, cla := range []byte{0x00, 0x80, 0x10} {
				for _, p := range []uint16{0x0000, 0x0001, 0x0002, 0x0081, 0x0083, 0x3FFF, 0x8000, 0x8100, 0x9E9A, 0xFF81, 0x0100} {
					r.check(apdu.Command{CLA: cla, INS: ins, P1: byte(p >> 8), P2: byte(p), Data: make([]byte, n), Le: 256})
				}
			}
		}
	}
	// The listed forms of the commands that must never be sent, by name.
	for name, c := range map[string]apdu.Command{
		"terminate":                            {INS: 0xE6},
		"activate":                             {INS: 0x44},
		"reset retry counter, Admin":           {INS: 0x2C, P1: 0x02, P2: 0x81, Data: make([]byte, 16)},
		"reset retry counter, code":            {INS: 0x2C, P1: 0x00, P2: 0x81, Data: make([]byte, 16)},
		"import key":                           {INS: 0xDB, P1: 0x3F, P2: 0xFF, Data: make([]byte, 100)},
		"decipher":                             {INS: 0x2A, P1: 0x80, P2: 0x86, Data: make([]byte, 100)},
		"get challenge":                        {INS: 0x84, Le: 8},
		"write the CA fingerprints":            {INS: 0xDA, P2: 0xCA, Data: make([]byte, 20)},
		"write the times list":                 {INS: 0xDA, P2: 0xCD, Data: make([]byte, 12)},
		"write the attestation touch":          {INS: 0xDA, P2: 0xD9, Data: []byte{1, 0x20}},
		"generate the attestation key":         {INS: 0x47, P1: 0x80, Data: []byte{0xB6, 0x03, 0x84, 0x01, 0x81}},
		"attest the decryption key":            {CLA: 0x80, INS: 0xFB, P1: 0x02},
		"verify with no PIN":                   {INS: 0x20, P2: 0x81},
		"write the key attributes of the DEC":  {INS: 0xDA, P2: 0xC2, Data: qaP384},
		"write a certificate":                  {INS: 0xDA, P1: 0x7F, P2: 0x21, Data: make([]byte, 100)},
		"write the key derivation function":    {INS: 0xDA, P2: 0xF9, Data: []byte{0x81, 0x01, 0x00}},
		"write the attestation certificate":    {INS: 0xDA, P2: 0xFC, Data: make([]byte, 100)},
		"write the cardholder name":            {INS: 0xDA, P1: 0x00, P2: 0x5B, Data: []byte("A")},
		"write the resetting code":             {INS: 0xDA, P2: 0xD3, Data: make([]byte, 8)},
		"read the extended capabilities alone": {INS: 0xCA, P2: 0xC0},
	} {
		r.t.Run(name, func(t *testing.T) {
			if ok, _ := qaOracle(c); ok {
				t.Fatal("the oracle allows it")
			}
		})
		r.check(c)
	}
	r.done("never sent", 0)
}
