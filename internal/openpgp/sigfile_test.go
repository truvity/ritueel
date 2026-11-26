package openpgp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"ritueel.id/ritueel/internal/keystore/software"
	"ritueel.id/ritueel/internal/openpgp"
)

// ReadSignatureFile returns the one signature packet that a stored file holds: the binary packet, or
// exactly one armour block of type PGP SIGNATURE with no header or `Comment: TEST ONLY`, whose CRC-24
// line is checked, in the form that go-crypto writes. The tests write the armour with a writer of their
// own and a CRC-24 of their own, and check that writer against go-crypto's before they trust it.

// crc24 is the checksum of RFC 9580, section 6.1, written for the tests apart from the code under test.
func crc24(data []byte) uint32 {
	crc := uint32(0xB704CE)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for range 8 {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864CFB
			}
		}
	}
	return crc & 0xFFFFFF
}

// armourOpts say how the tests' own writer departs from the text that go-crypto writes.
type armourOpts struct {
	typ     string   // default "PGP SIGNATURE"
	headers []string // lines such as "Comment: TEST ONLY"
	width   int      // characters of a line of the body; default 64
	eol     string   // line end; default "\n"
	noCRC   bool
	crcXOR  uint32 // XORed into the checksum
	crcRaw  string // when set, the whole CRC line
	final   string // after the end line; default "\n"
	noBlank bool   // no empty line after the headers
	endType string // the type of the end line; default: typ
	noEnd   bool
}

func (o armourOpts) text(body []byte) []byte {
	typ, width, eol, final, endType := o.typ, o.width, o.eol, o.final, o.endType
	if typ == "" {
		typ = "PGP SIGNATURE"
	}
	if width == 0 {
		width = 64
	}
	if eol == "" {
		eol = "\n"
	}
	if final == "" && o.final != "none" {
		final = "\n"
	}
	if o.final == "none" {
		final = ""
	}
	if endType == "" {
		endType = typ
	}
	var b strings.Builder
	b.WriteString("-----BEGIN " + typ + "-----" + eol)
	for _, h := range o.headers {
		b.WriteString(h + eol)
	}
	if !o.noBlank {
		b.WriteString(eol)
	}
	enc := base64.StdEncoding.EncodeToString(body)
	for len(enc) > 0 {
		n := min(width, len(enc))
		b.WriteString(enc[:n] + eol)
		enc = enc[n:]
	}
	switch {
	case o.crcRaw != "":
		b.WriteString(o.crcRaw + eol)
	case !o.noCRC:
		c := crc24(body) ^ o.crcXOR
		b.WriteString("=" + base64.StdEncoding.EncodeToString([]byte{byte(c >> 16), byte(c >> 8), byte(c)}) + eol)
	}
	if !o.noEnd {
		b.WriteString("-----END " + endType + "-----")
		b.WriteString(final)
	}
	return []byte(b.String())
}

// goCryptoArmour is what go-crypto writes for a block, with no byte after the end line.
func goCryptoArmour(t testing.TB, typ string, header map[string]string, body []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := armor.Encode(&b, typ, header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

var testOnly = map[string]string{"Comment": "TEST ONLY"}

func fileSafely(t testing.TB, what string, in []byte) (pkt []byte, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: ReadSignatureFile panicked: %v", what, r)
			pkt, err = nil, errors.New("panic")
		}
	}()
	return openpgp.ReadSignatureFile(in)
}

// assertFile reads a file that must be accepted and holds want.
func assertFile(t testing.TB, what string, in, want []byte) {
	t.Helper()
	before := bytes.Clone(in)
	got, err := fileSafely(t, what, in)
	if err != nil {
		t.Errorf("%s: ReadSignatureFile: %v", what, err)
		return
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s: the packet has %d bytes and is not the one that was stored (%d bytes)", what, len(got), len(want))
	}
	if !bytes.Equal(in, before) {
		t.Errorf("%s: ReadSignatureFile changed its input", what)
	}
}

// assertFileRefused reads a file that must be refused with an ErrSignatureFile, no packet, a text of
// one short line that holds no byte of the file, and the words given.
func assertFileRefused(t testing.TB, what string, in []byte, words ...string) {
	t.Helper()
	before := bytes.Clone(in)
	got, err := fileSafely(t, what, in)
	if err == nil {
		t.Errorf("%s: no error, want an ErrSignatureFile (%d bytes returned)", what, len(got))
		return
	}
	if got != nil {
		t.Errorf("%s: %d bytes were returned with the error %v", what, len(got), err)
	}
	if !errors.Is(err, openpgp.ErrSignatureFile) {
		t.Errorf("%s: error = %v, want an ErrSignatureFile", what, err)
	}
	for _, other := range []error{openpgp.ErrRevocation, openpgp.ErrCertificateForm, openpgp.ErrKeyring, openpgp.ErrParams, openpgp.ErrAnswer} {
		if errors.Is(err, other) {
			t.Errorf("%s: error %v is also %v", what, err, other)
		}
	}
	if !bytes.Equal(in, before) {
		t.Errorf("%s: ReadSignatureFile changed its input", what)
	}
	checkErrorText(t, what, err)
	for _, bad := range []string{"Example", "<script>", "SECRET"} {
		if strings.Contains(err.Error(), bad) && !strings.Contains(what, "text of the file") {
			t.Errorf("%s: the text %q holds %q from the file", what, err.Error(), bad)
		}
	}
	for _, w := range words {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%s: the text %q does not hold %q", what, err.Error(), w)
		}
	}
}

// aRevocation is a revocation signature packet of a primary of the tests.
func aRevocation(t testing.TB) []byte {
	t.Helper()
	return newRevKit(t, "file").made(t, openpgp.Compromised)
}

func TestTheTestsOwnArmourWriterWritesWhatGoCryptoWrites(t *testing.T) {
	for _, n := range []int{1, 2, 3, 47, 48, 49, 100, 150, 151, 152, 1024} {
		body := bytes.Repeat([]byte{0xA5, 0x3C, 0x00, 0xFF}, n)[:n]
		want := goCryptoArmour(t, "PGP SIGNATURE", testOnly, body)
		got := armourOpts{headers: []string{"Comment: TEST ONLY"}, final: "none"}.text(body)
		if !bytes.Equal(got, want) {
			t.Errorf("%d bytes: the tests' writer gives\n%q\nand go-crypto\n%q", n, got, want)
		}
		want = goCryptoArmour(t, "PGP SIGNATURE", nil, body)
		got = armourOpts{final: "none"}.text(body)
		if !bytes.Equal(got, want) {
			t.Errorf("%d bytes, no header: the tests' writer gives\n%q\nand go-crypto\n%q", n, got, want)
		}
	}
}

func TestReadSignatureFileReadsTheBinaryPacket(t *testing.T) {
	k := newRevKit(t, "binary")
	for _, c := range allReasons {
		t.Run(c.name, func(t *testing.T) {
			pkt := k.made(t, c.r)
			assertFile(t, c.name, pkt, pkt)
		})
	}
}

func TestReadSignatureFileReadsTheArmourOfAPacket(t *testing.T) {
	k := newRevKit(t, "armour")
	for _, c := range allReasons {
		pkt := k.made(t, c.r)
		for name, text := range map[string][]byte{
			"go-crypto, TEST ONLY":               goCryptoArmour(t, "PGP SIGNATURE", testOnly, pkt),
			"go-crypto, TEST ONLY, a final LF":   append(goCryptoArmour(t, "PGP SIGNATURE", testOnly, pkt), '\n'),
			"go-crypto, no header":               goCryptoArmour(t, "PGP SIGNATURE", nil, pkt),
			"go-crypto, no header, a final LF":   append(goCryptoArmour(t, "PGP SIGNATURE", nil, pkt), '\n'),
			"the tests' writer, TEST ONLY":       armourOpts{headers: []string{"Comment: TEST ONLY"}}.text(pkt),
			"the tests' writer, no header":       armourOpts{}.text(pkt),
			"the tests' writer, no final LF":     armourOpts{final: "none"}.text(pkt),
			"the tests' writer, 64 characters":   armourOpts{width: 64}.text(pkt),
			"the tests' writer, TEST ONLY, none": armourOpts{headers: []string{"Comment: TEST ONLY"}, final: "none"}.text(pkt),
		} {
			t.Run(c.name+", "+name, func(t *testing.T) { assertFile(t, name, text, pkt) })
		}
	}
}

// The armour of every size of packet up to the limit of 1 KiB is read, one byte more is refused: the
// limit holds for the armour as it does for the binary file.
func TestReadSignatureFileHoldsThePacketToOneKibibyte(t *testing.T) {
	sized := func(n int) []byte {
		// A signature packet of n bytes with its header, whatever it holds: the reader judges the frame.
		var body []byte
		switch {
		case n-2 < 192:
			body = bytes.Repeat([]byte{4}, n-2)
		default:
			body = bytes.Repeat([]byte{4}, n-3)
		}
		pkt := wrap(tagSignature, body)
		if len(pkt) != n {
			t.Fatalf("the test made %d bytes, wanted %d", len(pkt), n)
		}
		return pkt
	}
	for _, n := range []int{3, 100, 191, 192, 193, 1000, 1023, 1024} {
		pkt := sized(n)
		assertFile(t, fmt.Sprintf("binary, %d bytes", n), pkt, pkt)
		assertFile(t, fmt.Sprintf("armour, %d bytes", n), goCryptoArmour(t, "PGP SIGNATURE", testOnly, pkt), pkt)
	}
	for _, n := range []int{1025, 1026, 2000, 4000} {
		pkt := sized(n)
		assertFileRefused(t, fmt.Sprintf("binary, %d bytes", n), pkt, "longer than 1024")
		assertFileRefused(t, fmt.Sprintf("armour, %d bytes", n), goCryptoArmour(t, "PGP SIGNATURE", testOnly, pkt), "longer than 1024")
	}
}

// The file is checked against 8 KiB before anything is read: a file of one byte more is refused with the
// text of the size, and a file of exactly 8 KiB is read (and refused for what it is).
func TestReadSignatureFileChecksTheSizeOfTheFileFirst(t *testing.T) {
	rev := aRevocation(t)
	if openpgp.MaxSignatureFileBytes != 8192 {
		t.Fatalf("MaxSignatureFileBytes is %d, the page says 8 KiB", openpgp.MaxSignatureFileBytes)
	}
	for name, in := range map[string][]byte{
		"zeros":                 make([]byte, openpgp.MaxSignatureFileBytes+1),
		"the start of a packet": cat(rev, make([]byte, openpgp.MaxSignatureFileBytes+1-len(rev))),
		"the start of armour":   cat([]byte("-----BEGIN PGP SIGNATURE-----\n\n"), bytes.Repeat([]byte("A"), openpgp.MaxSignatureFileBytes)),
		"an age file":           cat([]byte("age-encryption.org/v1\n"), make([]byte, openpgp.MaxSignatureFileBytes)),
		"a megabyte":            make([]byte, 1<<20),
	} {
		t.Run(name, func(t *testing.T) { assertFileRefused(t, name, in, "longer than 8192") })
	}
	for name, in := range map[string][]byte{
		"zeros":     make([]byte, openpgp.MaxSignatureFileBytes),
		"armour":    cat([]byte("-----BEGIN PGP SIGNATURE-----\n\n"), bytes.Repeat([]byte("A"), openpgp.MaxSignatureFileBytes-31)),
		"an age":    cat([]byte("age-encryption.org/v1\n"), make([]byte, openpgp.MaxSignatureFileBytes-22)),
		"a packet":  cat(rev, make([]byte, openpgp.MaxSignatureFileBytes-len(rev))),
		"all 0xFF":  bytes.Repeat([]byte{0xFF}, openpgp.MaxSignatureFileBytes),
		"all dash":  bytes.Repeat([]byte("-"), openpgp.MaxSignatureFileBytes),
		"all lines": bytes.Repeat([]byte("\n"), openpgp.MaxSignatureFileBytes),
	} {
		t.Run("exactly 8 KiB, "+name, func(t *testing.T) {
			if len(in) != openpgp.MaxSignatureFileBytes {
				t.Fatalf("the test input has %d bytes", len(in))
			}
			assertFileRefused(t, name, in)
			if _, err := openpgp.ReadSignatureFile(in); err != nil && strings.Contains(err.Error(), "longer than 8192") {
				t.Errorf("a file of exactly 8 KiB is refused as too long: %v", err)
			}
		})
	}
}

// The reader judges the container and the frame, not the signature: a packet that is a whole signature
// packet with a body that no signature has is returned, and ReadRevocation is what refuses it.
func TestReadSignatureFileJudgesTheFrameAndNotTheSignature(t *testing.T) {
	k := newRevKit(t, "frame")
	for name, pkt := range map[string][]byte{
		"an empty body":      {0xC2, 0x00},
		"a body of one byte": {0xC2, 0x01, 0x04},
		"a body of zeros":    wrap(tagSignature, make([]byte, 100)),
	} {
		t.Run(name, func(t *testing.T) {
			assertFile(t, name, pkt, pkt)
			assertFile(t, name+" armoured", goCryptoArmour(t, "PGP SIGNATURE", testOnly, pkt), pkt)
			k.assertNotRevoked(t, name, pkt, false)
		})
	}
}

func TestReadSignatureFileRefusesWhatIsNotOneSignature(t *testing.T) {
	pkt := aRevocation(t)
	body := bodyOf(t, pkt)
	other := newKeyringPrimary(t, "B", true)
	for _, c := range []struct {
		name string
		in   []byte
		want []string
	}{
		{"the empty file", []byte{}, []string{"empty"}},
		{"a nil file", nil, []string{"empty"}},
		{"one byte", []byte{0xC2}, nil},
		{"a text file", []byte("hello\n"), nil},
		{"the hexadecimal of the packet", []byte(fmt.Sprintf("%x\n", pkt)), nil},
		{"the base64 of the packet with no armour", []byte(base64.StdEncoding.EncodeToString(pkt)), nil},
		{"a cut packet", pkt[:len(pkt)-1], nil},
		{"a second packet after the first", cat(pkt, pkt), []string{"after"}},
		{"a zero byte after the packet", cat(pkt, []byte{0}), []string{"after"}},
		{"a packet in the old format", oldHeader(tagSignature, body), []string{"shortest"}},
		{"a packet with a five-octet header", wrapLong(tagSignature, body), []string{"shortest"}},
		{"a packet with an old four-octet header", mustForm(t, "old4", tagSignature, body), []string{"shortest"}},
		{"a partial length", cat([]byte{0xC2, 0xE0}, body), nil},
		{"an indeterminate length", cat([]byte{0x80 | tagSignature<<2 | 3}, body), nil},
		{"a length past the file", cat([]byte{0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, body), nil},
		{"a key packet", wrap(tagPublicKey, body), []string{"not a Signature"}},
		{"a subkey packet", wrap(tagSubkey, body), []string{"not a Signature"}},
		{"a user ID packet", other.uidPacket(), []string{"not a Signature"}},
		{"a literal data packet", wrap(11, []byte("hello")), []string{"not a Signature"}},
		{"a public key as the binary file", other.keyPacket(), []string{"not a Signature"}},
		{"a whole certificate", other.cert(t), []string{"not a Signature"}},
		{"a signature and a key", cat(pkt, other.keyPacket()), []string{"after"}},
		{"a one-pass signature packet", wrap(4, []byte{3, 0, 9, 19, 1, 2, 3, 4, 5, 6, 7, 8, 1}), []string{"not a Signature"}},
	} {
		t.Run(c.name, func(t *testing.T) { assertFileRefused(t, c.name, c.in, c.want...) })
	}
}

func mustForm(t testing.TB, form string, tag byte, body []byte) []byte {
	t.Helper()
	pkt, ok := packetIn(form, tag, body)
	if !ok {
		t.Fatalf("the form %s does not hold the body", form)
	}
	return pkt
}

func TestReadSignatureFileRefusesArmourThatIsNotExactlyOneBlockOfASignature(t *testing.T) {
	pkt := aRevocation(t)
	body := bodyOf(t, pkt)
	good := armourOpts{headers: []string{"Comment: TEST ONLY"}}.text(pkt)
	assertFile(t, "the control", good, pkt)
	other := newKeyringPrimary(t, "B", true)
	for _, c := range []struct {
		name string
		in   []byte
		want []string
	}{
		// the checksum
		{"a wrong CRC-24", armourOpts{headers: []string{"Comment: TEST ONLY"}, crcXOR: 1}.text(pkt), []string{"CRC-24"}},
		{"a CRC-24 that differs in the top byte", armourOpts{headers: []string{"Comment: TEST ONLY"}, crcXOR: 1 << 16}.text(pkt), []string{"CRC-24"}},
		{"a CRC-24 that differs in the middle byte", armourOpts{headers: []string{"Comment: TEST ONLY"}, crcXOR: 1 << 8}.text(pkt), []string{"CRC-24"}},
		{"a CRC-24 of zero", armourOpts{headers: []string{"Comment: TEST ONLY"}, crcRaw: "=AAAA"}.text(pkt), []string{"CRC-24"}},
		{"no CRC-24 line", armourOpts{headers: []string{"Comment: TEST ONLY"}, noCRC: true}.text(pkt), nil},
		{"a CRC-24 line with no equals sign", armourOpts{headers: []string{"Comment: TEST ONLY"}, crcRaw: base64.StdEncoding.EncodeToString([]byte{1, 2, 3})}.text(pkt), nil},
		{"a CRC-24 line of five bytes", armourOpts{headers: []string{"Comment: TEST ONLY"}, crcRaw: "=AAAAAA"}.text(pkt), nil},
		{"a CRC-24 line that is not base64", armourOpts{headers: []string{"Comment: TEST ONLY"}, crcRaw: "=!!!!"}.text(pkt), nil},
		{"two CRC-24 lines", cat(bytes.TrimSuffix(good, []byte("-----END PGP SIGNATURE-----\n")), []byte("=AAAA\n-----END PGP SIGNATURE-----\n")), nil},
		// the headers
		{"another header line", armourOpts{headers: []string{"Comment: something else"}}.text(pkt), []string{"header"}},
		{"a Version header", armourOpts{headers: []string{"Version: example 1.0"}}.text(pkt), []string{"header"}},
		{"two header lines", armourOpts{headers: []string{"Comment: TEST ONLY", "Version: example 1.0"}}.text(pkt), []string{"header"}},
		{"the comment twice", armourOpts{headers: []string{"Comment: TEST ONLY", "Comment: TEST ONLY"}}.text(pkt), nil},
		{"the comment in lower case", armourOpts{headers: []string{"Comment: test only"}}.text(pkt), []string{"header"}},
		{"the comment with a space after", armourOpts{headers: []string{"Comment: TEST ONLY "}}.text(pkt), nil},
		{"an empty comment", armourOpts{headers: []string{"Comment: "}}.text(pkt), []string{"header"}},
		{"a header of a name that is not allowed", armourOpts{headers: []string{"Hash: SHA384"}}.text(pkt), []string{"header"}},
		{"a header that is not valid UTF-8", armourOpts{headers: []string{"Comment: \xff\xfe"}}.text(pkt), nil},
		{"no empty line after the header", armourOpts{headers: []string{"Comment: TEST ONLY"}, noBlank: true}.text(pkt), nil},
		// the lines
		{"CRLF line ends", armourOpts{headers: []string{"Comment: TEST ONLY"}, eol: "\r\n"}.text(pkt), nil},
		{"CR line ends", armourOpts{headers: []string{"Comment: TEST ONLY"}, eol: "\r"}.text(pkt), nil},
		{"lines of 76 characters", armourOpts{headers: []string{"Comment: TEST ONLY"}, width: 76}.text(pkt), nil},
		{"lines of 32 characters", armourOpts{headers: []string{"Comment: TEST ONLY"}, width: 32}.text(pkt), nil},
		{"lines of 65 characters", armourOpts{headers: []string{"Comment: TEST ONLY"}, width: 65}.text(pkt), nil},
		{"one long line", armourOpts{headers: []string{"Comment: TEST ONLY"}, width: 4000}.text(pkt), nil},
		// before and after
		{"a line end before the block", cat([]byte("\n"), good), nil},
		{"a space before the block", cat([]byte(" "), good), nil},
		{"text before the block", cat([]byte("a note\n"), good), []string{"not a whole packet"}},
		{"a byte-order mark before the block", cat([]byte{0xEF, 0xBB, 0xBF}, good), nil},
		{"a zero byte before the block", cat([]byte{0}, good), nil},
		{"a second line end after the block", cat(good, []byte("\n")), nil},
		{"text after the block", cat(good, []byte("a note\n")), nil},
		{"a space after the end line", cat(bytes.TrimSuffix(good, []byte("\n")), []byte(" \n")), nil},
		{"a CRLF after the end line", cat(bytes.TrimSuffix(good, []byte("\n")), []byte("\r\n")), nil},
		{"a zero byte after the block", cat(good, []byte{0}), nil},
		{"a second block", cat(good, good), []string{"second"}},
		{"a second block with no line end between", cat(bytes.TrimSuffix(good, []byte("\n")), good), nil},
		{"a second block of another kind", cat(good, armourOpts{typ: "PGP PUBLIC KEY BLOCK"}.text(other.cert(t))), []string{"second"}},
		{"the same block twice with a note between", cat(good, []byte("note\n"), good), nil},
		{"a block and a binary packet after it", cat(good, pkt), nil},
		{"a binary packet and a block after it", cat(pkt, good), nil},
		// the kind
		{"a public key block", armourOpts{typ: "PGP PUBLIC KEY BLOCK"}.text(other.cert(t)), []string{"PGP SIGNATURE"}},
		{"a private key block", armourOpts{typ: "PGP PRIVATE KEY BLOCK"}.text(other.cert(t)), []string{"PGP SIGNATURE"}},
		{"a message block", armourOpts{typ: "PGP MESSAGE"}.text(pkt), []string{"PGP SIGNATURE"}},
		{"a signed message block", armourOpts{typ: "PGP SIGNED MESSAGE"}.text(pkt), nil},
		{"a block of the type SIGNATURE", armourOpts{typ: "SIGNATURE"}.text(pkt), nil},
		{"a block of the type in lower case", armourOpts{typ: "pgp signature"}.text(pkt), nil},
		{"a block of a type with a space after", armourOpts{typ: "PGP SIGNATURE "}.text(pkt), nil},
		{"a public key block that holds a signature packet", armourOpts{typ: "PGP PUBLIC KEY BLOCK"}.text(pkt), []string{"PGP SIGNATURE"}},
		{"a signature block that holds a key", armourOpts{}.text(other.cert(t)), nil},
		{"an age armour block", cat([]byte("-----BEGIN AGE ENCRYPTED FILE-----\n"), []byte("YWdlLWVuY3J5cHRpb24ub3JnL3YxCg==\n-----END AGE ENCRYPTED FILE-----\n")), []string{"age", "not read here"}},
		{"an age armour block of a signature size", armourOpts{typ: "AGE ENCRYPTED FILE"}.text(pkt), []string{"age", "not read here"}},
		// the ends
		{"no end line", armourOpts{headers: []string{"Comment: TEST ONLY"}, noEnd: true}.text(pkt), nil},
		{"an end line of another type", armourOpts{headers: []string{"Comment: TEST ONLY"}, endType: "PGP MESSAGE"}.text(pkt), nil},
		{"an end line cut", bytes.TrimSuffix(good, []byte("-\n")), nil},
		{"only the begin line", []byte("-----BEGIN PGP SIGNATURE-----\n"), nil},
		{"only the begin line, no line end", []byte("-----BEGIN PGP SIGNATURE-----"), nil},
		{"the begin line and the end line", []byte("-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n"), nil},
		{"a begin line with three dashes less", []byte("--BEGIN PGP SIGNATURE-----\n\nAA==\n-----END PGP SIGNATURE-----\n"), nil},
		{"a begin line with a space after", cat([]byte("-----BEGIN PGP SIGNATURE----- \n"), good[len("-----BEGIN PGP SIGNATURE-----\n"):]), nil},
		// the body
		{"an empty body", armourOpts{headers: []string{"Comment: TEST ONLY"}}.text(nil), nil},
		{"a body that is a packet and a byte", armourOpts{headers: []string{"Comment: TEST ONLY"}}.text(cat(pkt, []byte{0})), []string{"after"}},
		{"a body that is two packets", armourOpts{headers: []string{"Comment: TEST ONLY"}}.text(cat(pkt, pkt)), []string{"after"}},
		{"a body that is a packet with an old header", armourOpts{headers: []string{"Comment: TEST ONLY"}}.text(oldHeader(tagSignature, body)), []string{"shortest"}},
		{"a body that is a packet with a five-octet header", armourOpts{headers: []string{"Comment: TEST ONLY"}}.text(wrapLong(tagSignature, body)), []string{"shortest"}},
		{"a body that is a cut packet", armourOpts{headers: []string{"Comment: TEST ONLY"}}.text(pkt[:len(pkt)-1]), nil},
		{"a body that is a key packet", armourOpts{headers: []string{"Comment: TEST ONLY"}}.text(other.keyPacket()), []string{"not a Signature"}},
		{"a body that is not base64", []byte("-----BEGIN PGP SIGNATURE-----\n\n!!!!\n=AAAA\n-----END PGP SIGNATURE-----\n"), nil},
		{"a body with a line of text", []byte("-----BEGIN PGP SIGNATURE-----\n\nhello world\n=AAAA\n-----END PGP SIGNATURE-----\n"), nil},
	} {
		t.Run(c.name, func(t *testing.T) { assertFileRefused(t, c.name, c.in, c.want...) })
	}
}

// The text of a refusal of the armour says which part is wrong: the first line, the checksum line, the
// end of the block.
func TestReadSignatureFileSaysWhichPartOfTheArmourIsWrong(t *testing.T) {
	pkt := aRevocation(t)
	good := armourOpts{headers: []string{"Comment: TEST ONLY"}}.text(pkt)
	for _, c := range []struct {
		name string
		in   []byte
		word string
	}{
		{"a space after the first line", cat([]byte("-----BEGIN PGP SIGNATURE----- \n"), good[len("-----BEGIN PGP SIGNATURE-----\n"):]), "not a block of type"},
		{"a carriage return after the first line", cat([]byte("-----BEGIN PGP SIGNATURE-----\r\n"), good[len("-----BEGIN PGP SIGNATURE-----\n"):]), "not a block of type"},
		{"a wrong CRC-24 line", armourOpts{headers: []string{"Comment: TEST ONLY"}, crcXOR: 1}.text(pkt), "is wrong"},
		{"a wrong CRC-24 line with no header", armourOpts{crcXOR: 1 << 12}.text(pkt), "is wrong"},
		{"the end line glued to the CRC-24 line", bytes.Replace(good, []byte("\n-----END"), []byte("-----END"), 1), "does not read"},
		{"a header that is not the comment", armourOpts{headers: []string{"Version: example"}}.text(pkt), "header line"},
	} {
		_, err := openpgp.ReadSignatureFile(c.in)
		if err == nil || !strings.Contains(err.Error(), c.word) {
			t.Errorf("%s: the refusal is %v, want a text that holds %q", c.name, err, c.word)
		}
	}
}

func TestReadSignatureFileRefusesAnAgeFileWithATextThatSaysItIsNotReadHere(t *testing.T) {
	pkt := aRevocation(t)
	for name, in := range map[string][]byte{
		"the header of a binary age file":    []byte("age-encryption.org/v1\n-> scrypt abcdefgh 18\nAAAA\n--- BBBB\n"),
		"a binary age file of the size":      cat([]byte("age-encryption.org/v1\n-> X25519 abc\n--- mac\n"), pkt),
		"the prefix alone":                   []byte("age-encryption.org/"),
		"an age file holding a signature":    cat([]byte("age-encryption.org/v1\n"), pkt),
		"an age armour block":                []byte("-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n"),
		"an age armour block with no end":    []byte("-----BEGIN AGE ENCRYPTED FILE-----\n"),
		"an age armour block after a note":   []byte("note\n-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n"),
		"an age armour with CRLF line ends":  []byte("-----BEGIN AGE ENCRYPTED FILE-----\r\nYWdl\r\n-----END AGE ENCRYPTED FILE-----\r\n"),
		"an age armour with the first line":  []byte("-----BEGIN AGE ENCRYPTED FILE-----"),
		"an age binary prefix in the middle": cat(pkt, []byte("age-encryption.org/v1\n")),
	} {
		t.Run(name, func(t *testing.T) {
			assertFileRefused(t, name, in)
			if strings.HasPrefix(name, "an age armour block after") || strings.Contains(name, "middle") {
				return
			}
			if _, err := openpgp.ReadSignatureFile(in); err == nil || !strings.Contains(err.Error(), "age") || !strings.Contains(err.Error(), "not read here") {
				t.Errorf("the refusal of an age file is %v, want a text that says it is an age file that is not read here", err)
			}
		})
	}
}

// An armour block that go-crypto reads with no complaint and that is not the text it writes is refused:
// go-crypto skips what stands before the block, does not read the CRC-24 and reads a line of any width.
func TestReadSignatureFileHoldsTheFileToTheTextThatGoCryptoWrites(t *testing.T) {
	pkt := aRevocation(t)
	for name, text := range map[string][]byte{
		"go-crypto, TEST ONLY":     goCryptoArmour(t, "PGP SIGNATURE", testOnly, pkt),
		"go-crypto, no header":     goCryptoArmour(t, "PGP SIGNATURE", nil, pkt),
		"a final LF added by hand": append(goCryptoArmour(t, "PGP SIGNATURE", testOnly, pkt), '\n'),
	} {
		assertFile(t, name, text, pkt)
		// Go-crypto decodes each of these variants; ReadSignatureFile refuses each of them.
		variants := map[string][]byte{
			"a leading line end":     cat([]byte("\n"), text),
			"leading text":           cat([]byte("note\n"), text),
			"the CRC-24 line gone":   removeCRCLine(text),
			"the line ends as CRLF":  bytes.ReplaceAll(text, []byte("\n"), []byte("\r\n")),
			"trailing spaces":        cat(text, []byte("  ")),
			"two trailing line ends": cat(bytes.TrimSuffix(text, []byte("\n")), []byte("\n\n")),
		}
		for vname, v := range variants {
			if _, err := armor.Decode(bytes.NewReader(v)); err != nil {
				continue // go-crypto refuses it too: not a case of this test
			}
			assertFileRefused(t, name+", "+vname, v)
		}
	}
}

func removeCRCLine(text []byte) []byte {
	lines := bytes.Split(text, []byte("\n"))
	var out [][]byte
	for _, l := range lines {
		if len(l) == 5 && l[0] == '=' {
			continue
		}
		out = append(out, l)
	}
	return bytes.Join(out, []byte("\n"))
}

// A text of the file in the error: a file that holds words, a script, a long header, a name of a
// person, none of it reaches the text of the error.
func TestReadSignatureFileErrorsShowNoByteOfTheFile(t *testing.T) {
	pkt := aRevocation(t)
	for name, in := range map[string][]byte{
		"a note that says SECRET":               []byte("SECRET SECRET SECRET\n"),
		"a header with a script":                armourOpts{headers: []string{"Comment: <script>alert(1)</script>"}}.text(pkt),
		"a header with a person":                armourOpts{headers: []string{"Comment: Example Person <person@example.org>"}}.text(pkt),
		"a header with a very long line":        armourOpts{headers: []string{"Comment: " + strings.Repeat("x", 3000)}}.text(pkt),
		"a header with invalid UTF-8":           armourOpts{headers: []string{"Comment: \xff\xfe\xfd"}}.text(pkt),
		"a header with a control character":     armourOpts{headers: []string{"Comment: \x1b[31mred"}}.text(pkt),
		"text before the block":                 cat([]byte("SECRET\n"), armourOpts{}.text(pkt)),
		"text after the block":                  cat(armourOpts{}.text(pkt), []byte("SECRET\n")),
		"an unknown block type with a name":     armourOpts{typ: "EXAMPLE PERSON SECRET"}.text(pkt),
		"an unknown block type of invalid UTF8": armourOpts{typ: "PGP \xff\xfe"}.text(pkt),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := openpgp.ReadSignatureFile(in)
			if err == nil {
				t.Fatal("accepted")
			}
			for _, bad := range []string{"SECRET", "script", "Example", "person", "\x1b", "\xff", "xxxx"} {
				if strings.Contains(err.Error(), bad) {
					t.Errorf("the text %q holds %q", err.Error(), bad)
				}
			}
			checkErrorText(t, name, err)
		})
	}
}

func TestReadSignatureFileReturnsACopy(t *testing.T) {
	pkt := aRevocation(t)
	for name, in := range map[string][]byte{
		"binary": bytes.Clone(pkt),
		"armour": goCryptoArmour(t, "PGP SIGNATURE", testOnly, pkt),
	} {
		t.Run(name, func(t *testing.T) {
			keep := bytes.Clone(in)
			got, err := openpgp.ReadSignatureFile(in)
			if err != nil {
				t.Fatal(err)
			}
			clear(got)
			if !bytes.Equal(in, keep) {
				t.Error("changing the packet changed the file")
			}
			again, err := openpgp.ReadSignatureFile(in)
			if err != nil {
				t.Fatal(err)
			}
			clear(in)
			if !bytes.Equal(again, pkt) {
				t.Error("changing the file changed a packet that was returned")
			}
		})
	}
}

// Every byte of an armoured file changed, one at a time, is refused or returns the same packet: the
// text is held to exactly what go-crypto writes, so a byte that is not the packet's cannot be changed.
func TestReadSignatureFileRefusesEveryArmourByteChangedOrReturnsTheSamePacket(t *testing.T) {
	pkt := aRevocation(t)
	text := goCryptoArmour(t, "PGP SIGNATURE", testOnly, pkt)
	for i := range text {
		for _, mask := range []byte{0x01, 0x20, 0x80} {
			bad := bytes.Clone(text)
			bad[i] ^= mask
			got, err := fileSafely(t, fmt.Sprintf("byte %d", i), bad)
			if err == nil && !bytes.Equal(got, pkt) {
				t.Errorf("byte %d xor %#x: the file is read as another packet (%d bytes)", i, mask, len(got))
			}
			if err == nil && !bytes.Equal(bad, text) {
				t.Errorf("byte %d xor %#x of %d: a changed file is accepted, so the text is not held to the one form", i, mask, len(text))
			}
		}
	}
	// Cuts: every strict prefix is refused, and no cut reads.
	for n := range len(text) - 1 {
		if _, err := fileSafely(t, fmt.Sprintf("cut at %d", n), text[:n]); err == nil {
			t.Errorf("the first %d of %d bytes of the file are accepted", n, len(text))
		}
	}
}

// The two armour readers agree: the file that the software store of a test root writes for each reason is
// read by ReadSignatureFile, the packet is the one that the store reads, and a file that the store refuses
// for its armour is refused here too.
func TestReadSignatureFileAgreesWithTheSoftwareStoreOnEveryFileItWrites(t *testing.T) {
	root := t.TempDir()
	bundle, keys := filepath.Join(root, "bundle"), filepath.Join(root, "keys")
	for _, d := range []string{bundle, filepath.Join(bundle, "history"), keys} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bundle, "ritueel.yaml"), []byte("name: Example Test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := software.Open(software.Config{KeyDir: keys, BundleDir: bundle, Mode: software.ModeTest})
	if err != nil {
		t.Fatalf("software.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	k := newRevKit(t, "store")
	for _, c := range allReasons {
		t.Run(c.name, func(t *testing.T) {
			pkt := k.made(t, c.r)
			if err := st.SaveRevocation("A", c.r.Text, pkt); err != nil {
				t.Fatalf("SaveRevocation: %v", err)
			}
			file, err := os.ReadFile(filepath.Join(keys, "A.revocation."+c.r.Text+".asc"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := openpgp.ReadSignatureFile(file)
			if err != nil {
				t.Fatalf("ReadSignatureFile of the file that the store wrote: %v", err)
			}
			fromStore, err := st.ReadRevocation(context.Background(), "A", c.r.Text)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, fromStore) || !bytes.Equal(got, pkt) {
				t.Error("the packet is not the one that the store reads and the one that was saved")
			}
			// What the store wrote is what a reader of the page sees: one block, the one header, no more.
			if !bytes.HasPrefix(file, []byte("-----BEGIN PGP SIGNATURE-----\nComment: TEST ONLY\n\n")) || !bytes.HasSuffix(file, []byte("-----END PGP SIGNATURE-----\n")) {
				t.Errorf("the file of the store is not the armour of the page: %q", file[:min(len(file), 60)])
			}
			// The reader of the packet reads it as the one that was made.
			k.assertRevoked(t, "the file of the store", got, c.r)
			// Verdicts for variants of this file: the store and ReadSignatureFile agree on a file with
			// the one header, except that this reader also reads a file with no header.
			variants := map[string][]byte{
				"as written":         file,
				"no final LF":        bytes.TrimSuffix(file, []byte("\n")),
				"two final LF":       append(bytes.Clone(file), '\n'),
				"CRLF":               bytes.ReplaceAll(file, []byte("\n"), []byte("\r\n")),
				"a wrong CRC":        flipCRC(file),
				"a space after":      append(bytes.TrimSuffix(bytes.Clone(file), []byte("\n")), ' ', '\n'),
				"leading line end":   append([]byte("\n"), file...),
				"the header another": bytes.Replace(file, []byte("TEST ONLY"), []byte("TEST ON"), 1),
				"lines of 76":        armourOpts{headers: []string{"Comment: TEST ONLY"}, width: 76}.text(pkt),
				"no CRC line":        armourOpts{headers: []string{"Comment: TEST ONLY"}, noCRC: true}.text(pkt),
				"a second block":     append(bytes.Clone(file), file...),
			}
			for name, v := range variants {
				path := filepath.Join(keys, "A.revocation."+c.r.Text+".asc")
				if err := os.WriteFile(path, v, 0o600); err != nil {
					t.Fatal(err)
				}
				_, storeErr := st.ReadRevocation(context.Background(), "A", c.r.Text)
				gotV, readerErr := openpgp.ReadSignatureFile(v)
				if (storeErr == nil) != (readerErr == nil) {
					t.Errorf("%s: the store accepts it: %v, ReadSignatureFile accepts it: %v (%v, %v)", name, storeErr == nil, readerErr == nil, storeErr, readerErr)
				}
				if readerErr == nil && !bytes.Equal(gotV, pkt) {
					t.Errorf("%s: another packet", name)
				}
			}
			if err := os.WriteFile(filepath.Join(keys, "A.revocation."+c.r.Text+".asc"), file, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func flipCRC(file []byte) []byte {
	out := bytes.Clone(file)
	i := bytes.LastIndex(out, []byte("\n=")) + 2
	out[i] = 'A' + (out[i]-'A'+1)%26
	return out
}
