package openpgp_test

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // the version 4 fingerprint is a SHA-1 by the standard
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// The kit of the tests of the lone secret key packet that the adopted key is kept in. It reads and
// writes the packet with code of its own, apart from the code under test, so that the layout is held
// by a second reader. The names start with al.

// alMPI reads one number in the form of RFC 9580, section 3.2, as the tests read it: the bit count,
// then exactly the bytes that hold it, the first of them not zero and with that many bits. It returns
// the piece as it is written, the value and the rest.
func alMPI(b []byte) (piece, val, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, nil, false
	}
	count := int(binary.BigEndian.Uint16(b))
	n := (count + 7) / 8
	if count == 0 || len(b) < 2+n {
		return nil, nil, nil, false
	}
	val = b[2 : 2+n]
	if val[0] == 0 || count != (n-1)*8+bits.Len8(val[0]) {
		return nil, nil, nil, false
	}
	return b[:2+n], val, b[2+n:], true
}

// alPacket is a lone secret key packet taken apart: the six fixed octets of the public part (the
// version, the creation time and the algorithm), the pieces of the rest of the public part, the usage
// octet, the secret numbers as written (each with its bit count) and the checksum that stood there.
type alPacket struct {
	Head  []byte
	Pub   [][]byte
	Usage byte
	Sec   [][]byte
	Sum   uint16
}

// alAlg is the algorithm number of the packet.
func (p alPacket) alg() byte { return p.Head[5] }

// alParse reads a lone secret key packet with the strictest reading there is, and says what is not
// canonical: the one-octet or two-octet header of the shortest form (tag 5), the public part of one of
// the three algorithms, usage 0, every number in its shortest form, a checksum that is the sum of the
// bytes of the numbers, and nothing else.
func alParse(pkt []byte) (alPacket, error) {
	var p alPacket
	if len(pkt) < 2 || pkt[0] != 0xC5 {
		return p, errors.New("the header is not a new-format header of tag 5")
	}
	var hl, n int
	switch l := int(pkt[1]); {
	case l < 192:
		hl, n = 2, l
	case l < 224:
		if len(pkt) < 3 {
			return p, errors.New("cut short in the length")
		}
		hl, n = 3, (l-192)<<8+int(pkt[2])+192
	default:
		return p, errors.New("the length is not a one or two octet length")
	}
	if len(pkt) != hl+n {
		return p, fmt.Errorf("the length is %d and the packet holds %d bytes after its header", n, len(pkt)-hl)
	}
	body := pkt[hl:]
	if len(body) < 6 || body[0] != 4 {
		return p, errors.New("not a version 4 key")
	}
	p.Head = body[:6]
	rest := body[6:]
	take := func() ([]byte, bool) {
		piece, _, r, ok := alMPI(rest)
		if !ok {
			return nil, false
		}
		rest = r
		return piece, true
	}
	var secrets int
	switch p.alg() {
	case 1:
		for range 2 {
			piece, ok := take()
			if !ok {
				return p, errors.New("a public number of RSA is not in its shortest form")
			}
			p.Pub = append(p.Pub, piece)
		}
		secrets = 4
	case 19, 22:
		if len(rest) < 1 || rest[0] == 0 || rest[0] == 0xFF || len(rest) < 1+int(rest[0]) {
			return p, errors.New("the curve identifier is cut short")
		}
		p.Pub = append(p.Pub, rest[:1+int(rest[0])])
		rest = rest[1+int(rest[0]):]
		piece, ok := take()
		if !ok {
			return p, errors.New("the public point is not in its shortest form")
		}
		p.Pub = append(p.Pub, piece)
		secrets = 1
	default:
		return p, fmt.Errorf("the algorithm %d is not one of the three", p.alg())
	}
	if len(rest) < 1 || rest[0] != 0 {
		return p, errors.New("the usage octet is not 0")
	}
	p.Usage, rest = 0, rest[1:]
	var sum uint16
	for range secrets {
		piece, ok := take()
		if !ok {
			return p, errors.New("a secret number is not in its shortest form")
		}
		for _, c := range piece {
			sum += uint16(c)
		}
		p.Sec = append(p.Sec, piece)
	}
	if len(rest) != 2 {
		return p, fmt.Errorf("%d bytes follow the numbers, want the two of the checksum", len(rest))
	}
	p.Sum = binary.BigEndian.Uint16(rest)
	if p.Sum != sum {
		return p, errors.New("the checksum is not the sum of the bytes of the numbers")
	}
	return p, nil
}

// pubBody is the public part of the packet as written.
func (p alPacket) pubBody() []byte {
	out := bytes.Clone(p.Head)
	for _, piece := range p.Pub {
		out = append(out, piece...)
	}
	return out
}

// body writes the body of the packet. A negative sum is the right checksum of the numbers.
func (p alPacket) body(usage byte, sum int) []byte {
	out := p.pubBody()
	out = append(out, usage)
	var s uint16
	for _, piece := range p.Sec {
		out = append(out, piece...)
		for _, c := range piece {
			s += uint16(c)
		}
	}
	if sum >= 0 {
		s = uint16(sum)
	}
	return append(out, byte(s>>8), byte(s))
}

// packet is the packet in the shortest header of the new format, with the right checksum.
func (p alPacket) packet() []byte { return wrap(5, p.body(0, -1)) }

// clone copies the packet so that a change does not reach the one it came from.
func (p alPacket) clone() alPacket {
	q := alPacket{Head: bytes.Clone(p.Head), Usage: p.Usage, Sum: p.Sum}
	for _, piece := range p.Pub {
		q.Pub = append(q.Pub, bytes.Clone(piece))
	}
	for _, piece := range p.Sec {
		q.Sec = append(q.Sec, bytes.Clone(piece))
	}
	return q
}

// values are the secret numbers of the packet as values.
func (p alPacket) values() [][]byte {
	var out [][]byte
	for _, piece := range p.Sec {
		out = append(out, bytes.Clone(piece[2:]))
	}
	return out
}

// alLone writes the lone packet of a template, unprotected or protected with fkPass, and takes it apart.
func alLone(t testing.TB, b *fkBase, protected bool) (*openpgp.ForeignKey, []byte, alPacket) {
	t.Helper()
	pass := ""
	if protected {
		pass = fkPass
	}
	k, pkt := fkLone(t, b, pass)
	p, err := alParse(pkt)
	if err != nil {
		t.Fatalf("the packet that SecretPacket wrote is not canonical: %v", err)
	}
	return k, pkt, p
}

// alFingerprint is the version 4 fingerprint of a public body, computed here.
func alFingerprint(pub []byte) string {
	h := sha1.New() //nolint:gosec // see the import
	h.Write([]byte{0x99, byte(len(pub) >> 8), byte(len(pub))})
	h.Write(pub)
	return hex.EncodeToString(h.Sum(nil))
}

// alIndex holds the windows of the forms that a leak of some numbers could take: eight bytes of a
// number as they are, backwards, and with spaces; sixteen hexadecimal digits of it in both cases;
// twelve characters of its Base64 in the two alphabets, at each of the three alignments; and twelve
// decimal digits. A number of less than eight bytes is looked for whole. Windows are kept by length,
// so that a text is looked at once for each length.
type alIndex struct {
	sets map[int]map[string]int
}

// alIndexOf makes the index of the numbers.
func alIndexOf(numbers ...[]byte) *alIndex {
	x := &alIndex{sets: map[int]map[string]int{}}
	for i, v := range numbers {
		v = bytes.TrimLeft(v, "\x00")
		if len(v) == 0 {
			continue
		}
		x.addAll(i, v)
	}
	return x
}

func (x *alIndex) add(n int, w string) {
	if len(w) < 4 {
		return
	}
	if x.sets[len(w)] == nil {
		x.sets[len(w)] = map[string]int{}
	}
	x.sets[len(w)][w] = n
}

func (x *alIndex) windows(n int, s string, w int) {
	if len(s) <= w {
		x.add(n, s)
		return
	}
	for i := 0; i+w <= len(s); i++ {
		x.add(n, s[i:i+w])
	}
}

func (x *alIndex) addAll(n int, v []byte) {
	x.windows(n, string(v), 8)
	rev := make([]byte, len(v))
	for i, c := range v {
		rev[len(v)-1-i] = c
	}
	x.windows(n, string(rev), 8)
	if len(v) < 8 {
		x.add(n, fmt.Sprintf("% x", v))
		x.add(n, fmt.Sprintf("% X", v))
	}
	for i := 0; i+8 <= len(v); i++ {
		x.add(n, fmt.Sprintf("% x", v[i:i+8]))
		x.add(n, fmt.Sprintf("% X", v[i:i+8]))
	}
	h := hex.EncodeToString(v)
	x.windows(n, h, 16)
	x.windows(n, strings.ToUpper(h), 16)
	for shift := 0; shift < 3 && shift < len(v); shift++ {
		for _, e := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			x.windows(n, e.EncodeToString(v[shift:]), 12)
		}
	}
	x.windows(n, new(big.Int).SetBytes(v).String(), 12)
}

// find says whether the text holds a window of the index, and which number and form.
func (x *alIndex) find(text string) (string, bool) {
	for l, set := range x.sets {
		for i := 0; i+l <= len(text); i++ {
			if n, ok := set[text[i:i+l]]; ok {
				return fmt.Sprintf("number %d as %q", n, text[i:i+l]), true
			}
		}
	}
	return "", false
}

// alLeaks says whether the text holds a window of any form of any of the numbers, and which.
func alLeaks(text string, numbers ...[]byte) (string, bool) {
	return alIndexOf(numbers...).find(text)
}

var alTemplateIndexes sync.Map

// alTemplateIndex is the index of the numbers of a template, made once.
func alTemplateIndex(t testing.TB, b *fkBase) *alIndex {
	t.Helper()
	if x, ok := alTemplateIndexes.Load(b.name); ok {
		return x.(*alIndex)
	}
	x := alIndexOf(b.secrets(t).all()...)
	alTemplateIndexes.Store(b.name, x)
	return x
}

// alRefusal holds the answer of OpenSecretPacket to what it must refuse: the error is an ErrForeignKey
// of each kind given, no secret and no public facts come back, and the text holds no run of the numbers
// of the template, of the numbers that stand in the input given, of the passphrases or of the user ID.
// extra is more that the text must not hold. It returns the error.
func alRefusal(t testing.TB, what string, b *fkBase, in []byte, extra [][]byte, kinds ...error) error {
	t.Helper()
	secret, pub, err := openpgp.OpenSecretPacket(in)
	if err == nil {
		if secret != nil {
			secret.Wipe()
		}
		t.Errorf("%s: the packet was read, want a refusal", what)
		return nil
	}
	if secret != nil || pub.Fingerprint != "" || pub.PublicBody != nil || !pub.Created.IsZero() || pub.Algorithm != (openpgp.ForeignAlgorithm{}) {
		t.Errorf("%s: something is returned with the error %v", what, err)
	}
	if !errors.Is(err, openpgp.ErrForeignKey) {
		t.Errorf("%s: %v is not an ErrForeignKey", what, err)
	}
	for _, kind := range kinds {
		if !errors.Is(err, kind) {
			t.Errorf("%s: %v is not the kind %v", what, err, kind)
		}
	}
	fkCheckText(t, what, err, nil, extra...)
	if b != nil {
		if where, bad := alTemplateIndex(t, b).find(err.Error()); bad {
			t.Errorf("%s: the error text holds a run of a secret of the key (%s): %q", what, where, err)
		}
	}
	if where, bad := alLeaks(err.Error(), extra...); bad {
		t.Errorf("%s: the error text holds a run of a secret of the input (%s): %q", what, where, err)
	}
	return err
}

// alReported skips the test of a defect that is reported and not fixed, unless the variable
// RITUEEL_TEST_REPORTED is 1.
func alReported(t testing.TB) {
	t.Helper()
	if os.Getenv("RITUEEL_TEST_REPORTED") != "1" {
		t.Skip("a reported defect: set RITUEEL_TEST_REPORTED=1 to run this test")
	}
}

// alRefuses is alRefusal for a caller that does not look at the error.
func alRefuses(t testing.TB, what string, b *fkBase, in []byte, extra [][]byte, kinds ...error) {
	t.Helper()
	_ = alRefusal(t, what, b, in, extra, kinds...)
}

// alPad left-pads a number to n bytes: a number that is written without its leading zero bytes is
// n bytes long again, so that a case that is "one byte too long" is that for every key.
func alPad(v []byte, n int) []byte {
	if len(v) >= n {
		return v
	}
	return append(make([]byte, n-len(v)), v...)
}
