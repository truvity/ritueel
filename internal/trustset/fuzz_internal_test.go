package trustset

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
)

func FuzzRawSignature(f *testing.F) {
	one := big.NewInt(1)
	n := new(big.Int).Sub(order(), one)
	for _, v := range [][2]*big.Int{{one, one}, {n, n}, {big.NewInt(0), one}, {order(), one}, {big.NewInt(-1), one}} {
		der, err := asn1.Marshal(struct{ R, S *big.Int }{v[0], v[1]})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(der)
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00})
	f.Add([]byte{0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01})
	f.Add(bytes.Repeat([]byte{0x30}, 100))
	f.Fuzz(func(t *testing.T, der []byte) {
		sig, err := rawSignature(der)
		if err != nil {
			if sig != nil {
				t.Fatalf("a signature comes with the error")
			}
			kindOf(t, err, ErrSign)
			return
		}
		if len(sig) != jws.SignatureSize {
			t.Fatalf("%d bytes", len(sig))
		}
		r, s := new(big.Int).SetBytes(sig[:48]), new(big.Int).SetBytes(sig[48:])
		if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(order()) >= 0 || s.Cmp(order()) >= 0 {
			t.Fatalf("r or s out of range")
		}
		// The input was the one shortest form of that pair.
		again, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil || !bytes.Equal(again, der) {
			t.Fatalf("the input %x is not the shortest form %x", der, again)
		}
	})
}

func FuzzMarshalGeneral(f *testing.F) {
	a := newIKey(f, "A", 0)
	listJSON := firstList(f, a)
	good := signFile(f, listJSON, rootlist.ListTyp, a)[0]
	f.Add(good.protected, good.sig, byte(1))
	f.Add(good.protected, good.sig, byte(2))
	f.Add(good.protected, good.sig[:95], byte(1))
	f.Add("", good.sig, byte(1))
	f.Add("e30", good.sig, byte(1))
	f.Add(good.protected, good.sig, byte(0))
	f.Fuzz(func(t *testing.T, protected string, sig []byte, count byte) {
		var sigs []fileSignature
		for i := 0; i < int(count)%30; i++ {
			sigs = append(sigs, fileSignature{protected: protected, sig: sig})
		}
		out, err := marshalGeneral(sigs)
		if err != nil {
			if out != nil {
				t.Fatalf("bytes come with the error")
			}
			kindOf(t, err, ErrParams)
			return
		}
		g, err := jws.ParseGeneral(out, rootlist.ListTyp)
		if err != nil || len(g.Signatures) != len(sigs) {
			t.Fatalf("the reader refuses what was written: %v", err)
		}
		if len(out) > MaxBytes || bytes.HasSuffix(out, []byte("\n")) {
			t.Fatalf("%d bytes", len(out))
		}
	})
}

// FuzzFailWith gives the cause any text: what is shown is the reference, in printable ASCII, not
// longer than the bound and the dots, and the cause is asked once.
func FuzzFailWith(f *testing.F) {
	for _, seed := range []string{"", "x", "\x1b[31m", "\xff\xfe", "\u202e", strings.Repeat("a", 200), strings.Repeat("a", 201),
		strings.Repeat("\x1b", 100), strings.Repeat("\U0001f600", 60), strings.Repeat("a", 199) + "\u00e9", "%s%d%w", `a\b c`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		calls := 0
		err := failWith(ErrSign, "what", &fuzzCause{text: text, calls: &calls})
		if calls != 1 {
			t.Fatalf("the cause was asked %d times", calls)
		}
		kindOf(t, err, ErrSign)
		prefix := ErrSign.Error() + ": what: "
		if !strings.HasPrefix(err.Error(), prefix) {
			t.Fatalf("text %q", err)
		}
		got := err.Error()[len(prefix):]
		if want := reference(text); got != want {
			t.Fatalf("text %+q: shown %q, want %q", text, got, want)
		}
		if !asciiOnly(err.Error()) || len(got) > maxCauseText+len("...") {
			t.Fatalf("text %+q: shown %+q", text, got)
		}
		_ = fmt.Sprintf("%v %+v %#v", err, err, err)
		if calls != 1 {
			t.Fatalf("printing the error asked the cause again")
		}
	})
}

type fuzzCause struct {
	text  string
	calls *int
}

func (c *fuzzCause) Error() string {
	*c.calls++
	return c.text
}

// FuzzCauseTextNested gives an error of this package, which holds escapes already, as the cause of
// another: what is shown is the reference for the text of the inner error, is a start of that text,
// is within the bound, and does not end in a part of an escape.
func FuzzCauseTextNested(f *testing.F) {
	for _, seed := range []string{"", "x", "\x1b", "\xff\xfe", strings.Repeat("\u00e9", 120), strings.Repeat("\U0001f600", 40),
		strings.Repeat("a", 163) + "\U0001f600", strings.Repeat("a", 160) + strings.Repeat("\u20ac", 20), "%s%d%w"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		inner := failWith(ErrSign, "in", errors.New(text))
		outer := failWith(ErrSign, "what", inner)
		kindOf(t, outer, ErrSign)
		got := shown(t, outer)
		whole := inner.Error()
		if want := reference(whole); got != want {
			t.Fatalf("text %+q: shown %q, want %q", text, got, want)
		}
		body := strings.TrimSuffix(got, "...")
		if len(got) > maxCauseText+len("...") || !strings.HasPrefix(whole, body) || !asciiOnly(got) {
			t.Fatalf("text %+q: shown %+q", text, got)
		}
		if len(whole) <= maxCauseText && got != whole {
			t.Fatalf("text %+q: a text that was not cut is changed: %q", text, got)
		}
		if len(whole) > maxCauseText && endsInPartOfAnEscape(body) {
			t.Fatalf("text %+q: shown %q ends in a part of an escape", text, got)
		}
	})
}

// FuzzDropPartialEscape gives any text to the drop: the result is a start of the text and is the
// plain model of it, and the text ends in no part of an escape afterwards.
func FuzzDropPartialEscape(f *testing.F) {
	for _, seed := range []string{"", "a", `\`, `\u`, `\u0`, `\u00e`, `\u00e9`, `\ud83d`, `\ud83d\ude00`, `\ud83d\ude0`, `ab\ud83d\u`,
		`\u00e9\u00`, "\u00e9\\", `\x`, `\uD83D`, `a\ude00`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := dropPartialEscape(s)
		if !strings.HasPrefix(s, got) {
			t.Fatalf("%q gives %q, which is not a start of it", s, got)
		}
		if want := dropTail(s); got != want {
			t.Fatalf("%q gives %q, want %q", s, got, want)
		}
		if endsInPartOfAnEscape(got) {
			t.Fatalf("%q gives %q, which ends in a part of an escape", s, got)
		}
		if endsInPartOfAnEscape(s) == (got == s) {
			t.Fatalf("%q gives %q: a text is changed if and only if it ends in a part of an escape", s, got)
		}
	})
}
