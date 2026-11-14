package software

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The page says the removal file is the compact JWS: three parts of Base64url text without
// padding and two dots. The strict decoder of the standard library skips a carriage return and a
// line feed, so the check looks at every byte first. These tests try every byte value at every
// place of a good text, through the one check behind SaveRemoval and ReadRemoval.

const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func TestRemovalByteIsExactlyTheBase64urlAlphabetAndTheDot(t *testing.T) {
	want := map[byte]bool{'.': true}
	for i := 0; i < len(base64urlAlphabet); i++ {
		want[base64urlAlphabet[i]] = true
	}
	if len(want) != 65 {
		t.Fatalf("the alphabet has %d members", len(want))
	}
	for b := 0; b < 256; b++ {
		if got := removalByte(byte(b)); got != want[byte(b)] {
			t.Errorf("byte %#02x: %v, want %v", b, got, want[byte(b)])
		}
	}
}

func TestAnyByteOutsideTheAlphabetAtAnyPlaceOfAGoodTextIsRefusedByEveryEntrance(t *testing.T) {
	const good = "AAAA.BBBB.CCCC"
	s, _, keys := openStore(t)
	rec := record(s)
	first := ""
	for b := 0; b < 256; b++ {
		if removalByte(byte(b)) {
			continue
		}
		for at := 0; at <= len(good); at++ {
			inserted := good[:at] + string([]byte{byte(b)}) + good[at:]
			variants := []string{inserted}
			if at < len(good) {
				variants = append(variants, good[:at]+string([]byte{byte(b)})+good[at+1:])
			}
			for _, text := range variants {
				if err := checkRemoval([]byte(text)); !errors.Is(err, ErrKeyFile) {
					t.Fatalf("checkRemoval accepted %q: %v", text, err)
				}
				err := s.SaveRemoval("A", []byte(text))
				if !errors.Is(err, ErrParams) {
					t.Fatalf("SaveRemoval of %q: %v", text, err)
				}
				if first == "" {
					first = err.Error()
				} else if err.Error() != first {
					t.Fatalf("the error text depends on the input: %q and %q", first, err.Error())
				}
				st := staticStore(t, map[string][]byte{"A.removal.jws": []byte(text)})
				if got, err := st.ReadRemoval(bg(), "A"); err == nil || got != nil || !errors.Is(err, ErrKeyFile) {
					t.Fatalf("ReadRemoval of %q: %q, %v", text, got, err)
				}
			}
		}
	}
	if rec.calls() != 0 || len(dirNames(t, keys)) != 0 {
		t.Errorf("a refused text was written: %d writer calls, %v", rec.calls(), dirNames(t, keys))
	}
	// The store was not stopped by the refusals: a good text still writes.
	if err := s.SaveRemoval("A", []byte(good)); err != nil {
		t.Fatalf("a good text after the refusals: %v", err)
	}
}

func TestEveryByteOfTheAlphabetIsAcceptedInAPartAndTheTextIsWrittenAsItIs(t *testing.T) {
	// Four characters make three whole bytes, so no left-over bit can fail the strict decoder.
	for i := 0; i+4 <= len(base64urlAlphabet); i++ {
		quad := base64urlAlphabet[i : i+4]
		text := quad + "." + quad + "." + quad
		if err := checkRemoval([]byte(text)); err != nil {
			t.Fatalf("%q: %v", text, err)
		}
	}
	s, _, keys := openStore(t)
	text := base64urlAlphabet[:4] + "." + base64urlAlphabet[60:] + "AA." + base64urlAlphabet[4:8]
	if err := s.SaveRemoval("A", []byte(text)); err != nil {
		t.Fatal(err)
	}
	if got := readKeyFile(t, keys, "A.removal.jws"); string(got) != text {
		t.Errorf("the file is %q, want %q", got, text)
	}
	got, err := s.ReadRemoval(bg(), "A")
	if err != nil || string(got) != text {
		t.Errorf("read back %q: %v", got, err)
	}
}

// A byte that is not UTF-8, a letter that looks like Base64url, a line separator of Unicode and a
// zero-width space are all refused: the check is on bytes, never on text.
func TestTextThatLooksRightButIsNotBase64urlIsRefused(t *testing.T) {
	for name, text := range map[string]string{
		"a Cyrillic A":                "\u0410AAA.BBBB.CCCC",
		"a full-width A":              "\uff21AAA.BBBB.CCCC",
		"a zero-width space":          "AAAA.BB\u200bBB.CCCC",
		"a line separator":            "AAAA.BBBB.CCCC\u2028",
		"a next line character":       "AAAA.BBBB.CCCC\u0085",
		"a byte that is not UTF-8":    "AAAA.BBBB.CCCC\xff",
		"a lone continuation byte":    "AAAA.BBBB.\x80CCC",
		"a form feed":                 "AAAA.BBBB.CCCC\f",
		"a vertical tab":              "AAAA.BBBB.CCCC\v",
		"a tab":                       "AAAA.\tBBBB.CCCC",
		"a NUL at the start":          "\x00AAAA.BBBB.CCCC",
		"a delete character":          "AAAA.BBBB.CCCC\x7f",
		"a CR LF pair in a part":      "AAAA.BB\r\nBB.CCCC",
		"a LF CR pair at the end":     "AAAA.BBBB.CCCC\n\r",
		"only a newline between dots": ".\n.",
	} {
		if err := checkRemoval([]byte(text)); !errors.Is(err, ErrKeyFile) {
			t.Errorf("%s: %q accepted (%v)", name, text, err)
		}
	}
}

func TestARemovalFileOfTheLimitIsAcceptedAndOneOfTheAlphabetsEdgeBytesPastTheLimitIsNot(t *testing.T) {
	a := func(n int) string { return strings.Repeat("A", n) }
	at := a(1364) + "." + a(1364) + "." + a(1366)
	if len(at) != maxRemovalSize {
		t.Fatalf("the test text has %d bytes", len(at))
	}
	if err := checkRemoval([]byte(at)); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	for _, extra := range []string{"A", "\n", "\xff"} {
		if err := checkRemoval([]byte(at + extra)); err == nil {
			t.Errorf("over the limit by %q accepted", extra)
		}
	}
	// Hostile size: a megabyte of junk, and of valid-looking text, is refused at once.
	for _, big := range [][]byte{bytes.Repeat([]byte{'A'}, 1<<20), bytes.Repeat([]byte("A.A."), 1<<18), bytes.Repeat([]byte{0xff}, 1<<20)} {
		if err := checkRemoval(big); !errors.Is(err, ErrKeyFile) {
			t.Errorf("%d bytes: %v", len(big), err)
		}
	}
}
