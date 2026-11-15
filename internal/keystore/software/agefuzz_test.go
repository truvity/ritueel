package software

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"
)

// The fuzz targets of the passphrase files read bytes that a person or a hostile folder gives.
// None starts a program, none runs scrypt (a header that passes is answered by a source that
// fails, or by a stub identity), and none writes a file.

func FuzzInspectAgeHeader(f *testing.F) {
	for _, s := range []string{
		scryptStanza("18"), scryptStanza("22"), scryptStanza("17"), scryptStanza("23"), scryptStanza("018"), scryptStanza("+18"),
		scryptStanza("18") + scryptStanza("18"), stanzaText("X25519", []string{b64(bytes.Repeat([]byte{3}, 32))}, bytes.Repeat([]byte{4}, 32)),
		stanzaText("scrypt", []string{"18"}, scryptBody()), stanzaText("scrypt", goodArgs("18"), scryptBody()[:16]), "",
	} {
		f.Add(headerOf(s))
	}
	f.Add([]byte{})
	f.Add([]byte(ageVersionLine))
	f.Add([]byte("age-encryption.org/v1\n-> scrypt\n--- AA\n"))
	f.Add(bytes.Repeat([]byte{0}, 300))
	f.Fuzz(func(t *testing.T, data []byte) {
		err := inspectHeader(data)
		stub := &stubIdentity{}
		_, derr := age.Decrypt(bytes.NewReader(data), scryptGate{inner: stub})
		if err != nil {
			if !errors.Is(err, ErrKeyFile) {
				t.Fatalf("a refusal that is not ErrKeyFile: %v", err)
			}
			if stub.calls != 0 {
				t.Fatalf("the header is refused and the inner identity ran %d times", stub.calls)
			}
			if strings.Contains(err.Error(), "age-encryption") {
				t.Fatalf("the error repeats a line of the file: %v", err)
			}
			return
		}
		if stub.calls != 1 {
			t.Fatalf("the header is accepted and the inner identity ran %d times (%v)", stub.calls, derr)
		}
		if (ageFormat{}).inspect(data) != nil && len(data) <= MaxKeyFileSize {
			t.Fatal("inspect and inspectHeader disagree")
		}
	})
}

func FuzzCheckStanzas(f *testing.F) {
	f.Add("scrypt", b64(saltOf16), "18", scryptBody(), "", uint8(2))
	f.Add("scrypt", b64(saltOf16), "22", scryptBody(), "", uint8(2))
	f.Add("scrypt", b64(saltOf16), "23", scryptBody(), "", uint8(2))
	f.Add("scrypt", b64(saltOf16), "018", scryptBody(), "", uint8(2))
	f.Add("scrypt", b64(saltOf16), "18", scryptBody(), "x", uint8(3))
	f.Add("X25519", b64(saltOf16), "18", scryptBody(), "", uint8(2))
	f.Add("scrypt", b64(saltOf16)+"==", "18", scryptBody(), "", uint8(2))
	f.Add("scrypt", b64(saltOf16), "18", []byte{}, "", uint8(2))
	f.Fuzz(func(t *testing.T, typ, a0, a1 string, body []byte, a2 string, n uint8) {
		args := []string{a0, a1, a2}[:min(int(n)%4, 3)]
		err := checkStanzas([]*age.Stanza{{Type: typ, Args: args, Body: body}})
		if err != nil {
			if !errors.Is(err, ErrKeyFile) {
				t.Fatalf("a refusal that is not ErrKeyFile: %v", err)
			}
			return
		}
		// what is accepted is exactly the stanza of the page, judged here by other means
		wf, cerr := strconv.Atoi(a1)
		salt, serr := base64.RawStdEncoding.Strict().DecodeString(a0)
		ok := typ == "scrypt" && len(args) == 2 && cerr == nil && strconv.Itoa(wf) == a1 &&
			wf >= workFactorLowest && wf <= MaxWorkFactor && serr == nil && len(salt) == 16 &&
			base64.RawStdEncoding.EncodeToString(salt) == a0 && len(body) == 32
		if !ok {
			t.Fatalf("accepted: %q %q %q body %d bytes", typ, a0, a1, len(body))
		}
	})
}

func FuzzCheckPassphrase(f *testing.F) {
	for _, s := range []string{
		testPass, "short", strings.Repeat("a", 15), strings.Repeat("a", 14), strings.Repeat("a", 1024), strings.Repeat("a", 1025),
		"abc\x00defghijklmnopq", "abcdefghijklmnop\u202e", "abcdefghijklmnop\xff", strings.Repeat("\u0301", 15), "",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		before := bytes.Clone(p)
		err := CheckPassphrase(p)
		if !bytes.Equal(p, before) {
			t.Fatal("CheckPassphrase changed its argument")
		}
		if err != nil && !errors.Is(err, ErrPassphrase) {
			t.Fatalf("%v", err)
		}
		// judged here by other means: the same rule, one rune at a time
		want := len(p) <= MaxPassphraseBytes && utf8.Valid(p) && utf8.RuneCount(p) >= MinPassphraseChars
		for _, r := range string(p) {
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) || unicode.In(r, unicode.Cf) {
				want = false
			}
		}
		if (err == nil) != want {
			t.Fatalf("accepted %v, want %v for %q", err == nil, want, p)
		}
		if err != nil {
			text := err.Error()
			for _, w := range windowsOf(p, 6) {
				if strings.Contains(text, w) {
					t.Fatalf("the error holds %q of the passphrase", w)
				}
			}
		}
	})
}

// errorWords holds the fixed words of the errors of a passphrase, so that a window of them is not a leak.
var errorWords = "the passphrase is not valid UTF-8 shorter than 15 characters longer than 1024 bytes holds a control or a format character software: acceptable"

// windowsOf returns the windows of n bytes of p that are text and are not words of the error texts.
func windowsOf(p []byte, n int) []string {
	var out []string
	if !utf8.Valid(p) {
		return nil
	}
	for i := 0; i+n <= len(p); i += 3 {
		w := string(p[i : i+n])
		if utf8.ValidString(w) && !strings.ContainsAny(w, " \t") && !strings.Contains(errorWords, w) {
			out = append(out, w)
		}
	}
	return out
}

func FuzzReaderSource(f *testing.F) {
	for _, s := range []string{
		testPass + "\n", testPass + "\r\n", testPass, "\n", "\r\n", "", "short\n", testPass + "\n" + testPass2 + "\n",
		strings.Repeat("a", 1024) + "\n", strings.Repeat("a", 1025) + "\n", strings.Repeat("a", 1026), testPass + "\r", testPass + "\r\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cr := &countReader{r: bytes.NewReader(data)}
		got, err := ReaderSource(cr).Passphrase(context.Background(), Purpose{Label: "A", File: FileX509})
		if cr.n > MaxPassphraseBytes+2 {
			t.Fatalf("%d bytes were read", cr.n)
		}
		if cr.closed {
			t.Fatal("the reader was closed")
		}
		// the expected line, found by other means
		end := bytes.IndexByte(data, '\n')
		var line []byte
		complete := false
		switch {
		case end >= 0 && end < MaxPassphraseBytes+2:
			line, complete = data[:end], true
		case end < 0 && len(data) < MaxPassphraseBytes+2:
			line = data
		}
		if complete {
			line = bytes.TrimSuffix(line, []byte{'\r'})
		}
		want := (complete || end < 0 && len(data) < MaxPassphraseBytes+2) && len(line) > 0 && CheckPassphrase(line) == nil
		if err != nil {
			if want {
				t.Fatalf("refused a line that is acceptable: %v", err)
			}
			if got != nil {
				t.Fatal("a value came with an error")
			}
			if !errors.Is(err, ErrPassphrase) {
				t.Fatalf("%v", err)
			}
			return
		}
		if !want || !bytes.Equal(got, line) {
			t.Fatalf("accepted %q for the input %q", got, data)
		}
		if complete && cr.n != end+1 {
			t.Fatalf("read %d bytes for a line that ends at %d", cr.n, end)
		}
	})
}

// FuzzOpenPassphraseFile reads whatever file stands in the place of a passphrase file, through the
// Store, with a source that fails when it is asked: scrypt never runs. The file is refused for its
// shape, or the source is asked and its error comes back; nothing else may come out.
func FuzzOpenPassphraseFile(f *testing.F) {
	lib := libraryFile(f, testPass, 10, []byte("a payload"))
	// the header of the file of the library says 10; a header that says 18 passes the check
	hdr := bytes.Replace(lib, []byte(" 10\n"), []byte(" 18\n"), 1)
	f.Add(hdr)
	f.Add(lib)
	f.Add(hdr[:len(hdr)/2])
	f.Add(headerOf(scryptStanza("18")))
	f.Add(headerOf(scryptStanza("22")))
	f.Add(headerOf(scryptStanza("23")))
	f.Add(headerOf(scryptStanza("18"), scryptStanza("18")))
	f.Add([]byte("-----BEGIN AGE ENCRYPTED FILE-----\n"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xA5}, MaxKeyFileSize+1))
	boom := errors.New("the source failed")
	f.Fuzz(func(t *testing.T, data []byte) {
		src := &passSource{def: testPass, err: boom}
		st := &Store{
			mode: ModePassphrase, fsys: staticFS{files: map[string][]byte{"A.x509.key.age": data}},
			w: refuseWriter{t}, format: ageFormat{}, source: src,
		}
		key, err := st.OpenX509(bg(), "A")
		if err == nil || key != nil {
			t.Fatalf("a key came out of the fuzzed file (%v)", err)
		}
		if errors.Is(err, boom) {
			if len(data) > MaxKeyFileSize || inspectHeader(data) != nil {
				t.Fatal("the source was asked for a file that the header check refuses")
			}
			if src.calls() != 1 {
				t.Fatalf("asked %d times", src.calls())
			}
			return
		}
		if !errors.Is(err, ErrKeyFile) {
			t.Fatalf("a refusal that is not ErrKeyFile: %v", err)
		}
		if src.calls() != 0 {
			t.Fatal("the source was asked for a refused file")
		}
	})
}

// FuzzReadPayloadOfAnAgeFile reads the payload stream of an age file under a key that the test
// knows, so that no scrypt runs: the header of a good file stays and the bytes after it are the
// fuzzed ones. It must not panic, must stay inside the buffer and must give an ErrKeyFile or a
// payload.
func FuzzReadPayloadOfAnAgeFile(f *testing.F) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatal(err)
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, id.Recipient())
	if err != nil {
		f.Fatal(err)
	}
	payload := bytes.Repeat([]byte("payload "), 20)
	_, _ = w.Write(payload)
	_ = w.Close()
	good := out.Bytes()
	hl := headerLen(f, good)
	header, body := good[:hl], good[hl:]
	f.Add(bytes.Clone(body))
	f.Add(bytes.Clone(body[:len(body)-1]))
	f.Add(append(bytes.Clone(body), 0))
	f.Add(body[:16])
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{1}, 200000))
	f.Fuzz(func(t *testing.T, tail []byte) {
		r, err := age.Decrypt(bytes.NewReader(append(bytes.Clone(header), tail...)), id)
		if err != nil {
			return
		}
		buf := make([]byte, MaxKeyFileSize+1)
		n, err := readPayload(r, buf)
		if err != nil {
			if !errors.Is(err, ErrKeyFile) || n != 0 {
				t.Fatalf("%d, %v", n, err)
			}
			if !allZero(buf[:min(len(buf), 64)]) {
				t.Fatal("the buffer is not cleared after an error")
			}
			return
		}
		if n < 0 || n > len(buf) {
			t.Fatalf("n = %d", n)
		}
		if bytes.Equal(tail, body) && !bytes.Equal(buf[:n], payload) {
			t.Fatal("the good file does not read as its payload")
		}
	})
}
