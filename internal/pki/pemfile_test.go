package pki_test

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// ReadPEMFile is the strict rule of the contract for a PEM file ("The request"), with the label as a parameter.

func pemText(label string, der []byte, width int, eol string) string {
	text := base64.StdEncoding.EncodeToString(der)
	var b strings.Builder
	b.WriteString("-----BEGIN " + label + "-----" + eol)
	for len(text) > 0 {
		n := min(width, len(text))
		b.WriteString(text[:n] + eol)
		text = text[n:]
	}
	b.WriteString("-----END " + label + "-----" + eol)
	return b.String()
}

func someDER(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*7 + 3)
	}
	return out
}

// refusedPEM checks that err is a refusal of a PEM file: it wraps ErrPEM and none of the three other kinds
// (a fault of a file is not a fault of a request, of a signature or of a parameter), and its text is
// printable ASCII.
func refusedPEM(t testing.TB, got error) {
	t.Helper()
	refused(t, got, pki.ErrPEM)
}

func isPEM(got error) bool { return errors.Is(got, pki.ErrPEM) }

func TestReadPEMFileReadsTheOneFormOfTheRule(t *testing.T) {
	for _, c := range []struct {
		name  string
		label string
		file  string
		der   []byte
	}{
		{"a request, lines of 64", "CERTIFICATE REQUEST", pemText("CERTIFICATE REQUEST", someDER(300), 64, "\n"), someDER(300)},
		{"a certificate, lines of 64", "CERTIFICATE", pemText("CERTIFICATE", someDER(300), 64, "\n"), someDER(300)},
		{"lines of 76", "CERTIFICATE", pemText("CERTIFICATE", someDER(300), 76, "\n"), someDER(300)},
		{"lines of 1 character", "CERTIFICATE", pemText("CERTIFICATE", someDER(3), 1, "\n"), someDER(3)},
		{"CRLF in the whole file", "CERTIFICATE", pemText("CERTIFICATE", someDER(100), 64, "\r\n"), someDER(100)},
		{"no line end after the footer", "CERTIFICATE", strings.TrimSuffix(pemText("CERTIFICATE", someDER(100), 64, "\n"), "\n"), someDER(100)},
		{"one byte", "CERTIFICATE", pemText("CERTIFICATE", []byte{7}, 64, "\n"), []byte{7}},
		{"two bytes", "CERTIFICATE", pemText("CERTIFICATE", []byte{7, 8}, 64, "\n"), []byte{7, 8}},
		{"a label of two words", "PUBLIC KEY", pemText("PUBLIC KEY", someDER(50), 64, "\n"), someDER(50)},
		{"a label of three words", "A B C", pemText("A B C", someDER(50), 64, "\n"), someDER(50)},
	} {
		t.Run(c.name, func(t *testing.T) {
			der, err := pki.ReadPEMFile([]byte(c.file), c.label)
			if err != nil || !bytes.Equal(der, c.der) {
				t.Fatalf("der %x, error %v", der, err)
			}
		})
	}
}

func TestReadPEMFileReadsWhatEncodingPemWrites(t *testing.T) {
	for _, n := range []int{1, 2, 3, 47, 48, 49, 200, 1000, 70000} {
		der := someDER(n)
		file := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		got, err := pki.ReadPEMFile(file, "CERTIFICATE")
		if err != nil || !bytes.Equal(got, der) {
			t.Errorf("%d bytes: %v", n, err)
		}
	}
}

func TestReadPEMFileRefusesEveryFileThatBreaksARule(t *testing.T) {
	good := pemText("CERTIFICATE", someDER(200), 64, "\n")
	lines := strings.Split(strings.TrimSuffix(good, "\n"), "\n")
	join := func(l []string) string { return strings.Join(l, "\n") + "\n" }
	for _, c := range []struct {
		name  string
		file  string
		label string
	}{
		{"an empty file", "", "CERTIFICATE"},
		{"text", "certificate", "CERTIFICATE"},
		{"another label", good, "CERTIFICATE REQUEST"},
		{"a label that is a longer one", pemText("CERTIFICATE REQUEST", someDER(50), 64, "\n"), "CERTIFICATE"},
		{"a label that is a shorter one", good, "CERTIFICATE REQUEST"},
		{"a label in lower case in the file", strings.ReplaceAll(good, "CERTIFICATE", "certificate"), "CERTIFICATE"},
		{"a header that is not a marker", "-----BEGIN-----\n" + strings.Join(lines[1:], "\n") + "\n", "CERTIFICATE"},
		{"a space after the first line", strings.Replace(good, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE----- \n", 1), "CERTIFICATE"},
		{"no line end after the first line", strings.Replace(good, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----", 1), "CERTIFICATE"},
		{"a carriage return alone after the first line", strings.Replace(good, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\r", 1), "CERTIFICATE"},
		{"mixed line ends: CRLF first", strings.Replace(good, "\n", "\r\n", 1), "CERTIFICATE"},
		{"mixed line ends: LF after CRLF", strings.Replace(pemText("CERTIFICATE", someDER(200), 64, "\r\n"), "\r\n", "\n", 2), "CERTIFICATE"},
		{"a header line", join(append([]string{lines[0], "Proc-Type: 4,ENCRYPTED"}, lines[1:]...)), "CERTIFICATE"},
		{"a line with a colon", join(append([]string{lines[0], "ab:cd"}, lines[1:]...)), "CERTIFICATE"},
		{"a blank line in the body", join(append(append([]string{}, lines[:2]...), append([]string{""}, lines[2:]...)...)), "CERTIFICATE"},
		{"a blank line before the footer", join(append(append([]string{}, lines[:len(lines)-1]...), "", lines[len(lines)-1])), "CERTIFICATE"},
		{"a line of 77 characters", join(append([]string{lines[0], lines[1] + strings.Repeat("A", 13)}, lines[2:]...)), "CERTIFICATE"},
		{"a space in a line", join(append([]string{lines[0], lines[1][:10] + " " + lines[1][10:]}, lines[2:]...)), "CERTIFICATE"},
		{"a tab at the end of a line", join(append([]string{lines[0], lines[1] + "\t"}, lines[2:]...)), "CERTIFICATE"},
		{"a character outside the alphabet", join(append([]string{lines[0], "*" + lines[1][1:]}, lines[2:]...)), "CERTIFICATE"},
		{"the URL alphabet", join(append([]string{lines[0], strings.NewReplacer("+", "-", "/", "_").Replace(lines[1])}, lines[2:]...)), "CERTIFICATE"},
		{"a padding that is left out", pemText("CERTIFICATE", []byte{1}, 64, "\n")[:len("-----BEGIN CERTIFICATE-----\n")+2] + "\n-----END CERTIFICATE-----\n", "CERTIFICATE"},
		{"an empty body", "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", "CERTIFICATE"},
		{"no footer", join(lines[:len(lines)-1]), "CERTIFICATE"},
		{"another footer", strings.Replace(good, "-----END CERTIFICATE-----", "-----END CERTIFICATE REQUEST-----", 1), "CERTIFICATE"},
		{"a footer with a space after it", strings.Replace(good, "-----END CERTIFICATE-----", "-----END CERTIFICATE----- ", 1), "CERTIFICATE"},
		{"text before the block", "note\n" + good, "CERTIFICATE"},
		{"a blank line before the block", "\n" + good, "CERTIFICATE"},
		{"text after the block", good + "x", "CERTIFICATE"},
		{"a line of text after the block", good + "x\n", "CERTIFICATE"},
		{"two line ends after the block", good + "\n", "CERTIFICATE"},
		{"a second block", good + good, "CERTIFICATE"},
		{"a second block of another kind", good + pemText("CERTIFICATE REQUEST", someDER(5), 64, "\n"), "CERTIFICATE"},
		{"the footer twice", good + "-----END CERTIFICATE-----\n", "CERTIFICATE"},
		{"a NUL", strings.Replace(good, lines[1][:3], "A\x00B", 1), "CERTIFICATE"},
		{"a byte above ASCII", strings.Replace(good, lines[1][:1], "\xc3\xa9", 1), "CERTIFICATE"},
		{"a file over 256 KiB", pemText("CERTIFICATE", someDER(pki.MaxRequestSize), 64, "\n"), "CERTIFICATE"},
		{"a file of 256 KiB and a byte of text", strings.Repeat("A", pki.MaxRequestSize+1), "CERTIFICATE"},
	} {
		t.Run(c.name, func(t *testing.T) {
			der, err := pki.ReadPEMFile([]byte(c.file), c.label)
			if err == nil || der != nil {
				t.Fatalf("der %x, error %v", der, err)
			}
			refusedPEM(t, err)
		})
	}
	t.Run("bits after the data", func(t *testing.T) {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		for _, n := range []int{1, 2, 4, 5, 100, 101} {
			file := pemText("CERTIFICATE", someDER(n), 64, "\n")
			ls := strings.Split(strings.TrimSuffix(file, "\n"), "\n")
			last := ls[len(ls)-2]
			pad := len(last) - len(strings.TrimRight(last, "="))
			if pad == 0 {
				continue
			}
			i := len(last) - pad - 1
			idx := strings.IndexByte(alphabet, last[i])
			mask := 3
			if pad == 2 {
				mask = 15
			}
			ls[len(ls)-2] = last[:i] + string(alphabet[idx&^mask|((idx+1)&mask)]) + last[i+1:]
			if got, err := pki.ReadPEMFile([]byte(strings.Join(ls, "\n")+"\n"), "CERTIFICATE"); err == nil {
				t.Errorf("%d bytes: bits after the data are read as %x", n, got)
			}
		}
	})
	t.Run("a file of exactly the limit is refused for its text and one of 100 KiB is read", func(t *testing.T) {
		_, err := pki.ReadPEMFile(bytes.Repeat([]byte("A"), pki.MaxRequestSize), "CERTIFICATE")
		refusedPEM(t, err)
		der := someDER(100 * 1024)
		got, err := pki.ReadPEMFile([]byte(pemText("CERTIFICATE", der, 64, "\n")), "CERTIFICATE")
		if err != nil || !bytes.Equal(got, der) {
			t.Errorf("%v", err)
		}
	})
}

func TestReadPEMFileRefusesALabelThatIsNotAMarkerAsAParameter(t *testing.T) {
	file := []byte(pemText("CERTIFICATE", someDER(30), 64, "\n"))
	for _, label := range []string{"", " ", "certificate", "CERTIFICATE ", " CERTIFICATE", "CERTIFICATE  REQUEST", "CERT-IFICATE", "CERTIFICATE\n", "CERT1", "CERTIFICATE-----\n-----BEGIN X", "É"} {
		der, err := pki.ReadPEMFile(file, label)
		if der != nil {
			t.Errorf("label %q: a DER comes with the error", label)
		}
		refused(t, err, pki.ErrParams)
		if isPEM(err) {
			t.Errorf("label %q: a parameter is a fault of a file", label)
		}
	}
}

func TestReadPEMFileCopiesWhatItReadsAndReturnsNothingThatSharesTheFile(t *testing.T) {
	der := someDER(100)
	file := []byte(pemText("CERTIFICATE", der, 64, "\n"))
	keep := bytes.Clone(file)
	got, err := pki.ReadPEMFile(file, "CERTIFICATE")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(file, keep) {
		t.Error("the file was changed")
	}
	for i := range file {
		file[i] = 'A'
	}
	if !bytes.Equal(got, der) {
		t.Error("the DER changed with the file")
	}
	got[0] ^= 1
	again, _ := pki.ReadPEMFile(keep, "CERTIFICATE")
	if !bytes.Equal(again, der) {
		t.Error("two readings share the bytes")
	}
}

// ParseRequestFile is the same rule: a file that ReadPEMFile refuses is a request that is refused with
// malformed, and the words are about the request file.
func TestParseRequestFileSaysEachRefusalOfTheSharedReaderInItsOwnWords(t *testing.T) {
	good := pemText("CERTIFICATE REQUEST", someDER(50), 64, "\n")
	for _, c := range []struct {
		name string
		file string
		text string
	}{
		{"too long", strings.Repeat("A", pki.MaxRequestSize+1), "the request file is longer than"},
		{"not a block", "x", "the request file does not start with a PEM block"},
		{"another label", pemText("CERTIFICATE", someDER(5), 64, "\n"), "does not have the label CERTIFICATE REQUEST"},
		{"no line end", strings.Replace(good, "-----BEGIN CERTIFICATE REQUEST-----\n", "-----BEGIN CERTIFICATE REQUEST-----", 1), "the first line of the request file is not followed by a line end"},
		{"no footer", strings.Replace(good, "-----END CERTIFICATE REQUEST-----\n", "", 1), "the request file is not a PEM block"},
		{"text after", good + "x", "the request file has something after its PEM block"},
		{"a header", strings.Replace(good, "\n", "\nA: b\n", 1), "the PEM block of the request file has headers"},
		{"a blank line", strings.Replace(good, "\n", "\n\n", 1), "a line of the base64 text of the request file is empty or longer than 76 characters"},
		{"bad base64", strings.Replace(good, "\n", "\n*", 1), "the base64 text of the request file is not the standard base64"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := pki.ParseRequestFile([]byte(c.file))
			refused(t, err, pki.ErrRequest)
			if pki.CheckOf(err) != pki.CheckMalformed {
				t.Fatalf("error %v, check %v", err, pki.CheckOf(err))
			}
			if !strings.Contains(err.Error(), c.text) {
				t.Errorf("the error %q does not say %q", err, c.text)
			}
		})
	}
}

// The package says that an error wraps one of four kinds and one only, and that only ReadPEMFile returns the fourth.
func TestEveryErrorOfTheReaderIsOneOfTheFourKindsAndOnlyThisReaderMakesThePEMKind(t *testing.T) {
	if len(kinds) != 4 || !errors.Is(kinds[3], pki.ErrPEM) {
		t.Fatalf("the kinds of the helpers are %v", kinds)
	}
	for name, c := range map[string]struct {
		file  string
		label string
		kind  error
	}{
		"a file that is not a block": {"x", "CERTIFICATE", pki.ErrPEM},
		"a file that is too long":    {strings.Repeat("A", pki.MaxRequestSize+1), "CERTIFICATE", pki.ErrPEM},
		"a label that is no marker":  {pemText("CERTIFICATE", someDER(9), 64, "\n"), "certificate", pki.ErrParams},
	} {
		_, err := pki.ReadPEMFile([]byte(c.file), c.label)
		if got := kindOf(t, err); !errors.Is(got, c.kind) {
			t.Errorf("%s: the kind is %v, want %v", name, got, c.kind)
		}
	}
	// The request side keeps its own kind for the same faults, and none of its errors is of the PEM kind.
	for name, file := range map[string]string{
		"not a block":     "x",
		"too long":        strings.Repeat("A", pki.MaxRequestSize+1),
		"another label":   pemText("CERTIFICATE", someDER(9), 64, "\n"),
		"text after":      pemText("CERTIFICATE REQUEST", someDER(9), 64, "\n") + "x",
		"a blank line":    strings.Replace(pemText("CERTIFICATE REQUEST", someDER(90), 64, "\n"), "\n", "\n\n", 1),
		"a header":        strings.Replace(pemText("CERTIFICATE REQUEST", someDER(90), 64, "\n"), "\n", "\nA: b\n", 1),
		"CR alone":        strings.ReplaceAll(pemText("CERTIFICATE REQUEST", someDER(90), 64, "\n"), "\n", "\r"),
		"base64 trailing": strings.Replace(pemText("CERTIFICATE REQUEST", []byte{1}, 64, "\n"), "AQ==", "AR==", 1),
	} {
		_, err := pki.ParseRequestFile([]byte(file))
		refused(t, err, pki.ErrRequest)
		if isPEM(err) {
			t.Errorf("%s: the request reader returns the PEM kind: %v", name, err)
		}
	}
}

func FuzzReadPEMFile(f *testing.F) {
	f.Add([]byte(pemText("CERTIFICATE", someDER(100), 64, "\n")), "CERTIFICATE")
	f.Add([]byte(pemText("CERTIFICATE REQUEST", someDER(100), 76, "\r\n")), "CERTIFICATE REQUEST")
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"), "CERTIFICATE")
	f.Add(readFixture(f, "csr-nc.csr.pem"), "CERTIFICATE REQUEST")
	f.Fuzz(func(t *testing.T, file []byte, label string) {
		keep := bytes.Clone(file)
		der, err := pki.ReadPEMFile(file, label)
		if !bytes.Equal(file, keep) {
			t.Fatal("the file was changed")
		}
		if err != nil {
			if der != nil {
				t.Fatal("a DER comes with an error")
			}
			if !isPEM(err) && !errors.Is(err, kinds[0]) {
				t.Fatalf("an error of no kind: %v", err)
			}
			return
		}
		if len(der) == 0 || len(file) > pki.MaxRequestSize {
			t.Fatalf("a DER of %d bytes from a file of %d", len(der), len(file))
		}
		// The text is the one text of the DER: the standard reader, which is looser, finds the same block.
		blk, _ := pem.Decode(file)
		if blk == nil || blk.Type != label || !bytes.Equal(blk.Bytes, der) {
			t.Fatalf("the standard reader finds %v for a file that the strict reader reads as %x", blk, der)
		}
	})
}
