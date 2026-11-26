package openpgp_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// F. The armour: one block of type PGP PRIVATE KEY BLOCK, and every fault of it. And the truncation of
// a file at every byte, binary and armoured.

// fkArmourText is the armour block of a file as text, with the pieces apart so that a test changes one.
type fkArmourText struct {
	head    string
	headers []string
	data    []string // the base64 lines
	crc     string   // the CRC-24 line with its equals sign, or ""
	end     string
}

func (a fkArmourText) String(eol string) string {
	var b strings.Builder
	b.WriteString(a.head + eol)
	for _, h := range a.headers {
		b.WriteString(h + eol)
	}
	b.WriteString(eol)
	for _, d := range a.data {
		b.WriteString(d + eol)
	}
	if a.crc != "" {
		b.WriteString(a.crc + eol)
	}
	b.WriteString(a.end + eol)
	return b.String()
}

// fkSplitArmour reads the text that go-crypto writes into its pieces.
func fkSplitArmour(t testing.TB, text []byte) fkArmourText {
	t.Helper()
	lines := strings.Split(strings.TrimRight(string(text), "\n"), "\n")
	a := fkArmourText{head: lines[0], end: lines[len(lines)-1]}
	i := 1
	for ; lines[i] != ""; i++ {
		a.headers = append(a.headers, lines[i])
	}
	i++
	for ; i < len(lines)-1; i++ {
		if strings.HasPrefix(lines[i], "=") {
			a.crc = lines[i]
			continue
		}
		a.data = append(a.data, lines[i])
	}
	if a.crc == "" {
		t.Fatalf("go-crypto wrote no CRC-24 line")
	}
	return a
}

// fkRewrap writes the base64 text again in lines of n characters.
func fkRewrap(a fkArmourText, n int) fkArmourText {
	all := strings.Join(a.data, "")
	a.data = nil
	for len(all) > n {
		a.data = append(a.data, all[:n])
		all = all[n:]
	}
	a.data = append(a.data, all)
	return a
}

func TestForeignArmourAcceptedForms(t *testing.T) {
	b := fkNamed(t, "ed25519")
	for _, prot := range []fkProt{{}, {Pass: fkPass}} {
		file := b.file(t, prot)
		want := fkViewOf(fkRead(t, file))
		text := fkSplitArmour(t, fkArmourKey(t, file))
		many := text
		many.headers = nil
		for i := 0; i < 32; i++ {
			many.headers = append(many.headers, fmt.Sprintf("Header%d: value %d", i, i))
		}
		noCRC := text
		noCRC.crc = ""
		padded := text
		padded.data = append([]string(nil), text.data...)
		for i := range padded.data {
			padded.data[i] += " \t"
		}
		cases := []struct {
			name string
			in   string
		}{
			{"as go-crypto writes it", text.String("\n")},
			{"with CRLF line ends", text.String("\r\n")},
			{"with no CRC-24 line", noCRC.String("\n")},
			{"with no line end after the end line", strings.TrimSuffix(text.String("\n"), "\n")},
			{"with white space after every line", padded.String("\n")},
			{"with blank lines and white space after the block", text.String("\n") + "\n\n \t\n\r\n"},
			{"with 32 header lines", many.String("\n")},
			{"with no header line", func() string { x := text; x.headers = nil; return x.String("\n") }()},
			{"in lines of 76 characters", fkRewrap(text, 76).String("\n")},
			{"in lines of 4 characters", fkRewrap(text, 4).String("\n")},
			{"in lines of 60 characters", fkRewrap(text, 60).String("\n")},
			{"with a header that holds colons and quotes", func() string { x := text; x.headers = []string{"Comment: a: b: \"c\""}; return x.String("\n") }()},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				k, err := openpgp.ReadForeignKey([]byte(c.in))
				if err != nil {
					t.Fatalf("%v", err)
				}
				if !fkDeepEqual(fkViewOf(k), want) {
					t.Error("another key than the binary file")
				}
			})
		}
	}
}

func TestForeignArmourFaults(t *testing.T) {
	b := fkNamed(t, "ed25519")
	for _, prot := range []fkProt{{}, {Pass: fkPass}} {
		file := b.file(t, prot)
		good := fkSplitArmour(t, fkArmourKey(t, file))
		block := good.String("\n")
		change := func(f func(a *fkArmourText)) string {
			a := good
			a.headers = append([]string(nil), good.headers...)
			a.data = append([]string(nil), good.data...)
			f(&a)
			return a.String("\n")
		}
		pub := "-----BEGIN PGP PUBLIC KEY BLOCK-----"
		cases := []struct {
			name  string
			in    string
			kind  error
			words []string
		}{
			{"a public key block", strings.NewReplacer("PRIVATE", "PUBLIC").Replace(block), openpgp.ErrForeignArmour, []string{"public key block"}},
			{"a message", change(func(a *fkArmourText) { a.head = "-----BEGIN PGP MESSAGE-----" }), openpgp.ErrForeignArmour, []string{"message"}},
			{"a message in parts", change(func(a *fkArmourText) { a.head = "-----BEGIN PGP MESSAGE, PART 1/2-----" }), openpgp.ErrForeignArmour, []string{"message"}},
			{"a signature", change(func(a *fkArmourText) { a.head = "-----BEGIN PGP SIGNATURE-----" }), openpgp.ErrForeignArmour, []string{"signature"}},
			{"a signed message", change(func(a *fkArmourText) { a.head = "-----BEGIN PGP SIGNED MESSAGE-----" }), openpgp.ErrForeignArmour, []string{"signed message"}},
			{"a type that is not known", change(func(a *fkArmourText) { a.head = "-----BEGIN PGP QUOKKA BLOCK-----" }), openpgp.ErrForeignArmour, []string{"another armour type"}},
			{"a head line with text after it", change(func(a *fkArmourText) { a.head += " x" }), openpgp.ErrForeignArmour, nil},
			{"a head line with the dashes cut", change(func(a *fkArmourText) { a.head = a.head[:len(a.head)-2] }), openpgp.ErrForeignArmour, nil},
			{"two blocks", block + block, openpgp.ErrForeignArmour, []string{"second armour block"}},
			{"two blocks with a blank line between", block + "\n" + block, openpgp.ErrForeignArmour, []string{"second armour block"}},
			{"a public block after the block", block + pub + "\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n", openpgp.ErrForeignArmour, []string{"second armour block"}},
			{"text after the end line", block + "trailer\n", openpgp.ErrForeignArmour, []string{"text after the end line"}},
			{"text after the end line, on the same line", strings.TrimSuffix(block, "\n") + " trailer\n", openpgp.ErrForeignArmour, nil},
			{"no blank line after the headers", strings.Replace(block, "\n\n", "\n", 1), openpgp.ErrForeignArmour, []string{"blank line"}},
			{"no blank line and no headers", strings.Replace(change(func(a *fkArmourText) { a.headers = nil }), "\n\n", "\n", 1), openpgp.ErrForeignArmour, nil},
			{"a bad CRC-24 line", change(func(a *fkArmourText) { a.crc = "=AAAA" }), openpgp.ErrForeignArmour, []string{"CRC-24"}},
			{"a CRC-24 line that is one character short", change(func(a *fkArmourText) { a.crc = a.crc[:4] }), openpgp.ErrForeignArmour, []string{"CRC-24"}},
			{"a CRC-24 line that is one character long", change(func(a *fkArmourText) { a.crc += "A" }), openpgp.ErrForeignArmour, []string{"CRC-24"}},
			{"a CRC-24 line that is not base64", change(func(a *fkArmourText) { a.crc = "=!!!!" }), openpgp.ErrForeignArmour, []string{"CRC-24"}},
			{"two CRC-24 lines", change(func(a *fkArmourText) { a.data = append(a.data, a.crc) }), openpgp.ErrForeignArmour, []string{"CRC-24"}},
			{"text after the CRC-24 line", change(func(a *fkArmourText) { a.end = "AAAA\n" + a.end }), openpgp.ErrForeignArmour, []string{"after its padding or its CRC-24"}},
			{"a line of 80 characters", fkRewrap(good, 80).String("\n"), openpgp.ErrForeignArmour, []string{"76"}},
			{"a line of 77 characters", func() string {
				a := fkRewrap(good, 76)
				a.data[0] += "A"
				return a.String("\n")
			}(), openpgp.ErrForeignArmour, []string{"76"}},
			{"a line that is not a whole number of groups", change(func(a *fkArmourText) { a.data[0] = a.data[0][:len(a.data[0])-1] }), openpgp.ErrForeignArmour, []string{"groups of four"}},
			{"an empty line among the data", change(func(a *fkArmourText) { a.data = append([]string{a.data[0], ""}, a.data[1:]...) }), openpgp.ErrForeignArmour, []string{"empty"}},
			{"padding in the middle", change(func(a *fkArmourText) { a.data[0] = a.data[0][:len(a.data[0])-4] + "AA==" }), openpgp.ErrForeignArmour, []string{"after its padding"}},
			{"a character that is not base64", change(func(a *fkArmourText) { a.data[1] = "!" + a.data[1][1:] }), openpgp.ErrForeignArmour, []string{"not base64"}},
			{"a header of 257 characters", change(func(a *fkArmourText) { a.headers = []string{"Comment: " + strings.Repeat("x", 249)} }), openpgp.ErrForeignArmour, []string{"256"}},
			{"33 header lines", change(func(a *fkArmourText) {
				a.headers = nil
				for i := 0; i < 33; i++ {
					a.headers = append(a.headers, fmt.Sprintf("Header%d: v", i))
				}
			}), openpgp.ErrForeignArmour, []string{"32 header"}},
			{"a header with no colon", change(func(a *fkArmourText) { a.headers = []string{"Comment is here"} }), openpgp.ErrForeignArmour, []string{"Key: Value"}},
			{"no end line", change(func(a *fkArmourText) { a.end = "" }), openpgp.ErrForeignArmour, nil},
			{"the end line of another type", change(func(a *fkArmourText) { a.end = "-----END PGP PUBLIC KEY BLOCK-----" }), openpgp.ErrForeignArmour, []string{"end line"}},
			{"an end line with text after it", change(func(a *fkArmourText) { a.end += " x" }), openpgp.ErrForeignArmour, []string{"end line"}},
			{"a block of no bytes", change(func(a *fkArmourText) { a.data, a.crc = nil, "" }), openpgp.ErrForeignArmour, []string{"no bytes"}},
			{"the head line and nothing more", good.head + "\n", openpgp.ErrForeignArmour, []string{"blank line"}},
			{"the head line with no line end", good.head, openpgp.ErrForeignArmour, nil},
			// not armour: the file does not start with the head line, so it is read as packets
			{"a line of text before the block", "hello\n" + block, openpgp.ErrForeignForm, nil},
			{"a blank line before the block", "\n" + block, openpgp.ErrForeignForm, nil},
			{"a space before the head line", " " + block, openpgp.ErrForeignForm, nil},
			// the block holds bytes that are not a key
			{"an armoured file of other bytes", func() string {
				a := good
				a.data = []string{base64.StdEncoding.EncodeToString([]byte("not a key at all"))}
				a.crc = ""
				return a.String("\n")
			}(), openpgp.ErrForeignForm, nil},
		}
		for _, c := range cases {
			name := c.name
			if prot.Pass != "" {
				name += " (protected)"
			}
			t.Run(name, func(t *testing.T) {
				err := fkRefused(t, name, []byte(c.in), b, c.kind)
				if err == nil {
					return
				}
				for _, w := range c.words {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("the text %q does not say %q", err, w)
					}
				}
				if strings.Contains(err.Error(), "QUOKKA") || strings.Contains(err.Error(), "trailer") || strings.Contains(err.Error(), "hello") {
					t.Errorf("the text copies a byte of the file: %q", err)
				}
			})
		}
	}
}

// A truncation at every byte: at a packet boundary the file is read if it holds a primary, a user ID and
// its self-signature, and refused for want of a self-signature before; anywhere else it is cut short.
func TestForeignTruncationOfBinaryFiles(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, prot := range []fkProt{{}, {Pass: fkPass}} {
			file := b.file(t, prot)
			boundary := map[int]int{0: 0} // the offset and the number of packets before it
			off := 0
			var tags []byte
			for i, p := range splitPackets(t, file) {
				off += len(p.Raw)
				boundary[off] = i + 1
				tags = append(tags, p.Tag)
			}
			// a secret subkey is read only with a binding after it: a cut that leaves one without
			// its signature is refused for that
			unbound := func(n int) bool {
				for i := 0; i < n; i++ {
					if tags[i] == 7 && (i+1 >= n || tags[i+1] != 2) {
						return true
					}
				}
				return false
			}
			for cut := 0; cut <= len(file); cut++ {
				in := file[:cut]
				n, atBoundary := boundary[cut]
				switch {
				case cut == 0:
					_ = fkRefused(t, "empty", in, b, openpgp.ErrForeignForm)
				case atBoundary && n < 3:
					_ = fkRefused(t, fmt.Sprintf("%d packets", n), in, b, openpgp.ErrForeignSelfSignature)
				case atBoundary && unbound(n):
					// the file is read, and the subkey with no binding is left out and reported
					k, err := openpgp.ReadForeignKey(in)
					if err != nil {
						t.Fatalf("%d packets: %v", n, err)
					}
					left := 0
					for _, s := range k.Subkeys {
						if !s.InCertificate {
							left++
						}
					}
					if left == 0 {
						t.Errorf("%d packets: a secret subkey with no binding is in the certificate", n)
					}
					_ = fkCertProperty(t, fmt.Sprintf("%d packets", n), k)
				case atBoundary:
					if _, err := openpgp.ReadForeignKey(in); err != nil {
						t.Fatalf("%d packets: %v", n, err)
					}
				default:
					_ = fkRefused(t, fmt.Sprintf("cut at byte %d of %d", cut, len(file)), in, b, openpgp.ErrForeignForm)
				}
			}
		}
	})
}

func TestForeignTruncationOfArmouredFiles(t *testing.T) {
	for _, name := range []string{"ed25519", "p384"} {
		b := fkNamed(t, name)
		for _, prot := range []fkProt{{}, {Pass: fkPass}} {
			text := fkArmourKey(t, b.file(t, prot))
			for cut := 0; cut <= len(text); cut++ {
				in := text[:cut]
				switch {
				case cut == 0:
					_ = fkRefused(t, "empty", in, b, openpgp.ErrForeignForm)
				case cut < len("-----BEGIN"):
					// not armour yet: read as packets, and the first byte is a dash
					_ = fkRefused(t, "less than a head line", in, b, openpgp.ErrForeignForm)
				case cut == len(text):
					// go-crypto writes no line end after the end line, and none is needed
					if _, err := openpgp.ReadForeignKey(in); err != nil {
						t.Fatalf("cut %d of %d: %v", cut, len(text), err)
					}
				default:
					_ = fkRefused(t, fmt.Sprintf("cut at byte %d of %d", cut, len(text)), in, b, openpgp.ErrForeignArmour)
				}
			}
		}
	}
}
