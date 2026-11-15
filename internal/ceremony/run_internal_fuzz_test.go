package ceremony

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzTypedConfirmation is the line that a person types, as the process reads it from standard input:
// any bytes. A line confirms only when it is the first eight characters of the digest in
// hexadecimal digits of either case, with its line feed within the first 64 bytes, and nothing is
// taken from the input beyond them.
func FuzzTypedConfirmation(f *testing.F) {
	const digest = "0123abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345"
	for _, s := range []string{
		"0123abcd\n", "0123ABCD\r\n", "\n", "", "0123abcd", "0123abc\n", "0123abcde\n", "0123abcd \n",
		strings.Repeat("a", 64) + "\n", strings.Repeat("a", 63) + "\n", "0123abcd\n0123abcd\n", "\xff\xfe\n", "0123abc\x00\n",
		"０123abc\n", "0123abcd\r\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		r := &countReader{r: bytes.NewReader(in)}
		line, err := readTypedLine(r)
		if r.n > maxTypedLine {
			t.Fatalf("%d bytes were taken, the limit is %d", r.n, maxTypedLine)
		}
		if err != nil {
			if line != "" {
				t.Fatalf("an error with a line %q", line)
			}
			return
		}
		head := in
		if len(head) > maxTypedLine {
			head = head[:maxTypedLine]
		}
		i := bytes.IndexByte(head, '\n')
		if i < 0 {
			t.Fatalf("a line was read with no line feed in the first %d bytes: %q", maxTypedLine, line)
		}
		want := strings.TrimSuffix(string(head[:i]), "\r")
		if line != want {
			t.Fatalf("the line is %q, the input holds %q", line, want)
		}
		if typedMatches(line, digest) {
			if len(line) != typedLength || !strings.EqualFold(line, digest[:typedLength]) {
				t.Fatalf("%q confirms", line)
			}
			for _, c := range []byte(line) {
				if !strings.ContainsRune("0123456789abcdefABCDEF", rune(c)) {
					t.Fatalf("%q confirms and holds %q", line, c)
				}
			}
		}
	})
}

type countReader struct {
	r interface{ Read([]byte) (int, error) }
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}
