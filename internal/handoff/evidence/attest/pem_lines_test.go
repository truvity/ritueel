package attest_test

import (
	"bytes"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff/evidence/attest"
)

const (
	pemBegin = "-----BEGIN CERTIFICATE-----"
	pemEnd   = "-----END CERTIFICATE-----"
)

// pemLines is the canonical text of one block, line by line, with no line end: the BEGIN line, the Base64
// lines and the END line.
func pemLines(t testing.TB, der []byte) []string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(string(pemOf("CERTIFICATE", der)), "\n"), "\n")
	if len(lines) < 4 || lines[0] != pemBegin || lines[len(lines)-1] != pemEnd {
		t.Fatalf("test setup: a block of %d lines", len(lines))
	}
	return lines
}

// pemText writes blocks, each a list of lines, with eol after every line. between goes between two blocks
// after the line end of the END line. When final is false the last line has no line end.
func pemText(blocks [][]string, eol, between string, final bool) []byte {
	var b strings.Builder
	for i, lines := range blocks {
		if i > 0 {
			b.WriteString(between)
		}
		for j, l := range lines {
			b.WriteString(l)
			if final || i < len(blocks)-1 || j < len(lines)-1 {
				b.WriteString(eol)
			}
		}
	}
	return []byte(b.String())
}

// The doc comment of CertificatesFromPEM: the BEGIN line and the END line are exactly the marker and a line
// end, LF or CRLF, or the end of the text after the last END line. The two certificates come back in order.
func TestCertificatesFromPEMReadsExactLines(t *testing.T) {
	a, b := pemCerts(t)
	la, lb := pemLines(t, a), pemLines(t, b)

	for name, text := range map[string][]byte{
		"LF, one block":   pemText([][]string{la}, "\n", "", true),
		"CRLF, one block": pemText([][]string{la}, "\r\n", "", true),
		"LF, one block, no line end after the END":   pemText([][]string{la}, "\n", "", false),
		"CRLF, one block, no line end after the END": pemText([][]string{la}, "\r\n", "", false),
		"LF, two blocks":   pemText([][]string{la, lb}, "\n", "", true),
		"CRLF, two blocks": pemText([][]string{la, lb}, "\r\n", "", true),
		"LF, two blocks, no line end after the END":    pemText([][]string{la, lb}, "\n", "", false),
		"CRLF, two blocks, no line end after the END":  pemText([][]string{la, lb}, "\r\n", "", false),
		"LF, one empty line between two blocks":        pemText([][]string{la, lb}, "\n", "\n", true),
		"CRLF, one empty line between two blocks":      pemText([][]string{la, lb}, "\r\n", "\r\n", true),
		"CRLF, one empty line of LF between two":       pemText([][]string{la, lb}, "\r\n", "\n", true),
		"LF, one empty line, no line end at the end":   pemText([][]string{la, lb}, "\n", "\n", false),
		"CRLF, one empty line, no line end at the end": pemText([][]string{la, lb}, "\r\n", "\r\n", false),
		"an empty line inside the Base64 lines": pemText([][]string{append(append(append([]string{}, la[:2]...), ""), la[2:]...), lb},
			"\n", "", true),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := attest.CertificatesFromPEM(text)
			if err != nil {
				t.Fatal(err)
			}
			want := [][]byte{a}
			if bytes.Count(text, []byte(pemBegin)) == 2 {
				want = append(want, b)
			}
			if len(got) != len(want) {
				t.Fatalf("%d blocks, want %d", len(got), len(want))
			}
			for i := range want {
				if !bytes.Equal(got[i], want[i]) {
					t.Errorf("block %d is not the certificate that was written", i+1)
				}
			}
		})
	}

	// The line ends of one file may differ from line to line: each line end is LF or CRLF by itself.
	mixed := strings.Join(la, "\r\n") + "\n" + strings.Join(lb, "\n") + "\r\n"
	if got, err := attest.CertificatesFromPEM([]byte(mixed)); err != nil || len(got) != 2 ||
		!bytes.Equal(got[0], a) || !bytes.Equal(got[1], b) {
		t.Errorf("mixed LF and CRLF: %v, %d blocks", err, len(got))
	}
}

// A blank (space, tab or both) anywhere on a marker line, and anywhere in a Base64 line, is refused, in the
// first block and in the second, with LF and with CRLF, and when the END line ends the text.
func TestCertificatesFromPEMRefusesBlanksInTheLines(t *testing.T) {
	a, b := pemCerts(t)
	blanks := []string{" ", "\t", " \t", "\t ", "  "}

	// edits changes one block in a copy of its lines. Each edit puts a blank at one place.
	type edit struct {
		name string
		do   func(lines []string, blank string)
	}
	setBase64 := func(i int, at func(line string) int) func([]string, string) {
		return func(lines []string, blank string) {
			l := lines[i]
			k := at(l)
			lines[i] = l[:k] + blank + l[k:]
		}
	}
	last := func(lines []string) int { return len(lines) - 2 }
	edits := []edit{
		{"after the BEGIN marker", func(l []string, x string) { l[0] += x }},
		{"before the BEGIN marker", func(l []string, x string) { l[0] = x + l[0] }},
		{"after the END marker", func(l []string, x string) { l[len(l)-1] += x }},
		{"before the END marker", func(l []string, x string) { l[len(l)-1] = x + l[len(l)-1] }},
		{"inside the BEGIN marker", func(l []string, x string) { l[0] = l[0][:5] + x + l[0][5:] }},
		{"inside the END marker", func(l []string, x string) { l[len(l)-1] = l[len(l)-1][:5] + x + l[len(l)-1][5:] }},
		{"at the start of the first Base64 line", setBase64(1, func(string) int { return 0 })},
		{"in the middle of the first Base64 line", setBase64(1, func(l string) int { return len(l) / 2 })},
		{"at the end of the first Base64 line", setBase64(1, func(l string) int { return len(l) })},
		{"in the middle of a middle Base64 line", func(l []string, x string) { setBase64(2, func(s string) int { return len(s) / 2 })(l, x) }},
		{"at the start of the last Base64 line", func(l []string, x string) { setBase64(last(l), func(string) int { return 0 })(l, x) }},
		{"in the middle of the last Base64 line", func(l []string, x string) { setBase64(last(l), func(s string) int { return len(s) / 2 })(l, x) }},
		{"at the end of the last Base64 line", func(l []string, x string) { setBase64(last(l), func(s string) int { return len(s) })(l, x) }},
		{"as a line of its own", func(l []string, x string) { l[1] = x }},
		{"as a line of its own before the END line", func(l []string, x string) { l[len(l)-1] = x + "\n" + l[len(l)-1] }},
	}

	for _, e := range edits {
		for _, blank := range blanks {
			for _, which := range []int{0, 1} {
				for _, eol := range []string{"\n", "\r\n"} {
					for _, final := range []bool{true, false} {
						blocks := [][]string{pemLines(t, a), pemLines(t, b)}
						e.do(blocks[which], blank)
						// The edit that makes a line of its own writes its line end as LF; the text still has a
						// blank line in the block.
						text := pemText(blocks, eol, "", final)
						if got, err := attest.CertificatesFromPEM(text); err == nil {
							t.Fatalf("%s, %q, block %d, eol %q, final %v: read %d blocks from\n%q",
								e.name, blank, which+1, eol, final, len(got), text)
						} else if got != nil {
							t.Errorf("%s: a result beside an error", e.name)
						}
					}
				}
			}
		}
	}

	// A blank in the line ends between the blocks: after the END marker, before the next BEGIN marker.
	la, lb := pemLines(t, a), pemLines(t, b)
	for _, blank := range blanks {
		for name, text := range map[string][]byte{
			"a blank line between the blocks":        pemText([][]string{la, lb}, "\n", blank+"\n", true),
			"a blank line between the blocks, CRLF":  pemText([][]string{la, lb}, "\r\n", blank+"\r\n", true),
			"a blank after the last END, then LF":    []byte(strings.Join(la, "\n") + "\n" + strings.Join(lb, "\n") + blank + "\n"),
			"a blank after the last END, then CRLF":  []byte(strings.Join(la, "\r\n") + "\r\n" + strings.Join(lb, "\r\n") + blank + "\r\n"),
			"a blank after the last END, then none":  []byte(strings.Join(la, "\n") + "\n" + strings.Join(lb, "\n") + blank),
			"a blank after the last END, then a CR":  []byte(strings.Join(la, "\n") + "\n" + strings.Join(lb, "\n") + blank + "\r"),
			"a blank after the last END, then lines": []byte(strings.Join(la, "\n") + "\n" + strings.Join(lb, "\n") + blank + "\n\n\n"),
			"a blank before the first BEGIN":         []byte(blank + strings.Join(la, "\n") + "\n"),
			"a blank line before the first BEGIN":    []byte(blank + "\n" + strings.Join(la, "\n") + "\n"),
		} {
			if got, err := attest.CertificatesFromPEM(text); err == nil {
				t.Errorf("%s, %q: read %d blocks", name, blank, len(got))
			}
		}
	}
}

// A CR that is not the first half of a CRLF is not a line end inside the lines of a block and after a
// marker: it is refused there. (Between blocks and around them a CR may stand, as the doc comment says.)
func TestCertificatesFromPEMRefusesALoneCRInTheLines(t *testing.T) {
	a, b := pemCerts(t)
	la, lb := pemLines(t, a), pemLines(t, b)
	one := strings.Join(la, "\n") + "\n"

	for name, text := range map[string]string{
		"a CR after the last END, at the end of the text":     strings.TrimSuffix(one, "\n") + "\r",
		"two CRs after the last END, then an LF":              strings.TrimSuffix(one, "\n") + "\r\r\n",
		"a CR after the END, then the next block":             strings.Join(la, "\n") + "\r" + strings.Join(lb, "\n") + "\n",
		"a CR after the END, then a text":                     strings.Join(la, "\n") + "\rnote\n",
		"two CRs after the END, then an LF, in the middle":    strings.Join(la, "\n") + "\r\r\n" + strings.Join(lb, "\n") + "\n",
		"a CR before the END marker":                          strings.Join(la[:len(la)-1], "\n") + "\n\r" + pemEnd + "\n",
		"a CR in the END marker":                              strings.Join(la[:len(la)-1], "\n") + "\n-----END\rCERTIFICATE-----\n",
		"two CRs after the BEGIN marker":                      pemBegin + "\r\r\n" + strings.Join(la[1:], "\n") + "\n",
		"a CR after the BEGIN marker, at the end of the text": pemBegin + "\r",
		"a CR after the BEGIN marker, with no LF at all":      pemBegin + "\r" + strings.Join(la[1:], "\r"),
		"a CR in the middle of a Base64 line":                 pemBegin + "\n" + la[1][:10] + "\r" + la[1][10:] + "\n" + strings.Join(la[2:], "\n") + "\n",
		"a CR at the end of a Base64 line, then CRLF":         pemBegin + "\r\n" + la[1] + "\r\r\n" + strings.Join(la[2:], "\r\n") + "\r\n",
		"a CR at the end of a Base64 line, then LF":           pemBegin + "\n" + la[1] + "\r\r\n" + strings.Join(la[2:], "\n") + "\n",
		"a CR at the start of a Base64 line":                  pemBegin + "\n\r" + la[1] + "\n" + strings.Join(la[2:], "\n") + "\n",
		"a CR as a Base64 line of its own, CRLF around":       pemBegin + "\r\n\r\r\n" + strings.Join(la[1:], "\r\n") + "\r\n",
		"a lone CR as the whole line before the END":          strings.Join(la[:len(la)-1], "\n") + "\n\r\r\n" + pemEnd + "\n",
		"a CR joins the last Base64 line and the END marker":  strings.Join(la[:len(la)-1], "\n") + "\r" + pemEnd + "\n",
		"a CR joins the BEGIN marker and the first Base64 ln": pemBegin + "\r" + strings.Join(la[1:], "\n") + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := attest.CertificatesFromPEM([]byte(text)); err == nil {
				t.Fatalf("read %d blocks from %q", len(got), text)
			} else if got != nil {
				t.Error("a result beside an error")
			}
		})
	}

	// The same texts with their CRs where the doc comment lets a CR stand are read.
	for name, text := range map[string]string{
		"a CR before the first BEGIN":                  "\r" + one,
		"a CR before the second BEGIN, after the LF":   one + "\r" + strings.Join(lb, "\n") + "\n",
		"a CR after the LF of the last END":            one + "\r",
		"CRs and LFs before, between and after blocks": "\r\n\r" + one + "\r\r\n\n" + strings.Join(lb, "\n") + "\n\r\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := attest.CertificatesFromPEM([]byte(text)); err != nil || len(got) == 0 {
				t.Fatalf("%v from %q", err, text)
			}
		})
	}
}

// Whatever is on a marker line besides the marker, or on the line of a marker that is not at the start of
// its line, is refused.
func TestCertificatesFromPEMRefusesTextOnTheMarkerLines(t *testing.T) {
	a, _ := pemCerts(t)
	la := pemLines(t, a)
	body := strings.Join(la[1:len(la)-1], "\n") + "\n"

	for name, text := range map[string]string{
		"Base64 on the BEGIN line":          pemBegin + la[1] + "\n" + strings.Join(la[2:], "\n") + "\n",
		"a letter after the BEGIN marker":   pemBegin + "x\n" + body + pemEnd + "\n",
		"a dash after the BEGIN marker":     pemBegin + "-\n" + body + pemEnd + "\n",
		"a letter after the END marker":     pemBegin + "\n" + body + pemEnd + "x\n",
		"a dash after the END marker":       pemBegin + "\n" + body + pemEnd + "-\n",
		"a letter after the last END":       pemBegin + "\n" + body + pemEnd + "x",
		"Base64 before the END marker":      pemBegin + "\n" + body + "AAAA" + pemEnd + "\n",
		"the END marker with no line start": pemBegin + "\n" + strings.TrimSuffix(body, "\n") + pemEnd + "\n",
		"a short END marker":                pemBegin + "\n" + body + "-----END CERTIFICATE----\n",
		"a lower-case END marker":           pemBegin + "\n" + body + "-----end certificate-----\n",
		"a lower-case BEGIN marker":         "-----begin certificate-----\n" + body + pemEnd + "\n",
		"an END marker of another label":    pemBegin + "\n" + body + "-----END PRIVATE KEY-----\n",
		"no END marker, a text after":       pemBegin + "\n" + body + "note\n",
		"no END marker, the text ends":      pemBegin + "\n" + body,
		"a NUL after the END marker":        pemBegin + "\n" + body + pemEnd + "\x00\n",
		"a vertical tab after the END":      pemBegin + "\n" + body + pemEnd + "\v\n",
		"a form feed after the END":         pemBegin + "\n" + body + pemEnd + "\f\n",
		"a vertical tab in a Base64 line":   pemBegin + "\n" + la[1][:7] + "\v" + la[1][7:] + "\n" + strings.Join(la[2:], "\n") + "\n",
		"a form feed in a Base64 line":      pemBegin + "\n" + la[1][:7] + "\f" + la[1][7:] + "\n" + strings.Join(la[2:], "\n") + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := attest.CertificatesFromPEM([]byte(text)); err == nil {
				t.Fatalf("read %d blocks from %q", len(got), text)
			} else if got != nil {
				t.Error("a result beside an error")
			}
		})
	}
}
