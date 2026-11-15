package cards

import (
	"regexp"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jsonset"
)

var (
	highSurrogate = regexp.MustCompile(`^\\ud[89ab][0-9a-f]{2}$`)
	lowSurrogate  = regexp.MustCompile(`^\\ud[c-f][0-9a-f]{2}$`)
)

// FuzzCutDetail: a detail of any bytes is written as printable ASCII of at most 240 bytes, and a text that
// fits is not changed.
func FuzzCutDetail(f *testing.F) {
	for _, s := range []string{"", "line 3: bad", strings.Repeat("a", 241), strings.Repeat("\u00e9", 60), strings.Repeat("\U0001f600", 40),
		"\xff\xfe", strings.Repeat("\\u", 200), strings.Repeat("a", 237) + "\u00e9", strings.Repeat("a", 234) + "\u00e9\u00e9", "aa" + strings.Repeat("\u00e9", 60),
		strings.Repeat("a", 225) + strings.Repeat("\U0001f600", 5), strings.Repeat("a", 231) + "\U0001f600" + "b", strings.Repeat("a", 230) + "\U0001f600" + "b",
		strings.Repeat("a", 232) + "\U0001f600" + "b", strings.Repeat("a", 233) + "\U0001f600" + "b", strings.Repeat("a", 236) + "\U0001f600" + "b", strings.Repeat("\\", 300)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := cutDetail(s)
		whole := jsonset.Escape(s)
		if len(got) > wantMaxDetail {
			t.Fatalf("%d bytes", len(got))
		}
		for i := 0; i < len(got); i++ {
			if got[i] < 0x20 || got[i] > 0x7e {
				t.Fatalf("not printable: %+q", got)
			}
		}
		if len(whole) <= wantMaxDetail {
			if got != whole {
				t.Fatalf("a detail that fits was changed: %q -> %q", whole, got)
			}
			return
		}
		if !strings.HasSuffix(got, wantCutMark) || !strings.HasPrefix(whole, strings.TrimSuffix(got, wantCutMark)) {
			t.Fatalf("a cut that is not a prefix ended with the mark: %q", got)
		}
		if splitEscape(whole, len(got)-len(wantCutMark)) {
			t.Fatalf("a cut inside an escape: %q", got)
		}
		body := strings.TrimSuffix(got, wantCutMark)
		if strings.HasSuffix(body, `\`) {
			t.Fatalf("a cut right after a backslash: %q", got)
		}
		// The first escape of a pair is never left alone: the escape that follows it in the whole text is
		// the second one.
		if n := len(body); n >= 6 && highSurrogate.MatchString(body[n-6:]) && lowSurrogate.MatchString(whole[n:min(len(whole), n+6)]) {
			t.Fatalf("a cut between the two escapes of a pair: %q", got)
		}
	})
}

// splitEscape reports whether a cut of whole at n lies inside a \uXXXX that jsonset.Escape wrote. The escapes
// are found from the start, so that a backslash that came from the text is not taken for one.
func splitEscape(whole string, n int) bool {
	for i := 0; i < len(whole); {
		if whole[i] == '\\' && i+1 < len(whole) && whole[i+1] == 'u' && i+6 <= len(whole) && isHex(whole[i+2:i+6]) {
			if i < n && n < i+6 {
				return true
			}
			i += 6
			continue
		}
		i++
	}
	return false
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// FuzzFindingLine: any finding is written as one line of printable ASCII.
func FuzzFindingLine(f *testing.F) {
	f.Add("card-file-invalid", "want/cards/a.yaml", "line 1: x")
	f.Add("", "", "")
	f.Add("a\n", "b\r", "c\u202e")
	f.Add("\xff", "\\", " ")
	f.Fuzz(func(t *testing.T, code, path, detail string) {
		line := Finding{Code: Code(code), Path: path, Detail: detail}.Line()
		for i := 0; i < len(line); i++ {
			if line[i] < 0x20 || line[i] > 0x7e {
				t.Fatalf("Line() = %+q", line)
			}
		}
	})
}
