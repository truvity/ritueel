package files_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// printableASCII reports whether s holds only the characters from space to tilde.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func TestDigestIsTheSHA256OfTheBytesAsLowerCaseHex(t *testing.T) {
	for _, in := range []string{"", "abc", "a\r\nb\n", strings.Repeat("x", 1<<20)} {
		sum := sha256.Sum256([]byte(in))
		want := hex.EncodeToString(sum[:])
		if got := files.Digest([]byte(in)); got != want {
			t.Errorf("Digest(%d bytes) = %s, want %s", len(in), got, want)
		}
	}
	// Two vectors of FIPS 180-4, written out by hand.
	if got, want := files.Digest(nil), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Errorf("Digest(nil) = %s, want %s", got, want)
	}
	if got, want := files.Digest([]byte("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Errorf("Digest(abc) = %s, want %s", got, want)
	}
}

func TestIsDigestWantsSixtyFourLowerCaseHexCharacters(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	if !files.IsDigest(good) {
		t.Fatalf("IsDigest(%q) = false", good)
	}
	if !files.IsDigest(files.Digest([]byte("x"))) {
		t.Error("a digest that Digest wrote is refused")
	}
	bad := map[string]string{
		"empty":            "",
		"63 characters":    good[:63],
		"65 characters":    good + "0",
		"upper case":       strings.ToUpper(good),
		"one upper case":   good[:10] + "A" + good[11:],
		"letter g":         good[:63] + "g",
		"trailing newline": good[:63] + "\n",
		"leading space":    " " + good[:63],
		"prefix 0x":        "0x" + good[:62],
		"colon":            good[:32] + ":" + good[33:],
		// 32 two-byte characters are 64 bytes long and not hexadecimal.
		"64 bytes of letters beyond ASCII": strings.Repeat(string(rune(0x430)), 32),
		"a zero byte":                      good[:63] + "\x00",
	}
	for name, s := range bad {
		if files.IsDigest(s) {
			t.Errorf("IsDigest(%s) = true", name)
		}
	}
}

func TestCheckTimeWantsExactlyTheFormOfThePages(t *testing.T) {
	good := []string{
		"2026-11-14T10:00:00Z",
		"1999-12-31T23:59:59Z",
		"2028-02-29T00:00:00Z", // a leap day
		"2026-01-01T00:00:00Z",
	}
	for _, s := range good {
		if err := files.CheckTime(s); err != nil {
			t.Errorf("CheckTime(%q): %v", s, err)
		}
	}
	bad := map[string]string{
		"empty":                "",
		"date only":            "2026-11-14",
		"no zone":              "2026-11-14T10:00:00",
		"lower case t":         "2026-11-14t10:00:00Z",
		"lower case z":         "2026-11-14T10:00:00z",
		"space for T":          "2026-11-14 10:00:00Z",
		"fraction":             "2026-11-14T10:00:00.5Z",
		"offset":               "2026-11-14T10:00:00+00:00",
		"offset of a zone":     "2026-11-14T11:00:00+01:00",
		"month 13":             "2026-13-01T00:00:00Z",
		"day 30 of February":   "2026-02-30T00:00:00Z",
		"29 February, no leap": "2027-02-29T00:00:00Z",
		"hour 24":              "2026-11-14T24:00:00Z",
		"minute 60":            "2026-11-14T10:60:00Z",
		"a letter for a digit": "2026-11-14T1a:00:00Z",
		"trailing newline":     "2026-11-14T10:00:00Z\n",
		"leading space":        " 2026-11-14T10:00:00Z",
		"basic format":         "20261114T100000Z",
		"year of 5 digits":     "12026-11-14T10:00:00Z",
	}
	for name, s := range bad {
		if err := files.CheckTime(s); err == nil {
			t.Errorf("CheckTime(%s = %q) = nil", name, s)
		} else if !printableASCII(err.Error()) {
			t.Errorf("CheckTime(%s): error text %q is not printable ASCII", name, err)
		}
	}
}

func TestCheckPathAcceptsThePathsOfABundle(t *testing.T) {
	long255 := strings.Repeat("a", 255)
	good := []string{
		"a",
		"ritueel.yaml",
		"want/cards/root-a.yaml",
		"trust/13-3fa9c1d2/root-list.json",
		"requests/stem-1/answer.result.json",
		"a.b-c_d",
		"0",
		".hidden",
		".rtx",  // starts like a temporary name, but is not one
		"a/.rt", // one character short of the prefix
		long255,
		long255 + "/" + long255,
	}
	for _, p := range good {
		if err := files.CheckPath(p); err != nil {
			t.Errorf("CheckPath(%q): %v", p, err)
		}
	}
}

func TestCheckPathRefusesWhatARecordMayNotList(t *testing.T) {
	bad := map[string]string{
		"empty":                  "",
		"absolute":               "/etc/hosts",
		"absolute, one element":  "/a",
		"double slash":           "//host/share",
		"trailing slash":         "a/",
		"empty element":          "a//b",
		"dot":                    "./a",
		"dot inside":             "a/./b",
		"only a dot":             ".",
		"dot dot":                "../x",
		"dot dot inside":         "a/../../x",
		"only dot dot":           "..",
		"backslash":              "a" + string(rune(0x5c)) + "b",
		"backslash path":         string(rune(0x5c)) + "windows" + string(rune(0x5c)) + "x",
		"drive letter":           "C:x",
		"space":                  "a b",
		"tab":                    "a\tb",
		"newline":                "a\nb",
		"carriage return":        "a\rb",
		"control byte":           "a\x01b",
		"delete":                 "a\x7fb",
		"escape sequence":        "a\x1b[31mb",
		"a zero byte":            "a\x00b",
		"bytes that are no UTF8": "a\xffb",
		"Cyrillic look-alike":    "a" + string(rune(0x430)) + "b",
		"right to left override": "a" + string(rune(0x202e)) + "b",
		"temporary prefix":       ".rt-abcdefghijk",
		"temporary prefix, caps": ".RT-abcdefghijk",
		"temporary prefix, mix":  ".Rt-x",
		"temporary folder":       "a/.rt-abc/b",
		"temporary folder, caps": ".RT-abc/b",
		"temporary last":         "a/b/.rt-abc",
		"device AUX":             "aux",
		"device CON caps":        "CON",
		"device with extension":  "con.txt",
		"device COM1":            "com1",
		"device LPT9 in a path":  "a/LPT9/b",
		"trailing dot":           "x.",
		"trailing dot in path":   "a/x./b",
		"percent":                "a%20b",
		"star":                   "a*",
		"256 bytes":              strings.Repeat("a", 256),
		"256 bytes in the path":  "a/" + strings.Repeat("b", 256),
	}
	for name, p := range bad {
		err := files.CheckPath(p)
		if err == nil {
			t.Errorf("CheckPath(%s) = nil", name)
			continue
		}
		if !printableASCII(err.Error()) {
			t.Errorf("CheckPath(%s): the error %q is not printable ASCII", name, err)
		}
		// The error never holds the path (it is data from a file).
		if len(p) > 3 && strings.Contains(err.Error(), p) {
			t.Errorf("CheckPath(%s): the error holds the path: %q", name, err)
		}
	}
}

// There is no limit in bytes: a path of the most elements of the longest names is what the limit
// on elements allows, and no more. It is the rule that replaced the limit of 4,096 bytes.
func TestCheckPathNeedsNoLimitInBytesBecauseTheLimitOnElementsBoundsIt(t *testing.T) {
	longest := strings.Repeat(strings.Repeat("a", 255)+"/", files.MaxPathElements-1) + strings.Repeat("a", 255)
	if err := files.CheckPath(longest); err != nil {
		t.Errorf("a path of %d elements of 255 bytes: %v", files.MaxPathElements, err)
	}
	if err := files.CheckPath(longest + "/a"); err == nil {
		t.Error("a path of one element more is accepted")
	} else if !printableASCII(err.Error()) || len(err.Error()) > 200 {
		t.Errorf("the error is not short and plain: %.100q", err)
	}
	// Many bytes in few elements: an element of 256 bytes is refused as before.
	if err := files.CheckPath(strings.Repeat("a", 256)); err == nil {
		t.Error("an element of 256 bytes is accepted")
	}
}

func TestNamesOfTheFilesOfACeremonyFolder(t *testing.T) {
	// The six names are set by record 0006, rule 37, and the path of the plan by record 0006, rule 9.
	want := map[string]string{
		files.PlanFile:         "plan.json",
		files.AttemptFile:      "attempt.json",
		files.BirthsFile:       "births.jsonl",
		files.SignaturesFile:   "signatures.jsonl",
		files.TranscriptFile:   "transcript.txt",
		files.RecordFile:       "record.json",
		files.WantedDir:        "wanted",
		files.CommandApply:     "apply",
		files.CommandClose:     "close",
		files.OutcomeCompleted: "completed",
		files.OutcomeDeclined:  "declined",
		files.OutcomeClosed:    "closed",
	}
	for got, w := range want {
		if got != w {
			t.Errorf("constant %q, want %q", got, w)
		}
	}
	if files.FormatVersion != 1 {
		t.Errorf("FormatVersion = %d, want 1", files.FormatVersion)
	}
}
