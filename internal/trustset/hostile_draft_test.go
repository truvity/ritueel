package trustset_test

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/trustset"
)

// Hostile input to NewDraft: a previous list of any shape, entries of the history with bytes that
// are not UTF-8, strings in a departure. Every one is refused with ErrParams, no draft comes, there
// is no panic, and the text of the error is printable ASCII and short.
func TestHostilePreviousList(t *testing.T) {
	c := abc(t)
	good := string(c.last().ListJSON())
	deep := strings.Repeat("[", 200000) + strings.Repeat("]", 200000)
	for name, prev := range map[string]string{
		"empty text":               "",
		"one space":                " ",
		"null":                     "null",
		"an array":                 "[]",
		"a number":                 "7",
		"a string":                 `"x"`,
		"an empty object":          "{}",
		"depth":                    deep,
		"depth in a member":        `{"roots":` + deep + `}`,
		"a byte order mark":        "\xef\xbb\xbf" + good,
		"bytes that are not UTF-8": strings.Replace(good, `"label":"A"`, "\"label\":\"\xff\"", 1),
		"a NUL":                    strings.Replace(good, `"label":"A"`, "\"label\":\"\x00\"", 1),
		"a sequence as a string":   strings.Replace(good, `"sequence":1`, `"sequence":"1"`, 1),
		"a sequence as a float":    strings.Replace(good, `"sequence":1`, `"sequence":1.0`, 1),
		"a sequence of 1e0":        strings.Replace(good, `"sequence":1`, `"sequence":1e0`, 1),
		"roots as an object":       strings.Replace(good, `"roots":[`, `"roots":{"a":`, 1),
		"roots empty":              `{"expires_at":"2027-12-15T12:00:00Z","roots":[],"sequence":1,"signed_at":"2026-11-15T12:00:00Z","version":1}`,
		"version 2":                strings.Replace(good, `"version":1`, `"version":2`, 1),
		"a member twice":           strings.Replace(good, `"version":1`, `"version":1,"version":1`, 1),
		"an unknown member":        strings.Replace(good, `"version":1`, `"version":1,"x":1`, 1),
		"signed_at in a zone":      strings.Replace(good, `T12:00:00Z","version"`, `T12:00:00+01:00","version"`, 1),
		"a cut list":               good[:len(good)/2],
		"a list and another":       good + good,
		"over the limit":           good + strings.Repeat(" ", trustset.MaxBytes),
		"a very long member":       `{"x":"` + strings.Repeat("a", trustset.MaxBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			in := c.input(next{labels: []string{"A", "B", "C"}, change: func(in *trustset.Input) { in.Previous = []byte(prev) }})
			d, err := trustset.NewDraft(in)
			if d != nil || err == nil {
				t.Fatal("a draft was made")
			}
			wantOnly(t, err, trustset.ErrParams)
		})
	}
}

// The strings of the input that are not UTF-8: a label, a pin, a fingerprint, a departure, an
// authorisation, a name of an earlier list. None reaches an error unescaped.
func TestHostileStringsInTheInput(t *testing.T) {
	bad := "\xff\xfe\x00\x1b[31m\u202e"
	c := abc(t)
	cases := map[string]func(*trustset.Input){
		"label":       func(in *trustset.Input) { in.Roots[0].Label = bad },
		"pin":         func(in *trustset.Input) { in.Roots[0].X509SPKISHA256 = bad },
		"fingerprint": func(in *trustset.Input) { in.Roots[0].OpenPGPFingerprint = bad },
		"anchor":      func(in *trustset.Input) { in.LastRecordSHA256 = bad },
		"departure pin": func(in *trustset.Input) {
			in.Departures = []trustset.Departure{{X509SPKISHA256: bad, Leave: trustset.LeaveRetired}}
		},
		"authorisation": func(in *trustset.Input) {
			in.Departures = []trustset.Departure{{X509SPKISHA256: newRoot(t, "C", true).Pin, Leave: trustset.LeaveRevoked, Authorisation: bad}}
			in.Roots = in.Roots[:2]
			delete(in.Certificates, "C")
		},
		"earlier label":     func(in *trustset.Input) { in.Earlier[0].Keys[0].Label = bad },
		"earlier pin":       func(in *trustset.Input) { in.Earlier[0].Keys[0].Pin = bad },
		"earlier name":      func(in *trustset.Input) { in.Earlier[0].Name = bad; in.Earlier[0].Unreadable = true },
		"certificate label": func(in *trustset.Input) { in.Certificates[bad] = []byte{1} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			in := c.input(next{labels: []string{"A", "B", "C"}, change: change})
			d, err := trustset.NewDraft(in)
			if d != nil || err == nil {
				t.Fatal("a draft was made")
			}
			wantOnly(t, err, trustset.ErrParams)
			for _, b := range []byte{0xff, 0xfe, 0x00, 0x1b} {
				if strings.IndexByte(err.Error(), b) >= 0 {
					t.Errorf("the error shows a byte of the input: %+q", err.Error())
				}
			}
		})
	}
}

// Entries of the earlier lists with an entry of the history reader that is not in strict form but
// that FindReturns reads (upper case, white space, a prefix): the builder refuses them rather than
// pass them on, so that a returning key cannot hide in a spelling.
func TestEarlierEntriesInAnotherSpellingAreRefused(t *testing.T) {
	c := chainOf(t, true, next{labels: []string{"A", "B"}}, next{labels: []string{"B"}, deps: []trustset.Departure{retire(t, "A")}})
	pin := newRoot(t, "A", true).Pin
	for name, spelling := range map[string]string{
		"upper case":  strings.ToUpper(pin),
		"white space": " " + pin + "\n",
		"a prefix":    "0x" + pin,
		"colons":      strings.Join(strings.Split(pin, ""), ":"),
	} {
		t.Run(name, func(t *testing.T) {
			in := c.input(next{labels: []string{"A", "B"}, noPrint: true, change: func(in *trustset.Input) {
				in.Earlier[0].Keys[0] = history.RootKey{Label: "A", Pin: spelling}
			}})
			refuses(t, in, "not in the form of the page")
		})
	}
}

// Write: a link, a plain file or a pipe in place of trust/, and a link or a pipe at finalDir. fsx
// refuses each; nothing is written through a link, and the set is not there.
func TestSetWriteWithLinksAndPipes(t *testing.T) {
	_, s := aSet(t)
	final := "trust/" + nameOf(t, s)
	for name, prepare := range map[string]func(t *testing.T, dir, outside string){
		"trust is a plain file": func(t *testing.T, dir, _ string) {
			if err := os.WriteFile(filepath.Join(dir, "trust"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"trust is a link": func(t *testing.T, dir, outside string) {
			if err := os.Symlink(outside, filepath.Join(dir, "trust")); err != nil {
				t.Fatal(err)
			}
		},
		"trust is a pipe": func(t *testing.T, dir, _ string) {
			if err := syscall.Mkfifo(filepath.Join(dir, "trust"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"finalDir is a dangling link": func(t *testing.T, dir, outside string) {
			if err := os.Mkdir(filepath.Join(dir, "trust"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(outside, "nowhere"), filepath.Join(dir, final)); err != nil {
				t.Fatal(err)
			}
		},
		"finalDir is a link to a folder": func(t *testing.T, dir, outside string) {
			if err := os.Mkdir(filepath.Join(dir, "trust"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(dir, final)); err != nil {
				t.Fatal(err)
			}
		},
		"finalDir is a pipe": func(t *testing.T, dir, _ string) {
			if err := os.Mkdir(filepath.Join(dir, "trust"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(filepath.Join(dir, final), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"finalDir is a plain file": func(t *testing.T, dir, _ string) {
			if err := os.Mkdir(filepath.Join(dir, "trust"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, final), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, outside := t.TempDir(), t.TempDir()
			prepare(t, dir, outside)
			w, err := fsx.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = w.Close() }()
			err = s.Write(w, final)
			if err == nil {
				t.Fatal("Write took it")
			}
			if ents, _ := os.ReadDir(outside); len(ents) != 0 {
				t.Errorf("something was written through a link: %d entries", len(ents))
			}
			// What stands at finalDir is still what stood there.
			if info, err := os.Lstat(filepath.Join(dir, final)); err == nil && info.IsDir() && !strings.Contains(name, "link") {
				t.Error("a folder stands at finalDir")
			}
		})
	}
}
