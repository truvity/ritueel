package cli

import (
	"fmt"
	"strings"
	"testing"
)

// What a person typed is echoed in a usage error, and a character outside printable ASCII in it is
// shown as an escape: a command word through %+q (Go's escapes: \xNN for a control character or a
// byte that is not UTF-8, \uXXXX for a character of the BMP, \UXXXXXXXX above it), and the library's
// message about a flag through jsonset.Escape (\uXXXX, a pair above U+FFFF, � for a bad byte).
// No escape is written out in this file: bs and the helpers build them.

const bs = "\\"

// u is the escape of a character of the BMP as both forms write it.
func u(r rune) string { return fmt.Sprintf("%su%04x", bs, r) }

// onlyPrintable reports whether every byte of s is printable ASCII or a line break.
func onlyPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '\n' && (s[i] < 0x20 || s[i] >= 0x7f) {
			return false
		}
	}
	return true
}

const helpLine = "Run \"ritueel --help\" for the usage.\n"

func TestAnUnknownCommandIsShownWithEscapes(t *testing.T) {
	withSpecs(t, words(&seen{})...)
	cases := []struct {
		name string
		args []string
		want string // the message, between "ritueel: " and the line break
	}{
		{"an ASCII word reads as before", []string{"nosuch"}, `unknown command "nosuch"`},
		{"an ASCII word with a quote and a backslash reads as before", []string{`a"b` + bs + `c`}, `unknown command "a` + bs + `"b` + bs + bs + `c"`},
		{"a word with a space", []string{"no such"}, `unknown command "no such"`},
		{"a Cyrillic letter that looks like a Latin one", []string{"v" + string(rune(0x0435)) + "rsion"}, `unknown command "v` + u(0x0435) + `rsion"`},
		{"the Kelvin sign", []string{string(rune(0x212A))}, `unknown command "` + u(0x212A) + `"`},
		{"an accented letter", []string{"caf" + string(rune(0xE9))}, `unknown command "caf` + u(0xE9) + `"`},
		{"an emoji", []string{string(rune(0x1F600))}, `unknown command "` + bs + `U0001f600"`},
		{"ESC", []string{"\x1b[31m"}, `unknown command "` + bs + `x1b[31m"`},
		{"DEL", []string{"a\x7fb"}, `unknown command "a` + bs + `x7fb"`},
		{"a line feed", []string{"a\nb"}, `unknown command "a` + bs + `nb"`},
		{"a tab", []string{"a\tb"}, `unknown command "a` + bs + `tb"`},
		{"a bad byte", []string{"a\xffb"}, `unknown command "a` + bs + `xffb"`},
		{"a truncated character", []string{"a\xc3"}, `unknown command "a` + bs + `xc3"`},
		{"a second word", []string{"verify", "bo" + string(rune(0x0261)) + "us"}, `verify: unknown command "bo` + u(0x0261) + `us"`},
		{"a second word with ESC", []string{"verify", "\x1b"}, `verify: unknown command "` + bs + `x1b"`},
		{"a second word with a bad byte", []string{"check", "\xff"}, `check: unknown command "` + bs + `xff"`},
		{"a second word, ASCII, reads as before", []string{"verify", "bogus"}, `verify: unknown command "bogus"`},
		{"after a global flag", []string{"--dir", "x", "v" + string(rune(0x0435)) + "rsion"}, `unknown command "v` + u(0x0435) + `rsion"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, tc.args...)
			if r.code != ExitUsage {
				t.Errorf("exit code = %d, want %d", int(r.code), int(ExitUsage))
			}
			if r.stdout != "" {
				t.Errorf("stdout = %q, want empty", r.stdout)
			}
			if want := "ritueel: " + tc.want + "\n" + helpLine; r.stderr != want {
				t.Errorf("stderr =\n  %q\nwant\n  %q", r.stderr, want)
			}
			if !onlyPrintable(r.stderr) {
				t.Errorf("stderr holds a byte that is not printable ASCII or a line break: %q", r.stderr)
			}
		})
	}
}

// A flag that is not defined, a flag without its value and a flag with a bad value: the library
// echoes what was typed, and the message goes through Escape. The same flag in ASCII is the
// baseline: the message of a look-alike is the baseline's with the name escaped.
func TestAFlagThatWasTypedIsShownWithEscapes(t *testing.T) {
	withSpecs(t, words(&seen{})...)
	bogus := func(name string, prefix ...string) []string { return append(prefix, "--"+name) }
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"an unknown flag, ASCII, reads as before", bogus("bogus"), "flag provided but not defined: -bogus"},
		{"an unknown flag with an accented letter", bogus("bog" + string(rune(0xE9))), "flag provided but not defined: -bog" + u(0xE9)},
		{"an unknown flag with a Cyrillic letter", bogus("b" + string(rune(0x043E)) + "gus"), "flag provided but not defined: -b" + u(0x043E) + "gus"},
		{"an unknown flag with ESC", bogus("bog\x1bus"), "flag provided but not defined: -bog" + u(0x1B) + "us"},
		{"an unknown flag with a bad byte", bogus("bog\xffus"), "flag provided but not defined: -bog" + u(0xFFFD) + "us"},
		{"an unknown flag with an emoji", bogus("bog" + string(rune(0x1F600))), "flag provided but not defined: -bog" + u(0xD83D) + u(0xDE00)},
		{"a short unknown flag with a look-alike", []string{"-" + string(rune(0xE9))}, "flag provided but not defined: -" + u(0xE9)},
		{"a bad output value, ASCII, reads as before", []string{"--output", "yaml"}, `invalid value "yaml" for flag -output: must be "text" or "json"`},
		{"a bad output value with a look-alike", []string{"--output", "j" + string(rune(0x0455)) + "on"}, `invalid value "j` + u(0x0455) + `on" for flag -output: must be "text" or "json"`},
		{"a bad output value that is not UTF-8", []string{"--output=\xff"}, `invalid value "` + bs + `xff" for flag -output: must be "text" or "json"`},
		{"a bad output value with ESC", []string{"--output", "\x1b"}, `invalid value "` + bs + `x1b" for flag -output: must be "text" or "json"`},
		{"an unknown flag of a command, ASCII", bogus("bogus", "verify", "root-list"), "flag provided but not defined: -bogus"},
		{"an unknown flag of a command with a look-alike", bogus("bog"+string(rune(0xE9)), "verify", "root-list"), "flag provided but not defined: -bog" + u(0xE9)},
		{"an unknown flag between the words of a command", []string{"verify", "--bog" + string(rune(0xE9)), "root-list"}, "flag provided but not defined: -bog" + u(0xE9)},
		{"a bad boolean value of a command with a look-alike", []string{"verify", "root-list", "--strict=mayb" + string(rune(0xE9))}, `invalid value "mayb` + u(0xE9) + `" for flag -strict: parse error`},
		{"a bad boolean value of a command with ESC", []string{"verify", "root-list", "--strict=\x1b"}, `invalid value "` + bs + `x1b" for flag -strict: parse error`},
		{"an unknown flag of a plain command with a look-alike", []string{"plain", "--bog" + string(rune(0xE9))}, "flag provided but not defined: -bog" + u(0xE9)},
		{"a flag without its value, ASCII, reads as before", []string{"--dir"}, "flag needs an argument: --dir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, tc.args...)
			if r.code != ExitUsage {
				t.Errorf("exit code = %d, want %d", int(r.code), int(ExitUsage))
			}
			if r.stdout != "" {
				t.Errorf("stdout = %q, want empty", r.stdout)
			}
			if want := "ritueel: " + tc.want + "\n" + helpLine; r.stderr != want {
				t.Errorf("stderr =\n  %q\nwant\n  %q", r.stderr, want)
			}
			if !onlyPrintable(r.stderr) {
				t.Errorf("stderr holds a byte that is not printable ASCII or a line break: %q", r.stderr)
			}
		})
	}
}

// In the JSON mode the error member is the same text, and standard output holds printable ASCII and
// the one line break of the object.
func TestAUsageErrorWithALookAlikeInTheJSONMode(t *testing.T) {
	withSpecs(t, words(&seen{})...)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"a command", []string{"--output", "json", "v" + string(rune(0x0435)) + "rsion"}, `unknown command "v` + u(0x0435) + `rsion"`},
		{"a command with ESC", []string{"--output", "json", "\x1b"}, `unknown command "` + bs + `x1b"`},
		{"a flag", []string{"--output", "json", "--bog" + string(rune(0xE9))}, "flag provided but not defined: -bog" + u(0xE9)},
		{"a flag of a command", []string{"--output", "json", "verify", "root-list", "--bog\xffus"}, "flag provided but not defined: -bog" + u(0xFFFD) + "us"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, tc.args...)
			if r.code != ExitUsage {
				t.Errorf("exit code = %d, want %d", int(r.code), int(ExitUsage))
			}
			if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
				t.Errorf("stdout %q or stderr %q holds a byte that is not printable ASCII or a line break", r.stdout, r.stderr)
			}
			obj := object(t, r.stdout)
			if obj["error"] != tc.want {
				t.Errorf("error = %q, want %q", obj["error"], tc.want)
			}
			if !strings.HasPrefix(r.stderr, "ritueel: "+tc.want+"\n") {
				t.Errorf("stderr = %q", r.stderr)
			}
		})
	}
}
