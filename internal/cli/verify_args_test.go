package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// The arguments are FILE (--held FILE | --pin SHA256... [--min-sequence N]) [--ca-bundle FILE], as the
// page writes them; a FILE that does not end in .json is a usage error, exit code 2. Every fault of the arguments is exit code 2 and is found before any file
// is read, so these tests name files that do not exist.

func usageObject(msg string) string {
	return fmt.Sprintf(`{"output":1,"command":"verify","exit_code":2,"outcome":"usage","warnings":[],"error":%q}`+"\n", msg)
}

// wantUsage runs the arguments in both output modes and compares the exit code, the exact lines of
// standard error and the exact object. msg is the whole message after "ritueel: ".
func wantUsage(t *testing.T, msg string, args ...string) {
	t.Helper()
	m := vloadManifest(t)
	clock := m.clockOf(t, "")
	text := vrunAt(t, clock, args...)
	js := vrunAt(t, clock, append([]string{"--output", "json"}, args...)...)
	wantErr := "ritueel: " + msg + "\n" + helpLine
	if text.code != ExitUsage || text.stdout != "" || text.stderr != wantErr {
		t.Errorf("%q text: exit %d stdout %q stderr %q, want stderr %q", args, text.code, text.stdout, text.stderr, wantErr)
	}
	if js.code != ExitUsage || js.stdout != usageObject(msg) || js.stderr != wantErr {
		t.Errorf("%q json: exit %d stdout %q stderr %q", args, js.code, js.stdout, js.stderr)
	}
	terminalSafe(t, text)
	terminalSafe(t, js)
}

const (
	msgOneFile  = "verify root-list takes exactly one FILE, the root-list.json to check"
	msgNotJSON  = "FILE must be a root-list.json, a name that ends in .json: its signature is the .jws file beside it"
	msgBoth     = "give the list the host holds (--held) or its initial pins (--pin), not both"
	msgNeither  = "give the list the host holds (--held FILE) or its initial pins (--pin SHA256, once for each)"
	msgHeldName = "--held needs a file name"
	msgBundle   = "--ca-bundle needs a file name"
	msgMinWith  = "--min-sequence goes with --pin; a host that holds a list has its sequence"
	msgMinForm  = "--min-sequence must be an integer from 1 to 9007199254740991, written in digits"
)

func TestTheArgumentsOfVerifyRootList(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	verify := []string{"verify", "root-list"}
	with := func(rest ...string) []string { return append(append([]string{}, verify...), rest...) }
	for _, c := range []struct {
		name string
		args []string
		msg  string
	}{
		{"no FILE", with("--pin", pin), msgOneFile},
		{"no FILE and nothing else", with(), msgOneFile},
		{"two FILEs", with("a.json", "b.json", "--pin", pin), msgOneFile},
		{"three FILEs", with("a.json", "b.json", "c.json", "--held", "h.json"), msgOneFile},
		{"a FILE that does not end in .json", with("list.txt", "--pin", pin), msgNotJSON},
		{"a FILE with the ending in capitals", with("list.JSON", "--pin", pin), msgNotJSON},
		{"a FILE that ends in .jws", with("list.jws", "--pin", pin), msgNotJSON},
		{"a FILE with no ending", with("list", "--pin", pin), msgNotJSON},
		{"a FILE that ends in .json.txt", with("list.json.txt", "--pin", pin), msgNotJSON},
		{"a FILE that is a folder with a slash", with("dir/", "--pin", pin), msgNotJSON},
		{"an empty FILE", with("", "--pin", pin), msgNotJSON},
		{"FILE before the other faults", with("list.txt"), msgNotJSON},
		{"the count of FILEs before the name", with("a.txt", "b.txt"), msgOneFile},
		{"neither --held nor --pin", with("a.json"), msgNeither},
		{"neither, with a bundle", with("a.json", "--ca-bundle", "b.pem"), msgNeither},
		{"both --held and --pin", with("a.json", "--held", "h.json", "--pin", pin), msgBoth},
		{"both, in the other order", with("a.json", "--pin", pin, "--held", "h.json"), msgBoth},
		{"--held with no name", with("a.json", "--held", ""), msgHeldName},
		{"--ca-bundle with no name", with("a.json", "--pin", pin, "--ca-bundle", ""), msgBundle},
		{"--min-sequence with --held", with("a.json", "--held", "h.json", "--min-sequence", "3"), msgMinWith},
		{"--min-sequence with --held and a bad number", with("a.json", "--held", "h.json", "--min-sequence", "0"), msgMinWith},
		{"--min-sequence with neither", with("a.json", "--min-sequence", "3"), msgNeither},
		{"--min-sequence 0", with("a.json", "--pin", pin, "--min-sequence", "0"), msgMinForm},
		{"--min-sequence -1", with("a.json", "--pin", pin, "--min-sequence=-1"), msgMinForm},
		{"--min-sequence +3", with("a.json", "--pin", pin, "--min-sequence", "+3"), msgMinForm},
		{"--min-sequence 07", with("a.json", "--pin", pin, "--min-sequence", "07"), msgMinForm},
		{"--min-sequence 3.0", with("a.json", "--pin", pin, "--min-sequence", "3.0"), msgMinForm},
		{"--min-sequence 3e2", with("a.json", "--pin", pin, "--min-sequence", "3e2"), msgMinForm},
		{"--min-sequence abc", with("a.json", "--pin", pin, "--min-sequence", "abc"), msgMinForm},
		{"--min-sequence empty", with("a.json", "--pin", pin, "--min-sequence", ""), msgMinForm},
		{"--min-sequence with a space", with("a.json", "--pin", pin, "--min-sequence", " 3"), msgMinForm},
		{"--min-sequence of 2^53", with("a.json", "--pin", pin, "--min-sequence", "9007199254740992"), msgMinForm},
		{"--min-sequence far over", with("a.json", "--pin", pin, "--min-sequence", "99999999999999999999"), msgMinForm},
		{"--min-sequence in another script", with("a.json", "--pin", pin, "--min-sequence", "\u0663"), msgMinForm},
	} {
		t.Run(c.name, func(t *testing.T) { wantUsage(t, c.msg, c.args...) })
	}
}

func TestABadPinIsAUsageError(t *testing.T) {
	good := strings.Repeat("0f", 32)
	for name, pin := range map[string]string{
		"upper case":               strings.ToUpper(strings.Repeat("ab", 32)),
		"one letter in upper case": "A" + good[1:],
		"63 digits":                good[:63],
		"65 digits":                good + "0",
		"not hexadecimal":          "g" + good[1:],
		"empty":                    "",
		"two pins in one":          good + "," + good,
		"with a space":             good + " ",
		"a 0x prefix":              "0x" + good[2:],
		"a look-alike letter":      "\u0430" + good[1:],
		"not UTF-8":                "\xff" + good[1:],
		"a control character":      "\x01" + good[1:],
	} {
		t.Run(name, func(t *testing.T) {
			m := vloadManifest(t)
			for _, mode := range []string{"text", "json"} {
				r := vrunAt(t, m.clockOf(t, ""), "--output", mode, "verify", "root-list", "/nonexistent/a.json", "--pin", good, "--pin", pin)
				if r.code != ExitUsage || !strings.HasPrefix(r.stderr, "ritueel: --pin: ") || !strings.HasSuffix(r.stderr, "\n"+helpLine) {
					t.Fatalf("%s: exit %d stderr %q", mode, r.code, r.stderr)
				}
				if mode == "text" && r.stdout != "" {
					t.Errorf("stdout %q", r.stdout)
				}
				if mode == "json" {
					obj := jsonObject(t, r)
					if obj["exit_code"] != float64(2) && fmt.Sprint(obj["exit_code"]) != "2" || obj["outcome"] != "usage" || obj["error"] == nil {
						t.Errorf("object %v", obj)
					}
				}
				terminalSafe(t, r)
			}
		})
	}
}

func TestTheWordsOfVerify(t *testing.T) {
	m := vloadManifest(t)
	clock := m.clockOf(t, "")
	for name, c := range map[string]struct {
		args []string
		msg  string
	}{
		"verify alone":                 {[]string{"verify"}, "verify needs a second word"},
		"an unknown second word":       {[]string{"verify", "nosuch"}, "verify: unknown command \"nosuch\""},
		"a second word that is a flag": {[]string{"verify", "--pin"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			r := vrunAt(t, clock, c.args...)
			if r.code != ExitUsage || r.stdout != "" || !strings.HasSuffix(r.stderr, helpLine) {
				t.Fatalf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
			}
			if c.msg != "" && r.stderr != "ritueel: "+c.msg+"\n"+helpLine {
				t.Errorf("stderr %q", r.stderr)
			}
		})
	}
	t.Run("an unknown flag", func(t *testing.T) {
		r := vrunAt(t, clock, "verify", "root-list", "a.json", "--nosuch", "x")
		if r.code != ExitUsage || r.stdout != "" || !strings.HasPrefix(r.stderr, "ritueel: ") || !strings.HasSuffix(r.stderr, helpLine) {
			t.Fatalf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
		}
	})
	t.Run("a flag without its value", func(t *testing.T) {
		for _, f := range []string{"--held", "--pin", "--ca-bundle", "--min-sequence"} {
			r := vrunAt(t, clock, "verify", "root-list", "a.json", f)
			if r.code != ExitUsage || r.stdout != "" || !strings.HasSuffix(r.stderr, helpLine) {
				t.Errorf("%s: exit %d stdout %q stderr %q", f, r.code, r.stdout, r.stderr)
			}
		}
	})
	t.Run("a bad output mode gives no object", func(t *testing.T) {
		r := vrunAt(t, clock, "--output", "xml", "verify", "root-list", "a.json", "--pin", strings.Repeat("ab", 32))
		if r.code != ExitUsage || r.stdout != "" || !strings.HasSuffix(r.stderr, helpLine) {
			t.Fatalf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
		}
	})
}

func TestTheFlagsStandWhereTheLibraryLetsThem(t *testing.T) {
	m := vloadManifest(t)
	s := vstage(t, m, m.newAgainstHeld(t))
	files := [][2]string{{"cand.json", sum(s.candBytes)}, {"cand.jws", sum(s.jwsBytes)}}
	want := doneObject(nil, files...)
	for name, args := range map[string][]string{
		"flags after FILE":                   {"--output", "json", "verify", "root-list", s.cand, "--held", s.held},
		"flags before FILE":                  {"--output", "json", "verify", "root-list", "--held", s.held, s.cand},
		"the flag with an equals sign":       {"--output", "json", "verify", "root-list", s.cand, "--held=" + s.held},
		"--output after the words":           {"verify", "root-list", s.cand, "--held", s.held, "--output", "json"},
		"--output between the words":         {"verify", "--output", "json", "root-list", s.cand, "--held", s.held},
		"--dir is accepted and not read":     {"--dir", "/nonexistent/dir", "--output", "json", "verify", "root-list", s.cand, "--held", s.held},
		"--dir after the words":              {"--output", "json", "verify", "root-list", s.cand, "--held", s.held, "--dir", "/nonexistent/dir"},
		"--dir that is a file":               {"--dir", s.cand, "--output", "json", "verify", "root-list", s.cand, "--held", s.held},
		"--output given twice, the last one": {"--output", "text", "--output", "json", "verify", "root-list", s.cand, "--held", s.held},
	} {
		t.Run(name, func(t *testing.T) {
			r := vrunAt(t, s.clock, args...)
			if r.code != ExitOK || r.stdout != want || r.stderr != "" {
				t.Fatalf("exit %d\nstdout %q\nstderr %q", r.code, r.stdout, r.stderr)
			}
		})
	}
	t.Run("a pin is one value for each --pin, and a comma is part of it", func(t *testing.T) {
		p := m.againstPins(t)
		ps := vstage(t, m, p)
		a := ps.args("json")
		// All the pins in one --pin joined by a comma are not two pins.
		joined := []string{"--output", "json", "verify", "root-list", ps.cand, "--pin", strings.Join(ps.pins, ",")}
		r := vrunAt(t, ps.clock, joined...)
		if r.code != ExitUsage {
			t.Errorf("a comma between pins: exit %d %q", r.code, r.stderr)
		}
		if r := vrunAt(t, ps.clock, a...); r.code != ExitOK {
			t.Errorf("one --pin for each: exit %d %q", r.code, r.stderr)
		}
	})
}

func TestAFileNameThatDoesNotEndInDotJSONIsNotGuessed(t *testing.T) {
	m := vloadManifest(t)
	c := m.newAgainstHeld(t)
	s := vstage(t, m, c)
	// list.txt is a usage error even when list.jws and list.txt.jws exist beside it.
	txt := vwrite(t, s.dir, "list.txt", s.candBytes)
	vwrite(t, s.dir, "list.jws", s.jwsBytes)
	vwrite(t, s.dir, "list.txt.jws", s.jwsBytes)
	r := vrunAt(t, s.clock, "verify", "root-list", txt, "--held", s.held)
	if r.code != ExitUsage || r.stderr != "ritueel: "+msgNotJSON+"\n"+helpLine {
		t.Fatalf("exit %d stderr %q", r.code, r.stderr)
	}
	t.Run("only the last .json is replaced: x.json.json has the signature x.json.jws", func(t *testing.T) {
		both := vwrite(t, s.dir, "x.json.json", s.candBytes)
		vwrite(t, s.dir, "x.json.jws", s.jwsBytes)
		r := vrunAt(t, s.clock, "--output", "json", "verify", "root-list", both, "--held", s.held)
		files := [][2]string{{"x.json.json", sum(s.candBytes)}, {"x.json.jws", sum(s.jwsBytes)}}
		if r.code != ExitOK || r.stdout != doneObject(nil, files...) {
			t.Fatalf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
		}
	})
	t.Run("a name that is only .json has the signature .jws and is read, not refused as a name", func(t *testing.T) {
		r := vrunAt(t, s.clock, "verify", "root-list", filepath.Join(s.dir, ".json"), "--held", s.held)
		if r.code != ExitFailure || !strings.HasPrefix(r.stderr, "ritueel: cannot read the root list: ") {
			t.Fatalf("exit %d stderr %q", r.code, r.stderr)
		}
	})
}
