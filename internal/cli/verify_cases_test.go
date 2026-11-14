package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/rootlist"
)

// doneObject is the exact standard output of an accepted list in JSON mode: every member, in the
// order of the object, and nothing else.
func doneObject(warnings []string, files ...[2]string) string {
	return doneObjectAgain(warnings, false, files...)
}

// doneObjectAgain is the same with the member again, written last, when the list is the held one again.
func doneObjectAgain(warnings []string, again bool, files ...[2]string) string {
	var checked []string
	for _, f := range files {
		checked = append(checked, fmt.Sprintf(`{"name":%q,"sha256":%q}`, f[0], f[1]))
	}
	tail := ""
	if again {
		tail = `,"again":true`
	}
	return fmt.Sprintf(`{"output":1,"command":"verify","exit_code":0,"outcome":"done","warnings":%s,"checked":[%s]%s}`+"\n", jsonStrings(warnings), strings.Join(checked, ","), tail)
}

// wantTextAgain is the line of the text output for the held list coming again, as the page's command
// reference says: one line, after the line accepted.
const wantTextAgain = "again: the list the host holds, byte for byte; install nothing"

// vacceptedText is the whole standard output of an accepted list in text mode.
func vacceptedText(s *vscene, again bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "accepted: sequence %d, %s, expires %s\n", s.candList.Sequence, rootKeys(len(s.candList.Roots)), s.candList.ExpiresAt.Format("2006-01-02T15:04:05Z"))
	if again {
		b.WriteString(wantTextAgain + "\n")
	}
	for _, f := range vfiles(s) {
		fmt.Fprintf(&b, "%s  %s\n", f[1], f[0])
	}
	return b.String()
}

// vfiles are the entries of checked that the command must give for the scene: the list, its .jws
// and, when the bundle is given, the bundle (the page's order).
func vfiles(s *vscene) [][2]string {
	files := [][2]string{{"cand.json", sum(s.candBytes)}, {"cand.jws", sum(s.jwsBytes)}}
	if s.bundle != "" {
		files = append(files, [2]string{"bundle.pem", sum(s.bundleData)})
	}
	return files
}

// vagain is whether the case's candidate is the held list again, by the bytes.
func vagain(s *vscene) bool { return s.held != "" && string(s.heldBytes) == string(s.candBytes) }

func jsonStrings(s []string) string {
	if len(s) == 0 {
		return "[]"
	}
	q := make([]string, len(s))
	for i, e := range s {
		q[i] = fmt.Sprintf("%q", e)
	}
	return "[" + strings.Join(q, ",") + "]"
}

func refusedObject(reason string, warnings ...string) string {
	return fmt.Sprintf(`{"output":1,"command":"verify","exit_code":3,"outcome":"refused","reasons":[%q],"warnings":%s}`+"\n", reason, jsonStrings(warnings))
}

// checkNumberOf is the number of the check that refuses each case of the manifest, from the order
// of docs/reference/root-list.md. A refusing case that is not here fails the test.
var checkNumberOf = map[string]int{
	"signed-by-a-revoked-root":        2,
	"unknown-signer":                  2,
	"tampered":                        3,
	"version-2":                       4,
	"unknown-member":                  5,
	"rollback":                        6,
	"same-sequence-different-content": 7,
	"a-second-signer-on-no-list":      8,
	"removal-with-another-roots-authorisation": 9,
	"set-change-with-one-signature":            10,
	"removal-without-authorisation":            10,
	"addition-not-signed-by-the-new-root":      10,
	"addition-without-every-current-root":      10,
	"expired":                                  11,
	// The cases of the dates and of the small refusals of check 5, the lowest sequence (check 6)
	// and the held list again after its expiry (check 11).
	"expires-13-months-and-a-second-after-signing":  5,
	"expires-12-months-after-signing":               5,
	"signed-after-the-clock":                        5,
	"expires-by-plain-month-addition-from-the-31st": 5,
	"expires-by-plain-month-addition-from-the-30th": 5,
	"label-twice":                        5,
	"pin-twice":                          5,
	"fingerprint-in-upper-case":          5,
	"last-record-digest-one-digit-short": 5,
	"sequence-0":                         5,
	"pin-twice-in-removals":              5,
	"empty-authorisation":                5,
	"initial-pins-lowest-sequence-above": 6,
	"same-list-again-after-its-expiry":   11,
}

// TestEveryCaseOfTheManifestThroughTheCommand runs the cases of the manifest through cli.Run, in both
// output modes, with the clock of the case.
func TestEveryCaseOfTheManifestThroughTheCommand(t *testing.T) {
	m := vloadManifest(t)
	ran := 0
	for _, c := range m.Cases {
		t.Run(c.ID, func(t *testing.T) {
			ran++
			switch c.Expect {
			case "accept":
				s := vstage(t, m, c)
				warn := vheldWarnings(t, m, c, s.clock)
				again := vagain(s)
				j := vrunAt(t, s.clock, s.args("json")...)
				if j.code != ExitOK || j.stdout != doneObjectAgain(warn, again, vfiles(s)...) || j.stderr != warnLines(warn...) {
					t.Fatalf("json: %d\nstdout %q\nstderr %q", j.code, j.stdout, j.stderr)
				}
				txt := vrunAt(t, s.clock, s.args("text")...)
				want := vacceptedText(s, again)
				if txt.code != ExitOK || txt.stdout != want || txt.stderr != warnLines(warn...) {
					t.Fatalf("text: %d\nstdout %q\nwant   %q\nstderr %q", txt.code, txt.stdout, want, txt.stderr)
				}
			case "refuse":
				s := vstage(t, m, c)
				warn := vheldWarnings(t, m, c, s.clock)
				// The line of the refusal begins with the check that refused: a refusal of the CA bundle
				// has no check, because the list was accepted and the bundle was not.
				wantLine := warnLines(warn...) + "ritueel: refused: " + c.Reason + " ("
				if c.Bundle != "" {
					if c.Reason != "ca-bundle-mismatch" {
						t.Fatalf("a kind of case this test does not know: %q has a bundle and the reason %q", c.ID, c.Reason)
					}
				} else {
					n, known := checkNumberOf[c.ID]
					if !known {
						t.Fatalf("a kind of case this test does not know: %q is refused and the test does not know which check refuses it", c.ID)
					}
					wantLine += fmt.Sprintf("check %d: ", n)
				}
				j := vrunAt(t, s.clock, s.args("json")...)
				if j.code != ExitRefused || j.stdout != refusedObject(c.Reason, warn...) || !strings.HasPrefix(j.stderr, wantLine) || strings.Count(j.stderr, "\n") != 1+len(warn) {
					t.Fatalf("json: %d\nstdout %q\nstderr %q\nwant the line to begin %q", j.code, j.stdout, j.stderr, wantLine)
				}
				txt := vrunAt(t, s.clock, s.args("text")...)
				if txt.code != ExitRefused || txt.stdout != "" || txt.stderr != j.stderr {
					t.Fatalf("text: %d stdout %q stderr %q (json stderr %q)", txt.code, txt.stdout, txt.stderr, j.stderr)
				}
				terminalSafe(t, j)
			case "warn":
				vwarnCase(t, m, c)
			default:
				t.Fatalf("a kind of case this test does not know: case %q expects %q", c.ID, c.Expect)
			}
		})
	}
	if ran != len(m.Cases) || ran == 0 {
		t.Fatalf("ran %d of %d cases", ran, len(m.Cases))
	}
}

// vheldWarnings is the warning that the host's list raises at the clock, by the page: the held list
// has expired (the clock is not before its expires_at). It is worked out here from the held list.
func vheldWarnings(t *testing.T, m *vmanifest, c vcase, clock time.Time) []string {
	t.Helper()
	if c.Held == nil {
		return nil
	}
	if l := m.listOf(t, *c.Held); !clock.Before(l.ExpiresAt) {
		return []string{"held-expired"}
	}
	return nil
}

func rootKeys(n int) string {
	if n == 1 {
		return "1 root key"
	}
	return fmt.Sprintf("%d root keys", n)
}

// vwarnCase: the manifest's warn case has no candidate (it is about the held list), so the command
// is run with a candidate that is accepted at that clock, and with one that is refused; each raises
// the warning held-expired, which does not change the exit code.
func vwarnCase(t *testing.T, m *vmanifest, c vcase) {
	t.Helper()
	if c.Held == nil || c.Candidate != nil {
		t.Fatalf("a kind of case this test does not know: the warn case %q should name a held list and no candidate", c.ID)
	}
	clock := m.clockOf(t, c.Clock)
	heldBytes, _ := m.bytesOf(t, *c.Held)
	heldList := m.listOf(t, *c.Held)
	var accepted, refused string
	for _, l := range m.Lists {
		if l.ID == *c.Held {
			continue
		}
		cdata, _ := m.bytesOf(t, l.ID)
		cl, err := rootlist.ParseList(cdata)
		if err != nil {
			continue
		}
		dir := t.TempDir()
		cj, cs := m.bytesOf(t, l.ID)
		vwrite(t, dir, "cand.json", cj)
		vwrite(t, dir, "cand.jws", cs)
		hp := vwrite(t, dir, "held.json", heldBytes)
		r := vrunAt(t, clock, "--output", "json", "verify", "root-list", filepath.Join(dir, "cand.json"), "--held", hp)
		switch r.code {
		case ExitOK:
			if accepted == "" && cl.Sequence > heldList.Sequence {
				accepted = l.ID
			}
		case ExitRefused:
			if refused == "" {
				refused = l.ID
			}
		}
	}
	if accepted == "" || refused == "" {
		t.Fatalf("no list of the manifest is accepted (%q) and none refused (%q) at the clock of the warn case", accepted, refused)
	}
	for _, id := range []string{accepted, refused} {
		dir := t.TempDir()
		cj, cs := m.bytesOf(t, id)
		cand := vwrite(t, dir, "cand.json", cj)
		vwrite(t, dir, "cand.jws", cs)
		hp := vwrite(t, dir, "held.json", heldBytes)
		j := vrunAt(t, clock, "--output", "json", "verify", "root-list", cand, "--held", hp)
		txt := vrunAt(t, clock, "--output", "text", "verify", "root-list", cand, "--held", hp)
		warn := "ritueel: warning: held-expired\n"
		if id == accepted {
			files := [][2]string{{"cand.json", sum(cj)}, {"cand.jws", sum(cs)}}
			if j.code != ExitOK || j.stdout != doneObject([]string{"held-expired"}, files...) || j.stderr != warn {
				t.Fatalf("accepted, json: %d\nstdout %q\nstderr %q", j.code, j.stdout, j.stderr)
			}
			if txt.code != ExitOK || !strings.HasPrefix(txt.stdout, "accepted: sequence ") || txt.stderr != warn {
				t.Fatalf("accepted, text: %d stdout %q stderr %q", txt.code, txt.stdout, txt.stderr)
			}
			continue
		}
		reason := strings.TrimSuffix(strings.TrimPrefix(strings.SplitN(j.stderr, "\n", 3)[1], "ritueel: refused: "), "")
		reason = strings.SplitN(reason, " ", 2)[0]
		if j.code != ExitRefused || j.stdout != refusedObject(reason, "held-expired") || !strings.HasPrefix(j.stderr, warn+"ritueel: refused: "+reason+" (check ") {
			t.Fatalf("refused, json: %d\nstdout %q\nstderr %q", j.code, j.stdout, j.stderr)
		}
		if txt.code != ExitRefused || txt.stdout != "" || txt.stderr != j.stderr {
			t.Fatalf("refused, text: %d stdout %q stderr %q", txt.code, txt.stdout, txt.stderr)
		}
	}
}

// TestTheSha256sumLinesAreWhatTheToolReads writes the lines the command prints into a file beside
// the two files and has sha256sum -c read them there: the lines are accepted for the files the
// command checked, and a file that changes afterwards is caught. The digests are also computed in
// this test, not taken from the command.
func TestTheSha256sumLinesAreWhatTheToolReads(t *testing.T) {
	tool := requireTool(t, "sha256sum")
	m := vloadManifest(t)
	// The scenes: a new list, the held list again, a first list, and (with the CA bundle of a case of
	// the manifest) the three files of an accepted bundle.
	var bundleCase vcase
	for _, c := range m.Cases {
		if c.Expect == "accept" && c.Bundle != "" {
			bundleCase = c
			break
		}
	}
	if bundleCase.ID == "" {
		t.Fatal("the manifest has no accepting case with a CA bundle")
	}
	for _, c := range []vcase{m.newAgainstHeld(t), m.againCase(t), m.againstPins(t), bundleCase} {
		t.Run(c.ID, func(t *testing.T) {
			s := vstage(t, m, c)
			again := vagain(s)
			r := vrunAt(t, s.clock, s.args("text")...)
			if r.code != ExitOK {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			if r.stdout != vacceptedText(s, again) {
				t.Fatalf("stdout %q, want %q", r.stdout, vacceptedText(s, again))
			}
			lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
			// After the line accepted, and the line again when there is one, come the lines for sha256sum:
			// the digest, two spaces and the name, one for each file in one folder.
			skip := 1
			if again {
				skip = 2
			}
			sums := lines[skip:]
			if want := len(vfiles(s)); len(sums) != want {
				t.Fatalf("%d lines for sha256sum, want %d: %q", len(sums), want, sums)
			}
			for i, f := range vfiles(s) {
				if sums[i] != f[1]+"  "+f[0] {
					t.Fatalf("line %d is %q, not the digest computed here %q", i, sums[i], f[1]+"  "+f[0])
				}
			}
			vwrite(t, s.dir, "SHA256SUMS", []byte(strings.Join(sums, "\n")+"\n"))
			cmd := exec.CommandContext(t.Context(), tool, "-c", "SHA256SUMS")
			cmd.Dir = s.dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("sha256sum -c: %v\n%s", err, out)
			}
			var wantOut string
			for _, f := range vfiles(s) {
				wantOut += f[0] + ": OK\n"
			}
			if string(out) != wantOut {
				t.Errorf("sha256sum says %q, want %q", out, wantOut)
			}
			if again {
				// The page says a script reads the lines after "accepted". With the line again among them,
				// the first of those lines is no digest line: sha256sum -c skips it with a warning and
				// checks the files, and --strict refuses it. A script that means to run the tool on
				// the lines takes the lines that have a digest.
				vwrite(t, s.dir, "ALLAFTER", []byte(strings.Join(lines[1:], "\n")+"\n"))
				cmd = exec.CommandContext(t.Context(), tool, "-c", "ALLAFTER")
				cmd.Dir = s.dir
				out, err = cmd.CombinedOutput()
				if err != nil || !strings.Contains(string(out), "cand.json: OK") || !strings.Contains(string(out), "improperly formatted") {
					t.Errorf("sha256sum -c on the lines after accepted: %v %q", err, out)
				}
				cmd = exec.CommandContext(t.Context(), tool, "-c", "--strict", "ALLAFTER")
				cmd.Dir = s.dir
				if out, err := cmd.CombinedOutput(); err == nil {
					t.Errorf("sha256sum -c --strict took the line again: %q", out)
				}
			}
			// The file that changes after the check is the file the lines do not describe: each of the
			// files, the bundle included.
			for _, f := range vfiles(s) {
				p := filepath.Join(s.dir, f[0])
				orig, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, append(slices.Clone(orig), '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
				cmd = exec.CommandContext(t.Context(), tool, "-c", "SHA256SUMS")
				cmd.Dir = s.dir
				if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), f[0]+": FAILED") {
					t.Errorf("sha256sum -c did not catch a changed %s: %v %q", f[0], err, out)
				}
				if err := os.WriteFile(p, orig, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
