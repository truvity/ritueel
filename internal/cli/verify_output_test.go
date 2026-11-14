package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
)

// The command gives the SHA-256 of root-list.json and of its .jws in the JSON object
// (the member "checked") and on the lines after "accepted", in the form that sha256sum -c reads, so
// that a script can compare before it installs. They are the digests of the bytes that were checked.
// Only an accepted list has them. --min-sequence N is for a host that has pins.

func TestTheCheckedMemberAndTheLinesBelowAccepted(t *testing.T) {
	m := vloadManifest(t)
	for name, c := range map[string]vcase{"a new list": m.newAgainstHeld(t), "the held list again": m.againCase(t), "a first list against pins": m.againstPins(t)} {
		t.Run(name, func(t *testing.T) {
			s := vstage(t, m, c)
			js := vrunAt(t, s.clock, s.args("json")...)
			obj := jsonObject(t, js)
			want := [][2]string{{"cand.json", sum(s.candBytes)}, {"cand.jws", sum(s.jwsBytes)}}
			list, _ := obj["checked"].([]any)
			if len(list) != 2 {
				t.Fatalf("checked: %v", obj["checked"])
			}
			for i, e := range list {
				entry, _ := e.(map[string]any)
				if len(entry) != 2 || entry["name"] != want[i][0] || entry["sha256"] != want[i][1] {
					t.Errorf("entry %d is %v, want %v", i, entry, want[i])
				}
			}
			again := vagain(s)
			if js.stdout != doneObjectAgain(vheldWarnings(t, m, c, s.clock), again, want...) {
				t.Errorf("stdout %q", js.stdout)
			}
			txt := vrunAt(t, s.clock, s.args("text")...)
			if txt.stdout != vacceptedText(s, again) {
				t.Errorf("text %q", txt.stdout)
			}
		})
	}
	t.Run("the name is the base name of the path as given, whatever folder it is in", func(t *testing.T) {
		s := vstage(t, m, m.newAgainstHeld(t))
		sub := t.TempDir() + "/deeper"
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		cand := vwrite(t, sub, "list-7.json", s.candBytes)
		vwrite(t, sub, "list-7.jws", s.jwsBytes)
		r := vrunAt(t, s.clock, "--output", "json", "verify", "root-list", cand, "--held", s.held)
		if r.stdout != doneObject(nil, [2]string{"list-7.json", sum(s.candBytes)}, [2]string{"list-7.jws", sum(s.jwsBytes)}) {
			t.Errorf("stdout %q", r.stdout)
		}
	})
	t.Run("the digest is of the bytes that were checked, not of a file of the same name", func(t *testing.T) {
		// The two files differ from each other, and each digest is its own: a digest that was of the
		// other file, or of both, would show here.
		s := vstage(t, m, m.newAgainstHeld(t))
		if sum(s.candBytes) == sum(s.jwsBytes) {
			t.Fatal("the two files are the same")
		}
		r := vrunAt(t, s.clock, s.args("json")...)
		if !strings.Contains(r.stdout, sum(s.candBytes)) || !strings.Contains(r.stdout, sum(s.jwsBytes)) || strings.Contains(r.stdout, sum(append(slicesClone(s.candBytes), s.jwsBytes...))) {
			t.Errorf("stdout %q", r.stdout)
		}
		first := strings.Index(r.stdout, sum(s.candBytes))
		second := strings.Index(r.stdout, sum(s.jwsBytes))
		if first > second {
			t.Errorf("the .jws is named before the list")
		}
	})
	t.Run("with a CA bundle the bundle is the third, last entry", func(t *testing.T) {
		s, bundle, _ := m.bundleScene(t)
		bp := vwrite(t, s.dir, "bundle.pem", bundle)
		bs := *s
		bs.bundle, bs.bundleData = bp, bundle
		r := vrunAt(t, s.clock, bs.args("json")...)
		if r.code != ExitOK || r.stdout != doneObject(vheldWarnings(t, m, s.caseRecord, s.clock), vfiles(&bs)...) {
			t.Fatalf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
		}
	})
	t.Run("a refusal, a failure and a usage error have no checked member and no extra line", func(t *testing.T) {
		c := m.refusing(t, "rollback")
		s := vstage(t, m, c)
		for _, r := range []result{
			vrunAt(t, s.clock, s.args("json")...),
			vrunAt(t, s.clock, s.args("text")...),
			vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.dir+"/missing.json", "--held", s.held),
			vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.cand),
		} {
			if strings.Contains(r.stdout, "checked") || strings.Contains(r.stdout, sum(s.candBytes)) || strings.Contains(r.stderr, sum(s.candBytes)) {
				t.Errorf("a digest or the member checked in %q / %q", r.stdout, r.stderr)
			}
		}
	})
}

func slicesClone(b []byte) []byte { return append([]byte(nil), b...) }

func TestTheTextLineSaysRootKeyInTheSingular(t *testing.T) {
	m := vloadManifest(t)
	one, many := false, false
	for _, c := range m.Cases {
		if c.Expect != "accept" {
			continue
		}
		s := vstage(t, m, c)
		r := vrunAt(t, s.clock, s.args("text")...)
		first := strings.SplitN(r.stdout, "\n", 2)[0]
		switch len(s.candList.Roots) {
		case 1:
			one = true
			if !strings.Contains(first, ", 1 root key, expires ") {
				t.Errorf("%s: %q", c.ID, first)
			}
		default:
			many = true
			if !strings.Contains(first, fmt.Sprintf(", %d root keys, expires ", len(s.candList.Roots))) {
				t.Errorf("%s: %q", c.ID, first)
			}
		}
	}
	if !one || !many {
		t.Errorf("the manifest has an accepted list of one root key: %v, and of several: %v", one, many)
	}
}

func TestTheLowestSequenceThroughTheCommand(t *testing.T) {
	m := vloadManifest(t)
	s := vstage(t, m, m.againstPins(t))
	seq := s.candList.Sequence
	files := [][2]string{{"cand.json", sum(s.candBytes)}, {"cand.jws", sum(s.jwsBytes)}}
	n := func(x int64) string { return fmt.Sprint(x) }
	for _, mode := range []string{"json", "text"} {
		for _, c := range []struct {
			min  int64
			code ExitCode
		}{{1, ExitOK}, {seq, ExitOK}, {seq + 1, ExitRefused}, {seq + 1000, ExitRefused}, {9007199254740991, ExitRefused}} {
			t.Run(fmt.Sprintf("%s: --min-sequence %d against a list of sequence %d", mode, c.min, seq), func(t *testing.T) {
				r := vrunAt(t, s.clock, s.args(mode, "--min-sequence", n(c.min))...)
				if r.code != c.code {
					t.Fatalf("exit %d, want %d\nstdout %q\nstderr %q", r.code, c.code, r.stdout, r.stderr)
				}
				if c.code == ExitOK {
					if mode == "json" && r.stdout != doneObject(nil, files...) || r.stderr != "" {
						t.Errorf("stdout %q stderr %q", r.stdout, r.stderr)
					}
					return
				}
				wantLine := fmt.Sprintf("ritueel: refused: rollback (check 6: the sequence %d is lower than the lowest sequence %d that the host accepts)\n", seq, c.min)
				if r.stderr != wantLine || (mode == "json" && r.stdout != refusedObject("rollback")) || (mode == "text" && r.stdout != "") {
					t.Errorf("stdout %q\nstderr %q\nwant   %q", r.stdout, r.stderr, wantLine)
				}
			})
		}
	}
	t.Run("without the flag nothing changes", func(t *testing.T) {
		r := vrunAt(t, s.clock, s.args("json")...)
		if r.code != ExitOK || r.stdout != doneObject(nil, files...) {
			t.Errorf("exit %d stdout %q", r.code, r.stdout)
		}
	})
	t.Run("an earlier check speaks first", func(t *testing.T) {
		// A list that is below the lowest sequence and is not signed by a pin the host holds: check 2.
		other := m.refusing(t, "unknown-signer")
		o := vstage(t, m, other)
		r := vrunAt(t, o.clock, "--output", "json", "verify", "root-list", o.cand, "--pin", strings.Repeat("0", 64), "--min-sequence", "9007199254740991")
		if r.code != ExitRefused || r.stdout != refusedObject("unknown-signer") {
			t.Errorf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
		}
	})
	t.Run("a lowest sequence with a CA bundle", func(t *testing.T) {
		r := vrunAt(t, s.clock, s.args("json", "--min-sequence", n(seq+1), "--ca-bundle", s.dir+"/missing.pem")...)
		if r.code != ExitFailure {
			t.Errorf("all inputs are read before any check: exit %d", r.code)
		}
	})
}

func TestTheCABundleThroughTheCommand(t *testing.T) {
	m := vloadManifest(t)
	s, bundle, _ := m.bundleScene(t)
	good := vwrite(t, s.dir, "bundle.pem", bundle)
	warn := vheldWarnings(t, m, s.caseRecord, s.clock)
	withBundle := func(p string, data []byte) *vscene {
		c := *s
		c.bundle, c.bundleData = p, data
		return &c
	}
	good0 := withBundle(good, bundle)
	if r := vrunAt(t, s.clock, good0.args("json")...); r.code != ExitOK || r.stdout != doneObject(warn, vfiles(good0)...) {
		t.Fatalf("the witness: exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
	// A certificate with the right key whose signature byte is changed: the text is not what
	// the root key signed.
	block, _ := pem.Decode(bundle)
	if block == nil {
		t.Fatal("the bundle has no block")
	}
	lines := bytes.SplitN(bundle, []byte("\n"), 2)
	flipLast := func(der []byte) []byte { d := append([]byte(nil), der...); d[len(d)-1] ^= 0x01; return d }
	bad := append(append([]byte(nil), lines[0]...), '\n')
	bad = append(bad, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: flipLast(block.Bytes)})...)
	rest := lines[1][len(pem.EncodeToMemory(block)):]
	bad = append(bad, rest...)
	for name, data := range map[string][]byte{
		"a certificate whose own signature does not verify": bad,
		"the sequence line changed":                         bytes.Replace(bundle, lines[0], []byte(string(lines[0])+"0"), 1),
		"only the first line":                               append(lines[0], '\n'),
		"nothing":                                           nil,
	} {
		t.Run(name, func(t *testing.T) {
			p := vwrite(t, s.dir, "bad.pem", data)
			j := vrunAt(t, s.clock, withBundle(p, data).args("json")...)
			x := vrunAt(t, s.clock, withBundle(p, data).args("text")...)
			wantErr := warnLines(warn...) + "ritueel: refused: ca-bundle-mismatch ("
			if j.code != ExitRefused || j.stdout != refusedObject("ca-bundle-mismatch", warn...) || !strings.HasPrefix(j.stderr, wantErr) || x.code != ExitRefused || x.stdout != "" || x.stderr != j.stderr {
				t.Fatalf("json: %d %q %q\ntext: %d %q %q", j.code, j.stdout, j.stderr, x.code, x.stdout, x.stderr)
			}
		})
	}
	t.Run("the bundle is judged only for a list that is accepted", func(t *testing.T) {
		c := m.refusing(t, "rollback")
		rs := vstage(t, m, c)
		bp := vwrite(t, rs.dir, "bundle.pem", []byte("not a bundle"))
		r := vrunAt(t, rs.clock, rs.args("json", "--ca-bundle", bp)...)
		if r.code != ExitRefused || !strings.Contains(r.stdout, `"reasons":["rollback"]`) {
			t.Errorf("exit %d stdout %q", r.code, r.stdout)
		}
	})
	t.Run("the bundle is read before any check: a bundle that is not there is a failure", func(t *testing.T) {
		c := m.refusing(t, "rollback")
		rs := vstage(t, m, c)
		r := vrunAt(t, rs.clock, rs.args("json", "--ca-bundle", rs.dir+"/missing.pem")...)
		if r.code != ExitFailure || !strings.HasPrefix(r.stderr, "ritueel: cannot read the CA bundle: ") {
			t.Errorf("exit %d stderr %q", r.code, r.stderr)
		}
	})
}

func TestWhatReachesTheTerminalIsPrintableASCIIWhateverTheFilesHold(t *testing.T) {
	m := vloadManifest(t)
	s := vstage(t, m, m.newAgainstHeld(t))
	hostile := []string{"\xff\xfe", "\x1b[31mred", "\u0430\u0431", "\u202e", "a\nb", "\x00", "\xed\xa0\x80", strings.Repeat("\u0430", 300), "\x7f", "\r\n"}
	header := func(alg string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + strings.NewReplacer(`"`, `\"`, "\n", `\n`, "\r", `\r`, "\x00", `\u0000`, "\x1b", `\u001b`, "\x7f", `\u007f`).Replace(alg) + `","kid":"x","typ":"root-list+json","x5c":[]}`))
	}
	for _, h := range hostile {
		for name, fn := range map[string]func() result{
			"a hostile text in the header of the signature": func() result {
				jws := []byte(`{"signatures":[{"protected":"` + header(h) + `","signature":"AAAA"}]}`)
				p := vwrite(t, s.dir, "hostile.json", s.candBytes)
				vwrite(t, s.dir, "hostile.jws", jws)
				return vrunAt(t, s.clock, "--output", "json", "verify", "root-list", p, "--held", s.held)
			},
			"a hostile member name in the held list": func() result {
				data := bytes.Replace(s.heldBytes, []byte(`"version":1`), []byte(`"version":1,"`+h+`":1`), 1)
				p := vwrite(t, s.dir, "held2.json", data)
				return vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.cand, "--held", p)
			},
			"a hostile file as the candidate": func() result {
				p := vwrite(t, s.dir, "junk.json", []byte(h))
				vwrite(t, s.dir, "junk.jws", []byte(h))
				return vrunAt(t, s.clock, "--output", "json", "verify", "root-list", p, "--held", s.held)
			},
			"a hostile bundle": func() result {
				p := vwrite(t, s.dir, "junk.pem", []byte(h))
				return vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.cand, "--held", s.held, "--ca-bundle", p)
			},
			"a hostile name of a file that is not there": func() result {
				return vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.dir+"/"+h+".json", "--held", s.held)
			},
			"a hostile name of the held list": func() result {
				return vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.cand, "--held", s.dir+"/"+h)
			},
			"a hostile pin": func() result {
				return vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.cand, "--pin", h)
			},
			"a hostile lowest sequence": func() result {
				return vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.cand, "--pin", strings.Repeat("a", 64), "--min-sequence", h)
			},
			"a hostile second word": func() result { return vrunAt(t, s.clock, "--output", "json", "verify", h) },
		} {
			t.Run(name, func(t *testing.T) {
				r := fn()
				if r.code == ExitOK {
					t.Fatalf("accepted: %q", r.stdout)
				}
				terminalSafe(t, r)
				obj := jsonObject(t, r)
				if _, has := obj["checked"]; has {
					t.Errorf("checked in the object of a refusal")
				}
			})
		}
	}
}
