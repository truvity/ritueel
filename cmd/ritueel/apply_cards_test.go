//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The program that the release builds, run on a bundle with card files: "apply --plan-only" stops at a card
// file that fails its check with the exit code 1 and writes nothing, and gives the result it always gave for a
// good set (record 0005, rule 19). The names of this file start with acp.

const (
	acpRootA = "version: 1\nserial: \"10000001\"\nkind: root\napplications: [piv, fido2]\nother_rows: [3]\n"
	acpRootB = "version: 1\nserial: \"10000002\"\nkind: root\napplications: [piv, fido2]\n"
	acpBad   = "version: 2\nserial: \"10000009\"\nkind: server\napplications: [piv]\n"
)

func TestProgramApplyPlanOnlyWithCardFiles(t *testing.T) {
	p := apProgram{t: t, exe: buildForCheck(t), dir: t.TempDir()}
	// bundle makes a bundle of one test root, as a person has it after new, with a key directory.
	bundle := func(t *testing.T, cards map[string]string) (ca, keys string) {
		t.Helper()
		root := t.TempDir()
		ca, keys = filepath.Join(root, "ca"), filepath.Join(root, "keys")
		if code, _, stderr := p.run(nil, "new", "--test-root", ca); code != 0 {
			t.Fatalf("new: %d %s", code, stderr)
		}
		if _, err := os.Lstat(filepath.Join(ca, "want", "cards")); err == nil {
			t.Fatal("new made want/cards")
		}
		if err := os.Remove(filepath.Join(ca, "want", "roots", "openpgp.yaml")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(keys, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, text := range cards {
			putFile(t, ca, "want/cards/"+name, text)
		}
		return ca, keys
	}
	planOnly := func(ca, keys string, extra ...string) (int, string, string) {
		args := append([]string{"--dir", ca, "apply", "--plan-only", "--key-dir", keys}, extra...)
		return p.run(nil, args...)
	}

	t.Run("a good set is exit 0 and the plan folder holds no card file", func(t *testing.T) {
		ca, keys := bundle(t, map[string]string{"root-a.yaml": acpRootA, "root-b.yaml": acpRootB})
		code, stdout, stderr := planOnly(ca, keys, "--output", "json")
		if code != 0 {
			t.Fatalf("exit %d, stderr %s", code, stderr)
		}
		var obj struct{ Plan struct{ Path string } }
		if err := json.Unmarshal([]byte(stdout), &obj); err != nil || obj.Plan.Path == "" {
			t.Fatalf("standard output %q, %v", stdout, err)
		}
		tree := apTreeOf(t, ca)
		if !strings.Contains(tree, "history/") || strings.Contains(tree, "wanted/want/cards") || strings.Contains(tree, "wanted/cards") {
			t.Errorf("the plan folder holds a card file:\n%s", tree)
		}
		for _, name := range []string{"root-a.yaml", "root-b.yaml"} {
			got, err := os.ReadFile(filepath.Join(ca, "want", "cards", name))
			if err != nil || len(got) == 0 {
				t.Errorf("card file %s: %v", name, err)
			}
		}
		// check history accepts what was written, with a bad card file beside it.
		code, hist, _ := p.run(nil, "--dir", ca, "check", "history")
		putFile(t, ca, "want/cards/bad.yaml", acpBad)
		code2, hist2, _ := p.run(nil, "--dir", ca, "check", "history")
		if code != 0 || code2 != 0 || hist != hist2 {
			t.Errorf("check history: %d %q / %d %q", code, hist, code2, hist2)
		}
	})

	t.Run("a bundle with no card file gives the same result as one with an empty folder", func(t *testing.T) {
		ca, keys := bundle(t, nil)
		code, _, _ := planOnly(ca, keys)
		ca2, keys2 := bundle(t, nil)
		if err := os.MkdirAll(filepath.Join(ca2, "want", "cards"), 0o755); err != nil {
			t.Fatal(err)
		}
		code2, _, _ := planOnly(ca2, keys2)
		if code != 0 || code2 != 0 {
			t.Errorf("exit codes %d and %d", code, code2)
		}
	})

	bad := map[string]struct {
		cards map[string]string
		path  string
	}{
		"a version that is not 1":    {map[string]string{"root-a.yaml": acpRootA, "bad.yaml": acpBad}, "want/cards/bad.yaml"},
		"a card named twice":         {map[string]string{"root-a.yaml": acpRootA, "twin.yaml": acpRootA}, "want/cards/twin.yaml"},
		"a name that is not allowed": {map[string]string{"root-a.yaml": acpRootA, "Bad.yaml": acpRootB}, "want/cards/Bad.yaml"},
		"a name with a control code": {map[string]string{"root-a.yaml": acpRootA, "a\x01b.yaml": acpRootB}, `want/cards/a\u0001b.yaml`},
		"a folder":                   {map[string]string{"root-a.yaml": acpRootA, "sub/x.yaml": acpRootB}, "want/cards/sub"},
	}
	for name, c := range bad {
		t.Run("refused: "+name, func(t *testing.T) {
			ca, keys := bundle(t, c.cards)
			before, keysBefore := apTreeOf(t, ca), apTreeOf(t, keys)
			code, stdout, stderr := planOnly(ca, keys)
			if code != 1 || stdout != "" {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if !strings.Contains(stderr, c.path) || !strings.Contains(stderr, "nothing was written") {
				t.Errorf("standard error %q does not name %q and say that nothing was written", stderr, c.path)
			}
			for _, l := range strings.Split(stderr, "\n") {
				for i := 0; i < len(l); i++ {
					if l[i] < 0x20 || l[i] > 0x7e {
						t.Fatalf("standard error is not printable ASCII: %+q", stderr)
					}
				}
			}
			if after := apTreeOf(t, ca); after != before {
				t.Errorf("the bundle changed:\n%s\n%s", before, after)
			}
			if after := apTreeOf(t, keys); after != keysBefore {
				t.Errorf("the key directory changed")
			}
			// JSON: an error member and no reasons.
			code, stdout, _ = planOnly(ca, keys, "--output", "json")
			var obj map[string]any
			if err := json.Unmarshal([]byte(stdout), &obj); err != nil {
				t.Fatalf("standard output %q: %v", stdout, err)
			}
			msg, _ := obj["error"].(string)
			if code != 1 || obj["exit_code"] != float64(1) || !strings.Contains(msg, c.path) {
				t.Errorf("JSON: exit %d, %v", code, obj)
			}
			if _, has := obj["reasons"]; has {
				t.Errorf("a refusal of a wanted file has reasons: %v", obj)
			}
		})
	}
}
