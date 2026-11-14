package wanted_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// The wanted root file holds version, kind and the optional test, and nothing else yet.

const rootFilePath = "want/roots/x509.yaml"

func mustRoot(t testing.TB, name, text string) *wanted.Root {
	t.Helper()
	r, err := wanted.ParseRoot(name, []byte(text))
	if err != nil {
		t.Fatalf("the reader refuses a root file that must be accepted: %v\n%s", err, text)
	}
	if r == nil || !r.Valid() {
		t.Fatalf("no error, and the root is %v", r)
	}
	return r
}

func refuseRoot(t testing.TB, text string, line int, words ...string) *wanted.Error {
	t.Helper()
	r, err := wanted.ParseRoot("x509", []byte(text))
	if r != nil {
		t.Errorf("a value beside the error %v", err)
	}
	return wantFault(t, err, rootFilePath, line, words...)
}

func TestARootFileOfEachKindIsRead(t *testing.T) {
	for _, kind := range []wanted.RootKind{wanted.RootX509, wanted.RootOpenPGP, wanted.RootSSH} {
		r := mustRoot(t, "x509", "version: 1\nkind: "+string(kind)+"\n")
		if r.Kind != kind || r.Test || r.Name != "x509" || r.File.Path != rootFilePath {
			t.Errorf("kind %s: %+v", kind, r)
		}
	}
	if string(wanted.RootX509) != "x509" || string(wanted.RootOpenPGP) != "openpgp" || string(wanted.RootSSH) != "ssh" {
		t.Error("the spellings of the kinds changed")
	}
	if r := mustRoot(t, "x509", goodRoot); r.Test {
		t.Error("test: false is read as a test root")
	}
	if r := mustRoot(t, "openpgp", "version: 1\nkind: openpgp\ntest: true  # set at birth\n"); !r.Test || r.File.Path != "want/roots/openpgp.yaml" {
		t.Errorf("%+v", r)
	}
}

func TestARootFileThatIsNotTheSmallShapeIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		text  string
		line  int
		words []string
	}{
		"kind rsa":                {"version: 1\nkind: rsa\n", 2, []string{"kind", "x509, openpgp, ssh"}},
		"kind in upper case":      {"version: 1\nkind: X509\n", 2, []string{"kind"}},
		"kind with a space":       {"version: 1\nkind: \"x509 \"\n", 2, []string{"kind"}},
		"kind as a list":          {"version: 1\nkind: [x509]\n", 2, []string{"kind must be a string"}},
		"kind as a number":        {"version: 1\nkind: 509\n", 2, []string{"kind must be a string"}},
		"no kind":                 {"version: 1\ntest: true\n", -1, []string{"kind", "required"}},
		"no version":              {"kind: x509\n", -1, []string{"version", "required"}},
		"version 2":               {"version: 2\nkind: x509\n", 1, []string{"version must be 1"}},
		"test yes":                {"version: 1\nkind: x509\ntest: yes\n", 3, []string{"test must be true or false"}},
		"test on":                 {"version: 1\nkind: x509\ntest: on\n", 3, []string{"test must be true or false"}},
		"test True":               {"version: 1\nkind: x509\ntest: True\n", 3, []string{"test must be true or false"}},
		"test quoted":             {"version: 1\nkind: x509\ntest: \"true\"\n", 3, []string{"test must be true or false"}},
		"test 1":                  {"version: 1\nkind: x509\ntest: 1\n", 3, []string{"test must be true or false"}},
		"test empty":              {"version: 1\nkind: x509\ntest:\n", 3, []string{"null"}},
		"test null":               {"version: 1\nkind: x509\ntest: null\n", 3, []string{"null"}},
		"keys":                    {"version: 1\nkind: x509\nkeys: []\n", 3, []string{"keys", "not read yet", "first apply"}},
		"keys with a label":       {"version: 1\nkind: x509\nkeys:\n  - label: A\n", 3, []string{"not read yet"}},
		"a retirement date":       {"version: 1\nkind: x509\nretire_at: 2030-01-01\n", 3, []string{"retire_at", "not read yet"}},
		"revocation reasons":      {"version: 1\nkind: x509\nrevocation_reasons: [compromised]\n", 3, []string{"not read yet"}},
		"a name":                  {"version: 1\nkind: x509\nname: x\n", 3, []string{"not read yet"}},
		"a key in another case":   {"version: 1\nKind: x509\n", 2, []string{"not read yet"}},
		"a list":                  {"- x509\n", 1, []string{"not a mapping"}},
		"empty":                   {"", 0, []string{"no document"}},
		"a repeated kind":         {"version: 1\nkind: x509\nkind: ssh\n", 3, []string{"appears twice"}},
		"a tag":                   {"version: 1\nkind: !!str x509\n", 2, []string{"tag"}},
		"an anchor":               {"version: 1\nkind: &k x509\n", 2, []string{"anchor"}},
		"a second document":       {"version: 1\nkind: x509\n---\nversion: 1\nkind: x509\n", 3, []string{"second document"}},
		"a tab":                   {"version: 1\nkind:\tx509\n", 2, []string{"tab"}},
		"a bidirectional control": {"version: 1\nkind: x509 # \u202e\n", 2, []string{"format character"}},
	} {
		t.Run(name, func(t *testing.T) { _ = refuseRoot(t, tc.text, tc.line, tc.words...) })
	}
	// An unknown member is named, cut and escaped.
	e := refuseRoot(t, "version: 1\nkind: x509\n"+strings.Repeat("k", 100)+": 1\n", 3, "not read yet")
	if strings.Contains(e.Msg, strings.Repeat("k", 41)) {
		t.Errorf("the member name is not cut: %s", e.Msg)
	}
}

func TestARootNameHasTheFormOfAName(t *testing.T) {
	for _, name := range []string{"a", "x509", "acme-tls", strings.Repeat("a", 63)} {
		if r, err := wanted.ParseRoot(name, []byte(goodRoot)); err != nil || r.Name != name || r.File.Path != "want/roots/"+name+".yaml" {
			t.Errorf("%q: %v %v", name, r, err)
		}
	}
	for _, name := range []string{"", "X509", "a_b", "-a", strings.Repeat("a", 64), "a.yaml", "a/b", "..", ".rt-x", "a b", "a\x00", "\u0430"} {
		t.Run(strings.ToValidUTF8(name, "?"), func(t *testing.T) {
			r, err := wanted.ParseRoot(name, []byte(goodRoot))
			if r != nil || err == nil {
				t.Fatalf("accepted: %v", r)
			}
			_ = wantFault(t, err, "", 0)
			if r, err := wanted.LoadRoot(nil, name); r != nil || err == nil {
				t.Errorf("LoadRoot accepted: %v", r)
			}
		})
	}
}

func TestARootIsNeverMadeByHand(t *testing.T) {
	var zero wanted.Root
	var none *wanted.Root
	if zero.Valid() || none.Valid() {
		t.Error("a zero or nil Root is valid")
	}
	if byHand := (wanted.Root{Name: "x509", Kind: wanted.RootX509}); byHand.Valid() {
		t.Error("a Root that a caller filled in is valid")
	}
}
