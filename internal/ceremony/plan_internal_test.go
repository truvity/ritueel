package ceremony

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"

	"ritueel.id/ritueel/internal/wanted"
)

// The checks that MakePlan makes of a Found before it builds anything, and the check that a plan
// reader makes of the version, are the first of two layers: the reader of the run judges the bytes
// again. These tests look at the first layer alone, so that a change that leaves only the second
// layer in place is seen.

const (
	piSettings = "version: 1\nname: Example\nrelease_address: release@example.org\npolicy:\n  stores: [piv, openpgp-card, aws-kms, software]\n  min_firmware: 5.7.0\n  pin_policy: [once, always]\n  require_name_constraints: true\n  validity_months: 13\n"
	piRoot     = "version: 1\nkind: x509\ntest: true\n"
)

// piFound makes the Found of a first apply by hand, from the readers of the wanted package.
func piFound(t testing.TB) *Found {
	t.Helper()
	s, err := wanted.ParseSettings("ritueel.yaml", []byte(piSettings))
	if err != nil {
		t.Fatal(err)
	}
	r, err := wanted.ParseRoot("x509", []byte(piRoot))
	if err != nil {
		t.Fatal(err)
	}
	return &Found{
		Applies:  []Change{{Change: "create", Object: "x509/A"}, {Change: "create", Object: "x509/B"}},
		Root:     r,
		Settings: s,
		Wanted:   []wanted.File{s.File, r.File},
	}
}

func TestCheckFoundAcceptsTheFoundOfAFirstApply(t *testing.T) {
	labels, err := checkFound(piFound(t))
	if err != nil || strings.Join(labels, "") != "AB" {
		t.Errorf("checkFound = %q, %v", labels, err)
	}
}

func TestCheckFoundRefusesWhatMakePlanMustNotBuildFrom(t *testing.T) {
	cases := map[string]func(f *Found){
		"a third wanted file": func(f *Found) {
			f.Wanted = append(f.Wanted, wanted.File{Path: "want/roots/other.yaml", Data: []byte("x")})
		},
		"the same wanted file twice": func(f *Found) { f.Wanted[1] = f.Wanted[0] },
		"a third wanted file that is one of the two": func(f *Found) {
			f.Wanted = append(f.Wanted, f.Wanted[0])
		},
		"one wanted file": func(f *Found) { f.Wanted = f.Wanted[:1] },
		"another root name in a change": func(f *Found) {
			f.Applies[0].Object = "other/A"
		},
		"another label in a change":   func(f *Found) { f.Applies[1].Object = "x509/C" },
		"a change that is not create": func(f *Found) { f.Applies[0].Change = "retire" },
		"a wanted path that is not a path": func(f *Found) {
			f.Wanted[1].Path = "want/roots/../x509.yaml"
			f.Root.File.Path = f.Wanted[1].Path
		},
		"a wanted path of 13 elements": func(f *Found) {
			p := strings.Repeat("a/", 12) + "x.yaml"
			f.Wanted[1].Path = p
			f.Root.File.Path = p
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := piFound(t)
			edit(f)
			if labels, err := checkFound(f); err == nil || labels != nil {
				t.Errorf("checkFound = %q, %v; want an error", labels, err)
			}
		})
	}
}

func TestThePlanReaderRefusesAnotherVersionOnItsOwn(t *testing.T) {
	// files.ReadPlan refuses a version that is not 1 before this check is reached; the check of the
	// typed plan says it again, so that a typed plan is never judged on the word of another reader.
	env := Env{
		Now: func() time.Time { return time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC) },
		Self: func() (buildinfo.Program, error) {
			return buildinfo.Program{Version: "v1", OSArch: "linux/amd64", SHA256: strings.Repeat("ab", 32)}, nil
		},
	}
	p, err := MakePlan(piFound(t), env)
	if err != nil {
		t.Fatal(err)
	}
	var d planDoc
	if err := json.Unmarshal(p.JSON, &d); err != nil {
		t.Fatal(err)
	}
	if _, err := d.check(); err != nil {
		t.Fatalf("the plan that was made is refused: %v", err)
	}
	d.Version = 2
	if out, err := d.check(); err == nil || out != nil {
		t.Errorf("check = %v, %v; want a refusal of the version", out, err)
	}
}
