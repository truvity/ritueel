package ceremony_test

import (
	"bytes"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/wanted"
)

// A plan that is hostile is refused by WritePlan and by Adopt before a write, and never makes a
// panic or a long run.
func TestAHostilePlanIsRefusedByWritePlanAndAdopt(t *testing.T) {
	s := newSpec(name1, 1, "")
	good := s.plan(t)
	swap := func(from, to string) []byte {
		if !bytes.Contains(good, []byte(from)) {
			t.Fatalf("the plan holds no %s", from)
		}
		return bytes.Replace(good, []byte(from), []byte(to), 1)
	}
	deep := []byte(`{"version":1,"ceremony":"` + name1 + `","command":"apply","trust_sequence":1,"arguments":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`)
	cases := map[string][]byte{
		"wanted that is a string":        swap(`"wanted":[`, `"wanted":"x","y":[`),
		"wanted of numbers":              []byte(`{"version":1,"ceremony":"` + name1 + `","command":"apply","trust_sequence":1,"wanted":[1,2]}`),
		"wanted with a path of a number": []byte(`{"version":1,"ceremony":"` + name1 + `","command":"apply","trust_sequence":1,"wanted":[{"path":1,"sha256":"x"}]}`),
		"a trust sequence that is text":  swap(`"trust_sequence":1`, `"trust_sequence":"1"`),
		"a trust sequence of a fraction": swap(`"trust_sequence":1`, `"trust_sequence":1.5`),
		"signatures that is an object":   swap(`"signatures":[`, `"signatures":{"a":[`+"1]}"+`,"b":[`),
		"a ceremony that is a number":    swap(`"ceremony":"`+name1+`"`, `"ceremony":1`),
		"a command that is not apply":    swap(`"command":"apply"`, `"command":"close"`),
		"a version that is text":         swap(`"version":1`, `"version":"1"`),
		"a version that is null":         swap(`"version":1`, `"version":null`),
		"a member twice":                 swap(`"version":1`, `"version":1,"version":1`),
		"nesting of 20,000 levels":       deep,
		"a byte order mark":              append([]byte("\xef\xbb\xbf"), good...),
		"bytes that are not UTF-8":       swap(`"made_at":"`, "\"made_at\":\"\xff\xfe"),
		"a null byte":                    append(append([]byte{}, good[:len(good)-1]...), 0, '}'),
		"a plan that is an array":        []byte(`[` + string(good) + `]`),
		"a plan that is a string":        []byte(`"x"`),
		"only a brace":                   []byte(`{`),
		"a plan of 300,000 bytes":        append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"pad":"`+strings.Repeat("x", 300000)+`"}`)...),
	}
	for name, plan := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			f, _ := ceremony.NewFolder(b.w, name1)
			before := tree(t, b.dir)
			wantKind(t, f.WritePlan(plan, s.copies), ceremony.ErrInvalidInput)
			wantKind(t, adoptErr(f, plan), ceremony.ErrInvalidInput)
			if got := b.r.snapshot(); len(got) != 0 {
				t.Errorf("a hostile plan reached the file system: %v", got)
			}
			sameTree(t, "a hostile plan", before, tree(t, b.dir))
		})
	}
}

// A hostile copy: size, a path of any kind, a path that is also a plan member.
func TestAHostileCopyIsRefused(t *testing.T) {
	s := newSpec(name1, 1, "")
	huge := make([]byte, 9<<20)
	cases := map[string][]wanted.File{
		"a copy over 8 MiB": {wantedFile("ritueel.yaml", "v"), {Path: "want/roots/x509.yaml", Data: huge}},
		"a nil copy list":   nil,
	}
	for name, copies := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			f, _ := ceremony.NewFolder(b.w, name1)
			plan := s.plan(t)
			if name == "a copy over 8 MiB" {
				plan = planFor(t, s, []wanted.File{wantedFile("ritueel.yaml", "v"), {Path: "want/roots/x509.yaml", Data: huge, SHA256: sum(huge)}})
			}
			err := f.WritePlan(plan, copies)
			wantKind(t, err, ceremony.ErrInvalidInput)
			if got := b.r.snapshot(); len(got) != 0 {
				t.Errorf("changes: %v", got)
			}
		})
	}
}
