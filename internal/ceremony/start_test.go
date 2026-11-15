package ceremony_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
)

func TestStartWritesTheAttemptFirstAndThenTheTwoEmptyJournals(t *testing.T) {
	b := newBundle(t)
	fl := newFlow(t, b, newSpec(name1, 1, ""))
	fl.must("plan")
	mark := b.r.mark()
	fl.must("start")
	var seen []string
	for _, e := range b.r.since(mark) {
		verb, path, _ := strings.Cut(e, " ")
		if verb == "rename" || verb == "create" {
			seen = append(seen, path)
		}
	}
	d := "history/" + name1 + "/"
	if got, want := strings.Join(seen, "|"), d+"attempt.json|"+d+"births.jsonl|"+d+"signatures.jsonl"; got != want {
		t.Errorf("Start made %s, want %s", got, want)
	}
	for _, j := range []string{"births.jsonl", "signatures.jsonl"} {
		if got := b.read("history", name1, j); len(got) != 0 {
			t.Errorf("%s is not empty at the start: %q", j, got)
		}
	}
	a, err := files.ReadAttempt(fl.file("attempt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Root != "A" || a.StartedAt != ts || a.Version != 1 {
		t.Errorf("attempt %+v", a)
	}
}

// A version of 0 is taken as 1: the attempt on the disk has the version 1.
func TestStartTakesAVersionOfZeroAsOne(t *testing.T) {
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	fl := newFlow(t, b, s)
	fl.must("plan")
	a := s.attempt(t, s.plan(t))
	a.Version = 0
	if _, err := fl.f.Start(a); err != nil {
		t.Fatal(err)
	}
	if got := fl.file("attempt.json"); !bytes.Contains(got, []byte(`"version":1`)) {
		t.Errorf("attempt.json is %s", got)
	}
}

func TestStartRefusesABadAttemptAndStaysPlanned(t *testing.T) {
	cases := []struct {
		name string
		edit func(a *files.Attempt)
	}{
		{"another version", func(a *files.Attempt) { a.Version = 2 }},
		{"a negative version", func(a *files.Attempt) { a.Version = -1 }},
		{"another ceremony", func(a *files.Attempt) { a.Ceremony = name2 }},
		{"no ceremony", func(a *files.Attempt) { a.Ceremony = "" }},
		{"the name in another case", func(a *files.Attempt) { a.Ceremony = strings.ToUpper(a.Ceremony) }},
		{"no plan digest", func(a *files.Attempt) { a.PlanSHA256 = "" }},
		{"another plan digest", func(a *files.Attempt) { a.PlanSHA256 = rep('9') }},
		{"the plan digest in capitals", func(a *files.Attempt) { a.PlanSHA256 = strings.ToUpper(a.PlanSHA256) }},
		{"a short plan digest", func(a *files.Attempt) { a.PlanSHA256 = a.PlanSHA256[:63] }},
		{"a start time with a fraction", func(a *files.Attempt) { a.StartedAt = "2026-11-14T10:00:00.5Z" }},
		{"a start time that is not a time", func(a *files.Attempt) { a.StartedAt = "soon" }},
		{"the zero attempt", func(a *files.Attempt) { *a = files.Attempt{} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newBundle(t)
			s := newSpec(name1, 1, "")
			fl := newFlow(t, b, s)
			fl.must("plan")
			a := s.attempt(t, s.plan(t))
			c.edit(&a)
			before, mark := tree(t, b.dir), b.r.mark()
			tr, err := fl.f.Start(a)
			if tr != nil {
				t.Error("Start returned a Trace with its error")
			}
			wantKind(t, err, ceremony.ErrInvalidInput)
			if errors.Is(err, ceremony.ErrFolderStopped) {
				t.Error("a refused attempt stopped the folder")
			}
			if got := b.r.since(mark); len(got) != 0 {
				t.Errorf("a refused attempt reached the file system: %v", got)
			}
			sameTree(t, "Start", before, tree(t, b.dir))
			// The folder is still planned: the right attempt is written next.
			if _, err := fl.f.Start(s.attempt(t, s.plan(t))); err != nil {
				t.Errorf("the right attempt after a refused one: %v", err)
			}
		})
	}
}

// The attempt names the plan that the folder holds, whichever way the folder got it.
func TestStartOfAnAdoptedFolderNamesTheAdoptedPlan(t *testing.T) {
	b, s, plan := planned(t)
	f, b2, err := adoptIn(t, b, name1, plan)
	if err != nil {
		t.Fatal(err)
	}
	a := s.attempt(t, plan)
	if _, err := f.Start(a); err != nil {
		t.Fatal(err)
	}
	got, err := files.ReadAttempt(b2.read("history", name1, "attempt.json"))
	if err != nil || got.PlanSHA256 != sum(plan) {
		t.Errorf("attempt %+v, %v", got, err)
	}
}
