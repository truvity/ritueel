package trustset

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/strictjson"
)

// The two name methods give the empty text when SetName refuses: a forged Draft or Set whose number
// is out of range or whose digest is not 64 lower-case hexadecimal digits gives no name and no panic.
func TestNameOfAForgedDraftAndSet(t *testing.T) {
	f := newIFixture(t)
	for name, mutate := range map[string]func(*Draft){
		"sequence 0":                 func(d *Draft) { d.sequence = 0 },
		"sequence below 0":           func(d *Draft) { d.sequence = -1 },
		"sequence above the safe":    func(d *Draft) { d.sequence = strictjson.MaxSafeInt + 1 },
		"digest of the wrong length": func(d *Draft) { d.listSHA = d.listSHA[:63] },
		"digest in upper case":       func(d *Draft) { d.listSHA = strings.ToUpper(d.listSHA) },
		"no digest":                  func(d *Draft) { d.listSHA = "" },
		"kind 0":                     func(d *Draft) { d.kind = 0 },
		"kind 6":                     func(d *Draft) { d.kind = 6 },
		"no list":                    func(d *Draft) { d.listJSON = nil },
		"no CA bundle":               func(d *Draft) { d.caBundle = nil },
	} {
		d := *f.second
		if d.SetName() == "" {
			t.Fatal("the good draft has no name")
		}
		mutate(&d)
		if got := d.SetName(); got != "" {
			t.Errorf("%s: name %q", name, got)
		}
	}
	good := *f.secondS
	if good.Name() == "" {
		t.Fatal("the good set has no name")
	}
	for name, mutate := range map[string]func(*Set){
		"sequence 0":              func(s *Set) { s.sequence = 0 },
		"sequence above the safe": func(s *Set) { s.sequence = strictjson.MaxSafeInt + 1 },
		"no list":                 func(s *Set) { s.listJSON = nil },
		"no jws":                  func(s *Set) { s.listJWS = nil },
		"no CA":                   func(s *Set) { s.caBundle = nil },
	} {
		s := good
		mutate(&s)
		if got := s.Name(); got != "" {
			t.Errorf("%s: name %q", name, got)
		}
	}
	// The name of the set is the name of its list file, not of the list that the draft kept.
	s := good
	s.listJSON = append(append([]byte{}, s.listJSON...), ' ')
	if s.Name() == good.Name() {
		t.Error("the name of a set does not depend on its list file")
	}
}

// Both methods are the one function SetName: the same number and digest give the same text.
func TestTheMethodsAreTheFunction(t *testing.T) {
	f := newIFixture(t)
	want, err := SetName(f.second.sequence, hexSHA256(f.second.listJSON))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.second.SetName(); got != want {
		t.Errorf("Draft.SetName = %q, want %q", got, want)
	}
	if got := f.secondS.Name(); got != want {
		t.Errorf("Set.Name = %q, want %q", got, want)
	}
}
