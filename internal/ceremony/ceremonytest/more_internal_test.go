package ceremonytest

import (
	"encoding/json"
	"strings"
	"testing"
)

var testSynth = synth{label: "C", pin: strings.Repeat("c", 64), seq: 3, end: strings.Repeat("e", 64)}

// A root list that More continues: it keeps every member of the list before, adds the new key at the
// end of roots, and sets the next sequence and the digest of the record before.
func TestNextListKeepsTheMembersAndAddsOneKey(t *testing.T) {
	prev := `{"expires_at":"2027-01-01T00:00:00Z","last_record_sha256":"` + strings.Repeat("d", 64) + `","pad":[1,2,{"x":"y"}],"roots":[{"label":"A","x509_spki_sha256":"` + strings.Repeat("a", 64) + `"},{"label":"B","x509_spki_sha256":"` + strings.Repeat("b", 64) + `"}],"sequence":2,"signed_at":"2026-12-01T00:00:00Z","version":1}`
	got := testSynth.nextList(t, []byte(prev))
	var v map[string]any
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatalf("%v in %s", err, got)
	}
	if v["sequence"] != float64(3) || v["last_record_sha256"] != testSynth.end || v["version"] != float64(1) || v["expires_at"] != "2027-01-01T00:00:00Z" {
		t.Errorf("members: %s", got)
	}
	roots, _ := v["roots"].([]any)
	if len(roots) != 3 {
		t.Fatalf("roots: %s", got)
	}
	last, _ := roots[2].(map[string]any)
	if last["label"] != "C" || last["x509_spki_sha256"] != testSynth.pin {
		t.Errorf("the new key: %v", last)
	}
	if first, _ := roots[0].(map[string]any); first["label"] != "A" {
		t.Errorf("the keys before are not kept in order: %v", roots)
	}
	if _, ok := v["pad"].([]any); !ok {
		t.Errorf("a member of the list before is gone: %s", got)
	}
	// A list with no roots gets one key.
	got = testSynth.nextList(t, []byte(`{"sequence":1,"version":1}`))
	if err := json.Unmarshal(got, &v); err != nil || len(v["roots"].([]any)) != 1 {
		t.Errorf("%v: %s", err, got)
	}
}

// What is not a root list of the form that ritueel writes fails the test, and never panics.
func TestNextListRefusesWhatIsNotAList(t *testing.T) {
	for name, prev := range map[string]string{
		"not JSON":         `{`,
		"empty":            ``,
		"an array":         `[]`,
		"a string":         `"x"`,
		"a number":         `5`,
		"a fraction":       `{"sequence":1.5,"roots":[]}`,
		"a number too big": `{"sequence":1e400,"roots":[]}`,
		"a fraction deep":  `{"roots":[{"a":[2.5]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			msg := failing(t, func(tb testing.TB) { testSynth.nextList(tb, []byte(prev)) })
			if msg == "" {
				t.Error("no message")
			}
		})
	}
	// A root list is a JSON object. The JSON value null decodes to a nil map, and a number, a list, a
	// string and a Boolean decode to no map at all: each fails the test with one sentence, and none
	// panics. The decoder reads the first value only, so bytes after it do not change the verdict.
	t.Run("a value that is not an object", func(t *testing.T) {
		for _, prev := range []string{`null`, ` null `, "\n\tnull", `null0`, `null{}`, `5`, `0`, `-1`, `1.5`, `[]`, `[{}]`, `[null]`, `"x"`, `""`, `true`, `false`, `[] {}`} {
			msg := failingOrNot(t, func(tb testing.TB) { testSynth.nextList(tb, []byte(prev)) })
			if !strings.Contains(msg, "not a JSON object") && !strings.Contains(msg, "cannot be read") {
				t.Errorf("%q: message %q", prev, msg)
			}
		}
		for _, prev := range []string{`null`, `5`, `[]`, `"x"`, `true`} {
			if msg := failingOrNot(t, func(tb testing.TB) { testSynth.nextList(tb, []byte(prev)) }); !strings.Contains(msg, "not a JSON object") {
				t.Errorf("%q: message %q: a value that decodes is not called an object", prev, msg)
			}
		}
	})
	// An object that holds nothing is a list that is made whole.
	t.Run("an empty object is a list", func(t *testing.T) {
		if msg := failingOrNot(t, func(tb testing.TB) { testSynth.nextList(tb, []byte(`{}`)) }); msg != "" {
			t.Errorf("message %q", msg)
		}
	})
}

// failingOrNot runs f with a testing.TB that records a failure; it returns the message, "" when f
// did not fail.
func failingOrNot(t *testing.T, f func(tb testing.TB)) string {
	t.Helper()
	ft := &failTB{TB: t}
	done := make(chan struct{})
	var panicked any
	go func() {
		defer close(done)
		defer func() { panicked = recover() }()
		f(ft)
	}()
	<-done
	if panicked != nil {
		t.Errorf("panic: %v", panicked)
	}
	return ft.msg
}

func TestIntegersTurnsNumbersIntoIntegers(t *testing.T) {
	var v any
	dec := json.NewDecoder(strings.NewReader(`{"a":1,"b":[2,{"c":3}],"d":"x","e":null,"f":true}`))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	got := integers(t, v).(map[string]any)
	if got["a"] != int64(1) || got["d"] != "x" || got["e"] != nil || got["f"] != true {
		t.Errorf("%v", got)
	}
	b := got["b"].([]any)
	if b[0] != int64(2) || b[1].(map[string]any)["c"] != int64(3) {
		t.Errorf("%v", b)
	}
	if msg := failing(t, func(tb testing.TB) { integers(tb, json.Number("1.5")) }); !strings.Contains(msg, "not an integer") {
		t.Errorf("message %q", msg)
	}
	if msg := failing(t, func(tb testing.TB) { integers(tb, []any{json.Number("9223372036854775808")}) }); !strings.Contains(msg, "not an integer") {
		t.Errorf("message %q", msg)
	}
}

// FuzzNextList: any bytes as the list before. A list that is accepted gives bytes that are JSON with
// the next sequence, the anchor and one more key, in canonical form (the same bytes again when they
// are read and written once more); one that is not accepted fails the test. Nothing panics.
func FuzzNextList(f *testing.F) {
	f.Add([]byte(`{"sequence":1,"version":1,"roots":[{"label":"A","x509_spki_sha256":"` + strings.Repeat("a", 64) + `"}]}`))
	f.Add([]byte(`{"roots":[],"sequence":1}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`7`))
	f.Add([]byte(`{`))
	f.Add([]byte(`{"roots":"x"}`))
	f.Add([]byte(`{"roots":[1,2,3],"sequence":2.5}`))
	f.Add([]byte(`{"a":{"b":{"c":[[[[1]]]]}},"roots":null}`))
	f.Add([]byte(`{"roots":[{"label":"é"}],"sequence":9007199254740993}`))
	f.Fuzz(func(t *testing.T, prev []byte) {
		if len(prev) > 1<<16 {
			t.Skip("large")
		}
		var out []byte
		msg := failingFuzz(t, func(tb testing.TB) { out = testSynth.nextList(tb, prev) })
		if msg != "" {
			return
		}
		var v map[string]any
		if err := json.Unmarshal(out, &v); err != nil {
			t.Fatalf("the list is no JSON object: %v: %q", err, out)
		}
		if v["sequence"] != float64(testSynth.seq) || v["last_record_sha256"] != testSynth.end {
			t.Fatalf("members: %q", out)
		}
		roots, _ := v["roots"].([]any)
		if len(roots) == 0 {
			t.Fatalf("no key in %q", out)
		}
		last, _ := roots[len(roots)-1].(map[string]any)
		if last["label"] != "C" || last["x509_spki_sha256"] != testSynth.pin {
			t.Fatalf("the new key is not last: %q", out)
		}
	})
}

// failingFuzz is failingOrNot for a fuzz target: a panic is a failure of the target.
func failingFuzz(t *testing.T, f func(tb testing.TB)) string {
	t.Helper()
	ft := &failTB{TB: t}
	done := make(chan struct{})
	var panicked any
	go func() {
		defer close(done)
		defer func() { panicked = recover() }()
		f(ft)
	}()
	<-done
	if panicked != nil {
		t.Fatalf("panic: %v", panicked)
	}
	return ft.msg
}
