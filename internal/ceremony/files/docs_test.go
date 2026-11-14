package files_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// The documents of these tests are built from plain maps and written with the standard encoder, so
// that a fault shared by the writer and the reader of the package under test cannot hide: the
// bytes do not come from Canonical.

// dg is a digest of 64 copies of one hexadecimal character.
func dg(c byte) string { return strings.Repeat(string(c), 64) }

// ref is one entry of a list of files.
func ref(path string, c byte) map[string]any {
	return map[string]any{"path": path, "sha256": dg(c)}
}

// applyDoc is a record of the command apply with only the members that check history requires.
func applyDoc() map[string]any {
	return map[string]any{
		"version":            1,
		"ceremony":           "20261114T100000Z-apply",
		"command":            "apply",
		"outcome":            "completed",
		"plan_sha256":        dg('1'),
		"prev_record_sha256": dg('2'),
		"transcript_sha256":  dg('3'),
		"wanted":             []any{ref("ritueel.yaml", '4')},
		"artifacts":          []any{ref("trust/1-3fa9c1d2/root-list.json", '5')},
	}
}

// closeDoc is a closing record.
func closeDoc() map[string]any {
	return map[string]any{
		"version":            1,
		"ceremony":           "20261114T110000Z-close",
		"command":            "close",
		"outcome":            "closed",
		"prev_record_sha256": dg('2'),
		"transcript_sha256":  dg('3'),
		"artifacts":          []any{},
		"closes": map[string]any{
			"ceremony":       "20261114T100000Z-apply",
			"attempt_sha256": dg('6'),
			"reason":         "the card was lost",
		},
	}
}

// declineDoc is the record of a ceremony in which the person declined.
func declineDoc() map[string]any {
	m := applyDoc()
	m["outcome"] = "declined"
	m["declined"] = map[string]any{"stem": "alice", "reason": "not today"}
	return m
}

func attemptDoc() map[string]any {
	return map[string]any{
		"version":     1,
		"ceremony":    "20261114T100000Z-apply",
		"plan_sha256": dg('1'),
		"root":        "root-a",
		"started_at":  "2026-11-14T10:00:00Z",
	}
}

func planDoc() map[string]any {
	return map[string]any{
		"version":            1,
		"ceremony":           "20261114T100000Z-apply",
		"command":            "apply",
		"trust_sequence":     3,
		"made_at":            "2026-11-14T09:00:00Z",
		"ceremony_time":      "2026-11-14T10:00:00Z",
		"wanted":             []any{ref("ritueel.yaml", '4')},
		"inputs":             []any{ref("requests/alice/alice.csr", '7')},
		"last_record_sha256": dg('2'),
	}
}

// encode writes a map with the standard encoder after edit changed it.
func encode(t testing.TB, m map[string]any, edit func(map[string]any)) []byte {
	t.Helper()
	if edit != nil {
		edit(m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

// without removes members.
func without(names ...string) func(map[string]any) {
	return func(m map[string]any) {
		for _, n := range names {
			delete(m, n)
		}
	}
}

// set sets a member.
func set(name string, v any) func(map[string]any) {
	return func(m map[string]any) { m[name] = v }
}

// setIn sets a member of a member that is an object.
func setIn(outer, name string, v any) func(map[string]any) {
	return func(m map[string]any) { m[outer].(map[string]any)[name] = v }
}

// setEntry sets a member of one entry of a list of files.
func setEntry(list string, i int, name string, v any) func(map[string]any) {
	return func(m map[string]any) { m[list].([]any)[i].(map[string]any)[name] = v }
}

// delEntry removes a member of one entry of a list of files.
func delEntry(list string, i int, name string) func(map[string]any) {
	return func(m map[string]any) { delete(m[list].([]any)[i].(map[string]any), name) }
}

// pad returns a JSON object of exactly n bytes with the member "arguments" that holds a string.
func padArguments(t testing.TB, base map[string]any, n int) []byte {
	t.Helper()
	probe := encode(t, cloneMap(base), set("arguments", map[string]any{"pad": ""}))
	if len(probe) > n {
		t.Fatalf("padArguments: the document is %d bytes without padding, more than %d", len(probe), n)
	}
	b := encode(t, cloneMap(base), set("arguments", map[string]any{"pad": strings.Repeat("x", n-len(probe))}))
	if len(b) != n {
		t.Fatalf("padArguments made %d bytes, want %d", len(b), n)
	}
	return b
}

func cloneMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}
