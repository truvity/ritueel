package answer_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff/answer"
)

// The checks 1 and 2 of the requester: the version is read alone, and then result.json is read by the strict
// reader of the contract ("Messages and files", "Versioning", "The answer"). A fault of the form is malformed
// at check 2, and a version that cannot be read leaves check 1 not run.

const (
	malformedAt2   = "pfnnnnnnn" // the version was read and the files do not parse
	malformedNoVer = "nfnnnnnnn" // the version could not be read
	versionRefused = "fnnnnnnnn"
)

// resultOf is the control result file of an x509 case, as the JSON text.
func resultOf(t testing.TB, k *memKit) []byte {
	t.Helper()
	return k.newX509(nil).files()[answer.FileResult]
}

// x509WithResult makes the control case with the given bytes for result.json.
func (k *memKit) x509WithResult(raw []byte) *x509Case {
	c := k.newX509(nil)
	c.rawJSON = raw
	return c
}

func TestTheVersionIsReadAloneAndANumberOtherThanOneIsRefusedWithNothingElseRead(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	for _, c := range []struct {
		name string
		raw  string
		code answer.Code
		st   string
	}{
		{"2", `{"handoff":2}`, answer.CodeVersionUnsupported, versionRefused},
		{"2 with members of no kind", `{"handoff":2,"x":null,"y":[1,2,{"z":true}],"x":1}`, answer.CodeVersionUnsupported, versionRefused},
		{"0", `{"handoff":0,"type":"x509-intermediate"}`, answer.CodeVersionUnsupported, versionRefused},
		{"-1", `{"handoff":-1}`, answer.CodeVersionUnsupported, versionRefused},
		{"the largest safe integer", `{"handoff":9007199254740991}`, answer.CodeVersionUnsupported, versionRefused},
		{"a string", `{"handoff":"1"}`, answer.CodeMalformed, malformedNoVer},
		{"a fraction", `{"handoff":1.5}`, answer.CodeMalformed, malformedNoVer},
		{"one point nought", `{"handoff":1.0}`, answer.CodeMalformed, malformedNoVer},
		{"an exponent", `{"handoff":1e0}`, answer.CodeMalformed, malformedNoVer},
		{"absent", `{"type":"x509-intermediate"}`, answer.CodeMalformed, malformedNoVer},
		{"twice", `{"handoff":1,"handoff":1}`, answer.CodeMalformed, malformedNoVer},
		{"null", `{"handoff":null}`, answer.CodeMalformed, malformedNoVer},
		{"outside the safe range", `{"handoff":9007199254740992}`, answer.CodeMalformed, malformedNoVer},
		{"not an object", `[]`, answer.CodeMalformed, malformedNoVer},
		{"empty", ``, answer.CodeMalformed, malformedNoVer},
		{"text", `handoff`, answer.CodeMalformed, malformedNoVer},
		{"a byte order mark", "\xef\xbb\xbf" + string(resultOf(t, k)), answer.CodeMalformed, malformedNoVer},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, err := k.x509WithResult([]byte(c.raw)).check(chk)
			if err != nil {
				t.Fatal(err)
			}
			if v.Code != c.code || statuses(v) != c.st || v.Accepted() {
				t.Fatalf("code %q statuses %s detail %q; want %q and %s", v.Code, statuses(v), v.Detail, c.code, c.st)
			}
			if c.st == malformedNoVer && v.Checks[0].Reason != "the version could not be read" {
				t.Errorf("check 1 is not run and says %q", v.Checks[0].Reason)
			}
		})
	}
}

// A result file that carries version 1 and then breaks the form of the page is malformed at check 2. Each case
// changes the control in one place.
func TestAResultFileThatBreaksTheFormOfThePageIsMalformedAtCheckTwo(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	control := string(resultOf(t, k))
	var m map[string]any
	if err := json.Unmarshal([]byte(control), &m); err != nil {
		t.Fatal(err)
	}
	edit := func(f func(m map[string]any)) func(*x509Case) {
		return func(c *x509Case) { c.with(f) }
	}
	raw := func(f func(s string) string) func(*x509Case) {
		return func(c *x509Case) { c.rawJSON = []byte(f(control)) }
	}
	valid := "2026-11-15T12:00:00Z"
	good64 := strings.Repeat("a", 64)
	for _, c := range []struct {
		name string
		mod  func(*x509Case)
	}{
		{"a member twice", raw(func(s string) string {
			return strings.Replace(s, `"outcome":"issued"`, `"outcome":"issued","outcome":"issued"`, 1)
		})},
		{"an unknown member", edit(func(m map[string]any) { m["extra"] = 1 })},
		{"an unknown member of an artifact", edit(func(m map[string]any) {
			m["artifacts"] = []map[string]any{{"name": "example-answer.cert.pem", "sha256": good64, "size": 1}}
		})},
		{"a null member", edit(func(m map[string]any) { m["valid_until"] = nil })},
		{"a null artifact name", raw(func(s string) string { return strings.Replace(s, `"name":"example-answer.cert.pem"`, `"name":null`, 1) })},
		{"an integer outside the safe range", edit(func(m map[string]any) { m["trust_sequence"] = json.Number("9007199254740992") })},
		{"a trust sequence of zero", edit(func(m map[string]any) { m["trust_sequence"] = 0 })},
		{"a negative trust sequence", edit(func(m map[string]any) { m["trust_sequence"] = -7 })},
		{"a trust sequence that is a string", edit(func(m map[string]any) { m["trust_sequence"] = "7" })},
		{"a trust sequence with a fraction", edit(func(m map[string]any) { m["trust_sequence"] = json.Number("7.5") })},
		{"no trust sequence", edit(func(m map[string]any) { delete(m, "trust_sequence") })},
		{"no type", edit(func(m map[string]any) { delete(m, "type") })},
		{"no request digest", edit(func(m map[string]any) { delete(m, "request_sha256") })},
		{"no outcome", edit(func(m map[string]any) { delete(m, "outcome") })},
		{"no artifacts", edit(func(m map[string]any) { delete(m, "artifacts") })},
		{"no valid_from", edit(func(m map[string]any) { delete(m, "valid_from") })},
		{"no valid_until", edit(func(m map[string]any) { delete(m, "valid_until") })},
		{"no issuer", edit(func(m map[string]any) { delete(m, "issuer") })},
		{"a time with a fraction", edit(func(m map[string]any) { m["valid_from"] = "2026-11-15T12:00:00.5Z" })},
		{"a time with a zone", edit(func(m map[string]any) { m["valid_from"] = "2026-11-15T12:00:00+00:00" })},
		{"a time in lower case", edit(func(m map[string]any) { m["valid_from"] = "2026-11-15t12:00:00z" })},
		{"a time with a space", edit(func(m map[string]any) { m["valid_from"] = "2026-11-15 12:00:00Z" })},
		{"a date only", edit(func(m map[string]any) { m["valid_until"] = "2027-12-15" })},
		{"a time that is not a date", edit(func(m map[string]any) { m["valid_until"] = "2027-02-30T12:00:00Z" })},
		{"a time of a leap second", edit(func(m map[string]any) { m["valid_until"] = "2027-12-15T12:00:60Z" })},
		{"a time that is a number", edit(func(m map[string]any) { m["valid_until"] = 1800000000 })},
		{"a digest in capitals", edit(func(m map[string]any) { m["request_sha256"] = strings.ToUpper(good64) })},
		{"a digest of 63 digits", edit(func(m map[string]any) { m["request_sha256"] = good64[:63] })},
		{"a digest of 65 digits", edit(func(m map[string]any) { m["request_sha256"] = good64 + "a" })},
		{"a digest that is not hexadecimal", edit(func(m map[string]any) { m["request_sha256"] = strings.Repeat("g", 64) })},
		{"a pin of 63 digits", edit(func(m map[string]any) { m["issuer"] = good64[:63] })},
		{"a pin in capitals", edit(func(m map[string]any) { m["issuer"] = strings.ToUpper(k.a.pin) })},
		{"an issuer of 40 digits for X.509", edit(func(m map[string]any) { m["issuer"] = good64[:40] })},
		{"an outcome that is done", edit(func(m map[string]any) { m["outcome"] = "done" })},
		{"an outcome in capitals", edit(func(m map[string]any) { m["outcome"] = "Issued" })},
		{"a type that is unknown", edit(func(m map[string]any) { m["type"] = "x509" })},
		{"reasons in an issued answer", edit(func(m map[string]any) { m["reasons"] = []string{"policy"} })},
		{"an empty list of reasons in an issued answer", edit(func(m map[string]any) { m["reasons"] = []string{} })},
		{"no artifacts: a list that is not a list", edit(func(m map[string]any) { m["artifacts"] = "x" })},
		{"five artifacts", edit(func(m map[string]any) {
			var l []map[string]any
			for _, n := range []string{"a", "b", "c", "d", "e"} {
				l = append(l, map[string]any{"name": n + ".pem", "sha256": good64})
			}
			m["artifacts"] = l
		})},
		{"an artifact that is not an object", edit(func(m map[string]any) { m["artifacts"] = []any{"example-answer.cert.pem"} })},
		{"an artifact with no name", edit(func(m map[string]any) { m["artifacts"] = []any{map[string]any{"sha256": good64}} })},
		{"an artifact with no digest", edit(func(m map[string]any) { m["artifacts"] = []any{map[string]any{"name": "a.pem"}} })},
		{"an artifact name with a path", edit(func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "a/example-answer.cert.pem", "sha256": good64}}
		})},
		{"an artifact name with a space", edit(func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "example answer.cert.pem", "sha256": good64}}
		})},
		{"an artifact name that is not ASCII", edit(func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "example-answer.cert.pém", "sha256": good64}}
		})},
		{"an artifact name that is empty", edit(func(m map[string]any) { m["artifacts"] = []any{map[string]any{"name": "", "sha256": good64}} })},
		{"an artifact name of 256 characters", edit(func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": strings.Repeat("a", 252) + ".pem", "sha256": good64}}
		})},
		{"an artifact name that is a dot", edit(func(m map[string]any) { m["artifacts"] = []any{map[string]any{"name": "..", "sha256": good64}} })},
		{"an artifact digest in capitals", edit(func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "example-answer.cert.pem", "sha256": strings.ToUpper(good64)}}
		})},
		{"a time that is valid in time but not as text", edit(func(m map[string]any) { m["valid_from"] = valid + " " })},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newX509(nil)
			c.mod(x)
			v, err := x.check(chk)
			want(t, v, err, answer.CodeMalformed, malformedAt2)
		})
	}
	_ = m
}

// A result file that is not one JSON object at all has no readable version: it is malformed and check 1 is not run.
func TestAResultFileThatIsNotJSONHasNoReadableVersion(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	control := string(resultOf(t, k))
	raw := func(f func(s string) string) func(*x509Case) {
		return func(c *x509Case) { c.rawJSON = []byte(f(control)) }
	}
	for _, c := range []struct {
		name string
		mod  func(*x509Case)
	}{
		{"a string that is not UTF-8", raw(func(s string) string {
			return strings.Replace(s, `"type":"x509-intermediate"`, "\"type\":\"x509-\xff\xfe\"", 1)
		})},
		{"a control character in a string", raw(func(s string) string {
			return strings.Replace(s, `"outcome":"issued"`, "\"outcome\":\"iss\x01ued\"", 1)
		})},
		{"nothing but an object after it", raw(func(s string) string { return s + "{}" })},
		{"text after it", raw(func(s string) string { return s + " x" })},
		{"a trailing comma", raw(func(s string) string { return strings.TrimSuffix(s, "}") + ",}" })},
		{"a single quote", raw(func(s string) string { return strings.ReplaceAll(s, `"`, "'") })},
		{"a comment", raw(func(s string) string { return "/* x */" + s })},
		{"nothing valid", raw(func(s string) string { return `{"handoff":1` })},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newX509(nil)
			c.mod(x)
			v, err := x.check(chk)
			want(t, v, err, answer.CodeMalformed, malformedNoVer)
		})
	}
}

// An answer whose result.json is exactly 256 KiB is read, and one byte more is refused before it is read.
func TestTheLimitOfAResultFileIsTwoHundredFiftySixKiB(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	control := resultOf(t, k)
	pad := func(n int) []byte { return pad2(control, n) }
	t.Run("exactly the limit", func(t *testing.T) {
		x := k.newX509(nil)
		x.rawJSON = pad2(x.files()[answer.FileResult], answer.MaxFileSize)
		v, err := x.check(chk)
		want(t, v, err, "", "ppppppppp")
	})
	t.Run("one byte more", func(t *testing.T) {
		v, err := k.x509WithResult(pad(answer.MaxFileSize + 1)).check(chk)
		want(t, v, err, answer.CodeMalformed, malformedNoVer)
		if !strings.Contains(v.Detail, "longer than 262144 bytes") {
			t.Errorf("detail %q: a file over the limit is refused for its size before it is read", v.Detail)
		}
	})
	t.Run("a great file of zeros", func(t *testing.T) {
		v, err := k.x509WithResult(make([]byte, 4*answer.MaxFileSize)).check(chk)
		want(t, v, err, answer.CodeMalformed, malformedNoVer)
	})
}

// A hostile result file never crashes the reader and is refused: nesting past any limit in a member that
// the page does not define, or in one that it does, and a great list of reasons or artifacts.
func TestHostileResultFilesAreRefusedAndNeverCrash(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	control := string(resultOf(t, k))
	deep := func(n int, open, shut string) string { return strings.Repeat(open, n) + strings.Repeat(shut, n) }
	for _, c := range []struct {
		name string
		raw  string
	}{
		{"a nest in an unknown member", strings.Replace(control, `"handoff":1`, `"handoff":1,"x":`+deep(100000, "[", "]"), 1)},
		{"a nest of objects in an unknown member", strings.Replace(control, `"handoff":1`, `"handoff":1,"x":`+deep(40000, `{"a":`, "}")+"1", 1)},
		{"a nest where a list is wanted", strings.Replace(control, `"handoff":1`, `"handoff":1,"artifacts":`+deep(100000, "[", "]"), 1)},
		{"a nest past the depth that the page allows", strings.Replace(control, `"handoff":1`, `"handoff":1,"x":`+deep(10001, "[", "]"), 1)},
		{"a great list of artifacts", strings.Replace(control, `"artifacts":[`, `"artifacts":[`+strings.Repeat(`{"name":"a.pem","sha256":"`+strings.Repeat("a", 64)+`"},`, 3000), 1)},
		{"a great list of empty artifacts", strings.Replace(control, `"artifacts":[`, `"artifacts":[`+strings.Repeat(`{},`, 60000), 1)},
		{"a great string", strings.Replace(control, `"type":"x509-intermediate"`, `"type":"`+strings.Repeat("a", 250000)+`"`, 1)},
		{"a great number", strings.Replace(control, `"trust_sequence":7`, `"trust_sequence":`+strings.Repeat("9", 250000), 1)},
		{"a great number of members", `{"handoff":1,` + strings.Repeat(`"a":1,`, 40000) + `"b":1}`},
		{"a lone surrogate", strings.Replace(control, `"type":"x509-intermediate"`, `"type":"\ud800"`, 1)},
		{"a null byte", strings.Replace(control, `"outcome":"issued"`, "\"outcome\":\"issued\x00\"", 1)},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, err := k.x509WithResult([]byte(c.raw)).check(chk)
			if err != nil {
				t.Fatalf("Check returned %v", err)
			}
			if v.Accepted() || v.Code != answer.CodeMalformed {
				t.Fatalf("code %q, accepted %v, detail %q", v.Code, v.Accepted(), v.Detail)
			}
		})
	}
}

// A detail of a refusal never holds a byte of the answer: the words are fixed.
func TestTheDetailOfAMalformedResultHoldsNoByteOfTheFile(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	marker := "ZZMARKERZZ"
	for _, name := range []string{"type", "outcome", "issuer", "request_sha256", "valid_from"} {
		x := k.newX509(nil)
		x.with(func(m map[string]any) { m[name] = marker })
		v, err := x.check(chk)
		if err != nil || v.Code != answer.CodeMalformed {
			t.Fatalf("%s: %v %q", name, err, v.Code)
		}
		if strings.Contains(v.Detail, marker) {
			t.Errorf("%s: the detail %q holds the text of the file", name, v.Detail)
		}
	}
	x := k.newX509(nil)
	x.with(func(m map[string]any) {
		m["artifacts"] = []any{map[string]any{"name": marker + "/x", "sha256": strings.Repeat("a", 64)}}
	})
	v, _ := x.check(chk)
	if strings.Contains(v.Detail, marker) {
		t.Errorf("the detail %q holds a name of an artifact", v.Detail)
	}
}

// pad2 pads a JSON text with spaces, which the format allows, up to n bytes.
func pad2(text []byte, n int) []byte {
	return append(bytes.Clone(text), bytes.Repeat([]byte(" "), n-len(text))...)
}
