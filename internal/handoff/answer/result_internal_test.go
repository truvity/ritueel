package answer

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// The reader of a result file, read directly. These are tests of the package, in its own scope, for the parts
// that no exported call shows alone.

func goodResult(t testing.TB) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"handoff": 1, "type": "x509-intermediate", "request_sha256": strings.Repeat("a", 64), "outcome": "issued",
		"artifacts":  []map[string]any{{"name": "a.cert.pem", "sha256": strings.Repeat("b", 64)}},
		"valid_from": "2026-11-15T12:00:00Z", "valid_until": "2027-12-15T12:00:00Z",
		"issuer": strings.Repeat("c", 64), "trust_sequence": 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReadResultReadsAGoodFileIntoItsFields(t *testing.T) {
	res, err := readResult(goodResult(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.typ != handoff.TypeX509 || res.outcome != outcomeIssued || res.trustSequence != 7 || len(res.artifacts) != 1 || res.artifacts[0].name != "a.cert.pem" {
		t.Errorf("result %+v", res)
	}
	if res.validFrom.Format(timeLayout) != "2026-11-15T12:00:00Z" || res.validUntil.Format(timeLayout) != "2027-12-15T12:00:00Z" || res.issuer != strings.Repeat("c", 64) {
		t.Errorf("result %+v", res)
	}
}

const timeLayout = "2006-01-02T15:04:05Z"

func TestAShapeErrorHoldsNoByteOfTheFile(t *testing.T) {
	for _, bad := range []string{
		`{"handoff":1,"type":"ZZZ"}`, `{"handoff":2}`, `x`, ``,
		strings.Replace(string(goodResult(t)), `"outcome":"issued"`, `"outcome":"ZZZ"`, 1),
		strings.Replace(string(goodResult(t)), `"issuer"`, `"ZZZ"`, 1),
	} {
		_, err := readResult([]byte(bad))
		var s shapeError
		if !errors.As(err, &s) {
			t.Fatalf("%q: error %v is not a shape error", bad, err)
		}
		if strings.Contains(err.Error(), "ZZZ") {
			t.Errorf("the error %q holds a byte of the file", err)
		}
	}
}

func TestReadTimeReadsTheOneFormOfThePageAndNothingElse(t *testing.T) {
	if _, ok := readTime("2026-11-15T12:00:00Z"); !ok {
		t.Fatal("the form of the page is refused")
	}
	for _, s := range []string{"", "2026-11-15T12:00:00", "2026-11-15T12:00:00z", "2026-11-15T12:00:00.0Z", "2026-11-15t12:00:00Z",
		"2026-11-15T12:00:00+00:00", "2026-11-15T12:00:00-00:00", "2026-11-15T14:00:00+02:00", "2026-11-15T24:00:00Z", "2026-02-30T12:00:00Z",
		" 2026-11-15T12:00:00Z", "2026-11-15T12:00:00Z ", "2026-1-15T12:00:00Z", "26-11-15T12:00:00Z", "+2026-11-15T12:00:00Z",
		"2026-11-15T12:00:60Z", "2026-11-15T12:00:00Z\x00", "２０２６-11-15T12:00:00Z"} {
		if _, ok := readTime(s); ok {
			t.Errorf("%q is read as a time", s)
		}
	}
}

func TestLowerHexIsExactlyNLowerCaseDigits(t *testing.T) {
	for _, c := range []struct {
		s    string
		n    int
		want bool
	}{
		{"", 0, true}, {"a", 1, true}, {"0123456789abcdef", 16, true}, {"A", 1, false}, {"g", 1, false}, {"aa", 1, false}, {"a", 2, false},
		{"é", 2, false}, {" a", 2, false}, {"a\n", 2, false}, {"/", 1, false}, {":", 1, false}, {"`", 1, false}, {"@", 1, false},
	} {
		if got := lowerHex(c.s, c.n); got != c.want {
			t.Errorf("lowerHex(%q, %d) = %v", c.s, c.n, got)
		}
	}
}

func TestPeekVersionAgreesWithTheReaderOnWhatIsReadable(t *testing.T) {
	for _, c := range []struct {
		file string
		want int64
		ok   bool
	}{
		{`{"handoff":1}`, 1, true}, {`{"handoff":2,"x":[1]}`, 2, true}, {`{"handoff":-1}`, -1, true},
		{`{"handoff":"1"}`, 0, false}, {`{}`, 0, false}, {`[]`, 0, false}, {``, 0, false}, {`{"handoff":1,"handoff":1}`, 0, false},
		{`{"handoff":1.5}`, 0, false}, {`{"handoff":null}`, 0, false},
	} {
		n, err := peekVersion([]byte(c.file))
		if (err == nil) != c.ok || (c.ok && n != c.want) {
			t.Errorf("%s: %d, %v", c.file, n, err)
		}
	}
}

func FuzzReadResult(f *testing.F) {
	f.Add(goodResult(f))
	f.Add([]byte(`{"handoff":1,"type":"openpgp-subkey","request_sha256":"` + strings.Repeat("a", 64) + `","outcome":"refused","reasons":["policy"],"trust_sequence":1}`))
	f.Add([]byte(`{"handoff":2}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := readResult(data)
		if err != nil {
			if res != nil {
				t.Fatal("a result comes with an error")
			}
			var s shapeError
			if !errors.As(err, &s) && !errors.Is(err, ErrInternal) {
				t.Fatalf("an error of no kind: %v", err)
			}
			if errors.Is(err, ErrInternal) {
				t.Fatalf("the strict reader and the reader of the shape disagree: %v", err)
			}
			return
		}
		if len(data) > MaxFileSize {
			t.Fatal("a file over the limit is read")
		}
		// A result that is read is a result that encoding/json reads to the same values.
		var w struct {
			Handoff       int64    `json:"handoff"`
			Type          string   `json:"type"`
			RequestSHA256 string   `json:"request_sha256"`
			Outcome       string   `json:"outcome"`
			Reasons       []string `json:"reasons"`
			TrustSequence int64    `json:"trust_sequence"`
			Artifacts     []struct {
				Name   string `json:"name"`
				SHA256 string `json:"sha256"`
			} `json:"artifacts"`
		}
		if err := json.Unmarshal(data, &w); err != nil {
			t.Fatalf("the strict reader reads what encoding/json refuses: %v", err)
		}
		if w.Handoff != 1 || string(res.typ) != w.Type || res.requestSHA256 != w.RequestSHA256 || res.outcome != w.Outcome || res.trustSequence != w.TrustSequence {
			t.Fatalf("the readers differ: %+v and %+v", res, w)
		}
		if len(res.reasons) != len(w.Reasons) || len(res.artifacts) != len(w.Artifacts) {
			t.Fatalf("the lists differ: %+v and %+v", res, w)
		}
		for i, a := range res.artifacts {
			if a.name != w.Artifacts[i].Name || a.sha256 != w.Artifacts[i].SHA256 {
				t.Fatalf("artifact %d differs", i)
			}
		}
		if len(res.artifacts) > MaxArtifacts || len(res.reasons) > MaxReasons {
			t.Fatalf("the bounds are passed: %d artifacts, %d reasons", len(res.artifacts), len(res.reasons))
		}
		if res.trustSequence < 1 || !lowerHex(res.requestSHA256, 64) {
			t.Fatalf("result %+v", res)
		}
		if res.outcome == outcomeIssued && (res.validFrom.IsZero() || (res.typ != handoff.TypeSSH && res.validUntil.IsZero())) {
			t.Fatalf("an issued result without its dates: %+v", res)
		}
	})
}

// The shape of an answer to an ssh-ca-key request is read although no check of it is built: it has valid_from
// only and no artifact ("The answer").
func TestReadResultReadsTheShapeOfAnSSHAnswer(t *testing.T) {
	ssh := func(change func(m map[string]any)) []byte {
		m := map[string]any{
			"handoff": 1, "type": "ssh-ca-key", "request_sha256": strings.Repeat("a", 64), "outcome": "issued",
			"artifacts": []any{}, "valid_from": "2026-11-15T12:00:00Z", "issuer": strings.Repeat("c", 64), "trust_sequence": 7,
		}
		if change != nil {
			change(m)
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	res, err := readResult(ssh(nil))
	if err != nil || res.typ != handoff.TypeSSH || !res.validUntil.IsZero() || len(res.artifacts) != 0 || res.issuer != strings.Repeat("c", 64) {
		t.Fatalf("%+v, %v", res, err)
	}
	for name, change := range map[string]func(m map[string]any){
		"a valid_until": func(m map[string]any) { m["valid_until"] = "2027-12-15T12:00:00Z" },
		"an artifact": func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "a.pem", "sha256": strings.Repeat("a", 64)}}
		},
		"no artifacts member":    func(m map[string]any) { delete(m, "artifacts") },
		"no valid_from":          func(m map[string]any) { delete(m, "valid_from") },
		"an issuer of 40 digits": func(m map[string]any) { m["issuer"] = strings.Repeat("c", 40) },
	} {
		if _, err := readResult(ssh(change)); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	// The OpenPGP shape takes an issuer of 40 digits and refuses one of 64.
	pgp := func(issuer string) error {
		m := map[string]any{
			"handoff": 1, "type": "openpgp-subkey", "request_sha256": strings.Repeat("a", 64), "outcome": "issued",
			"artifacts": []any{}, "valid_from": "2026-11-15T12:00:00Z", "valid_until": "2027-12-15T12:00:00Z", "issuer": issuer, "trust_sequence": 7,
		}
		b, _ := json.Marshal(m)
		_, err := readResult(b)
		return err
	}
	if err := pgp(strings.Repeat("c", 40)); err != nil {
		t.Errorf("an OpenPGP issuer of 40 digits: %v", err)
	}
	if err := pgp(strings.Repeat("c", 64)); err == nil {
		t.Error("an OpenPGP issuer of 64 digits is read")
	}
	if err := pgp(strings.Repeat("c", 39)); err == nil {
		t.Error("an OpenPGP issuer of 39 digits is read")
	}
}
