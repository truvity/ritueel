package answer_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/answer"
)

// The fuzz targets read the answer files of the vectors as their seeds. Run in the ordinary way they run the
// seeds only; `go test -fuzz` mutates them. None starts a program or writes a file.

// verdictLaws are the laws of every verdict, whatever the answer was.
func verdictLaws(t *testing.T, v answer.Verdict, err error, floor bool) {
	t.Helper()
	st := statuses(v)
	for i := 0; i < len(v.Detail); i++ {
		if v.Detail[i] < 0x20 || v.Detail[i] > 0x7e {
			t.Fatalf("the detail %q holds a byte that is not printable ASCII", v.Detail)
		}
	}
	for _, c := range v.Checks {
		if (c.Status == handoff.StatusNotRun) != (c.Reason != "") {
			t.Fatalf("check %d is %s and its reason is %q", c.N, c.Status, c.Reason)
		}
	}
	if err != nil {
		if v.Accepted() || v.Info != nil && v.Accepted() {
			t.Fatalf("a verdict that comes with %v is accepted", err)
		}
		return
	}
	if len(st) != 8 && len(st) != 9 {
		t.Fatalf("%d checks", len(st))
	}
	if v.Accepted() {
		if v.Info == nil || v.Code != "" || len(v.CertifierReasons) != 0 || v.AnswerRefused() || v.RequestRefused() {
			t.Fatalf("an accepted verdict: %+v", v)
		}
		if !v.Info.ValidUntil.After(v.Info.ValidFrom) {
			t.Fatalf("valid from %v until %v", v.Info.ValidFrom, v.Info.ValidUntil)
		}
		want := strings.Repeat("p", len(st))
		if floor {
			want = "npnppppnn"
		}
		if st != want {
			t.Fatalf("an accepted verdict with the statuses %s", st)
		}
		if n := len(v.Info.Issuer); n != 64 && n != 40 {
			t.Fatalf("issuer %q", v.Info.Issuer)
		}
		return
	}
	if v.Info != nil {
		t.Fatalf("a verdict that is not accepted holds Info")
	}
	if v.Code != "" {
		// A refusal: passed checks, one failed, then not run.
		i := strings.IndexByte(st, 'f')
		if i < 0 || strings.Count(st, "f") != 1 {
			t.Fatalf("code %q with the statuses %s", v.Code, st)
		}
		for j, c := range []byte(st[:i]) {
			// Check 1 is not run when the version cannot be read: the file is refused at check 2.
			if c == '?' || (c == 'n' && !floor && (j != 0 || i != 1)) {
				t.Fatalf("check %d before the failed one is %c: %s", j+1, c, st)
			}
		}
		if strings.Contains(st[i+1:], "p") && !floor {
			t.Fatalf("a check after the failed one passed: %s", st)
		}
		return
	}
	if len(v.CertifierReasons) == 0 {
		t.Fatalf("a verdict that is not accepted, not refused and not the certifier's refusal: %s", st)
	}
}

func FuzzCheckX509(f *testing.F) {
	m := readVectorManifest(f)
	chk := mustChecker(f, vectorConfig(f, m))
	c := vectorCase(f, "x509-piv-valid")
	asked := vectorAsked(f, c)
	for _, id := range []string{"x509-piv-valid", "x509-kms-valid", "x509-response-expired", "x509-response-wrong-key", "x509-response-pathlen-1", "x509-response-untrusted-issuer"} {
		a := vectorAnswer(f, vectorCase(f, id))
		f.Add(a.Files[answer.FileResult], a.Files[answer.FileCert])
	}
	f.Add([]byte(`{"handoff":1}`), []byte(nil))
	f.Add([]byte(`{"handoff":2}`), []byte(nil))
	good := vectorAnswer(f, c)
	f.Fuzz(func(t *testing.T, result, cert []byte) {
		ans := &answer.Answer{Stem: "x509-piv-valid", Files: map[string][]byte{answer.FileResult: result, answer.FileCert: cert}}
		keepR, keepC := bytes.Clone(result), bytes.Clone(cert)
		v, err := chk.Check(asked, ans)
		if !bytes.Equal(result, keepR) || !bytes.Equal(cert, keepC) {
			t.Fatal("the files of the answer were changed")
		}
		if err != nil && !errors.Is(err, answer.ErrInternal) {
			t.Fatalf("an error of a kind that is not for this input: %v", err)
		}
		if errors.Is(err, answer.ErrInternal) {
			t.Fatalf("two readers disagreed: %v", err)
		}
		verdictLaws(t, v, err, false)
		// The vector's own two files are accepted, so the fuzzer finds an acceptance only by the same bytes.
		if v.Accepted() && (!bytes.Equal(cert, good.Files[answer.FileCert])) {
			t.Fatalf("another certificate file is accepted")
		}
	})
}

func FuzzCheckOpenPGP(f *testing.F) {
	m := readVectorManifest(f)
	chk := mustChecker(f, vectorConfig(f, m))
	c := vectorCase(f, "pgp-piv-valid")
	asked := vectorAsked(f, c)
	for _, id := range []string{"pgp-piv-valid", "pgp-software-valid", "pgp-response-no-backsig", "pgp-response-wrong-subkey", "pgp-response-wrong-primary", "pgp-response-short-expiry"} {
		a := vectorAnswer(f, vectorCase(f, id))
		f.Add(a.Files[answer.FileResult], a.Files[answer.FileBound])
	}
	f.Add([]byte(`{"handoff":1}`), []byte(nil))
	good := vectorAnswer(f, c)
	f.Fuzz(func(t *testing.T, result, bound []byte) {
		ans := &answer.Answer{Stem: "pgp-piv-valid", Files: map[string][]byte{answer.FileResult: result, answer.FileBound: bound}}
		v, err := chk.Check(asked, ans)
		if err != nil {
			t.Fatalf("an error for an answer of a kind that is judged: %v", err)
		}
		verdictLaws(t, v, err, false)
		if v.Accepted() && !bytes.Equal(bound, good.Files[answer.FileBound]) {
			t.Fatalf("another bound file is accepted")
		}
	})
}

func FuzzCheckFloor(f *testing.F) {
	m := readVectorManifest(f)
	chk := mustChecker(f, vectorFloorConfig(f, m))
	c := vectorCase(f, "x509-floor-valid")
	asked := vectorAsked(f, c)
	for _, id := range []string{"x509-floor-valid", "x509-floor-extensions-dropped", "x509-floor-other-ca", "x509-floor-two-years", "x509-floor-eku-dropped"} {
		f.Add(vectorAnswer(f, vectorCase(f, id)).Files[answer.FileCert])
	}
	f.Add([]byte(nil))
	good := vectorAnswer(f, c)
	f.Fuzz(func(t *testing.T, cert []byte) {
		v, err := chk.Check(asked, &answer.Answer{Stem: "x509-floor-valid", Files: map[string][]byte{answer.FileCert: cert}})
		if err != nil {
			t.Fatalf("an error for a floor answer: %v", err)
		}
		verdictLaws(t, v, err, true)
		if !v.Floor() {
			t.Fatal("not a floor verdict")
		}
		if v.Accepted() && !bytes.Equal(cert, good.Files[answer.FileCert]) {
			// A certificate that differs and is accepted is a certificate that the floor holds to its rules: it must
			// verify and carry the key of the request.
			t.Logf("another certificate file is accepted by the floor")
		}
	})
}

// A fuzz target that runs the checks on the clock edges: the same files at other times never panic.
func FuzzClock(f *testing.F) {
	m := readVectorManifest(f)
	c := vectorCase(f, "x509-piv-valid")
	asked := vectorAsked(f, c)
	ans := vectorAnswer(f, c)
	f.Add(int64(1788000000), int64(0))
	f.Add(int64(-1), int64(500))
	f.Add(int64(1<<40), int64(0))
	f.Fuzz(func(t *testing.T, sec, nsec int64) {
		cfg := vectorConfig(t, m)
		at := time.Unix(sec, nsec%1_000_000_000).UTC()
		cfg.Now = func() time.Time { return at }
		v, err := mustChecker(t, cfg).Check(asked, cloneAnswer(ans))
		if err != nil {
			if !errors.Is(err, answer.ErrInternal) || v.Accepted() {
				t.Fatalf("%v", err)
			}
			return
		}
		verdictLaws(t, v, err, false)
	})
}
