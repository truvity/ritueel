package handoff_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/testrepo"
)

// The fuzz targets read the request files of the vectors as their seeds. Run in the ordinary way they
// run the seeds only; `go test -fuzz` mutates them. Neither starts a program, and neither writes a file.

// fuzzVerifier is the evidence verifier of the fuzz targets: it reads the key of the request itself, so
// that the checks after check 7 are reached, and it reports a recent firmware and an allowed PIN policy.
type fuzzVerifier struct{}

func (fuzzVerifier) Verify(_ context.Context, r *handoff.Request, _ *handoff.Proof, _ time.Time) (*handoff.Evidence, error) {
	key, err := pki.RequestKeyFile(r.Files[handoff.FileCSR])
	if err != nil {
		return nil, &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "no key"}
	}
	return &handoff.Evidence{
		Key: key, Firmware: "5.8.0", PINPolicy: handoff.PINOnce,
		SignPrincipals: []handoff.Principal{{ARN: "arn:aws:iam::123456789012:role/example-holder", Kind: handoff.PrincipalRole}},
	}, nil
}

func fuzzChecker(t testing.TB) *handoff.Checker {
	t.Helper()
	m := readManifest(t)
	v := fuzzVerifier{}
	return checkerOfCase(t, m, vectorCase{ID: "fuzz", Type: "x509-intermediate", Config: "development"}, rootsOfManifest(t, m), testNow,
		map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: v, handoff.StoreKMS: v, handoff.StoreOpenPGPCard: v})
}

// seedRequests are the files of every request case of the vectors, each as four byte strings: the proof,
// the certificate request, the subkey and the SSH key line with its signature joined by a zero byte.
func seedRequests(t testing.TB) [][4][]byte {
	t.Helper()
	m := readManifest(t)
	var out [][4][]byte
	seen := map[string]bool{}
	for _, c := range m.Cases {
		var set [4][]byte
		stem := ""
		for _, f := range c.Files {
			if s, ok := strings.CutSuffix(path.Base(f), "."+handoff.FileProof); ok {
				stem = s
			}
		}
		if stem == "" || seen[stem] {
			continue
		}
		seen[stem] = true
		for i, suffix := range []string{handoff.FileProof, handoff.FileCSR, handoff.FileSubkey, handoff.FileSSHKey} {
			b, err := os.ReadFile(testrepo.Path(t, vectorsDir, "requests", stem+"."+suffix))
			if err == nil {
				set[i] = b
			}
		}
		if sig, err := os.ReadFile(testrepo.Path(t, vectorsDir, "requests", stem+"."+handoff.FileSSHSig)); err == nil {
			set[3] = append(append(bytes.Clone(set[3]), 0), sig...)
		}
		out = append(out, set)
	}
	if len(out) == 0 {
		t.Fatal("no seed: a check that finds nothing to check fails")
	}
	return out
}

func requestOf(proof, csr, subkey, ssh []byte) *handoff.Request {
	r := &handoff.Request{Stem: "fuzz", Files: map[string][]byte{handoff.FileProof: proof}}
	if csr != nil {
		r.Files[handoff.FileCSR] = csr
	}
	if subkey != nil {
		r.Files[handoff.FileSubkey] = subkey
	}
	if key, sig, ok := bytes.Cut(ssh, []byte{0}); ssh != nil {
		r.Files[handoff.FileSSHKey] = key
		if ok {
			r.Files[handoff.FileSSHSig] = sig
		}
	}
	return r
}

// checkVerdictLaws says what holds for every verdict of every input.
func checkVerdictLaws(t *testing.T, r *handoff.Request, v handoff.Verdict, err error) {
	t.Helper()
	if len(v.Checks) != 9 {
		t.Fatalf("%d check results", len(v.Checks))
	}
	failed := -1
	seenNot := false
	for i, c := range v.Checks {
		if c.N != i+1 {
			t.Fatalf("check %d is numbered %d", i+1, c.N)
		}
		switch c.Status {
		case handoff.StatusPassed:
			if seenNot || failed >= 0 {
				t.Fatalf("check %d passed after one that did not: %s", i+1, statuses(v))
			}
			if len(c.NotRun) != 0 {
				t.Fatalf("check %d passed and names rules that did not run", i+1)
			}
		case handoff.StatusFailed:
			// The one place where a check fails with an earlier one not run: a proof file whose version
			// cannot be read fails check 2 and check 1 does not run.
			if failed >= 0 || (seenNot && (i != 1 || statuses(v) != "nfnnnnnnn")) {
				t.Fatalf("check %d failed after one that did not pass: %s", i+1, statuses(v))
			}
			if len(c.NotRun) != 0 {
				t.Fatalf("check %d failed and names rules that did not run", i+1)
			}
			failed = i
		case handoff.StatusNotRun:
			seenNot = true
		default:
			t.Fatalf("check %d has the status %q", i+1, c.Status)
		}
	}
	if (failed >= 0) != v.Refused() {
		t.Fatalf("code %q and statuses %s disagree", v.Code, statuses(v))
	}
	if v.Refused() {
		wantCheck := map[handoff.Code][]int{
			handoff.CodeVersionUnsupported: {0}, handoff.CodeMalformed: {1, 6}, handoff.CodeRequestMismatch: {2},
			handoff.CodeUnknownPrimary:       {2},
			handoff.CodeAlgorithmUnsupported: {3}, handoff.CodePossessionInvalid: {4}, handoff.CodeStoreNotAllowed: {5},
			handoff.CodeProofInvalid: {6}, handoff.CodeKeyMismatch: {7}, handoff.CodePolicy: {8},
		}[v.Code]
		if !containsInt(wantCheck, failed) {
			t.Fatalf("the code %q was given by check %d", v.Code, failed+1)
		}
		if v.Detail == "" {
			t.Fatalf("a refusal with the code %q has no detail", v.Code)
		}
	}
	for _, r := range v.Detail {
		if r < 0x20 || r >= 0x7f {
			t.Fatalf("the detail holds the character %U: %q", r, v.Detail)
		}
	}
	if err != nil && (v.Refused() || v.Complete()) {
		t.Fatalf("an error beside a verdict that is decided: %v, code %q", err, v.Code)
	}
	// Accepted() is the one reading of an acceptance, and it agrees with the parts it is made of.
	if v.Accepted() != (err == nil && !v.Refused() && v.Complete()) {
		t.Fatalf("Accepted() is %v, with error %v, code %q, statuses %s", v.Accepted(), err, v.Code, statuses(v))
	}
	if !v.Accepted() && (v.Key != nil || v.Evidence != nil || v.Subkey != nil) {
		t.Fatalf("a verdict that is not accepted holds a key or evidence: %v %v", v.Key, v.Evidence)
	}
	if v.Accepted() {
		if statuses(v) != "ppppppppp" || v.Key == nil || v.Evidence == nil || err != nil || v.Code != "" || v.Detail != "" {
			t.Fatalf("an acceptance that is not one: %s, key %v, evidence %v, error %v", statuses(v), v.Key, v.Evidence, err)
		}
		// An acceptance is of a request that every check has read: both files exist and are within the limit.
		if len(r.Files[handoff.FileProof]) > handoff.MaxFileSize || len(r.Files[handoff.FileCSR]) > handoff.MaxFileSize {
			t.Fatal("a file over the limit was accepted")
		}
	}
	if err != nil && !errors.Is(err, handoff.ErrTypeNotBuilt) && !errors.Is(err, handoff.ErrNoVerifier) &&
		!errors.Is(err, handoff.ErrInternal) && !errors.Is(err, handoff.ErrConfig) {
		t.Fatalf("an error of no kind of the package: %v", err)
	}
	if errors.Is(err, handoff.ErrInternal) {
		t.Fatalf("two readers disagree: %v", err)
	}
	// The one request that a configuration made by New can leave undecided with ErrConfig is an openpgp-subkey
	// request on a checker that holds no primaries: checks 1 and 2 passed, and nothing else ran.
	if errors.Is(err, handoff.ErrConfig) && statuses(v) != "ppnnnnnnn" {
		t.Fatalf("the configuration is read as wrong: %v, statuses %s", err, statuses(v))
	}
	if v.Subkey != nil && !v.Accepted() {
		t.Fatalf("a verdict that is not accepted holds a subkey: %+v", v.Subkey)
	}
}

func containsInt(list []int, n int) bool {
	for _, x := range list {
		if x == n {
			return true
		}
	}
	return false
}

// neverACardIntermediate says what holds for a request that names the type x509-intermediate and the store
// openpgp-card: check 6 never passes for it, so no evidence is read and no later check runs.
func neverACardIntermediate(t *testing.T, proof []byte, v handoff.Verdict) {
	t.Helper()
	var head struct{ Type, Store string }
	if json.Unmarshal(proof, &head) != nil || head.Type != "x509-intermediate" || head.Store != "openpgp-card" {
		return
	}
	if v.Checks[5].Status == handoff.StatusPassed || v.Accepted() {
		t.Fatalf("an x509-intermediate request on an openpgp-card passed check 6: %s", statuses(v))
	}
	if v.Code == handoff.CodeStoreNotAllowed && v.Detail != cardRefusalWords {
		t.Fatalf("the refusal has the words %q", v.Detail)
	}
}

func FuzzCheck(f *testing.F) {
	for _, s := range seedRequests(f) {
		f.Add(s[0], s[1], s[2], s[3])
		// The same request on the card store: for an X.509 request, check 6 refuses it.
		if card := bytes.Replace(s[0], []byte(`"store": "piv"`), []byte(`"store": "openpgp-card"`), 1); !bytes.Equal(card, s[0]) {
			f.Add(card, s[1], s[2], s[3])
		}
	}
	chk := fuzzChecker(f)
	f.Fuzz(func(t *testing.T, proof, csr, subkey, ssh []byte) {
		r := requestOf(proof, csr, subkey, ssh)
		before := copyOfRequest(r)
		v, err := chk.Check(t.Context(), r)
		checkVerdictLaws(t, r, v, err)
		neverACardIntermediate(t, proof, v)
		if !sameRequest(before, r) {
			t.Fatal("the request of the caller was changed")
		}
		// The same request gives the same answer.
		v2, err2 := chk.Check(t.Context(), r)
		if v2.Code != v.Code || statuses(v2) != statuses(v) || (err == nil) != (err2 == nil) {
			t.Fatalf("two runs differ: %q %s %v, and %q %s %v", v.Code, statuses(v), err, v2.Code, statuses(v2), err2)
		}
	})
}

func copyOfRequest(r *handoff.Request) *handoff.Request {
	c := &handoff.Request{Stem: r.Stem, Files: map[string][]byte{}}
	for k, v := range r.Files {
		c.Files[k] = bytes.Clone(v)
	}
	return c
}

func sameRequest(a, b *handoff.Request) bool {
	if a.Stem != b.Stem || len(a.Files) != len(b.Files) {
		return false
	}
	for k, v := range a.Files {
		w, ok := b.Files[k]
		if !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}

// FuzzLoadRequest loads the files of a folder on a real disk. The folder is made once and its content is
// replaced at every run: the proof, the request file and the subkey from the input, and a shape that puts
// a link, a pipe or a folder where a file or a folder belongs. The stem and the folder of the call are the
// input's when the high bit of shape is set, and the folder's own otherwise. Nothing is written outside the
// folder: the names of the files are fixed.
func FuzzLoadRequest(f *testing.F) {
	for _, s := range seedRequests(f) {
		f.Add("fuzz", "requests/fuzz", s[0], s[1], s[2], uint8(0))
	}
	f.Add("a", ".", []byte("{}"), []byte(nil), []byte(nil), uint8(129))
	f.Add("A", "..", []byte("{}"), []byte(nil), []byte(nil), uint8(130))
	f.Add("a", "a//b", []byte("{}"), []byte(nil), []byte(nil), uint8(131))
	for shape := uint8(1); shape < 6; shape++ {
		f.Add("fuzz", "requests/fuzz", []byte("{}"), []byte("C"), []byte("K"), shape)
	}
	chk := fuzzChecker(f)
	base := f.TempDir()
	root, err := fsx.OpenFS(base)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = root.Close() })
	folder := filepath.Join(base, "requests", "fuzz")
	other := filepath.Join(base, "other")
	secret := filepath.Join(base, "secret")
	for _, d := range []string{filepath.Dir(folder), other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			f.Fatal(err)
		}
	}
	if err := os.WriteFile(secret, []byte("SECRET"), 0o600); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "fuzz.proof.json"), []byte("{}"), 0o600); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, stem, dir string, proof, csr, subkey []byte, shape uint8) {
		kind := shape % 6
		if err := os.RemoveAll(folder); err != nil {
			t.Fatal(err)
		}
		if kind == 4 {
			// The folder of the request is a link to another folder that holds a proof file.
			if err := os.Symlink(other, folder); err != nil {
				t.Skip(err)
			}
		} else {
			if err := os.Mkdir(folder, 0o700); err != nil {
				t.Fatal(err)
			}
			put := func(suffix string, data []byte) {
				if err := os.WriteFile(filepath.Join(folder, "fuzz."+suffix), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case 5:
				if err := syscall.Mkfifo(filepath.Join(folder, "fuzz."+handoff.FileProof), 0o600); err != nil {
					t.Skip(err)
				}
			default:
				put(handoff.FileProof, proof)
			}
			switch kind {
			case 1:
				if err := os.Symlink(secret, filepath.Join(folder, "fuzz."+handoff.FileCSR)); err != nil {
					t.Skip(err)
				}
			case 2:
				if err := syscall.Mkfifo(filepath.Join(folder, "fuzz."+handoff.FileCSR), 0o600); err != nil {
					t.Skip(err)
				}
			case 3:
				if err := os.Mkdir(filepath.Join(folder, "fuzz."+handoff.FileCSR), 0o700); err != nil {
					t.Fatal(err)
				}
			default:
				if csr != nil {
					put(handoff.FileCSR, csr)
				}
			}
			if subkey != nil {
				put(handoff.FileSubkey, subkey)
			}
		}
		callStem, callDir := "fuzz", "requests/fuzz"
		if shape >= 128 {
			callStem, callDir = stem, dir
		}
		r, err := loadWithin(t, root, callDir, callStem)
		if err != nil {
			if !errors.Is(err, handoff.ErrLoad) && !errors.Is(err, handoff.ErrNoProof) {
				t.Fatalf("an error of no kind of the package: %v", err)
			}
			if r != nil {
				t.Fatal("a request beside an error")
			}
			return
		}
		if kind != 0 && shape < 128 {
			t.Fatalf("a link, a pipe or a folder was taken for a file (kind %d): %v", kind, r.Files)
		}
		if r.Stem != callStem {
			t.Fatalf("the stem is %q, not %q", r.Stem, callStem)
		}
		if _, ok := r.Files[handoff.FileProof]; !ok {
			t.Fatal("no proof file, and no error")
		}
		for name, data := range r.Files {
			if len(data) > handoff.MaxFileSize+1 {
				t.Fatalf("%s holds %d bytes", name, len(data))
			}
			if bytes.Contains(data, []byte("SECRET")) {
				t.Fatalf("%s holds the content of a file that is outside the folder", name)
			}
			switch name {
			case handoff.FileProof, handoff.FileCSR, handoff.FileSubkey, handoff.FileSSHKey, handoff.FileSSHSig:
			default:
				t.Fatalf("the file %q is not one of the five", name)
			}
		}
		v, err := chk.Check(t.Context(), r)
		checkVerdictLaws(t, r, v, err)
	})
}
