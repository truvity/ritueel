package ceremonytest_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony/ceremonytest"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/history"
)

const ceremonyName = "20261120T100000Z-apply"

// Each step leaves the files of its row of the table of what a cut leaves behind (record 0005,
// rules 10 to 12): the plan and the copies; the attempt and the two empty journals; the key file
// and its birth line; both; every signature line and the removal files; the transcript; the
// root.json files and the trust set; the record. The key files are in the key directory, which is
// outside the bundle.
func TestEachStepLeavesTheFilesOfItsRow(t *testing.T) {
	c := "history/" + ceremonyName + "/"
	plan := []string{
		"ritueel.yaml", "want/roots/x509.yaml",
		c + "plan.json", c + "wanted/ritueel.yaml", c + "wanted/want/roots/x509.yaml",
	}
	attempt := append(slices.Clone(plan), c+"attempt.json", c+"births.jsonl", c+"signatures.jsonl")
	transcript := append(slices.Clone(attempt), c+"transcript.txt")
	set := append(slices.Clone(transcript), "roots/A/root.json", "roots/B/root.json",
		"trust/N-*/ca-bundle.pem", "trust/N-*/root-list.json", "trust/N-*/root-list.jws")
	recorded := append(slices.Clone(set), c+"record.json")
	rows := []struct {
		step   ceremonytest.Step
		bundle []string
		keys   []string
		births int // lines of births.jsonl
		sigs   int // lines of signatures.jsonl
		pins   int
	}{
		{ceremonytest.AtPlan, plan, nil, -1, -1, 0},
		{ceremonytest.AtAttempt, attempt, nil, 0, 0, 0},
		{ceremonytest.AtFirstBirth, attempt, []string{"test-only-keys/x509-root-a.p8"}, 1, 0, 1},
		{ceremonytest.AtBirths, attempt, []string{"test-only-keys/x509-root-a.p8", "test-only-keys/x509-root-b.p8"}, 2, 0, 2},
		{ceremonytest.AtSignatures, attempt, []string{"A.removal.jws", "B.removal.jws", "test-only-keys/x509-root-a.p8", "test-only-keys/x509-root-b.p8"}, 2, 5, 2},
		{ceremonytest.AtTranscript, transcript, []string{"A.removal.jws", "B.removal.jws", "test-only-keys/x509-root-a.p8", "test-only-keys/x509-root-b.p8"}, 2, 5, 2},
		{ceremonytest.AtSet, set, []string{"A.removal.jws", "B.removal.jws", "test-only-keys/x509-root-a.p8", "test-only-keys/x509-root-b.p8"}, 2, 5, 2},
		{ceremonytest.Recorded, recorded, []string{"A.removal.jws", "B.removal.jws", "test-only-keys/x509-root-a.p8", "test-only-keys/x509-root-b.p8"}, 2, 5, 2},
	}
	for _, r := range rows {
		t.Run(r.step.String(), func(t *testing.T) {
			m := ceremonytest.Bundle(t, ceremonytest.Options{Step: r.step})
			tree, keys := treeOf(t, m.Dir), treeOf(t, m.KeyDir)
			want := slices.Clone(r.bundle)
			slices.Sort(want)
			if got := shape(tree); !slices.Equal(got, want) {
				t.Errorf("the bundle holds\n%v\nwant\n%v", got, want)
			}
			var gotKeys []string
			for p, e := range keys {
				if e.dir {
					if p != "test-only-keys" {
						t.Errorf("a folder %s in the key directory", p)
					}
					if p == "test-only-keys" && len(r.keys) == 0 {
						t.Errorf("the folder test-only-keys stands in the key directory before any key was made: the key store is not started before the first birth")
					}
					continue
				}
				gotKeys = append(gotKeys, p)
			}
			slices.Sort(gotKeys)
			if !slices.Equal(gotKeys, r.keys) && (len(gotKeys) != 0 || len(r.keys) != 0) {
				t.Errorf("the key directory holds %v, want %v", gotKeys, r.keys)
			}
			if r.births >= 0 {
				if got := lines(t, filepath.Join(m.Dir, c+"births.jsonl")); got != r.births {
					t.Errorf("births.jsonl has %d lines, want %d", got, r.births)
				}
				if got := lines(t, filepath.Join(m.Dir, c+"signatures.jsonl")); got != r.sigs {
					t.Errorf("signatures.jsonl has %d lines, want %d", got, r.sigs)
				}
			}
			if len(m.Pins) != r.pins {
				t.Errorf("Pins = %v, want %d", m.Pins, r.pins)
			}
			// What no step leaves: a temporary name, and anything that is not a plain file or folder.
			for p := range tree {
				if isLeftover(p) {
					t.Errorf("the bundle holds the temporary name %s", p)
				}
			}
			for p, e := range keys {
				want := os.FileMode(0o600)
				if p == "test-only-keys" {
					want = 0o700
				}
				if isLeftover(p) || e.mode != want {
					t.Errorf("key directory file %s has mode %v, want %v", p, e.mode, want)
				}
			}
		})
	}
}

// What a bundle at each step says to the check of the history (the column "check history" of the
// table): clean with no record until the trust set is renamed into place; then the notice that a
// ceremony is unfinished; then one record. The state names what Made names.
func TestEachStepIsSeenByTheCheckOfTheHistory(t *testing.T) {
	steps := []ceremonytest.Step{
		ceremonytest.AtPlan, ceremonytest.AtAttempt, ceremonytest.AtFirstBirth, ceremonytest.AtBirths,
		ceremonytest.AtSignatures, ceremonytest.AtTranscript, ceremonytest.AtSet, ceremonytest.Recorded,
	}
	for _, step := range steps {
		t.Run(step.String(), func(t *testing.T) {
			m := ceremonytest.Bundle(t, ceremonytest.Options{Step: step})
			rep, in := check(t, m.Dir)
			if m.Ceremony != ceremonyName {
				t.Errorf("Ceremony = %q, want %q", m.Ceremony, ceremonyName)
			}
			switch {
			case step < ceremonytest.AtSet:
				if len(rep.Findings) != 0 || rep.Records != 0 {
					t.Errorf("findings %v, %d records; want a clean history with no record", rep.Findings, rep.Records)
				}
				if in.State == nil || in.State.Newest != nil || len(in.State.Unlisted) != 0 || in.State.NewestListed != nil {
					t.Errorf("State %+v: no set is written yet", in.State)
				}
			case step == ceremonytest.AtSet:
				if want := []history.Code{history.UnfinishedCeremony}; !slices.Equal(codes(rep), want) || len(rep.Findings) != 1 {
					t.Errorf("findings %v, want one unfinished-ceremony", rep.Findings)
				}
				if rep.Findings[0].Path != "trust/"+m.Set {
					t.Errorf("the finding is at %s, want trust/%s", rep.Findings[0].Path, m.Set)
				}
				if in.State == nil || in.State.Newest == nil || in.State.Newest.Name != m.Set || in.State.NewestListed != nil ||
					len(in.State.Unlisted) != 1 || in.State.Unlisted[0].Name != m.Set || in.State.Unlisted[0].Number != 1 {
					t.Errorf("State %+v: the leftover set is the newest and the only unlisted one", in.State)
				}
			default:
				if len(rep.Findings) != 0 || rep.Records != 1 {
					t.Errorf("findings %v, %d records; want one record and nothing else", rep.Findings, rep.Records)
				}
				if in.State == nil || len(in.State.Chain) != 1 || in.State.Chain[0] != (history.CeremonyInfo{
					Folder: ceremonyName, Command: "apply", Outcome: "completed", SHA256: digestOf(t, filepath.Join(m.Dir, "history", ceremonyName, "record.json")),
				}) {
					t.Errorf("State %+v", in.State)
				}
				if in.State.NewestListed == nil || in.State.NewestListed.Name != m.Set || in.State.Newest.Name != m.Set || len(in.State.Unlisted) != 0 {
					t.Errorf("NewestListed %+v, Newest %+v, Unlisted %+v", in.State.NewestListed, in.State.Newest, in.State.Unlisted)
				}
			}
			// The attempt is open from the attempt to the trust set, and in no other step.
			open := step >= ceremonytest.AtAttempt && step <= ceremonytest.AtSet
			if got := len(in.Unfinished) == 1 && in.Unfinished[0] == ceremonyName; got != open || (!open && len(in.Unfinished) != 0) {
				t.Errorf("Unfinished = %v at %s", in.Unfinished, step)
			}
			if in.State != nil && !slices.Equal(in.State.Unfinished, in.Unfinished) {
				t.Errorf("State.Unfinished %v, Unfinished %v", in.State.Unfinished, in.Unfinished)
			}
		})
	}
}

// Made names what the files hold: the digest of the plan, the digest of the attempt (only once it
// is written), the pins of the keys that the birth lines name, in the order of the labels, and the
// name of the trust set (only once it is written).
func TestMadeNamesWhatTheFilesHold(t *testing.T) {
	for _, step := range []ceremonytest.Step{ceremonytest.AtPlan, ceremonytest.AtAttempt, ceremonytest.AtFirstBirth, ceremonytest.AtBirths, ceremonytest.AtSet, ceremonytest.Recorded} {
		t.Run(step.String(), func(t *testing.T) {
			dir, keyDir := filepath.Join(t.TempDir(), "bundle"), filepath.Join(t.TempDir(), "keys")
			m := ceremonytest.Bundle(t, ceremonytest.Options{Step: step, Dir: dir, KeyDir: keyDir})
			if m.Dir != dir || m.KeyDir != keyDir {
				t.Errorf("Dir %q, KeyDir %q; want %q, %q", m.Dir, m.KeyDir, dir, keyDir)
			}
			c := filepath.Join(m.Dir, "history", m.Ceremony)
			if want := digestOf(t, filepath.Join(c, "plan.json")); m.PlanSHA256 != want {
				t.Errorf("PlanSHA256 = %s, the file has %s", m.PlanSHA256, want)
			}
			if step == ceremonytest.AtPlan {
				if m.AttemptSHA256 != "" {
					t.Errorf("AttemptSHA256 = %q with no attempt", m.AttemptSHA256)
				}
			} else if want := digestOf(t, filepath.Join(c, "attempt.json")); m.AttemptSHA256 != want {
				t.Errorf("AttemptSHA256 = %s, the file has %s", m.AttemptSHA256, want)
			}
			var pins []string
			if step >= ceremonytest.AtFirstBirth {
				data, err := os.ReadFile(filepath.Join(c, "births.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
					b, err := files.ReadBirthLine([]byte(line))
					if err != nil {
						t.Fatalf("a birth line: %v", err)
					}
					pins = append(pins, b.PublicKeySHA256)
				}
			}
			if !slices.Equal(m.Pins, pins) && (len(m.Pins) != 0 || len(pins) != 0) {
				t.Errorf("Pins = %v, the birth lines say %v", m.Pins, pins)
			}
			if step >= ceremonytest.AtSet {
				if m.Set == "" {
					t.Fatal("Set is empty")
				}
				if _, err := os.Stat(filepath.Join(m.Dir, "trust", m.Set, "root-list.json")); err != nil {
					t.Errorf("Set %s: %v", m.Set, err)
				}
				// The pins are the keys of the root list, in the order of the labels.
				data, err := os.ReadFile(filepath.Join(m.Dir, "trust", m.Set, "root-list.json"))
				if err != nil {
					t.Fatal(err)
				}
				for _, p := range m.Pins {
					if !strings.Contains(string(data), p) {
						t.Errorf("the root list does not hold the pin %s", p)
					}
				}
			} else if m.Set != "" {
				t.Errorf("Set = %q before the set is written", m.Set)
			}
			if _, err := os.Stat(keyDir); err != nil {
				t.Errorf("the key directory: %v", err)
			}
			if fi, err := os.Stat(keyDir); err == nil && fi.Mode().Perm() != 0o700 {
				t.Errorf("the key directory has mode %v, want 0700", fi.Mode().Perm())
			}
		})
	}
}

// A bundle holds no secret: the private scalar of each key file, as raw bytes, in hexadecimal, in
// Base64 (standard and URL), and the DER of the key as hexadecimal and Base64, is in no file of the
// bundle at any step.
func TestNoSecretIsInTheBundle(t *testing.T) {
	for _, step := range []ceremonytest.Step{ceremonytest.AtFirstBirth, ceremonytest.AtSignatures, ceremonytest.AtSet, ceremonytest.Recorded} {
		t.Run(step.String(), func(t *testing.T) {
			m := ceremonytest.Bundle(t, ceremonytest.Options{Step: step})
			keyFiles, err := filepath.Glob(filepath.Join(m.KeyDir, "test-only-keys", "*.p8"))
			if err != nil || len(keyFiles) == 0 {
				t.Fatalf("no key file: %v", err)
			}
			var secrets [][]byte
			for _, kf := range keyFiles {
				data, err := os.ReadFile(kf)
				if err != nil {
					t.Fatal(err)
				}
				key, err := x509.ParsePKCS8PrivateKey(data)
				if err != nil {
					t.Fatalf("%s: %v", kf, err)
				}
				ec, ok := key.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("%s holds a %T", kf, key)
				}
				d, err := ec.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				for _, raw := range [][]byte{d, data} {
					secrets = append(secrets, raw, []byte(hex.EncodeToString(raw)),
						[]byte(base64.StdEncoding.EncodeToString(raw)), []byte(base64.URLEncoding.EncodeToString(raw)),
						[]byte(base64.RawStdEncoding.EncodeToString(raw)), []byte(base64.RawURLEncoding.EncodeToString(raw)))
				}
			}
			n := 0
			for p, e := range treeOf(t, m.Dir) {
				if e.dir {
					continue
				}
				data, err := os.ReadFile(filepath.Join(m.Dir, p))
				if err != nil {
					t.Fatal(err)
				}
				n++
				for _, s := range secrets {
					if len(s) >= 16 && strings.Contains(string(data), string(s)) {
						t.Errorf("%s holds a secret", p)
					}
				}
			}
			if n == 0 {
				t.Fatal("no file was looked at")
			}
		})
	}
}

func TestStepNames(t *testing.T) {
	names := map[ceremonytest.Step]string{
		ceremonytest.AtPlan: "AtPlan", ceremonytest.AtAttempt: "AtAttempt", ceremonytest.AtFirstBirth: "AtFirstBirth",
		ceremonytest.AtBirths: "AtBirths", ceremonytest.AtSignatures: "AtSignatures", ceremonytest.AtTranscript: "AtTranscript",
		ceremonytest.AtSet: "AtSet", ceremonytest.Recorded: "Recorded",
	}
	for s, want := range names {
		if got := s.String(); got != want {
			t.Errorf("Step(%d).String() = %q, want %q", int(s), got, want)
		}
	}
	for _, s := range []ceremonytest.Step{0, -1, 9, 100} {
		if got := s.String(); got != "" {
			t.Errorf("Step(%d).String() = %q, want empty", int(s), got)
		}
	}
	// The steps are in the order of the ceremony, one after the other.
	order := []ceremonytest.Step{ceremonytest.AtPlan, ceremonytest.AtAttempt, ceremonytest.AtFirstBirth, ceremonytest.AtBirths, ceremonytest.AtSignatures, ceremonytest.AtTranscript, ceremonytest.AtSet, ceremonytest.Recorded}
	for i, s := range order {
		if int(s) != i+1 {
			t.Errorf("%s = %d, want %d", s, int(s), i+1)
		}
	}
}

// A step that is none, or an option that cannot be kept, fails the test and makes nothing.
func TestBundleRefuses(t *testing.T) {
	t.Run("the zero step", func(t *testing.T) {
		msg := failsWith(t, func(tb testing.TB) { ceremonytest.Bundle(tb, ceremonytest.Options{}) })
		if !strings.Contains(msg, "no step") {
			t.Errorf("message %q", msg)
		}
	})
	t.Run("a step that is none", func(t *testing.T) {
		for _, s := range []ceremonytest.Step{-3, 9, 1000} {
			msg := failsWith(t, func(tb testing.TB) { ceremonytest.Bundle(tb, ceremonytest.Options{Step: s}) })
			if !strings.Contains(msg, "no step") {
				t.Errorf("step %d: message %q", int(s), msg)
			}
			msg = failsWith(t, func(tb testing.TB) { ceremonytest.AfterWrites(tb, ceremonytest.Options{Step: s}, 1) })
			if !strings.Contains(msg, "no step") {
				t.Errorf("AfterWrites, step %d: message %q", int(s), msg)
			}
			msg = failsWith(t, func(tb testing.TB) { ceremonytest.Writes(tb, ceremonytest.Options{Step: s}) })
			if !strings.Contains(msg, "no step") {
				t.Errorf("Writes, step %d: message %q", int(s), msg)
			}
		}
	})
	t.Run("a bundle folder that exists", func(t *testing.T) {
		dir := t.TempDir()
		msg := failsWith(t, func(tb testing.TB) {
			ceremonytest.Bundle(tb, ceremonytest.Options{Step: ceremonytest.AtPlan, Dir: dir})
		})
		if !strings.Contains(msg, "bundle") {
			t.Errorf("message %q", msg)
		}
		if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
			t.Errorf("the folder that existed was written into: %v %v", ents, err)
		}
	})
	t.Run("a bundle folder whose parent is missing", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "missing", "ca")
		failsWith(t, func(tb testing.TB) {
			ceremonytest.Bundle(tb, ceremonytest.Options{Step: ceremonytest.AtPlan, Dir: dir})
		})
	})
	t.Run("a key directory that is a file", func(t *testing.T) {
		kd := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(kd, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		msg := failsWith(t, func(tb testing.TB) {
			ceremonytest.Bundle(tb, ceremonytest.Options{Step: ceremonytest.AtPlan, KeyDir: kd})
		})
		if !strings.Contains(msg, "key directory") {
			t.Errorf("message %q", msg)
		}
	})
	t.Run("a clock outside the years of a timestamp", func(t *testing.T) {
		for _, tm := range []time.Time{time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(-5, 1, 1, 0, 0, 0, 0, time.UTC)} {
			msg := failsWith(t, func(tb testing.TB) {
				ceremonytest.Bundle(tb, ceremonytest.Options{Step: ceremonytest.AtPlan, Now: func() time.Time { return tm }})
			})
			if !strings.Contains(msg, "clock") {
				t.Errorf("time %v: message %q", tm, msg)
			}
		}
	})
}

// The folders that Options leaves empty are made under the test's own temporary folder, and the key
// directory is outside the bundle.
func TestDefaultFoldersAreOutsideEachOther(t *testing.T) {
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtFirstBirth})
	if m.Dir == "" || m.KeyDir == "" || m.Dir == m.KeyDir {
		t.Fatalf("Dir %q, KeyDir %q", m.Dir, m.KeyDir)
	}
	for _, p := range []string{m.Dir, m.KeyDir} {
		if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
			t.Errorf("%s: %v", p, err)
		}
	}
	rel, err := filepath.Rel(m.Dir, m.KeyDir)
	if err == nil && !strings.HasPrefix(rel, "..") {
		t.Errorf("the key directory %s is inside the bundle %s", m.KeyDir, m.Dir)
	}
	// Two calls make two bundles.
	m2 := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtPlan})
	if m2.Dir == m.Dir || m2.KeyDir == m.KeyDir {
		t.Errorf("two calls share a folder: %s, %s", m2.Dir, m2.KeyDir)
	}
}
