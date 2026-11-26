//go:build linux

package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/testrepo"
)

// The first apply of an X.509 test root, as the command line runs it, with the keys made through the key port
// of atom: what stands in the key directory, what the records and the plan say about the keys, what happens to
// a key directory that was used, to a plan of an earlier version and to a stop at the key store, and that
// nothing listens. The names of this file start with ak.

// akApply runs the first apply of the bundle from a saved plan, in JSON, and returns the result.
func akApply(t *testing.T, dir, keys string) (result, map[string]any, string) {
	t.Helper()
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	r := arRun(t, newTicker(apClock).now, strings.NewReader(""), false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest)
	return r, apObject(t, r.stdout), path
}

func akReadJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return m
}

func akMembers(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func akLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		out = append(out, m)
	}
	return out
}

// akDone is a finished first apply: the bundle, the key directory and the JSON result.
func akDone(t *testing.T) (dir, keys string, obj map[string]any) {
	t.Helper()
	dir, keys = arBundle(t)
	r, obj, _ := akApply(t, dir, keys)
	if r.code != ExitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	return dir, keys, obj
}

func TestTheFirstApplyLeavesTheKeyDirectoryWithExactlyTheFolderOfTheKeysAndTheRemovalAuthorisations(t *testing.T) {
	_, keys, obj := akDone(t)
	type entry struct {
		name string
		mode fs.FileMode
	}
	list := func(dir string) (out []entry) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			fi, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, entry{e.Name(), fi.Mode()})
		}
		return out
	}
	if got, want := list(keys), []entry{{"A.removal.jws", 0o600}, {"B.removal.jws", 0o600}, {"test-only-keys", fs.ModeDir | 0o700}}; !slices.Equal(got, want) {
		t.Errorf("the key directory holds %v, want %v", got, want)
	}
	if got, want := list(filepath.Join(keys, "test-only-keys")), []entry{{"x509-root-a.p8", 0o600}, {"x509-root-b.p8", 0o600}}; !slices.Equal(got, want) {
		t.Errorf("the folder test-only-keys holds %v, want %v", got, want)
	}
	// Each key file holds the P-384 key whose public key the result names as the pin of the root.
	roots, _ := obj["roots"].([]any)
	if len(roots) != 2 {
		t.Fatalf("roots = %v", obj["roots"])
	}
	for i, label := range []string{"a", "b"} {
		der, err := os.ReadFile(filepath.Join(keys, "test-only-keys", "x509-root-"+label+".p8"))
		if err != nil {
			t.Fatal(err)
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatalf("the key file of %s is not PKCS#8: %v", label, err)
		}
		priv, ok := k.(*ecdsa.PrivateKey)
		if !ok || priv.Curve != elliptic.P384() {
			t.Fatalf("the key file of %s holds %T", label, k)
		}
		spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(spki)
		root, _ := roots[i].(map[string]any)
		if root["label"] != strings.ToUpper(label) || root["x509_spki_sha256"] != hex.EncodeToString(sum[:]) {
			t.Errorf("root %d = %v, want the pin %x of the key file", i, root, sum)
		}
	}
	// The removal authorisation is a file of ritueel beside the folder, with the shape of a compact JWS.
	for _, l := range []string{"A", "B"} {
		b, err := os.ReadFile(filepath.Join(keys, l+".removal.jws"))
		if err != nil || strings.Count(string(b), ".") != 2 || strings.ContainsAny(string(b), "\n\r ") {
			t.Errorf("%s.removal.jws: %q, %v", l, b, err)
		}
	}
}

func TestThePlaceOfAKeyInThePlanAndInTheBirthsIsItsPurposeAndNeverAPath(t *testing.T) {
	dir, keys, obj := akDone(t)
	ceremony, _ := obj["ceremony"].(string)
	h := filepath.Join(dir, "history", ceremony)
	plan := akReadJSON(t, filepath.Join(h, "plan.json"))
	var places []string
	for _, b := range plan["births"].([]any) {
		places = append(places, b.(map[string]any)["place"].(string))
	}
	if !slices.Equal(places, []string{"x509-root-a", "x509-root-b"}) {
		t.Errorf("the places of the plan are %q", places)
	}
	places = nil
	for _, b := range akLines(t, filepath.Join(h, "births.jsonl")) {
		places = append(places, b["place"].(string))
	}
	if !slices.Equal(places, []string{"x509-root-a", "x509-root-b"}) {
		t.Errorf("the places of the births are %q", places)
	}
	// No file of the bundle says where the key directory is, names a key file, or holds a key.
	root := filepath.Dir(keys)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, bad := range []string{keys, root, ".p8", ".x509.key.pem", "PRIVATE KEY"} {
			if bytes.Contains(b, []byte(bad)) {
				t.Errorf("%s holds %q", p, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The members of the records are those of the bundle that an earlier build recorded, and the values of the
// members that say where a key lives, whether it is a test key and whether it can be copied are what they were.
func TestTheRecordsOfTheFirstApplyHaveTheMembersAndTheValuesOfTheRecordedBundle(t *testing.T) {
	dir, _, obj := akDone(t)
	ceremony, _ := obj["ceremony"].(string)
	recorded := testrepo.Path(t, "testdata", "recorded-bundles", "first-apply-x509-test-root")
	const recordedCeremony = "20261120T100000Z-apply"
	cases := []struct{ name, now, then string }{
		{"the record", filepath.Join("history", ceremony, "record.json"), filepath.Join("history", recordedCeremony, "record.json")},
		{"the plan", filepath.Join("history", ceremony, "plan.json"), filepath.Join("history", recordedCeremony, "plan.json")},
		{"the root file of A", filepath.Join("roots", "A", "root.json"), filepath.Join("roots", "A", "root.json")},
		{"the root file of B", filepath.Join("roots", "B", "root.json"), filepath.Join("roots", "B", "root.json")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now, then := akReadJSON(t, filepath.Join(dir, c.now)), akReadJSON(t, filepath.Join(recorded, c.then))
			if a, b := akMembers(now), akMembers(then); !slices.Equal(a, b) {
				t.Errorf("the members are %v, the recorded bundle has %v", a, b)
			}
			if r, ok := then["root"].(map[string]any); ok {
				got, _ := now["root"].(map[string]any)
				if a, b := akMembers(got), akMembers(r); !slices.Equal(a, b) {
					t.Errorf("the members of root are %v, the recorded bundle has %v", a, b)
				}
				for _, m := range []string{"store", "test", "copyable", "label"} {
					if got[m] != r[m] {
						t.Errorf("root.%s = %v, the recorded bundle has %v", m, got[m], r[m])
					}
				}
			}
			for _, m := range []string{"store", "test", "copyable", "version"} {
				if v, ok := then[m]; ok && now[m] != v {
					t.Errorf("%s = %v, the recorded bundle has %v", m, now[m], v)
				}
			}
		})
	}
	// The births: the same members as before, with the places in the new form and every other value of the same kind.
	nowBirths := akLines(t, filepath.Join(dir, "history", ceremony, "births.jsonl"))
	thenBirths := akLines(t, filepath.Join(recorded, "history", recordedCeremony, "births.jsonl"))
	if len(nowBirths) != len(thenBirths) {
		t.Fatalf("%d birth lines, the recorded bundle has %d", len(nowBirths), len(thenBirths))
	}
	for i := range nowBirths {
		if a, b := akMembers(nowBirths[i]), akMembers(thenBirths[i]); !slices.Equal(a, b) {
			t.Errorf("birth %d: the members are %v, the recorded bundle has %v", i, a, b)
		}
		for _, m := range []string{"store", "purpose", "label"} {
			if nowBirths[i][m] != thenBirths[i][m] {
				t.Errorf("birth %d: %s = %v, the recorded bundle has %v", i, m, nowBirths[i][m], thenBirths[i][m])
			}
		}
	}
	// The births of the plan likewise.
	nowPlan := akReadJSON(t, filepath.Join(dir, "history", ceremony, "plan.json"))["births"].([]any)
	thenPlan := akReadJSON(t, filepath.Join(recorded, "history", recordedCeremony, "plan.json"))["births"].([]any)
	for i := range thenPlan {
		a, b := nowPlan[i].(map[string]any), thenPlan[i].(map[string]any)
		if x, y := akMembers(a), akMembers(b); !slices.Equal(x, y) {
			t.Errorf("plan birth %d: the members are %v, the recorded bundle has %v", i, x, y)
		}
		if a["store"] != b["store"] || a["purpose"] != b["purpose"] || a["label"] != b["label"] {
			t.Errorf("plan birth %d is %v, the recorded bundle has %v", i, a, b)
		}
	}
	// The bundle that was just made passes the check of its history, as the recorded one does.
	if r := checkHistoryOf(t, dir); r.code != ExitOK {
		t.Errorf("check history of the new bundle: %d %s", r.code, r.stderr)
	}
}

// The key directory that was used is refused as key-exists with the exit code 4 before anything is written: in the
// bundle or in the key directory.
func TestAnApplyOnAUsedKeyDirectoryIsRefusedAsKeyExistsWithExitCode4AndWritesNothing(t *testing.T) {
	cases := map[string]func(t *testing.T, keys string){
		"one that an earlier apply finished": func(t *testing.T, keys string) {
			dir, k, _ := akDone(t)
			_ = dir
			copyTree(t, k, keys)
		},
		"one that holds a removal authorisation": func(t *testing.T, keys string) {
			akWrite(t, filepath.Join(keys, "A.removal.jws"), "AAAA.BBBB.CCCC")
		},
		"one that holds a key file of the earlier naming": func(t *testing.T, keys string) {
			akWrite(t, filepath.Join(keys, "A.x509.key.pem"), "x")
		},
		"one that holds a folder test-only-keys with a key": func(t *testing.T, keys string) {
			mustMkdir(t, filepath.Join(keys, "test-only-keys"), 0o700)
			akWrite(t, filepath.Join(keys, "test-only-keys", "x509-root-a.p8"), "x")
		},
		"one that holds a folder test-only-keys of the mode 0755": func(t *testing.T, keys string) {
			mustMkdir(t, filepath.Join(keys, "test-only-keys"), 0o755)
		},
		"one that holds a file test-only-keys": func(t *testing.T, keys string) {
			akWrite(t, filepath.Join(keys, "test-only-keys"), "x")
		},
		"one that holds a link test-only-keys": func(t *testing.T, keys string) {
			if err := os.Symlink(filepath.Join(keys, "nowhere"), filepath.Join(keys, "test-only-keys")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, use := range cases {
		for _, how := range []string{"direct", "saved plan"} {
			t.Run(name+", "+how, func(t *testing.T) {
				dir, keys := arBundle(t)
				path, digest := "", ""
				if how == "saved plan" {
					path, digest = arPlan(t, apClock, dir, "--key-dir", keys) // made while the key directory was still empty
				}
				use(t, keys)
				beforeBundle, beforeKeys := apSnapshot(t, dir), apSnapshot(t, keys)
				var args []string
				if how == "saved plan" {
					args = []string{"--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest}
				} else {
					// The digest of a plan that the run makes is not known: the plan-only run, which refuses as
					// well, is not what is under test, so the confirmation is the typed one that a script does not give.
					args = []string{"--dir", dir, "--output", "json", "apply", "--key-dir", keys, "--confirm", strings.Repeat("0", 64)}
				}
				r := arRun(t, newTicker(apClock).now, strings.NewReader(""), false, args...)
				obj := apObject(t, r.stdout)
				reasons, _ := stringList(obj["reasons"])
				if r.code != ExitBackend || obj["outcome"] != "refused" || !slices.Equal(reasons, []string{"key-exists"}) || obj["error"] != nil {
					t.Fatalf("exit %d, %v; want the exit code 4 and the reason key-exists", r.code, obj)
				}
				if !strings.Contains(r.stderr, "nothing was written") || strings.Contains(r.stderr, keys) {
					t.Errorf("standard error = %q", r.stderr)
				}
				crqSame(t, "the refused apply in the bundle", beforeBundle, apSnapshot(t, dir))
				crqSame(t, "the refused apply in the key directory", beforeKeys, apSnapshot(t, keys))
			})
		}
	}
}

func akWrite(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// copyTree copies the files and folders of src into the existing folder dst, with their modes.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel == "." {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Mkdir(filepath.Join(dst, rel), fi.Mode().Perm())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, fi.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The empty folder that an earlier run left is not a use: the next run takes it as it is.
func TestAnEmptyFolderOfTheKeysThatFitsIsUsedAsItIs(t *testing.T) {
	dir, keys := arBundle(t)
	mustMkdir(t, filepath.Join(keys, "test-only-keys"), 0o700)
	r, obj, _ := akApply(t, dir, keys)
	if r.code != ExitOK {
		t.Fatalf("exit %d, %v", r.code, obj)
	}
	st, err := os.Lstat(filepath.Join(keys, "test-only-keys"))
	if err != nil || st.Mode() != fs.ModeDir|0o700 {
		t.Errorf("the folder is %v, %v", st, err)
	}
	if got, _ := os.ReadDir(filepath.Join(keys, "test-only-keys")); len(got) != 2 {
		t.Errorf("the folder holds %d entries, want the two keys", len(got))
	}
}

// A stop at the write of the attempt, which comes after the key store started, leaves the empty folder; the line says
// that it may stand and that it is harmless, and the run that follows takes it as it is.
func TestAStopAfterTheKeyStoreStartedLeavesAnEmptyFolderAndNoKeyAndTheNextRunUsesIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a folder that has no write bit")
	}
	dir, keys := arBundle(t)
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	folder := filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(path, "/plan.json")))
	if err := os.Chmod(folder, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(folder, 0o755) })
	r := arRun(t, newTicker(apClock).now, nil, false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest)
	obj := apObject(t, r.stdout)
	msg, _ := obj["error"].(string)
	if r.code != ExitFailure || obj["outcome"] != "failed" || !strings.Contains(msg, "stopped at attempt") {
		t.Fatalf("exit %d, %v", r.code, obj)
	}
	for _, want := range []string{"the empty folder test-only-keys may stand in the key directory", "it is harmless, and the next run uses it", "ritueel deleted nothing"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the line does not say %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, keys) {
		t.Errorf("the line holds the path of the key directory: %s", msg)
	}
	// No key exists, and no removal authorisation: the folder is there, empty, with the mode 0700.
	ents, err := os.ReadDir(keys)
	if err != nil || len(ents) != 1 || ents[0].Name() != "test-only-keys" {
		t.Fatalf("the key directory holds %v, %v; want only the folder test-only-keys", ents, err)
	}
	if inner, err := os.ReadDir(filepath.Join(keys, "test-only-keys")); err != nil || len(inner) != 0 {
		t.Errorf("the folder holds %v, %v; want no key", inner, err)
	}
	if st, err := os.Lstat(filepath.Join(keys, "test-only-keys")); err != nil || st.Mode() != fs.ModeDir|0o700 {
		t.Errorf("the folder is %v, %v", st, err)
	}
	// The cause is gone; the same saved plan runs to its end in the same key directory, and uses the folder.
	if err := os.Chmod(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	again := arRun(t, newTicker(apClock).now, strings.NewReader(""), false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest)
	if again.code != ExitOK {
		t.Fatalf("the next run: exit %d, %s %s", again.code, again.stdout, again.stderr)
	}
	if got, _ := os.ReadDir(filepath.Join(keys, "test-only-keys")); len(got) != 2 {
		t.Errorf("the folder holds %d entries after the next run, want the two keys", len(got))
	}
}

// A key directory that cannot take the folder of the keys stops the run at the key store, with the plan folder written
// and no attempt, no key and nothing in the key directory.
func TestAKeyDirectoryThatCannotTakeTheFolderOfTheKeysStopsTheRunAtTheKeyStoreAndMakesNoKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root makes a folder where the mode of the key directory says it cannot")
	}
	dir, keys := arBundle(t)
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	if err := os.Chmod(keys, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keys, 0o700) })
	beforeKeys := apSnapshot(t, keys)
	r := arRun(t, newTicker(apClock).now, nil, false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest)
	obj := apObject(t, r.stdout)
	msg, _ := obj["error"].(string)
	if r.code != ExitFailure || obj["outcome"] != "failed" {
		t.Fatalf("exit %d, %v", r.code, obj)
	}
	if _, ok := obj["reasons"]; ok {
		t.Errorf("a stop has reasons: %v", obj)
	}
	for _, want := range []string{"stopped at key-store", "the folder test-only-keys cannot be made in the key directory", "no key was made", "ritueel deleted nothing", "the empty folder test-only-keys may stand in the key directory"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the line does not say %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, keys) || strings.Contains(msg, filepath.Dir(keys)) {
		t.Errorf("the line holds a path: %s", msg)
	}
	if !apPrintable(msg) {
		t.Errorf("the line %+q is not printable ASCII", msg)
	}
	crqSame(t, "the stop at the key store, in the key directory", beforeKeys, apSnapshot(t, keys))
	if _, err := os.Stat(filepath.Join(dir, strings.TrimSuffix(path, "plan.json")+"attempt.json")); err == nil {
		t.Error("an attempt was written although the key store did not start")
	}
	if _, err := os.Stat(filepath.Join(dir, strings.TrimSuffix(path, "plan.json")+"plan.json")); err != nil {
		t.Errorf("the plan folder holds no plan: %v", err)
	}
}

// A saved plan of an earlier version names each key by the file of its key. The plan is refused, with the words that
// tell the person to make it again, before anything is written.
func TestAPlanThatNamesTheKeysByTheirFilesIsRefusedWithTheWordsToMakeThePlanAgain(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(plan []byte) []byte
		again bool // the line says to make the plan again
	}{
		{"the places of both keys as an earlier version wrote them", func(p []byte) []byte {
			p = bytes.ReplaceAll(p, []byte(`"place":"x509-root-a"`), []byte(`"place":"A.x509.key.pem"`))
			return bytes.ReplaceAll(p, []byte(`"place":"x509-root-b"`), []byte(`"place":"B.x509.key.pem"`))
		}, true},
		{"the place of the first key only", func(p []byte) []byte {
			return bytes.ReplaceAll(p, []byte(`"place":"x509-root-a"`), []byte(`"place":"A.x509.key.pem"`))
		}, true},
		{"a place of the new form with a capital", func(p []byte) []byte {
			return bytes.ReplaceAll(p, []byte(`"place":"x509-root-a"`), []byte(`"place":"x509-root-A"`))
		}, false},
		{"a place that is a path", func(p []byte) []byte {
			return bytes.ReplaceAll(p, []byte(`"place":"x509-root-a"`), []byte(`"place":"test-only-keys/x509-root-a.p8"`))
		}, false},
		{"the place of the other key", func(p []byte) []byte {
			return bytes.ReplaceAll(p, []byte(`"place":"x509-root-a"`), []byte(`"place":"x509-root-b"`))
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, keys := arBundle(t)
			path, _ := arPlan(t, apClock, dir, "--key-dir", keys)
			full := filepath.Join(dir, filepath.FromSlash(path))
			plan, err := os.ReadFile(full)
			if err != nil {
				t.Fatal(err)
			}
			edited := c.edit(bytes.Clone(plan))
			if bytes.Equal(edited, plan) {
				t.Fatal("the edit changed nothing")
			}
			if err := os.WriteFile(full, edited, 0o644); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(edited)
			digest := hex.EncodeToString(sum[:])
			beforeBundle, beforeKeys := apSnapshot(t, dir), apSnapshot(t, keys)
			r := arRun(t, newTicker(apClock).now, strings.NewReader(""), false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest)
			obj := apObject(t, r.stdout)
			if r.code == ExitOK {
				t.Fatalf("a plan of an earlier version was applied: %v", obj)
			}
			text := r.stderr + " " + r.stdout
			if got := strings.Contains(text, "make the plan again with apply --plan-only"); got != c.again {
				t.Errorf("the words to make the plan again are said = %v, want %v: %s", got, c.again, text)
			}
			if c.again && !strings.Contains(text, "x509-root-a") {
				t.Errorf("the line does not name the purpose that the key has now: %s", text)
			}
			if c.again && !strings.Contains(text, "nothing was written") {
				t.Errorf("the line does not say that nothing was written: %s", text)
			}
			crqSame(t, "the refused plan in the bundle", beforeBundle, apSnapshot(t, dir))
			crqSame(t, "the refused plan in the key directory", beforeKeys, apSnapshot(t, keys))
			t.Logf("exit %d: %s", r.code, strings.TrimSpace(r.stderr))
		})
	}
}

// socketsOfThisProcess returns the inodes of the sockets that the process holds open, and which of them listen,
// from /proc/self/fd and /proc/net.
func socketsOfThisProcess(t *testing.T) (all []string, listening []string) {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	var inodes []string
	for _, e := range ents {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue // the descriptor of the directory listing itself
		}
		if inode, ok := strings.CutPrefix(target, "socket:["); ok {
			inodes = append(inodes, strings.TrimSuffix(inode, "]"))
		}
	}
	listen := map[string]bool{}
	for _, f := range []string{"tcp", "tcp6"} { // state 0A is LISTEN
		b, err := os.ReadFile("/proc/net/" + f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n")[1:] {
			fields := strings.Fields(l)
			if len(fields) > 9 && fields[3] == "0A" {
				listen[fields[9]] = true
			}
		}
	}
	if b, err := os.ReadFile("/proc/net/unix"); err == nil { // flags 00010000 is a listening socket
		for _, l := range strings.Split(string(b), "\n")[1:] {
			fields := strings.Fields(l)
			if len(fields) > 6 && fields[3] == "00010000" {
				listen[fields[6]] = true
			}
		}
	}
	for _, f := range []string{"udp", "udp6", "raw", "raw6"} { // a bound datagram socket receives: count each as one that listens
		if b, err := os.ReadFile("/proc/net/" + f); err == nil {
			for _, l := range strings.Split(string(b), "\n")[1:] {
				if fields := strings.Fields(l); len(fields) > 9 {
					listen[fields[9]] = true
				}
			}
		}
	}
	for _, in := range inodes {
		if listen[in] {
			listening = append(listening, in)
		}
	}
	slices.Sort(inodes)
	return inodes, listening
}

// During a whole first apply the process holds no socket that it did not hold before, and none listens.
func TestAnApplyOpensNoSocketAndNothingListens(t *testing.T) {
	// The probe sees a socket that listens: the test would pass for the wrong reason if it did not.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot make a socket to try the probe: %v", err)
	}
	if all, listening := socketsOfThisProcess(t); len(all) == 0 || len(listening) == 0 {
		t.Fatalf("the probe sees %d sockets and %d that listen, with one that listens open", len(all), len(listening))
	}
	_ = l.Close()
	if _, listening := socketsOfThisProcess(t); len(listening) != 0 {
		t.Fatalf("a socket listens after the probe's own was closed: %v", listening)
	}

	dir, keys := arBundle(t)
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	before, _ := socketsOfThisProcess(t)
	var (
		mu    sync.Mutex
		seen  = map[string]bool{}
		onair = map[string]bool{}
		done  = make(chan struct{})
		wg    sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			all, listening := socketsOfThisProcess(t)
			mu.Lock()
			for _, in := range all {
				if !slices.Contains(before, in) {
					seen[in] = true
				}
			}
			for _, in := range listening {
				onair[in] = true
			}
			mu.Unlock()
			time.Sleep(200 * time.Microsecond)
		}
	}()
	r := arRun(t, newTicker(apClock).now, strings.NewReader(""), false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest)
	close(done)
	wg.Wait()
	if r.code != ExitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	after, listening := socketsOfThisProcess(t)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 0 || len(onair) != 0 || len(listening) != 0 || !slices.Equal(before, after) {
		t.Errorf("the apply held sockets %v, listening %v; after the apply %v listening %v; before %v", seen, onair, after, listening, before)
	}
}
