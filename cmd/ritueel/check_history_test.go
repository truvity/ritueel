//go:build linux || darwin

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The command "ritueel check history", run as the program that the release builds: its exit
// code, its standard output and its standard error, on bundles that this test spells out by hand
// (every file written here, every digest worked out with crypto/sha256). The default folder, ".",
// needs a working folder of the process, so these runs set the folder of the process and not the
// folder of the test.

func sumOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func putFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// makeBundle writes a clean bundle of n ceremonies and returns its folder, the digest of its newest
// record, and the path of the keys of the newest trust set.
func makeBundle(t *testing.T, n int) (dir, end, keys string) {
	t.Helper()
	dir = t.TempDir()
	putFile(t, dir, "ritueel.yaml", "name: test\n")
	prev := ""
	for i := 1; i <= n; i++ {
		ns := fmt.Sprint(i)
		folder := fmt.Sprintf("2026%04dT100000Z-apply", i)
		set := fmt.Sprintf("%d-3fa9c1d%d", i, i)
		wanted := "name: bundle " + ns + "\n"
		transcript := "ceremony " + ns + "\n"
		keysText := "keys of set " + ns + "\n"
		rootList := `{"version":1}`
		plan := `{"ceremony":"` + folder + `","command":"apply","trust_sequence":` + ns + `,"version":1,"wanted":[{"path":"ritueel.yaml","sha256":"` + sumOf(wanted) + `"}]}`
		if prev != "" {
			rootList = `{"last_record_sha256":"` + prev + `","version":1}`
			plan = `{"ceremony":"` + folder + `","command":"apply","last_record_sha256":"` + prev + `","trust_sequence":` + ns + `,"version":1,"wanted":[{"path":"ritueel.yaml","sha256":"` + sumOf(wanted) + `"}]}`
		}
		attempt := `{"ceremony":"` + folder + `","plan_sha256":"` + sumOf(plan) + `","version":1}`
		record := `{"artifacts":[` +
			`{"path":"trust/` + set + `/keys.txt","sha256":"` + sumOf(keysText) + `"},` +
			`{"path":"trust/` + set + `/root-list.json","sha256":"` + sumOf(rootList) + `"}],` +
			`"ceremony":"` + folder + `","command":"apply","outcome":"completed","plan_sha256":"` + sumOf(plan) + `",`
		if prev != "" {
			record += `"prev_record_sha256":"` + prev + `",`
		}
		record += `"transcript_sha256":"` + sumOf(transcript) + `","trust_sequence":` + ns + `,"version":1,` +
			`"wanted":[{"path":"ritueel.yaml","sha256":"` + sumOf(wanted) + `"}]}`
		base := "history/" + folder + "/"
		putFile(t, dir, base+"plan.json", plan)
		putFile(t, dir, base+"attempt.json", attempt)
		putFile(t, dir, base+"wanted/ritueel.yaml", wanted)
		putFile(t, dir, base+"transcript.txt", transcript)
		putFile(t, dir, "trust/"+set+"/keys.txt", keysText)
		putFile(t, dir, "trust/"+set+"/root-list.json", rootList)
		putFile(t, dir, base+"record.json", record)
		prev = sumOf(record)
		keys = "trust/" + set + "/keys.txt"
	}
	return dir, prev, keys
}

// buildForCheck builds the program the way the release builds it.
func buildForCheck(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is not on PATH: cannot build the program for this test")
	}
	readSources(t)
	exe := filepath.Join(t.TempDir(), "ritueel")
	build := exec.CommandContext(t.Context(), goBin, "build", "-trimpath", "-o", exe, "ritueel.id/ritueel/cmd/ritueel")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	return exe
}

func TestProgramCheckHistory(t *testing.T) {
	exe := buildForCheck(t)
	runIn := func(t *testing.T, workDir string, args ...string) (code int, stdout, stderr string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), exe, args...)
		cmd.Dir = workDir
		var out, errOut bytes.Buffer
		cmd.Stdin = strings.NewReader("")
		cmd.Stdout = &out
		cmd.Stderr = &errOut
		err := cmd.Run()
		var ee *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &ee):
			code = ee.ExitCode()
		default:
			t.Fatalf("running the program: %v", err)
		}
		return code, out.String(), errOut.String()
	}

	t.Run("a clean bundle", func(t *testing.T) {
		dir, end, _ := makeBundle(t, 3)
		want := "history: 3 ceremony records, end " + end[:8] + "\n"
		code, stdout, stderr := runIn(t, t.TempDir(), "check", "history", "--dir", dir)
		if code != 0 || stdout != want || stderr != "" {
			t.Errorf("exit %d, stdout %q, stderr %q; want 0, %q and nothing", code, stdout, stderr, want)
		}
	})

	t.Run("a clean bundle as JSON", func(t *testing.T) {
		dir, _, _ := makeBundle(t, 2)
		code, stdout, stderr := runIn(t, t.TempDir(), "check", "history", "--dir", dir, "--output", "json")
		if code != 0 || stderr != "" {
			t.Errorf("exit %d, stderr %q", code, stderr)
		}
		if strings.Count(stdout, "\n") != 1 || !strings.HasSuffix(stdout, "\n") {
			t.Fatalf("stdout is not one line: %q", stdout)
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(stdout), &obj); err != nil {
			t.Fatalf("stdout is not a JSON object: %v: %q", err, stdout)
		}
		want := map[string]any{
			"output": float64(1), "command": "check", "exit_code": float64(0), "outcome": "done", "warnings": []any{},
		}
		if !reflect.DeepEqual(obj, want) {
			t.Errorf("object = %#v, want %#v", obj, want)
		}
	})

	t.Run("a changed byte", func(t *testing.T) {
		dir, _, keys := makeBundle(t, 3)
		p := filepath.Join(dir, filepath.FromSlash(keys))
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		data[0] ^= 0x01
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runIn(t, t.TempDir(), "check", "history", "--dir", dir)
		if code != 3 || stdout != "" {
			t.Errorf("exit %d, stdout %q; want 3 and nothing on standard output", code, stdout)
		}
		lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "file-digest "+keys+": ") || lines[1] != "ritueel: refused: file-digest" {
			t.Errorf("stderr = %q", stderr)
		}
		code, stdout, stderr2 := runIn(t, t.TempDir(), "check", "history", "--dir", dir, "--output", "json")
		if code != 3 || stderr2 != stderr {
			t.Errorf("JSON: exit %d; stderr %q differs from %q", code, stderr2, stderr)
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(stdout), &obj); err != nil {
			t.Fatalf("stdout is not a JSON object: %v: %q", err, stdout)
		}
		if !reflect.DeepEqual(obj["reasons"], []any{"file-digest"}) || obj["outcome"] != "refused" || obj["exit_code"] != float64(3) {
			t.Errorf("object = %#v", obj)
		}
		if _, ok := obj["error"]; ok {
			t.Errorf("a refusal has an error member: %#v", obj)
		}
	})

	// The default folder is the current folder of the process, when it holds ritueel.yaml.
	t.Run("the working folder holds the manifest", func(t *testing.T) {
		dir, end, _ := makeBundle(t, 3)
		want := "history: 3 ceremony records, end " + end[:8] + "\n"
		code, stdout, stderr := runIn(t, dir, "check", "history")
		if code != 0 || stdout != want || stderr != "" {
			t.Errorf("exit %d, stdout %q, stderr %q; want 0, %q and nothing", code, stdout, stderr, want)
		}
	})

	t.Run("the working folder holds no manifest", func(t *testing.T) {
		dir, _, _ := makeBundle(t, 3)
		if err := os.Remove(filepath.Join(dir, "ritueel.yaml")); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runIn(t, dir, "check", "history")
		if code != 2 || stdout != "" || !strings.Contains(stderr, "--dir") {
			t.Errorf("exit %d, stdout %q, stderr %q; want 2, nothing and a text that names --dir", code, stdout, stderr)
		}
		// With --dir the stick's copy, which has no manifest, is checked.
		code, stdout, _ = runIn(t, t.TempDir(), "check", "history", "--dir", dir)
		if code != 0 || !strings.HasPrefix(stdout, "history: 3 ceremony records, end ") {
			t.Errorf("--dir: exit %d, stdout %q", code, stdout)
		}
	})

	t.Run("an argument", func(t *testing.T) {
		dir, _, _ := makeBundle(t, 1)
		code, stdout, stderr := runIn(t, dir, "check", "history", "extra")
		if code != 2 || stdout != "" || stderr == "" {
			t.Errorf("exit %d, stdout %q, stderr %q; want 2, nothing and a message", code, stdout, stderr)
		}
	})

	t.Run("a link to a bundle is not followed", func(t *testing.T) {
		dir, _, _ := makeBundle(t, 1)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runIn(t, t.TempDir(), "check", "history", "--dir", link)
		if code != 1 || stdout != "" || stderr == "" {
			t.Errorf("exit %d, stdout %q, stderr %q; want 1, nothing and a message", code, stdout, stderr)
		}
	})

	t.Run("a folder that is not a bundle", func(t *testing.T) {
		code, stdout, stderr := runIn(t, t.TempDir(), "check", "history", "--dir", t.TempDir())
		if code != 1 || stdout != "" || !strings.Contains(stderr, "not a bundle") {
			t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
}
