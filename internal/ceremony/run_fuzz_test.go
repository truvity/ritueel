//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// The fuzz targets of what a run reads from outside: the path of a saved plan, the file of a saved
// plan, the line that a person types, and a whole run of a saved plan that is never confirmed. No
// target starts an outside program.

func FuzzCheckPlanPath(f *testing.F) {
	for _, s := range []string{
		"history/" + pfName + "/plan.json", "history/a/plan.json", "", "plan.json", "/history/x/plan.json",
		"history/../plan.json", "history/x/plan.json/", "history//plan.json", "history/x\\y/plan.json",
		"history/\xff/plan.json", "history/x\x00/plan.json", strings.Repeat("history/", 13) + "plan.json",
		"history/" + strings.Repeat("a", 300) + "/plan.json", "history/.rt-x/plan.json", "history/а/plan.json",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		name, err := ceremony.CheckPlanPath(path)
		if err != nil {
			var u *ceremony.UsageError
			if name != "" || !errors.As(err, &u) || !pfPrintable(err.Error()) {
				t.Fatalf("CheckPlanPath(%+q) = %q, %v", path, name, err)
			}
			return
		}
		if path != "history/"+name+"/plan.json" || name == "" || fsx.CheckName(name) != nil || files.CheckPath(path) != nil {
			t.Fatalf("CheckPlanPath(%+q) accepted %q", path, name)
		}
	})
}

// rtFuzzBundle is a bundle folder that a fuzz target uses once and for all, made before the first input.
type rtFuzzBundle struct {
	dir, keys string
	w         *fsx.Writer
}

func newFuzzBundle(f *testing.F) *rtFuzzBundle {
	f.Helper()
	root := f.TempDir()
	b := &rtFuzzBundle{dir: filepath.Join(root, "ca"), keys: filepath.Join(root, "keys")}
	for _, d := range []string{b.dir, b.keys} {
		if err := os.Mkdir(d, 0o700); err != nil {
			f.Fatal(err)
		}
	}
	for p, text := range pfFiles() {
		full := filepath.Join(b.dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			f.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			f.Fatal(err)
		}
	}
	w, err := fsx.Open(b.dir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = w.Close() })
	b.w = w
	return b
}

func FuzzReadSavedPlan(f *testing.F) {
	b := newFuzzBundle(f)
	folder := filepath.Join(b.dir, "history", pfName)
	if err := os.MkdirAll(folder, 0o755); err != nil {
		f.Fatal(err)
	}
	path := "history/" + pfName + "/plan.json"
	golden := []byte(pfGolden)
	f.Add(golden)
	f.Add(golden[:len(golden)/2])
	f.Add(append(append([]byte(nil), golden...), '\n'))
	f.Add(bytes.Replace(golden, []byte(pfName), []byte("20261120T100001Z-apply"), 1))
	f.Add(bytes.Replace(golden, []byte(`"version":1`), []byte(`"version":2`), 1))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(strings.Repeat("[", 20000)))
	f.Add(bytes.Repeat([]byte(" "), 300<<10))
	f.Add([]byte("\xef\xbb\xbf" + pfGolden))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(filepath.Join(folder, "plan.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		p, err := ceremony.ReadSavedPlan(b.w.FS, path)
		if err != nil {
			if p != nil || !pfPrintable(err.Error()) {
				t.Fatalf("ReadSavedPlan = %v, %v", p, err)
			}
			return
		}
		if !bytes.Equal(p.JSON, data) || p.SHA256 != files.Digest(data) || p.Name != pfName {
			t.Fatalf("an accepted plan is not the file: name %q", p.Name)
		}
	})
}

// FuzzRunSavedPlan runs a saved plan whose three files are the input, with a confirmation that is
// never the digest of the plan: whatever the plan, the run writes nothing, in the bundle or in the key
// directory, and ends with an error.
func FuzzRunSavedPlan(f *testing.F) {
	b := newFuzzBundle(f)
	folder := filepath.Join(b.dir, "history", pfName)
	if err := os.MkdirAll(filepath.Join(folder, "wanted", "want", "roots"), 0o755); err != nil {
		f.Fatal(err)
	}
	path := "history/" + pfName + "/plan.json"
	golden := []byte(pfGolden)
	f.Add(golden, []byte(pfSettings), []byte(pfX509Test))
	f.Add(golden, []byte(pfSettings), []byte(pfX509Real))
	f.Add(golden, []byte(pfPersonal), []byte(pfX509Test))
	f.Add(golden, []byte("version: 1\nname: Other\n"), []byte(pfX509Test))
	f.Add(golden, []byte(""), []byte(""))
	f.Add(bytes.Replace(golden, []byte(`"x509/A"`), []byte(`"x509/C"`), 1), []byte(pfSettings), []byte(pfX509Test))
	f.Add([]byte(`{"version":1}`), []byte(pfSettings), []byte(pfX509Test))
	f.Add(golden, []byte("\xff\xfe"), []byte(strings.Repeat("a: [", 5000)))
	f.Fuzz(func(t *testing.T, plan, settings, root []byte) {
		for p, data := range map[string][]byte{
			"plan.json":                   plan,
			"wanted/ritueel.yaml":         settings,
			"wanted/want/roots/x509.yaml": root,
		} {
			if err := os.WriteFile(filepath.Join(folder, filepath.FromSlash(p)), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		saved, err := ceremony.ReadSavedPlan(b.w.FS, path)
		if err != nil {
			return
		}
		before, keys := tree(t, b.dir), tree(t, b.keys)
		out := &rtBuf{}
		in := ceremony.RunIn{
			Writer: b.w, Env: ceremony.Env{Now: rtFixed, Rand: &pfCounter{}, Self: pfSelf, Out: ceremony.NewConsole(out, out)},
			Plan: saved, Saved: true, KeyDir: b.keys, BundleDir: b.dir,
			Confirm: ceremony.Confirm{Flag: true, Digest: strings.Repeat("0", 64)},
		}
		done, err := ceremony.Run(context.Background(), in)
		if done != nil || err == nil {
			t.Fatalf("Run with a wrong digest = %v, %v", done, err)
		}
		if _, stopped := rtStopped(err); stopped {
			t.Fatalf("a run that was not confirmed is a stop: %v", err)
		}
		if !pfPrintable(err.Error()) {
			t.Fatalf("the text %+q is not printable ASCII", err.Error())
		}
		if d := treeDiff(before, tree(t, b.dir)); d != "" {
			t.Fatalf("a run that was not confirmed changed the bundle:\n%s", d)
		}
		if d := treeDiff(keys, tree(t, b.keys)); d != "" {
			t.Fatalf("a run that was not confirmed changed the key directory:\n%s", d)
		}
	})
}
