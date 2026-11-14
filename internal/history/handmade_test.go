//go:build linux || darwin

package history

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The clean bundle of three ceremonies, written a second way: every byte is spelled out here and
// every digest is worked out with crypto/sha256, with no use of the package's Canonical methods,
// of files.Digest or of the builder in bundle_test.go. A fault that the writer and the reader of
// the package share (a member that is written under one name and read under the same wrong name,
// a digest of the wrong bytes) cannot hide in this bundle.

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

type handmade struct {
	dir     string
	digests [3]string // of the three record.json files
}

func writeHand(t testing.TB, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func handmadeBundle(t testing.TB) handmade {
	t.Helper()
	h := handmade{dir: t.TempDir()}
	writeHand(t, h.dir, "ritueel.yaml", "name: test\n")
	if err := os.MkdirAll(filepath.Join(h.dir, "history"), 0o755); err != nil {
		t.Fatal(err)
	}
	folders := [3]string{"20260001T100000Z-apply", "20260002T100000Z-apply", "20260003T100000Z-apply"}
	sets := [3]string{"1-3fa9c1d3", "2-3fa9c1d4", "3-3fa9c1d5"}
	numbers := [3]string{"1", "2", "3"}
	prev := ""
	for i := 0; i < 3; i++ {
		c, set, n := folders[i], sets[i], numbers[i]
		wanted := "name: bundle " + n + "\n"
		transcript := "ceremony " + n + "\n"
		keys := "keys of set " + n + "\n"
		rootList := `{"version":1}`
		plan := `{"ceremony":"` + c + `","command":"apply","trust_sequence":` + n + `,"version":1,"wanted":[{"path":"ritueel.yaml","sha256":"` + sum(wanted) + `"}]}`
		if prev != "" {
			rootList = `{"last_record_sha256":"` + prev + `","version":1}`
			plan = `{"ceremony":"` + c + `","command":"apply","last_record_sha256":"` + prev + `","trust_sequence":` + n + `,"version":1,"wanted":[{"path":"ritueel.yaml","sha256":"` + sum(wanted) + `"}]}`
		}
		attempt := `{"ceremony":"` + c + `","plan_sha256":"` + sum(plan) + `","version":1}`
		record := `{"artifacts":[` +
			`{"path":"trust/` + set + `/keys.txt","sha256":"` + sum(keys) + `"},` +
			`{"path":"trust/` + set + `/root-list.json","sha256":"` + sum(rootList) + `"}],` +
			`"ceremony":"` + c + `","command":"apply","outcome":"completed","plan_sha256":"` + sum(plan) + `",`
		if prev != "" {
			record += `"prev_record_sha256":"` + prev + `",`
		}
		record += `"transcript_sha256":"` + sum(transcript) + `","trust_sequence":` + n + `,"version":1,` +
			`"wanted":[{"path":"ritueel.yaml","sha256":"` + sum(wanted) + `"}]}`
		base := "history/" + c + "/"
		writeHand(t, h.dir, base+"plan.json", plan)
		writeHand(t, h.dir, base+"attempt.json", attempt)
		writeHand(t, h.dir, base+"wanted/ritueel.yaml", wanted)
		writeHand(t, h.dir, base+"transcript.txt", transcript)
		writeHand(t, h.dir, "trust/"+set+"/keys.txt", keys)
		writeHand(t, h.dir, "trust/"+set+"/root-list.json", rootList)
		writeHand(t, h.dir, base+"record.json", record)
		prev = sum(record)
		h.digests[i] = prev
	}
	return h
}

// tree reads every file of a folder: the path, "/" separated, to the bytes.
func tree(t testing.TB, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			out[filepath.ToSlash(rel)] = string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestHandmadeBundleIsClean(t *testing.T) {
	h := handmadeBundle(t)
	rep := runDir(t, h.dir)
	wantFindings(t, rep, nil)
	if rep.Records != 3 {
		t.Errorf("Records = %d, want 3", rep.Records)
	}
	if want := []string{h.digests[2]}; !slices.Equal(rep.Ends, want) {
		t.Errorf("Ends = %v, want %v", rep.Ends, want)
	}
	eight, count, ok := rep.End()
	if !ok || count != 3 || eight != h.digests[2][:8] {
		t.Errorf("End() = %q, %d, %v; want %q, 3, true", eight, count, ok, h.digests[2][:8])
	}
	if want := "history: 3 ceremony records, end " + h.digests[2][:8]; rep.EndLine() != want {
		t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
	}
	if !rep.Clean() || len(rep.Reasons()) != 0 || len(rep.Warnings()) != 0 {
		t.Errorf("not clean: Clean %v, reasons %v, warnings %v", rep.Clean(), rep.Reasons(), rep.Warnings())
	}
}

// The bundle that the builder writes with the Canonical methods holds the same bytes as the
// bundle spelled out by hand, file for file: the writer of the package writes the canonical form
// of the page, and the digests it computes are the SHA-256 of those bytes.
func TestBuilderWritesTheBytesOfTheHandmadeBundle(t *testing.T) {
	h := handmadeBundle(t)
	b := newBundle(t)
	b.apply()
	b.apply()
	b.apply()
	want, got := tree(t, h.dir), tree(t, b.dir)
	for p, w := range want {
		g, ok := got[p]
		if !ok {
			t.Errorf("the builder did not write %s", p)
			continue
		}
		if g != w {
			t.Errorf("%s differs:\n builder %s\n by hand %s", p, strings.TrimSpace(g), strings.TrimSpace(w))
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			t.Errorf("the builder wrote %s, which the bundle by hand does not hold", p)
		}
	}
	if got := b.recs[2].digest; got != h.digests[2] {
		t.Errorf("the end of the builder's bundle is %s, by hand %s", got, h.digests[2])
	}
}
