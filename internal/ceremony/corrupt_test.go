package ceremony_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/fsx"
)

// A file that the disk holds with other bytes than were written is found when it is read back, and
// stops the folder: the write is done and nothing is deleted.
func TestAFileThatIsNotWhatWasWrittenStopsTheFolder(t *testing.T) {
	// Find the number of the write of each file in a whole run.
	b0 := newBundle(t)
	newFlow(t, b0, newSpec(name1, 1, "")).must("")
	var order []string
	for _, e := range b0.r.snapshot() {
		if strings.HasPrefix(e, "write ") {
			order = append(order, strings.TrimPrefix(e, "write "))
		}
	}
	d := "history/" + name1 + "/"
	nth := func(path string, last bool) int {
		n := 0
		for i, p := range order {
			if p == path {
				n = i + 1
				if !last {
					return n
				}
			}
		}
		return n
	}
	cases := []struct {
		name  string
		write int
		stage string
		files []string // that do not exist after the stop
	}{
		{"plan.json", nth(d+"(tmp)", false), "plan", []string{"wanted", "attempt.json"}},
		{"attempt.json", 4, "start", []string{"births.jsonl", "signatures.jsonl"}},
		{"record.json", nth(d+"(tmp)", true), "record", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.write == 0 {
				t.Fatal("the write was not found")
			}
			dir := t.TempDir()
			if err := os.WriteFile(dir+"/ritueel.yaml", []byte(manifestText), 0o644); err != nil {
				t.Fatal(err)
			}
			b := openBundle(t, dir, 0)
			b.r.corruptAt = c.write
			fl := newFlow(t, b, newSpec(name1, 1, ""))
			err := fl.run("")
			if err == nil {
				t.Fatal("a file that is not what was written was taken")
			}
			if !strings.HasPrefix(err.Error(), "stage "+c.stage+":") {
				t.Errorf("the fault is found at %v, want the stage %s", err, c.stage)
			}
			wantKind(t, errors.Unwrap(err), ceremony.ErrFolderStopped, ceremony.ErrDiskMismatch)
			// The folder is stopped; the writer is not, since its own write was whole.
			for call, fn := range calls(t, fl.s, fl.s.plan(t)) {
				e := fn(fl.f)
				if e == nil || !errors.Is(e, ceremony.ErrFolderStopped) {
					t.Errorf("%s after the fault: %v, want an error that says the folder is stopped", call, e)
				}
			}
			for _, name := range c.files {
				path := b.path("history", name1, name)
				if _, err := os.Lstat(path); err == nil && c.stage != "record" {
					t.Errorf("%s was written after the fault", name)
				}
			}
			if c.stage == "start" && fl.tr != nil {
				t.Error("Start returned a Trace with its error")
			}
			_ = fsx.ErrStopped
		})
	}
}
