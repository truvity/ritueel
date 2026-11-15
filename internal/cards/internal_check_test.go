//go:build linux || darwin

package cards

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// Check stops only for a finding that refuses. Both codes of this version refuse, so a code that does not is
// made for the test by changing the table, and the table is put back.
func TestCheckIgnoresAFindingThatDoesNotRefuseAndNamesTheFirstThatDoes(t *testing.T) {
	dir := t.TempDir()
	card := "version: 1\nserial: \"1\"\nkind: server\napplications: [piv]\n"
	files := map[string]string{"a.yaml": card, "b.yaml": card, "c.yaml": "version: 2\n"}
	if err := os.MkdirAll(filepath.Join(dir, "want", "cards"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, "want", "cards", name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fsys.Close() }()
	defer func(old bool) { refuses[SerialTwice] = old }(refuses[SerialTwice])
	refuses[SerialTwice] = false
	// The findings are the invalid file c (refuses) and the twin b (does not): the first is named, with no count.
	err = Check(t.Context(), fsys)
	var we *wanted.Error
	if !errors.As(err, &we) || we.Path != "want/cards/c.yaml" {
		t.Fatalf("Check = %v, want a fault at want/cards/c.yaml", err)
	}
	if strings.Contains(we.Msg, "more") {
		t.Errorf("the text %q counts a finding that does not refuse", we.Msg)
	}
	// Only the twin: nothing refuses, so Check is nil.
	if err := os.Remove(filepath.Join(dir, "want", "cards", "c.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := Check(t.Context(), fsys); err != nil {
		t.Errorf("Check = %v, want nil for a finding that does not refuse", err)
	}
	rep, err := Inspect(t.Context(), fsys)
	if err != nil || len(rep.Findings) != 1 || !rep.Clean() {
		t.Errorf("Inspect = %+v, %v", rep, err)
	}
}
