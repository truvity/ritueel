package answer_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff/answer"
)

func openDir(t *testing.T, dir string) fsx.FS {
	t.Helper()
	root, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAnswerReadsTheFilesOfTheStemAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "in", "example-answer.result.json"), []byte("R"))
	write(t, filepath.Join(dir, "in", "example-answer.cert.pem"), []byte("C"))
	write(t, filepath.Join(dir, "in", "example-answer.bound.pgp"), []byte("B"))
	write(t, filepath.Join(dir, "in", "example-answer.result.json.bak"), []byte("X"))
	write(t, filepath.Join(dir, "in", "other.cert.pem"), []byte("Y"))
	write(t, filepath.Join(dir, "in", "example-answer.csr.pem"), []byte("Z"))
	root := openDir(t, dir)
	a, err := answer.LoadAnswer(root, "in", "example-answer")
	if err != nil {
		t.Fatal(err)
	}
	if a.Stem != "example-answer" || len(a.Files) != 3 || string(a.Files["result.json"]) != "R" || string(a.Files["cert.pem"]) != "C" || string(a.Files["bound.pgp"]) != "B" {
		t.Errorf("answer %+v", a)
	}
	t.Run("a file that is not there has no entry", func(t *testing.T) {
		a, err := answer.LoadAnswer(root, "in", "other")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := a.Files["result.json"]; ok || len(a.Files) != 1 || string(a.Files["cert.pem"]) != "Y" {
			t.Errorf("files %v", a.Files)
		}
	})
	t.Run("the root itself as the folder", func(t *testing.T) {
		write(t, filepath.Join(dir, "example-top.cert.pem"), []byte("T"))
		a, err := answer.LoadAnswer(root, ".", "example-top")
		if err != nil || string(a.Files["cert.pem"]) != "T" {
			t.Fatalf("%v %v", err, a)
		}
	})
}

// Nothing came back: there is nothing to judge, and that is the problem of the caller, not a verdict.
func TestLoadAnswerOfNoFileIsAnErrorOfTheCaller(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "in", "example-answer.result.json"), []byte("R"))
	write(t, filepath.Join(dir, "in", "example-answer.result.json.bak"), []byte("X"))
	write(t, filepath.Join(dir, "in", "example-answer.csr.pem"), []byte("Z"))
	write(t, filepath.Join(dir, "in", "other.cert.pem"), []byte("Y"))
	write(t, filepath.Join(dir, "empty", "keep"), nil)
	root := openDir(t, dir)
	for name, c := range map[string]struct{ dir, stem string }{
		"a folder that is not there":                {"nowhere", "example-answer"},
		"a folder below a folder that is not there": {"nowhere/deeper", "example-answer"},
		"a stem with a typing mistake":              {"in", "example-anwser"},
		"a stem that is the start of a real one":    {"in", "example"},
		"a stem that is the end of a real one":      {"in", "answer"},
		"an empty folder":                           {"empty", "example-answer"},
		"a folder that holds only files of others":  {"in", "third"},
		"the root, which holds no answer":           {".", "example-answer"},
		"a file that is a folder of the same name":  {".", "in"},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := answer.LoadAnswer(root, c.dir, c.stem)
			if !errors.Is(err, answer.ErrLoad) || a != nil {
				t.Fatalf("error %v, answer %v", err, a)
			}
			if strings.ContainsAny(err.Error(), "\n\r\x00") {
				t.Errorf("the text of the error is not one printable line: %q", err)
			}
		})
	}
	t.Run("the error is not a verdict: Check is never reached, and no verdict is made", func(t *testing.T) {
		k := newKit(t)
		a, err := answer.LoadAnswer(root, "nowhere", "example-answer")
		if err == nil || a != nil {
			t.Fatalf("error %v, answer %v", err, a)
		}
		// What the caller may do with the nil Answer is Check's own rule: a nil Answer is not judged.
		x := k.newX509(nil)
		v, cerr := k.checker(nil).Check(x.csr.asked(t), a)
		if cerr == nil && v.Accepted() {
			t.Fatalf("a nil Answer is accepted: %+v", v)
		}
	})
	t.Run("one file of the three is an Answer, whatever the others lack", func(t *testing.T) {
		for _, suffix := range []string{"result.json", "cert.pem", "bound.pgp"} {
			one := t.TempDir()
			write(t, filepath.Join(one, "in", "example-answer."+suffix), []byte("F"))
			a, err := answer.LoadAnswer(openDir(t, one), "in", "example-answer")
			if err != nil {
				t.Fatalf("%s: %v", suffix, err)
			}
			if a.Stem != "example-answer" || len(a.Files) != 1 || string(a.Files[suffix]) != "F" {
				t.Errorf("%s: answer %+v", suffix, a)
			}
		}
	})
	t.Run("a file that is empty is a file", func(t *testing.T) {
		one := t.TempDir()
		write(t, filepath.Join(one, "in", "example-answer.cert.pem"), nil)
		a, err := answer.LoadAnswer(openDir(t, one), "in", "example-answer")
		if err != nil || len(a.Files) != 1 {
			t.Fatalf("error %v, answer %+v", err, a)
		}
		if _, ok := a.Files["cert.pem"]; !ok {
			t.Errorf("an empty file has no entry: %+v", a.Files)
		}
	})
	t.Run("an Answer made by hand with no file is judged malformed by Check, as before", func(t *testing.T) {
		k := newKit(t)
		x := k.newX509(nil)
		for _, a := range []*answer.Answer{
			{Stem: "example-answer"},
			{Stem: "example-answer", Files: map[string][]byte{}},
		} {
			v, err := k.checker(nil).Check(x.csr.asked(t), a)
			if err != nil || v.Accepted() || v.Code != answer.CodeMalformed {
				t.Errorf("%v code %q accepted %v", err, v.Code, v.Accepted())
			}
		}
	})
}

func TestLoadAnswerRefusesWhatIsNotAnAnswerFolder(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "in", "example-answer.result.json"), []byte("R"))
	// The files of the stems that are refused are there, so that only the rule of the stem refuses them.
	for _, stem := range []string{"Example", "-a", "a.b", "a", strings.Repeat("a", 64)} {
		for _, suffix := range []string{"result.json", "cert.pem", "bound.pgp"} {
			write(t, filepath.Join(dir, "in", stem+"."+suffix), []byte("F"))
		}
	}
	write(t, filepath.Join(dir, "in", "a", "b.result.json"), []byte("F"))
	root := openDir(t, dir)
	for name, c := range map[string]struct {
		root fsx.FS
		dir  string
		stem string
	}{
		"a nil root":                {nil, "in", "example-answer"},
		"a stem in capitals":        {root, "in", "Example"},
		"no stem":                   {root, "in", ""},
		"a stem with a dot":         {root, "in", "a.b"},
		"a stem with a slash":       {root, "in", "a/b"},
		"a stem of 64 characters":   {root, "in", strings.Repeat("a", 64)},
		"a stem that starts with -": {root, "in", "-a"},
		"a folder above the root":   {root, "../in", "example-answer"},
		"a folder with dots":        {root, "in/../in", "example-answer"},
		"an absolute folder":        {root, "/in", "example-answer"},
		"an empty folder":           {root, "", "example-answer"},
		"a folder with two slashes": {root, "in//x", "example-answer"},
		"a folder with a backslash": {root, `in\x`, "example-answer"},
		"a folder with a nul":       {root, "in\x00", "example-answer"},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := answer.LoadAnswer(c.root, c.dir, c.stem)
			if !errors.Is(err, answer.ErrLoad) || a != nil {
				t.Fatalf("error %v, answer %v", err, a)
			}
		})
	}
	t.Run("a stem of 63 characters is a stem", func(t *testing.T) {
		stem := strings.Repeat("a", 63)
		write(t, filepath.Join(dir, "in", stem+".cert.pem"), []byte("C"))
		a, err := answer.LoadAnswer(root, "in", stem)
		if err != nil || a.Stem != stem || string(a.Files["cert.pem"]) != "C" {
			t.Fatalf("error %v, answer %+v", err, a)
		}
	})
}

func TestLoadAnswerFollowsNoLinkAndNeverWaitsOnAPipe(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "outside", "secret.txt")
	write(t, secret, []byte("secret"))
	in := filepath.Join(dir, "in")
	write(t, filepath.Join(in, "x.keep"), nil)
	root := openDir(t, in)
	t.Run("a link in place of a file", func(t *testing.T) {
		if err := os.Symlink(secret, filepath.Join(in, "linked.result.json")); err != nil {
			t.Fatal(err)
		}
		a, err := answer.LoadAnswer(root, ".", "linked")
		if !errors.Is(err, answer.ErrLoad) || a != nil {
			t.Fatalf("error %v, answer %v", err, a)
		}
	})
	t.Run("a link to a file that is not there", func(t *testing.T) {
		if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(in, "dangling.cert.pem")); err != nil {
			t.Fatal(err)
		}
		a, err := answer.LoadAnswer(root, ".", "dangling")
		if !errors.Is(err, answer.ErrLoad) || a != nil {
			t.Fatalf("error %v, answer %v", err, a)
		}
	})
	t.Run("a link in place of the folder", func(t *testing.T) {
		write(t, filepath.Join(dir, "real", "example-answer.cert.pem"), []byte("C"))
		if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(in, "sub")); err != nil {
			t.Fatal(err)
		}
		a, err := answer.LoadAnswer(root, "sub", "example-answer")
		if !errors.Is(err, answer.ErrLoad) || a != nil {
			t.Fatalf("error %v, answer %v", err, a)
		}
	})
	t.Run("a folder in place of a file", func(t *testing.T) {
		if err := os.Mkdir(filepath.Join(in, "dir.result.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		a, err := answer.LoadAnswer(root, ".", "dir")
		if !errors.Is(err, answer.ErrLoad) || a != nil {
			t.Fatalf("error %v, answer %v", err, a)
		}
	})
	t.Run("a pipe in place of a file", func(t *testing.T) {
		if err := syscall.Mkfifo(filepath.Join(in, "pipe.result.json"), 0o600); err != nil {
			t.Skipf("no pipe: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := answer.LoadAnswer(root, ".", "pipe")
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, answer.ErrLoad) {
				t.Fatalf("error %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("LoadAnswer waits on a pipe")
		}
	})
}

func TestLoadAnswerCutsAFileThatIsTooLargeSoThatCheckRefusesIt(t *testing.T) {
	k := newKit(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	for name, size := range map[string]int{"exact": answer.MaxFileSize, "over": answer.MaxFileSize + 1, "plus2": answer.MaxFileSize + 2, "double": 2 * answer.MaxFileSize, "huge": fsx.MaxReadSize + 1} {
		write(t, filepath.Join(in, name+".result.json"), bytes.Repeat([]byte{'a'}, size))
	}
	root := openDir(t, in)
	for name, want := range map[string]int{"exact": answer.MaxFileSize, "over": answer.MaxFileSize + 1, "plus2": answer.MaxFileSize + 1, "double": answer.MaxFileSize + 1, "huge": answer.MaxFileSize + 1} {
		a, err := answer.LoadAnswer(root, ".", name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := len(a.Files["result.json"]); got != want {
			t.Errorf("%s: %d bytes, want %d", name, got, want)
		}
		if name == "exact" {
			continue
		}
		x := k.newX509(nil)
		v, err := k.checker(nil).Check(x.csr.asked(t), a)
		if err != nil || v.Code != answer.CodeMalformed || v.Accepted() {
			t.Errorf("%s: %v code %q", name, err, v.Code)
		}
	}
}

// The way from the files on a disk to the verdict, for the vectors' files and for a made answer.
func TestAnAnswerOnADiskIsLoadedAndJudged(t *testing.T) {
	k := newKit(t)
	x := k.newX509(nil)
	dir := t.TempDir()
	for suffix, data := range x.files() {
		write(t, filepath.Join(dir, "out", "example-answer."+suffix), data)
	}
	root := openDir(t, dir)
	a, err := answer.LoadAnswer(root, "out", "example-answer")
	if err != nil {
		t.Fatal(err)
	}
	v, err := k.checker(nil).Check(x.csr.asked(t), a)
	want(t, v, err, "", "ppppppppp")
	// The answer of the vectors, read by LoadAnswer from the folder of the vectors under the stem of its files.
	m := readVectorManifest(t)
	c := vectorCase(t, "pgp-piv-valid")
	vr := vectorRoot(t)
	loaded, err := answer.LoadAnswer(vr, "responses", "pgp-piv-valid")
	if err != nil {
		t.Fatal(err)
	}
	v, err = mustChecker(t, vectorConfig(t, m)).Check(vectorAsked(t, c), loaded)
	want(t, v, err, "", pOK)
}
