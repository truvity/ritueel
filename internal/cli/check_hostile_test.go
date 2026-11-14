//go:build linux || darwin

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/strictjson"
)

// A stick may be hostile. These tests give the command bundles whose files are the wrong size, too
// deep, of the wrong type, not UTF-8, or not files at all (links, pipes, folders). Whatever is
// there, the command ends; it never panics; it never says the history is whole; it writes nothing
// but printable ASCII; and a run that checked says so with exit code 3 or one that did not with
// exit code 1.

// chRefused runs the command on the bundle and holds the common shape of a refusal.
func chRefused(t *testing.T, name string, b *hbundle) result {
	t.Helper()
	r := chHist(t, b.dir)
	if r.code != ExitRefused {
		t.Errorf("%s: exit %d, want 3; stdout %q, stderr %q", name, r.code, r.stdout, cut(r.stderr))
		return r
	}
	if r.stdout != "" {
		t.Errorf("%s: standard output = %q on a refusal", name, r.stdout)
	}
	rep := chReport(t, b.dir)
	if got, want := chLines(r.stderr), chWantLines(rep); !slices.Equal(got, want) {
		t.Errorf("%s: standard error is not the library's lines", name)
	}
	j := chJSON(t, b.dir)
	chWantRefused(t, j, chCodes(rep.Reasons()), chCodes(rep.Warnings()))
	return r
}

func cut(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

// chSparse makes a file of size bytes that takes no room on the disk.
func chSparse(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHostileRecordIsRefusedAndNeverClean(t *testing.T) {
	deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	deepObj := strings.Repeat(`{"a":`, 20000) + "1" + strings.Repeat("}", 20000)
	big := `{"version":1,"x":"` + strings.Repeat("a", strictjson.DefaultMaxBytes+10) + `"}`
	good := newHB(t, 3).cs[2].record
	cases := map[string]string{
		"an empty file":                       "",
		"null":                                "null",
		"an array":                            "[]",
		"a string":                            `"x"`,
		"a number":                            "1",
		"an open brace":                       "{",
		"an empty object":                     "{}",
		"only a version":                      `{"version":1}`,
		"text":                                "this is not JSON",
		"binary":                              "\x00\x01\x02\xff\xfe",
		"a NUL byte in the record":            strings.Replace(good, `"command"`, "\x00", 1),
		"a byte order mark":                   "\ufeff" + good,
		"a byte that is not UTF-8":            strings.Replace(good, `"apply"`, "\"\xff\xfe\"", 1),
		"the record twice":                    good + good,
		"a line break after":                  good + "\n",
		"a member twice":                      strings.Replace(good, `"version":1`, `"version":1,"version":1`, 1),
		"an unknown member":                   strings.Replace(good, `"version":1`, `"version":1,"zzz":1`, 1),
		"a version that is a string":          strings.Replace(good, `"version":1`, `"version":"1"`, 1),
		"a version that is a float":           strings.Replace(good, `"version":1`, `"version":1.0`, 1),
		"a version that is true":              strings.Replace(good, `"version":1`, `"version":true`, 1),
		"a version beyond 2^53":               strings.Replace(good, `"version":1`, `"version":9007199254740993`, 1),
		"a version of 400 digits":             strings.Replace(good, `"version":1`, `"version":`+strings.Repeat("9", 400), 1),
		"a number as 1e999":                   strings.Replace(good, `"version":1`, `"version":1e999`, 1),
		"a trust sequence of text":            strings.Replace(good, `"trust_sequence":3`, `"trust_sequence":"3"`, 1),
		"artifacts as an object":              strings.Replace(good, `"artifacts":[`, `"artifacts":{"a":[`, 1),
		"artifacts as null":                   regexpReplace(good, `"artifacts":\[.*?\],"ceremony"`, `"artifacts":null,"ceremony"`),
		"artifacts as a string":               regexpReplace(good, `"artifacts":\[.*?\],"ceremony"`, `"artifacts":"x","ceremony"`),
		"an artifact that is a number":        regexpReplace(good, `"artifacts":\[.*?\],"ceremony"`, `"artifacts":[1],"ceremony"`),
		"an artifact with no digest":          regexpReplace(good, `"artifacts":\[.*?\],"ceremony"`, `"artifacts":[{"path":"trust/x/keys.txt"}],"ceremony"`),
		"an artifact digest of text":          regexpReplace(good, `"artifacts":\[.*?\],"ceremony"`, `"artifacts":[{"path":"trust/x/keys.txt","sha256":"zz"}],"ceremony"`),
		"an artifact with a path above":       regexpReplace(good, `"artifacts":\[.*?\],"ceremony"`, `"artifacts":[{"path":"../../etc/passwd","sha256":"`+strings.Repeat("0", 64)+`"}],"ceremony"`),
		"an artifact with an absolute path":   regexpReplace(good, `"artifacts":\[.*?\],"ceremony"`, `"artifacts":[{"path":"/etc/passwd","sha256":"`+strings.Repeat("0", 64)+`"}],"ceremony"`),
		"an artifact with a path of 13 parts": regexpReplace(good, `"artifacts":\[.*?\],"ceremony"`, `"artifacts":[{"path":"`+strings.Repeat("a/", 12)+`b","sha256":"`+strings.Repeat("0", 64)+`"}],"ceremony"`),
		"an artifact path with a backslash":   regexpReplace(good, `"artifacts":\[.*?\],"ceremony"`, `"artifacts":[{"path":"trust\\x","sha256":"`+strings.Repeat("0", 64)+`"}],"ceremony"`),
		"an artifact path with a newline":     regexpReplace(good, `"artifacts":\[.*?\],"ceremony"`, `"artifacts":[{"path":"trust/x\ny","sha256":"`+strings.Repeat("0", 64)+`"}],"ceremony"`),
		"a ceremony of another name":          strings.Replace(good, `"ceremony":"`+hbFolder(3)+`"`, `"ceremony":"other"`, 1),
		"a command of another word":           strings.Replace(good, `"command":"apply"`, `"command":"nosuch"`, 1),
		"an outcome of text":                  strings.Replace(good, `"outcome":"completed"`, `"outcome":"\u0000"`, 1),
		"a digest of upper case":              strings.Replace(good, `"transcript_sha256":"`, `"transcript_sha256":"`+strings.ToUpper("ab"), 1),
		"nested arrays 20000 deep":            deep,
		"nested objects 20000 deep":           deepObj,
		"a record over 256 KiB":               big,
		"a record of one megabyte":            strings.Repeat(" ", 1<<20),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			b := newHB(t, 3)
			if err := os.WriteFile(b.path(b.recordPath(3)), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			chRefused(t, name, b)
		})
		t.Run(name+" (the only record)", func(t *testing.T) {
			b := newHB(t, 1)
			if err := os.WriteFile(b.path(b.recordPath(1)), []byte(strings.ReplaceAll(content, hbFolder(3), hbFolder(1))), 0o644); err != nil {
				t.Fatal(err)
			}
			chRefused(t, name, b)
		})
	}
}

// regexpReplace is strings.Replace with a pattern, for a text that the test makes.
func regexpReplace(s, pattern, repl string) string {
	re := regexp.MustCompile(pattern)
	if !re.MatchString(s) {
		panic("the pattern " + pattern + " does not match the record")
	}
	return re.ReplaceAllLiteralString(s, repl)
}

// Every member of a record, given in turn a value of each wrong type, is refused: the record is
// never read as whole.
func TestEveryMemberOfARecordWithTheWrongTypeIsRefused(t *testing.T) {
	members := []string{"version", "ceremony", "command", "outcome", "plan_sha256", "transcript_sha256", "artifacts", "wanted", "trust_sequence", "prev_record_sha256"}
	values := []string{"null", "true", "0", "-1", "1.5", `"x"`, `""`, "[]", "{}", `[1,2]`, `{"a":1}`, `"\u0000"`}
	for _, m := range members {
		for _, v := range values {
			if m == "trust_sequence" && (v == "0" || v == "-1") {
				continue // an integer, which is the type of the member; the page gives it no range
			}
			b := newHB(t, 3)
			b.rewrite(t, b.recordPath(3), func(s string) string {
				re := regexp.MustCompile(`"` + m + `":("[^"]*"|\[.*?\]|[0-9]+)`)
				if !re.MatchString(s) {
					t.Fatalf("no member %s in the record", m)
				}
				return re.ReplaceAllLiteralString(s, `"`+m+`":`+v)
			})
			rep := chReport(t, b.dir)
			if len(rep.Reasons()) == 0 {
				t.Errorf("%s = %s was accepted by the check", m, v)
				continue
			}
			chRefused(t, m+" = "+v, b)
		}
	}
}

func TestFilesOfTheWrongSizeAreRefused(t *testing.T) {
	over := int64(fsxMaxReadSize + 1)
	for _, rel := range []func(*hbundle) string{
		func(b *hbundle) string { return b.recordPath(3) },
		func(b *hbundle) string { return b.folderPath(3) + "/plan.json" },
		func(b *hbundle) string { return b.folderPath(3) + "/transcript.txt" },
		func(b *hbundle) string { return b.folderPath(3) + "/wanted/ritueel.yaml" },
		func(b *hbundle) string { return "trust/" + b.cs[2].set + "/keys.txt" },
		func(b *hbundle) string { return "trust/" + b.cs[2].set + "/root-list.json" },
	} {
		b := newHB(t, 3)
		p := rel(b)
		chSparse(t, b.path(p), over)
		r := chRefused(t, p, b)
		if !strings.Contains(r.stderr, "8 MiB") && !strings.Contains(r.stderr, "regular file") {
			t.Errorf("%s: the text does not say why: %q", p, cut(r.stderr))
		}
	}
	// Exactly the limit is a file that can be read, and then its digest is wrong.
	b := newHB(t, 3)
	chSparse(t, b.path("trust/"+b.cs[2].set+"/keys.txt"), fsxMaxReadSize)
	r := chRefused(t, "a file of exactly 8 MiB", b)
	if !strings.Contains(r.stderr, "file-digest") || strings.Contains(r.stderr, "8 MiB") {
		t.Errorf("a file of exactly 8 MiB: %q", cut(r.stderr))
	}
}

const fsxMaxReadSize = 8 << 20

// What stands where a file belongs: a link, a pipe, a folder, a device behind a link. None is
// read, none is waited on, none is clean.
func TestAnythingButAFileWhereAFileBelongsIsRefused(t *testing.T) {
	where := map[string]func(*hbundle) string{
		"the record":        func(b *hbundle) string { return b.recordPath(2) },
		"the newest record": func(b *hbundle) string { return b.recordPath(3) },
		"the plan":          func(b *hbundle) string { return b.folderPath(2) + "/plan.json" },
		"the attempt":       func(b *hbundle) string { return b.folderPath(2) + "/attempt.json" },
		"the transcript":    func(b *hbundle) string { return b.folderPath(2) + "/transcript.txt" },
		"a wanted copy":     func(b *hbundle) string { return b.folderPath(2) + "/wanted/ritueel.yaml" },
		"the wanted folder": func(b *hbundle) string { return b.folderPath(2) + "/wanted" },
		"an artifact":       func(b *hbundle) string { return "trust/" + b.cs[1].set + "/keys.txt" },
		"a root list":       func(b *hbundle) string { return "trust/" + b.cs[1].set + "/root-list.json" },
		"a ceremony folder": func(b *hbundle) string { return b.folderPath(2) },
		"a trust set":       func(b *hbundle) string { return "trust/" + b.cs[1].set },
	}
	kinds := map[string]func(t *testing.T, b *hbundle, p string){
		"a link to a good file": func(t *testing.T, b *hbundle, p string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			replace(t, b, p, func(path string) error { return os.Symlink(target, path) })
		},
		"a link to a folder": func(t *testing.T, b *hbundle, p string) {
			replace(t, b, p, func(path string) error { return os.Symlink(t.TempDir(), path) })
		},
		"a link to nothing": func(t *testing.T, b *hbundle, p string) {
			replace(t, b, p, func(path string) error { return os.Symlink(filepath.Join(t.TempDir(), "nowhere"), path) })
		},
		"a link to itself": func(t *testing.T, b *hbundle, p string) {
			replace(t, b, p, func(path string) error { return os.Symlink(filepath.Base(path), path) })
		},
		"a link to a device": func(t *testing.T, b *hbundle, p string) {
			if _, err := os.Stat("/dev/zero"); err != nil {
				t.Fatalf("this system has no /dev/zero, and the test needs a device: %v", err)
			}
			replace(t, b, p, func(path string) error { return os.Symlink("/dev/zero", path) })
		},
		"a FIFO": func(t *testing.T, b *hbundle, p string) {
			replace(t, b, p, func(path string) error { return syscall.Mkfifo(path, 0o600) })
		},
		"an empty folder": func(t *testing.T, b *hbundle, p string) {
			replace(t, b, p, func(path string) error { return os.Mkdir(path, 0o755) })
		},
	}
	for wname, rel := range where {
		for kname, make := range kinds {
			t.Run(wname+" is "+kname, func(t *testing.T) {
				b := newHB(t, 3)
				p := rel(b)
				make(t, b, p)
				r := chHist(t, b.dir)
				if r.code != ExitRefused && r.code != ExitFailure {
					t.Fatalf("exit %d; stdout %q, stderr %q; want 3 or 1", r.code, r.stdout, cut(r.stderr))
				}
				if r.stdout != "" {
					t.Errorf("standard output = %q", r.stdout)
				}
				if strings.Contains(r.stdout+r.stderr, "history: ") {
					t.Errorf("an end line: %q", r.stdout+r.stderr)
				}
				if r.code == ExitRefused {
					rep := chReport(t, b.dir)
					if got, want := chLines(r.stderr), chWantLines(rep); !slices.Equal(got, want) {
						t.Errorf("standard error:\n got %q\nwant %q", got, want)
					}
				}
			})
		}
	}
}

// replace removes what is at p in the bundle and makes it again with make; where p is a folder with
// files, they go with it.
func replace(t *testing.T, b *hbundle, p string, make func(path string) error) {
	t.Helper()
	full := b.path(p)
	if err := os.RemoveAll(full); err != nil {
		t.Fatal(err)
	}
	if err := make(full); err != nil {
		t.Fatalf("cannot make %s here: %v", p, err)
	}
}

// The attempt, the plan and the root list of a ceremony that has no record are read for their
// content; a hostile content there must not be clean either.
func TestHostileFilesOfAnUnfinishedCeremonyAreNotClean(t *testing.T) {
	deep := strings.Repeat("[", 20000)
	contents := map[string]string{
		"empty":                          "",
		"null":                           "null",
		"text":                           "no",
		"deep":                           deep,
		"a digest of text":               `{"ceremony":"x","plan_sha256":"zz","version":1}`,
		"not UTF-8":                      "\xff\xfe\x00",
		"big":                            `{"x":"` + strings.Repeat("a", 300000) + `"}`,
		"a trust sequence 0":             `{"trust_sequence":0}`,
		"a trust sequence of 400 digits": `{"trust_sequence":` + strings.Repeat("9", 400) + `}`,
	}
	for _, file := range []string{"plan.json", "attempt.json"} {
		for name, content := range contents {
			t.Run(file+" "+name, func(t *testing.T) {
				b := newHB(t, 2)
				c := b.add(t, false)
				if err := os.WriteFile(b.path(c.base()+file), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
				r := chHist(t, b.dir)
				if r.code != ExitRefused && (r.code != ExitOK || !strings.Contains(r.stdout, "2 ceremony records")) {
					t.Fatalf("exit %d, stdout %q, stderr %q", r.code, r.stdout, cut(r.stderr))
				}
				// A hostile file never makes an unfinished ceremony out of three small files.
				if r.code == ExitOK {
					t.Errorf("a damaged %s gave a notice and not a finding: %q", file, cut(r.stderr))
				}
			})
		}
	}
	for name, content := range contents {
		t.Run("root-list.json "+name, func(t *testing.T) {
			b := newHB(t, 2)
			c := b.add(t, false)
			if err := os.WriteFile(b.path("trust/"+c.set+"/root-list.json"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			r := chHist(t, b.dir)
			if r.code != ExitRefused {
				t.Errorf("exit %d, stdout %q, stderr %q; want 3", r.code, r.stdout, cut(r.stderr))
			}
		})
	}
}

// Whole folders in place of the folders of the bundle: a refusal to look, never a clean history.
func TestFoldersOfTheBundleThatAreNotFolders(t *testing.T) {
	for _, top := range []string{"history", "trust"} {
		kinds := map[string]func(t *testing.T, b *hbundle){
			"a link to the good folder": func(t *testing.T, b *hbundle) {
				other := filepath.Join(t.TempDir(), top)
				if err := os.Rename(b.path(top), other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, b.path(top)); err != nil {
					t.Fatal(err)
				}
			},
			"a FIFO": func(t *testing.T, b *hbundle) {
				replace(t, b, top, func(p string) error { return syscall.Mkfifo(p, 0o600) })
			},
			"a file": func(t *testing.T, b *hbundle) {
				replace(t, b, top, func(p string) error { return os.WriteFile(p, []byte("x"), 0o644) })
			},
		}
		for name, make := range kinds {
			t.Run(top+" is "+name, func(t *testing.T) {
				b := newHB(t, 2)
				make(t, b)
				r := chHist(t, b.dir)
				if r.code != ExitFailure || r.stdout != "" {
					t.Errorf("exit %d, stdout %q, stderr %q; want 1 and nothing on standard output", r.code, r.stdout, r.stderr)
				}
				chWantFailed(t, chJSON(t, b.dir))
			})
		}
	}
	// A bundle with a manifest and a history folder that was removed, while its trust sets stay, is
	// not a history with no ceremony: its trust sets are said.
	b := newHB(t, 2)
	b.remove(t, "history")
	r := chHist(t, b.dir)
	if r.code != ExitRefused || strings.Contains(r.stdout, "history:") {
		t.Errorf("a removed history folder: exit %d, stdout %q", r.code, r.stdout)
	}
}

// A folder with more names than a read lists ends the run with exit code 1: a limit of the run
// is never clean.
func TestFolderWithTooManyNamesIsNotChecked(t *testing.T) {
	if testing.Short() {
		t.Skip("makes more than 65,536 files")
	}
	for _, where := range []string{"history", "trust"} {
		b := newHB(t, 2)
		dir := b.path(where)
		for i := 0; i <= 65536; i++ {
			f, err := os.Create(filepath.Join(dir, "n"+itoa(i)))
			if err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
		}
		r := chHist(t, b.dir)
		chWantNotChecked(t, "too many names in '"+where+"'", r, chJSON(t, b.dir))
	}
}

// Names that a stick may hold in every place the check lists, each with a byte or a shape that a
// name should not have: the command shows them with escapes, and never as whole.
func TestHostileNamesInEveryPlace(t *testing.T) {
	names := []string{
		"a\x1b[2Jb", "a\nb", "a\u0430b", "\xff", "a\\b", "a b", ".", "..", "...", "-", "-rf", "~", "a:b", "a*b", "a?b",
		strings.Repeat("a", 255), "CON", "a.", ".hidden", "a\u202eb", "\u200b", "\ufeff", "a\x00b",
	}
	places := []string{"history", "trust", "history/" + hbFolder(1), "history/" + hbFolder(1) + "/wanted", "trust/" + hbSet(1)}
	for _, place := range places {
		for _, name := range names {
			b := newHB(t, 2)
			p := filepath.Join(b.path(place), name)
			if strings.ContainsAny(name, "\x00") || name == "." || name == ".." {
				continue // no file system can hold these
			}
			if err := os.Mkdir(p, 0o755); err != nil {
				continue // this file system cannot hold the name
			}
			r := chHist(t, b.dir)
			if r.code == ExitFailure || r.code == ExitUsage {
				t.Errorf("%s/%q: exit %d: %q", place, name, r.code, cut(r.stderr))
			}
			if r.code == ExitOK && r.stdout != chEnd(2, b.end()) {
				t.Errorf("%s/%q: exit 0 and the end line %q", place, name, r.stdout)
			}
			if strings.Count(r.stderr, "\n") != len(chLines(r.stderr)) {
				t.Errorf("%s/%q: a line without its line break", place, name)
			}
			if r.code == ExitRefused {
				rep := chReport(t, b.dir)
				if got, want := chLines(r.stderr), chWantLines(rep); !slices.Equal(got, want) {
					t.Errorf("%s/%q: the lines differ from the library's", place, name)
				}
			}
		}
	}
}
