//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/keydir"
	"ritueel.id/ritueel/internal/wanted"
)

// Small points of the plan: the plan lists the digests of the bytes that Settings and Root hold; the
// words escape every text, the digests too; the fault text of the check of the key directory is one
// line; and the doc of Env says what MakePlan reads. The names of this file start with ps.

// psCopy is a copy of a Found that shares no byte and no field with f, so that a test can change it.
func psCopy(f *ceremony.Found) *ceremony.Found {
	c := *f
	c.Applies = slices.Clone(f.Applies)
	s := *f.Settings
	s.File.Data = bytes.Clone(s.File.Data)
	c.Settings = &s
	r := *f.Root
	r.File.Data = bytes.Clone(r.File.Data)
	c.Root = &r
	c.Wanted = make([]wanted.File, len(f.Wanted))
	for i, w := range f.Wanted {
		w.Data = bytes.Clone(w.Data)
		c.Wanted[i] = w
	}
	return &c
}

// psFlip changes one byte of b.
func psFlip(b []byte) []byte {
	out := bytes.Clone(b)
	out[len(out)-2] ^= 0x01
	return out
}

func TestMakePlanRefusesAFoundWhoseWantedBytesAreNotTheBytesOfItsSettingsAndRoot(t *testing.T) {
	base := pfMustFind(t, pfFiles())
	if base.Wanted[0].Path != "ritueel.yaml" || base.Wanted[1].Path != "want/roots/x509.yaml" {
		t.Fatalf("the wanted files are %q and %q", base.Wanted[0].Path, base.Wanted[1].Path)
	}
	cases := map[string]func(f *ceremony.Found){
		"the root bytes are missing":     func(f *ceremony.Found) { f.Wanted[1].Data = nil },
		"the settings bytes are missing": func(f *ceremony.Found) { f.Wanted[0].Data = nil },
		"both bytes are empty": func(f *ceremony.Found) {
			f.Wanted[0].Data = []byte{}
			f.Wanted[1].Data = []byte{}
		},
		"the two bytes are swapped": func(f *ceremony.Found) {
			f.Wanted[0].Data, f.Wanted[1].Data = f.Wanted[1].Data, f.Wanted[0].Data
		},
		"one byte of the root bytes is changed":     func(f *ceremony.Found) { f.Wanted[1].Data = psFlip(f.Wanted[1].Data) },
		"one byte of the settings bytes is changed": func(f *ceremony.Found) { f.Wanted[0].Data = psFlip(f.Wanted[0].Data) },
		"a byte is added to the root bytes":         func(f *ceremony.Found) { f.Wanted[1].Data = append(f.Wanted[1].Data, '\n') },
		"a byte is cut from the settings bytes":     func(f *ceremony.Found) { f.Wanted[0].Data = f.Wanted[0].Data[:len(f.Wanted[0].Data)-1] },
		"the bytes of the settings are the root's own bytes of another file": func(f *ceremony.Found) {
			f.Wanted[0].Data = []byte(pfX509Real)
		},
		"the bytes that Settings holds are changed": func(f *ceremony.Found) {
			f.Settings.File.Data = psFlip(f.Settings.File.Data)
		},
		"the bytes that Root holds are changed": func(f *ceremony.Found) {
			f.Root.File.Data = psFlip(f.Root.File.Data)
		},
		"the bytes that Settings holds are missing": func(f *ceremony.Found) { f.Settings.File.Data = nil },
		"the bytes that Root holds are missing":     func(f *ceremony.Found) { f.Root.File.Data = nil },
		"the same wanted file twice":                func(f *ceremony.Found) { f.Wanted[1] = f.Wanted[0] },
		"the settings path twice, with the root bytes": func(f *ceremony.Found) {
			f.Wanted[1].Path = f.Wanted[0].Path
		},
		"the root path twice": func(f *ceremony.Found) { f.Wanted[0] = f.Wanted[1] },
		"the paths are swapped and the bytes stay": func(f *ceremony.Found) {
			f.Wanted[0].Path, f.Wanted[1].Path = f.Wanted[1].Path, f.Wanted[0].Path
		},
		"a path that no reader made": func(f *ceremony.Found) { f.Wanted[1].Path = "want/roots/other.yaml" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := psCopy(base)
			edit(f)
			p, err := ceremony.MakePlan(f, pfEnv())
			if err == nil || p != nil {
				t.Fatalf("MakePlan = %v, %v; want an error and no plan", p, err)
			}
			if !pfPrintable(err.Error()) {
				t.Errorf("the text is not printable ASCII: %+q", err.Error())
			}
		})
	}
}

func TestMakePlanListsTheDigestsOfTheBytesThatSettingsAndRootHold(t *testing.T) {
	base := pfMustFind(t, pfFiles())
	t.Run("a copy of a Found gives the golden plan", func(t *testing.T) {
		p, err := ceremony.MakePlan(psCopy(base), pfEnv())
		if err != nil || string(p.JSON) != pfGolden || p.SHA256 != pfGoldenDigest {
			t.Fatalf("MakePlan = %v, %v", p, err)
		}
	})
	t.Run("the wanted files in the other order give the golden plan", func(t *testing.T) {
		f := psCopy(base)
		f.Wanted[0], f.Wanted[1] = f.Wanted[1], f.Wanted[0]
		p, err := ceremony.MakePlan(f, pfEnv())
		if err != nil || string(p.JSON) != pfGolden {
			t.Fatalf("MakePlan = %v, %v", p, err)
		}
	})
	t.Run("a digest field that lies is not what the plan lists", func(t *testing.T) {
		f := psCopy(base)
		f.Wanted[0].SHA256 = strings.Repeat("0", 64)
		f.Wanted[1].SHA256 = "x\ny"
		p, err := ceremony.MakePlan(f, pfEnv())
		if err != nil || string(p.JSON) != pfGolden {
			t.Fatalf("MakePlan = %v, %v", p, err)
		}
		for _, w := range p.Wanted {
			if w.SHA256 != pfSumSet && w.SHA256 != pfSumRoot {
				t.Errorf("the plan lists the digest %q", w.SHA256)
			}
		}
	})
	t.Run("bytes that differ from the file that was read change the plan, when Settings and Root hold them too", func(t *testing.T) {
		// A Found whose Settings, Root and Wanted all hold the same other bytes is a Found that is
		// consistent in itself; the plan lists the digests of those bytes, and they are the bytes of
		// Settings and Root.
		other := pfFiles()
		other["ritueel.yaml"] = strings.Replace(pfSettings, "name: Example", "name: Example Two", 1)
		f := pfMustFind(t, other)
		p, err := ceremony.MakePlan(f, pfEnv())
		if err != nil {
			t.Fatal(err)
		}
		if p.Wanted[0].SHA256 != sum([]byte(other["ritueel.yaml"])) || p.Wanted[0].SHA256 == pfSumSet {
			t.Errorf("the plan lists the digest %s for ritueel.yaml", p.Wanted[0].SHA256)
		}
	})
	t.Run("MakePlan changes nothing of the Found", func(t *testing.T) {
		f := psCopy(base)
		keep := psCopy(base)
		if _, err := ceremony.MakePlan(f, pfEnv()); err != nil {
			t.Fatal(err)
		}
		for i := range f.Wanted {
			if !bytes.Equal(f.Wanted[i].Data, keep.Wanted[i].Data) || f.Wanted[i].Path != keep.Wanted[i].Path {
				t.Errorf("Wanted[%d] was changed", i)
			}
		}
	})
}

func TestTheWordsOfAPlanMadeByHandPrintNoRawLineBreakInADigest(t *testing.T) {
	cases := map[string]struct{ plan, wanted string }{
		"line feed":           {"x\ny", "a\nb"},
		"carriage return":     {"x\ry", "a\rb"},
		"both":                {"x\r\ny", "a\r\nb"},
		"only a line break":   {"\r\n", "\r\n"},
		"a vertical tab":      {"x\x0by", "a\x0cb"},
		"a next line":         {"x\u0085y", "a\u2028b"},
		"an escape sequence":  {"\x1b[2J", "\x1b[31m"},
		"a bidirectional run": {"x\u202ey", "a\u2066b"},
		"not UTF-8":           {"x\xffy", "a\xfeb"},
		"a NUL":               {"x\x00y", "a\x00b"},
		"a backslash":         {`x\ny`, `a\\b`},
		"a short digest":      {"x", "a"},
		"a long digest":       {strings.Repeat("a", 1000), strings.Repeat("b", 1000)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := &ceremony.PlanOut{
				Name:       pfName,
				SHA256:     c.plan,
				Program:    buildinfo.Program{Version: "v1", OSArch: "linux/amd64"},
				Wanted:     []files.FileRef{{Path: "ritueel.yaml", SHA256: c.wanted}, {Path: "want/roots/x509.yaml", SHA256: c.wanted}},
				Signatures: make([]ceremony.PlanSignature, 3),
			}
			words := p.Words()
			if len(words) == 0 {
				t.Fatal("no words")
			}
			for _, l := range words {
				if strings.ContainsAny(l, "\r\n") || !pfPrintable(l) {
					t.Errorf("the line %+q holds a raw line break or is not printable ASCII on one line", l)
				}
			}
			if !strings.HasPrefix(words[len(words)-1], "plan digest ") {
				t.Errorf("the plan digest is not the last line: %+q", words[len(words)-1])
			}
		})
	}
	t.Run("the escape of a line break in a digest is the escape of every other text", func(t *testing.T) {
		p := &ceremony.PlanOut{
			Name:    pfName,
			SHA256:  "x\ny",
			Program: buildinfo.Program{Version: "v1", OSArch: "linux/amd64"},
			Wanted:  []files.FileRef{{Path: "ritueel.yaml", SHA256: "a\r\nb"}},
		}
		words := p.Words()
		if last := words[len(words)-1]; last != `plan digest x\u000ay` {
			t.Errorf("the last line is %q", last)
		}
		var wantedLine string
		for _, l := range words {
			if strings.HasPrefix(l, "wanted file ") {
				wantedLine = l
			}
		}
		if wantedLine != `wanted file ritueel.yaml, digest a\u000d\u000ab` {
			t.Errorf("the wanted line is %q", wantedLine)
		}
	})
}

func TestTheWordsOfAValidPlanAreNotChangedByTheEscapeOfTheDigests(t *testing.T) {
	// Hexadecimal digits are what the escape leaves alone: the golden words stand.
	got := pfPlan(t, pfFiles()).Words()
	if last := got[len(got)-1]; last != "plan digest "+pfGoldenDigest {
		t.Errorf("last line = %q", last)
	}
	if !slices.Contains(got, "wanted file ritueel.yaml, digest "+pfSumSet[:8]) || !slices.Contains(got, "wanted file want/roots/x509.yaml, digest "+pfSumRoot[:8]) {
		t.Errorf("the wanted lines are not the golden ones:\n%s", strings.Join(got, "\n"))
	}
}

// FuzzWordsAnyDigest gives the words a plan whose digests are any text: no line holds a line break or
// a byte that is not printable ASCII, the plan digest is the last line, and a digest in the form of
// 64 hexadecimal digits is shown as it is.
func FuzzWordsAnyDigest(f *testing.F) {
	f.Add(pfGoldenDigest, pfSumSet, "ritueel.yaml")
	f.Add("x\ny", "a\r\nb", "p\nq")
	f.Add("\r\n", "\xff", "\x1b[2J")
	f.Add("", "", "")
	f.Add(strings.Repeat("a", 7), strings.Repeat("a", 8), "\u2028")
	f.Fuzz(func(t *testing.T, planDigest, wantedDigest, path string) {
		p := &ceremony.PlanOut{
			Name:       pfName,
			SHA256:     planDigest,
			Program:    buildinfo.Program{Version: "v1", OSArch: "linux/amd64"},
			Wanted:     []files.FileRef{{Path: path, SHA256: wantedDigest}},
			Signatures: make([]ceremony.PlanSignature, 3),
		}
		words := p.Words()
		if planDigest == "" {
			if len(words) != 0 {
				t.Fatal("words of a plan with no digest")
			}
			return
		}
		if len(words) == 0 {
			t.Fatal("no words")
		}
		for _, l := range words {
			if strings.ContainsAny(l, "\r\n") || !pfPrintable(l) {
				t.Fatalf("the line %+q holds a line break or is not printable ASCII", l)
			}
		}
		if files.IsDigest(planDigest) && words[len(words)-1] != "plan digest "+planDigest {
			t.Fatalf("the last line is %q for the digest %q", words[len(words)-1], planDigest)
		}
	})
}

func TestTheFaultTextOfCheckKeyDirThatIsNotARefusalIsOneLine(t *testing.T) {
	root, _ := pfKeyDirCase(t)
	err := ceremony.CheckKeyDir(root, "")
	if err == nil {
		t.Fatal("CheckKeyDir accepted an empty bundle folder")
	}
	var b *ceremony.BackendError
	if errors.As(err, &b) {
		t.Errorf("a fault of the caller was told as a refusal of the key store: %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("the text holds a line break: %+q", err.Error())
	}
	if !pfPrintable(err.Error()) {
		t.Errorf("the text is not printable ASCII on one line: %+q", err.Error())
	}
	if !strings.Contains(err.Error(), "nothing was written") {
		t.Errorf("the text does not say that nothing was written: %q", err)
	}
	// The one fault is wrapped in the other: the fault of the key store can still be found.
	if !errors.Is(err, keydir.ErrParams) && !errors.Is(err, keydir.ErrKeyDir) {
		t.Errorf("the fault of the key store cannot be reached from %q", err)
	}
	var join interface{ Unwrap() []error }
	if errors.As(err, &join) {
		t.Errorf("the error joins errors with a line feed: %T", err)
	}
}

func TestTheFaultTextOfCheckKeyDirIsOneLineForEveryFaultThatIsNotARefusal(t *testing.T) {
	root, _ := pfKeyDirCase(t)
	for name, bundle := range map[string]string{
		"an empty bundle folder":            "",
		"a bundle folder with a line break": "a\nb",
		"a bundle folder of a long name":    strings.Repeat("a", 5000),
	} {
		t.Run(name, func(t *testing.T) {
			err := ceremony.CheckKeyDir(root, bundle)
			if err == nil {
				return
			}
			var b *ceremony.BackendError
			if errors.As(err, &b) {
				return // a refusal has its own text, with the reason code
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("the text holds a line break: %+q", err.Error())
			}
		})
	}
}

// What MakePlan reads from Env: the clock, the source of the serials and the description of the
// program, and nothing else. It prints nothing.
func TestMakePlanReadsOnlyTheClockTheSerialsAndTheProgramAndPrintsNothing(t *testing.T) {
	f := pfMustFind(t, pfFiles())
	var out, errOut bytes.Buffer
	in := &psReader{t: t}
	env := pfEnv()
	env.In = in
	env.InIsTerminal = true
	env.Out = ceremony.NewConsole(&errOut, &out)
	p, err := ceremony.MakePlan(f, env)
	if err != nil || string(p.JSON) != pfGolden {
		t.Fatalf("MakePlan = %v, %v", p, err)
	}
	if in.reads != 0 {
		t.Errorf("MakePlan read In %d times", in.reads)
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Errorf("MakePlan printed %q and %q", out.String(), errOut.String())
	}
	if lines, terr := env.Out.Transcript(); terr != nil || len(lines) != 0 {
		t.Errorf("the console holds %q, %v", lines, terr)
	}
}

func TestAnEnvWithNoConsoleAndNoInputIsNoFaultOfMakePlan(t *testing.T) {
	f := pfMustFind(t, pfFiles())
	env := ceremony.Env{Now: pfEnv().Now, Rand: &pfCounter{}, Self: pfSelf}
	if env.Out != nil || env.In != nil {
		t.Fatal("the test Env holds a console or an input")
	}
	p, err := ceremony.MakePlan(f, env)
	if err != nil || string(p.JSON) != pfGolden {
		t.Errorf("MakePlan with a nil Out and a nil In = %v, %v", p, err)
	}
}

// psReader is an input that fails the test when it is read.
type psReader struct {
	t     *testing.T
	reads int
}

func (r *psReader) Read([]byte) (int, error) {
	r.reads++
	r.t.Error("the input was read")
	return 0, io.EOF
}

// The doc of Env says plainly which fields MakePlan reads and that it prints nothing, so that a nil
// Console is no fault of MakePlan, and keeps the rule for the part that prints.
func TestTheDocOfEnvSaysWhichFieldsMakePlanReads(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "env.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var doc string
	var outDoc string
	ast.Inspect(file, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok {
			return true
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != "Env" {
				continue
			}
			doc = gd.Doc.Text()
			if st, ok := ts.Type.(*ast.StructType); ok {
				for _, fld := range st.Fields.List {
					if len(fld.Names) == 1 && fld.Names[0].Name == "Out" {
						outDoc = fld.Doc.Text()
					}
				}
			}
		}
		return true
	})
	if doc == "" {
		t.Fatal("no doc of Env in env.go")
	}
	flat := strings.Join(strings.Fields(doc), " ")
	for _, w := range []string{"MakePlan", "(Now)", "(Rand)", "(Self)", "prints nothing", "nil Out", "no fault of MakePlan", "never reads In", "nil Console is an error", "reads three fields"} {
		if !strings.Contains(flat, w) {
			t.Errorf("the doc of Env does not hold %q:\n%s", w, doc)
		}
	}
	if strings.Contains(flat, "members") {
		t.Errorf("the doc of Env says members, it says fields:\n%s", doc)
	}
	if !strings.Contains(strings.Join(strings.Fields(outDoc), " "), "MakePlan does not use it") {
		t.Errorf("the doc of Out does not say that MakePlan does not use it:\n%s", outDoc)
	}
}
